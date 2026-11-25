//! Checks the Sigstore attestations of conda packages when they are locked.
//!
//! An attestation binds the sha256 of a package to the identity that
//! published it ([CEP 27](https://conda.org/learn/ceps/cep-0027)), and a
//! channel serves it in a sidecar next to the package
//! ([CEP 50](https://conda.org/learn/ceps/cep-0050)). The lock file pins the
//! same sha256, so a package that was checked when it was locked does not
//! need to be checked again when it is installed.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use futures::{StreamExt, stream};
use itertools::Itertools;
use miette::Diagnostic;
use pixi_config::{AttestationVerificationConfig, AttestationVerificationMode};
use rattler_conda_types::RepoDataRecord;
use rattler_digest::Sha256Hash;
use rattler_lock::LockFile;
use rattler_networking::LazyClient;
use rattler_sigstore::{
    ChannelCheck, DEFAULT_MAX_SIDECAR_SIZE, Publisher, SigstoreError, TrustedRoot,
    embedded_trusted_root, fetch_sidecar, production_trusted_root, verify_bundles,
};
use reqwest_middleware::ClientWithMiddleware;
use thiserror::Error;
use tokio::sync::OnceCell;
use url::Url;

/// Whether problems with attestations fail locking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Strictness {
    Warn,
    Require,
}

/// The attestation policy that newly locked conda packages are checked
/// against.
#[derive(Debug, Clone)]
struct AttestationPolicy {
    strictness: Strictness,

    /// An attestation must be signed by a publisher matching all of these.
    publishers: Vec<Publisher>,
}

impl AttestationPolicy {
    /// Builds the policy from the configuration, or returns `None` if
    /// attestations are not checked.
    fn from_config(
        config: &AttestationVerificationConfig,
    ) -> Result<Option<Self>, AttestationConfigError> {
        let strictness = match config.mode() {
            AttestationVerificationMode::Disabled => return Ok(None),
            AttestationVerificationMode::Warn => Strictness::Warn,
            AttestationVerificationMode::Require => Strictness::Require,
        };

        let publishers = config
            .default_publishers
            .iter()
            .map(|rule| {
                let mut publisher = Publisher::new();
                if let Some(identity) = &rule.identity {
                    publisher = publisher.with_identity(identity.as_str());
                }
                if let Some(issuer) = &rule.issuer {
                    publisher = publisher.with_issuer(issuer.as_str());
                }
                publisher
            })
            .collect_vec();

        // Without an identity any valid Sigstore signature is accepted,
        // including one made by an attacker's own repository.
        if strictness == Strictness::Require
            && !publishers
                .iter()
                .any(|publisher| publisher.identity.is_some())
        {
            return Err(AttestationConfigError::NoTrustedIdentity);
        }

        Ok(Some(Self {
            strictness,
            publishers,
        }))
    }
}

/// The `attestation-verification` configuration is invalid.
#[derive(Debug, Error, Diagnostic)]
pub enum AttestationConfigError {
    #[error(
        "no trusted publisher identity is configured for the `require` attestation verification mode"
    )]
    #[diagnostic(help(
        "set `attestation-verification.default.identity`, for example to `https://github.com/my-org/*`"
    ))]
    NoTrustedIdentity,
}

/// A newly locked package whose attestation could not be verified.
#[derive(Debug, Clone)]
pub struct UnverifiedPackage {
    /// The package filename.
    pub file_name: String,

    /// Why the attestation could not be verified.
    pub problem: AttestationProblem,
}

/// Why the attestation of a package could not be verified.
#[derive(Debug, Clone, Error)]
pub enum AttestationProblem {
    /// The channel does not advertise an attestation for the package.
    #[error("no attestation")]
    Missing,

    /// The channel advertises an attestation, but pixi is offline and the
    /// channel is not local.
    #[error("cannot fetch the attestation in offline mode")]
    Offline,

    /// The attestation could not be retrieved, is invalid, or was not signed
    /// by a trusted publisher.
    #[error("{0}")]
    Rejected(String),
}

#[derive(Debug, Error, Diagnostic)]
pub enum AttestationError {
    #[error(transparent)]
    TrustedRoot(Box<SigstoreError>),

    #[error(
        "the attestations of {} could not be verified:{}",
        pluralize_packages(.0.len()),
        format_unverified(.0)
    )]
    #[diagnostic(help(
        "packages without a verified attestation from a trusted publisher are rejected because `attestation-verification.mode` is `require`"
    ))]
    Unverified(Vec<UnverifiedPackage>),
}

fn pluralize_packages(count: usize) -> String {
    match count {
        1 => "1 newly locked package".to_string(),
        count => format!("{count} newly locked packages"),
    }
}

fn format_unverified(packages: &[UnverifiedPackage]) -> String {
    packages
        .iter()
        .map(|package| format!("\n  - {}: {}", package.file_name, package.problem))
        .collect()
}

/// A binary package as identified in the lock file.
type PackageKey = (Url, Sha256Hash);

/// The verification result of a package, computed once.
type SharedResult = Arc<OnceCell<Result<(), AttestationProblem>>>;

/// The binary conda packages of a lock file.
///
/// A package that is in the lock file with the same URL and sha256 is not
/// checked again. This is the lock file as it was before an update, so
/// packages that `pixi update` or `pixi add` re-solve to the same build are
/// not checked again either.
#[derive(Debug, Default)]
pub struct LockedPackages(HashSet<PackageKey>);

impl LockedPackages {
    pub fn from_lock_file(lock_file: &LockFile) -> Self {
        let mut packages = HashSet::new();
        for (_, environment) in lock_file.environments() {
            for (_, platform_packages) in environment.conda_packages_by_platform() {
                for binary in platform_packages.filter_map(|package| package.as_binary()) {
                    // A package without a sha256 is always checked.
                    if let (Some(sha256), Ok(url)) =
                        (binary.package_record.sha256, binary.location.try_into_url())
                    {
                        packages.insert((url, sha256));
                    }
                }
            }
        }
        Self(packages)
    }

    fn contains(&self, record: &RepoDataRecord) -> bool {
        package_key(record).is_some_and(|key| self.0.contains(&key))
    }
}

fn package_key(record: &RepoDataRecord) -> Option<PackageKey> {
    Some((record.url.clone(), record.package_record.sha256?))
}

/// Checks the attestations of the packages that solves add to the lock file.
///
/// One checker is shared by every solve of a lock file update, so a package
/// that is newly locked for several platforms is verified once.
pub struct AttestationChecker {
    policy: AttestationPolicy,
    locked: LockedPackages,
    /// Only built when an attestation is fetched.
    client: LazyClient,
    offline: bool,
    concurrency: usize,

    /// The verification result of each package, shared across solves.
    results: Mutex<HashMap<PackageKey, SharedResult>>,
}

impl AttestationChecker {
    /// Creates a checker from the configuration, or returns `None` if
    /// attestations are not checked.
    ///
    /// When `offline` is set, attestations of packages from local channels
    /// are verified against the trusted root embedded in pixi, and those of
    /// other packages cannot be fetched. `locked` is only called if
    /// attestations are checked.
    pub fn new(
        config: &AttestationVerificationConfig,
        locked: impl FnOnce() -> LockedPackages,
        client: LazyClient,
        offline: bool,
        concurrency: usize,
    ) -> Result<Option<Self>, AttestationConfigError> {
        Ok(AttestationPolicy::from_config(config)?.map(|policy| Self {
            policy,
            locked: locked(),
            client,
            offline,
            concurrency,
            results: Mutex::default(),
        }))
    }

    /// Checks the attestations of the `solved` records that are not in the
    /// lock file yet.
    ///
    /// In warn mode every problem is logged as a warning that names `scope`,
    /// for example the environment and platform. In require mode any problem
    /// is an error.
    pub async fn check<'a>(
        &self,
        solved: impl IntoIterator<Item = &'a RepoDataRecord>,
        scope: &str,
    ) -> Result<(), AttestationError> {
        let newly_locked = solved
            .into_iter()
            .filter(|record| !self.locked.contains(record))
            .collect_vec();
        if newly_locked.is_empty() {
            return Ok(());
        }

        let mut unverified = Vec::new();
        let mut to_verify = Vec::new();
        for record in newly_locked {
            let problem = if record.package_record.attestations_sha256.is_none() {
                AttestationProblem::Missing
            } else if self.offline && record.url.scheme() != "file" {
                AttestationProblem::Offline
            } else {
                to_verify.push(record);
                continue;
            };
            unverified.push(UnverifiedPackage {
                file_name: record.identifier.to_file_name(),
                problem,
            });
        }

        if !to_verify.is_empty() {
            match self.trusted_root().await {
                Ok(trusted_root) => {
                    unverified.extend(self.verify(&to_verify, &trusted_root).await);
                }
                Err(err) if self.policy.strictness == Strictness::Require => {
                    return Err(AttestationError::TrustedRoot(Box::new(err)));
                }
                Err(err) => {
                    tracing::warn!(
                        "skipping attestation verification of {} in {scope}: {err}",
                        pluralize_packages(to_verify.len()),
                    );
                }
            }
        }

        if unverified.is_empty() {
            return Ok(());
        }
        unverified.sort_by(|a, b| a.file_name.cmp(&b.file_name));

        match self.policy.strictness {
            Strictness::Require => Err(AttestationError::Unverified(unverified)),
            Strictness::Warn => {
                warn_unverified(unverified, scope);
                Ok(())
            }
        }
    }

    async fn trusted_root(&self) -> Result<TrustedRootRef, SigstoreError> {
        if self.offline {
            embedded_trusted_root().map(TrustedRootRef::Owned)
        } else {
            production_trusted_root().await.map(TrustedRootRef::Static)
        }
    }

    /// Verifies the attestations of `records`, which all advertise one, and
    /// returns those that fail.
    async fn verify(
        &self,
        records: &[&RepoDataRecord],
        trusted_root: &TrustedRoot,
    ) -> Vec<UnverifiedPackage> {
        stream::iter(records)
            .map(|record| async move {
                self.verify_once(record, trusted_root)
                    .await
                    .err()
                    .map(|problem| UnverifiedPackage {
                        file_name: record.identifier.to_file_name(),
                        problem,
                    })
            })
            .buffer_unordered(self.concurrency.max(1))
            .filter_map(std::future::ready)
            .collect()
            .await
    }

    /// Verifies a record, reusing the result if another solve already
    /// verified the same package.
    async fn verify_once(
        &self,
        record: &RepoDataRecord,
        trusted_root: &TrustedRoot,
    ) -> Result<(), AttestationProblem> {
        let Some(key) = package_key(record) else {
            return verify_record(&self.policy, record, self.client.client(), trusted_root).await;
        };
        let cell = self
            .results
            .lock()
            .expect("attestation results lock is poisoned")
            .entry(key)
            .or_default()
            .clone();
        cell.get_or_init(|| verify_record(&self.policy, record, self.client.client(), trusted_root))
            .await
            .clone()
    }
}

/// The production trusted root is cached by `rattler_sigstore`, the
/// embedded one is parsed on each use.
enum TrustedRootRef {
    Static(&'static TrustedRoot),
    Owned(TrustedRoot),
}

impl std::ops::Deref for TrustedRootRef {
    type Target = TrustedRoot;

    fn deref(&self) -> &TrustedRoot {
        match self {
            Self::Static(root) => root,
            Self::Owned(root) => root,
        }
    }
}

/// Logs the packages that failed verification in warn mode. Packages without
/// an attestation, which is common on channels that don't sign packages, are
/// summarized in one warning and listed with `-v`.
fn warn_unverified(unverified: Vec<UnverifiedPackage>, scope: &str) {
    let mut missing = Vec::new();
    let mut offline = Vec::new();
    for package in unverified {
        match package.problem {
            AttestationProblem::Missing => missing.push(package.file_name),
            AttestationProblem::Offline => offline.push(package.file_name),
            AttestationProblem::Rejected(reason) => tracing::warn!(
                "the attestation of {} in {scope} could not be verified: {reason}",
                package.file_name,
            ),
        }
    }
    if !missing.is_empty() {
        tracing::warn!(
            "{} in {scope} {} no attestation, run with `-v` to list them",
            pluralize_packages(missing.len()),
            if missing.len() == 1 { "has" } else { "have" }
        );
        tracing::info!(
            "newly locked packages in {scope} without an attestation: {}",
            missing.join(", ")
        );
    }
    if !offline.is_empty() {
        tracing::warn!(
            "the attestations of {} in {scope} cannot be fetched in offline mode, run with `-v` to list them",
            pluralize_packages(offline.len()),
        );
        tracing::info!(
            "newly locked packages in {scope} whose attestation was not fetched: {}",
            offline.join(", ")
        );
    }
}

/// Verifies the attestation of a single record.
///
/// `rattler_sigstore` verifies the signatures and leaves the trust policy to
/// the caller, which lets one signature be checked against the publisher
/// rules of every config layer.
async fn verify_record(
    policy: &AttestationPolicy,
    record: &RepoDataRecord,
    client: &ClientWithMiddleware,
    trusted_root: &TrustedRoot,
) -> Result<(), AttestationProblem> {
    let rejected = |err: SigstoreError| AttestationProblem::Rejected(format_error_chain(&err));
    let sidecar = fetch_sidecar(client, record, DEFAULT_MAX_SIDECAR_SIZE)
        .await
        .map_err(rejected)?
        .ok_or(AttestationProblem::Missing)?;

    let verification = verify_bundles(
        record,
        &sidecar.bundles,
        ChannelCheck::Require,
        trusted_root,
    )
    .map_err(rejected)?;

    let mut reasons = verification
        .rejected
        .iter()
        .map(|rejected| rejected.reason.to_string())
        .collect_vec();
    for attestation in &verification.verified {
        let identity = attestation.identity.as_deref();
        let issuer = attestation.issuer.as_deref();
        let Some(failed_rule) = policy
            .publishers
            .iter()
            .find(|publisher| !publisher.matches(identity, issuer))
        else {
            return Ok(());
        };
        let signer = format!(
            "signed by {} (issuer {})",
            identity.unwrap_or("an unknown identity"),
            issuer.unwrap_or("unknown"),
        );
        reasons.push(match (&failed_rule.identity, &failed_rule.issuer) {
            (Some(pattern), _) if !identity.is_some_and(|identity| pattern.matches(identity)) => {
                format!("{signer}, which does not match the trusted identity `{pattern}`")
            }
            (_, Some(trusted_issuer)) => {
                format!("{signer}, which does not match the trusted issuer `{trusted_issuer}`")
            }
            _ => format!("{signer}, which is not a trusted publisher"),
        });
    }
    Err(AttestationProblem::Rejected(reasons.join("; ")))
}

/// Formats an error with its causes, such as the DNS or TLS error behind a
/// failed sidecar fetch. `rattler_sigstore` redacts the URLs in these
/// errors, including the ones in their `reqwest` causes.
fn format_error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    std::iter::successors(Some(err), |err| err.source())
        .map(ToString::to_string)
        .join(": ")
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use pixi_config::TrustedPublisher;
    use rattler_conda_types::{PackageRecord, VersionWithSource, package::DistArchiveIdentifier};
    use rattler_digest::Sha256;

    use super::*;

    /// A package signed by the `hunger/octoconda` release workflow and
    /// published to `https://prefix.dev/github-releases`. The sidecar comes
    /// from the `rattler_sigstore` test data.
    const PACKAGE: &str = "actionlint-1.7.12-h60d57d3_0.conda";
    const PACKAGE_SHA256: &str = "e3e0f35dec5b09b18baac8729d14115903b5adfd25065f8bbb90a2b3be5401e4";
    const CHANNEL: &str = "https://prefix.dev/github-releases";
    const IDENTITY: &str =
        "https://github.com/hunger/octoconda/.github/workflows/octoconda.yaml@refs/heads/main";
    const SIDECAR: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/data/attestations/actionlint-1.7.12-h60d57d3_0.conda.sigs"
    ));

    /// A record for the fixture package served from a local mirror of
    /// [`CHANNEL`], with its sidecar written next to it.
    struct Fixture {
        _dir: tempfile::TempDir,
        record: RepoDataRecord,
    }

    impl Fixture {
        fn new(sidecar: Option<&[u8]>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let subdir = dir.path().join("osx-arm64");
            fs_err::create_dir_all(&subdir).unwrap();

            let identifier = DistArchiveIdentifier::try_from_filename(PACKAGE).unwrap();
            let mut package_record = PackageRecord::new(
                "actionlint".parse().unwrap(),
                VersionWithSource::from_str("1.7.12").unwrap(),
                "h60d57d3_0".parse().unwrap(),
            );
            package_record.subdir = "osx-arm64".to_string();
            package_record.sha256 =
                Some(rattler_digest::parse_digest_from_hex::<Sha256>(PACKAGE_SHA256).unwrap());

            let package_path = subdir.join(PACKAGE);
            if let Some(sidecar) = sidecar {
                let hash: Sha256Hash = rattler_digest::compute_bytes_digest::<Sha256>(sidecar);
                fs_err::write(
                    subdir.join(format!("{PACKAGE}.sigs.{}", hex::encode(hash))),
                    sidecar,
                )
                .unwrap();
                package_record.attestations_sha256 = Some(hash);
            }

            let record = RepoDataRecord {
                package_record,
                identifier,
                url: Url::from_file_path(&package_path).unwrap(),
                channel: Some(CHANNEL.to_string()),
            };
            Self { _dir: dir, record }
        }
    }

    fn config(
        mode: AttestationVerificationMode,
        identities: &[&str],
    ) -> AttestationVerificationConfig {
        AttestationVerificationConfig {
            mode: Some(mode),
            default_publishers: identities
                .iter()
                .map(|identity| TrustedPublisher {
                    identity: Some(identity.to_string()),
                    issuer: None,
                })
                .collect(),
        }
    }

    /// A checker that is offline, so that the embedded trusted root is used.
    fn checker(
        config: &AttestationVerificationConfig,
        locked: LockedPackages,
    ) -> AttestationChecker {
        let client =
            reqwest_middleware::ClientBuilder::new(reqwest_middleware::reqwest::Client::new())
                .build();
        AttestationChecker::new(config, || locked, client.into(), true, 1)
            .unwrap()
            .unwrap()
    }

    async fn check(
        config: &AttestationVerificationConfig,
        record: &RepoDataRecord,
    ) -> Result<(), String> {
        checker(config, LockedPackages::default())
            .check([record], "the test")
            .await
            .map_err(|err| err.to_string())
    }

    #[tokio::test]
    async fn accepts_trusted_publisher() {
        let fixture = Fixture::new(Some(SIDECAR));
        let config = config(
            AttestationVerificationMode::Require,
            &["https://github.com/hunger/*"],
        );
        check(&config, &fixture.record).await.unwrap();
    }

    #[tokio::test]
    async fn requires_every_publisher_rule() {
        let fixture = Fixture::new(Some(SIDECAR));
        let config = config(
            AttestationVerificationMode::Require,
            &["https://github.com/hunger/*", "https://github.com/my-org/*"],
        );
        insta::assert_snapshot!(check(&config, &fixture.record).await.unwrap_err(), @"
        the attestations of 1 newly locked package could not be verified:
          - actionlint-1.7.12-h60d57d3_0.conda: signed by https://github.com/hunger/octoconda/.github/workflows/octoconda.yaml@refs/heads/main (issuer https://token.actions.githubusercontent.com), which does not match the trusted identity `https://github.com/my-org/*`
        ");
    }

    #[tokio::test]
    async fn names_the_failed_issuer() {
        let fixture = Fixture::new(Some(SIDECAR));
        let config = AttestationVerificationConfig {
            mode: Some(AttestationVerificationMode::Require),
            default_publishers: vec![TrustedPublisher {
                identity: Some("https://github.com/hunger/*".to_string()),
                issuer: Some("https://gitlab.com".to_string()),
            }],
        };
        insta::assert_snapshot!(check(&config, &fixture.record).await.unwrap_err(), @"
        the attestations of 1 newly locked package could not be verified:
          - actionlint-1.7.12-h60d57d3_0.conda: signed by https://github.com/hunger/octoconda/.github/workflows/octoconda.yaml@refs/heads/main (issuer https://token.actions.githubusercontent.com), which does not match the trusted issuer `https://gitlab.com`
        ");
    }

    #[tokio::test]
    async fn rejects_unsigned_package() {
        let fixture = Fixture::new(None);
        let config = config(AttestationVerificationMode::Require, &[IDENTITY]);
        insta::assert_snapshot!(check(&config, &fixture.record).await.unwrap_err(), @"
        the attestations of 1 newly locked package could not be verified:
          - actionlint-1.7.12-h60d57d3_0.conda: no attestation
        ");
    }

    #[tokio::test]
    async fn rejects_attestation_for_another_package() {
        let mut fixture = Fixture::new(Some(SIDECAR));
        fixture.record.package_record.sha256 = Some(
            rattler_digest::compute_bytes_digest::<Sha256>(b"something else"),
        );
        let config = config(AttestationVerificationMode::Require, &[IDENTITY]);
        insta::assert_snapshot!(check(&config, &fixture.record).await.unwrap_err(), @"
        the attestations of 1 newly locked package could not be verified:
          - actionlint-1.7.12-h60d57d3_0.conda: sigstore verification failed: artifact mismatch: artifact hash does not match any subject in attestation
        ");
    }

    /// When offline, an attestation on a remote channel is not fetched.
    #[tokio::test]
    async fn offline_does_not_fetch_remote_attestations() {
        let mut fixture = Fixture::new(Some(SIDECAR));
        fixture.record.url = Url::parse(&format!("{CHANNEL}/osx-arm64/{PACKAGE}")).unwrap();
        let config = config(AttestationVerificationMode::Require, &[IDENTITY]);
        insta::assert_snapshot!(check(&config, &fixture.record).await.unwrap_err(), @"
        the attestations of 1 newly locked package could not be verified:
          - actionlint-1.7.12-h60d57d3_0.conda: cannot fetch the attestation in offline mode
        ");
    }

    /// A failed fetch keeps its cause, without printing the channel token.
    #[tokio::test]
    async fn failed_fetch_keeps_the_cause() {
        // Nothing listens on a port that was just released.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut fixture = Fixture::new(Some(SIDECAR));
        fixture.record.url = Url::parse(&format!(
            "http://127.0.0.1:{port}/t/secret-token/github-releases/osx-arm64/{PACKAGE}"
        ))
        .unwrap();

        let config = config(AttestationVerificationMode::Require, &[IDENTITY]);
        let policy = AttestationPolicy::from_config(&config).unwrap().unwrap();
        let client =
            reqwest_middleware::ClientBuilder::new(reqwest_middleware::reqwest::Client::new())
                .build();
        let problem = verify_record(
            &policy,
            &fixture.record,
            &client,
            &embedded_trusted_root().unwrap(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(!problem.contains("secret-token"), "{problem}");
        // The message of the operating system differs between platforms.
        let (problem, _) = problem
            .split_once("tcp connect error: ")
            .unwrap_or_else(|| panic!("no connect error in {problem}"));
        insta::assert_snapshot!(problem.replace(&port.to_string(), "[PORT]"), @"failed to fetch attestation sidecar from http://127.0.0.1:[PORT]/t/********/github-releases/osx-arm64/actionlint-1.7.12-h60d57d3_0.conda.sigs.d6dfbfcf1f3fdc2821ddaf525427461b9a68b879d70c265b67454cfbdcdb9c16: error sending request for url (http://127.0.0.1:[PORT]/t/********/github-releases/osx-arm64/actionlint-1.7.12-h60d57d3_0.conda.sigs.d6dfbfcf1f3fdc2821ddaf525427461b9a68b879d70c265b67454cfbdcdb9c16): client error (Connect):");
    }

    #[tokio::test]
    async fn warn_mode_does_not_fail() {
        let fixture = Fixture::new(None);
        let config = config(AttestationVerificationMode::Warn, &[]);
        check(&config, &fixture.record).await.unwrap();
    }

    #[test]
    fn require_needs_an_identity() {
        let config = AttestationVerificationConfig {
            mode: Some(AttestationVerificationMode::Require),
            default_publishers: vec![TrustedPublisher {
                identity: None,
                issuer: Some("https://token.actions.githubusercontent.com".to_string()),
            }],
        };
        assert!(matches!(
            AttestationPolicy::from_config(&config),
            Err(AttestationConfigError::NoTrustedIdentity)
        ));
        assert!(
            AttestationPolicy::from_config(&AttestationVerificationConfig::default())
                .unwrap()
                .is_none()
        );
    }

    /// Only records that are new or changed are checked. A record without a
    /// sha256 is always checked, it cannot be matched to the lock file.
    #[tokio::test]
    async fn only_new_or_changed_records_are_checked() {
        let unchanged = Fixture::new(None);
        let changed = Fixture::new(None);
        let added = Fixture::new(None);
        let mut without_sha256 = Fixture::new(None);
        without_sha256.record.package_record.sha256 = None;

        let mut previous_changed = changed.record.clone();
        previous_changed.package_record.sha256 =
            Some(rattler_digest::compute_bytes_digest::<Sha256>(b"old build"));
        let locked = LockedPackages(
            [&unchanged.record, &previous_changed, &without_sha256.record]
                .into_iter()
                .filter_map(package_key)
                .collect(),
        );

        let checker = checker(
            &config(AttestationVerificationMode::Require, &[IDENTITY]),
            locked,
        );
        let err = checker
            .check(
                [
                    &unchanged.record,
                    &changed.record,
                    &added.record,
                    &without_sha256.record,
                ],
                "the test",
            )
            .await
            .unwrap_err();
        let AttestationError::Unverified(unverified) = err else {
            panic!("unexpected error: {err}");
        };
        // The fixtures share a filename, so compare the number of records.
        assert_eq!(unverified.len(), 3);
    }
}
