use std::io::Write;

use pixi_test_utils::{MockRepoData, Package, format_diagnostic};
use rattler_conda_types::Subdir;
use tempfile::TempDir;

use crate::common::{LockFileExt, PixiControl, builders::HasNoInstallConfig};

/// Creates a `linux-64` workspace on a local channel with unsigned `foo` and
/// `bar` packages, with `config` appended to the workspace config.
async fn workspace_with_unsigned_packages(config: &str) -> (PixiControl, TempDir) {
    let mut package_database = MockRepoData::default();
    package_database.add_package(Package::build("foo", "1").finish());
    package_database.add_package(Package::build("bar", "1").finish());
    let channel_dir = TempDir::new().unwrap();
    package_database
        .write_repodata(channel_dir.path())
        .await
        .unwrap();

    let pixi = PixiControl::new().unwrap();
    pixi.init()
        .with_local_channel(channel_dir.path())
        .with_platforms(vec![Subdir::Linux64])
        .await
        .unwrap();
    set_workspace_config(&pixi, config);
    (pixi, channel_dir)
}

fn set_workspace_config(pixi: &PixiControl, config: &str) {
    let mut file = fs_err::OpenOptions::new()
        .append(true)
        .open(pixi.workspace_path().join(".pixi").join("config.toml"))
        .unwrap();
    writeln!(file, "{config}").unwrap();
}

const REQUIRE: &str = r#"
[attestation-verification]
mode = "require"
default.identity = "https://github.com/my-org/*"
"#;

#[tokio::test]
async fn require_rejects_unsigned_package() {
    let (pixi, _channel) = workspace_with_unsigned_packages(REQUIRE).await;

    let err = pixi.add("foo").with_install(false).await.unwrap_err();
    insta::assert_snapshot!(format_diagnostic(err.as_ref()), @"
    × failed to verify package attestations of environment 'default' for platform 'linux-64'
    ╰─▶   × the attestations of 1 newly locked package could not be verified:
          │   - foo-1-0.conda: no attestation
          help: packages without a verified attestation from a trusted publisher are rejected because `attestation-verification.mode` is `require`
    ");
}

#[tokio::test]
async fn warn_locks_unsigned_package() {
    let (pixi, _channel) = workspace_with_unsigned_packages(
        r#"
        [attestation-verification]
        mode = "warn"
        "#,
    )
    .await;

    pixi.add("foo").with_install(false).await.unwrap();
    let lock = pixi.lock_file().await.unwrap();
    assert!(lock.contains_conda_package("default", Subdir::Linux64, "foo"));
}

#[tokio::test]
async fn require_without_identity_is_an_error() {
    let (pixi, _channel) = workspace_with_unsigned_packages(
        r#"
        [attestation-verification]
        mode = "require"
        "#,
    )
    .await;

    let err = pixi.add("foo").with_install(false).await.unwrap_err();
    insta::assert_snapshot!(format_diagnostic(err.as_ref()), @"
    × no trusted publisher identity is configured for the `require` attestation verification mode
    help: set `attestation-verification.default.identity`, for example to `https://github.com/my-org/*`
    ");
}

/// Packages that are already locked are not checked again, only packages
/// that are new to the lock file.
#[tokio::test]
async fn require_only_checks_newly_locked_packages() {
    let (pixi, _channel) = workspace_with_unsigned_packages("").await;
    pixi.add("foo").with_install(false).await.unwrap();

    set_workspace_config(&pixi, REQUIRE);
    pixi.lock().await.unwrap();

    let err = pixi.add("bar").with_install(false).await.unwrap_err();
    insta::assert_snapshot!(format_diagnostic(err.as_ref()), @"
    × failed to verify package attestations of environment 'default' for platform 'linux-64'
    ╰─▶   × the attestations of 1 newly locked package could not be verified:
          │   - bar-1-0.conda: no attestation
          help: packages without a verified attestation from a trusted publisher are rejected because `attestation-verification.mode` is `require`
    ");
}

/// `pixi update` re-solves every package. Packages that re-solve to the build
/// that is already locked are not checked again.
#[tokio::test]
async fn require_does_not_recheck_packages_on_update() {
    let (pixi, _channel) = workspace_with_unsigned_packages("").await;
    pixi.add("foo").with_install(false).await.unwrap();

    set_workspace_config(&pixi, REQUIRE);
    pixi.update().await.unwrap();
    let lock = pixi.lock_file().await.unwrap();
    assert!(lock.contains_conda_package("default", Subdir::Linux64, "foo"));
}

/// `pixi add` unlocks the packages it adds. A package that is added again and
/// re-solves to the build that is already locked is not checked again.
#[tokio::test]
async fn require_does_not_recheck_packages_on_add() {
    let (pixi, _channel) = workspace_with_unsigned_packages("").await;
    pixi.add("foo").with_install(false).await.unwrap();

    set_workspace_config(&pixi, REQUIRE);
    pixi.add("foo>=1").with_install(false).await.unwrap();
    let lock = pixi.lock_file().await.unwrap();
    assert!(lock.contains_conda_package("default", Subdir::Linux64, "foo"));
}

/// Prepending a channel discards the locked packages for the solve, unlike
/// appending one. Packages that re-solve to the build that is already locked
/// are not checked again.
#[tokio::test]
async fn require_does_not_recheck_packages_after_channel_edit() {
    let (pixi, _channel) = workspace_with_unsigned_packages("").await;
    pixi.add("foo").with_install(false).await.unwrap();

    set_workspace_config(&pixi, REQUIRE);
    let mut other_packages = MockRepoData::default();
    other_packages.add_package(Package::build("baz", "1").finish());
    let other_channel = TempDir::new().unwrap();
    other_packages
        .write_repodata(other_channel.path())
        .await
        .unwrap();
    pixi.project_channel_add()
        .with_local_channel(other_channel.path())
        .with_prepend()
        .await
        .unwrap();
    pixi.lock().await.unwrap();

    let lock = pixi.lock_file().await.unwrap();
    assert!(lock.contains_conda_package("default", Subdir::Linux64, "foo"));
}

/// A package signed by the `hunger/octoconda` release workflow and published
/// to [`SIGNED_CHANNEL`].
const SIGNED_PACKAGE: &str = "actionlint-1.7.12-h60d57d3_0.conda";
const SIGNED_PACKAGE_SHA256: &str =
    "e3e0f35dec5b09b18baac8729d14115903b5adfd25065f8bbb90a2b3be5401e4";
const SIGNED_CHANNEL: &str = "https://prefix.dev/github-releases";
const SIDECAR: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/data/attestations/actionlint-1.7.12-h60d57d3_0.conda.sigs"
));

/// Serves a mirror of [`SIGNED_CHANNEL`] that only contains
/// [`SIGNED_PACKAGE`] and its attestation, and returns its URL.
async fn serve_signed_channel_mirror(root: &std::path::Path) -> url::Url {
    let sidecar_sha256 =
        hex::encode(rattler_digest::compute_bytes_digest::<rattler_digest::Sha256>(SIDECAR));

    let subdir = root.join("osx-arm64");
    fs_err::create_dir_all(&subdir).unwrap();
    let repodata = serde_json::json!({
        "info": { "subdir": "osx-arm64" },
        "packages": {},
        "packages.conda": {
            SIGNED_PACKAGE: {
                "name": "actionlint",
                "version": "1.7.12",
                "build": "h60d57d3_0",
                "build_number": 0,
                "depends": [],
                "subdir": "osx-arm64",
                "sha256": SIGNED_PACKAGE_SHA256,
                "attestations_sha256": sidecar_sha256,
            }
        },
        "repodata_version": 1,
    });
    fs_err::write(subdir.join("repodata.json"), repodata.to_string()).unwrap();
    fs_err::write(
        subdir.join(format!("{SIGNED_PACKAGE}.sigs.{sidecar_sha256}")),
        SIDECAR,
    )
    .unwrap();
    let noarch = root.join("noarch");
    fs_err::create_dir_all(&noarch).unwrap();
    fs_err::write(
        noarch.join("repodata.json"),
        r#"{"info": {"subdir": "noarch"}, "packages": {}, "packages.conda": {}}"#,
    )
    .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let root = root.to_path_buf();
    let router = axum::Router::new().fallback(axum::routing::get(move |uri: axum::http::Uri| {
        let path = root.join(uri.path().trim_start_matches('/'));
        async move {
            match fs_err::read(&path) {
                Ok(bytes) => Ok(bytes),
                Err(_) => Err(axum::http::StatusCode::NOT_FOUND),
            }
        }
    }));
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    url::Url::parse(&format!("http://{addr}/")).unwrap()
}

/// Locks [`SIGNED_PACKAGE`] from a mirror of its channel with `identity` as
/// the trusted publisher. This fetches Sigstore's trusted root.
async fn lock_signed_package_from_mirror(identity: &str) -> miette::Result<()> {
    let mirror_dir = TempDir::new().unwrap();
    let mirror = serve_signed_channel_mirror(mirror_dir.path()).await;

    let pixi = PixiControl::new().unwrap().with_network_access();
    pixi.update_manifest(&format!(
        r#"
        [workspace]
        name = "attestations"
        channels = ["{SIGNED_CHANNEL}"]
        platforms = ["osx-arm64"]

        [dependencies]
        actionlint = "*"
        "#
    ))
    .unwrap();

    // Overwrite the default test config. The cache is isolated so that the
    // mirrored repodata doesn't end up in the cache of the real channel.
    let cache_dir = TempDir::new().unwrap();
    fs_err::write(
        pixi.workspace_path().join(".pixi").join("config.toml"),
        format!(
            r#"
            [mirrors]
            "{SIGNED_CHANNEL}" = ["{mirror}"]

            [cache]
            root = "{cache}"

            [repodata-config."https://prefix.dev"]
            disable-sharded = true

            [attestation-verification]
            mode = "require"
            default.identity = "{identity}"
            "#,
            cache = cache_dir.path().display().to_string().replace('\\', "/"),
        ),
    )
    .unwrap();

    pixi.lock().await?;
    let lock = pixi.lock_file().await.unwrap();
    assert!(lock.contains_conda_package("default", Subdir::OsxArm64, "actionlint"));
    Ok(())
}

/// The attestation of a package from a mirror is checked against the
/// channel it mirrors.
#[tokio::test]
#[cfg_attr(not(feature = "online_tests"), ignore)]
async fn require_accepts_trusted_publisher_through_mirror() {
    lock_signed_package_from_mirror("https://github.com/hunger/*")
        .await
        .unwrap();
}

#[tokio::test]
#[cfg_attr(not(feature = "online_tests"), ignore)]
async fn require_rejects_untrusted_publisher() {
    let err = lock_signed_package_from_mirror("https://github.com/my-org/*")
        .await
        .unwrap_err();
    insta::assert_snapshot!(format_diagnostic(err.as_ref()), @"
    × failed to verify package attestations of environment 'default' for platform 'osx-arm64'
    ╰─▶   × the attestations of 1 newly locked package could not be verified:
          │   - actionlint-1.7.12-h60d57d3_0.conda: signed by https://github.com/hunger/octoconda/.github/workflows/octoconda.yaml@refs/heads/main (issuer https://token.actions.githubusercontent.com),
          │ which does not match the trusted identity `https://github.com/my-org/*`
          help: packages without a verified attestation from a trusted publisher are rejected because `attestation-verification.mode` is `require`
    ");
}
