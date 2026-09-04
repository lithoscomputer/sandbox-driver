//! Discovery and trust mechanics against the real plugin binary:
//! checksum enforcement, environment scrubbing observed from inside a
//! sandbox, and the post-handshake identity check.

use std::path::Path;
use std::time::Duration;

use sandbox_driver::{Error, ExecSpec, ProviderKind, SandboxProvider, SandboxSource, SandboxSpec};
use sandbox_driver_protocol::{PluginConfig, file_sha256, launch_plugin};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sandbox-driver-host")
}

#[tokio::test(flavor = "multi_thread")]
async fn launch_verifies_checksum_and_scrubs_environment() {
    let pin = file_sha256(Path::new(binary())).await.expect("hash");
    // SAFETY-free ambient marker: set via the test process's own
    // environment through the config only; the ambient var below must
    // NOT reach the plugin.
    let config = PluginConfig::new(ProviderKind::try_new("host").expect("kind"))
        .path(binary())
        .sha256(pin)
        .env_var("SD_DISCOVERY_MARKER", "expected")
        .inherit_env_var("PATH");

    let launch = launch_plugin("unused-prefix", &config)
        .await
        .expect("launch");
    assert!(launch.verified);

    // Observe the plugin's environment from inside a sandbox: the host
    // provider's exec inherits the plugin process environment.
    let sandbox = launch
        .provider
        .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
        .await
        .expect("create");
    let spec = ExecSpec::bash(
        "printf '%s:%s' \"${SD_DISCOVERY_MARKER:-unset}\" \"${CARGO_MANIFEST_DIR:-scrubbed}\"",
    )
    .timeout(Duration::from_secs(30));
    let result = sandbox.exec().run(&spec).await.expect("exec");
    assert_eq!(
        result.stdout_lossy(),
        "expected:scrubbed",
        "declared vars must arrive and ambient vars must not"
    );
    sandbox.delete().await.expect("delete");
    launch.provider.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_checksum_refuses_to_launch() {
    let config = PluginConfig::new(ProviderKind::try_new("host").expect("kind"))
        .path(binary())
        .sha256("0000000000000000000000000000000000000000000000000000000000000000");
    let Err(error) = launch_plugin("unused-prefix", &config).await else {
        panic!("mismatched checksum must refuse to launch");
    };
    assert!(error.to_string().contains("checksum mismatch"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn unpinned_without_dev_refuses_and_dev_launches_unverified() {
    let kind = ProviderKind::try_new("host").expect("kind");
    let unpinned = PluginConfig::new(kind.clone())
        .path(binary())
        .inherit_env_var("PATH");
    assert!(launch_plugin("unused-prefix", &unpinned).await.is_err());

    let dev = unpinned.dev(true);
    let launch = launch_plugin("unused-prefix", &dev)
        .await
        .expect("dev launch");
    assert!(!launch.verified);
    launch.provider.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread")]
async fn kind_mismatch_is_refused_after_handshake() {
    let config = PluginConfig::new(ProviderKind::try_new("docker").expect("kind"))
        .path(binary())
        .dev(true)
        .inherit_env_var("PATH");
    let Err(error) = launch_plugin("unused-prefix", &config).await else {
        panic!("kind mismatch must be refused");
    };
    let message = error.to_string();
    assert!(message.contains("declares kind host"), "{message}");
    assert!(matches!(error, Error::InvalidSpec { .. }));
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_binary_is_not_found() {
    let config = PluginConfig::new(ProviderKind::try_new("nonexistent").expect("kind")).dev(true);
    let Err(error) = launch_plugin("sd-test-prefix", &config).await else {
        panic!("missing binary must be NotFound");
    };
    assert!(matches!(error, Error::NotFound { .. }), "{error}");
}
