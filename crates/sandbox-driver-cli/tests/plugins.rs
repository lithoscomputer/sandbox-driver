//! CLI provider selection and trust checks cross a real executable boundary.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{env, fs};

use sandbox_driver_protocol::file_sha256;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[tokio::test]
async fn default_profile_requires_a_pin_or_explicit_development_mode() {
    let fixture = Fixture::new();
    let script = fixture.script(
        "provider",
        &format!(
            "printf launched > {}\nexec {}\n",
            shell_path(&fixture.root.join("launched")),
            shell_path(&host_binary()),
        ),
    );
    let mut command = fixture.command();
    command.env("SANDBOX_DRIVER_HOST_PLUGIN", &script);
    let unpinned = command.output().unwrap();
    assert!(!unpinned.status.success());
    assert!(stderr(&unpinned).contains("no pinned sha256"));
    assert!(!fixture.root.join("launched").exists());

    // Development mode never bypasses a configured checksum mismatch.
    command.env("SANDBOX_DRIVER_PLUGIN_DEV", "1");
    command.env("SANDBOX_DRIVER_HOST_SHA256", "deadbeef");
    let mismatch = command.output().unwrap();
    assert!(!mismatch.status.success());
    assert!(stderr(&mismatch).contains("checksum mismatch"));
    assert!(!fixture.root.join("launched").exists());

    command.env_remove("SANDBOX_DRIVER_PLUGIN_DEV");
    command.env(
        "SANDBOX_DRIVER_HOST_SHA256",
        file_sha256(&script).await.unwrap(),
    );
    let pinned = command.output().unwrap();
    assert!(pinned.status.success(), "{}", stderr(&pinned));
    assert_eq!(
        fs::read_to_string(fixture.root.join("launched")).unwrap(),
        "launched"
    );
    assert!(String::from_utf8_lossy(&pinned.stdout).contains("status: ok"));
}

#[test]
fn default_profile_honors_the_executable_override_and_scrubs_environment() {
    let fixture = Fixture::new();
    let observed = fixture.root.join("environment");
    let script = fixture.script(
        "provider",
        &format!(
            "printf '%s:%s' \"$HOME\" \"${{UNRELATED_TOKEN-unset}}\" > {}\nexec {}\n",
            shell_path(&observed),
            shell_path(&host_binary()),
        ),
    );
    let output = fixture
        .command()
        .env("SANDBOX_DRIVER_PLUGIN_DEV", "1")
        .env("SANDBOX_DRIVER_HOST_PLUGIN", script)
        .env("HOME", &fixture.root)
        .env("UNRELATED_TOKEN", "must-not-reach-plugin")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        fs::read_to_string(observed).unwrap(),
        format!("{}:unset", fixture.root.display())
    );
}

#[test]
fn missing_override_fails_instead_of_using_an_embedded_provider() {
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .env("SANDBOX_DRIVER_PLUGIN_DEV", "1")
        .env("SANDBOX_DRIVER_HOST_PLUGIN", fixture.root.join("missing"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("missing"));
}

#[test]
fn explicit_profile_keeps_its_own_trust_and_environment_configuration() {
    let fixture = Fixture::new();
    let config = fixture.root.join("config.toml");
    let profile = format!(
        "[providers.local]\ntype = 'plugin'\nkind = 'host'\npath = {}\ninherit-env = ['PATH', 'LLVM_PROFILE_FILE']\n[providers.local.env]\nRUST_LOG = 'off'\n",
        toml::Value::String(host_binary().to_string_lossy().into_owned()),
    );
    fs::write(&config, &profile).unwrap();
    let mut command = fixture.command();
    command
        .args(["--provider", "local", "--config"])
        .arg(&config)
        .env("SANDBOX_DRIVER_PLUGIN_DEV", "1");
    let unpinned = command.output().unwrap();
    assert!(!unpinned.status.success());
    assert!(stderr(&unpinned).contains("no pinned sha256"));

    fs::write(
        &config,
        profile.replace("type = 'plugin'", "type = 'plugin'\ndev = true"),
    )
    .unwrap();
    let allowed = command.output().unwrap();
    assert!(allowed.status.success(), "{}", stderr(&allowed));
}

#[test]
fn daytona_profile_overrides_standard_environment_with_named_settings() {
    let fixture = Fixture::new();
    let observed = fixture.root.join("environment");
    let script = fixture.script("daytona", &format!(
        "printf '%s\\n' \"$DAYTONA_API_KEY\" \"${{DAYTONA_JWT_TOKEN-unset}}\" \"$DAYTONA_API_URL\" \"$DAYTONA_TARGET\" > {}\nexit 1\n",
        shell_path(&observed),
    ));
    let config = fixture.root.join("config.toml");
    fs::write(&config, "[providers.cloud]\ntype = 'daytona'\napi-key-env = 'TEST_CLOUD_KEY'\napi-url = 'https://example.invalid/api'\ntarget = 'test-region'\n").unwrap();
    let output = fixture
        .command()
        .args(["--provider", "cloud", "--config"])
        .arg(config)
        .env("SANDBOX_DRIVER_PLUGIN_DEV", "1")
        .env("SANDBOX_DRIVER_DAYTONA_PLUGIN", script)
        .env("TEST_CLOUD_KEY", "configured-test-key")
        .env("DAYTONA_API_KEY", "ambient-test-key")
        .env("DAYTONA_JWT_TOKEN", "ambient-test-token")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "the environment probe exits before the handshake"
    );
    assert_eq!(
        fs::read_to_string(observed).unwrap(),
        "configured-test-key\nambient-test-token\nhttps://example.invalid/api\ntest-region\n"
    );
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = env::temp_dir().join(format!("sd-cli-plugins-{}-{id}", process::id()));
        fs::create_dir_all(&root).expect("create fixture directory");
        Self { root }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lithos-sandbox"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("RUST_LOG", "off")
            .env("XDG_CONFIG_HOME", &self.root)
            .args(["provider", "health"]);
        if let Some(profile_file) = env::var_os("LLVM_PROFILE_FILE") {
            command.env("LLVM_PROFILE_FILE", profile_file);
        }
        command
    }

    fn script(&self, name: &str, body: &str) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}")).expect("write plugin script");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("make plugin executable");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove fixture directory");
    }
}

fn host_binary() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_lithos-sandbox"))
        .parent()
        .expect("Cargo binary has a parent directory")
        .join("sandbox-driver-host")
}

fn shell_path(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
