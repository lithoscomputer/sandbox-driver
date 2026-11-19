//! Third-party plugin entries cross a real executable boundary: the CLI's
//! catalog verifies trust, launches the `test-host` fixture plugin over
//! protocol version 3, and passes it exactly the configured environment.
//! The fixture is built by `mise run plugins:build`.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{env, fs};

use sandbox_driver_protocol::file_sha256;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[tokio::test]
async fn a_pinned_plugin_entry_runs_commands_through_the_plugin() {
    let fixture = Fixture::new();
    let digest = file_sha256(&fixture_plugin()).await.unwrap();
    fixture.catalog(&fixture_plugin(), &format!("sha256 = '{digest}'"), "");

    let describe = fixture.run(&["provider", "describe", "plugged"]);
    assert_success(&describe);
    assert!(
        stdout(&describe).contains("plugin: test-host "),
        "{}",
        stdout(&describe)
    );

    let run = fixture.run(&[
        "run",
        "scratch",
        "--",
        "sh",
        "-c",
        "echo through the plugin; exit 4",
    ]);
    assert_eq!(run.status.code(), Some(4), "{}", stderr(&run));
    assert_eq!(stdout(&run), "through the plugin\n");
}

#[test]
fn an_unpinned_or_mismatched_plugin_is_never_launched() {
    let fixture = Fixture::new();
    let marker = fixture.root.join("launched");
    let script = fixture.script(&format!(
        "printf launched > {}\nexec {} \"$@\"\n",
        shell_path(&marker),
        shell_path(&fixture_plugin()),
    ));

    fixture.catalog(&script, "", "");
    let unpinned = fixture.run(&["provider", "health", "plugged"]);
    assert!(!unpinned.status.success());
    assert!(
        stderr(&unpinned).contains("sha256"),
        "{}",
        stderr(&unpinned)
    );
    assert!(!marker.exists());

    fixture.catalog(&script, &format!("sha256 = '{}'", "0".repeat(64)), "");
    let mismatch = fixture.run(&["provider", "health", "plugged"]);
    assert!(!mismatch.status.success());
    assert!(
        stderr(&mismatch).contains("checksum mismatch"),
        "{}",
        stderr(&mismatch)
    );
    assert!(!marker.exists());

    // Development trust cannot sit beside a pin to bypass it.
    fixture.catalog(
        &script,
        &format!("sha256 = '{}'\ndev = true", "0".repeat(64)),
        "",
    );
    let both = fixture.run(&["provider", "health", "plugged"]);
    assert!(!both.status.success());
    assert!(!marker.exists());

    fixture.catalog(&script, "dev = true", "");
    assert_success(&fixture.run(&["provider", "health", "plugged"]));
    assert!(marker.exists());
}

#[test]
fn the_plugin_receives_only_inherited_conveniences_explicit_env_and_secrets() {
    let fixture = Fixture::new();
    let observed = fixture.root.join("environment");
    // Discovery probes the plugin with a fixed minimal environment; the
    // activation launch is the one that carries the secret.
    let script = fixture.script(&format!(
        "if [ -n \"${{PLUGIN_TOKEN-}}\" ]; then printf '%s:%s:%s:%s' \"$HOME\" \"${{UNRELATED_TOKEN-unset}}\" \"$EXPLICIT\" \"$PLUGIN_TOKEN\" > {}; fi\nexec {} \"$@\"\n",
        shell_path(&observed),
        shell_path(&fixture_plugin()),
    ));
    fixture.catalog(
        &script,
        "dev = true\nsecrets = ['PLUGIN_TOKEN']",
        "[providers.plugged.env]\nEXPLICIT = 'explicit'\n",
    );

    let missing = fixture.run(&["provider", "health", "plugged"]);
    assert!(!missing.status.success());
    assert!(
        stderr(&missing).contains("requires secret PLUGIN_TOKEN"),
        "{}",
        stderr(&missing)
    );

    let output = fixture
        .command(&["provider", "health", "plugged"])
        .env("HOME", &fixture.root)
        .env("UNRELATED_TOKEN", "must-not-reach-plugin")
        .env("PLUGIN_TOKEN", "resolved-secret")
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(
        fs::read_to_string(observed).unwrap(),
        format!("{}:unset:explicit:resolved-secret", fixture.root.display())
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

    /// Writes a catalog with the plugin entry `plugged` at `path` and the
    /// `scratch` environment on it.
    fn catalog(&self, path: &Path, trust: &str, extra: &str) {
        let path = toml::Value::String(path.to_string_lossy().into_owned());
        fs::write(
            self.root.join("config.toml"),
            format!(
                "[providers.plugged]\nplugin = 'test-host'\npath = {path}\n{trust}\n\n{extra}\n\
                 [environments.scratch]\nprovider = 'plugged'\nspec = {{ source = 'host_directory' }}\n"
            ),
        )
        .expect("write catalog");
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lithos-sandbox"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .arg("--config")
            .arg(self.root.join("config.toml"))
            .args(args);
        if let Some(profile_file) = env::var_os("LLVM_PROFILE_FILE") {
            command.env("LLVM_PROFILE_FILE", profile_file);
        }
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("lithos-sandbox starts")
    }

    fn script(&self, body: &str) -> PathBuf {
        let path = self.root.join("plugin");
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}")).expect("write plugin script");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("make plugin executable");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// The fixture plugin, built beside this CLI by `mise run plugins:build`.
fn fixture_plugin() -> PathBuf {
    let path = Path::new(env!("CARGO_BIN_EXE_lithos-sandbox"))
        .parent()
        .expect("Cargo binary has a parent directory")
        .join("sandbox-driver-test-host");
    assert!(
        path.is_file(),
        "{} is missing; run `mise run plugins:build`",
        path.display()
    );
    path
}

fn shell_path(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn assert_success(output: &Output) {
    assert!(output.status.success(), "{}", stderr(output));
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
