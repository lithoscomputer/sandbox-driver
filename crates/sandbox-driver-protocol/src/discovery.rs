//! Plugin discovery and trust mechanisms: resolve a plugin binary by
//! naming convention, verify a pinned checksum before exec, scrub the
//! environment, and confirm the plugin's identity after the handshake.
//!
//! These are **mechanisms**; policy stays with the embedder. The library
//! does not decide where plugin configuration lives, when `dev` mode is
//! permitted, or which environment variables a plugin deserves — it
//! guarantees that whatever the embedder decided is enforced:
//!
//! - **Deny by default.** Nothing is launched without a [`PluginConfig`]; there
//!   is no fallback search beyond the explicit path or the naming convention.
//! - **Checksum or dev, never neither.** A missing `sha256` is a hard error
//!   unless the embedder explicitly set `dev` (gating *that* on an operator
//!   opt-in is the embedder's policy). A mismatch is a hard error naming both
//!   hashes.
//! - **No ambient environment.** The child starts from an empty environment
//!   plus exactly the variables the config declares or forwards. Secrets never
//!   ride along by accident.
//! - **Identity check.** After the handshake, the plugin's declared kind must
//!   match the configured kind; a mismatch kills the child.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::{env, fs, process};

use sandbox_driver::{Error, ProviderKind, ResourceKind, Result, SandboxProvider as _};
use sha2::{Digest, Sha256};
use tokio::fs as tokio_fs;
use tokio::process::Command;

use crate::client::PluginProvider;

/// How to find, trust, and start one plugin binary.
///
/// The embedder builds this from its own configuration (for fabro, a
/// `[extension.sandbox.<name>]` table). Construct with
/// [`PluginConfig::new`] and refine with the setters.
#[derive(Clone, Debug)]
pub struct PluginConfig {
    /// The provider kind this plugin must serve, e.g. `e2b`.
    pub kind:        ProviderKind,
    /// Explicit binary path. When absent, the binary is resolved on
    /// `PATH` by the naming convention `<prefix>-<kind>`.
    pub path:        Option<PathBuf>,
    /// Pinned SHA-256 of the binary, lowercase or uppercase hex.
    pub sha256:      Option<String>,
    /// Allow launching without a checksum. The embedder gates this on
    /// its own operator opt-in; the library only enforces the pairing.
    pub dev:         bool,
    /// Arguments passed to the binary.
    pub args:        Vec<String>,
    /// Environment variables set for the child. This is the *complete*
    /// environment apart from `inherit_env`.
    pub env:         BTreeMap<String, String>,
    /// Ambient variables forwarded from this process when set (`PATH` is
    /// the usual candidate). Everything else is scrubbed.
    pub inherit_env: Vec<String>,
}

impl PluginConfig {
    pub fn new(kind: ProviderKind) -> Self {
        Self {
            kind,
            path: None,
            sha256: None,
            dev: false,
            args: Vec::new(),
            env: BTreeMap::new(),
            inherit_env: Vec::new(),
        }
    }

    #[must_use]
    pub fn path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    #[must_use]
    pub fn sha256(mut self, sha256: impl Into<String>) -> Self {
        self.sha256 = Some(sha256.into());
        self
    }

    #[must_use]
    pub fn dev(mut self, dev: bool) -> Self {
        self.dev = dev;
        self
    }

    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    #[must_use]
    pub fn env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn inherit_env_var(mut self, key: impl Into<String>) -> Self {
        self.inherit_env.push(key.into());
        self
    }
}

/// Resolves the plugin binary: the explicit path when configured, else
/// `<prefix>-<kind>` searched on `PATH`. No other fallback exists.
pub fn resolve_plugin_binary(prefix: &str, config: &PluginConfig) -> Result<PathBuf> {
    if let Some(path) = &config.path {
        if is_executable_file(path) {
            return Ok(path.clone());
        }
        return Err(Error::NotFound {
            resource: ResourceKind::Plugin,
            id:       path.display().to_string(),
        });
    }
    let name = format!("{prefix}-{}", config.kind);
    let search = env::var_os("PATH").unwrap_or_default();
    resolve_on_search_path(&name, &search).ok_or_else(|| Error::NotFound {
        resource: ResourceKind::Plugin,
        id:       format!("{name} (searched PATH)"),
    })
}

fn resolve_on_search_path(name: &str, search: &OsStr) -> Option<PathBuf> {
    env::split_paths(search)
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable_file(candidate))
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    true
}

/// The SHA-256 of a file, as lowercase hex. Useful for generating pins.
pub async fn file_sha256(path: &Path) -> Result<String> {
    let bytes = tokio_fs::read(path)
        .await
        .map_err(|error| Error::io(format!("reading {}", path.display()), error))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

/// Enforces the checksum policy: verified pin, or explicit dev mode.
/// Returns whether the binary was verified.
async fn enforce_checksum(path: &Path, config: &PluginConfig) -> Result<bool> {
    match &config.sha256 {
        Some(expected) => {
            let actual = file_sha256(path).await?;
            if !actual.eq_ignore_ascii_case(expected.trim()) {
                return Err(Error::invalid_spec(
                    "sha256",
                    format!(
                        "checksum mismatch for {}: pinned {expected}, found {actual}",
                        path.display()
                    ),
                ));
            }
            Ok(true)
        }
        None if config.dev => Ok(false),
        None => Err(Error::invalid_spec(
            "sha256",
            format!(
                "plugin {} has no pinned sha256; pin one or explicitly mark the plugin dev",
                config.kind
            ),
        )),
    }
}

/// Outcome of a [`launch_plugin`] call.
pub struct PluginLaunch {
    pub provider: PluginProvider,
    /// The binary that was executed.
    pub path:     PathBuf,
    /// Whether the binary's checksum was verified (`false` only in dev
    /// mode). Embedders should surface unverified plugins to operators.
    pub verified: bool,
}

/// Resolves, verifies, and launches a plugin with a scrubbed
/// environment, then confirms its declared kind matches the config.
///
/// `prefix` is the embedder's binary naming convention prefix (fabro
/// uses `fabro-sandbox`, giving binaries like `fabro-sandbox-e2b`).
pub async fn launch_plugin(prefix: &str, config: &PluginConfig) -> Result<PluginLaunch> {
    let path = resolve_plugin_binary(prefix, config)?;
    let verified = enforce_checksum(&path, config).await?;

    let mut command = Command::new(&path);
    command.args(&config.args);
    command.env_clear();
    for key in &config.inherit_env {
        if let Some(value) = env::var_os(key) {
            command.env(key, value);
        }
    }
    for (key, value) in &config.env {
        command.env(key, value);
    }

    let provider = PluginProvider::spawn(command).await?;
    if *provider.kind() != config.kind {
        let declared = provider.kind().clone();
        // The child dies with the provider (kill-on-drop); ask nicely
        // first so a well-behaved plugin exits cleanly.
        let _ = provider.shutdown().await;
        return Err(Error::invalid_spec(
            "kind",
            format!(
                "plugin at {} declares kind {declared} but was configured as {}",
                path.display(),
                config.kind
            ),
        ));
    }
    Ok(PluginLaunch {
        provider,
        path,
        verified,
    })
}

#[cfg(test)]
mod tests {
    use std::process;

    use super::*;

    #[test]
    fn resolves_by_naming_convention_on_the_search_path() {
        let dir = env::temp_dir().join(format!("sd-discovery-{}", process::id()));
        fs::create_dir_all(&dir).expect("mkdir");
        let binary = dir.join("testpfx-somekind");
        fs::write(&binary, b"#!/bin/sh\n").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        let found = resolve_on_search_path("testpfx-somekind", dir.as_os_str());
        assert_eq!(found, Some(binary.clone()));
        // A non-executable file is not a candidate.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&binary, fs::Permissions::from_mode(0o644)).expect("chmod");
            assert_eq!(
                resolve_on_search_path("testpfx-somekind", dir.as_os_str()),
                None
            );
        }
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[tokio::test]
    async fn checksums_are_enforced_in_both_directions() {
        let dir = env::temp_dir().join(format!("sd-checksum-{}", process::id()));
        fs::create_dir_all(&dir).expect("mkdir");
        let binary = dir.join("plugin");
        fs::write(&binary, b"payload").expect("write");
        let good = file_sha256(&binary).await.expect("hash");

        let kind = ProviderKind::try_new("somekind").expect("kind");
        let pinned = PluginConfig::new(kind.clone()).sha256(good.to_uppercase());
        assert!(enforce_checksum(&binary, &pinned).await.expect("verifies"));

        let wrong = PluginConfig::new(kind.clone()).sha256("deadbeef");
        let error = enforce_checksum(&binary, &wrong)
            .await
            .expect_err("mismatch");
        let message = error.to_string();
        assert!(
            message.contains("deadbeef") && message.contains(&good),
            "{message}"
        );

        let unpinned = PluginConfig::new(kind.clone());
        enforce_checksum(&binary, &unpinned)
            .await
            .expect_err("unpinned is refused");

        let dev = PluginConfig::new(kind).dev(true);
        assert!(
            !enforce_checksum(&binary, &dev)
                .await
                .expect("dev mode allowed")
        );

        fs::remove_dir_all(&dir).expect("cleanup");
    }
}
