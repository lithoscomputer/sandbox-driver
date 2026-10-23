//! Credential-free discovery for the new shared contract. This is separate
//! from the legacy v2 loader: discovering schemas never initializes a runtime.
//!
//! Probes execute trusted code, not sandboxed code. Installations must protect
//! executable files and their parent directories against concurrent
//! replacement. The digest covers the executable, not an interpreter or its
//! dependencies.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sandbox_driver::contract::{
    Descriptor, Error, MutationOutcome, PluginTrust, ProviderEntry, ProviderName, ProviderSchemas,
    Sha256Digest,
};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::time;

use crate::discovery::{PluginConfig, file_sha256, resolve_plugin_binary};

/// Budgets shared by all probes using one discovery cache.
#[derive(Clone, Debug)]
pub struct DiscoveryLimits {
    /// Includes executable lookup, hashing, probe exit, and both output pipes.
    pub timeout:           Duration,
    pub stdout_bytes:      usize,
    pub stderr_bytes:      usize,
    pub concurrent_probes: usize,
    pub cached_binaries:   usize,
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        Self {
            timeout:           Duration::from_secs(5),
            stdout_bytes:      1024 * 1024,
            stderr_bytes:      64 * 1024,
            concurrent_probes: 4,
            cached_binaries:   64,
        }
    }
}

/// Bounded in-memory metadata cache. Construction performs no lookup or launch.
/// Each lookup rehashes the executable and enforces that entry's trust policy,
/// including cache hits. Failed probes are never cached.
pub struct SchemaDiscovery {
    limits: DiscoveryLimits,
    probes: Semaphore,
    cache:  Mutex<BTreeMap<Sha256Digest, Arc<ProviderSchemas>>>,
}

impl Default for SchemaDiscovery {
    fn default() -> Self {
        Self::try_new(DiscoveryLimits::default()).expect("default discovery limits are valid")
    }
}

impl SchemaDiscovery {
    pub fn try_new(limits: DiscoveryLimits) -> Result<Self, Error> {
        if limits.timeout.is_zero()
            || limits.stdout_bytes == 0
            || limits.stderr_bytes == 0
            || limits.concurrent_probes == 0
            || limits.concurrent_probes > Semaphore::MAX_PERMITS
            || limits.cached_binaries == 0
        {
            return Err(Error::InvalidSpec {
                path:    "discovery_limits".into(),
                message:
                    "discovery budgets must be positive and concurrency within semaphore limits"
                        .into(),
            });
        }
        Ok(Self {
            probes: Semaphore::new(limits.concurrent_probes),
            limits,
            cache: Mutex::new(BTreeMap::new()),
        })
    }

    /// Resolves only the selected entry. The probe receives exactly
    /// `--describe-schema`, null stdin, a platform-only environment, and no
    /// entry config, arguments, explicit/inherited environment, or secrets.
    /// Saturation fails before launching instead of queuing unbounded work.
    pub async fn discover(
        &self,
        prefix: &str,
        name: &ProviderName,
        entry: &ProviderEntry,
    ) -> Result<DiscoveredPlugin, Error> {
        let _permit = self
            .probes
            .try_acquire()
            .map_err(|_| Error::ResourceExhausted {
                message:        "metadata discovery capacity exhausted".into(),
                retry_after_ms: None,
            })?;
        time::timeout(
            self.limits.timeout,
            self.discover_inner(prefix, name, entry),
        )
        .await
        .map_err(|_| unavailable("metadata discovery timed out"))?
    }

    async fn discover_inner(
        &self,
        prefix: &str,
        name: &ProviderName,
        entry: &ProviderEntry,
    ) -> Result<DiscoveredPlugin, Error> {
        let trust = entry.trust.as_ref().ok_or_else(|| {
            invalid_config(
                name,
                "sha256",
                "pin the plugin checksum or explicitly set dev = true",
            )
        })?;
        let config = PluginConfig::new(entry.plugin.clone());
        let config = match &entry.path {
            Some(path) => config.path(path),
            None => config,
        };
        let prefix = prefix.to_owned();
        let path = tokio::task::spawn_blocking(move || {
            resolve_plugin_binary(&prefix, &config).and_then(|path| {
                path.canonicalize()
                    .map_err(|error| sandbox_driver::Error::io("resolving plugin", error))
            })
        })
        .await
        .map_err(|_| unavailable("plugin lookup failed"))?
        .map_err(|_| unavailable("plugin executable is missing or inaccessible"))?;
        let digest = digest(&path).await?;
        if let PluginTrust::Sha256 { digest: expected } = trust {
            if expected != &digest {
                return Err(invalid_config(
                    name,
                    "sha256",
                    "plugin executable checksum mismatch",
                ));
            }
        }
        let cached = self
            .cache
            .lock()
            .expect("metadata cache lock")
            .get(&digest)
            .cloned();
        let schemas = match cached {
            Some(schemas) => schemas,
            None => {
                let schemas = Arc::new(probe(&path, &self.limits).await?);
                if self::digest(&path).await? != digest {
                    return Err(invalid_config(
                        name,
                        "sha256",
                        "plugin executable changed during discovery",
                    ));
                }
                let mut cache = self.cache.lock().expect("metadata cache lock");
                if cache.len() >= self.limits.cached_binaries {
                    cache.pop_first();
                }
                cache.insert(digest.clone(), Arc::clone(&schemas));
                schemas
            }
        };
        if schemas.kind != entry.plugin {
            return Err(invalid_config(
                name,
                "plugin",
                "discovered kind does not match the configured plugin",
            ));
        }
        Ok(DiscoveredPlugin {
            path,
            digest,
            schemas,
            verified: matches!(trust, PluginTrust::Sha256 { .. }),
        })
    }
}

/// Verified metadata, not live namespace or capability facts. The private
/// fields prevent callers from substituting an unverified executable/schema.
#[derive(Clone, Debug)]
pub struct DiscoveredPlugin {
    path:     PathBuf,
    digest:   Sha256Digest,
    schemas:  Arc<ProviderSchemas>,
    verified: bool,
}

impl DiscoveredPlugin {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
    pub fn schemas(&self) -> &ProviderSchemas {
        &self.schemas
    }
    /// False only for explicit development trust. Even development probes
    /// are cached by the actual digest, never by a path or kind.
    pub fn verified(&self) -> bool {
        self.verified
    }

    /// Recheck immediately before runtime launch. A replacement must go
    /// through discovery and trust verification again, even in development.
    pub async fn verify_unchanged(&self) -> Result<(), Error> {
        if digest(&self.path).await? != self.digest {
            return Err(unavailable(
                "plugin executable changed since metadata discovery",
            ));
        }
        Ok(())
    }

    /// Initialization must agree with discovery before any sandbox call.
    /// Namespace/capabilities are live facts, not cached metadata.
    pub fn check_descriptor(&self, descriptor: &Descriptor) -> Result<(), Error> {
        if descriptor.schemas != *self.schemas {
            return Err(Error::Transport {
                message: "initialized plugin metadata differs from discovery".into(),
                outcome: MutationOutcome::NotStarted,
            });
        }
        Ok(())
    }
}

async fn digest(path: &Path) -> Result<Sha256Digest, Error> {
    let hash = file_sha256(path)
        .await
        .map_err(|_| unavailable("cannot read plugin executable"))?;
    Ok(Sha256Digest::try_new(hash).expect("SHA-256 produces a valid digest"))
}

async fn probe(path: &Path, limits: &DiscoveryLimits) -> Result<ProviderSchemas, Error> {
    let mut command = Command::new(path);
    command.arg("--describe-schema").env_clear();
    // No HOME, user-configurable PATH, loader injection variables, or runtime
    // settings. A native executable needs no credential-bearing environment.
    #[cfg(unix)]
    command.env("PATH", "/usr/bin:/bin");
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|_| unavailable("cannot start plugin metadata probe"))?;
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");
    // Poll pipes concurrently with wait: neither a noisy stderr nor a child
    // retaining stdout can deadlock discovery. Drop/timeout kills the child;
    // Tokio owns reaping. No detached output collection tasks survive it.
    let (stdout, _, status) = tokio::try_join!(
        read_bounded(stdout, limits.stdout_bytes),
        read_bounded(stderr, limits.stderr_bytes),
        async {
            child
                .wait()
                .await
                .map_err(|_| unavailable("cannot reap metadata probe"))
        },
    )?;
    if !status.success() {
        return Err(unavailable("plugin metadata probe exited unsuccessfully"));
    }
    // Do not echo plugin stdout/stderr or serde errors (which can quote input).
    serde_json::from_slice(&stdout)
        .map_err(|_| unavailable("plugin metadata probe did not return one ProviderSchemas object"))
}

async fn read_bounded(mut reader: impl AsyncRead + Unpin, max: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        let count = reader
            .read(&mut buffer)
            .await
            .map_err(|_| unavailable("cannot read metadata probe output"))?;
        if count == 0 {
            return Ok(bytes);
        }
        if count > max.saturating_sub(bytes.len()) {
            return Err(unavailable(
                "plugin metadata probe output exceeded its budget",
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

/// SDK helper for `--describe-schema`. Call before constructing a provider or
/// loading runtime configuration. The caller must exit after writing metadata.
pub fn write_schema(mut writer: impl Write, schemas: &ProviderSchemas) -> io::Result<()> {
    serde_json::to_writer(&mut writer, schemas)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn invalid_config(name: &ProviderName, path: &str, message: &str) -> Error {
    Error::InvalidConfig {
        entry:   name.clone(),
        path:    path.into(),
        message: message.into(),
    }
}

fn unavailable(message: &str) -> Error {
    Error::Unavailable {
        message: message.into(),
        outcome: MutationOutcome::NotStarted,
    }
}
