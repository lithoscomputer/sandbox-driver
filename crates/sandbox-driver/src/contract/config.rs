use std::collections::BTreeMap;
use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{EnvironmentName, Error, ProviderName, SandboxSpec, Sha256Digest};
use crate::ProviderKind;
use crate::redact::EnvKeys;

/// Operator-owned connection data, with no backend or environment template.
/// This is an unvalidated DTO. Catalog admission, trust verification, secret
/// resolution, and schema validation are separate steps (see shared contract).
///
/// On the wire, `trust` is the flat `sha256 = "…"` or `dev = true` an
/// operator writes; decoding rejects both together.
#[derive(Clone, Serialize, Deserialize)]
#[serde(into = "RawProviderEntry", try_from = "RawProviderEntry")]
pub struct ProviderEntry {
    pub plugin:      ProviderKind,
    pub config:      BTreeMap<String, Value>,
    pub secrets:     Vec<String>,
    pub path:        Option<String>,
    pub trust:       Option<PluginTrust>,
    pub args:        Vec<String>,
    pub env:         BTreeMap<String, String>,
    /// None uses PATH/HOME/TMPDIR/USER; Some([]) inherits nothing.
    /// An explicit list replaces defaults. `env` wins over inherited values.
    pub inherit_env: Option<Vec<String>>,
}

/// The entry as written: trust is two flat keys rather than a tagged object.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProviderEntry {
    plugin:      ProviderKind,
    #[serde(default)]
    config:      BTreeMap<String, Value>,
    #[serde(default)]
    secrets:     Vec<String>,
    #[serde(default)]
    path:        Option<String>,
    #[serde(default)]
    sha256:      Option<Sha256Digest>,
    #[serde(default)]
    dev:         bool,
    #[serde(default)]
    args:        Vec<String>,
    #[serde(default)]
    env:         BTreeMap<String, String>,
    #[serde(default)]
    inherit_env: Option<Vec<String>>,
}

impl TryFrom<RawProviderEntry> for ProviderEntry {
    type Error = &'static str;

    fn try_from(raw: RawProviderEntry) -> Result<Self, Self::Error> {
        let trust = match (raw.sha256, raw.dev) {
            (Some(_), true) => return Err("dev trust does not take a sha256 pin"),
            (Some(digest), false) => Some(PluginTrust::Sha256 { digest }),
            (None, true) => Some(PluginTrust::Development),
            (None, false) => None,
        };
        Ok(Self {
            plugin: raw.plugin,
            config: raw.config,
            secrets: raw.secrets,
            path: raw.path,
            trust,
            args: raw.args,
            env: raw.env,
            inherit_env: raw.inherit_env,
        })
    }
}

impl From<ProviderEntry> for RawProviderEntry {
    fn from(entry: ProviderEntry) -> Self {
        let (sha256, dev) = match entry.trust {
            Some(PluginTrust::Sha256 { digest }) => (Some(digest), false),
            Some(PluginTrust::Development) => (None, true),
            None => (None, false),
        };
        Self {
            plugin: entry.plugin,
            config: entry.config,
            secrets: entry.secrets,
            path: entry.path,
            sha256,
            dev,
            args: entry.args,
            env: entry.env,
            inherit_env: entry.inherit_env,
        }
    }
}

// Config, arguments, and launch environment can carry credentials, so `Debug`
// shows names only. Destructuring makes every new field choose here.
impl fmt::Debug for ProviderEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            plugin,
            config: _,
            secrets,
            path,
            trust,
            args: _,
            env,
            inherit_env,
        } = self;
        f.debug_struct("ProviderEntry")
            .field("plugin", plugin)
            .field("config", &"<redacted>")
            .field("secrets", secrets)
            .field("path", path)
            .field("trust", trust)
            .field("args", &"<redacted>")
            .field("env_keys", &EnvKeys(env))
            .field("inherit_env", inherit_env)
            .finish()
    }
}

/// Installation/trust policy only; the metadata probe must obey it too.
/// Entry decoding rejects a pin together with development trust, so a pinned
/// checksum is never silently skipped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PluginTrust {
    /// Checked before executing the binary.
    Sha256 { digest: Sha256Digest },
    /// Explicit development opt-in; never inferred from a missing checksum.
    Development,
}

/// Mutable named template. A running sandbox keeps its admitted spec, not a
/// pointer to this record. Deleting this record does not affect saved refs.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub provider: ProviderName,
    pub spec:     SandboxSpec,
}

/// Application-owned environment storage. Implementations return snapshots;
/// consumers must not reread a changed template to resume an existing sandbox.
/// A storage failure is `Error::Unavailable`, never an absent environment.
#[async_trait]
pub trait EnvironmentSource: Send + Sync {
    async fn names(&self) -> Result<Vec<EnvironmentName>, Error>;
    /// `Ok(None)` means the store has no environment with this name.
    async fn get(&self, name: &str) -> Result<Option<Environment>, Error>;
}
