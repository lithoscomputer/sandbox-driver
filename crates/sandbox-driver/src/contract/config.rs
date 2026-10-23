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
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEntry {
    pub plugin:      ProviderKind,
    #[serde(default)]
    pub config:      BTreeMap<String, Value>,
    #[serde(default)]
    pub secrets:     Vec<String>,
    #[serde(default)]
    pub path:        Option<String>,
    #[serde(default)]
    pub trust:       Option<PluginTrust>,
    #[serde(default)]
    pub args:        Vec<String>,
    #[serde(default)]
    pub env:         BTreeMap<String, String>,
    /// None uses PATH/HOME/TMPDIR/USER; Some([]) inherits nothing.
    /// An explicit list replaces defaults. `env` wins over inherited values.
    #[serde(default)]
    pub inherit_env: Option<Vec<String>>,
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
/// Decoding rejects a digest on development trust, so a pinned checksum is
/// never silently skipped.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", try_from = "RawPluginTrust")]
pub enum PluginTrust {
    /// Checked before executing the binary.
    Sha256 { digest: Sha256Digest },
    /// Explicit development opt-in; never inferred from a missing checksum.
    Development,
}

// Serde's `deny_unknown_fields` does not reach unit variants of an internally
// tagged enum, so decoding goes through this flat form instead.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPluginTrust {
    mode:   TrustMode,
    digest: Option<Sha256Digest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum TrustMode {
    Sha256,
    Development,
}

impl TryFrom<RawPluginTrust> for PluginTrust {
    type Error = &'static str;

    fn try_from(raw: RawPluginTrust) -> Result<Self, Self::Error> {
        match (raw.mode, raw.digest) {
            (TrustMode::Sha256, Some(digest)) => Ok(Self::Sha256 { digest }),
            (TrustMode::Sha256, None) => Err("sha256 trust requires digest"),
            (TrustMode::Development, None) => Ok(Self::Development),
            (TrustMode::Development, Some(_)) => {
                Err("development trust does not take a digest; use mode sha256")
            }
        }
    }
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
