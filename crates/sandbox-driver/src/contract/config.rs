use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{EnvironmentName, ProviderName, SandboxSpec};
use crate::ProviderKind;

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

impl fmt::Debug for ProviderEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderEntry")
            .field("plugin", &self.plugin)
            .field("config", &"<redacted>")
            .field("secrets", &self.secrets)
            .field("path", &self.path)
            .field("trust", &self.trust)
            .field("args", &"<redacted>")
            .field("env", &"<redacted>")
            .field("inherit_env", &self.inherit_env)
            .finish()
    }
}

/// Installation/trust policy only; the metadata probe must obey it too.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum PluginTrust {
    /// Exactly 64 hexadecimal digits, checked before executing the binary.
    Sha256 { digest: String },
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
pub trait EnvironmentSource: Send + Sync {
    fn names(&self) -> Vec<EnvironmentName>;
    fn get(&self, name: &str) -> Option<Environment>;
}
