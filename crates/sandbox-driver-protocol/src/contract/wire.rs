//! Protocol version 3: the shared contract's calls over the version 2
//! envelope, framing and data channels. Method names never contain `/`, so
//! they cannot be confused with a version 2 method.

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU16;
use std::path::PathBuf;

use sandbox_driver::contract::{
    Error, ExecSpec, Expose, FileRange, LabelFilter, MutationOutcome, ProviderName, SandboxRef,
    SandboxSpec, TerminalSize,
};
use sandbox_driver::{ErrorReport, SandboxId, StopLevel};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::channel::{ChannelRequest, DataTransport};
use crate::client::Failure;
use crate::wire::{CODE_APPLICATION, CODE_METHOD_NOT_FOUND, WireError, WireErrorData};

pub const PROTOCOL_VERSION: u32 = 3;

pub const DESCRIBE: &str = "describe";
pub const HEALTH: &str = "health";
pub const CREATE: &str = "create";
pub const ATTACH: &str = "attach";
pub const LIST: &str = "list";
pub const DESTROY: &str = "destroy";
pub const STATUS: &str = "status";
pub const START: &str = "start";
pub const STOP: &str = "stop";
pub const EXEC: &str = "exec";
pub const EXEC_STOP: &str = "exec.stop";
pub const EXEC_RESIZE: &str = "exec.resize";
pub const FILES_GET: &str = "files.get";
pub const FILES_PUT: &str = "files.put";
pub const FILES_LIST: &str = "files.list";
pub const PORTS_EXPOSE: &str = "ports.expose";
pub const PORTS_RELEASE: &str = "ports.release";

/// Error reports whose `detail` is a serialized `contract::Error`.
const CONTRACT_ERROR: &str = "contract";

/// The configured entry's identity and connection settings. Secret values
/// are never here: the plugin reads the named secrets from its environment.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InitializeParams {
    pub protocol_version: u32,
    pub data_transport:   DataTransport,
    pub entry:            ProviderName,
    #[serde(default)]
    pub config:           BTreeMap<String, Value>,
    #[serde(default)]
    pub secrets:          Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct InitializeResult {
    pub protocol_version: u32,
}

/// Workload credentials travel to the trusted child on its private control
/// pipe, never into persisted specs or errors.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateParams {
    pub spec:        SandboxSpec,
    #[serde(default)]
    pub credentials: BTreeMap<String, String>,
}

impl fmt::Debug for CreateParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateParams")
            .field("spec", &self.spec)
            .field("credentials", &"<redacted>")
            .finish()
    }
}

/// What a client needs to answer a handle's local accessors.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SandboxInfo {
    pub reference:         SandboxRef,
    pub working_directory: PathBuf,
    pub env:               BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdParams {
    pub id: SandboxId,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListParams {
    pub filter: LabelFilter,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecParams {
    pub sandbox: SandboxId,
    /// Client-chosen, unique per connection; addresses `exec.stop`.
    pub exec:    String,
    pub spec:    ExecSpec,
    /// Whether `stdin` frames follow; otherwise the command's input is empty.
    pub stdin:   bool,
    pub channel: ChannelRequest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecStopParams {
    pub exec:  String,
    pub level: StopLevel,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecResizeParams {
    pub exec: String,
    pub size: TerminalSize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FilesGetParams {
    pub sandbox: SandboxId,
    pub path:    String,
    #[serde(default)]
    pub range:   Option<FileRange>,
    pub channel: ChannelRequest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FilesPutParams {
    pub sandbox: SandboxId,
    pub path:    String,
    pub channel: ChannelRequest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FilesListParams {
    pub sandbox: SandboxId,
    pub path:    String,
    pub depth:   u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortParams {
    pub sandbox: SandboxId,
    pub port:    NonZeroU16,
    #[serde(default)]
    pub options: Option<Expose>,
}

/// The plugin's reply to a failed call: the shared error, intact.
pub(crate) fn to_wire(error: &Error) -> WireError {
    let message = error.to_string();
    WireError {
        code:    CODE_APPLICATION,
        message: message.clone(),
        data:    Some(WireErrorData {
            report: ErrorReport::new(CONTRACT_ERROR, message),
            detail: serde_json::to_value(error).unwrap_or(Value::Null),
        }),
    }
}

/// Decodes a failed call. Only an admission refusal before sending is known
/// not to have started; any other local or undecodable failure leaves the
/// outcome unknown, and an unknown future error code never becomes absence.
pub(crate) fn from_failure(failure: Failure) -> Error {
    match failure {
        Failure::Remote(error) => {
            if error.code == CODE_METHOD_NOT_FOUND {
                return Error::Unsupported {
                    capability: error.message,
                };
            }
            match error.data {
                Some(data) if data.report.kind == CONTRACT_ERROR => {
                    serde_json::from_value(data.detail).unwrap_or_else(|_| Error::Transport {
                        message: "plugin returned an unknown error code".into(),
                        outcome: MutationOutcome::Unknown,
                    })
                }
                Some(data) if data.report.kind == "overloaded" => Error::ResourceExhausted {
                    message:        data.report.message,
                    retry_after_ms: None,
                },
                _ => Error::Transport {
                    message: format!("plugin protocol failure: {}", error.message),
                    outcome: MutationOutcome::Unknown,
                },
            }
        }
        Failure::Local(sandbox_driver::Error::Overloaded { limit }) => Error::ResourceExhausted {
            message:        format!("local transport budget {limit} is exhausted"),
            retry_after_ms: None,
        },
        Failure::Local(error) => Error::Transport {
            message: error.to_string(),
            outcome: MutationOutcome::Unknown,
        },
    }
}
