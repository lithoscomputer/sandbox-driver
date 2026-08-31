//! JSON-RPC 2.0 envelope and error mapping.
//!
//! Newline-delimited JSON over any byte stream. Requests carry a `u64`
//! id; notifications carry none. Out-of-order responses are expected —
//! the protocol itself never serializes concurrent calls.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sandbox_driver::{
    Capability, Error, ErrorReport, ExecFailure, ProviderError, ResourceKind, Termination,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const JSONRPC_VERSION: &str = "2.0";

/// One incoming or outgoing JSON-RPC message.
#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id:      Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method:  Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params:  Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result:  Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error:   Option<WireError>,
}

impl Message {
    pub fn request(id: u64, method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id:      Some(id),
            method:  Some(method.into()),
            params:  Some(params),
            result:  None,
            error:   None,
        }
    }

    pub fn notification(method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id:      None,
            method:  Some(method.into()),
            params:  Some(params),
            result:  None,
            error:   None,
        }
    }

    pub fn response(id: u64, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id:      Some(id),
            method:  None,
            params:  None,
            result:  Some(result),
            error:   None,
        }
    }

    pub fn error_response(id: u64, error: WireError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id:      Some(id),
            method:  None,
            params:  None,
            result:  None,
            error:   Some(error),
        }
    }
}

/// JSON-RPC error object. `data` carries the [`ErrorReport`] plus
/// variant-specific detail so the typed error survives the boundary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireError {
    pub code:    i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data:    Option<WireErrorData>,
}

/// Structured error payload: the bounded report plus reconstruction detail.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireErrorData {
    pub report: ErrorReport,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub detail: Value,
}

/// Application-level failure (a typed [`Error`]).
pub(crate) const CODE_APPLICATION: i64 = -32000;
/// Malformed request or params.
pub(crate) const CODE_INVALID_REQUEST: i64 = -32600;
/// Unknown method.
pub(crate) const CODE_METHOD_NOT_FOUND: i64 = -32601;

pub(crate) fn encode_bytes(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

pub(crate) fn decode_bytes(text: &str) -> Result<Vec<u8>, Error> {
    BASE64
        .decode(text)
        .map_err(|error| Error::invalid_spec("base64", error.to_string()))
}

/// Variant-specific reconstruction payloads.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Detail {
    #[serde(skip_serializing_if = "Option::is_none")]
    capability: Option<Capability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource:   Option<ResourceKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id:         Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    field:      Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason:     Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider:   Option<ProviderError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exec:       Option<ExecDetail>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExecDetail {
    label:       String,
    termination: Termination,
    exit_code:   Option<i32>,
    stdout_b64:  String,
    stderr_b64:  String,
}

impl WireError {
    /// Projects a typed [`Error`] onto the wire, keeping enough structure
    /// to reconstruct the important variants on the other side.
    pub fn from_error(error: &Error) -> Self {
        let report = ErrorReport::from(error);
        let mut detail = Detail::default();
        match error {
            Error::Unsupported { capability } => detail.capability = Some(*capability),
            Error::NotFound { resource, id } => {
                detail.resource = Some(*resource);
                detail.id = Some(id.clone());
            }
            Error::InvalidSpec { field, reason } => {
                detail.field = Some(field.clone());
                detail.reason = Some(reason.clone());
            }
            Error::Provider(provider) => {
                let mut copy =
                    ProviderError::new(provider.provider.clone(), provider.message.clone());
                copy.code.clone_from(&provider.code);
                copy.retryable = provider.retryable;
                copy.detail.clone_from(&provider.detail);
                detail.provider = Some(copy);
            }
            Error::Exec(failure) => {
                detail.exec = Some(ExecDetail {
                    label:       failure.label().to_owned(),
                    termination: failure.termination(),
                    exit_code:   failure.exit_code(),
                    stdout_b64:  encode_bytes(failure.stdout()),
                    stderr_b64:  encode_bytes(failure.stderr()),
                });
            }
            _ => {}
        }
        Self {
            code:    CODE_APPLICATION,
            message: report.message.clone(),
            data:    Some(WireErrorData {
                report,
                detail: serde_json::to_value(detail).unwrap_or(Value::Null),
            }),
        }
    }

    /// Reconstructs the closest typed [`Error`] from the wire.
    pub fn into_error(self) -> Error {
        let Some(data) = self.data else {
            // Envelope-level failures (unknown method, malformed params)
            // carry no data; keep the JSON-RPC code so callers can
            // branch on it (e.g. -32601 from an older plugin).
            let mut provider = ProviderError::new(unknown_kind(), self.message);
            provider.code = Some(self.code.to_string());
            return Error::Provider(provider);
        };
        let detail: Detail = serde_json::from_value(data.detail).unwrap_or_default();
        match data.report.kind.as_str() {
            "unsupported" => {
                if let Some(capability) = detail.capability {
                    return Error::Unsupported { capability };
                }
            }
            "not_found" => {
                if let (Some(resource), Some(id)) = (detail.resource, detail.id) {
                    return Error::NotFound { resource, id };
                }
            }
            "invalid_spec" => {
                if let (Some(field), Some(reason)) = (detail.field, detail.reason) {
                    return Error::InvalidSpec { field, reason };
                }
            }
            "provider" => {
                if let Some(provider) = detail.provider {
                    return Error::Provider(provider);
                }
            }
            "exec" => {
                if let Some(exec) = detail.exec {
                    return Error::Exec(ExecFailure::new(
                        exec.label,
                        exec.termination,
                        exec.exit_code,
                        decode_bytes(&exec.stdout_b64).unwrap_or_default(),
                        decode_bytes(&exec.stderr_b64).unwrap_or_default(),
                    ));
                }
            }
            _ => {}
        }
        let mut provider = ProviderError::new(unknown_kind(), data.report.message);
        provider.retryable = data.report.retryable;
        provider.code = Some(data.report.kind);
        Error::Provider(provider)
    }
}

fn unknown_kind() -> sandbox_driver::ProviderKind {
    sandbox_driver::ProviderKind::try_new("plugin").expect("static kind is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_errors_round_trip_the_wire() {
        let error = Error::unsupported(Capability::LifecyclePause);
        let back = WireError::from_error(&error).into_error();
        assert!(matches!(back, Error::Unsupported {
            capability: Capability::LifecyclePause,
        }));

        let error = Error::NotFound {
            resource: ResourceKind::Sandbox,
            id:       "sb-1".into(),
        };
        let back = WireError::from_error(&error).into_error();
        assert!(matches!(back, Error::NotFound { .. }));

        let error = Error::Exec(ExecFailure::new(
            "probe",
            Termination::Exited,
            Some(3),
            b"out".to_vec(),
            b"err".to_vec(),
        ));
        let Error::Exec(failure) = WireError::from_error(&error).into_error() else {
            panic!("expected exec failure");
        };
        assert_eq!(failure.label(), "probe");
        assert_eq!(failure.exit_code(), Some(3));
        assert_eq!(failure.stdout(), b"out");
    }
}
