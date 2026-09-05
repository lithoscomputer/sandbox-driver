//! JSON-RPC 2.0 envelope and error mapping.
//!
//! Newline-delimited JSON over any byte stream. Requests carry a `u64`
//! id; notifications carry none. Out-of-order responses are expected —
//! the protocol itself never serializes concurrent calls. The only bytes
//! that cross in JSON are the bounded output samples inside an `exec`
//! error report.

use std::time::Duration;
use std::{error, fmt, io};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sandbox_driver::{
    Action, AuthError, Capability, Error, ErrorReport, ExecFailure, ProviderError, ProviderKind,
    ResourceKind, SandboxState, Termination, TransportError,
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
    capability:        Option<Capability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource:          Option<ResourceKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id:                Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    field:             Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason:            Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current:           Option<SandboxState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action:            Option<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation:         Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed:           Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth:              Option<AuthDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after:       Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider:          Option<ProviderError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exec:              Option<ExecDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    io_context:        Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport_context: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthDetail {
    provider: ProviderKind,
    reason:   String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExecDetail {
    label:       String,
    termination: Termination,
    exit_code:   Option<i32>,
    stdout_b64:  String,
    stderr_b64:  String,
    /// Additive since v1: absent from older peers, tolerated by them.
    #[serde(default)]
    duration_ms: Option<u64>,
}

#[derive(Debug)]
struct RemoteCause {
    message: String,
    source:  Option<Box<Self>>,
}

impl fmt::Display for RemoteCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl error::Error for RemoteCause {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn error::Error + 'static))
    }
}

fn remote_cause(messages: &[String]) -> Option<RemoteCause> {
    messages.iter().rev().fold(None, |source, message| {
        Some(RemoteCause {
            message: message.clone(),
            source:  source.map(Box::new),
        })
    })
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
            Error::InvalidState { current, action } => {
                detail.current = Some(*current);
                detail.action = Some(*action);
            }
            Error::Timeout { operation, elapsed } => {
                detail.operation = Some(operation.clone());
                detail.elapsed = Some(*elapsed);
            }
            Error::Auth(auth) => {
                detail.auth = Some(AuthDetail {
                    provider: auth.provider.clone(),
                    reason:   auth.reason.clone(),
                });
            }
            Error::RateLimited { retry_after } => detail.retry_after = *retry_after,
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
                    duration_ms: failure
                        .duration()
                        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)),
                });
            }
            Error::Io { context, .. } => detail.io_context = Some(context.clone()),
            Error::Transport(transport) => {
                detail.transport_context = Some(transport.context.clone());
            }
            _ => {}
        }
        Self {
            code:    CODE_APPLICATION,
            message: report.message.clone(),
            data:    Some(WireErrorData {
                report,
                detail: serde_json::to_value(detail)
                    .expect("wire error detail contains only serializable values"),
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
            "invalid_state" => {
                if let (Some(current), Some(action)) = (detail.current, detail.action) {
                    return Error::InvalidState { current, action };
                }
            }
            "timeout" => {
                if let (Some(operation), Some(elapsed)) = (detail.operation, detail.elapsed) {
                    return Error::Timeout { operation, elapsed };
                }
            }
            "auth" => {
                if let Some(auth) = detail.auth {
                    let auth = match remote_cause(&data.report.causes) {
                        Some(source) => AuthError::with_source(auth.provider, auth.reason, source),
                        None => AuthError::new(auth.provider, auth.reason),
                    };
                    return Error::Auth(auth);
                }
            }
            "rate_limited" => {
                return Error::RateLimited {
                    retry_after: detail.retry_after,
                };
            }
            "provider" => {
                if let Some(provider) = detail.provider {
                    let mut copy = match remote_cause(&data.report.causes) {
                        Some(source) => {
                            ProviderError::with_source(provider.provider, provider.message, source)
                        }
                        None => ProviderError::new(provider.provider, provider.message),
                    };
                    copy.code = provider.code;
                    copy.retryable = provider.retryable;
                    copy.detail = provider.detail;
                    return Error::Provider(copy);
                }
            }
            "exec" => {
                if let Some(exec) = detail.exec {
                    if let (Ok(stdout), Ok(stderr)) = (
                        decode_bytes(&exec.stdout_b64),
                        decode_bytes(&exec.stderr_b64),
                    ) {
                        let mut failure = ExecFailure::new(
                            exec.label,
                            exec.termination,
                            exec.exit_code,
                            stdout,
                            stderr,
                        );
                        if let Some(duration_ms) = exec.duration_ms {
                            failure = failure.with_duration(Duration::from_millis(duration_ms));
                        }
                        return Error::Exec(failure);
                    }
                }
            }
            "io" => {
                if let Some(context) = detail.io_context {
                    let source = remote_cause(&data.report.causes).unwrap_or_else(|| RemoteCause {
                        message: "remote I/O failure".to_owned(),
                        source:  None,
                    });
                    return Error::io(context, io::Error::other(source));
                }
            }
            "transport" => {
                if let Some(context) = detail.transport_context {
                    let transport = match remote_cause(&data.report.causes) {
                        Some(source) => TransportError::with_source(context, source),
                        None => TransportError::new(context),
                    };
                    return Error::Transport(transport);
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
    use std::error::Error as _;

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

        let error = Error::InvalidState {
            current: SandboxState::Paused,
            action:  Action::Stop,
        };
        let back = WireError::from_error(&error).into_error();
        assert!(matches!(back, Error::InvalidState {
            current: SandboxState::Paused,
            action:  Action::Stop,
        }));

        let error = Error::invalid_spec("source", "must be an image");
        let back = WireError::from_error(&error).into_error();
        assert!(matches!(back, Error::InvalidSpec { field, reason }
            if field == "source" && reason == "must be an image"));

        let error = Error::Timeout {
            operation: "creating sandbox".into(),
            elapsed:   Duration::from_secs(7),
        };
        let back = WireError::from_error(&error).into_error();
        assert!(matches!(back, Error::Timeout { operation, elapsed }
            if operation == "creating sandbox" && elapsed == Duration::from_secs(7)));

        let provider = ProviderKind::try_new("test").expect("static provider kind is valid");
        let error = Error::Auth(AuthError::with_source(
            provider.clone(),
            "token expired",
            io::Error::new(io::ErrorKind::PermissionDenied, "remote rejected token"),
        ));
        let Error::Auth(auth) = WireError::from_error(&error).into_error() else {
            panic!("expected auth failure");
        };
        assert_eq!(auth.provider, provider);
        assert_eq!(auth.reason, "token expired");
        assert_eq!(
            auth.source().expect("remote auth cause").to_string(),
            "remote rejected token"
        );

        let error = Error::RateLimited {
            retry_after: Some(Duration::from_millis(250)),
        };
        let back = WireError::from_error(&error).into_error();
        assert!(matches!(back, Error::RateLimited { retry_after }
            if retry_after == Some(Duration::from_millis(250))));

        let mut provider_error = ProviderError::with_source(
            provider.clone(),
            "listing sandboxes",
            io::Error::new(io::ErrorKind::ConnectionReset, "daemon disconnected"),
        );
        provider_error.code = Some("backend_unavailable".into());
        provider_error.retryable = true;
        let error = Error::Provider(provider_error);
        let Error::Provider(provider_error) = WireError::from_error(&error).into_error() else {
            panic!("expected provider failure");
        };
        assert_eq!(provider_error.provider, provider);
        assert_eq!(provider_error.code.as_deref(), Some("backend_unavailable"));
        assert!(provider_error.retryable);
        assert_eq!(
            provider_error
                .source()
                .expect("remote provider cause")
                .to_string(),
            "daemon disconnected"
        );

        let error = Error::Exec(
            ExecFailure::new(
                "probe",
                Termination::Exited,
                Some(3),
                b"out".to_vec(),
                b"err".to_vec(),
            )
            .with_duration(Duration::from_millis(1500)),
        );
        let Error::Exec(failure) = WireError::from_error(&error).into_error() else {
            panic!("expected exec failure");
        };
        assert_eq!(failure.label(), "probe");
        assert_eq!(failure.exit_code(), Some(3));
        assert_eq!(failure.stdout(), b"out");
        assert_eq!(failure.duration(), Some(Duration::from_millis(1500)));

        // duration_ms is additive: a v1 peer that omits it must decode
        // to a duration-less failure, not an error.
        let old_shape: ExecDetail = serde_json::from_str(
            r#"{"label":"probe","termination":"exited","exit_code":3,
                "stdout_b64":"","stderr_b64":""}"#,
        )
        .expect("old exec detail decodes");
        assert_eq!(old_shape.duration_ms, None);

        let error = Error::io(
            "reading plugin executable",
            io::Error::new(io::ErrorKind::NotFound, "binary disappeared"),
        );
        let Error::Io { context, source } = WireError::from_error(&error).into_error() else {
            panic!("expected I/O failure");
        };
        assert_eq!(context, "reading plugin executable");
        assert_eq!(source.to_string(), "binary disappeared");

        let error = Error::Transport(TransportError::with_source(
            "reading plugin response",
            io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed"),
        ));
        let Error::Transport(transport) = WireError::from_error(&error).into_error() else {
            panic!("expected transport failure");
        };
        assert_eq!(transport.context, "reading plugin response");
        assert_eq!(
            transport
                .source()
                .expect("remote transport cause")
                .to_string(),
            "pipe closed"
        );
    }
}
