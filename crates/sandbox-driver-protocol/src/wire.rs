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
    Action, AuthError, Capability, Error, ErrorReport, ExecFailure, GitFailure, GitFailureKind,
    ProviderError, ProviderKind, ResourceKind, SandboxState, Termination, TransportError,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const JSONRPC_VERSION: &str = "2.0";

/// One incoming or outgoing JSON-RPC message.
#[derive(Serialize, Deserialize)]
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

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("id", &self.id)
            .field("method", &self.method)
            .field("body", &"<redacted>")
            .finish_non_exhaustive()
    }
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

// Per-kind `detail` payloads, one per row of the `docs/protocol.md`
// section 7 table. Each carries exactly the fields its `report.kind`
// needs to rebuild the typed error; the wire shape is the flat object
// those fields form.

#[derive(Debug, Serialize, Deserialize)]
struct UnsupportedDetail {
    capability: Capability,
}

/// `not_found` and `not_owned`: the resource kind and id in question.
#[derive(Debug, Serialize, Deserialize)]
struct ResourceDetail {
    resource: ResourceKind,
    id:       String,
}

#[derive(Debug, Serialize, Deserialize)]
struct InvalidSpecDetail {
    field:  String,
    reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct InvalidStateDetail {
    current: SandboxState,
    action:  Action,
}

#[derive(Debug, Serialize, Deserialize)]
struct TimeoutDetail {
    operation: String,
    elapsed:   Duration,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthEnvelope {
    auth: AuthDetail,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RateLimitedDetail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_after: Option<Duration>,
}

/// `overloaded`: admission was refused before any work started, which
/// `not_started` states explicitly so a receiver never confuses it with
/// an incomplete operation.
#[derive(Debug, Serialize, Deserialize)]
struct OverloadedDetail {
    limit:       String,
    #[serde(default)]
    not_started: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct LimitDetail {
    limit:     String,
    max_bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct IncompleteDetail {
    incomplete: sandbox_driver::IncompleteOperation,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProviderEnvelope {
    provider: ProviderError,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExecEnvelope {
    exec: ExecDetail,
}

#[derive(Debug, Serialize, Deserialize)]
struct GitEnvelope {
    git: GitDetail,
}

#[derive(Debug, Serialize, Deserialize)]
struct IoDetail {
    io_context: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TransportDetail {
    transport_context: String,
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

/// A classified git failure: the class plus whichever evidence it was
/// read from.
#[derive(Debug, Serialize, Deserialize)]
struct GitDetail {
    operation: String,
    kind:      GitFailureKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exec:      Option<ExecDetail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider:  Option<ProviderError>,
}

fn exec_detail(failure: &ExecFailure) -> ExecDetail {
    ExecDetail {
        label:       failure.label().to_owned(),
        termination: failure.termination(),
        exit_code:   failure.exit_code(),
        stdout_b64:  encode_bytes(failure.stdout()),
        stderr_b64:  encode_bytes(failure.stderr()),
        duration_ms: failure
            .duration()
            .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)),
    }
}

fn exec_failure(detail: ExecDetail) -> Option<ExecFailure> {
    let (Ok(stdout), Ok(stderr)) = (
        decode_bytes(&detail.stdout_b64),
        decode_bytes(&detail.stderr_b64),
    ) else {
        return None;
    };
    let mut failure = ExecFailure::new(
        detail.label,
        detail.termination,
        detail.exit_code,
        stdout,
        stderr,
    );
    if let Some(duration_ms) = detail.duration_ms {
        failure = failure.with_duration(Duration::from_millis(duration_ms));
    }
    Some(failure)
}

/// A provider error without its in-process source, for the wire.
fn provider_copy(provider: &ProviderError) -> ProviderError {
    let mut copy = ProviderError::new(provider.provider.clone(), provider.message.clone());
    copy.code.clone_from(&provider.code);
    copy.retryable = provider.retryable;
    copy.detail.clone_from(&provider.detail);
    copy
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
        Self {
            code:    CODE_APPLICATION,
            message: report.message.clone(),
            data:    Some(WireErrorData {
                report,
                detail: detail_of(error),
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
        if let Some(error) = typed_error(&data.report.kind, data.detail, &data.report.causes) {
            return error;
        }
        // A kind this side does not know, or a detail missing the fields
        // its kind needs: keep what the report says.
        let mut provider = ProviderError::new(unknown_kind(), data.report.message);
        provider.retryable = data.report.retryable;
        provider.code = Some(data.report.kind);
        Error::Provider(provider)
    }
}

/// The kind-specific `detail` object for `error`, or `{}` for a kind
/// that needs none.
fn detail_of(error: &Error) -> Value {
    let detail = match error {
        Error::Incomplete(outcome) => serde_json::to_value(IncompleteDetail {
            incomplete: outcome.clone(),
        }),
        Error::Overloaded { limit } => serde_json::to_value(OverloadedDetail {
            limit:       limit.clone(),
            not_started: true,
        }),
        Error::LimitExceeded { limit, max_bytes } => serde_json::to_value(LimitDetail {
            limit:     limit.clone(),
            max_bytes: *max_bytes,
        }),
        Error::Unsupported { capability } => serde_json::to_value(UnsupportedDetail {
            capability: *capability,
        }),
        Error::NotFound { resource, id } | Error::NotOwned { resource, id } => {
            serde_json::to_value(ResourceDetail {
                resource: *resource,
                id:       id.clone(),
            })
        }
        Error::InvalidSpec { field, reason } => serde_json::to_value(InvalidSpecDetail {
            field:  field.clone(),
            reason: reason.clone(),
        }),
        Error::InvalidState { current, action } => serde_json::to_value(InvalidStateDetail {
            current: *current,
            action:  *action,
        }),
        Error::Timeout { operation, elapsed } => serde_json::to_value(TimeoutDetail {
            operation: operation.clone(),
            elapsed:   *elapsed,
        }),
        Error::Auth(auth) => serde_json::to_value(AuthEnvelope {
            auth: AuthDetail {
                provider: auth.provider.clone(),
                reason:   auth.reason.clone(),
            },
        }),
        Error::RateLimited { retry_after } => serde_json::to_value(RateLimitedDetail {
            retry_after: *retry_after,
        }),
        Error::Provider(provider) => serde_json::to_value(ProviderEnvelope {
            provider: provider_copy(provider),
        }),
        Error::Exec(failure) => serde_json::to_value(ExecEnvelope {
            exec: exec_detail(failure),
        }),
        Error::Git(failure) => serde_json::to_value(GitEnvelope {
            git: GitDetail {
                operation: failure.operation().to_owned(),
                kind:      failure.kind(),
                exec:      failure.output().map(exec_detail),
                provider:  failure.provider().map(provider_copy),
            },
        }),
        Error::Io { context, .. } => serde_json::to_value(IoDetail {
            io_context: context.clone(),
        }),
        Error::Transport(transport) => serde_json::to_value(TransportDetail {
            transport_context: transport.context.clone(),
        }),
        _ => Ok(Value::Object(serde_json::Map::new())),
    };
    detail.expect("wire error detail contains only serializable values")
}

/// The typed [`Error`] that `kind` and its `detail` describe, or `None`
/// when the kind is unknown here or the detail lacks the fields the
/// kind needs. `causes` is the report's rendered source chain, restored
/// as an opaque remote source where the error type carries one.
fn typed_error(kind: &str, detail: Value, causes: &[String]) -> Option<Error> {
    fn read<T: DeserializeOwned>(detail: Value) -> Option<T> {
        serde_json::from_value(detail).ok()
    }
    Some(match kind {
        "incomplete" => Error::Incomplete(read::<IncompleteDetail>(detail)?.incomplete),
        "overloaded" => {
            let detail: OverloadedDetail = read(detail)?;
            if !detail.not_started {
                return None;
            }
            Error::Overloaded {
                limit: detail.limit,
            }
        }
        "limit_exceeded" => {
            let LimitDetail { limit, max_bytes } = read(detail)?;
            Error::LimitExceeded { limit, max_bytes }
        }
        "unsupported" => Error::Unsupported {
            capability: read::<UnsupportedDetail>(detail)?.capability,
        },
        "not_found" => {
            let ResourceDetail { resource, id } = read(detail)?;
            Error::NotFound { resource, id }
        }
        "not_owned" => {
            let ResourceDetail { resource, id } = read(detail)?;
            Error::NotOwned { resource, id }
        }
        "invalid_spec" => {
            let InvalidSpecDetail { field, reason } = read(detail)?;
            Error::InvalidSpec { field, reason }
        }
        "invalid_state" => {
            let InvalidStateDetail { current, action } = read(detail)?;
            Error::InvalidState { current, action }
        }
        "timeout" => {
            let TimeoutDetail { operation, elapsed } = read(detail)?;
            Error::Timeout { operation, elapsed }
        }
        "auth" => {
            let AuthEnvelope { auth } = read(detail)?;
            Error::Auth(match remote_cause(causes) {
                Some(source) => AuthError::with_source(auth.provider, auth.reason, source),
                None => AuthError::new(auth.provider, auth.reason),
            })
        }
        // A rate limit needs no detail at all; an absent or malformed
        // one still reads as "rate limited, retry time unknown".
        "rate_limited" => Error::RateLimited {
            retry_after: read::<RateLimitedDetail>(detail)
                .unwrap_or_default()
                .retry_after,
        },
        "provider" => {
            let ProviderEnvelope { provider } = read(detail)?;
            let mut copy = match remote_cause(causes) {
                Some(source) => {
                    ProviderError::with_source(provider.provider, provider.message, source)
                }
                None => ProviderError::new(provider.provider, provider.message),
            };
            copy.code = provider.code;
            copy.retryable = provider.retryable;
            copy.detail = provider.detail;
            Error::Provider(copy)
        }
        "exec" => Error::Exec(exec_failure(read::<ExecEnvelope>(detail)?.exec)?),
        "git" => {
            let GitEnvelope { git } = read(detail)?;
            let mut failure = GitFailure::classified(git.operation, git.kind, git.provider);
            if let Some(output) = git.exec.and_then(exec_failure) {
                failure = failure.with_output(output);
            }
            Error::Git(failure)
        }
        "io" => {
            let IoDetail { io_context } = read(detail)?;
            let source = remote_cause(causes).unwrap_or_else(|| RemoteCause {
                message: "remote I/O failure".to_owned(),
                source:  None,
            });
            Error::io(io_context, io::Error::other(source))
        }
        "transport" => {
            let TransportDetail { transport_context } = read(detail)?;
            Error::Transport(match remote_cause(causes) {
                Some(source) => TransportError::with_source(transport_context, source),
                None => TransportError::new(transport_context),
            })
        }
        _ => return None,
    })
}

/// Whether `error` is a plugin's `-32601` for a method it does not know.
/// Methods added within a protocol version are optional on the plugin
/// side, and a host treats this answer as "not offered", not as failure.
pub(crate) fn is_method_not_found(error: &Error) -> bool {
    matches!(
        error,
        Error::Provider(provider)
            if provider.code.as_deref().and_then(|code| code.parse::<i64>().ok())
                == Some(CODE_METHOD_NOT_FOUND)
    )
}

fn unknown_kind() -> sandbox_driver::ProviderKind {
    sandbox_driver::ProviderKind::try_new("plugin").expect("static kind is valid")
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    #[test]
    fn admission_rejection_and_incomplete_outcome_remain_distinct() {
        let overloaded = Error::Overloaded {
            limit: "active_io".into(),
        };
        assert!(
            matches!(WireError::from_error(&overloaded).into_error(), Error::Overloaded { limit } if limit == "active_io")
        );
        let incomplete = sandbox_driver::IncompleteOperation::new("hard cancellation drain");
        let Error::Incomplete(back) =
            WireError::from_error(&Error::Incomplete(incomplete)).into_error()
        else {
            panic!("incomplete outcome must survive the wire");
        };
        assert!(back.output_abandoned);
        assert!(!back.stop_acknowledged && !back.termination_confirmed && !back.cleanup_confirmed);
        let limit = Error::LimitExceeded {
            limit:     "buffered_value_bytes".into(),
            max_bytes: 4,
        };
        assert!(matches!(
            WireError::from_error(&limit).into_error(),
            Error::LimitExceeded { max_bytes: 4, .. }
        ));
    }

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

        let error = Error::NotOwned {
            resource: ResourceKind::Sandbox,
            id:       "sb-2".into(),
        };
        let back = WireError::from_error(&error).into_error();
        assert!(
            matches!(back, Error::NotOwned { resource: ResourceKind::Sandbox, id } if id == "sb-2")
        );

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

        let error = Error::Git(GitFailure::from_command(
            "git clone",
            ExecFailure::new(
                "git fetch",
                Termination::Exited,
                Some(128),
                Vec::new(),
                b"fatal: couldn't find remote ref refs/tags/v9".to_vec(),
            ),
        ));
        let wire = WireError::from_error(&error);
        assert_eq!(
            wire.data.as_ref().map(|data| data.report.kind.as_str()),
            Some("git")
        );
        let Error::Git(failure) = wire.into_error() else {
            panic!("expected git failure");
        };
        assert_eq!(failure.operation(), "git clone");
        assert_eq!(failure.kind(), GitFailureKind::RefNotFound);
        let output = failure.output().expect("command output crosses");
        assert_eq!(output.exit_code(), Some(128));
        assert!(String::from_utf8_lossy(output.stderr()).contains("refs/tags/v9"));

        let mut native = ProviderError::new(provider.clone(), "authentication failed");
        native.code = Some("auth".into());
        let error = Error::Git(GitFailure::classified(
            "git clone",
            GitFailureKind::AuthRejected,
            Some(native),
        ));
        let Error::Git(failure) = WireError::from_error(&error).into_error() else {
            panic!("expected git failure");
        };
        assert_eq!(failure.kind(), GitFailureKind::AuthRejected);
        assert!(failure.output().is_none());
        assert_eq!(
            failure.provider().and_then(|p| p.code.as_deref()),
            Some("auth")
        );

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
