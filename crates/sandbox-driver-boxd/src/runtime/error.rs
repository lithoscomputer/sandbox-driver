//! boxd's gRPC status codes as the contract's errors.

use sandbox_driver::{Error, MutationOutcome};
use tonic::{Code, Status};

/// Whether boxd said the thing addressed does not exist.
pub(super) fn not_found(status: &Status) -> bool {
    status.code() == Code::NotFound
}

/// The contract's view of a failed call that carries no spec value.
/// `NOT_FOUND` must be handled by the caller, which knows what was
/// addressed; here it is a transport fault, never absence.
pub(super) fn classify(operation: &str, status: &Status) -> Error {
    let message = format!("{operation}: {}", status.message());
    match status.code() {
        Code::Unauthenticated => Error::Unauthenticated { message },
        Code::PermissionDenied => Error::PermissionDenied { message },
        Code::ResourceExhausted => Error::ResourceExhausted {
            message,
            retry_after_ms: None,
        },
        Code::FailedPrecondition | Code::Aborted => Error::Busy { message },
        Code::Unimplemented => Error::Unsupported {
            capability: operation.to_owned(),
        },
        // boxd refused a request this provider built: nothing was admitted.
        Code::InvalidArgument | Code::OutOfRange | Code::AlreadyExists => Error::Transport {
            message,
            outcome: MutationOutcome::NotStarted,
        },
        Code::Unavailable | Code::DeadlineExceeded | Code::Cancelled => Error::Unavailable {
            message,
            outcome: MutationOutcome::Unknown,
        },
        Code::Ok | Code::Unknown | Code::Internal | Code::DataLoss | Code::NotFound => {
            Error::Transport {
                message,
                outcome: MutationOutcome::Unknown,
            }
        }
    }
}

/// A failed call that applies `path` of the spec: boxd refusing the value
/// is an invalid spec at that path.
pub(super) fn classify_spec(path: &str, status: &Status) -> Error {
    match status.code() {
        Code::InvalidArgument | Code::OutOfRange => Error::InvalidSpec {
            path:    path.to_owned(),
            message: status.message().to_owned(),
        },
        _ => classify(path, status),
    }
}

/// Whether boxd refused a call before admitting it, so the resource it
/// addressed is untouched.
pub(super) fn refused(error: &Error) -> bool {
    matches!(
        error,
        Error::Unauthenticated { .. }
            | Error::PermissionDenied { .. }
            | Error::ResourceExhausted { .. }
            | Error::InvalidSpec { .. }
            | Error::Busy { .. }
            | Error::Unsupported { .. }
            | Error::Transport {
                outcome: MutationOutcome::NotStarted,
                ..
            }
            | Error::Unavailable {
                outcome: MutationOutcome::NotStarted,
                ..
            }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absence_and_outages_are_never_confused() {
        assert!(matches!(
            classify("x", &Status::not_found("vm")),
            Error::Transport { .. }
        ));
        assert!(matches!(
            classify("x", &Status::unavailable("down")),
            Error::Unavailable {
                outcome: MutationOutcome::Unknown,
                ..
            }
        ));
    }

    #[test]
    fn a_refused_value_names_its_spec_path_only_where_there_is_one() {
        let refusal = Status::invalid_argument("10.0.0.0/8 is not public");
        assert!(matches!(
            classify_spec("network", &refusal),
            Error::InvalidSpec { path, .. } if path == "network"
        ));
        let error = classify("listing machines", &refusal);
        assert!(matches!(error, Error::Transport {
            outcome: MutationOutcome::NotStarted,
            ..
        }));
        assert!(refused(&error));
        assert!(refused(&classify(
            "x",
            &Status::failed_precondition("stopped")
        )));
    }
}
