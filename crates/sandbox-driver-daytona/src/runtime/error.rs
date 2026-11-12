//! Classifying legacy Daytona errors as shared-contract errors.
//!
//! Classification reads structured evidence: the legacy variant, the
//! provider code the Daytona adapter recorded, and the HTTP status of a
//! `DaytonaError` in the source chain. It never reads message text. An
//! error that does not establish what happened keeps an unknown outcome.

use std::error::Error as StdError;

use daytona_sdk::DaytonaError;
use sandbox_driver::Error as Legacy;
use sandbox_driver::contract::{Error, MutationOutcome, RemainingResource};

use crate::cleanup::INCOMPLETE_CLEANUP_CODE;

/// Classifies a legacy error from `operation`. The legacy cause is kept in
/// the provider's diagnostics; the returned message is safe to expose.
pub(super) fn classify(operation: &'static str, error: Legacy) -> Error {
    tracing::debug!(operation, error = ?error, "daytona operation failed");
    let message = format!("{operation}: {error}");
    match error {
        Legacy::NotFound { resource, id } => Error::NotFound {
            resource: format!("{resource:?}").to_lowercase(),
            id,
        },
        Legacy::NotOwned { id, .. } => Error::NotOwned { id },
        Legacy::ReadOnly { .. } | Legacy::InvalidState { .. } => Error::Busy { message },
        Legacy::Unsupported { capability } => Error::Unsupported {
            capability: capability.to_string(),
        },
        Legacy::InvalidSpec { field, reason } => Error::InvalidSpec {
            path:    field,
            message: reason,
        },
        Legacy::RateLimited { retry_after } => Error::ResourceExhausted {
            message,
            retry_after_ms: retry_after
                .map(|delay| u64::try_from(delay.as_millis()).unwrap_or(u64::MAX)),
        },
        Legacy::Overloaded { .. } => Error::Unavailable {
            message,
            outcome: MutationOutcome::NotStarted,
        },
        Legacy::Auth(ref auth) => match http_status(auth) {
            Some(403) => Error::PermissionDenied { message },
            _ => Error::Unauthenticated { message },
        },
        Legacy::Provider(ref provider)
            if provider.code.as_deref() == Some(INCOMPLETE_CLEANUP_CODE) =>
        {
            let remaining = provider
                .detail
                .as_ref()
                .and_then(|detail| detail.get("remaining"))
                .and_then(|value| {
                    serde_json::from_value::<Vec<RemainingResource>>(value.clone()).ok()
                })
                .unwrap_or_default();
            Error::IncompleteCleanup { message, remaining }
        }
        Legacy::Provider(ref provider)
            if provider.code.as_deref() == Some(super::runner::UNHEALTHY_CODE) =>
        {
            Error::Unhealthy {
                message: provider.message.clone(),
            }
        }
        Legacy::Provider(ref provider) => by_status(http_status(provider), message),
        Legacy::Exec(_) | Legacy::Git(_) => Error::Unhealthy { message },
        // A timeout, a lost transport, an unbuffered value or an I/O failure
        // establishes nothing about the remote operation.
        _ => Error::Unavailable {
            message,
            outcome: MutationOutcome::Unknown,
        },
    }
}

/// Whether Daytona refused the request outright, so nothing was admitted
/// and the sandbox is as it was.
pub(super) fn refused(error: &Error) -> bool {
    matches!(
        error,
        Error::Unauthenticated { .. }
            | Error::PermissionDenied { .. }
            | Error::ResourceExhausted { .. }
    )
}

/// Classifies a failed control-plane call that carries its own status.
pub(super) fn from_sdk(operation: &'static str, error: &DaytonaError) -> Error {
    tracing::debug!(operation, error = ?error, "daytona control-plane call failed");
    let message = format!("{operation}: {error}");
    if let DaytonaError::RateLimit { .. } = *error {
        return Error::ResourceExhausted {
            message,
            retry_after_ms: None,
        };
    }
    by_status(error.status_code(), message)
}

fn by_status(status: Option<u16>, message: String) -> Error {
    match status {
        Some(401) => Error::Unauthenticated { message },
        Some(403) => Error::PermissionDenied { message },
        Some(409) => Error::Busy { message },
        Some(429) => Error::ResourceExhausted {
            message,
            retry_after_ms: None,
        },
        // Daytona rejects an invalid request before admitting it.
        Some(400 | 422) => Error::InvalidSpec {
            path: "spec".to_owned(),
            message,
        },
        // A 404 from an endpoint other than a sandbox lookup names no
        // resource the caller asked about; it proves no absence.
        _ => Error::Unavailable {
            message,
            outcome: MutationOutcome::Unknown,
        },
    }
}

/// The HTTP status of the first Daytona SDK error in `error`'s source chain.
fn http_status(error: &(dyn StdError + 'static)) -> Option<u16> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(daytona) = error.downcast_ref::<DaytonaError>() {
            return daytona.status_code();
        }
        current = error.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use sandbox_driver::{AuthError, ProviderError, ProviderKind, ResourceKind};

    use super::*;

    fn kind() -> ProviderKind {
        ProviderKind::try_new("daytona").expect("static kind")
    }

    fn api(status_code: u16) -> DaytonaError {
        DaytonaError::Api {
            status_code,
            message: "refused".to_owned(),
            headers: HashMap::new(),
        }
    }

    #[test]
    fn credential_refusals_are_distinct_from_an_outage() {
        let rejected = Legacy::Auth(AuthError::with_source(kind(), "listing", api(401)));
        assert!(matches!(
            classify("listing", rejected),
            Error::Unauthenticated { .. }
        ));
        let forbidden = Legacy::Auth(AuthError::with_source(kind(), "listing", api(403)));
        assert!(matches!(
            classify("listing", forbidden),
            Error::PermissionDenied { .. }
        ));
        let down = Legacy::Provider(ProviderError::with_source(kind(), "listing", api(503)));
        assert!(matches!(classify("listing", down), Error::Unavailable {
            outcome: MutationOutcome::Unknown,
            ..
        }));
    }

    #[test]
    fn incomplete_cleanup_keeps_the_known_remaining_resources() {
        let mut provider = ProviderError::new(kind(), "cleanup unconfirmed");
        provider.code = Some(INCOMPLETE_CLEANUP_CODE.to_owned());
        provider.detail = Some(serde_json::json!({
            "remaining": [{"kind": "sandbox", "id": "sb-7"}],
        }));
        let Error::IncompleteCleanup { remaining, .. } =
            classify("creating", Legacy::Provider(provider))
        else {
            panic!("expected incomplete cleanup");
        };
        assert_eq!(remaining, vec![RemainingResource {
            kind: "sandbox".to_owned(),
            id:   "sb-7".to_owned(),
        }]);
    }

    #[test]
    fn a_timeout_is_never_absence_or_success() {
        let timeout = Legacy::Timeout {
            operation: "stopping".to_owned(),
            elapsed:   Duration::from_secs(1),
        };
        assert!(matches!(
            classify("stopping", timeout),
            Error::Unavailable {
                outcome: MutationOutcome::Unknown,
                ..
            }
        ));
        let not_found = Legacy::NotFound {
            resource: ResourceKind::Sandbox,
            id:       "sb-1".to_owned(),
        };
        assert!(matches!(
            classify("attaching", not_found),
            Error::NotFound { resource, .. } if resource == "sandbox"
        ));
    }

    #[test]
    fn quota_and_rate_limits_are_resource_exhaustion() {
        let limited = Legacy::RateLimited {
            retry_after: Some(Duration::from_secs(3)),
        };
        assert!(matches!(
            classify("creating", limited),
            Error::ResourceExhausted {
                retry_after_ms: Some(3000),
                ..
            }
        ));
    }
}
