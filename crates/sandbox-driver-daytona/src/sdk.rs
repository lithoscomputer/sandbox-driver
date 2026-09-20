//! Daytona SDK error and state mapping.

use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use daytona_api_client::apis::Error as ApiError;
use daytona_api_client::models::sandbox::SandboxClass as DaytonaSandboxClass;
use daytona_api_client::models::snapshot_dto::SandboxClass as DaytonaSnapshotClass;
use daytona_api_client::models::{
    SandboxClass as DaytonaCreateSandboxClass, SnapshotState as ApiSnapshotState,
    VolumeState as ApiVolumeState,
};
use daytona_sdk::{Client, DaytonaError};
use sandbox_driver::{
    AuthError, Error, ProviderError, ProviderKind, ResourceKind, Result, SandboxKind, SandboxState,
    SnapshotState, VolumeState,
};

pub(crate) type DaytonaClient = Arc<Client>;

pub(crate) fn is_not_found(error: &DaytonaError) -> bool {
    matches!(error, DaytonaError::NotFound { .. })
}

/// The error mapping for fetching one resource by id: the SDK's not-found
/// becomes the typed [`Error::NotFound`] for `resource`, anything else is
/// a provider error under `context`.
pub(crate) fn fetch_error(
    resource: ResourceKind,
    id: &str,
    context: &'static str,
) -> impl FnOnce(DaytonaError) -> Error {
    let id = id.to_owned();
    move |error| {
        if is_not_found(&error) {
            Error::NotFound { resource, id }
        } else {
            daytona_error(context, error)
        }
    }
}

/// A lifecycle action racing an in-flight state change: Daytona rejects
/// it with "Sandbox state change in progress" — HTTP 400 in observed
/// traffic (409 accepted defensively). For an idempotent action that
/// means wait for the transition to settle and re-check, never fail.
pub(crate) fn is_state_change_in_progress(error: &DaytonaError) -> bool {
    matches!(
        error,
        DaytonaError::Api {
            status_code: 400 | 409,
            message,
            ..
        } if message.to_lowercase().contains("state change in progress")
    )
}

pub(crate) fn is_snapshot_deactivation_in_progress(error: &DaytonaError) -> bool {
    matches!(
        error,
        DaytonaError::Api {
            status_code: 400,
            message,
            ..
        } if message.to_lowercase().contains("deactivation is still in progress")
    )
}

/// Maps a generated-client error for the few control-plane endpoints the
/// wrapped SDK does not cover (snapshot deactivation, API-key
/// introspection).
pub(crate) fn generated_error<T>(context: &str, error: ApiError<T>) -> Error
where
    T: Debug + Send + Sync + 'static,
{
    let kind = ProviderKind::try_new("daytona").expect("static kind is valid");
    let status = match &error {
        ApiError::ResponseError(content) => Some(content.status),
        _ => None,
    };
    let mut provider = ProviderError::with_source(kind, context, error);
    if let Some(status) = status {
        provider.code = Some(status.as_u16().to_string());
        provider.retryable = status.is_server_error();
    }
    Error::Provider(provider)
}

pub(crate) fn is_generated_not_found<T>(error: &ApiError<T>) -> bool {
    matches!(error, ApiError::ResponseError(content) if content.status.as_u16() == 404)
}

/// The console page listing sandboxes, derived from the API base path —
/// the hosted control plane serves the API under `/api` next to the
/// dashboard. A differently shaped deployment gets no link rather than
/// a guessed one.
pub(crate) fn dashboard_url(client: &daytona_sdk::Client) -> Option<String> {
    client
        .api_configuration()
        .base_path
        .strip_suffix("/api")
        .map(|base| format!("{base}/dashboard/sandboxes"))
}

pub(crate) fn daytona_error(context: &str, error: DaytonaError) -> Error {
    let kind = ProviderKind::try_new("daytona").expect("static kind is valid");
    if let DaytonaError::RateLimit { headers, .. } = &error {
        let retry_after = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
            .and_then(|(_, value)| value.parse::<u64>().ok())
            .map(Duration::from_secs);
        return Error::RateLimited { retry_after };
    }
    if matches!(&error, DaytonaError::Api {
        status_code: 401 | 403,
        ..
    }) {
        return Error::Auth(AuthError::with_source(kind, context, error));
    }

    let status_code = error.status_code();
    let timed_out = matches!(&error, DaytonaError::Timeout { .. });
    let mut provider = ProviderError::with_source(kind, context, error);
    if let Some(status_code) = status_code {
        provider.code = Some(status_code.to_string());
        provider.retryable = status_code >= 500;
    } else if timed_out {
        provider.code = Some("timeout".to_owned());
        // A request timeout does not prove the remote operation stopped:
        // retrying a clone whose first attempt is still writing the
        // target overlaps it (fabro never retried timeouts for exactly
        // this reason). Callers judge idempotent retries themselves.
        provider.retryable = false;
    }
    Error::Provider(provider)
}

pub(crate) fn map_state(state: Option<daytona_sdk::SandboxState>) -> SandboxState {
    use daytona_sdk::SandboxState as Ds;
    match state {
        None => SandboxState::Unknown,
        Some(state) => match state {
            Ds::Creating | Ds::PendingBuild | Ds::BuildingSnapshot | Ds::PullingSnapshot => {
                SandboxState::Creating
            }
            Ds::Restoring | Ds::Starting => SandboxState::Starting,
            // A snapshotting sandbox stays fully usable (fabro mapped it
            // to Running deliberately); reporting it transitional makes
            // activation and waits stall through a multi-minute snapshot.
            // The raw string still reaches callers via provider_state.
            Ds::Started | Ds::Snapshotting => SandboxState::Running,
            Ds::Stopping => SandboxState::Stopping,
            Ds::Stopped => SandboxState::Stopped,
            Ds::Archiving => SandboxState::Archiving,
            Ds::Archived => SandboxState::Archived,
            Ds::Resizing => SandboxState::Resizing,
            Ds::Forking => SandboxState::Forking,
            Ds::Pausing => SandboxState::Pausing,
            Ds::Paused => SandboxState::Paused,
            Ds::Resuming => SandboxState::Resuming,
            Ds::Destroying => SandboxState::Deleting,
            Ds::Destroyed => SandboxState::Deleted,
            Ds::Error | Ds::BuildFailed => SandboxState::Error,
            Ds::Unknown | Ds::UnknownDefaultOpenApi => SandboxState::Unknown,
        },
    }
}

pub(crate) fn sandbox_kind_from_sandbox_class(class: DaytonaSandboxClass) -> SandboxKind {
    match class {
        DaytonaSandboxClass::CONTAINER => SandboxKind::Container,
        DaytonaSandboxClass::LINUX_VM
        | DaytonaSandboxClass::ANDROID
        | DaytonaSandboxClass::WINDOWS => SandboxKind::VirtualMachine,
        DaytonaSandboxClass::UnknownDefaultOpenApi => SandboxKind::Unknown,
    }
}

pub(crate) fn sandbox_kind_from_snapshot_class(class: DaytonaSnapshotClass) -> SandboxKind {
    match class {
        DaytonaSnapshotClass::CONTAINER => SandboxKind::Container,
        DaytonaSnapshotClass::LINUX_VM
        | DaytonaSnapshotClass::ANDROID
        | DaytonaSnapshotClass::WINDOWS => SandboxKind::VirtualMachine,
        DaytonaSnapshotClass::UnknownDefaultOpenApi => SandboxKind::Unknown,
    }
}

pub(crate) fn daytona_snapshot_class(kind: SandboxKind) -> Result<DaytonaCreateSandboxClass> {
    match kind {
        SandboxKind::Container => Ok(DaytonaCreateSandboxClass::CONTAINER),
        SandboxKind::VirtualMachine => Ok(DaytonaCreateSandboxClass::LINUX_VM),
        _ => Err(Error::invalid_spec("sandbox_kind", "unknown sandbox kind")),
    }
}

pub(crate) fn map_snapshot_state(state: ApiSnapshotState) -> SnapshotState {
    use ApiSnapshotState as Ds;
    match state {
        Ds::Building | Ds::Pending | Ds::Pulling | Ds::Snapshotting => SnapshotState::Building,
        Ds::Active => SnapshotState::Active,
        Ds::Inactive => SnapshotState::Inactive,
        Ds::Error | Ds::BuildFailed => SnapshotState::Error,
        Ds::Removing => SnapshotState::Deleting,
        Ds::UnknownDefaultOpenApi => SnapshotState::Unknown,
    }
}

pub(crate) fn map_volume_state(state: ApiVolumeState) -> VolumeState {
    use ApiVolumeState as Ds;
    match state {
        Ds::Creating | Ds::PendingCreate => VolumeState::Creating,
        Ds::Ready => VolumeState::Ready,
        Ds::Deleting | Ds::PendingDelete => VolumeState::Deleting,
        Ds::Deleted => VolumeState::Deleted,
        Ds::Error => VolumeState::Error,
        Ds::UnknownDefaultOpenApi => VolumeState::Unknown,
    }
}

/// Converts a non-negative float to `u64`, `None` when out of range.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "guarded by the range check"
)]
pub(crate) fn to_u64(value: f64) -> Option<u64> {
    (value.is_finite() && value >= 0.0 && value < u64::MAX as f64).then(|| value.round() as u64)
}

/// Converts a timer duration to Daytona's whole-minute intervals,
/// rounding up so a sub-minute timer never truncates away. Wire `0`
/// (from `Duration::ZERO`) is deliberate and timer-specific: it
/// disables auto-stop, and defers auto-archive to Daytona's maximum
/// interval — the closest the API comes to disabling it.
pub(crate) fn minutes(duration: Duration) -> i32 {
    if duration.is_zero() {
        return 0;
    }
    i32::try_from(duration.as_secs().div_ceil(60)).unwrap_or(i32::MAX)
}

/// Auto-delete has inverted zero semantics on the wire: `0` means
/// "delete immediately upon stopping" (the ephemeral encoding, sent
/// only via the spec flag) and a negative value disables — so
/// `Duration::ZERO`, the crate-wide explicit "never", crosses as `-1`.
pub(crate) fn auto_delete_minutes(duration: Duration) -> i32 {
    if duration.is_zero() {
        return -1;
    }
    minutes(duration)
}

pub(crate) fn gigabytes(mb: u64) -> i32 {
    i32::try_from(mb.div_ceil(1024)).unwrap_or(i32::MAX).max(1)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap as StdHashMap;
    use std::error::Error as _;

    use super::*;

    fn api_error(status_code: u16, message: &str) -> DaytonaError {
        DaytonaError::Api {
            status_code,
            message: message.to_owned(),
            headers: StdHashMap::new(),
        }
    }

    #[test]
    fn state_change_in_progress_matches_the_observed_rejection() {
        // Real Daytona traffic reports this class as HTTP 400.
        assert!(is_state_change_in_progress(&api_error(
            400,
            "Sandbox state change in progress"
        )));
        assert!(is_state_change_in_progress(&api_error(
            409,
            "State change in progress"
        )));
        assert!(!is_state_change_in_progress(&api_error(400, "Bad request")));
        assert!(!is_state_change_in_progress(&api_error(
            409,
            "Name conflict"
        )));
    }

    #[test]
    fn snapshot_deactivation_race_matches_the_observed_rejection() {
        assert!(is_snapshot_deactivation_in_progress(&api_error(
            400,
            "Snapshot deactivation is still in progress. Please try again in a few minutes."
        )));
        assert!(!is_snapshot_deactivation_in_progress(&api_error(
            400,
            "Bad request"
        )));
    }

    #[test]
    fn fetch_errors_type_not_found_and_keep_the_context_otherwise() {
        let missing =
            fetch_error(ResourceKind::Volume, "vol-1", "fetching volume")(DaytonaError::NotFound {
                message: "gone".to_owned(),
                headers: StdHashMap::new(),
            });
        assert!(matches!(
            missing,
            Error::NotFound { resource: ResourceKind::Volume, id } if id == "vol-1"
        ));
        let failed =
            fetch_error(ResourceKind::Volume, "vol-1", "fetching volume")(api_error(500, "boom"));
        let Error::Provider(provider) = failed else {
            panic!("expected a provider error");
        };
        assert_eq!(provider.message, "fetching volume");
    }

    #[test]
    fn provider_mapping_preserves_sources_and_retry_metadata() {
        let error = daytona_error("listing sandboxes", api_error(503, "service unavailable"));
        let Error::Provider(provider) = error else {
            panic!("expected a provider error");
        };
        assert_eq!(provider.message, "listing sandboxes");
        assert_eq!(provider.code.as_deref(), Some("503"));
        assert!(provider.retryable);
        assert_eq!(
            provider.source().expect("provider source").to_string(),
            "service unavailable"
        );
    }

    #[test]
    fn a_request_timeout_is_not_marked_retryable() {
        // A timeout does not prove the remote operation stopped; a
        // consumer honoring `retryable` must not overlap a still-running
        // first attempt (a clone still writing its target, say).
        let error = daytona_error("cloning git repository", DaytonaError::Timeout {
            message: "request timed out".to_owned(),
        });
        let Error::Provider(provider) = error else {
            panic!("expected a provider error");
        };
        assert_eq!(provider.code.as_deref(), Some("timeout"));
        assert!(!provider.retryable);
    }

    #[test]
    fn authentication_mapping_keeps_the_sdk_cause() {
        let error = daytona_error("connecting to daytona", api_error(401, "invalid token"));
        let Error::Auth(auth) = error else {
            panic!("expected an authentication error");
        };
        assert_eq!(auth.reason, "connecting to daytona");
        assert_eq!(
            auth.source().expect("authentication source").to_string(),
            "invalid token"
        );
    }

    #[test]
    fn rate_limit_mapping_keeps_retry_after() {
        let mut headers = StdHashMap::new();
        headers.insert("Retry-After".to_owned(), "17".to_owned());
        let error = daytona_error("listing sandboxes", DaytonaError::RateLimit {
            message: "slow down".to_owned(),
            headers,
        });
        assert!(matches!(error, Error::RateLimited {
            retry_after: Some(retry_after),
        } if retry_after == Duration::from_secs(17)));
    }

    #[test]
    fn snapshotting_sandboxes_report_running() {
        // Usable during a snapshot: activation and waits must not stall
        // through it.
        assert_eq!(
            map_state(Some(daytona_sdk::SandboxState::Snapshotting)),
            SandboxState::Running
        );
    }

    #[test]
    fn minutes_round_up_to_at_least_one() {
        assert_eq!(minutes(Duration::from_secs(30)), 1);
        assert_eq!(minutes(Duration::from_secs(120)), 2);
        assert_eq!(minutes(Duration::from_secs(150)), 3);
    }

    #[test]
    fn minutes_pass_zero_through_as_disabled() {
        // Wire 0 disables auto-stop and defers auto-archive to the
        // maximum interval.
        assert_eq!(minutes(Duration::ZERO), 0);
    }

    #[test]
    fn auto_delete_zero_crosses_as_negative_disabled() {
        // Wire 0 means "delete immediately upon stopping"; disabled is
        // a negative value. Mapping ZERO to 0 would turn "never
        // auto-delete" into destroying the sandbox on every stop.
        assert_eq!(auto_delete_minutes(Duration::ZERO), -1);
        assert_eq!(auto_delete_minutes(Duration::from_secs(90)), 2);
    }

    #[test]
    fn gigabytes_round_up() {
        assert_eq!(gigabytes(1), 1);
        assert_eq!(gigabytes(1024), 1);
        assert_eq!(gigabytes(1025), 2);
    }
}
