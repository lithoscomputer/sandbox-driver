//! Bounded cleanup of known resources after a failed admission.

use std::time::Duration;

use sandbox_driver::{Error, ErrorReport, ProviderError, ProviderKind, Result, SandboxState};
use tokio::time;

use crate::TRANSITION_POLL;
use crate::sdk::{DaytonaClient, daytona_error, is_not_found, map_state};

/// A single delete request, followed by observations of authoritative absence.
/// No uncertain mutation is replayed. A failed observation cannot prove
/// cleanup.
async fn delete_and_confirm(client: &DaytonaClient, id: &str) -> Result<()> {
    match client.delete(id).await {
        Ok(()) => {}
        Err(error) if is_not_found(&error) => return Ok(()),
        Err(error) => return Err(daytona_error("requesting failed-create cleanup", error)),
    }
    loop {
        match client.get(id).await {
            Ok(sandbox) if map_state(sandbox.state) == SandboxState::Deleted => return Ok(()),
            Ok(_) => {}
            Err(error) if is_not_found(&error) => return Ok(()),
            Err(error) => return Err(daytona_error("confirming failed-create cleanup", error)),
        }
        time::sleep(TRANSITION_POLL).await;
    }
}

pub(crate) async fn failed_create(
    client: &DaytonaClient,
    id: &str,
    cause: Error,
    budget: Duration,
) -> Error {
    let cleanup = time::timeout(budget, delete_and_confirm(client, id))
        .await
        .unwrap_or_else(|_| {
            Err(Error::Timeout {
                operation: "confirming failed-create cleanup".to_owned(),
                elapsed:   budget,
            })
        });
    let Err(cleanup) = cleanup else {
        return cause;
    };
    // Preserve the legacy error surface and both failures. The new-contract
    // adapter can classify this explicit code, without matching message text.
    let mut error = ProviderError::with_source(
        ProviderKind::try_new("daytona").expect("static provider kind"),
        format!("failed-create cleanup is unconfirmed for sandbox {id}"),
        cause,
    );
    error.code = Some("cleanup_unconfirmed".to_owned());
    error.detail = Some(serde_json::json!({
        "remaining": [{"kind": "sandbox", "id": id}],
        "cleanup": ErrorReport::from(&cleanup),
    }));
    Error::Provider(error)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::fake_daytona::{FakeDaytona, Reply};

    fn cause() -> Error {
        Error::invalid_spec("service", "readiness failed")
    }

    fn sandbox(state: &str) -> Reply {
        Reply::Json(
            200,
            serde_json::json!({
                "id": "sb-1", "organizationId": "org-1", "name": "sb", "user": "daytona",
                "env": {}, "labels": {}, "public": false, "networkBlockAll": false,
                "target": "us", "cpu": 1.0, "gpu": 0.0, "memory": 1.0, "disk": 1.0,
                "state": state,
            })
            .to_string(),
        )
    }

    fn assert_unconfirmed(error: &Error, cleanup_kind: &str) {
        let Error::Provider(provider) = error else {
            panic!("expected unconfirmed cleanup, got {error:?}");
        };
        assert_eq!(provider.code.as_deref(), Some("cleanup_unconfirmed"));
        assert!(!provider.retryable, "uncertain creates are not replayable");
        let detail = provider.detail.as_ref().unwrap();
        assert_eq!(detail["remaining"][0]["id"], "sb-1");
        assert_eq!(detail["cleanup"]["kind"], cleanup_kind);
        assert!(
            ErrorReport::from(error)
                .causes
                .iter()
                .any(|cause| cause.contains("readiness failed"))
        );
    }

    #[tokio::test]
    async fn accepted_delete_waits_for_absence_without_replaying_delete() {
        let observations = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&observations);
        let fake = FakeDaytona::start(|_| {
            Arc::new(move |method, _| {
                if method == "DELETE" {
                    return Reply::Json(200, "{}".to_owned());
                }
                if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                    sandbox("destroying")
                } else {
                    Reply::Json(404, "{}".to_owned())
                }
            })
        })
        .await;
        let error = failed_create(
            &fake.client().await,
            "sb-1",
            cause(),
            Duration::from_secs(5),
        )
        .await;
        assert!(matches!(error, Error::InvalidSpec { .. }));
        assert_eq!(observations.load(Ordering::SeqCst), 2);
        assert_eq!(fake.deletes(), 1);
    }

    #[tokio::test]
    async fn terminal_deleted_state_and_delete_not_found_confirm_cleanup() {
        for missing in [false, true] {
            let fake = FakeDaytona::start(|_| {
                Arc::new(move |method, _| {
                    if method == "DELETE" {
                        Reply::Json(if missing { 404 } else { 200 }, "{}".to_owned())
                    } else {
                        sandbox("destroyed")
                    }
                })
            })
            .await;
            let error = failed_create(
                &fake.client().await,
                "sb-1",
                cause(),
                Duration::from_secs(1),
            )
            .await;
            assert!(matches!(error, Error::InvalidSpec { .. }));
            assert_eq!(fake.deletes(), 1);
        }
    }

    #[tokio::test]
    async fn pending_deletion_or_stalled_requests_retain_the_resource_id() {
        for hang in ["delete", "observe", "neither"] {
            let fake = FakeDaytona::start(|_| {
                Arc::new(move |method, _| {
                    if (method == "DELETE" && hang == "delete")
                        || (method == "GET" && hang == "observe")
                    {
                        Reply::Hang
                    } else if method == "DELETE" {
                        Reply::Json(200, "{}".to_owned())
                    } else {
                        sandbox("destroying")
                    }
                })
            })
            .await;
            let error = time::timeout(
                Duration::from_secs(2),
                failed_create(
                    &fake.client().await,
                    "sb-1",
                    cause(),
                    Duration::from_millis(100),
                ),
            )
            .await
            .expect("cleanup has an overall deadline");
            assert_unconfirmed(&error, "timeout");
            assert_eq!(fake.deletes(), 1);
        }
    }

    #[tokio::test]
    async fn delete_or_observation_failure_is_not_absence() {
        for fail_delete in [false, true] {
            let fake = FakeDaytona::start(|_| {
                Arc::new(move |method, _| {
                    Reply::Json(
                        if method == "DELETE" && !fail_delete {
                            200
                        } else {
                            500
                        },
                        "{}".to_owned(),
                    )
                })
            })
            .await;
            let error = failed_create(
                &fake.client().await,
                "sb-1",
                cause(),
                Duration::from_secs(1),
            )
            .await;
            assert_unconfirmed(&error, "provider");
            assert_eq!(fake.deletes(), 1);
        }
    }
}
