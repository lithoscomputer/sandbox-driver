//! Daemon-scoped admission serialization. Docker's unique container names
//! provide the compare-and-create operation shared by independent clients.
//!
//! The marker is never started. A dropped request deliberately retains it:
//! losing the caller cannot prove that the daemon finished its mutation.
//! No lease expiry or automatic takeover can restart work behind a drain.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::future::Future;
use std::process;
use std::result::Result as StdResult;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bollard::Docker;
use bollard::container::{Config, CreateContainerOptions, ListContainersOptions};
use bollard::errors::Error as DockerApiError;
use bollard::models::ContainerCreateResponse;
use futures_util::future::BoxFuture;
use sandbox_driver::{Error, ProviderError, Result, TransportError};
use serde_json::Value;
use tokio::time::error::Elapsed;
use tokio::time::{Instant, sleep, timeout};

use crate::MANAGED_LABEL;
use crate::container::{inspect_container, remove_container_forced};
use crate::daemon::{docker_error, docker_kind, is_conflict};
use crate::inspect::label_of;
use crate::one_shot::ONE_SHOT_LABEL;
use crate::sidecars::NETWORK_LABEL;

pub(crate) const FENCE_NAME_LABEL: &str = "sh.sandbox-driver.fence-name";
pub(crate) const FENCE_LABEL: &str = "sh.sandbox-driver.fence";
const OPERATION_LABEL: &str = "sh.sandbox-driver.fence-operation";
const ADMISSION_WAIT: Duration = Duration::from_secs(5);
const MAX_ADMISSION_POLL: Duration = Duration::from_millis(200);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
/// Creation and start wait on image pulls and service readiness.
const PROVISIONING_TIMEOUT: Duration = Duration::from_secs(360);

/// What a fence owner is doing, recorded on its marker.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    Admit,
    Create,
    Start,
    Stop,
    Delete,
    Pause,
    Resume,
}

impl Operation {
    fn label(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Create => "create",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Delete => "delete",
            Self::Pause => "pause",
            Self::Resume => "resume",
        }
    }

    fn budget(self) -> Duration {
        match self {
            Self::Create | Self::Start => PROVISIONING_TIMEOUT,
            _ => OPERATION_TIMEOUT,
        }
    }

    /// An absent primary cannot admit new work, so only teardown proceeds.
    fn tolerates_absent(self) -> bool {
        matches!(self, Self::Stop | Self::Delete)
    }
}

/// Serializes admissions and lifecycle changes, not the lifetime of a command.
/// Once admission completes, stopping the primary and sweeping its labeled
/// siblings ends the admitted work. The marker is excluded from inventory.
pub(crate) fn run<'a, T: Send + 'a>(
    docker: &'a Docker,
    id: &'a str,
    operation: Operation,
    work: impl Future<Output = Result<T>> + Send + 'a,
) -> BoxFuture<'a, Result<T>> {
    // Box this orchestration boundary: combining daemon inspection, claim
    // allocation, and the operation would otherwise inflate every caller.
    Box::pin(async move {
        let marker = match timeout(OPERATION_TIMEOUT, acquire(docker, id, operation)).await {
            Ok(result) => result?,
            Err(_) => return Err(acquisition_timeout(id)),
        };
        let Some(marker) = marker else {
            return timeout(OPERATION_TIMEOUT, work)
                .await
                .map_err(|_| acquisition_timeout(id))?;
        };
        finish(docker, &marker, operation, work).await
    })
}

async fn finish<T>(
    docker: &Docker,
    marker: &str,
    operation: Operation,
    work: impl Future<Output = Result<T>>,
) -> Result<T> {
    // A completed response (including a refusal) releases ownership. A lost
    // response does not prove that the daemon stopped processing the request.
    let result = match timeout(operation.budget(), work).await {
        Ok(Err(error)) if retain_claim(&error) => return Err(retain_error(marker, error)),
        Ok(result) => result,
        Err(_) => return Err(retained(marker, "operation timed out", None)),
    };
    match timeout(
        OPERATION_TIMEOUT,
        remove_container_forced(docker, marker, "releasing sandbox fence"),
    )
    .await
    {
        Ok(Ok(())) => result,
        Ok(Err(error)) => Err(retained(marker, "fence release failed", Some(error))),
        Err(_) => Err(retained(marker, "fence release timed out", None)),
    }
}

async fn acquire(docker: &Docker, id: &str, operation: Operation) -> Result<Option<String>> {
    // Canonical IDs prevent names and short IDs from producing different locks.
    let inspect = match inspect_container(docker, id).await {
        Ok(inspect) => inspect,
        Err(Error::NotFound { .. }) if operation.tolerates_absent() => {
            // An earlier request may still own its marker, though, so
            // absence alone is insufficient.
            ensure_absent(docker, id).await?;
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let id = inspect
        .id
        .as_deref()
        .ok_or_else(|| Error::Transport(TransportError::new("daemon omitted the sandbox ID")))?;
    let image = inspect
        .image
        .as_deref()
        .ok_or_else(|| Error::Transport(TransportError::new("daemon omitted the sandbox image")))?;
    let name = label_of(&inspect, FENCE_NAME_LABEL)
        .map_or_else(|| format!("sandbox-driver-fence-{id}"), str::to_owned);
    let deadline = Instant::now() + ADMISSION_WAIT;
    let mut poll = Duration::from_millis(10);
    loop {
        match create_marker(docker, image, &name, id, operation).await {
            Ok(Err(error)) if is_conflict(&error) => {
                // Short concurrent admissions can queue, preserving concurrent
                // exec callers. Lifecycle ownership is always a Busy refusal.
                let queued = match inspect_container(docker, &name).await {
                    Ok(marker) => {
                        label_of(&marker, OPERATION_LABEL) == Some(Operation::Admit.label())
                    }
                    // Released between the attempt and the inspect: retry, but
                    // still within the admission wait.
                    Err(Error::NotFound { .. }) => true,
                    Err(error) => return Err(error),
                };
                if !queued || Instant::now() >= deadline {
                    return Err(busy("another operation owns the sandbox fence"));
                }
                sleep(poll).await;
                poll = (poll * 2).min(MAX_ADMISSION_POLL);
            }
            attempt => return claimed(&name, attempt).map(Some),
        }
    }
}

/// Allocates the gate before the primary is visible to attach/list. Its name
/// is stored in the primary's immutable labels, so all later clients use it.
pub(crate) fn reserve_creation(labels: &mut Option<HashMap<String, String>>) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let name = format!(
        "sandbox-driver-fence-create-{}-{time}-{}",
        process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    labels
        .get_or_insert_default()
        .insert(FENCE_NAME_LABEL.to_owned(), name.clone());
    name
}

pub(crate) fn create<'a, T: Send + 'a>(
    docker: &'a Docker,
    image: &'a str,
    name: &'a str,
    work: impl Future<Output = Result<T>> + Send + 'a,
) -> BoxFuture<'a, Result<T>> {
    // Boxed for the same reason as `run`.
    Box::pin(async move {
        let attempt = create_marker(docker, image, name, name, Operation::Create).await;
        let marker = claimed(name, attempt)?;
        finish(docker, &marker, Operation::Create, work).await
    })
}

type MarkerAttempt = StdResult<StdResult<ContainerCreateResponse, DockerApiError>, Elapsed>;

async fn create_marker(
    docker: &Docker,
    image: &str,
    name: &str,
    id: &str,
    operation: Operation,
) -> MarkerAttempt {
    timeout(
        OPERATION_TIMEOUT,
        docker.create_container(
            Some(CreateContainerOptions {
                name:     name.to_owned(),
                platform: None,
            }),
            Config {
                image: Some(image.to_owned()),
                entrypoint: Some(vec!["/bin/false".to_owned()]),
                labels: Some(HashMap::from([
                    (FENCE_LABEL.to_owned(), id.to_owned()),
                    (MANAGED_LABEL.to_owned(), "false".to_owned()),
                    (OPERATION_LABEL.to_owned(), operation.label().to_owned()),
                    // Image labels are merged by Docker. A claim must never
                    // inherit a sibling-discovery label and be swept while
                    // its critical section is still running.
                    (ONE_SHOT_LABEL.to_owned(), String::new()),
                    (NETWORK_LABEL.to_owned(), String::new()),
                ])),
                ..Default::default()
            },
        ),
    )
    .await
}

/// The marker a creation attempt produced, unless the daemon refused it.
fn claimed(name: &str, attempt: MarkerAttempt) -> Result<String> {
    match attempt {
        Ok(Ok(created)) if created.id.is_empty() => {
            Err(retained(name, "daemon omitted the fence ID", None))
        }
        Ok(Ok(created)) => Ok(created.id),
        Ok(Err(error)) => {
            let error = docker_error("acquiring sandbox fence", error);
            Err(if uncertain(&error) {
                retained(name, "fence acquisition outcome is unknown", Some(error))
            } else {
                error
            })
        }
        Err(_) => Err(retained(name, "fence acquisition timed out", None)),
    }
}

/// An absent primary is not proof that an earlier request released ownership.
async fn ensure_absent(docker: &Docker, id: &str) -> Result<()> {
    let markers = timeout(
        OPERATION_TIMEOUT,
        docker.list_containers(Some(ListContainersOptions {
            all: true,
            filters: HashMap::from([("label".to_owned(), vec![format!("{FENCE_LABEL}={id}")])]),
            ..Default::default()
        })),
    )
    .await
    .map_err(|_| acquisition_timeout(id))?
    .map_err(|error| docker_error("discovering sandbox fence", error))?;
    if markers.is_empty() {
        Ok(())
    } else {
        Err(busy("another operation owns the sandbox fence"))
    }
}

fn retain_claim(error: &Error) -> bool {
    matches!(error, Error::Provider(error) if error.code.as_deref() == Some("fence_leaked"))
        || uncertain(error)
}

fn uncertain(error: &Error) -> bool {
    let mut cause: Option<&(dyn StdError + 'static)> = Some(error);
    while let Some(current) = cause {
        if matches!(current.downcast_ref::<Error>(), Some(Error::Transport(_))) {
            return true;
        }
        if let Some(error) = current.downcast_ref::<DockerApiError>() {
            return !matches!(error, DockerApiError::DockerResponseServerError { .. });
        }
        if current.downcast_ref::<TransportError>().is_some() {
            return true;
        }
        cause = current.source();
    }
    false
}

fn busy(message: &str) -> Error {
    let mut error = ProviderError::new(docker_kind(), message);
    error.code = Some("busy".to_owned());
    Error::Provider(error)
}

fn retain_error(marker: &str, error: Error) -> Error {
    match error {
        Error::Provider(mut failure) if failure.code.as_deref() == Some("fence_leaked") => {
            failure.detail.get_or_insert_with(|| serde_json::json!({}))["fence_container"] =
                Value::String(marker.to_owned());
            Error::Provider(failure)
        }
        Error::Provider(mut failure) if failure.code.as_deref() == Some("incomplete_cleanup") => {
            if let Some(remaining) = failure
                .detail
                .as_mut()
                .and_then(|detail| detail.get_mut("remaining"))
                .and_then(Value::as_array_mut)
            {
                remaining.push(serde_json::json!({"kind": "fence_container", "id": marker}));
            }
            Error::Provider(failure)
        }
        error => retained(marker, "daemon outcome is unknown", Some(error)),
    }
}

fn acquisition_timeout(id: &str) -> Error {
    let mut error = ProviderError::new(
        docker_kind(),
        "fence acquisition or discovery timed out; ownership requires reconciliation",
    );
    error.code = Some("transport".to_owned());
    error.detail = Some(serde_json::json!({"sandbox_id": id, "outcome": "unknown"}));
    Error::Provider(error)
}

fn retained(marker: &str, reason: &str, source: Option<Error>) -> Error {
    let message = format!("{reason}; sandbox fence retained for reconciliation");
    let mut error = match source {
        Some(source) => ProviderError::with_source(docker_kind(), message, source),
        None => ProviderError::new(docker_kind(), message),
    };
    error.code = Some("transport".to_owned());
    error.detail = Some(serde_json::json!({"fence_container": marker, "outcome": "unknown"}));
    Error::Provider(error)
}
