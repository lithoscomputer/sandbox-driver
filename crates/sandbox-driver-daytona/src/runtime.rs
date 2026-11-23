//! Daytona on the shared sandbox contract ([`sandbox_driver`]).
//!
//! [`DaytonaFactory`] is the built-in registration: an embedding program
//! adds it with `Registry::builtin("daytona", Arc::new(DaytonaFactory))`,
//! and a provider entry with `plugin = "daytona"` then reaches Daytona
//! through the catalog. It is additive; [`crate::DaytonaProvider`] keeps
//! serving the legacy traits for current callers.

mod error;
mod handle;
mod provider;
mod runner;
mod spec;

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use daytona_api_client::apis::sandbox_api;
use daytona_sdk::Client;
use sandbox_driver::legacy::SandboxState as LegacyState;
use sandbox_driver::{
    Activation, Error, JsonSchema, MutationOutcome, PluginLocation, Provider, ProviderFactory,
    ProviderKind, ProviderSchemas,
};
use tokio::time;
use tokio_util::sync::CancellationToken;

use self::error::classify;
use self::provider::DaytonaRuntime;
use crate::sdk::{generated_error, map_state};
use crate::{TRANSITION_BUDGET, TRANSITION_POLL};

/// The Daytona built-in for the shared contract's registry.
///
/// # Configuration
///
/// The entry's `config` takes `api_url`, `organization`, `target` (the
/// Daytona region) and `runner_image`, all optional. The entry names the
/// credential under `secrets`: `DAYTONA_API_KEY`, or `DAYTONA_JWT_TOKEN`
/// together with `organization`. Nothing is read from the process
/// environment. The namespace is `daytona:<organization>`, where an API
/// key's organization is the one the control plane reports for it.
///
/// # Workloads
///
/// The caller's `source` is the workload, and every exec, file operation,
/// environment and working directory addresses it. How it runs is this
/// provider's choice:
///
/// - Without services or `container` options, the workload is the Daytona
///   sandbox itself, built from an image or Dockerfile into a snapshot named by
///   its inputs and reused, or created from a Daytona snapshot. One-shot
///   containers run on Docker inside the workload, so they need a workload
///   image that provides `docker`, `start-docker` and `python3`; without them
///   `run` returns `Unsupported` before admitting anything.
/// - With services or `container` options, the provider creates a runner
///   sandbox from a pinned Docker-capable image (an entry's `runner_image`
///   overrides it) and runs the workload as a container on the runner's
///   network, beside its services. Services are reached at `127.0.0.1:<port>`,
///   one-shot containers share the workload's workspace and network, and a
///   workload port is reachable through `ports().expose`. Service images may
///   name a registry credential whose value is `{"username", "password",
///   "server"?}` JSON or `username:password`. A restrictive network policy
///   applies once provisioning has pulled its images.
///
/// # Fencing
///
/// Daytona's control plane holds each sandbox's lifecycle state, and every
/// provider instance reaching the namespace reads the same state, so the
/// fence is shared (`access: shared`). Exec, file writes and one-shots are
/// admitted only while the sandbox is started. `stop` returns once Daytona
/// reports the sandbox stopped, which ends every process inside it: the
/// workload, nested containers, services and one-shots. A command in
/// flight watches the state and reports `killed` once its sandbox is
/// confirmed stopped, and `lost` when that cannot be established. `start`
/// refuses with `Busy` while a stop is still draining.
#[derive(Clone, Copy, Debug, Default)]
pub struct DaytonaFactory;

impl DaytonaFactory {
    /// The provider kind this factory registers as.
    pub fn kind() -> ProviderKind {
        ProviderKind::try_new("daytona").expect("static kind is valid")
    }

    /// Credential-free metadata. Nothing here reaches a backend.
    pub fn schemas() -> ProviderSchemas {
        ProviderSchemas {
            kind:          Self::kind(),
            version:       env!("CARGO_PKG_VERSION").to_owned(),
            config_schema: object(config_schema()),
            spec_schema:   Some(object(spec::spec_schema())),
            // An entry names either DAYTONA_API_KEY or DAYTONA_JWT_TOKEN;
            // activation reports which one is missing.
            secrets:       Vec::new(),
        }
    }
}

/// Refuses work once the runtime that owns `closed` has shut down. Nothing
/// has been sent when this refuses.
fn ensure_open(closed: &CancellationToken) -> Result<(), Error> {
    if closed.is_cancelled() {
        Err(Error::Stale {
            outcome: MutationOutcome::NotStarted,
        })
    } else {
        Ok(())
    }
}

/// Waits until Daytona's sandbox listing, which lags the sandbox's own
/// record, reports sandbox `id` in a state `settled` accepts, `None` when
/// it is not listed. A stop or destroy returns only then, so a list
/// that follows it shows the change.
async fn until_listed(
    client: &Client,
    id: &str,
    settled: impl Fn(Option<LegacyState>) -> bool,
) -> Result<(), Error> {
    let started = Instant::now();
    loop {
        let listed = sandbox_api::list_sandboxes(
            client.api_configuration(),
            client.organization_id(),
            None,
            None,
            Some(id),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .map_err(|error| {
            classify(
                "listing sandboxes",
                generated_error("listing sandboxes", error),
            )
        })?;
        let state = listed
            .items
            .into_iter()
            .find(|item| item.id == id)
            .map(|item| map_state(item.state));
        if settled(state) {
            return Ok(());
        }
        if started.elapsed() >= TRANSITION_BUDGET {
            return Err(Error::Unavailable {
                message: format!("Daytona still lists the sandbox as {state:?}"),
                outcome: MutationOutcome::Unknown,
            });
        }
        time::sleep(TRANSITION_POLL).await;
    }
}

fn object(value: serde_json::Value) -> JsonSchema {
    serde_json::from_value(value).expect("a constant schema is an object")
}

fn config_schema() -> serde_json::Value {
    let text = |description: &str| serde_json::json!({"type": "string", "minLength": 1, "description": description});
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "api_url": text("Daytona API base URL; the hosted service when omitted"),
            "organization": text("Organization ID; required with DAYTONA_JWT_TOKEN"),
            "target": text("Daytona region for new sandboxes and snapshots"),
            "runner_image": text("Docker-capable runner image for workloads with services or container options"),
        }
    })
}

#[async_trait]
impl ProviderFactory for DaytonaFactory {
    async fn discover(&self, _location: &PluginLocation) -> Result<ProviderSchemas, Error> {
        Ok(Self::schemas())
    }

    async fn activate(&self, activation: Activation) -> Result<Arc<dyn Provider>, Error> {
        Ok(Arc::new(DaytonaRuntime::activate(activation).await?))
    }
}
