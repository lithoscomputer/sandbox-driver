//! Daytona on the shared sandbox contract ([`sandbox_driver::contract`]).
//!
//! [`DaytonaFactory`] is the built-in registration: an embedding program
//! adds it with `Registry::builtin("daytona", Arc::new(DaytonaFactory))`,
//! and a provider entry with `plugin = "daytona"` then reaches Daytona
//! through the catalog. It is additive; [`crate::DaytonaProvider`] keeps
//! serving the legacy traits for current callers.
//!
//! # Configuration
//!
//! The entry's `config` takes `api_url`, `organization`, `target` (the
//! Daytona region) and `runner_image`, all optional. The entry names the
//! credential under `secrets`: `DAYTONA_API_KEY`, or `DAYTONA_JWT_TOKEN`
//! together with `organization`. Nothing is read from the process
//! environment. The namespace is `daytona:<organization>`, where an API
//! key's organization is the one the control plane reports for it.
//!
//! # Workloads
//!
//! The caller's `source` is the workload, and every exec, file operation,
//! environment and working directory addresses it. How it runs is this
//! provider's choice:
//!
//! - Without services or `container` options, the workload is the Daytona
//!   sandbox itself, built from an image or Dockerfile into a snapshot named by
//!   its inputs and reused, or created from a Daytona snapshot. One-shot
//!   containers run on Docker inside the workload, so they need a workload
//!   image that provides `docker`, `start-docker` and `python3`; without them
//!   `run` returns `Unsupported` before admitting anything.
//! - With services or `container` options, the provider creates a runner
//!   sandbox from a pinned Docker-capable image (an entry's `runner_image`
//!   overrides it) and runs the workload as a container on the runner's
//!   network, beside its services. Services are reached at `127.0.0.1:<port>`,
//!   one-shot containers share the workload's workspace and network, and a
//!   workload port is reachable through `ports().expose`. Service images may
//!   name a registry credential whose value is `{"username", "password",
//!   "server"?}` JSON or `username:password`. A restrictive network policy
//!   applies once provisioning has pulled its images.
//!
//! # Fencing
//!
//! Daytona's control plane holds each sandbox's lifecycle state, and every
//! provider instance reaching the namespace reads the same state, so the
//! fence is shared (`access: shared`). Exec, file writes and one-shots are
//! admitted only while the sandbox is started. `stop` returns once Daytona
//! reports the sandbox stopped, which ends every process inside it: the
//! workload, nested containers, services and one-shots. A command in
//! flight watches the state and reports `killed` once its sandbox is
//! confirmed stopped, and `lost` when that cannot be established. `start`
//! refuses with `Busy` while a stop is still draining.

mod errors;
mod handle;
mod recipe;
mod runner;
mod runtime;

use std::sync::Arc;

use async_trait::async_trait;
use sandbox_driver::ProviderKind;
use sandbox_driver::contract::{
    Activation, Error, JsonSchema, PluginLocation, ProviderFactory, ProviderRuntime,
    ProviderSchemas,
};

use self::runtime::DaytonaRuntime;

/// The Daytona built-in for the shared contract's registry.
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
            spec_schema:   Some(object(recipe::spec_schema())),
            // An entry names either DAYTONA_API_KEY or DAYTONA_JWT_TOKEN;
            // activation reports which one is missing.
            secrets:       Vec::new(),
        }
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

    async fn activate(&self, activation: Activation) -> Result<Arc<dyn ProviderRuntime>, Error> {
        Ok(Arc::new(DaytonaRuntime::activate(activation).await?))
    }
}
