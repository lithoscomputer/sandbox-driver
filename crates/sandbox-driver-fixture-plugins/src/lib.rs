//! Fixture plugins for the third-party plugin path. Each binary serves a
//! built-in provider's unchanged runtime over protocol version 3 under a
//! non-reserved kind, so the loader is proven with real processes, streams
//! and fences. Only the kind differs; everything else is delegated.

use std::sync::Arc;

use async_trait::async_trait;
use sandbox_driver::contract::{
    Activation, Descriptor, Error, Health, LabelFilter, PluginLocation, ProviderFactory,
    ProviderRuntime, ProviderSchemas, Sandbox, SandboxSummary, WorkloadAdmission,
};
use sandbox_driver::{ProviderKind, SandboxId};
use sandbox_driver_protocol::{Plugin, run_plugin};

/// Serves `factory` over protocol version 3, reporting `kind` in place of
/// its own.
pub async fn serve_renamed(
    kind: &str,
    schemas: ProviderSchemas,
    factory: Arc<dyn ProviderFactory>,
) -> sandbox_driver::Result<()> {
    let schemas = ProviderSchemas {
        kind: ProviderKind::try_new(kind).expect("valid kind"),
        ..schemas
    };
    run_plugin(Plugin::new(
        schemas.clone(),
        Arc::new(Renamed { schemas, factory }),
    ))
    .await
}

struct Renamed {
    schemas: ProviderSchemas,
    factory: Arc<dyn ProviderFactory>,
}

#[async_trait]
impl ProviderFactory for Renamed {
    async fn discover(&self, _: &PluginLocation) -> Result<ProviderSchemas, Error> {
        Ok(self.schemas.clone())
    }

    async fn activate(&self, activation: Activation) -> Result<Arc<dyn ProviderRuntime>, Error> {
        Ok(Arc::new(RenamedRuntime {
            schemas: self.schemas.clone(),
            runtime: self.factory.activate(activation).await?,
        }))
    }
}

struct RenamedRuntime {
    schemas: ProviderSchemas,
    runtime: Arc<dyn ProviderRuntime>,
}

#[async_trait]
impl ProviderRuntime for RenamedRuntime {
    async fn describe(&self) -> Result<Descriptor, Error> {
        Ok(Descriptor {
            schemas: self.schemas.clone(),
            ..self.runtime.describe().await?
        })
    }

    async fn health(&self) -> Result<Health, Error> {
        self.runtime.health().await
    }

    async fn create(&self, admission: WorkloadAdmission) -> Result<Box<dyn Sandbox>, Error> {
        self.runtime.create(admission).await
    }

    async fn attach(&self, id: &SandboxId) -> Result<Box<dyn Sandbox>, Error> {
        self.runtime.attach(id).await
    }

    async fn list(&self, filter: &LabelFilter) -> Result<Vec<SandboxSummary>, Error> {
        self.runtime.list(filter).await
    }

    async fn destroy(&self, id: &SandboxId) -> Result<(), Error> {
        self.runtime.destroy(id).await
    }

    async fn shutdown(&self) -> Result<(), Error> {
        self.runtime.shutdown().await
    }
}
