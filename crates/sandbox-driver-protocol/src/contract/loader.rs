use std::sync::Arc;

use async_trait::async_trait;
use sandbox_driver::contract::{
    Activation, Error, PluginLocation, ProviderFactory, ProviderRuntime, ProviderSchemas,
};

use crate::TransportLimits;
use crate::client::contract::{Launch, PluginRuntime};
use crate::metadata::SchemaDiscovery;

/// The ordinary loader for configured third-party plugins. Discovery
/// verifies trust and probes without credentials; activation re-verifies
/// the same bytes, then starts the child with exactly the catalog's frozen
/// environment and resolved secrets.
pub struct PluginLoader {
    discovery: SchemaDiscovery,
    limits:    TransportLimits,
}

impl Default for PluginLoader {
    fn default() -> Self {
        Self::new(SchemaDiscovery::default(), TransportLimits::default())
    }
}

impl PluginLoader {
    pub fn new(discovery: SchemaDiscovery, limits: TransportLimits) -> Self {
        Self { discovery, limits }
    }
}

#[async_trait]
impl ProviderFactory for PluginLoader {
    async fn discover(&self, location: &PluginLocation) -> Result<ProviderSchemas, Error> {
        Ok(self.discovery.discover(location).await?.schemas().clone())
    }

    async fn activate(&self, activation: Activation) -> Result<Arc<dyn ProviderRuntime>, Error> {
        let Activation {
            name,
            entry,
            schemas,
            mut environment,
            secrets,
        } = activation;
        let discovered = self
            .discovery
            .discover(&PluginLocation {
                entry: name.clone(),
                kind:  entry.plugin.clone(),
                path:  entry.path.clone(),
                trust: entry.trust.clone(),
            })
            .await?;
        if discovered.schemas() != &schemas {
            return Err(Error::InvalidConfig {
                entry:   name,
                path:    "path".into(),
                message: "the plugin changed after its schemas were discovered".into(),
            });
        }
        if !discovered.verified() {
            tracing::warn!(provider_entry = %name, "launching an unverified development plugin");
        }
        environment.extend(secrets.values().clone());
        let runtime = PluginRuntime::start(Launch {
            plugin: discovered,
            entry: name,
            args: entry.args,
            environment,
            config: entry.config,
            secrets: entry.secrets,
            schemas,
            limits: self.limits.clone(),
        })
        .await?;
        Ok(runtime)
    }
}
