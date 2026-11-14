//! The shared contract across a process boundary.
//!
//! [`PluginLoader`] is the `ProviderFactory` an application registers with
//! `Registry::plugins`: it discovers a configured executable's schemas
//! without credentials, then starts one supervised child per activated entry
//! and speaks protocol version 3 to it. [`Plugin`] and [`run_plugin`] are the
//! other side, for plugin executables. Version 2 stays available on both
//! sides; a version 3 host never falls back to it.

mod loader;
pub(crate) mod stream;
pub mod wire;

use std::env;
use std::io::{self, Write as _};
use std::sync::Arc;

use sandbox_driver::SandboxProvider;
use sandbox_driver::contract::{ProviderFactory, ProviderSchemas};
use tokio::io::{stdin, stdout};

pub use self::loader::PluginLoader;
use crate::{TransportLimits, metadata, serve_plugin_with_limits};

/// What a plugin executable serves: the shared contract through its own
/// factory, the version 2 provider, or both while callers migrate.
pub struct Plugin {
    pub(crate) legacy: Option<Arc<dyn SandboxProvider>>,
    pub(crate) v3:     Option<(ProviderSchemas, Arc<dyn ProviderFactory>)>,
}

impl Plugin {
    /// A plugin serving protocol version 3. `schemas` is the credential-free
    /// metadata `--describe-schema` prints; the factory is activated with the
    /// entry's config when the host initializes.
    pub fn new(schemas: ProviderSchemas, factory: Arc<dyn ProviderFactory>) -> Self {
        Self {
            legacy: None,
            v3:     Some((schemas, factory)),
        }
    }

    /// A plugin serving only protocol version 2.
    pub fn legacy(provider: Arc<dyn SandboxProvider>) -> Self {
        Self {
            legacy: Some(provider),
            v3:     None,
        }
    }

    /// Also serves protocol version 2 to hosts that ask for it.
    #[must_use]
    pub fn with_legacy(mut self, provider: Arc<dyn SandboxProvider>) -> Self {
        self.legacy = Some(provider);
        self
    }
}

/// The main loop of a plugin executable. `--describe-schema` prints the
/// schemas and returns before anything else is constructed; otherwise the
/// plugin serves stdin/stdout until EOF or `shutdown`, and on the way out its
/// runtime gets a bounded cleanup.
pub async fn run_plugin(plugin: Plugin) -> sandbox_driver::Result<()> {
    let mut args = env::args_os().skip(1);
    if let (Some(flag), None) = (args.next(), args.next()) {
        if flag == "--describe-schema" {
            let Some((schemas, _)) = &plugin.v3 else {
                return Err(sandbox_driver::Error::invalid_spec(
                    "--describe-schema",
                    "this plugin does not serve the shared contract",
                ));
            };
            let mut out = io::stdout().lock();
            return metadata::write_schema(&mut out, schemas)
                .and_then(|()| out.flush())
                .map_err(|error| sandbox_driver::Error::io("writing plugin schemas", error));
        }
    }
    serve_plugin_with_limits(plugin, stdin(), stdout(), TransportLimits::default()).await
}
