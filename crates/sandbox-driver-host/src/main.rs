//! The host provider served as a sandbox-driver plugin.
//!
//! A reference plugin binary and a working one: speaks the JSON-RPC
//! plugin protocol on stdin/stdout and drives directory-backed sandboxes
//! on the machine it runs on. The executable is `sandbox-driver-host`,
//! the name plugin discovery looks for under the `sandbox-driver` prefix.
//! Stdout belongs to the protocol; logs go to stderr.

use std::env;
use std::io::stderr;
use std::sync::Arc;

use anyhow::Context as _;
use sandbox_driver_host::HostProvider;
use sandbox_driver_protocol::serve_stdio;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(stderr))
        .try_init()
        .context("configuring host plugin diagnostics")?;

    tracing::info!(provider_kind = "host", "host plugin starting");
    let provider = match env::var_os("SANDBOX_DRIVER_HOST_REGISTRY") {
        Some(root) => HostProvider::with_registry(root)
            .await
            .context("opening the host registry")?,
        None => HostProvider::new(),
    };
    serve_stdio(Arc::new(provider))
        .await
        .context("serving the host provider plugin")
}
