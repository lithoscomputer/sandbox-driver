//! The Daytona provider served as a sandbox-driver plugin.
//!
//! Speaks the JSON-RPC plugin protocol on stdin/stdout and drives cloud
//! sandboxes through the Daytona API. Credentials come from the
//! environment the host forwards (`DAYTONA_API_KEY`, or
//! `DAYTONA_JWT_TOKEN` with `DAYTONA_ORGANIZATION_ID`, plus the optional
//! `DAYTONA_API_URL` and `DAYTONA_TARGET`). Stdout belongs to the
//! protocol; logs go to stderr.

use std::io::stderr;
use std::sync::Arc;

use anyhow::Context as _;
use sandbox_driver_daytona::DaytonaProvider;
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
        .context("configuring daytona plugin diagnostics")?;

    tracing::info!(provider_kind = "daytona", "daytona plugin starting");
    let provider = DaytonaProvider::connect()
        .await
        .context("connecting to daytona")?;
    serve_stdio(Arc::new(provider))
        .await
        .context("serving the daytona provider plugin")
}
