//! The Docker provider served as a sandbox-driver plugin.
//!
//! Speaks the JSON-RPC plugin protocol on stdin/stdout and drives
//! containers on the daemon `DOCKER_HOST` names, or the local one. The
//! daemon is not required to answer at launch: an unreachable one is
//! reported through `provider/health`, so a host's preflight sees the
//! cause instead of a plugin that failed to start. Stdout belongs to the
//! protocol; logs go to stderr.

use std::io::stderr;
use std::sync::Arc;

use anyhow::Context as _;
use sandbox_driver_docker::DockerProvider;
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
        .context("configuring docker plugin diagnostics")?;

    tracing::info!(provider_kind = "docker", "docker plugin starting");
    let provider = DockerProvider::connect_unverified().context("configuring the docker client")?;
    serve_stdio(Arc::new(provider))
        .await
        .context("serving the docker provider plugin")
}
