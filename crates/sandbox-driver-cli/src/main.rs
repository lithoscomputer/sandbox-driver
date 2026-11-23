mod cli;
mod commands;
mod config;
mod output;
mod stdin;

use std::fmt::Write as _;
use std::io::stderr;
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::Parser as _;
use cli::Cli;
use sandbox_driver::Error;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Err(error) = configure_diagnostics(cli.verbose) {
        report_error(&error).await;
        return ExitCode::FAILURE;
    }

    match run(&cli).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            report_error(&error).await;
            ExitCode::FAILURE
        }
    }
}

/// Opens the catalog, runs the command, and always shuts the catalog down:
/// that ends plugin children and the sandboxes of `process`-durable
/// providers, such as Host.
async fn run(cli: &Cli) -> Result<u8> {
    let catalog = config::Catalog::load(cli.config.as_deref()).await?;
    let providers = catalog.providers.clone();
    let sandboxes = catalog.open()?;
    let result = commands::execute(&cli.command, &sandboxes, &providers, cli.output).await;
    let shutdown = sandboxes
        .shutdown()
        .await
        .context("shutting down providers");
    commands::after_cleanup(result, shutdown, "providers also failed to shut down")
}

fn configure_diagnostics(verbosity: u8) -> Result<()> {
    let default_level = match verbosity {
        // Errors reach the user through the command's own report; provider
        // logs would repeat them.
        0 => LevelFilter::OFF,
        1 => LevelFilter::WARN,
        2 => LevelFilter::INFO,
        3 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(default_level.into())
        .from_env_lossy();
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(stderr))
        .try_init()
        .context("configuring diagnostics")
}

async fn report_error(error: &anyhow::Error) {
    let mut rendered = format!("error: {error}\n");
    for cause in error.chain().skip(1) {
        let _ = writeln!(rendered, "  caused by: {cause}");
    }
    match error.root_cause().downcast_ref::<Error>() {
        Some(Error::NoEnvironment { .. }) => {
            rendered.push_str("hint: `lithos-sandbox environments` lists them\n");
        }
        Some(Error::NoProvider { .. }) => {
            rendered.push_str("hint: `lithos-sandbox providers` lists them\n");
        }
        _ => {}
    }
    if let Err(write_error) = output::write_stderr(rendered.as_bytes()).await {
        tracing::error!(error = ?write_error, "error report output failed");
    }
}
