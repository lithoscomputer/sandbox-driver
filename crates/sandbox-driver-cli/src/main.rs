mod cli;
mod commands;
mod config;
mod output;
mod provider;

use std::fmt::Write as _;
use std::io::stderr;
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::Parser as _;
use cli::Cli;
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

async fn run(cli: &Cli) -> Result<u8> {
    let config = config::Config::load(cli.config.as_deref()).await?;
    commands::execute(cli, &config).await
}

fn configure_diagnostics(verbosity: u8) -> Result<()> {
    let default_level = match verbosity {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
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
    if let Err(write_error) = output::write_stderr(rendered.as_bytes()).await {
        tracing::error!(error = ?write_error, "error report output failed");
    }
}
