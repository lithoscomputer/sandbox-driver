mod exec;
mod fs;
mod lifecycle;
mod shell;
mod spec;

use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use sandbox_driver::{
    Capability, EventContext, ProviderKind, Sandbox, SandboxFilter, SandboxId, SandboxProvider,
    WaitOptions, wait_for_stable_state,
};

use self::exec::{execute_command, execute_run};
use self::fs::execute_fs;
use self::lifecycle::{LifecycleAction, lifecycle_action};
use self::shell::execute_shell;
use self::spec::{build_spec, parse_assignments};
use crate::cli::{Cli, Command, EventFormat, OutputFormat, ProviderCommand, SandboxCommand};
use crate::config::Config;
use crate::output::{
    ProviderListing, event_context, health_exit_code, write_action, write_capabilities,
    write_health, write_provider_list, write_status, write_statuses,
};
use crate::provider::{BUILTIN_PROVIDERS, ProviderSession};

const DRIVER_ERROR_EXIT: u8 = 125;
const TIMEOUT_EXIT: u8 = 124;
const CANCELLED_EXIT: u8 = 130;
const KILLED_EXIT: u8 = 137;

pub(crate) async fn execute(cli: &Cli, config: &Config) -> Result<u8> {
    let selected = config.selected_provider(cli.provider.as_deref());
    match &cli.command {
        Command::Provider { command } => {
            execute_provider(command, config, selected, cli.output).await
        }
        Command::Sandbox { command } => {
            with_provider(selected, config, async |provider| {
                execute_sandbox(command, provider, cli.output, cli.events).await
            })
            .await
        }
    }
}

/// Connects the selected provider for the duration of `body`, then shuts it
/// down. `provider list` never reaches this: it reads configuration only.
async fn with_provider(
    selected: &str,
    config: &Config,
    body: impl AsyncFnOnce(&dyn SandboxProvider) -> Result<u8>,
) -> Result<u8> {
    let session = ProviderSession::connect(selected, config).await?;
    let command_result = execute_connected(&session.provider, body).await;
    let shutdown_result = session.shutdown().await;
    match (command_result, shutdown_result) {
        (Ok(code), Ok(())) => Ok(code),
        (Ok(_), Err(error)) | (Err(error), Ok(())) => Err(error),
        (Err(error), Err(shutdown_error)) => Err(error.context(format!(
            "the command also failed to shut down its plugin: {shutdown_error:#}"
        ))),
    }
}

#[tracing::instrument(
    name = "execute",
    skip_all,
    fields(provider_kind = %provider.kind()),
    err
)]
async fn execute_connected(
    provider: &dyn SandboxProvider,
    body: impl AsyncFnOnce(&dyn SandboxProvider) -> Result<u8>,
) -> Result<u8> {
    body(provider).await
}

async fn execute_provider(
    command: &ProviderCommand,
    config: &Config,
    selected: &str,
    output: OutputFormat,
) -> Result<u8> {
    match command {
        ProviderCommand::List => {
            list_providers(config, selected, output).await?;
            Ok(0)
        }
        ProviderCommand::Health => {
            with_provider(selected, config, async |provider| {
                let health = provider.health().await?;
                write_health(provider.kind().as_str(), &health, output).await?;
                Ok(health_exit_code(&health))
            })
            .await
        }
        ProviderCommand::Capabilities => {
            with_provider(selected, config, async |provider| {
                write_capabilities(provider.kind().as_str(), provider.capabilities(), output)
                    .await?;
                Ok(0)
            })
            .await
        }
    }
}

async fn list_providers(config: &Config, selected: &str, format: OutputFormat) -> Result<()> {
    let mut listings = Vec::new();
    for name in BUILTIN_PROVIDERS.iter().copied() {
        if !config.providers.contains_key(name) {
            listings.push(ProviderListing {
                name,
                provider_type: name,
                kind: name,
                selected: name == selected,
            });
        }
    }
    for (name, profile) in &config.providers {
        listings.push(ProviderListing {
            name,
            provider_type: profile.provider_type(),
            kind: profile.provider_kind(),
            selected: name == selected,
        });
    }
    listings.sort_by(|left, right| left.name.cmp(right.name));
    write_provider_list(&listings, format).await
}

async fn execute_sandbox(
    command: &SandboxCommand,
    provider: &dyn SandboxProvider,
    output: OutputFormat,
    events: EventFormat,
) -> Result<u8> {
    if is_host(provider.kind()) && !matches!(command, SandboxCommand::Run(_)) {
        bail!(
            "Host sandbox handles do not survive CLI process exit; use `lithos-sandbox --provider host sandbox run`"
        );
    }
    let event_context = event_context(events);
    match command {
        SandboxCommand::Create(args) => {
            let spec = build_spec(&args.spec, provider.kind()).await?;
            let sandbox = provider.create(&spec, event_context).await?;
            let status = if args.wait {
                wait_for_stable_state(sandbox.as_ref(), &WaitOptions::default()).await?
            } else {
                sandbox.describe().await?
            };
            write_status(&status, output).await?;
            Ok(0)
        }
        SandboxCommand::Run(args) => {
            require_raw_output(output, "sandbox run")?;
            execute_run(args, provider, event_context).await
        }
        SandboxCommand::List(args) => {
            let mut filter = SandboxFilter::default();
            filter.labels = parse_assignments(&args.labels, "label")?;
            let statuses = provider.list(&filter).await?;
            write_statuses(&statuses, output).await?;
            Ok(0)
        }
        SandboxCommand::Inspect(args) => {
            let sandbox = attach(provider, &args.id, event_context).await?;
            write_status(&sandbox.describe().await?, output).await?;
            Ok(0)
        }
        SandboxCommand::Start(args) => {
            lifecycle_action(
                provider,
                args,
                event_context,
                output,
                LifecycleAction::Start,
            )
            .await
        }
        SandboxCommand::Stop(args) => {
            lifecycle_action(provider, args, event_context, output, LifecycleAction::Stop).await
        }
        SandboxCommand::Pause(args) => {
            lifecycle_action(
                provider,
                args,
                event_context,
                output,
                LifecycleAction::Pause,
            )
            .await
        }
        SandboxCommand::Resume(args) => {
            lifecycle_action(
                provider,
                args,
                event_context,
                output,
                LifecycleAction::Resume,
            )
            .await
        }
        SandboxCommand::Archive(args) => {
            lifecycle_action(
                provider,
                args,
                event_context,
                output,
                LifecycleAction::Archive,
            )
            .await
        }
        SandboxCommand::Recover(args) => {
            lifecycle_action(
                provider,
                args,
                event_context,
                output,
                LifecycleAction::Recover,
            )
            .await
        }
        SandboxCommand::RefreshActivity(args) => {
            act_on_sandbox(
                provider,
                &args.id,
                event_context,
                output,
                Capability::LifecycleRefreshActivity,
                "refreshed activity for",
                async |sandbox| sandbox.refresh_activity().await,
            )
            .await
        }
        SandboxCommand::Undelete(args) => {
            require_provider_capability(provider, Capability::LifecycleUndelete)?;
            let id = parse_sandbox_id(&args.id)?;
            let sandbox = provider.undelete(&id, event_context).await?;
            write_status(&sandbox.describe().await?, output).await?;
            Ok(0)
        }
        SandboxCommand::Delete(args) => {
            // By id, with no attach: a sandbox no handle can be built for is
            // still removed, and an unknown id is already gone.
            let id = parse_sandbox_id(&args.id)?;
            provider
                .delete(&id, event_context)
                .await
                .with_context(|| format!("deleting sandbox {:?}", args.id))?;
            write_action(provider.kind().as_str(), id.as_str(), "deleted", output).await?;
            Ok(0)
        }
        SandboxCommand::Exec(args) => {
            require_raw_output(output, "sandbox exec")?;
            let sandbox = attach(provider, &args.id, event_context).await?;
            execute_command(sandbox.as_ref(), &args.options, &args.command).await
        }
        SandboxCommand::Shell(args) => {
            require_raw_output(output, "sandbox shell")?;
            let sandbox = attach(provider, &args.id, event_context).await?;
            sandbox_driver::activate(sandbox.as_ref(), &WaitOptions::default()).await?;
            execute_shell(sandbox.as_ref()).await
        }
        SandboxCommand::Fs { command } => {
            execute_fs(command, provider, event_context, output).await
        }
    }
}

async fn attach(
    provider: &dyn SandboxProvider,
    id: &str,
    events: Option<EventContext>,
) -> Result<Arc<dyn Sandbox>> {
    provider
        .attach(&parse_sandbox_id(id)?, events)
        .await
        .with_context(|| format!("attaching sandbox {id:?}"))
}

fn parse_sandbox_id(id: &str) -> Result<SandboxId> {
    SandboxId::try_new(id.to_owned()).context("validating sandbox ID")
}

/// Host handles live only as long as the CLI process, so most sandbox
/// commands are refused for it.
fn is_host(kind: &ProviderKind) -> bool {
    kind.as_str() == "host"
}

/// Attaches `id`, requires `capability`, runs `act`, and reports `verb`.
async fn act_on_sandbox(
    provider: &dyn SandboxProvider,
    id: &str,
    events: Option<EventContext>,
    output: OutputFormat,
    capability: Capability,
    verb: &str,
    act: impl AsyncFnOnce(&dyn Sandbox) -> sandbox_driver::Result<()>,
) -> Result<u8> {
    let sandbox = attach(provider, id, events).await?;
    require_capability(provider, sandbox.as_ref(), capability)?;
    act(sandbox.as_ref()).await?;
    write_action(
        provider.kind().as_str(),
        sandbox.id().as_str(),
        verb,
        output,
    )
    .await?;
    Ok(0)
}

fn require_provider_capability(
    provider: &dyn SandboxProvider,
    capability: Capability,
) -> Result<()> {
    if !provider.capabilities().supports(capability) {
        bail!("provider {} does not support {capability}", provider.kind());
    }
    Ok(())
}

fn require_capability(
    provider: &dyn SandboxProvider,
    sandbox: &dyn Sandbox,
    capability: Capability,
) -> Result<()> {
    if !sandbox.capabilities().supports(capability) {
        bail!(
            "provider {} does not support {capability} for sandbox {}",
            provider.kind(),
            sandbox.id()
        );
    }
    Ok(())
}

fn require_raw_output(output: OutputFormat, command: &str) -> Result<()> {
    if output != OutputFormat::Table {
        bail!("{command} streams raw output and requires --output table");
    }
    Ok(())
}
