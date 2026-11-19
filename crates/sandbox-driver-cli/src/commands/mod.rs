mod exec;
mod files;
mod spec;

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use sandbox_driver::{
    Durability, Expose, LabelFilter, ProviderEntry, ProviderName, Sandbox, SandboxId, SandboxRef,
    Sandboxes,
};
use tokio::signal::ctrl_c;

use crate::cli::{Command, CreateArgs, OutputFormat, ProviderCommand};
use crate::output::{
    display_ref, write_action, write_descriptor, write_environments, write_exposure, write_found,
    write_health, write_line, write_providers, write_status, write_stderr,
};

/// Runs one command against an open catalog. `providers` is the entry
/// configuration, which the catalog itself does not hand back.
pub(crate) async fn execute(
    command: &Command,
    catalog: &Sandboxes,
    providers: &BTreeMap<ProviderName, ProviderEntry>,
    output: OutputFormat,
) -> Result<u8> {
    match command {
        Command::Providers => {
            write_providers(providers, output).await?;
            Ok(0)
        }
        Command::Provider { command } => provider(catalog, command, output).await,
        Command::Environments => {
            let mut environments = Vec::new();
            for name in catalog.environments().await? {
                let environment = catalog.environment(name.as_str()).await?;
                environments.push((name, environment));
            }
            write_environments(&environments, output).await?;
            Ok(0)
        }
        Command::Create(args) => create(catalog, args, output).await,
        Command::Run(args) => {
            require_raw_output(output, "run")?;
            exec::run(catalog, args).await
        }
        Command::Find(args) => {
            let filter = LabelFilter(spec::parse_assignments(&args.labels, "label")?);
            write_found(&catalog.find(filter).await?, output).await?;
            Ok(0)
        }
        Command::Status(args) => {
            let (_, sandbox) = open(catalog, &args.sandbox).await?;
            write_status(&sandbox.status().await?, output).await?;
            Ok(0)
        }
        Command::Start(args) => {
            let (reference, sandbox) = open(catalog, &args.sandbox).await?;
            sandbox.start().await?;
            write_action(&reference, "started", output).await?;
            Ok(0)
        }
        Command::Stop(args) => {
            let (reference, sandbox) = open(catalog, &args.sandbox).await?;
            sandbox.stop().await?;
            write_action(&reference, "stopped", output).await?;
            Ok(0)
        }
        Command::Exec(args) => {
            require_raw_output(output, "exec")?;
            let spec = exec::exec_spec(&args.options, &args.command)?;
            let (_, sandbox) = open(catalog, &args.sandbox).await?;
            exec::execute(sandbox.as_ref(), spec, args.options.stdin).await
        }
        Command::Shell(args) => {
            require_raw_output(output, "shell")?;
            let (_, sandbox) = open(catalog, &args.sandbox).await?;
            exec::shell(sandbox.as_ref()).await
        }
        Command::Cp(args) => files::cp(catalog, args, output).await,
        Command::Ls(args) => files::ls(catalog, args, output).await,
        Command::Expose(args) => {
            // Checked before the provider is reached, like every option.
            let ttl_ms = args
                .ttl
                .as_deref()
                .map(|ttl| spec::duration("--ttl", ttl, "1h"))
                .transpose()?;
            let (_, sandbox) = open(catalog, &args.sandbox).await?;
            let exposure = sandbox
                .ports()
                .expose(args.port, Expose {
                    signed: args.signed,
                    ttl_ms,
                })
                .await?;
            write_exposure(&exposure, output).await?;
            // Some providers serve the exposure from this process, so it
            // lasts as long as the command does.
            write_stderr(b"exposed; press Ctrl-C to release\n").await?;
            ctrl_c().await.context("listening for Ctrl-C")?;
            sandbox.ports().release(args.port).await?;
            Ok(0)
        }
        Command::Destroy(args) => {
            let reference = resolve_ref(catalog, &args.sandbox).await?;
            catalog
                .destroy(&reference)
                .await
                .with_context(|| format!("destroying sandbox {}", display_ref(&reference)))?;
            write_action(&reference, "destroyed", output).await?;
            Ok(0)
        }
    }
}

async fn provider(
    catalog: &Sandboxes,
    command: &ProviderCommand,
    output: OutputFormat,
) -> Result<u8> {
    match command {
        ProviderCommand::Describe(args) => {
            let descriptor = catalog.provider(&args.name)?.describe().await?;
            write_descriptor(&args.name, &descriptor, output).await?;
            Ok(0)
        }
        ProviderCommand::Health(args) => {
            let health = catalog.provider(&args.name)?.health().await?;
            write_health(&args.name, &health, output).await?;
            Ok(u8::from(!health.healthy))
        }
    }
}

async fn create(catalog: &Sandboxes, args: &CreateArgs, output: OutputFormat) -> Result<u8> {
    let sandbox = create_sandbox(catalog, args, Some("create")).await?;
    let reference = sandbox.reference();
    match output {
        OutputFormat::Json => write_status(&sandbox.status().await?, output).await?,
        OutputFormat::Table | OutputFormat::Id => write_line(&display_ref(&reference)).await?,
    }
    Ok(0)
}

/// Creates a sandbox from the environment `args` names, with the
/// command-line changes applied. `must_outlive` names an operation that
/// needs the sandbox to survive this command.
async fn create_sandbox(
    catalog: &Sandboxes,
    args: &CreateArgs,
    must_outlive: Option<&str>,
) -> Result<Box<dyn Sandbox>> {
    let builder = catalog.builder(&args.environment).await?;
    let builder = spec::apply(builder, args).await?;
    if let Some(what) = must_outlive {
        require_outlives_command(catalog, &args.environment, what).await?;
    }
    builder
        .create()
        .await
        .with_context(|| format!("creating a sandbox from environment {}", args.environment))
}

/// Refuses an operation whose sandbox would be gone when this command
/// exits: a provider of `process` durability ends its sandboxes with the
/// process that made them.
async fn require_outlives_command(
    catalog: &Sandboxes,
    environment: &str,
    what: &str,
) -> Result<()> {
    let entry = catalog.environment(environment).await?.provider;
    let descriptor = catalog.provider(entry.as_str())?.describe().await?;
    if descriptor.durability == Durability::Process {
        bail!(
            "sandboxes of provider {entry} end when this command exits, so {what} would leave \
             nothing behind; use `lithos-sandbox run` without --keep"
        );
    }
    Ok(())
}

/// Folds a command's result with the result of the cleanup that followed
/// it. The command's own error wins; `also` introduces a cleanup failure
/// reported beside it.
pub(crate) fn after_cleanup(result: Result<u8>, cleanup: Result<()>, also: &str) -> Result<u8> {
    match (result, cleanup) {
        (Ok(code), Ok(())) => Ok(code),
        (Ok(_), Err(error)) | (Err(error), Ok(())) => Err(error),
        (Err(error), Err(cleanup)) => Err(error.context(format!("{also}: {cleanup:#}"))),
    }
}

/// Reads a sandbox ref: `<entry>/<id>` as `create` prints it, or the JSON
/// reference from `--output json`. The short form takes its namespace from
/// the entry's provider now; the JSON form is checked against it.
async fn resolve_ref(catalog: &Sandboxes, text: &str) -> Result<SandboxRef> {
    if text.trim_start().starts_with('{') {
        return serde_json::from_str(text).context("parsing the sandbox reference as JSON");
    }
    let (entry, id) = text
        .split_once('/')
        .filter(|(entry, id)| !entry.is_empty() && !id.is_empty())
        .with_context(|| {
            format!("{text:?} is not a sandbox ref; expected <provider>/<id>, as `create` prints")
        })?;
    let provider = ProviderName::try_new(entry).context("reading the sandbox ref")?;
    let id = SandboxId::try_new(id).context("reading the sandbox ref")?;
    let namespace = catalog.provider(entry)?.describe().await?.namespace.id;
    Ok(SandboxRef {
        provider,
        namespace,
        id,
    })
}

/// Resolves a sandbox ref and attaches to the sandbox it names.
pub(super) async fn open(
    catalog: &Sandboxes,
    text: &str,
) -> Result<(SandboxRef, Box<dyn Sandbox>)> {
    let reference = resolve_ref(catalog, text).await?;
    let sandbox = catalog
        .attach(&reference)
        .await
        .with_context(|| format!("attaching sandbox {}", display_ref(&reference)))?;
    Ok((reference, sandbox))
}

fn require_raw_output(output: OutputFormat, command: &str) -> Result<()> {
    if output != OutputFormat::Table {
        bail!("{command} streams the command's own output and requires --output table");
    }
    Ok(())
}
