use std::collections::BTreeMap;
use std::io::{IsTerminal as _, stdin as blocking_stdin};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
#[cfg(unix)]
use nix::sys::termios::{SetArg, Termios, cfmakeraw, tcgetattr, tcsetattr};
use sandbox_driver::{
    Capability, Error, EventContext, ExecControls, ExecSpec, NetworkPolicy, OutputSink,
    OutputStream, PtyOptions, PtySession, Sandbox, SandboxFilter, SandboxId, SandboxKind,
    SandboxProvider, SandboxSource, SandboxSpec, SandboxState, Termination, WaitOptions,
    wait_for_stable_state, wait_for_state,
};
use tokio::fs::{read, read_to_string};
use tokio::io::{
    AsyncReadExt as _, AsyncWriteExt as _, stderr as async_stderr, stdin as async_stdin,
    stdout as async_stdout,
};
use tokio::process::Command as TokioCommand;
use tokio::signal::ctrl_c;
use tokio_util::sync::CancellationToken;

use crate::cli::{
    Command, CreateSpecArgs, EventFormat, ExecOptions, FsCommand, NetworkArg, OutputFormat,
    ProviderCommand, RunArgs, SandboxCommand, SandboxKindArg, StateChangeArgs,
};
use crate::config::Config;
use crate::output::{
    ProviderListing, event_context, health_exit_code, write_action, write_capabilities,
    write_health, write_provider_list, write_status, write_statuses, write_stderr,
};

const DRIVER_ERROR_EXIT: u8 = 125;
const TIMEOUT_EXIT: u8 = 124;
const CANCELLED_EXIT: u8 = 130;
const KILLED_EXIT: u8 = 137;

pub(crate) async fn list_providers(
    config: &Config,
    selected: &str,
    format: OutputFormat,
) -> Result<()> {
    let mut listings = Vec::new();
    for name in ["daytona", "docker", "host"] {
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

#[tracing::instrument(skip_all, fields(provider_kind = %provider.kind()), err)]
pub(crate) async fn execute(
    command: &Command,
    provider: &dyn SandboxProvider,
    output: OutputFormat,
    events: EventFormat,
) -> Result<u8> {
    match command {
        Command::Provider { command } => execute_provider(command, provider, output).await,
        Command::Sandbox { command } => execute_sandbox(command, provider, output, events).await,
    }
}

async fn execute_provider(
    command: &ProviderCommand,
    provider: &dyn SandboxProvider,
    output: OutputFormat,
) -> Result<u8> {
    match command {
        ProviderCommand::List => bail!("internal error: provider list was not handled"),
        ProviderCommand::Health => {
            let health = provider.health().await?;
            write_health(provider.kind().as_str(), &health, output).await?;
            Ok(health_exit_code(&health))
        }
        ProviderCommand::Capabilities => {
            write_capabilities(provider.kind().as_str(), provider.capabilities(), output).await?;
            Ok(0)
        }
    }
}

async fn execute_sandbox(
    command: &SandboxCommand,
    provider: &dyn SandboxProvider,
    output: OutputFormat,
    events: EventFormat,
) -> Result<u8> {
    if provider.kind().as_str() == "host" && !matches!(command, SandboxCommand::Run(_)) {
        bail!(
            "Host sandbox handles do not survive CLI process exit; use `lithos-sandbox --provider host sandbox run`"
        );
    }
    let event_context = event_context(events);
    match command {
        SandboxCommand::Create(args) => {
            let spec = build_spec(&args.spec, provider.kind().as_str(), false).await?;
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
            let sandbox = attach(provider, &args.id, event_context).await?;
            require_capability(
                provider,
                sandbox.as_ref(),
                Capability::LifecycleRefreshActivity,
            )?;
            sandbox.refresh_activity().await?;
            write_action(
                provider.kind().as_str(),
                sandbox.id().as_str(),
                "refreshed activity for",
                output,
            )
            .await?;
            Ok(0)
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

#[derive(Clone, Copy)]
enum LifecycleAction {
    Start,
    Stop,
    Pause,
    Resume,
    Archive,
    Recover,
}

impl LifecycleAction {
    fn name(self) -> &'static str {
        match self {
            Self::Start => "started",
            Self::Stop => "stopped",
            Self::Pause => "paused",
            Self::Resume => "resumed",
            Self::Archive => "archived",
            Self::Recover => "recovered",
        }
    }

    fn target(self) -> Option<SandboxState> {
        match self {
            Self::Start | Self::Resume => Some(SandboxState::Running),
            Self::Stop => Some(SandboxState::Stopped),
            Self::Pause => Some(SandboxState::Paused),
            Self::Archive => Some(SandboxState::Archived),
            Self::Recover => None,
        }
    }

    fn capability(self) -> Option<Capability> {
        match self {
            Self::Start | Self::Stop => None,
            Self::Pause | Self::Resume => Some(Capability::LifecyclePause),
            Self::Archive => Some(Capability::LifecycleArchive),
            Self::Recover => Some(Capability::LifecycleRecover),
        }
    }
}

async fn lifecycle_action(
    provider: &dyn SandboxProvider,
    args: &StateChangeArgs,
    events: Option<EventContext>,
    output: OutputFormat,
    action: LifecycleAction,
) -> Result<u8> {
    let sandbox = attach(provider, &args.id, events).await?;
    if let Some(capability) = action.capability() {
        require_capability(provider, sandbox.as_ref(), capability)?;
    }

    match action {
        LifecycleAction::Start => sandbox.start().await?,
        LifecycleAction::Stop => sandbox.stop().await?,
        LifecycleAction::Pause => sandbox.pause().await?,
        LifecycleAction::Resume => sandbox.resume().await?,
        LifecycleAction::Archive => sandbox.archive().await?,
        LifecycleAction::Recover => sandbox.recover().await?,
    }

    if args.wait {
        let status = match action.target() {
            Some(target) => {
                wait_for_state(sandbox.as_ref(), target, &WaitOptions::default()).await?
            }
            None => wait_for_stable_state(sandbox.as_ref(), &WaitOptions::default()).await?,
        };
        write_status(&status, output).await?;
    } else {
        write_action(
            provider.kind().as_str(),
            sandbox.id().as_str(),
            action.name(),
            output,
        )
        .await?;
    }
    Ok(0)
}

async fn execute_run(
    args: &RunArgs,
    provider: &dyn SandboxProvider,
    events: Option<EventContext>,
) -> Result<u8> {
    if args.spec.spec.as_deref() == Some(Path::new("-")) && args.exec.stdin {
        bail!("--spec - and --stdin cannot read from stdin in the same command");
    }
    if args.keep && provider.kind().as_str() == "host" {
        bail!(
            "Host sandboxes cannot be reattached after this command exits; remove --keep or use a persistent provider"
        );
    }

    let spec = build_spec(&args.spec, provider.kind().as_str(), true).await?;
    let sandbox = provider.create(&spec, events).await?;
    let operation = async {
        sandbox_driver::activate(sandbox.as_ref(), &WaitOptions::default()).await?;
        execute_command(sandbox.as_ref(), &args.exec, &args.command).await
    }
    .await;

    if args.keep {
        write_stderr(format!("sandbox {} preserved\n", sandbox.id()).as_bytes()).await?;
        return operation;
    }

    let cleanup = sandbox.delete().await.context("deleting run sandbox");
    match (operation, cleanup) {
        (Ok(exit_code), Ok(())) => Ok(exit_code),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(operation_error), Ok(())) => Err(operation_error),
        (Err(operation_error), Err(cleanup_error)) => Err(operation_error.context(format!(
            "the command also failed to clean up its sandbox: {cleanup_error:#}"
        ))),
    }
}

async fn build_spec(
    args: &CreateSpecArgs,
    provider_kind: &str,
    running_one_shot: bool,
) -> Result<SandboxSpec> {
    let explicit_source = source_from_args(args).await?;
    let mut spec = if let Some(path) = &args.spec {
        let contents = read_local_input(path).await?;
        serde_json::from_slice(&contents)
            .with_context(|| format!("parsing SandboxSpec from {}", display_input(path)))?
    } else {
        let source = explicit_source
            .clone()
            .or_else(|| (provider_kind == "host").then_some(SandboxSource::HostDirectory));
        SandboxSpec::new(source.context(
            "a creation source is required; use --image, --dockerfile, --snapshot, --host-directory, or --spec",
        )?)
    };

    if let Some(source) = explicit_source {
        spec.source = source;
    }
    if let Some(name) = &args.name {
        spec.name = Some(name.clone());
    }
    if let Some(kind) = args.kind {
        spec.sandbox_kind = Some(match kind {
            SandboxKindArg::Container => SandboxKind::Container,
            SandboxKindArg::VirtualMachine => SandboxKind::VirtualMachine,
        });
    }
    if args.cpu.is_some()
        || args.memory_mb.is_some()
        || args.disk_mb.is_some()
        || args.gpus.is_some()
    {
        let mut resources = spec.resources;
        resources.cpu_cores = args.cpu.or(resources.cpu_cores);
        resources.memory_mb = args.memory_mb.or(resources.memory_mb);
        resources.disk_mb = args.disk_mb.or(resources.disk_mb);
        resources.gpus = args.gpus.or(resources.gpus);
        spec.resources = resources;
    }
    spec.env.extend(parse_assignments(&args.env, "env")?);
    spec.labels
        .extend(parse_assignments(&args.labels, "label")?);
    if let Some(directory) = &args.working_directory {
        spec.working_directory = Some(directory.clone());
    }
    if let Some(network) = args.network {
        spec.network = match network {
            NetworkArg::ProviderDefault => NetworkPolicy::ProviderDefault,
            NetworkArg::AllowAll => NetworkPolicy::AllowAll,
            NetworkArg::Block => NetworkPolicy::Block,
        };
    }
    if let Some(region) = &args.region {
        spec.region = Some(region.clone());
    }
    if args.ephemeral {
        spec.ephemeral = true;
    }
    if let Some(provider_config) = &args.provider_config {
        spec.provider_config =
            serde_json::from_str(provider_config).context("parsing --provider-config as JSON")?;
    }

    if running_one_shot && provider_kind == "host" && spec.working_directory.is_none() {
        tracing::debug!("Host run will use a managed temporary workspace");
    }
    spec.validate()
        .context("validating sandbox specification")?;
    Ok(spec)
}

async fn source_from_args(args: &CreateSpecArgs) -> Result<Option<SandboxSource>> {
    if let Some(reference) = &args.image {
        return Ok(Some(SandboxSource::Image {
            reference: reference.clone(),
        }));
    }
    if let Some(path) = &args.dockerfile {
        let content = read_to_string(path)
            .await
            .with_context(|| format!("reading Dockerfile from {}", path.display()))?;
        return Ok(Some(SandboxSource::Dockerfile { content }));
    }
    if let Some(id) = &args.snapshot {
        return Ok(Some(SandboxSource::Snapshot {
            id: sandbox_driver::SnapshotId::try_new(id.clone())
                .context("validating snapshot ID")?,
        }));
    }
    Ok(args.host_directory.then_some(SandboxSource::HostDirectory))
}

async fn read_local_input(path: &Path) -> Result<Vec<u8>> {
    if path == Path::new("-") {
        let mut contents = Vec::new();
        async_stdin()
            .read_to_end(&mut contents)
            .await
            .context("reading stdin")?;
        return Ok(contents);
    }
    read(path)
        .await
        .with_context(|| format!("reading {}", path.display()))
}

fn display_input(path: &Path) -> String {
    if path == Path::new("-") {
        "stdin".to_owned()
    } else {
        path.display().to_string()
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

fn parse_assignments(values: &[String], option: &str) -> Result<BTreeMap<String, String>> {
    let mut assignments = BTreeMap::new();
    for value in values {
        let (key, value) = value
            .split_once('=')
            .with_context(|| format!("--{option} must use KEY=VALUE syntax"))?;
        if key.is_empty() {
            bail!("--{option} key must not be empty");
        }
        assignments.insert(key.to_owned(), value.to_owned());
    }
    Ok(assignments)
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

async fn execute_command(
    sandbox: &dyn Sandbox,
    options: &ExecOptions,
    command: &[String],
) -> Result<u8> {
    // clap guarantees at least one word; it is the program.
    let (program, args) = command
        .split_first()
        .context("a command to execute is required")?;
    let mut spec = ExecSpec::new(program).args(args);
    if let Some(working_dir) = &options.working_dir {
        spec.working_dir = Some(working_dir.clone());
    }
    spec.env = parse_assignments(&options.exec_env, "exec-env")?;
    if options.no_timeout {
        spec.timeout = None;
    } else if let Some(seconds) = options.timeout_seconds {
        spec.timeout = Some(Duration::from_secs(seconds));
    }
    if options.stdin {
        if !sandbox.capabilities().exec.stdin {
            bail!(
                "provider does not support exec.stdin for sandbox {}",
                sandbox.id()
            );
        }
        let mut bytes = Vec::new();
        async_stdin()
            .read_to_end(&mut bytes)
            .await
            .context("reading command stdin")?;
        spec.stdin = Some(bytes);
    }

    // Ctrl-C is the caller's own ladder: the first sends TERM, a second
    // sends KILL. There is no automatic escalation.
    let stops = sandbox
        .capabilities()
        .exec
        .stop
        .then(|| (CancellationToken::new(), CancellationToken::new()));
    let controls = ExecControls {
        term: stops.as_ref().map(|(term, _)| term.clone()),
        kill: stops.as_ref().map(|(_, kill)| kill.clone()),
        sink: Some(command_output_sink()),
        retained_output_limit: Some(0),
        ..ExecControls::default()
    };
    let execution = sandbox.exec().run_streaming(&spec, controls);
    tokio::pin!(execution);
    let streaming = if let Some((term, kill)) = stops {
        tokio::select! {
            result = &mut execution => result?,
            signal = ctrl_c() => {
                signal.context("listening for Ctrl-C")?;
                term.cancel();
                tokio::select! {
                    result = &mut execution => result?,
                    signal = ctrl_c() => {
                        signal.context("listening for Ctrl-C")?;
                        kill.cancel();
                        execution.await?
                    }
                }
            }
        }
    } else {
        execution.await?
    };

    termination_exit_code(streaming.result.termination, streaming.result.exit_code).await
}

fn command_output_sink() -> OutputSink {
    Arc::new(|stream, bytes| {
        Box::pin(async move {
            let result = match stream {
                OutputStream::Stdout => {
                    let mut output = async_stdout();
                    match output.write_all(&bytes).await {
                        Ok(()) => output.flush().await,
                        Err(error) => Err(error),
                    }
                }
                OutputStream::Stderr => {
                    let mut output = async_stderr();
                    match output.write_all(&bytes).await {
                        Ok(()) => output.flush().await,
                        Err(error) => Err(error),
                    }
                }
            };
            result.map_err(|error| Error::io("writing command output", error))
        })
    })
}

async fn termination_exit_code(termination: Termination, exit_code: Option<i32>) -> Result<u8> {
    match termination {
        Termination::Exited => Ok(exit_code
            .and_then(|code| u8::try_from(code).ok())
            .unwrap_or(DRIVER_ERROR_EXIT)),
        Termination::TimedOut => {
            write_stderr(b"sandbox command timed out\n").await?;
            Ok(TIMEOUT_EXIT)
        }
        Termination::Cancelled => Ok(CANCELLED_EXIT),
        Termination::Killed => Ok(KILLED_EXIT),
        _ => Ok(DRIVER_ERROR_EXIT),
    }
}

async fn execute_shell(sandbox: &dyn Sandbox) -> Result<u8> {
    if let Some(access) = sandbox.shell_command() {
        let command = access.shell_command().await?;
        let status = TokioCommand::new("bash")
            .args(["-c", &command])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .context("running provider shell command")?;
        return Ok(status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .unwrap_or(DRIVER_ERROR_EXIT));
    }

    let pty = sandbox
        .pty()
        .context("this sandbox provides neither a shell command nor a PTY")?;
    let session = pty.open(&PtyOptions::default()).await?;
    run_pty(session.as_ref()).await
}

async fn run_pty(session: &dyn PtySession) -> Result<u8> {
    let _terminal_mode = enter_raw_terminal_mode()?;
    let result = {
        let input = forward_terminal_input(session);
        let output = forward_terminal_output(session);
        tokio::pin!(input);
        tokio::pin!(output);
        tokio::select! {
            result = &mut output => result.map(|()| 0),
            result = &mut input => {
                result?;
                output.await.map(|()| 0)
            }
            signal = ctrl_c() => {
                signal.context("listening for Ctrl-C")?;
                Ok(CANCELLED_EXIT)
            }
        }
    };
    let close = session.close().await.context("closing PTY session");
    let exit_code = result?;
    close?;
    Ok(exit_code)
}

async fn forward_terminal_input(session: &dyn PtySession) -> Result<()> {
    let mut input = async_stdin();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = input
            .read(&mut buffer)
            .await
            .context("reading terminal input")?;
        if count == 0 {
            return Ok(());
        }
        session.write_input(&buffer[..count]).await?;
    }
}

async fn forward_terminal_output(session: &dyn PtySession) -> Result<()> {
    let mut output = async_stdout();
    while let Some(bytes) = session.read_output().await? {
        output
            .write_all(&bytes)
            .await
            .context("writing terminal output")?;
        output.flush().await.context("flushing terminal output")?;
    }
    Ok(())
}

#[cfg(unix)]
struct RawTerminal {
    original: Termios,
}

#[cfg(unix)]
impl Drop for RawTerminal {
    fn drop(&mut self) {
        let input = blocking_stdin();
        if let Err(error) = tcsetattr(&input, SetArg::TCSANOW, &self.original) {
            tracing::warn!(error = ?error, "terminal mode restore failed");
        }
    }
}

#[cfg(unix)]
fn enter_raw_terminal_mode() -> Result<Option<RawTerminal>> {
    let input = blocking_stdin();
    if !input.is_terminal() {
        return Ok(None);
    }
    let original = tcgetattr(&input).context("reading terminal mode")?;
    let mut raw = original.clone();
    cfmakeraw(&mut raw);
    tcsetattr(&input, SetArg::TCSANOW, &raw).context("enabling raw terminal mode")?;
    Ok(Some(RawTerminal { original }))
}

#[cfg(not(unix))]
struct RawTerminal;

#[cfg(not(unix))]
fn enter_raw_terminal_mode() -> Result<Option<RawTerminal>> {
    Ok(None)
}

async fn execute_fs(
    command: &FsCommand,
    provider: &dyn SandboxProvider,
    events: Option<EventContext>,
    output: OutputFormat,
) -> Result<u8> {
    match command {
        FsCommand::Upload { id, local, remote } => {
            let sandbox = attach(provider, id, events).await?;
            require_capability(provider, sandbox.as_ref(), Capability::FsUpload)?;
            sandbox.fs().upload(local, remote).await?;
            write_action(
                provider.kind().as_str(),
                sandbox.id().as_str(),
                "uploaded file to",
                output,
            )
            .await?;
        }
        FsCommand::Download { id, remote, local } => {
            let sandbox = attach(provider, id, events).await?;
            require_capability(provider, sandbox.as_ref(), Capability::FsDownload)?;
            sandbox.fs().download(remote, local).await?;
            write_action(
                provider.kind().as_str(),
                sandbox.id().as_str(),
                "downloaded file from",
                output,
            )
            .await?;
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignments_split_only_on_the_first_equals_sign() {
        let values = vec!["TOKEN=abc=123".to_owned()];
        let assignments = parse_assignments(&values, "env").expect("assignment parses");
        assert_eq!(assignments["TOKEN"], "abc=123");
    }

    #[test]
    fn assignments_require_a_nonempty_key() {
        let missing_equals =
            parse_assignments(&["TOKEN".to_owned()], "env").expect_err("missing equals fails");
        assert!(missing_equals.to_string().contains("KEY=VALUE"));

        let empty_key =
            parse_assignments(&["=value".to_owned()], "env").expect_err("empty key fails");
        assert!(empty_key.to_string().contains("key must not be empty"));
    }
}
