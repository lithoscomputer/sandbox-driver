use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use sandbox_driver::{
    Error, EventContext, ExecControls, ExecSpec, OutputSink, OutputStream, Sandbox,
    SandboxProvider, Termination, WaitOptions,
};
use tokio::io::{
    AsyncReadExt as _, AsyncWriteExt as _, stderr as async_stderr, stdin as async_stdin,
    stdout as async_stdout,
};
use tokio::signal::ctrl_c;
use tokio_util::sync::CancellationToken;

use super::spec::{build_spec, parse_assignments};
use super::{CANCELLED_EXIT, DRIVER_ERROR_EXIT, KILLED_EXIT, TIMEOUT_EXIT};
use crate::cli::{ExecOptions, RunArgs};
use crate::output::write_stderr;

pub(super) async fn execute_run(
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

pub(super) async fn execute_command(
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
