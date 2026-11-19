use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use sandbox_driver::{
    Error, ExecControls, ExecSpec, MutationOutcome, OutputSink, OutputStream, Sandbox, Sandboxes,
    Termination,
};
use tokio::process::Command as TokioCommand;
use tokio::signal::ctrl_c;
use tokio_util::sync::CancellationToken;

use super::spec::{duration, parse_assignments};
use super::{after_cleanup, create_sandbox};
use crate::cli::{ExecOptions, RunArgs};
use crate::output::{display_ref, write_stderr, write_stdout};
use crate::stdin::local_stdin;

pub(super) const DRIVER_ERROR_EXIT: u8 = 125;
const TIMEOUT_EXIT: u8 = 124;
const TERMINATED_EXIT: u8 = 130;
const KILLED_EXIT: u8 = 137;

/// Creates a sandbox, runs one command, and destroys the sandbox, also
/// when the command fails.
pub(super) async fn run(catalog: &Sandboxes, args: &RunArgs) -> Result<u8> {
    if args.create.spec.as_deref() == Some("-".as_ref()) && args.exec.stdin {
        bail!("--spec - and --stdin cannot both read stdin");
    }
    // Every option is checked before anything is created: a typo must not
    // cost a sandbox.
    let spec = exec_spec(&args.exec, &args.command)?;
    let sandbox = create_sandbox(catalog, &args.create, args.keep.then_some("--keep")).await?;
    let reference = sandbox.reference();
    let outcome = execute(sandbox.as_ref(), spec, args.exec.stdin).await;

    if args.keep {
        write_stderr(format!("kept sandbox {}\n", display_ref(&reference)).as_bytes()).await?;
        return outcome;
    }
    drop(sandbox);
    let cleanup = catalog
        .destroy(&reference)
        .await
        .with_context(|| format!("destroying sandbox {}", display_ref(&reference)));
    after_cleanup(outcome, cleanup, "the sandbox also could not be destroyed")
}

/// The command and its exec options as an `ExecSpec`.
pub(super) fn exec_spec(options: &ExecOptions, command: &[String]) -> Result<ExecSpec> {
    let mut spec = ExecSpec::argv(command);
    spec.env = parse_assignments(&options.exec_env, "exec-env")?;
    spec.working_directory.clone_from(&options.workdir);
    if let Some(timeout) = &options.timeout {
        spec.timeout_ms = Some(duration("--timeout", timeout, "30s or 5m")?);
    }
    Ok(spec)
}

/// Runs `spec`, streaming its output to this process's stdout and stderr,
/// and local stdin to it when `stdin` is set. Returns the exit code the CLI
/// should exit with.
pub(super) async fn execute(sandbox: &dyn Sandbox, spec: ExecSpec, stdin: bool) -> Result<u8> {
    // Ctrl-C is the caller's own ladder: the first requests TERM, a second
    // KILL. There is no automatic escalation.
    let (term, kill) = (CancellationToken::new(), CancellationToken::new());
    let controls = ExecControls {
        stdin:  stdin.then(|| Box::pin(local_stdin()) as _),
        sink:   Some(output_sink()),
        term:   Some(term.clone()),
        kill:   Some(kill.clone()),
        resize: None,
    };
    let execution = sandbox.exec(spec, controls);
    tokio::pin!(execution);
    let outcome = tokio::select! {
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
    };

    Ok(match outcome.termination {
        Termination::Exited => exit_byte(outcome.exit_code),
        Termination::TimedOut => {
            write_stderr(b"command timed out\n").await?;
            TIMEOUT_EXIT
        }
        Termination::Terminated => TERMINATED_EXIT,
        Termination::Killed => KILLED_EXIT,
        Termination::Lost => {
            write_stderr(b"the command's outcome is unknown; it may still be running\n").await?;
            DRIVER_ERROR_EXIT
        }
    })
}

/// Opens the provider's interactive shell. Providers that offer one report
/// a local command, such as `docker exec -it`, that this process runs.
pub(super) async fn shell(sandbox: &dyn Sandbox) -> Result<u8> {
    let unsupported = || {
        anyhow::anyhow!(
            "this sandbox's provider offers no shell command; use `lithos-sandbox exec {} -- sh -c ...`",
            display_ref(&sandbox.reference())
        )
    };
    let endpoints = sandbox.endpoints().ok_or_else(unsupported)?;
    let command = match endpoints.shell_command().await {
        Ok(command) => command,
        Err(Error::Unsupported { .. }) => return Err(unsupported()),
        Err(error) => return Err(error.into()),
    };
    let status = TokioCommand::new("sh")
        .args(["-c", &command])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("running the provider's shell command")?;
    Ok(exit_byte(status.code()))
}

/// A command's exit code as this process can report it.
fn exit_byte(code: Option<i32>) -> u8 {
    code.and_then(|code| u8::try_from(code).ok())
        .unwrap_or(DRIVER_ERROR_EXIT)
}

fn output_sink() -> OutputSink {
    Arc::new(|stream, bytes| {
        Box::pin(async move {
            let result = match stream {
                OutputStream::Stderr => write_stderr(&bytes).await,
                OutputStream::Stdout | OutputStream::Terminal => write_stdout(&bytes).await,
            };
            result.map_err(|error| Error::Transport {
                message: format!("writing command output: {error:#}"),
                outcome: MutationOutcome::Unknown,
            })
        })
    })
}
