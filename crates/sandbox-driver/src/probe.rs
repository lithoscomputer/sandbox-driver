use std::sync::Arc;
use std::time::Duration;

use crate::error::{Error, ExecFailure, Result};
use crate::exec::{Exec, ExecControls, ExecResult, ExecSpec, OutputSink};
use crate::sandbox::Sandbox;
use crate::state::SandboxState;
use crate::wait::{WaitOptions, wait_for_stable_state, wait_for_state};

/// Bash contract probe, carried over from fabro. Run through
/// [`ExecSpec::bash`] on a fresh sandbox and after every resume, before
/// reporting the sandbox usable: the exec-derived facets are Bash scripts,
/// so a sandbox that cannot serve the helper cannot serve them. Fails when
/// `BASH_ENV` is set, Bash is missing, the shell is a login shell, or
/// POSIX mode is active. Success requires exit 0 and stdout
/// `fabro-bash-ready` — surrounding whitespace tolerated, because exec
/// transports pad or normalize output.
pub const BASH_PROBE_SCRIPT: &str = r#"
if [ -n "${BASH_ENV:-}" ]; then echo "probe: BASH_ENV is set" >&2; exit 1; fi
if [ -z "${BASH_VERSION:-}" ]; then echo "probe: not running under bash" >&2; exit 1; fi
if shopt -q login_shell; then echo "probe: login shell" >&2; exit 1; fi
if shopt -qo posix; then echo "probe: posix mode" >&2; exit 1; fi
printf 'fabro-bash-ready'
"#;

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_OK_MARKER: &str = "fabro-bash-ready";

/// Runs the bash contract probe through `exec`, over both transports.
///
/// Buffered and streaming execution can ride different provider
/// transports (Daytona: a one-shot endpoint vs. sessions; plugins:
/// separate wire methods). A streaming transport that never yields an
/// exit code otherwise surfaces as every streaming command timing out
/// rather than as an activation failure, so both are verified — the
/// buffered transport first, because it isolates "no usable Bash" from
/// "Bash runs but the streaming contract is broken".
#[tracing::instrument(skip_all, err)]
pub async fn run_bash_probe(exec: &dyn Exec) -> Result<()> {
    let spec = ExecSpec::bash(BASH_PROBE_SCRIPT).timeout(PROBE_TIMEOUT);
    let result = exec.run(&spec).await?;
    check_probe_result("bash probe", result)?;

    let sink: OutputSink = Arc::new(|_stream, _chunk| Box::pin(async { Ok(()) }));
    let controls = ExecControls {
        sink: Some(sink),
        ..ExecControls::default()
    };
    let streaming = exec.run_streaming(&spec, controls).await?;
    check_probe_result("bash probe (streaming transport)", streaming.result)
}

fn check_probe_result(label: &str, result: ExecResult) -> Result<()> {
    if result.success() && result.stdout_lossy().trim() == PROBE_OK_MARKER {
        return Ok(());
    }
    Err(Error::Exec(
        ExecFailure::new(
            label,
            result.termination,
            result.exit_code,
            result.stdout,
            result.stderr,
        )
        .with_duration(result.duration),
    ))
}

/// Ensures a sandbox is running and healthy: describe, then start (or
/// resume when paused), wait for `Running`, and run the bash probe.
///
/// This is fabro's `activate`, implemented once over the core instead of
/// per provider. Idempotent: a running sandbox only gets the probe.
#[tracing::instrument(skip_all, fields(sandbox_id = %sandbox.id()), err)]
pub async fn activate(sandbox: &dyn Sandbox, wait: &WaitOptions) -> Result<()> {
    let status = sandbox.describe().await?;
    // Wait out an in-flight transition (an auto-stop racing this
    // activation, say) instead of acting on a moving state: `Stopping`
    // settles into `Stopped` and gets a start, `Starting` into
    // `Running` and only the probe.
    let state = if status.state.is_stable() {
        status.state
    } else {
        wait_for_stable_state(sandbox, wait).await?.state
    };
    match state {
        SandboxState::Running => {}
        SandboxState::Paused => {
            sandbox.resume().await?;
            wait_for_state(sandbox, SandboxState::Running, wait).await?;
        }
        _ => {
            sandbox.start().await?;
            wait_for_state(sandbox, SandboxState::Running, wait).await?;
        }
    }
    run_bash_probe(sandbox.exec()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_exec::ScriptedExec;

    #[tokio::test]
    async fn probe_exercises_both_transports() {
        let exec = ScriptedExec::new(vec![
            ScriptedExec::ok("fabro-bash-ready"),
            ScriptedExec::ok("fabro-bash-ready\n"),
        ]);
        run_bash_probe(&exec).await.expect("probe passes");
        // One buffered run and one streaming run, same script.
        assert_eq!(exec.commands().len(), 2);
    }

    #[tokio::test]
    async fn probe_names_a_broken_streaming_transport() {
        let exec = ScriptedExec::new(vec![
            ScriptedExec::ok("fabro-bash-ready"),
            ScriptedExec::failed(1),
        ]);
        let error = run_bash_probe(&exec)
            .await
            .expect_err("streaming probe fails");
        assert!(
            format!("{error}").contains("streaming transport"),
            "error: {error}"
        );
    }
}
