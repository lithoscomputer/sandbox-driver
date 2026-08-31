use std::time::Duration;

use crate::error::{Error, ExecFailure, Result};
use crate::exec::{Exec, ExecSpec};
use crate::sandbox::Sandbox;
use crate::state::SandboxState;
use crate::wait::{WaitOptions, wait_for_stable_state, wait_for_state};

/// Bash contract probe, carried over from fabro. Run through the exec
/// facet on a fresh sandbox and after every resume, before reporting the
/// sandbox usable. Fails when `BASH_ENV` is set, Bash is missing, the
/// shell is a login shell, or POSIX mode is active. Success requires exit
/// 0 and stdout `fabro-bash-ready` — surrounding whitespace tolerated,
/// because exec transports pad or normalize output.
pub const BASH_PROBE_SCRIPT: &str = r#"
if [ -n "${BASH_ENV:-}" ]; then echo "probe: BASH_ENV is set" >&2; exit 1; fi
if [ -z "${BASH_VERSION:-}" ]; then echo "probe: not running under bash" >&2; exit 1; fi
if shopt -q login_shell; then echo "probe: login shell" >&2; exit 1; fi
if shopt -qo posix; then echo "probe: posix mode" >&2; exit 1; fi
printf 'fabro-bash-ready'
"#;

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_OK_MARKER: &str = "fabro-bash-ready";

/// A failed bash probe. The raw output stays behind [`ExecFailure`]'s
/// accessors.
#[derive(Debug, thiserror::Error)]
#[error("bash probe failed: {reason}")]
#[non_exhaustive]
pub struct ProbeFailure {
    pub reason: String,
}

/// Runs the bash contract probe through `exec`.
#[tracing::instrument(skip_all, err)]
pub async fn run_bash_probe(exec: &dyn Exec) -> Result<()> {
    let spec = ExecSpec::new(BASH_PROBE_SCRIPT).timeout(PROBE_TIMEOUT);
    let result = exec.run(&spec).await?;
    if result.success() && result.stdout_lossy().trim() == PROBE_OK_MARKER {
        return Ok(());
    }
    Err(Error::Exec(ExecFailure::new(
        "bash probe",
        result.termination,
        result.exit_code,
        result.stdout,
        result.stderr,
    )))
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
