//! Direct process execution for platforms without the sentinel fence. Each
//! command runs in its own process group where the platform has them and is
//! killed when its handle drops. Nothing pins a group id past the command,
//! no process records are written, and `stop` fences nothing: this backend
//! keeps the pre-fence behavior of those platforms.

use std::io;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use nix::sys::signal::{Signal, killpg};
#[cfg(unix)]
use nix::unistd::Pid;
use sandbox_driver::{Error, ExecResult, Result, Termination};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
#[cfg(unix)]
use tokio::time;

/// The process owner for a sandbox on a platform without the fence. It has
/// no state: commands are not admitted or refused by sandbox state, and stop
/// has nothing to drain.
pub(crate) struct ProcessGroups;

impl ProcessGroups {
    pub(crate) fn new(root: PathBuf, running: bool, cleanup_on_drop: bool) -> Self {
        // No records are written and nothing outlives its handle, so the
        // record location, the admission flag, and the drop policy have no
        // effect here.
        let _ = (root, running, cleanup_on_drop);
        Self
    }

    #[expect(
        clippy::unused_async,
        reason = "the sentinel backend awaits a drain here; both backends share one signature"
    )]
    pub(crate) async fn start(&self) -> Result<()> {
        Ok(())
    }

    #[expect(
        clippy::unused_async,
        reason = "the sentinel backend awaits generation setup here; both backends share one signature"
    )]
    pub(crate) async fn spawn(
        self: &Arc<Self>,
        program: &str,
        args: &[String],
        configure: impl FnOnce(&mut Command),
    ) -> Result<HostChild> {
        let mut command = Command::new(program);
        command.args(args);
        configure(&mut command);
        #[cfg(unix)]
        command.process_group(0);
        command.kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|error| Error::io("spawning host command", error))?;
        Ok(HostChild {
            stdin: child.stdin.take(),
            stdout: child.stdout.take(),
            stderr: child.stderr.take(),
            child,
        })
    }

    #[expect(
        clippy::unused_async,
        reason = "the sentinel backend awaits a drain here; both backends share one signature"
    )]
    pub(crate) async fn stop(&self) -> Result<()> {
        Ok(())
    }
}

/// A workload's status and pipes. The child is killed when this handle
/// drops.
pub(crate) struct HostChild {
    pub(crate) stdin:  Option<ChildStdin>,
    pub(crate) stdout: Option<ChildStdout>,
    pub(crate) stderr: Option<ChildStderr>,
    child:             Child,
}

impl HostChild {
    /// SIGTERMs the process group, once, and returns: the
    /// [`sandbox_driver::ExecControls::term`] path. Whether the command
    /// ends is the command's business; the caller escalates to `kill` if
    /// it must. Platforms without process groups have no term signal.
    pub(crate) fn term(&self) {
        #[cfg(unix)]
        self.signal(Signal::SIGTERM);
    }

    /// SIGKILLs the process group and the child directly: the
    /// [`sandbox_driver::ExecControls::kill`] path, the timeout, and a
    /// failing sink.
    ///
    /// The direct kill is the guarantee: a command that moved itself out of
    /// its process group makes the group signals miss entirely (killpg on
    /// an empty group is ESRCH), and the callers' subsequent `wait()` would
    /// hang forever. SIGKILL to the immediate child always lands, and
    /// `kill()` reaps it, so a completed kill means a returned wait.
    pub(crate) async fn kill(&mut self) {
        #[cfg(unix)]
        self.signal(Signal::SIGKILL);
        let _ = self.child.kill().await;
    }

    /// Sends SIGTERM to the process group, waits `grace` for a graceful
    /// exit, then kills: the stdio handle's `terminate`. Platforms without
    /// a term signal kill at once.
    pub(crate) async fn terminate(&mut self, grace: Duration) {
        #[cfg(unix)]
        {
            self.term();
            if time::timeout(grace, self.wait()).await.is_ok() {
                return;
            }
        }
        #[cfg(not(unix))]
        let _ = grace;
        self.kill().await;
    }

    pub(crate) async fn wait(&mut self) -> io::Result<ExitStatus> {
        self.child.wait().await
    }

    #[cfg(unix)]
    fn signal(&self, signal: Signal) {
        if let Some(pid) = self.child.id() {
            // A pid that does not fit i32 must skip the kill entirely: a
            // zero pgid would signal the caller's own process group.
            let Ok(pid) = i32::try_from(pid) else {
                return;
            };
            let _ = killpg(Pid::from_raw(pid), signal);
        }
    }
}

/// The exec result for a status the child reported directly. The exit code
/// is the process's own; a signal death is reported where the platform
/// exposes one.
pub(crate) fn exec_result(
    termination: Termination,
    status: ExitStatus,
    duration: Duration,
) -> ExecResult {
    #[cfg(unix)]
    let signal = status.signal();
    #[cfg(not(unix))]
    let signal = None;
    let mut result = ExecResult::new(termination, status.code(), duration);
    result.signal = signal;
    result
}
