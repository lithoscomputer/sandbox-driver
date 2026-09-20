//! A sentinel pins each process-group id until sandbox stop. Recovery writes
//! fence markers and only observes process death; it never signals saved ids.
//! The sentinel publishes its record before checking the marker and spawning
//! work. Its in-group watcher handles a fence even after the plugin dies. Once
//! the work has exited and its status is written, the idle sentinel also ends
//! its group when its owning provider process is gone.

use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{self, ExitStatus};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;
use std::{fs as sync_fs, io, mem, slice};

use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use sandbox_driver::{Error, ExecResult, ProviderError, Result, Termination};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::runtime::Handle;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::spawn_blocking;
use tokio::{fs, time};

use super::observation::group_is_live;
use crate::host_kind;

const POLL: Duration = Duration::from_millis(25);
const DRAIN: Duration = Duration::from_secs(5);
const FENCED: &str = "fenced";

// macOS creates pipes and sets close-on-exec in separate system calls.
// Serialize pipe creation and spawn across sandboxes so a sentinel cannot
// inherit another command's pipe during that gap and prevent its EOF.
#[cfg(target_os = "macos")]
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

use crate::registry::fresh_id;

fn sentinel_shell() -> &'static str {
    static SHELL: OnceLock<&'static str> = OnceLock::new();
    SHELL.get_or_init(|| {
        if Path::new("/bin/bash").is_file() {
            "/bin/bash"
        } else {
            "/bin/sh"
        }
    })
}

const SENTINEL_SCRIPT: &str = r#"
sf="$1"; gf="$2"; fence="$3"; owner="$4"; shift 4
printf '%s\n' "$$" > "$gf.tmp" && /bin/mv "$gf.tmp" "$gf" || exit 125
if [ -e "$fence" ]; then exit 0; fi
exec 3<&0
"$@" <&3 &
w=$!
trap '' TERM
exec >/dev/null 2>&1
( while kill -0 "$w" 2>/dev/null; do
    if [ -e "$fence" ]; then kill -KILL -- "-$$" 2>/dev/null || kill -KILL "-$$"; fi
    /bin/sleep 0.25
  done ) &
watch=$!
wait "$w"
s=$?
kill -9 "$watch" 2>/dev/null
echo "$s" > "$sf.tmp" && /bin/mv "$sf.tmp" "$sf"
while :; do
  if [ -e "$fence" ]; then kill -KILL -- "-$$" 2>/dev/null || kill -KILL "-$$"; fi
  kill -0 "$owner" 2>/dev/null || kill -KILL -- "-$$" 2>/dev/null || kill -KILL "-$$"
  /bin/sleep 1
done
"#;

/// Whether a sentinel still pins its process-group id.
enum Pin {
    /// The unreaped sentinel is held: the id cannot be recycled, so signals
    /// to the group are safe. Never wait or try_wait on it before stop: even
    /// a zombie pins the id.
    Held(Child),
    /// Stop took the child to reap it. No handle can signal during this
    /// window; the child comes back through [`PinnedGroup::restore`] if the
    /// reap fails.
    Reaping,
    /// The sentinel was reaped or dropped. The id may be recycled, so it is
    /// never signalled again.
    Reaped,
}

struct PinnedGroup {
    pgid: i32,
    pin:  Mutex<Pin>,
}

impl PinnedGroup {
    /// Signals the group while its id is pinned. `None` when the group is
    /// being reaped or was reaped: its id may be recycled, so it is neither
    /// signalled nor worth observing.
    fn signal(&self, signal: Signal) -> Option<io::Result<()>> {
        let pin = self.pin.lock().unwrap_or_else(PoisonError::into_inner);
        if !matches!(*pin, Pin::Held(_)) {
            return None;
        }
        Some(match killpg(Pid::from_raw(self.pgid), signal) {
            Ok(()) | Err(Errno::ESRCH) => Ok(()),
            Err(error) => Err(error.into()),
        })
    }

    fn is_pinned(&self) -> bool {
        matches!(
            *self.pin.lock().unwrap_or_else(PoisonError::into_inner),
            Pin::Held(_)
        )
    }

    /// Takes the held child for reaping, or `None` when nothing is held.
    fn take_for_reap(&self) -> Option<Child> {
        let mut pin = self.pin.lock().unwrap_or_else(PoisonError::into_inner);
        // No other handle can signal after this removes its proof of ownership.
        match mem::replace(&mut *pin, Pin::Reaping) {
            Pin::Held(child) => Some(child),
            other => {
                *pin = other;
                None
            }
        }
    }

    /// Puts an unreaped child back, so a later stop can retry both
    /// signalling and reaping.
    fn restore(&self, child: Child) {
        *self.pin.lock().unwrap_or_else(PoisonError::into_inner) = Pin::Held(child);
    }

    /// Records that the sentinel is gone: reaped here, or dropped for
    /// Tokio to reap.
    fn reaped(&self) {
        *self.pin.lock().unwrap_or_else(PoisonError::into_inner) = Pin::Reaped;
    }
}

/// A fork can publish a child after a group signal, and process-table
/// snapshots can briefly miss that child. Require two empty observations
/// while retaining the sentinels that pin these ids. Poll groups together
/// so stopping many completed commands pays one settling interval.
async fn kill_owned_groups(groups: &[Arc<PinnedGroup>]) -> io::Result<()> {
    let mut was_empty = false;
    loop {
        let signals: Vec<_> = groups
            .iter()
            .filter_map(|group| Some((group.pgid, group.signal(Signal::SIGKILL)?)))
            .collect();
        let live = spawn_blocking(move || {
            let mut live = false;
            for (pgid, signalled) in signals {
                if group_is_live(pgid) {
                    // macOS can reject signals to zombie-only groups.
                    // A failed signal matters only if a live member remains.
                    signalled?;
                    live = true;
                }
            }
            Ok::<_, io::Error>(live)
        })
        .await
        .map_err(io::Error::other)??;
        if !live && was_empty {
            return Ok(());
        }
        was_empty = !live;
        time::sleep(POLL).await;
    }
}

struct Generation {
    directory: PathBuf,
    groups:    Vec<Arc<PinnedGroup>>,
}

impl Generation {
    /// The record paths for the next group in this generation: the sentinel
    /// writes its group id to `group`, its workload's status to `status`,
    /// and watches `marker` for a fence.
    fn next_record_paths(&self) -> RecordPaths {
        let seq = self.groups.len();
        RecordPaths {
            status: self.directory.join(format!("{seq}.status")),
            group:  self.directory.join(format!("{seq}.group")),
            marker: self.directory.join(FENCED),
        }
    }
}

/// The files one sentinel and its owner communicate through, in the order
/// `SENTINEL_SCRIPT` reads them as `$1..$3`.
struct RecordPaths {
    status: PathBuf,
    group:  PathBuf,
    marker: PathBuf,
}

/// Admission and the current generation. The four combinations are all
/// legal: `accepting_work` with a generation is a running sandbox with
/// spawned work; `accepting_work` without one is running but idle (fresh,
/// or drained by a start); not accepting with a generation is stopped but
/// undrained, the retry state after a failed stop; not accepting without
/// one is stopped and drained.
struct GroupState {
    /// Whether `spawn` admits new work. Lifecycle code keeps this equal to
    /// `SandboxState::Running`; it is not the sandbox state itself.
    accepting_work: bool,
    generation:     Option<Generation>,
}

impl GroupState {
    /// The current generation, created on first use under `root`.
    async fn generation_or_create(&mut self, root: &Path) -> Result<&mut Generation> {
        if self.generation.is_none() {
            let directory = root.join(fresh_id());
            fs::create_dir_all(&directory)
                .await
                .map_err(|e| Error::io("creating process generation", e))?;
            self.generation = Some(Generation {
                directory,
                groups: Vec::new(),
            });
        }
        Ok(self
            .generation
            .as_mut()
            .expect("generation initialized above"))
    }
}

/// The sentinel invocation that runs `program` with `args` and reports
/// through `paths`.
fn sentinel_command(paths: &RecordPaths, program: &str, args: &[String]) -> Command {
    let mut command = Command::new(sentinel_shell());
    command
        .arg("-c")
        .arg(SENTINEL_SCRIPT)
        .arg("sandbox-driver-sentinel")
        .arg(&paths.status)
        .arg(&paths.group)
        .arg(&paths.marker)
        .arg(process::id().to_string())
        .arg(program)
        .args(args);
    command
}

pub(crate) struct ProcessGroups {
    root:            PathBuf,
    state:           AsyncMutex<GroupState>,
    cleanup_on_drop: bool,
}

impl ProcessGroups {
    pub(crate) fn new(root: PathBuf, running: bool, cleanup_on_drop: bool) -> Self {
        Self {
            root,
            cleanup_on_drop,
            state: AsyncMutex::new(GroupState {
                accepting_work: running,
                generation:     None,
            }),
        }
    }

    pub(crate) async fn start(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if !state.accepting_work {
            self.drain(&mut state).await?;
        }
        state.accepting_work = true;
        Ok(())
    }

    pub(crate) async fn spawn(
        self: &Arc<Self>,
        program: &str,
        args: &[String],
        configure: impl FnOnce(&mut Command),
    ) -> Result<HostChild> {
        let mut state = self.state.lock().await;
        if !state.accepting_work {
            return Err(
                ProviderError::new(host_kind(), "cannot execute in a stopped sandbox").into(),
            );
        }
        let generation = state.generation_or_create(&self.root).await?;
        let paths = generation.next_record_paths();
        let mut command = sentinel_command(&paths, program, args);
        configure(&mut command);
        command.process_group(0);
        command.kill_on_drop(false);
        let mut child = {
            #[cfg(target_os = "macos")]
            let _spawn = SPAWN_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
            command.spawn()
        }
        .map_err(|e| Error::io("spawning host sentinel", e))?;
        let pgid = child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .expect("a new Unix child has a positive pid");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let group = Arc::new(PinnedGroup {
            pgid,
            pin: Mutex::new(Pin::Held(child)),
        });
        generation.groups.push(group.clone());
        Ok(HostChild {
            stdin,
            stdout,
            stderr,
            group,
            _groups: self.clone(),
            status_file: paths.status,
        })
    }

    pub(crate) async fn stop(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        state.accepting_work = false;
        self.drain(&mut state).await
    }

    /// The recovery protocol, in order: fence every saved generation, kill
    /// and reap the groups this handle owns, wait until every id is gone,
    /// remove the generation records, and forget the generation. A failure
    /// leaves the generation in place so a later stop or start retries.
    async fn drain(&self, state: &mut GroupState) -> Result<()> {
        let deadline = time::Instant::now() + DRAIN;
        let (generation_paths, mut pgids) = fence_saved_generations(&self.root).await?;
        if let Some(generation) = &mut state.generation {
            // Persisted ids are never used here: each handle still owns its
            // unreaped sentinel.
            pgids.extend(generation.groups.iter().map(|group| group.pgid));
            kill_and_reap_owned(generation, deadline, &pgids).await?;
        }
        await_groups_gone(pgids, deadline).await?;
        remove_generation_dirs(&generation_paths).await?;
        state.generation = None;
        Ok(())
    }
}

/// Kills every owned group before waiting for any, then reaps each held
/// sentinel. `leaked` names every id the drain covers for the error. A
/// sentinel that cannot be reaped in time is put back so a later stop can
/// safely retry both signalling and reaping.
async fn kill_and_reap_owned(
    generation: &Generation,
    deadline: time::Instant,
    leaked: &[i32],
) -> Result<()> {
    time::timeout_at(deadline, kill_owned_groups(&generation.groups))
        .await
        .map_err(|_| fence_leaked(leaked))?
        .map_err(|error| Error::io("killing host process group", error))?;
    for group in &generation.groups {
        let Some(mut child) = group.take_for_reap() else {
            continue;
        };
        let outcome = match time::timeout_at(deadline, child.wait()).await {
            Ok(result) => result.map_err(|error| Error::io("reaping host process group", error)),
            Err(_) => Err(fence_leaked(leaked)),
        };
        if let Err(error) = outcome {
            // The unreaped child still pins this id.
            group.restore(child);
            return Err(error);
        }
        group.reaped();
    }
    Ok(())
}

/// Observes, without signalling, until no member of any group in `pgids`
/// is live, or the deadline passes.
async fn await_groups_gone(mut pgids: Vec<i32>, deadline: time::Instant) -> Result<()> {
    pgids.sort_unstable();
    pgids.dedup();
    loop {
        pgids = spawn_blocking(move || {
            pgids.retain(|id| group_is_live(*id));
            pgids
        })
        .await
        .map_err(|e| Error::io("observing process groups", io::Error::other(e)))?;
        if pgids.is_empty() {
            return Ok(());
        }
        if time::Instant::now() >= deadline {
            return Err(fence_leaked(&pgids));
        }
        time::sleep(POLL).await;
    }
}

/// Removes the record directories of drained generations; one that is
/// already gone is not an error.
async fn remove_generation_dirs(paths: &[PathBuf]) -> Result<()> {
    for directory in paths {
        match fs::remove_dir_all(directory).await {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(Error::io("removing drained process generation", error));
            }
        }
    }
    Ok(())
}

/// Marks every saved generation fenced and returns their directories with
/// the process-group ids they recorded. Marking precedes any observation, so
/// a concurrent old sentinel either publishes in time or sees the marker
/// before it spawns.
async fn fence_saved_generations(root: &Path) -> Result<(Vec<PathBuf>, Vec<i32>)> {
    let mut entries = match fs::read_dir(root).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), Vec::new())),
        Err(e) => return Err(Error::io("reading process generations", e)),
    };
    let mut directories = Vec::new();
    let mut pgids = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| Error::io("reading process generation", e))?
    {
        if !entry
            .file_type()
            .await
            .map_err(|e| Error::io("reading generation type", e))?
            .is_dir()
        {
            continue;
        }
        let directory = entry.path();
        fs::write(directory.join(FENCED), b"")
            .await
            .map_err(|e| Error::io("writing process fence", e))?;
        pgids.extend(saved_pgids(&directory).await?);
        directories.push(directory);
    }
    Ok((directories, pgids))
}

/// The process-group ids one generation directory recorded.
async fn saved_pgids(directory: &Path) -> Result<Vec<i32>> {
    let mut records = fs::read_dir(directory)
        .await
        .map_err(|e| Error::io("reading group records", e))?;
    let mut pgids = Vec::new();
    while let Some(record) = records
        .next_entry()
        .await
        .map_err(|e| Error::io("reading group record", e))?
    {
        let path = record.path();
        if path.extension().is_none_or(|ext| ext != "group") {
            continue;
        }
        let text = fs::read_to_string(&path)
            .await
            .map_err(|e| Error::io("reading saved process group", e))?;
        let pgid = text
            .trim()
            .parse::<i32>()
            .ok()
            .filter(|id| *id > 0)
            .ok_or_else(|| {
                Error::io(
                    "invalid saved process group",
                    io::Error::other("expected a positive process-group id"),
                )
            })?;
        pgids.push(pgid);
    }
    Ok(pgids)
}

impl Drop for ProcessGroups {
    fn drop(&mut self) {
        // Explicit stop already reaped the children and removed generation
        // records. Dropping a drained or unused handle needs no cleanup task.
        if !self.cleanup_on_drop {
            return;
        }
        let Some(generation) = &self.state.get_mut().generation else {
            return;
        };
        for group in &generation.groups {
            // Signal only ids still pinned by our child handles. Tokio
            // takes responsibility for reaping each dropped child.
            let _ = group.signal(Signal::SIGKILL);
            group.reaped();
        }
        // Disposable process records have no recovery caller. Their removal
        // is best effort and must not block the thread dropping the owner.
        if let Ok(runtime) = Handle::try_current() {
            let root = self.root.clone();
            runtime.spawn_blocking(move || sync_fs::remove_dir_all(root));
        }
    }
}

fn fence_leaked(pgids: &[i32]) -> Error {
    let mut error = ProviderError::new(
        host_kind(),
        format!("process groups {pgids:?} did not drain; no signal was sent to saved ids"),
    );
    error.code = Some("fence_leaked".to_owned());
    error.into()
}

/// A workload's status and pipes. The sandbox, not this handle, owns the
/// sentinel. Dropping or completing an exec cannot release its pinned id.
pub(crate) struct HostChild {
    pub(crate) stdin:  Option<ChildStdin>,
    pub(crate) stdout: Option<ChildStdout>,
    pub(crate) stderr: Option<ChildStderr>,
    group:             Arc<PinnedGroup>,
    // A standalone stdio process can outlive the HostExec that spawned it.
    _groups:           Arc<ProcessGroups>,
    status_file:       PathBuf,
}

impl HostChild {
    /// SIGTERMs the process group, once, and returns: the
    /// [`sandbox_driver::ExecControls::term`] path. Whether the command
    /// ends is the command's business; the caller escalates to `kill` if
    /// it must.
    pub(crate) fn term(&self) {
        let _ = self.group.signal(Signal::SIGTERM);
    }

    /// SIGKILLs the process group and waits for the group to settle: the
    /// [`sandbox_driver::ExecControls::kill`] path, the timeout, and a
    /// failing sink. The sentinel stays pinned; only stop reaps it.
    pub(crate) async fn kill(&mut self) {
        let _ = kill_owned_groups(slice::from_ref(&self.group)).await;
    }

    /// Sends SIGTERM to the process group, waits `grace` for a graceful
    /// exit, then SIGKILLs the group: the stdio handle's `terminate`.
    pub(crate) async fn terminate(&mut self, grace: Duration) {
        self.term();
        if time::timeout(grace, self.wait()).await.is_ok() {
            return;
        }
        self.kill().await;
    }

    pub(crate) async fn wait(&mut self) -> io::Result<ExitStatus> {
        loop {
            if let Some(status) = self.recorded_status().await {
                return Ok(status);
            }
            if !self.group.is_pinned() {
                // Stop took or reaped the sentinel: the group was killed.
                return Ok(ExitStatus::from_raw(9));
            }
            let pgid = self.group.pgid;
            let live = spawn_blocking(move || group_is_live(pgid))
                .await
                .map_err(io::Error::other)?;
            if !live {
                return Ok(self
                    .recorded_status()
                    .await
                    .unwrap_or_else(|| ExitStatus::from_raw(9)));
            }
            time::sleep(POLL).await;
        }
    }

    async fn recorded_status(&self) -> Option<ExitStatus> {
        let code = fs::read_to_string(&self.status_file)
            .await
            .ok()?
            .trim()
            .parse::<u8>()
            .ok()?;
        Some(ExitStatus::from_raw(i32::from(code) << 8))
    }
}

/// The exec result for a status the sentinel reported. The sentinel echoes
/// its workload's shell status, so a signal death arrives as `128 + N` and
/// is decoded by [`ExecResult::from_shell_status`]; a signal that ended the
/// sentinel itself takes precedence.
pub(crate) fn exec_result(
    termination: Termination,
    status: ExitStatus,
    duration: Duration,
) -> ExecResult {
    let mut result = ExecResult::from_shell_status(termination, status.code(), duration);
    result.signal = status.signal().or(result.signal);
    result
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::env;

    use sandbox_driver::{Exec, ExecSpec, SandboxProvider, SandboxSource, SandboxSpec, SpawnSpec};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    use super::*;
    use crate::{HostExec, HostProvider, registry};

    async fn wait_for_group_exit(pgid: i32) {
        time::timeout(Duration::from_secs(3), async {
            while spawn_blocking(move || group_is_live(pgid))
                .await
                .expect("observe process group")
            {
                time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the final temporary owner releases its sentinel");
    }

    #[tokio::test]
    async fn standalone_exec_releases_completed_process_groups_on_drop() {
        let exec = HostExec::new(env::temp_dir(), BTreeMap::new(), false);
        let result = exec.run(&ExecSpec::bash("echo $PPID")).await.unwrap();
        let pgid = result.stdout_lossy().trim().parse().unwrap();
        drop(exec);
        wait_for_group_exit(pgid).await;
    }

    #[tokio::test]
    async fn standalone_stdio_owns_its_process_after_the_executor_drops() {
        let exec = HostExec::new(env::temp_dir(), BTreeMap::new(), false);
        let mut process = exec
            .spawn_stdio(&SpawnSpec::new("sh").args(["-c", "echo $PPID; exec cat"]))
            .await
            .unwrap();
        drop(exec);
        let mut output = BufReader::new(process.stdout);
        let mut line = String::new();
        output.read_line(&mut line).await.unwrap();
        let pgid = line.trim().parse().unwrap();
        process.stdin.write_all(b"still alive\n").await.unwrap();
        line.clear();
        time::timeout(Duration::from_secs(3), output.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(line, "still alive\n");
        process.handle.terminate().await;
        wait_for_group_exit(pgid).await;
    }

    #[tokio::test]
    async fn only_durable_providers_keep_groups_after_the_last_handle_drops() {
        for durable in [false, true] {
            let root = env::temp_dir().join(registry::fresh_id());
            let provider = if durable {
                HostProvider::with_registry(&root).await.unwrap()
            } else {
                HostProvider::new()
            };
            let sandbox = provider
                .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
                .await
                .unwrap();
            let id = sandbox.id().clone();
            let workspace = sandbox.working_directory().to_owned();
            let result = sandbox
                .exec()
                .run(&ExecSpec::bash("echo $PPID"))
                .await
                .unwrap();
            let pgid = result.stdout_lossy().trim().parse().unwrap();
            drop(sandbox);
            drop(provider);
            if durable {
                assert!(spawn_blocking(move || group_is_live(pgid)).await.unwrap());
                HostProvider::with_registry(&root)
                    .await
                    .unwrap()
                    .delete(&id, None)
                    .await
                    .unwrap();
                fs::remove_dir_all(root).await.unwrap();
            } else {
                fs::remove_dir_all(workspace).await.unwrap();
            }
            wait_for_group_exit(pgid).await;
        }
    }
}
