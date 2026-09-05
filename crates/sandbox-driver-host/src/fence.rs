//! A sentinel pins each process-group id until sandbox stop. Recovery writes
//! fence markers and only observes process death; it never signals saved ids.
//! The sentinel publishes its record before checking the marker and spawning
//! work. Its in-group watcher handles a fence even after the plugin dies.

use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;
use std::{fs as sync_fs, io};

use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use sandbox_driver::{Error, ProviderError, ProviderKind, Result};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::runtime::Handle;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::spawn_blocking;
use tokio::{fs, time};

use crate::observation::group_is_live;

const POLL: Duration = Duration::from_millis(25);
const DRAIN: Duration = Duration::from_secs(5);
const FENCED: &str = "fenced";

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
sf="$1"; gf="$2"; fence="$3"; shift 3
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
  /bin/sleep 1
done
"#;

struct PinnedGroup {
    pgid:  i32,
    // Never wait or try_wait before stop: even a zombie pins the id.
    child: Mutex<Option<Child>>,
}

impl PinnedGroup {
    fn signal(&self, signal: Signal) -> io::Result<()> {
        let child = self.child.lock().unwrap_or_else(PoisonError::into_inner);
        if child.is_some() {
            match killpg(Pid::from_raw(self.pgid), signal) {
                Ok(()) | Err(Errno::ESRCH) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn take_for_reap(&self) -> Option<Child> {
        let mut child = self.child.lock().unwrap_or_else(PoisonError::into_inner);
        // No other handle can signal after this removes its proof of ownership.
        child.take()
    }
}

struct Generation {
    directory: PathBuf,
    groups:    Vec<Arc<PinnedGroup>>,
}

struct GroupState {
    running:    bool,
    generation: Option<Generation>,
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
                running,
                generation: None,
            }),
        }
    }

    pub(crate) async fn start(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if !state.running {
            self.drain(&mut state).await?;
        }
        state.running = true;
        Ok(())
    }

    pub(crate) async fn spawn(
        self: &Arc<Self>,
        program: &str,
        args: &[String],
        configure: impl FnOnce(&mut Command),
    ) -> Result<HostChild> {
        let mut state = self.state.lock().await;
        if !state.running {
            return Err(ProviderError::new(
                ProviderKind::try_new("host").expect("static kind"),
                "cannot execute in a stopped sandbox",
            )
            .into());
        }
        if state.generation.is_none() {
            let directory = self.root.join(fresh_id());
            fs::create_dir_all(&directory)
                .await
                .map_err(|e| Error::io("creating process generation", e))?;
            state.generation = Some(Generation {
                directory,
                groups: Vec::new(),
            });
        }
        let generation = state
            .generation
            .as_mut()
            .expect("generation initialized above");
        let seq = generation.groups.len();
        let status_file = generation.directory.join(format!("{seq}.status"));
        let group_file = generation.directory.join(format!("{seq}.group"));
        let marker = generation.directory.join(FENCED);
        let mut command = Command::new(sentinel_shell());
        command
            .arg("-c")
            .arg(SENTINEL_SCRIPT)
            .arg("sandbox-driver-sentinel")
            .arg(&status_file)
            .arg(&group_file)
            .arg(&marker)
            .arg(program)
            .args(args);
        configure(&mut command);
        command.process_group(0);
        command.kill_on_drop(false);
        let mut child = command
            .spawn()
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
            child: Mutex::new(Some(child)),
        });
        generation.groups.push(group.clone());
        Ok(HostChild {
            stdin,
            stdout,
            stderr,
            group,
            _groups: self.clone(),
            status_file,
        })
    }

    pub(crate) async fn stop(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        state.running = false;
        self.drain(&mut state).await
    }

    async fn drain(&self, state: &mut GroupState) -> Result<()> {
        let deadline = time::Instant::now() + DRAIN;
        // Mark all generations before observing any group. A concurrent old
        // sentinel must either publish in time or see the marker before spawn.
        let mut pgids = Vec::new();
        let mut generation_paths = Vec::new();
        let mut directories = match fs::read_dir(&self.root).await {
            Ok(entries) => Some(entries),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(Error::io("reading process generations", e)),
        };
        if let Some(entries) = &mut directories {
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
                generation_paths.push(directory.clone());
                let mut records = fs::read_dir(&directory)
                    .await
                    .map_err(|e| Error::io("reading group records", e))?;
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
            }
        }
        if let Some(generation) = &mut state.generation {
            // Kill every owned group before waiting for any. Persisted ids are
            // never used here: each handle still owns its unreaped sentinel.
            for group in &generation.groups {
                pgids.push(group.pgid);
                if let Err(error) = group.signal(Signal::SIGKILL) {
                    // Some platforms reject a signal to an already-dead
                    // group. Only a live group still needs a successful kill.
                    let pgid = group.pgid;
                    let live =
                        spawn_blocking(move || group_is_live(pgid))
                            .await
                            .map_err(|error| {
                                Error::io("observing process group", io::Error::other(error))
                            })?;
                    if live {
                        return Err(Error::io("killing host process group", error));
                    }
                }
            }
            for group in &generation.groups {
                let Some(mut child) = group.take_for_reap() else {
                    continue;
                };
                let outcome = match time::timeout_at(deadline, child.wait()).await {
                    Ok(result) => {
                        result.map_err(|error| Error::io("reaping host process group", error))
                    }
                    Err(_) => Err(fence_leaked(&pgids)),
                };
                if let Err(error) = outcome {
                    // The unreaped child still pins this id. Keep it so a
                    // later stop can safely retry both signalling and reaping.
                    *group.child.lock().unwrap_or_else(PoisonError::into_inner) = Some(child);
                    return Err(error);
                }
            }
        }
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
                for directory in &generation_paths {
                    match fs::remove_dir_all(directory).await {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => {
                            return Err(Error::io("removing drained process generation", error));
                        }
                    }
                }
                state.generation = None;
                return Ok(());
            }
            if time::Instant::now() >= deadline {
                return Err(fence_leaked(&pgids));
            }
            time::sleep(POLL).await;
        }
    }
}

impl Drop for ProcessGroups {
    fn drop(&mut self) {
        if !self.cleanup_on_drop {
            return;
        }
        if let Some(generation) = &self.state.get_mut().generation {
            for group in &generation.groups {
                // Signal only ids still pinned by our child handles. Tokio
                // takes responsibility for reaping each dropped child.
                let _ = group.signal(Signal::SIGKILL);
                drop(group.take_for_reap());
            }
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
        ProviderKind::try_new("host").expect("static kind"),
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
    pub(crate) fn signal(&self, signal: Signal) {
        let _ = self.group.signal(signal);
    }

    pub(crate) async fn kill(&mut self) -> io::Result<()> {
        self.group.signal(Signal::SIGKILL)?;
        self.wait().await.map(|_| ())
    }

    pub(crate) async fn wait(&mut self) -> io::Result<ExitStatus> {
        loop {
            if let Some(status) = self.recorded_status().await {
                return Ok(status);
            }
            if self
                .group
                .child
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_none()
            {
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
