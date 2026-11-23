//! Commands attached to a terminal, over the toolbox PTY WebSocket.
//!
//! The toolbox's `create-connect` endpoint starts the sandbox user's shell
//! on a new pseudo-terminal, not a command. That shell is handed one line
//! that prints a marker and then replaces itself with the command, so the
//! terminal's exit is the command's and everything after the marker is the
//! command's output. Input crosses as binary frames; resize and kill go to
//! the toolbox REST endpoints.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::{future, io, process};

use daytona_sdk::{PtyCreateOptions, PtyHandle, PtySize};
use futures_util::future::BoxFuture;
use sandbox_driver::legacy::{Error, Result, TransportError};
use sandbox_driver::{
    ByteStream, ExecControls, ExecOutcome, OutputLoss, OutputStream, TerminalSize, Termination,
    stop_signal,
};
use tokio::io::AsyncReadExt as _;
use tokio::runtime::Handle;
use tokio::sync::{mpsc, watch};
use tokio::time::{self, Duration};

use crate::sdk::{DaytonaClient, daytona_error};
use crate::shell::shell_quote;
use crate::{CLEANUP_TIMEOUT, toolbox};

const READY: &str = "sandbox-driver-ready-";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// A command for a new terminal: the shell line that `exec`s it, and the
/// environment that line refers to.
pub(crate) struct Terminal {
    pub(crate) cwd:     String,
    /// Whether the terminal echoes input. A command that attaches a
    /// terminal of its own, as `docker exec -t` does, needs it off, or
    /// input would echo twice.
    pub(crate) echo:    bool,
    pub(crate) line:    String,
    /// The terminal's environment: the values the line names.
    pub(crate) env:     HashMap<String, String>,
    /// Ends whatever the command left running once the terminal is killed.
    pub(crate) stopped: Option<BoxFuture<'static, ()>>,
}

impl Terminal {
    /// `argv` run directly on the sandbox, in `cwd`, with `env` added.
    pub(crate) fn direct(cwd: String, env: &BTreeMap<String, String>, argv: &[String]) -> Self {
        let mut terminal = Self {
            cwd,
            echo: true,
            line: String::new(),
            env: HashMap::new(),
            stopped: None,
        };
        let assignments = terminal.forward("", env);
        terminal.line.push_str("exec env");
        // The command must not inherit the private names.
        for alias in terminal.env.keys() {
            write!(terminal.line, " -u {alias}").expect("writing a String cannot fail");
        }
        terminal.line.push_str(&assignments);
        push_words(&mut terminal.line, argv);
        terminal
    }

    /// ` {flag}'KEY='"$ALIAS"` for each variable, its value moved into the
    /// terminal's environment under a private name. The terminal echoes the
    /// line before the command can start, so the line names values and
    /// never holds them.
    pub(crate) fn forward(&mut self, flag: &str, env: &BTreeMap<String, String>) -> String {
        let mut words = String::new();
        for (key, value) in env {
            let alias = format!("SANDBOX_DRIVER_ENV_{}", self.env.len());
            write!(
                words,
                " {flag}{}\"${alias}\"",
                shell_quote(&format!("{key}="))
            )
            .expect("writing a String cannot fail");
            self.env.insert(alias, value.clone());
        }
        words
    }
}

/// Appends each word to `line`, quoted.
pub(crate) fn push_words(line: &mut String, words: &[impl AsRef<str>]) {
    for word in words {
        line.push(' ');
        line.push_str(&shell_quote(word.as_ref()));
    }
}

/// Runs `terminal` on its own pseudo-terminal until it exits, a stop token
/// fires, or `timeout` passes. Output reaches the sink as one
/// [`OutputStream::Terminal`] stream; input and resizes reach the
/// terminal as they arrive. A dropped future kills the terminal.
pub(crate) async fn run(
    client: &DaytonaClient,
    sandbox_id: &str,
    terminal: Terminal,
    timeout: Option<Duration>,
    controls: ExecControls,
) -> Result<ExecOutcome> {
    let ExecControls {
        mut stdin,
        sink,
        term,
        kill,
        mut resize,
    } = controls;
    let process = toolbox::process(client, sandbox_id).await?;
    let nonce = format!("{:032x}", rand::random::<u128>());
    let size = resize.as_ref().map(|size| pty_size(*size.borrow()));
    let mut handle = process
        .create_pty(
            &format!("sandbox-driver-{}-{nonce}", process::id()),
            PtyCreateOptions {
                cwd: Some(terminal.cwd),
                envs: (!terminal.env.is_empty()).then_some(terminal.env),
                size,
            },
        )
        .await
        .map_err(|error| daytona_error("opening terminal", error))?;
    let mut output = handle
        .take_output_receiver()
        .expect("a newly created PTY owns its output receiver");
    let live = Live {
        handle:  Some(handle),
        stopped: terminal.stopped,
    };
    // The marker's two halves are separate words, so the echoed line
    // never contains it.
    let stty = if terminal.echo { "" } else { "stty -echo; " };
    live.handle()
        .send_input(format!(
            "{stty}printf '%s%s' {READY} {nonce}; {}\n",
            terminal.line
        ))
        .await
        .map_err(|error| daytona_error("starting terminal command", error))?;
    let marker = format!("{READY}{nonce}").into_bytes();
    let first = time::timeout(STARTUP_TIMEOUT, after_marker(&mut output, &marker))
        .await
        .map_err(|_| startup_failed("terminal startup timed out"))?
        .ok_or_else(|| startup_failed("terminal ended before startup"))?;

    let deliver = |bytes: Vec<u8>| {
        let delivery = sink
            .as_ref()
            .map(|sink| sink(OutputStream::Terminal, bytes));
        async move {
            match delivery {
                Some(delivery) => delivery.await.map_err(|error| {
                    Error::Transport(TransportError::new(format!("output sink failed: {error}")))
                }),
                None => Ok(()),
            }
        }
    };
    if !first.is_empty() {
        deliver(first).await?;
    }
    let expired = async {
        match timeout {
            Some(timeout) => time::sleep(timeout).await,
            None => future::pending().await,
        }
    };
    tokio::pin!(expired);
    let mut buffer = vec![0_u8; 8192];
    let stop = loop {
        tokio::select! {
            biased;
            () = stop_signal(kill.as_ref()) => break Termination::Killed,
            () = stop_signal(term.as_ref()) => break Termination::Terminated,
            () = &mut expired => break Termination::TimedOut,
            bytes = output.recv() => match bytes {
                Some(bytes) => deliver(bytes).await?,
                None => return live.exited().await,
            },
            size = next_size(&mut resize) => match size {
                Some(size) => {
                    let size = pty_size(size);
                    if let Err(error) = live.handle().resize(size.cols, size.rows).await {
                        let error = daytona_error("resizing terminal", error);
                        tracing::warn!(error = %error, "terminal resize failed");
                    }
                }
                None => resize = None,
            },
            read = read_input(&mut stdin, &mut buffer) => match read {
                Ok(read) if read > 0 => {
                    // A terminal that already exited refuses input; its
                    // output still drains and reports the exit.
                    if live.handle().send_input(&buffer[..read]).await.is_err() {
                        stdin = None;
                    }
                }
                _ => stdin = None,
            },
        }
    };
    live.stop().await;
    Ok(ExecOutcome {
        termination: stop,
        exit_code:   None,
        signal:      None,
        output_loss: OutputLoss::default(),
    })
}

fn pty_size(size: TerminalSize) -> PtySize {
    PtySize {
        rows: size.rows.get(),
        cols: size.columns.get(),
    }
}

fn startup_failed(message: &str) -> Error {
    Error::io("starting terminal command", io::Error::other(message))
}

/// Output after `marker`, or `None` when the terminal ended first.
async fn after_marker(output: &mut mpsc::Receiver<Vec<u8>>, marker: &[u8]) -> Option<Vec<u8>> {
    let mut seen = Vec::new();
    while let Some(bytes) = output.recv().await {
        seen.extend(bytes);
        if let Some(index) = seen
            .windows(marker.len())
            .position(|window| window == marker)
        {
            return Some(seen.split_off(index + marker.len()));
        }
        // Keep only the suffix needed to match a split marker.
        if seen.len() > marker.len() {
            seen.drain(..seen.len() - marker.len());
        }
    }
    None
}

/// The next input; never resolves once input has ended.
async fn read_input(stdin: &mut Option<ByteStream>, buffer: &mut [u8]) -> io::Result<usize> {
    match stdin {
        Some(stdin) => stdin.read(buffer).await,
        None => future::pending().await,
    }
}

/// The next requested size, `None` once the caller dropped the sender;
/// never resolves without one.
async fn next_size(resize: &mut Option<watch::Receiver<TerminalSize>>) -> Option<TerminalSize> {
    match resize {
        Some(resize) => resize.changed().await.ok().map(|()| *resize.borrow()),
        None => future::pending().await,
    }
}

/// A terminal still running; dropping it kills the terminal.
struct Live {
    handle:  Option<PtyHandle>,
    stopped: Option<BoxFuture<'static, ()>>,
}

impl Live {
    fn handle(&self) -> &PtyHandle {
        self.handle
            .as_ref()
            .expect("a live terminal has its handle")
    }

    /// The outcome of a terminal whose output ended.
    async fn exited(mut self) -> Result<ExecOutcome> {
        let mut handle = self.handle.take().expect("a live terminal has its handle");
        let result = handle.wait().await;
        let _ = handle.disconnect().await;
        let exit_code = result
            .map_err(|error| daytona_error("waiting for terminal command", error))?
            .exit_code
            .ok_or_else(|| {
                Error::Transport(TransportError::new(
                    "the terminal ended without an exit status",
                ))
            })?;
        Ok(ExecOutcome {
            termination: Termination::Exited,
            exit_code:   Some(exit_code),
            signal:      None,
            output_loss: OutputLoss::default(),
        })
    }

    async fn stop(mut self) {
        if let Some(handle) = self.handle.take() {
            stop(handle, self.stopped.take()).await;
        }
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take()
            && let Ok(runtime) = Handle::try_current()
        {
            runtime.spawn(stop(handle, self.stopped.take()));
        }
    }
}

/// Kills the terminal, then ends what it left behind, within the cleanup
/// budget.
async fn stop(mut handle: PtyHandle, stopped: Option<BoxFuture<'static, ()>>) {
    match time::timeout(CLEANUP_TIMEOUT, handle.kill()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            let error = daytona_error("killing terminal", error);
            tracing::debug!(error = %error, "terminal was already stopped");
        }
        Err(_) => tracing::warn!("killing the terminal timed out"),
    }
    if let Some(stopped) = stopped {
        stopped.await;
    }
    let _ = handle.disconnect().await;
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;

    /// What `line` prints, run by a shell with the terminal's environment.
    fn run_line(terminal: &Terminal) -> String {
        let output = Command::new("/bin/sh")
            .args(["-c", &terminal.line])
            .envs(&terminal.env)
            .output()
            .expect("shell");
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).expect("text output")
    }

    #[test]
    fn the_direct_line_runs_the_argv_literally_with_its_environment() {
        let env = BTreeMap::from([
            ("INPUT-NAME".to_owned(), "a b'\"$HOME".to_owned()),
            ("TOKEN".to_owned(), "s3cret".to_owned()),
        ]);
        let argv = |words: &[&str]| {
            words
                .iter()
                .map(|&word| word.to_owned())
                .collect::<Vec<_>>()
        };
        let terminal = Terminal::direct("/".to_owned(), &env, &argv(&["env"]));
        assert!(!terminal.line.contains("s3cret"), "{}", terminal.line);
        let printed = run_line(&terminal);
        let ours: Vec<&str> = printed
            .lines()
            .filter(|line| {
                ["INPUT-NAME=", "TOKEN=", "SANDBOX_DRIVER_"]
                    .iter()
                    .any(|prefix| line.starts_with(prefix))
            })
            .collect();
        assert_eq!(ours, ["INPUT-NAME=a b'\"$HOME", "TOKEN=s3cret"]);

        let terminal = Terminal::direct(
            "/".to_owned(),
            &BTreeMap::new(),
            &argv(&["printf", "<%s>", "two words", "$HOME", "*"]),
        );
        assert_eq!(run_line(&terminal), "<two words><$HOME><*>");
    }
}
