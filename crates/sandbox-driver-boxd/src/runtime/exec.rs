//! Commands over boxd's bidirectional `Exec` stream.
//!
//! boxd runs the command string with `/bin/sh -c`, so argv is quoted into
//! one line that changes directory and execs the program under `env`; no
//! shell parses the caller's arguments.
//!
//! Before it execs, the line takes an exclusive `flock` on a file named for
//! the command, on a descriptor every process the command starts inherits.
//! The lock is released only once all of them have exited, which another
//! exec can check. That is how a stop is confirmed: cancelling the call
//! makes boxd's in-machine agent signal the command's process tree
//! (SIGTERM, then SIGKILL), and the stop is reported only once the lock is
//! free. Without `flock` in the image the line runs unlocked and a stop
//! stays unconfirmed. Each line also removes the lock files of commands
//! that have ended, so they do not accumulate.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{future, mem, process};

use sandbox_driver::{ByteStream, Error, MutationOutcome, OutputSink, OutputStream, Termination};
use tokio::io::AsyncReadExt as _;
use tokio::sync::mpsc;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tonic::Status;

use super::api::ExecChunk;
use super::connection::{Connection, requests};

/// Bytes of stdin sent per message.
const STDIN_CHUNK: usize = 64 * 1024;
/// Where commands keep their locks.
const LOCKS: &str = "/tmp/.sandbox-driver/exec";
/// Bounds confirming that a stopped command has ended.
const CONFIRM_BUDGET: Duration = Duration::from_secs(15);
const CONFIRM_POLL: Duration = Duration::from_millis(500);
/// Bounds each confirming check, which is itself a command.
const CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// One command, ready to send.
pub(super) struct Command {
    pub(super) machine: String,
    /// Names the command's lock; unique per command.
    pub(super) token:   String,
    pub(super) line:    String,
    pub(super) timeout: Option<Duration>,
}

impl Command {
    /// A command running `argv` in `directory` with `env` added.
    pub(super) fn new(
        machine: &str,
        directory: &str,
        env: &BTreeMap<String, String>,
        argv: &[String],
        timeout: Option<Duration>,
    ) -> Self {
        let token = token();
        Self {
            machine: machine.to_owned(),
            line: line(&token, directory, env, argv),
            token,
            timeout,
        }
    }
}

pub(super) struct Controls {
    pub(super) stdin:  Option<ByteStream>,
    pub(super) sink:   Option<OutputSink>,
    pub(super) term:   Option<CancellationToken>,
    pub(super) kill:   Option<CancellationToken>,
    pub(super) closed: CancellationToken,
}

/// How a command ended, as far as the stream and its lock can tell.
pub(super) enum Ended {
    Exited(i32),
    /// Stopped by the caller or its timeout, and confirmed ended.
    Stopped(Termination),
    /// Stopped by the caller or its timeout; its end is not confirmed.
    Unconfirmed,
    /// The stream broke before boxd reported an exit code: with boxd's
    /// status, or without one when the stream just closed.
    Broken(Option<Status>),
}

/// A name for one command's lock, unique across processes and machines.
fn token() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    format!(
        "{:x}-{nanos:x}-{:x}",
        process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// The shell line that runs `argv` in `directory` with `env` added, holding
/// the lock `token` names.
fn line(token: &str, directory: &str, env: &BTreeMap<String, String>, argv: &[String]) -> String {
    // The lock is taken under a dot name and then renamed, so the prune
    // loop, which skips dot names, never removes a lock before it is held.
    let mut line = format!(
        "if command -v flock >/dev/null 2>&1 && mkdir -p {LOCKS} 2>/dev/null \
         && ( : > {LOCKS}/.{token} ) 2>/dev/null; then \
         for f in {LOCKS}/*; do [ -e \"$f\" ] && flock -n \"$f\" rm -f \"$f\"; done; \
         exec 9>{LOCKS}/.{token} && flock -n 9 && mv {LOCKS}/.{token} {LOCKS}/{token}; \
         fi; cd {} && exec env --",
        quote(directory)
    );
    for (key, value) in env {
        line.push(' ');
        line.push_str(&quote(&format!("{key}={value}")));
    }
    // `--` keeps `env` from reading a program or variable that starts with
    // `-` as an option. It still reads leading NAME=VALUE words as
    // assignments, so a program name containing `=` goes through `sh -c`.
    if argv.first().is_some_and(|program| program.contains('=')) {
        line.push_str(" sh -c 'exec \"$@\"' sh");
    }
    for arg in argv {
        line.push(' ');
        line.push_str(&quote(arg));
    }
    line
}

/// The check that `token`'s command has ended: exit 0 once its lock is
/// free (and then removed), 1 while it is held, 3 when there is no lock.
fn check_line(token: &str) -> String {
    format!(
        "for f in {LOCKS}/{token} {LOCKS}/.{token}; do \
         if [ -e \"$f\" ]; then flock -n \"$f\" rm -f \"$f\" && exit 0; exit 1; fi; done; exit 3"
    )
}

/// POSIX single-quoting: every byte stands for itself.
pub(super) fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// What ended the drive of one call.
enum Event {
    Stop(Termination),
    Ended(Ended),
}

/// Runs `command` to its end. A stop is reported only once confirmed;
/// what a broken stream means is for the caller to establish.
pub(super) async fn run(
    connection: &Connection,
    command: Command,
    controls: Controls,
) -> Result<Ended, Error> {
    let closed = controls.closed.clone();
    let event = drive(connection, &command, controls).await?;
    // The call is dropped by now, so boxd is signalling the command.
    let Event::Stop(termination) = event else {
        let Event::Ended(ended) = event else {
            unreachable!("both events are handled")
        };
        return Ok(ended);
    };
    let started = Instant::now();
    while started.elapsed() < CONFIRM_BUDGET {
        if closed.is_cancelled() {
            return Err(Error::Stale {
                outcome: MutationOutcome::Unknown,
            });
        }
        match check(connection, &command.machine, &command.token, &closed).await {
            Some(0) => return Ok(Ended::Stopped(termination)),
            Some(1) => time::sleep(CONFIRM_POLL).await,
            _ => break,
        }
    }
    Ok(Ended::Unconfirmed)
}

/// The exit code of the lock check, or `None` when it could not run.
async fn check(
    connection: &Connection,
    machine: &str,
    token: &str,
    closed: &CancellationToken,
) -> Option<i32> {
    exit_code(connection, machine, check_line(token), closed).await
}

/// Runs a provider-built shell `line` with no input or output and returns
/// its exit code, or `None` when it could not run to an exit.
pub(super) async fn exit_code(
    connection: &Connection,
    machine: &str,
    line: String,
    closed: &CancellationToken,
) -> Option<i32> {
    let command = Command {
        machine: machine.to_owned(),
        token: String::new(),
        line,
        timeout: Some(CHECK_TIMEOUT),
    };
    let controls = Controls {
        stdin:  None,
        sink:   None,
        term:   None,
        kill:   None,
        closed: closed.clone(),
    };
    match Box::pin(drive(connection, &command, controls)).await {
        Ok(Event::Ended(Ended::Exited(code))) => Some(code),
        _ => None,
    }
}

/// Sends the command and relays its stream until it ends or a stop asks
/// for it to be cancelled.
async fn drive(
    connection: &Connection,
    command: &Command,
    controls: Controls,
) -> Result<Event, Error> {
    let Controls {
        stdin,
        sink,
        term,
        kill,
        closed,
    } = controls;
    let (sender, receiver) = mpsc::channel(4);
    sender
        .send(ExecChunk {
            vm_id: command.machine.clone(),
            command: command.line.clone(),
            ..ExecChunk::default()
        })
        .await
        .expect("the receiver is held below");
    let request = connection.request(requests(receiver)).await?;
    let mut api = connection.api();
    let expired = async {
        match command.timeout {
            Some(timeout) => time::sleep(timeout).await,
            None => future::pending().await,
        }
    };
    tokio::pin!(expired);
    let call = api.exec(request);
    tokio::pin!(call);
    let mut stdin = Stdin::new(stdin, sender);
    let stop = |termination| Ok(Event::Stop(termination));

    let response = loop {
        tokio::select! {
            biased;
            () = closed.cancelled() => return Err(Error::Stale { outcome: MutationOutcome::Unknown }),
            () = sandbox_driver::stop_signal(kill.as_ref()) => return stop(Termination::Killed),
            () = sandbox_driver::stop_signal(term.as_ref()) => return stop(Termination::Terminated),
            () = &mut expired => return stop(Termination::TimedOut),
            result = stdin.pump(), if stdin.pending() => result?,
            response = &mut call => break response,
        }
    };
    let mut inbound = match response {
        Ok(response) => response.into_inner(),
        Err(status) => return Ok(Event::Ended(Ended::Broken(Some(status)))),
    };
    // boxd ends the stream with one message that carries no output and the
    // exit code; output messages carry the field at its default.
    let mut exit_code = None;
    loop {
        let message = tokio::select! {
            biased;
            () = closed.cancelled() => return Err(Error::Stale { outcome: MutationOutcome::Unknown }),
            () = sandbox_driver::stop_signal(kill.as_ref()) => return stop(Termination::Killed),
            () = sandbox_driver::stop_signal(term.as_ref()) => return stop(Termination::Terminated),
            () = &mut expired => return stop(Termination::TimedOut),
            result = stdin.pump(), if stdin.pending() => {
                result?;
                continue;
            }
            message = inbound.message() => message,
        };
        match message {
            Ok(Some(chunk)) if chunk.data.is_empty() => exit_code = Some(chunk.exit_code),
            Ok(Some(chunk)) => {
                exit_code = None;
                if let Some(sink) = &sink {
                    let stream = if chunk.is_stderr {
                        OutputStream::Stderr
                    } else {
                        OutputStream::Stdout
                    };
                    // A failed sink ends the command: returning drops the
                    // call, which cancels it.
                    sink(stream, chunk.data).await?;
                }
            }
            Ok(None) => {
                return Ok(Event::Ended(
                    exit_code.map_or(Ended::Broken(None), Ended::Exited),
                ));
            }
            Err(status) => return Ok(Event::Ended(Ended::Broken(Some(status)))),
        }
    }
}

/// Streams the caller's stdin into the call, then half-closes it.
struct Stdin {
    input:  Option<ByteStream>,
    sender: Option<mpsc::Sender<ExecChunk>>,
}

impl Stdin {
    fn new(input: Option<ByteStream>, sender: mpsc::Sender<ExecChunk>) -> Self {
        // Without input the send half closes at once: the command reads EOF.
        let sender = input.is_some().then_some(sender);
        Self { input, sender }
    }

    fn pending(&self) -> bool {
        self.sender.is_some()
    }

    /// Sends one chunk, or closes the input at its end. A read failure
    /// fails the command rather than delivering a truncated input as EOF.
    ///
    /// Cancel-safe, because the drive races it against output: capacity is
    /// reserved before anything is read, and a read that is dropped
    /// consumes nothing, so no chunk is ever read and then lost.
    async fn pump(&mut self) -> Result<(), Error> {
        let (Some(input), Some(sender)) = (self.input.as_mut(), self.sender.as_ref()) else {
            return future::pending().await;
        };
        let Ok(permit) = sender.clone().reserve_owned().await else {
            // The call has ended; its outcome arrives on the response.
            self.sender = None;
            return Ok(());
        };
        let mut buffer = vec![0; STDIN_CHUNK];
        let read = input
            .read(&mut buffer)
            .await
            .map_err(|_| Error::Transport {
                message: "reading stdin failed".to_owned(),
                outcome: MutationOutcome::Unknown,
            })?;
        if read == 0 {
            self.sender = None;
            self.input = None;
            return Ok(());
        }
        buffer.truncate(read);
        let chunk = ExecChunk {
            stdin: true,
            data: mem::take(&mut buffer),
            ..ExecChunk::default()
        };
        permit.send(chunk);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command as Shell;

    use super::*;

    /// Runs `argv` through the line boxd would run, in a local `sh`.
    fn through_sh(env: &BTreeMap<String, String>, argv: &[&str]) -> Vec<u8> {
        let argv: Vec<String> = argv.iter().map(|&arg| arg.to_owned()).collect();
        let line = line(&token(), "/", env, &argv);
        Shell::new("sh")
            .args(["-c", &line])
            .output()
            .expect("sh runs")
            .stdout
    }

    #[test]
    fn arguments_reach_the_program_untouched() {
        let tricky = ["a b", "it's", "$HOME", "`id`", "; exit 3", "\n", "*", ""];
        let mut argv = vec!["printf", "[%s]"];
        argv.extend(tricky);
        let expected: String = tricky.iter().flat_map(|arg| ["[", arg, "]"]).collect();
        assert_eq!(through_sh(&BTreeMap::new(), &argv), expected.into_bytes());
    }

    #[test]
    fn the_environment_reaches_the_program_as_given() {
        let env = BTreeMap::from([("ODD".to_owned(), "it's $HOME `id`".to_owned())]);
        assert_eq!(
            through_sh(&env, &["sh", "-c", "printf %s \"$ODD\""]),
            b"it's $HOME `id`"
        );
    }

    #[test]
    fn a_program_whose_name_has_an_equals_sign_still_runs() {
        assert_eq!(through_sh(&BTreeMap::new(), &["A=1", "x"]), b"");
        let env = BTreeMap::new();
        let argv = ["./a=b".to_owned()];
        let output = Shell::new("sh")
            .args(["-c", &line(&token(), "/", &env, &argv)])
            .output()
            .expect("sh runs");
        // The program is looked up, not taken as an assignment.
        assert!(String::from_utf8_lossy(&output.stderr).contains("a=b"));
    }

    #[test]
    fn a_program_or_variable_named_like_an_option_is_not_read_as_one() {
        // Read as `env -i`, this would run nothing and succeed.
        let argv = ["-i".to_owned()];
        let status = Shell::new("sh")
            .args(["-c", &line(&token(), "/", &BTreeMap::new(), &argv)])
            .status()
            .expect("sh runs");
        assert_eq!(status.code(), Some(127));
        let env = BTreeMap::from([("-i".to_owned(), "1".to_owned())]);
        assert_eq!(through_sh(&env, &["printf", "ran"]), b"ran");
    }
}
