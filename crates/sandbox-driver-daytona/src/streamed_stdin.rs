//! Streamed stdin for session commands, over the toolbox's text-only input.
//!
//! The session input endpoint takes UTF-8 strings and cannot close a
//! command's stdin. A command with streamed stdin therefore reads it from
//! a Bash decoder instead of from the session. The driver sends ASCII
//! records through the input endpoint: `D` and `printf %b` escapes for
//! data, `E` for the end of input. The decoder writes the decoded bytes to
//! the program and exits on `E`, which closes the program's stdin, so
//! every byte value survives and the program sees a real EOF. A record
//! the decoder cannot read kills the program: corrupted input fails the
//! command rather than passing as a truncated stream.

use std::fmt::Write as _;
use std::future::pending;
use std::io;

use daytona_sdk::ProcessService;
use sandbox_driver::{Error, Result, StdinReader};
use tokio::io::AsyncReadExt as _;
use tokio::task::JoinHandle;

use crate::sdk::daytona_error;

/// Runs before the command, inside the session script's subshell. The
/// target is that subshell, which the command's `exec` becomes; Bash 3
/// has no `BASHPID`, and there `$$` names the session script instead.
/// A failed write means the program stopped reading its input, which is
/// not an error; the decoder then stops forwarding.
const DECODE_INPUT: &str = r#"sandbox_driver_target=${BASHPID:-$$}
sandbox_driver_decode() {
    local record
    while IFS= read -r record; do
        case $record in
            D*) printf '%b' "${record#D}" 2>/dev/null || return 0 ;;
            E) return 0 ;;
            *) printf 'sandbox-driver: malformed stdin record\n' >&2
               kill -KILL "$sandbox_driver_target" 2>/dev/null
               return 1 ;;
        esac
    done
}
exec 5<&0
"#;

/// The end-of-input record.
const END_RECORD: &str = "E\n";

/// Input bytes per data record. An escaped byte takes at most five
/// characters, so one record line stays bounded.
const RECORD_BYTES: usize = 4096;

/// Input bytes read for one input request. Each request costs a round
/// trip, so a request carries several records when the input is ready.
const REQUEST_BYTES: usize = 64 * 1024;

/// `command` (an [`crate::shell::exec_line`]) with its stdin read from the
/// decoder. The decoder holds the session's stdin on descriptor 5, which
/// the program does not inherit. Redirections apply left to right, so the
/// decoder starts before descriptor 5 closes.
pub(crate) fn decoded_command(command: &str) -> String {
    format!("{DECODE_INPUT}{command} < <(sandbox_driver_decode <&5) 5<&-")
}

/// Appends `bytes` as data records. Printable ASCII other than the
/// backslash passes through; every other byte becomes a `\0ooo` escape.
fn encode_records(bytes: &[u8], records: &mut String) {
    for chunk in bytes.chunks(RECORD_BYTES) {
        records.push('D');
        for &byte in chunk {
            if byte != b'\\' && (0x20..=0x7e).contains(&byte) {
                records.push(char::from(byte));
            } else {
                let _ = write!(records, "\\0{byte:03o}");
            }
        }
        records.push('\n');
    }
}

/// The task that forwards one command's streamed stdin, owned so it is
/// always ended explicitly: dropping a bare `JoinHandle` would only detach
/// the task.
#[derive(Default)]
pub(crate) struct InputPump(Option<JoinHandle<Result<()>>>);

impl InputPump {
    pub(crate) fn spawn(
        process: ProcessService,
        session_id: &str,
        command_id: &str,
        reader: StdinReader,
    ) -> Self {
        let session_id = session_id.to_owned();
        let command_id = command_id.to_owned();
        Self(Some(tokio::spawn(async move {
            forward(&process, &session_id, &command_id, reader).await
        })))
    }

    /// Resolves with the error that ended forwarding early. Delivered
    /// input, and input still flowing, never resolve.
    pub(crate) async fn failed(&mut self) -> Error {
        let Some(task) = self.0.as_mut() else {
            return pending().await;
        };
        let outcome = task.await;
        self.0 = None;
        match outcome {
            Ok(Ok(())) => pending().await,
            Ok(Err(error)) => error,
            Err(join_error) => Error::io("exec stdin forwarding", io::Error::other(join_error)),
        }
    }

    /// Ends forwarding once the command is done. Unwritten input is
    /// unwanted then.
    pub(crate) async fn stop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

async fn forward(
    process: &ProcessService,
    session_id: &str,
    command_id: &str,
    mut reader: StdinReader,
) -> Result<()> {
    let mut buffer = vec![0; REQUEST_BYTES];
    let mut records = String::new();
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|error| Error::io("reading exec stdin", error))?;
        records.clear();
        if read == 0 {
            records.push_str(END_RECORD);
        } else {
            encode_records(&buffer[..read], &mut records);
        }
        if let Err(error) = process
            .send_session_command_input(session_id, command_id, &records)
            .await
        {
            // A command that has ended takes no more input. Like a
            // closed pipe, that is not an error.
            if command_ended(process, session_id, command_id).await {
                return Ok(());
            }
            return Err(daytona_error("sending exec stdin", error));
        }
        if read == 0 {
            return Ok(());
        }
    }
}

async fn command_ended(process: &ProcessService, session_id: &str, command_id: &str) -> bool {
    process
        .get_session_command(session_id, command_id)
        .await
        .map_or(true, |command| command.exit_code.is_some())
}

#[cfg(test)]
mod tests {
    use std::process::Stdio;
    use std::time::Duration;

    use tokio::io::AsyncWriteExt as _;
    use tokio::process::Command;
    use tokio::time::timeout;

    use super::*;

    fn records(bytes: &[u8]) -> String {
        let mut records = String::new();
        encode_records(bytes, &mut records);
        records
    }

    #[test]
    fn printable_ascii_passes_and_every_other_byte_is_escaped() {
        assert_eq!(records(b"a b%~"), "Da b%~\n");
        assert_eq!(records(b"\\\n\0\xff"), "D\\0134\\0012\\0000\\0377\n");
    }

    #[test]
    fn long_input_is_split_into_bounded_records() {
        let encoded = records(&vec![b'x'; RECORD_BYTES + 1]);
        let lines: Vec<&str> = encoded.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].len(), RECORD_BYTES + 1);
        assert_eq!(lines[1], "Dx");
    }

    /// Runs `argv` behind the decoder in a local Bash, with `input`
    /// written to the decoder and the input channel left open, as a
    /// session's is.
    async fn run_decoded(argv: &str, input: &str) -> (Option<i32>, Vec<u8>) {
        let mut child = Command::new("/bin/bash")
            .args(["-c", &decoded_command(&format!("exec {argv}"))])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("bash");
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(input.as_bytes()).await.expect("records");
        let output = timeout(Duration::from_secs(10), child.wait_with_output())
            .await
            .expect("the command ends without its input channel closing")
            .expect("output");
        drop(stdin);
        (output.status.code(), output.stdout)
    }

    #[tokio::test]
    async fn every_byte_value_reaches_the_program_and_the_end_record_closes_its_stdin() {
        let bytes: Vec<u8> = (0..=255).collect();
        let mut input = records(&bytes);
        input.push_str(END_RECORD);
        let (status, stdout) = run_decoded("cat", &input).await;
        assert_eq!(status, Some(0));
        assert_eq!(stdout, bytes);
    }

    #[tokio::test]
    async fn a_program_that_stops_reading_is_not_disturbed() {
        let mut input = records(b"one\ntwo\n");
        input.push_str(&records(b"three\n"));
        input.push_str(END_RECORD);
        let (status, stdout) = run_decoded("head -1", &input).await;
        assert_eq!(status, Some(0));
        assert_eq!(stdout, b"one\n");
    }

    #[tokio::test]
    async fn a_malformed_record_kills_the_program() {
        let (status, _) = run_decoded("cat", "Dok\nXbad\n").await;
        assert_eq!(status, None, "killed by a signal, not exited");
    }
}
