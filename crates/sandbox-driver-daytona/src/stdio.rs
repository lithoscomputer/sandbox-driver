//! Long-lived bidirectional stdio processes over command sessions.
//!
//! The toolbox has no raw byte pipes for session commands: stdin crosses
//! as UTF-8 strings through the session input endpoint, and streamed
//! logs arrive as UTF-8 text (lossily decoded by the SDK's demux). That
//! makes this transport **UTF-8 only** — exactly right for the ACP
//! backends the facet exists for (newline-delimited JSON both ways), and
//! wrong for arbitrary binary streams. Stdin bytes that are not valid
//! UTF-8 close the pipe rather than corrupting the stream, and there is
//! no way to signal stdin EOF (ACP never needs one; a workload that does
//! belongs on [`crate::DaytonaExec`]'s one-shot stdin).

use std::str;
use std::sync::Arc;
use std::time::Duration;

use daytona_sdk::DaytonaError;
use sandbox_driver::{
    Result, SpawnSpec, StderrTail, StdioProcess, StdioProcessHandle, Termination,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time;

use crate::exec::{build_session_script, wrap_session_script};
use crate::session::Session;
use crate::{DaytonaClient, daytona_error};

/// Buffered bytes per stdio pipe.
const PIPE_CAPACITY: usize = 64 * 1024;
/// Poll interval for the command's exit code.
const STATUS_POLL: Duration = Duration::from_millis(250);

pub(crate) async fn spawn(
    client: &DaytonaClient,
    sandbox_id: &str,
    cwd: &str,
    spec: &SpawnSpec,
) -> Result<StdioProcess> {
    let sandbox = client
        .get(sandbox_id)
        .await
        .map_err(|error| daytona_error("fetching sandbox", error))?;

    let mut session = Session::create(&sandbox).await?;
    let program = wrap_session_script(&build_session_script(cwd, &spec.env, &spec.command));
    let started = match session.execute(&program).await {
        Ok(result) => result,
        Err(error) => {
            session.close().await;
            return Err(error);
        }
    };
    let command_id = started.cmd_id;

    let stream_process = match sandbox.process().await {
        Ok(process) => process,
        Err(error) => {
            session.close().await;
            return Err(daytona_error("connecting to the toolbox", error));
        }
    };
    let input_process = match sandbox.process().await {
        Ok(process) => process,
        Err(error) => {
            session.close().await;
            return Err(daytona_error("connecting to the toolbox", error));
        }
    };

    // Stdout: the log stream's stdout side feeds one half of a local
    // pipe; the caller reads the other half. Stderr is the bounded
    // diagnostic tail from the facet contract, not a stream.
    let (stdout_into, stdout_reader) = duplex(PIPE_CAPACITY);
    let stderr_tail = StderrTail::default();
    let stream_task = tokio::spawn({
        let session_id = session.id().to_owned();
        let command_id = command_id.clone();
        let stdout_into = Arc::new(Mutex::new(stdout_into));
        let stderr_tail = stderr_tail.clone();
        async move {
            let _ = stream_process
                .get_session_command_logs_stream(
                    &session_id,
                    &command_id,
                    move |chunk: String| {
                        let stdout_into = Arc::clone(&stdout_into);
                        async move {
                            // A closed reader means the caller dropped
                            // stdout; drain silently so control flow
                            // (exit polling) is unaffected.
                            let _ = stdout_into.lock().await.write_all(chunk.as_bytes()).await;
                            Ok::<_, DaytonaError>(())
                        }
                    },
                    move |chunk: String| {
                        let stderr_tail = stderr_tail.clone();
                        async move {
                            stderr_tail.push(chunk.as_bytes());
                            Ok::<_, DaytonaError>(())
                        }
                    },
                )
                .await;
            // Dropping the writer half delivers EOF to the reader.
        }
    });

    // Stdin: the caller writes bytes into a local pipe; a pump forwards
    // complete UTF-8 prefixes through the session input endpoint,
    // holding back a split multi-byte character until its remainder
    // arrives. Invalid UTF-8 ends the pump (the caller's next write
    // fails with a closed pipe) instead of corrupting the stream.
    let (stdin_writer, mut stdin_reader) = duplex(PIPE_CAPACITY);
    let stdin_task = tokio::spawn({
        let session_id = session.id().to_owned();
        let command_id = command_id.clone();
        async move {
            let mut pending: Vec<u8> = Vec::new();
            let mut buffer = vec![0u8; PIPE_CAPACITY];
            loop {
                let read = match stdin_reader.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => read,
                };
                pending.extend_from_slice(&buffer[..read]);
                let valid_up_to = match str::from_utf8(&pending) {
                    Ok(_) => pending.len(),
                    Err(error) => {
                        if error.error_len().is_some() {
                            // Genuinely invalid bytes, not a split
                            // character: refuse rather than corrupt.
                            break;
                        }
                        error.valid_up_to()
                    }
                };
                if valid_up_to == 0 {
                    continue;
                }
                let data = String::from_utf8_lossy(&pending[..valid_up_to]).into_owned();
                pending.drain(..valid_up_to);
                if input_process
                    .send_session_command_input(&session_id, &command_id, &data)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    });

    let handle = DaytonaStdioHandle {
        session: Mutex::new(session),
        command_id,
        stream_task: Mutex::new(Some(stream_task)),
        stdin_task: Mutex::new(Some(stdin_task)),
    };

    Ok(StdioProcess {
        stdin: Box::pin(stdin_writer),
        stdout: Box::pin(stdout_reader),
        stderr_tail,
        handle: Box::new(handle),
    })
}

struct DaytonaStdioHandle {
    session:     Mutex<Session>,
    command_id:  String,
    stream_task: Mutex<Option<JoinHandle<()>>>,
    stdin_task:  Mutex<Option<JoinHandle<()>>>,
}

impl DaytonaStdioHandle {
    async fn abort_pumps(&self) {
        if let Some(task) = self.stdin_task.lock().await.take() {
            task.abort();
        }
        if let Some(mut task) = self.stream_task.lock().await.take() {
            // Give the log stream a moment to drain naturally — the
            // session deletion closes it server-side — then abort.
            if time::timeout(Duration::from_secs(2), &mut task)
                .await
                .is_err()
            {
                task.abort();
            }
        }
    }
}

#[async_trait::async_trait]
impl StdioProcessHandle for DaytonaStdioHandle {
    async fn terminate(&self) {
        // Deleting the session kills the command and closes its streams.
        self.session.lock().await.close().await;
        self.abort_pumps().await;
    }

    async fn wait(&self) -> (Termination, Option<i32>) {
        loop {
            let polled = {
                let session = self.session.lock().await;
                session.exit_code(&self.command_id).await
            };
            match polled {
                Ok(Some(code)) => {
                    self.abort_pumps().await;
                    return (Termination::Exited, Some(code));
                }
                Ok(None) => {}
                // The session is gone — terminate() ran, or the sandbox
                // dropped it.
                Err(_) => {
                    self.abort_pumps().await;
                    return (Termination::Killed, None);
                }
            }
            time::sleep(STATUS_POLL).await;
        }
    }
}
