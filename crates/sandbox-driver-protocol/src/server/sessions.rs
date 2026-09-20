//! `exec/stdio_*` and `pty/*`: long-lived processes and terminals the
//! plugin holds for the host between requests.

use std::sync::Arc;

use sandbox_driver::{Capability, Error, Result, StderrTail, StdioProcessHandle};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::OwnedSemaphorePermit;

use super::{DispatchError, ServerState, parse, to_value};
use crate::channel::{Channel, FrameKind};
use crate::methods as m;

/// A spawned stdio process the plugin holds for the host: its control
/// handle and the stderr tail the host reads back at `wait`.
pub(super) struct ServerStdio {
    pub(super) handle:      Arc<dyn StdioProcessHandle>,
    pub(super) stderr_tail: StderrTail,
    _permit:                Option<Arc<OwnedSemaphorePermit>>,
}

pub(super) struct ServerPty {
    pub(super) session: Arc<dyn sandbox_driver::PtySession>,
    _permit:            Option<Arc<OwnedSemaphorePermit>>,
}

fn stdio(state: &ServerState, id: &str) -> Result<Arc<ServerStdio>> {
    state
        .stdios
        .get(id)
        .ok_or_else(|| Error::invalid_spec("process_id", "unknown stdio process id"))
}

fn pty(state: &ServerState, id: &str) -> Result<Arc<dyn sandbox_driver::PtySession>> {
    state
        .ptys
        .get(id)
        .map(|entry| Arc::clone(&entry.session))
        .ok_or_else(|| Error::invalid_spec("pty_id", "unknown PTY id"))
}

pub(super) async fn dispatch(
    state: &Arc<ServerState>,
    method: &str,
    params: Value,
    io_permit: Option<Arc<OwnedSemaphorePermit>>,
) -> Result<Value, DispatchError> {
    match method {
        m::EXEC_STDIO_OPEN => {
            let request: m::StdioOpenParams = parse(params)?;
            let channel = state
                .open_channel(&request.channel, io_permit.clone())
                .await?;
            let process = state
                .sandbox(&request.sandbox_id)
                .await?
                .exec()
                .spawn_stdio(&request.spec)
                .await?;
            let handle: Arc<dyn StdioProcessHandle> = Arc::from(process.handle);
            let registered = state.stdios.try_insert(
                request.process_id.clone(),
                Arc::new(ServerStdio {
                    handle:      Arc::clone(&handle),
                    stderr_tail: process.stderr_tail,
                    _permit:     io_permit.clone(),
                }),
            );
            if registered.is_err() {
                handle.terminate().await;
                return Err(Error::invalid_spec("process_id", "duplicate stdio process id").into());
            }
            let Channel { mut reader, writer } = channel;
            let mut stdin = process.stdin;
            state.own(async move {
                // Anything but an input frame — the host's eof, a closed
                // connection, a stray kind — ends the process's stdin.
                while let Some(payload) = reader.next_stdin().await {
                    if stdin.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                let _ = stdin.shutdown().await;
            });
            let mut stdout = process.stdout;
            state.own(async move {
                let mut writer = writer;
                let mut buffer = vec![0; 32 * 1024];
                loop {
                    match stdout.read(&mut buffer).await {
                        Ok(0) => break,
                        Err(_) => return,
                        Ok(read) => {
                            if writer
                                .write(FrameKind::Stdout, &buffer[..read])
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                }
                let _ = writer.finish().await;
            });
            to_value(&m::Empty)
        }
        m::EXEC_STDIO_TERMINATE => {
            let request: m::StdioIdParams = parse(params)?;
            stdio(state, &request.process_id)?.handle.terminate().await;
            to_value(&m::Empty)
        }
        m::EXEC_STDIO_WAIT => {
            let request: m::StdioIdParams = parse(params)?;
            let process = stdio(state, &request.process_id)?;
            let (termination, exit_code) = process.handle.wait().await;
            state.stdios.remove(&request.process_id);
            to_value(&m::StdioWaitResult {
                termination,
                exit_code,
                stderr_tail: process.stderr_tail.to_string_lossy(),
            })
        }
        m::PTY_OPEN => {
            let request: m::PtyOpenParams = parse(params)?;
            let channel = state
                .open_channel(&request.channel, io_permit.clone())
                .await?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let pty = handle
                .pty()
                .ok_or_else(|| Error::unsupported(Capability::Pty))?
                .open(&request.options)
                .await?;
            let pty: Arc<dyn sandbox_driver::PtySession> = Arc::from(pty);
            let registered = state.ptys.try_insert(
                request.pty_id.clone(),
                Arc::new(ServerPty {
                    session: Arc::clone(&pty),
                    _permit: io_permit.clone(),
                }),
            );
            if registered.is_err() {
                if let Err(error) = pty.close().await {
                    tracing::warn!(error = %error, "duplicate plugin PTY cleanup failed");
                }
                return Err(Error::invalid_spec("pty_id", "duplicate PTY id").into());
            }
            let Channel { mut reader, writer } = channel;
            let input_pty = Arc::clone(&pty);
            state.own(async move {
                while let Some(payload) = reader.next_stdin().await {
                    if input_pty.write_input(&payload).await.is_err() {
                        break;
                    }
                }
            });
            let output_pty = Arc::clone(&pty);
            state.own(async move {
                let mut writer = writer;
                loop {
                    match output_pty.read_output().await {
                        Ok(Some(chunk)) => {
                            if writer.write(FrameKind::Stdout, &chunk).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(_) => return,
                    }
                }
                let _ = writer.finish().await;
            });
            to_value(&m::Empty)
        }
        m::PTY_RESIZE => {
            let request: m::PtyResizeParams = parse(params)?;
            pty(state, &request.pty_id)?.resize(request.size).await?;
            to_value(&m::Empty)
        }
        m::PTY_CLOSE => {
            let request: m::PtyIdParams = parse(params)?;
            if let Some(session) = state.ptys.remove(&request.pty_id) {
                if let Err(error) = session.session.close().await {
                    state.ptys.insert(request.pty_id, session);
                    return Err(error.into());
                }
            }
            to_value(&m::Empty)
        }
        _ => Err(DispatchError::UnknownMethod),
    }
}
