//! `fs/*`: file transfer through a data channel and the metadata calls.

use std::io;
use std::sync::Arc;

use sandbox_driver::{Error, Filesystem, Result};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::OwnedSemaphorePermit;

use super::exec::collect_stdin_frames;
use super::{DispatchError, ServerState, parse, to_value};
use crate::channel::{FrameKind, FrameReader, FrameWriter};
use crate::methods as m;

/// Moves a file through the channel with one bounded pipe between the
/// provider and frame writer. Neither future outlives this operation.
async fn send_file(
    fs: &dyn Filesystem,
    path: &str,
    writer: &mut FrameWriter<OwnedWriteHalf>,
) -> Result<()> {
    let (mut pipe_writer, mut pipe_reader) = duplex(64 * 1024);
    let produce = async move {
        fs.read_to(path, &mut pipe_writer).await?;
        pipe_writer
            .shutdown()
            .await
            .map_err(|error| Error::io("closing file stream", error))
    };
    let send = async {
        let mut buffer = vec![0; 64 * 1024];
        loop {
            let read = pipe_reader
                .read(&mut buffer)
                .await
                .map_err(|error| Error::io("reading file stream", error))?;
            if read == 0 {
                return Ok(());
            }
            writer.write(FrameKind::Stdout, &buffer[..read]).await?;
        }
    };
    tokio::try_join!(produce, send)?;
    Ok(())
}

async fn receive_file(
    reader: &mut FrameReader<OwnedReadHalf>,
    output: &mut (dyn AsyncWrite + Unpin + Send),
    length: u64,
) -> Result<()> {
    let mut remaining = length;
    loop {
        match reader.read().await? {
            Some((FrameKind::Stdin, payload)) => {
                remaining = remaining.checked_sub(payload.len() as u64).ok_or_else(|| {
                    Error::invalid_spec("content_length", "file exceeds its declared length")
                })?;
                output
                    .write_all(&payload)
                    .await
                    .map_err(|error| Error::io("writing file stream", error))?;
            }
            Some((FrameKind::Eof, _)) | None => {
                if remaining != 0 {
                    return Err(Error::io(
                        "reading file stream",
                        io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "file ended before its declared length",
                        ),
                    ));
                }
                return Ok(());
            }
            Some((kind, _)) => {
                return Err(Error::invalid_spec(
                    "frame",
                    format!("unexpected {kind:?} frame on a write channel"),
                ));
            }
        }
    }
}

async fn write_file(
    fs: &dyn Filesystem,
    path: &str,
    reader: &mut FrameReader<OwnedReadHalf>,
    length: u64,
) -> Result<()> {
    let (mut pipe_writer, mut pipe_reader) = duplex(64 * 1024);
    let receive = async move {
        receive_file(reader, &mut pipe_writer, length).await?;
        pipe_writer
            .shutdown()
            .await
            .map_err(|error| Error::io("closing file stream", error))
    };
    tokio::try_join!(fs.write_from(path, &mut pipe_reader, length), receive)?;
    Ok(())
}

pub(super) async fn dispatch(
    state: &Arc<ServerState>,
    method: &str,
    params: Value,
    io_permit: Option<Arc<OwnedSemaphorePermit>>,
) -> Result<Value, DispatchError> {
    match method {
        m::FS_READ => {
            let request: m::FsReadParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let mut channel = state.open_channel(&request.channel, io_permit).await?;
            let outcome = async {
                if request.offset.is_some() || request.length.is_some() {
                    let content = handle
                        .fs()
                        .read_range(&request.path, request.offset.unwrap_or(0), request.length)
                        .await?;
                    channel.writer.write(FrameKind::Stdout, &content).await
                } else {
                    send_file(handle.fs(), &request.path, &mut channel.writer).await
                }
            }
            .await;
            let finished = channel.writer.finish().await;
            outcome?;
            finished?;
            to_value(&m::Empty)
        }
        m::FS_WRITE => {
            let request: m::FsWriteParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let mut channel = state.open_channel(&request.channel, io_permit).await?;
            let outcome = if let Some(length) = request.content_length.filter(|_| !request.append) {
                write_file(handle.fs(), &request.path, &mut channel.reader, length).await
            } else {
                let content = if let Some(length) = request.content_length {
                    if length > state.limits.buffered_value_bytes as u64 {
                        return Err(Error::LimitExceeded {
                            limit:     "buffered_value_bytes".into(),
                            max_bytes: state.limits.buffered_value_bytes,
                        }
                        .into());
                    }
                    let mut content = Vec::new();
                    receive_file(&mut channel.reader, &mut content, length).await?;
                    content
                } else {
                    collect_stdin_frames(&mut channel.reader, state.limits.buffered_value_bytes)
                        .await?
                };
                if request.append {
                    handle.fs().write_append(&request.path, &content).await
                } else {
                    handle.fs().write(&request.path, &content).await
                }
            };
            let _ = channel.writer.finish().await;
            outcome?;
            to_value(&m::Empty)
        }
        m::FS_DELETE => {
            let request: m::FsDeleteParams = parse(params)?;
            state
                .sandbox(&request.sandbox_id)
                .await?
                .fs()
                .delete(&request.path, request.recursive)
                .await?;
            to_value(&m::Empty)
        }
        m::FS_EXISTS => {
            let request: m::FsPathParams = parse(params)?;
            let exists = state
                .sandbox(&request.sandbox_id)
                .await?
                .fs()
                .exists(&request.path)
                .await?;
            to_value(&m::FsExistsResult { exists })
        }
        m::FS_METADATA => {
            let request: m::FsPathParams = parse(params)?;
            let metadata = state
                .sandbox(&request.sandbox_id)
                .await?
                .fs()
                .metadata(&request.path)
                .await?;
            to_value(&m::FsMetadataResult { metadata })
        }
        m::FS_LIST_DIR => {
            let request: m::FsListDirParams = parse(params)?;
            let entries = state
                .sandbox(&request.sandbox_id)
                .await?
                .fs()
                .list_dir(&request.path, request.depth)
                .await?;
            to_value(&m::FsListDirResult { entries })
        }
        m::FS_CREATE_DIR => {
            let request: m::FsPathParams = parse(params)?;
            state
                .sandbox(&request.sandbox_id)
                .await?
                .fs()
                .create_dir(&request.path)
                .await?;
            to_value(&m::Empty)
        }
        m::FS_RENAME => {
            let request: m::FsRenameParams = parse(params)?;
            state
                .sandbox(&request.sandbox_id)
                .await?
                .fs()
                .rename(&request.from, &request.to)
                .await?;
            to_value(&m::Empty)
        }
        m::FS_SET_PERMISSIONS => {
            let request: m::FsSetPermissionsParams = parse(params)?;
            state
                .sandbox(&request.sandbox_id)
                .await?
                .fs()
                .set_permissions(&request.path, request.mode)
                .await?;
            to_value(&m::Empty)
        }
        _ => Err(DispatchError::UnknownMethod),
    }
}

#[cfg(test)]
mod file_transfer_tests {
    use tokio::net::UnixStream;

    use super::*;
    use crate::channel;

    #[tokio::test]
    async fn write_channel_enforces_the_declared_content_length() {
        for length in [0, 4, 5, 6] {
            let (host, plugin) = UnixStream::pair().expect("channel");
            let (_, host_write) = host.into_split();
            let (plugin_read, _) = plugin.into_split();
            let mut writer = FrameWriter::new(host_write, channel::MAX_FRAME_BYTES);
            let mut reader = FrameReader::new(plugin_read, channel::MAX_FRAME_BYTES);
            writer
                .write(FrameKind::Stdin, b"bytes")
                .await
                .expect("content");
            writer.finish().await.expect("end of content");
            let mut content = Vec::new();
            let outcome = receive_file(&mut reader, &mut content, length).await;
            match length {
                5 => {
                    outcome.expect("exact content length");
                    assert_eq!(content, b"bytes");
                }
                6 => assert!(matches!(outcome, Err(Error::Io { source, .. })
                    if source.kind() == io::ErrorKind::UnexpectedEof)),
                _ => assert!(matches!(outcome, Err(Error::InvalidSpec { field, .. })
                    if field == "content_length")),
            }
        }
    }
}
