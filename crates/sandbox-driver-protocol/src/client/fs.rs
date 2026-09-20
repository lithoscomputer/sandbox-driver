//! The filesystem facet: file contents ride a data channel, metadata
//! calls cross as plain requests.

use std::io;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use sandbox_driver::{
    DirEntry, Error, FileMetadata, Filesystem, Result, SandboxId, TransportError,
};
use tokio::fs as tokio_fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::Client;
use crate::channel::{self, Channel, FrameKind, WriteStall};
use crate::methods as m;

pub(super) struct SandboxFs {
    pub(super) client:     Arc<Client>,
    pub(super) sandbox_id: SandboxId,
}

impl SandboxFs {
    fn path_params(&self, path: &str) -> m::FsPathParams {
        m::FsPathParams {
            sandbox_id: self.sandbox_id.as_str().to_owned(),
            path:       path.to_owned(),
        }
    }

    async fn read_through_channel(
        &self,
        path: &str,
        offset: Option<u64>,
        length: Option<u64>,
        output: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<()> {
        let (channel, receiver) = self.client.listener.expect()?;
        let collect = |Channel { mut reader, .. }: Channel| async move {
            loop {
                match reader.read().await? {
                    Some((FrameKind::Stdout, payload)) => {
                        channel::write_with_progress(
                            output,
                            &payload,
                            self.client.limits.output_progress_timeout,
                        )
                        .await
                        .map_err(|stall| match stall {
                            WriteStall::Timeout => Error::Transport(TransportError::new(
                                "file output made no progress",
                            )),
                            WriteStall::Io(error) => Error::io("writing downloaded file", error),
                        })?;
                    }
                    Some((FrameKind::Eof, _)) | None => return Ok(()),
                    Some(_) => {
                        return Err(Error::invalid_spec(
                            "frame",
                            "unexpected frame on file output",
                        ));
                    }
                }
            }
        };
        let params = m::FsReadParams {
            sandbox_id: self.sandbox_id.as_str().to_owned(),
            path: path.to_owned(),
            channel,
            offset,
            length,
        };
        self.client
            .call_with_channel(
                m::FS_READ,
                self.client.call::<_, m::Empty>(m::FS_READ, &params),
                receiver,
                collect,
            )
            .await?;
        Ok(())
    }

    async fn write_through_channel(
        &self,
        path: &str,
        input: &mut (dyn AsyncRead + Unpin + Send),
        length: u64,
        append: bool,
    ) -> Result<()> {
        let (channel, receiver) = self.client.listener.expect()?;
        let send = |Channel { mut writer, .. }: Channel| async move {
            let mut input = input.take(length);
            let mut buffer = vec![0; 64 * 1024];
            loop {
                let read = input
                    .read(&mut buffer)
                    .await
                    .map_err(|error| Error::io("reading upload source", error))?;
                if read == 0 {
                    if input.limit() != 0 {
                        return Err(Error::io(
                            "reading upload source",
                            io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "source ended before its declared length",
                            ),
                        ));
                    }
                    break;
                }
                writer.write(FrameKind::Stdin, &buffer[..read]).await?;
            }
            writer.finish().await
        };
        let params = m::FsWriteParams {
            sandbox_id: self.sandbox_id.as_str().to_owned(),
            path: path.to_owned(),
            channel,
            append,
            content_length: Some(length),
        };
        self.client
            .call_with_channel(
                m::FS_WRITE,
                self.client.call::<_, m::Empty>(m::FS_WRITE, &params),
                receiver,
                send,
            )
            .await?;
        Ok(())
    }
}

#[async_trait]
impl Filesystem for SandboxFs {
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let mut content =
            sandbox_driver::BoundedBuffer::new(self.client.limits.buffered_value_bytes);
        let outcome = self.read_to(path, &mut content).await;
        content.finish(outcome)
    }

    async fn read_range(&self, path: &str, offset: u64, length: Option<u64>) -> Result<Vec<u8>> {
        let mut content =
            sandbox_driver::BoundedBuffer::new(self.client.limits.buffered_value_bytes);
        let outcome = self
            .read_through_channel(path, Some(offset), length, &mut content)
            .await;
        content.finish(outcome)
    }

    async fn write(&self, path: &str, mut content: &[u8]) -> Result<()> {
        let length = content.len() as u64;
        self.write_from(path, &mut content, length).await
    }

    async fn write_append(&self, path: &str, mut content: &[u8]) -> Result<()> {
        let length = content.len() as u64;
        self.write_through_channel(path, &mut content, length, true)
            .await
    }

    async fn read_to(
        &self,
        path: &str,
        output: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<()> {
        self.read_through_channel(path, None, None, output).await?;
        output
            .flush()
            .await
            .map_err(|error| Error::io("flushing file output", error))
    }

    async fn write_from(
        &self,
        path: &str,
        input: &mut (dyn AsyncRead + Unpin + Send),
        length: u64,
    ) -> Result<()> {
        self.write_through_channel(path, input, length, false).await
    }

    async fn delete(&self, path: &str, recursive: bool) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::FS_DELETE, &m::FsDeleteParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                path: path.to_owned(),
                recursive,
            })
            .await?;
        Ok(())
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        let result: m::FsExistsResult = self
            .client
            .call(m::FS_EXISTS, &self.path_params(path))
            .await?;
        Ok(result.exists)
    }

    async fn metadata(&self, path: &str) -> Result<FileMetadata> {
        let result: m::FsMetadataResult = self
            .client
            .call(m::FS_METADATA, &self.path_params(path))
            .await?;
        Ok(result.metadata)
    }

    async fn list_dir(&self, path: &str, depth: usize) -> Result<Vec<DirEntry>> {
        let result: m::FsListDirResult = self
            .client
            .call(m::FS_LIST_DIR, &m::FsListDirParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                path: path.to_owned(),
                depth,
            })
            .await?;
        Ok(result.entries)
    }

    async fn create_dir(&self, path: &str) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::FS_CREATE_DIR, &self.path_params(path))
            .await?;
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::FS_RENAME, &m::FsRenameParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                from:       from.to_owned(),
                to:         to.to_owned(),
            })
            .await?;
        Ok(())
    }

    async fn set_permissions(&self, path: &str, mode: u32) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::FS_SET_PERMISSIONS, &m::FsSetPermissionsParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                path: path.to_owned(),
                mode,
            })
            .await?;
        Ok(())
    }

    async fn upload(&self, local: &Path, remote: &str) -> Result<()> {
        let mut file = tokio_fs::File::open(local)
            .await
            .map_err(|error| Error::io(format!("reading {}", local.display()), error))?;
        let length = file
            .metadata()
            .await
            .map_err(|error| Error::io(format!("reading metadata of {}", local.display()), error))?
            .len();
        self.write_from(remote, &mut file, length).await
    }

    async fn download(&self, remote: &str, local: &Path) -> Result<()> {
        if let Some(parent) = local.parent() {
            tokio_fs::create_dir_all(parent).await.map_err(|error| {
                Error::io(format!("creating parent of {}", local.display()), error)
            })?;
        }
        let mut file = tokio_fs::File::create(local)
            .await
            .map_err(|error| Error::io(format!("writing {}", local.display()), error))?;
        self.read_to(remote, &mut file).await
    }
}
