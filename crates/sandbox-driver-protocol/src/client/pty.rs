//! The PTY facet: a session whose input and output ride one data channel.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sandbox_driver::{
    Error, IncompleteOperation, Pty, PtyOptions, PtySession, PtySize, Result, SandboxId,
};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit};
use tokio::time;

use super::Client;
use crate::channel::{Channel, FrameKind, FrameReader, FrameWriter};
use crate::methods as m;

pub(super) struct SandboxPty {
    pub(super) client:     Arc<Client>,
    pub(super) sandbox_id: SandboxId,
}

#[async_trait]
impl Pty for SandboxPty {
    async fn open(&self, options: &PtyOptions) -> Result<Box<dyn PtySession>> {
        let pty_id = self.client.next_stream_id("pty");
        let (channel, receiver) = self.client.listener.expect()?;
        let permit = receiver.io_permit();
        let _: m::Empty = self
            .client
            .call(m::PTY_OPEN, &m::PtyOpenParams {
                sandbox_id: self.sandbox_id.as_str().to_owned(),
                pty_id: pty_id.clone(),
                channel,
                options: options.clone(),
            })
            .await?;
        let Channel { reader, writer } = receiver.accept_soon().await?;
        Ok(Box::new(RemotePtySession {
            client: Arc::clone(&self.client),
            permit: Mutex::new(Some(permit)),
            closed: AtomicBool::new(false),
            pty_id,
            reader: AsyncMutex::new(Some(reader)),
            writer: AsyncMutex::new(Some(writer)),
        }))
    }
}

struct RemotePtySession {
    permit: Mutex<Option<Arc<OwnedSemaphorePermit>>>,
    closed: AtomicBool,
    client: Arc<Client>,
    pty_id: String,
    reader: AsyncMutex<Option<FrameReader<OwnedReadHalf>>>,
    writer: AsyncMutex<Option<FrameWriter<OwnedWriteHalf>>>,
}

impl Drop for RemotePtySession {
    fn drop(&mut self) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let permit = self
            .permit
            .get_mut()
            .expect("PTY permit lock")
            .take()
            .expect("PTY retains admission");
        let client = Arc::clone(&self.client);
        let pty_id = self.pty_id.clone();
        self.client.own_cleanup(permit, async move {
            client
                .cleanup_call(m::PTY_CLOSE, &m::PtyIdParams { pty_id })
                .await
        });
    }
}

#[async_trait]
impl PtySession for RemotePtySession {
    async fn write_input(&self, bytes: &[u8]) -> Result<()> {
        self.writer
            .lock()
            .await
            .as_mut()
            .ok_or_else(|| Error::invalid_spec("pty", "session is closed"))?
            .write(FrameKind::Stdin, bytes)
            .await
    }

    async fn read_output(&self) -> Result<Option<Vec<u8>>> {
        let mut reader = self.reader.lock().await;
        let Some(reader) = reader.as_mut() else {
            return Ok(None);
        };
        match reader.read().await? {
            Some((FrameKind::Stdout | FrameKind::Stderr, payload)) => Ok(Some(payload)),
            Some((FrameKind::Eof, _)) | None => Ok(None),
            Some((kind, _)) => Err(Error::invalid_spec(
                "frame",
                format!("unexpected {kind:?} on PTY output"),
            )),
        }
    }

    async fn resize(&self, size: PtySize) -> Result<()> {
        let _: m::Empty = self
            .client
            .call(m::PTY_RESIZE, &m::PtyResizeParams {
                pty_id: self.pty_id.clone(),
                size,
            })
            .await?;
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        time::timeout(self.client.limits.hard_cancel_drain_timeout, async {
            self.client
                .cleanup_call(m::PTY_CLOSE, &m::PtyIdParams {
                    pty_id: self.pty_id.clone(),
                })
                .await?;
            self.reader.lock().await.take();
            self.writer.lock().await.take();
            self.permit.lock().expect("PTY permit lock").take();
            self.closed.store(true, Ordering::SeqCst);
            Ok::<_, Error>(())
        })
        .await
        .map_err(|_| Error::Incomplete(IncompleteOperation::new("PTY close")))?
    }
}
