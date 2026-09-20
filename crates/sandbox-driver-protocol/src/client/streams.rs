//! Cancellable log streams: `logs/follow` and `snapshot/build_logs`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sandbox_driver::{Error, LogSink, Result, TransportError};
use serde::Serialize;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time;

use super::Client;
use crate::channel::{Channel, ChannelReceiver, FrameKind};
use crate::methods as m;

struct StreamCancelGuard {
    permit:    Option<Arc<OwnedSemaphorePermit>>,
    client:    Arc<Client>,
    stream_id: String,
    armed:     bool,
}

impl Drop for StreamCancelGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let client = Arc::clone(&self.client);
        let stream_id = self.stream_id.clone();
        let permit = self.permit.take().expect("armed stream retains admission");
        self.client.own_cleanup(permit, async move {
            loop {
                match client
                    .call::<_, m::Empty>(m::STREAM_CANCEL, &m::StreamIdParams {
                        stream_id: stream_id.clone(),
                    })
                    .await
                {
                    Err(Error::Overloaded { .. }) => time::sleep(Duration::from_millis(1)).await,
                    outcome => return outcome.map(|_| ()),
                }
            }
        });
    }
}

/// Feeds a log channel to `sink` until the plugin's `Eof`. A sink error
/// ends the pump and is the caller's result.
async fn pump_log_channel(
    receiver: ChannelReceiver,
    accepted: Arc<AtomicBool>,
    sink: LogSink,
    timeout: Duration,
) -> Result<()> {
    let Channel { mut reader, .. } = receiver.accept().await?;
    accepted.store(true, Ordering::SeqCst);
    loop {
        match reader.read().await? {
            Some((FrameKind::Stdout | FrameKind::Stderr, payload)) => {
                time::timeout(timeout, sink(payload)).await.map_err(|_| {
                    Error::Transport(TransportError::new("log sink made no progress"))
                })??;
            }
            Some((FrameKind::Eof, _)) | None => return Ok(()),
            Some((kind, _)) => {
                return Err(Error::invalid_spec(
                    "frame",
                    format!("unexpected {kind:?} on a log channel"),
                ));
            }
        }
    }
}

pub(super) async fn follow_log_stream<P: Serialize>(
    client: &Arc<Client>,
    method: &str,
    params: &P,
    stream_id: &str,
    receiver: ChannelReceiver,
    sink: LogSink,
) -> Result<()> {
    let mut guard = StreamCancelGuard {
        permit:    Some(receiver.io_permit()),
        client:    Arc::clone(client),
        stream_id: stream_id.to_owned(),
        armed:     true,
    };
    let accepted = Arc::new(AtomicBool::new(false));
    let call = async {
        let outcome = client.call::<_, m::Empty>(method, params).await;
        guard.armed = false;
        outcome
    };
    client
        .pump(
            call,
            pump_log_channel(
                receiver,
                Arc::clone(&accepted),
                sink,
                client.limits.output_progress_timeout,
            ),
            &accepted,
            method,
        )
        .await?;
    Ok(())
}
