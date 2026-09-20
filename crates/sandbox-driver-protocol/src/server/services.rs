//! `snapshot/*`, `volume/*`, `logs/follow`, and `stream/cancel`:
//! provider-level services and the cancellable log streams.

use std::future::Future;
use std::sync::Arc;

use sandbox_driver::{Capability, Error, Result};
use serde_json::Value;
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit};
use tokio_util::sync::CancellationToken;

use super::exec::{SharedWriter, finish_channel, log_frame_sink};
use super::{DispatchError, ServerState, parse, snapshot_id, to_value, volume_id};
use crate::methods as m;

/// A log stream the host can cancel by id. Registering precedes the
/// follow request's task, so a `stream/cancel` that overtakes the follow
/// finds the token already there; `Drop` removes the entry on every exit,
/// including a request that fails before it follows anything.
pub(super) struct StreamRegistration {
    state:  Arc<ServerState>,
    id:     String,
    cancel: CancellationToken,
}

impl StreamRegistration {
    /// Claims `id` for one stream, or rejects a second stream under it.
    pub(super) fn register(state: &Arc<ServerState>, id: String) -> Result<Self> {
        let cancel = state.exec_shutdown.child_token();
        state
            .streams
            .try_insert(id.clone(), cancel.clone())
            .map_err(|_| Error::invalid_spec("stream_id", "duplicate stream id"))?;
        Ok(Self {
            state: Arc::clone(state),
            id,
            cancel,
        })
    }

    /// Runs `follow` until it ends or the host cancels the stream, which
    /// is not an error.
    async fn follow<F>(self, follow: F) -> Result<()>
    where
        F: Future<Output = Result<()>>,
    {
        tokio::select! {
            outcome = follow => outcome,
            () = self.cancel.cancelled() => Ok(()),
        }
    }
}

impl Drop for StreamRegistration {
    fn drop(&mut self) {
        self.state.streams.remove(&self.id);
    }
}

fn registered(stream: Option<StreamRegistration>) -> Result<StreamRegistration> {
    stream.ok_or_else(|| Error::invalid_spec("stream_id", "missing stream id"))
}

pub(super) async fn dispatch(
    state: &Arc<ServerState>,
    method: &str,
    params: Value,
    io_permit: Option<Arc<OwnedSemaphorePermit>>,
    stream: Option<StreamRegistration>,
) -> Result<Value, DispatchError> {
    match method {
        m::LOGS_FOLLOW => {
            let request: m::LogsFollowParams = parse(params)?;
            let stream = registered(stream)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let logs = handle
                .logs()
                .ok_or_else(|| Error::unsupported(Capability::Logs))?;
            let channel = state.open_channel(&request.channel, io_permit).await?;
            let writer: SharedWriter = Arc::new(AsyncMutex::new(channel.writer));
            let outcome = stream
                .follow(logs.follow(request.source, log_frame_sink(&writer)))
                .await;
            finish_channel(&writer).await?;
            outcome?;
            to_value(&m::Empty)
        }
        m::STREAM_CANCEL => {
            let request: m::StreamIdParams = parse(params)?;
            if let Some(cancel) = state.streams.get(&request.stream_id) {
                cancel.cancel();
            }
            to_value(&m::Empty)
        }
        m::SNAPSHOT_CREATE => {
            let request: m::SnapshotCreateParams = parse(params)?;
            let events = state.event_context(request.events);
            let spec = request.spec.into();
            let service = state.snapshots()?;
            let id = service.create(&spec, events).await?;
            to_value(&m::SnapshotIdResult {
                snapshot_id: id.as_str().to_owned(),
            })
        }
        m::SNAPSHOT_GET => {
            let request: m::SnapshotIdParams = parse(params)?;
            let service = state.snapshots()?;
            let id = snapshot_id(&request.snapshot_id)?;
            let status = service.get(&id).await?;
            to_value(&m::SnapshotStatusResult { status })
        }
        m::SNAPSHOT_LIST => {
            let request: m::SnapshotListParams = parse(params)?;
            let service = state.snapshots()?;
            let snapshots = service.list(&request.filter).await?;
            to_value(&m::SnapshotListResult { snapshots })
        }
        m::SNAPSHOT_BUILD_LOGS => {
            let request: m::SnapshotBuildLogsParams = parse(params)?;
            let stream = registered(stream)?;
            let service = state.snapshots()?;
            let id = snapshot_id(&request.snapshot_id)?;
            let channel = state.open_channel(&request.channel, io_permit).await?;
            let writer: SharedWriter = Arc::new(AsyncMutex::new(channel.writer));
            let outcome = stream
                .follow(service.build_logs(&id, request.follow, log_frame_sink(&writer)))
                .await;
            finish_channel(&writer).await?;
            outcome?;
            to_value(&m::Empty)
        }
        m::SNAPSHOT_DELETE | m::SNAPSHOT_ACTIVATE | m::SNAPSHOT_DEACTIVATE => {
            let request: m::SnapshotIdParams = parse(params)?;
            let events = state.event_context(request.events);
            let service = state.snapshots()?;
            let id = snapshot_id(&request.snapshot_id)?;
            match method {
                m::SNAPSHOT_ACTIVATE => service.activate(&id, events).await?,
                m::SNAPSHOT_DEACTIVATE => service.deactivate(&id, events).await?,
                _ => service.delete(&id, events).await?,
            }
            to_value(&m::Empty)
        }
        m::VOLUME_CREATE => {
            let request: m::VolumeCreateParams = parse(params)?;
            let events = state.event_context(request.events);
            let service = state.volumes()?;
            let id = service.create(&request.spec, events).await?;
            to_value(&m::VolumeIdResult {
                volume_id: id.as_str().to_owned(),
            })
        }
        m::VOLUME_GET => {
            let request: m::VolumeIdParams = parse(params)?;
            let service = state.volumes()?;
            let id = volume_id(&request.volume_id)?;
            let status = service.get(&id).await?;
            to_value(&m::VolumeStatusResult { status })
        }
        m::VOLUME_LIST => {
            let service = state.volumes()?;
            let volumes = service.list().await?;
            to_value(&m::VolumeListResult { volumes })
        }
        m::VOLUME_DELETE => {
            let request: m::VolumeIdParams = parse(params)?;
            let events = state.event_context(request.events);
            let service = state.volumes()?;
            let id = volume_id(&request.volume_id)?;
            service.delete(&id, events).await?;
            to_value(&m::Empty)
        }
        _ => Err(DispatchError::UnknownMethod),
    }
}
