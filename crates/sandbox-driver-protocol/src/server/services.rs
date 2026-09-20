//! `snapshot/*`, `volume/*`, `logs/follow`, and `stream/cancel`:
//! provider-level services and the cancellable log streams.

use std::collections::hash_map::Entry;
use std::future::Future;
use std::sync::Arc;

use sandbox_driver::{Capability, Error, Result, SnapshotId, VolumeId};
use serde_json::Value;
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit};
use tokio_util::sync::CancellationToken;

use super::exec::{SharedWriter, finish_channel, log_frame_sink};
use super::{DispatchError, ServerState, parse, to_value};
use crate::methods as m;

async fn follow_logs<F>(state: &ServerState, stream_id: &str, follow: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    let cancel = {
        let mut streams = state.streams.lock().expect("streams lock");
        match streams.entry(stream_id.to_owned()) {
            Entry::Vacant(entry) => {
                let cancel = CancellationToken::new();
                entry.insert(cancel.clone());
                cancel
            }
            // A cancel request can overtake the task that handles the
            // follow request. Reuse its already-cancelled token.
            Entry::Occupied(entry) => entry.get().clone(),
        }
    };
    let outcome = tokio::select! {
        outcome = follow => outcome,
        () = cancel.cancelled() => Ok(()),
    };
    state
        .streams
        .lock()
        .expect("streams lock")
        .remove(stream_id);
    outcome
}

pub(super) async fn dispatch(
    state: &Arc<ServerState>,
    method: &str,
    params: Value,
    io_permit: Option<Arc<OwnedSemaphorePermit>>,
) -> Result<Value, DispatchError> {
    match method {
        m::LOGS_FOLLOW => {
            let request: m::LogsFollowParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let logs = handle
                .logs()
                .ok_or_else(|| Error::unsupported(Capability::Logs))?;
            let channel = state.open_channel(&request.channel, io_permit).await?;
            let writer: SharedWriter = Arc::new(AsyncMutex::new(channel.writer));
            let outcome = follow_logs(
                state,
                &request.stream_id,
                logs.follow(request.source, log_frame_sink(&writer)),
            )
            .await;
            finish_channel(&writer).await?;
            outcome?;
            to_value(&m::Empty)
        }
        m::STREAM_CANCEL => {
            let request: m::StreamIdParams = parse(params)?;
            let cancel = {
                let mut streams = state.streams.lock().expect("streams lock");
                match streams.entry(request.stream_id) {
                    Entry::Occupied(entry) => entry.get().clone(),
                    Entry::Vacant(_) => return to_value(&m::Empty),
                }
            };
            cancel.cancel();
            to_value(&m::Empty)
        }
        m::SNAPSHOT_CREATE => {
            let request: m::SnapshotCreateParams = parse(params)?;
            let events = state.event_context(request.events);
            let spec = request.spec.into();
            let service =
                state
                    .provider
                    .snapshots()
                    .ok_or(DispatchError::App(Error::unsupported(
                        Capability::Snapshots,
                    )))?;
            let id = service.create(&spec, events).await?;
            to_value(&m::SnapshotIdResult {
                snapshot_id: id.as_str().to_owned(),
            })
        }
        m::SNAPSHOT_GET => {
            let request: m::SnapshotIdParams = parse(params)?;
            let service =
                state
                    .provider
                    .snapshots()
                    .ok_or(DispatchError::App(Error::unsupported(
                        Capability::Snapshots,
                    )))?;
            let id = SnapshotId::try_new(&request.snapshot_id)
                .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))?;
            let status = service.get(&id).await?;
            to_value(&m::SnapshotStatusResult { status })
        }
        m::SNAPSHOT_LIST => {
            let request: m::SnapshotListParams = parse(params)?;
            let service =
                state
                    .provider
                    .snapshots()
                    .ok_or(DispatchError::App(Error::unsupported(
                        Capability::Snapshots,
                    )))?;
            let snapshots = service.list(&request.filter).await?;
            to_value(&m::SnapshotListResult { snapshots })
        }
        m::SNAPSHOT_BUILD_LOGS => {
            let request: m::SnapshotBuildLogsParams = parse(params)?;
            let service = state
                .provider
                .snapshots()
                .ok_or_else(|| Error::unsupported(Capability::Snapshots))?;
            let id = SnapshotId::try_new(&request.snapshot_id)
                .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))?;
            let channel = state.open_channel(&request.channel, io_permit).await?;
            let writer: SharedWriter = Arc::new(AsyncMutex::new(channel.writer));
            let outcome = follow_logs(
                state,
                &request.stream_id,
                service.build_logs(&id, request.follow, log_frame_sink(&writer)),
            )
            .await;
            finish_channel(&writer).await?;
            outcome?;
            to_value(&m::Empty)
        }
        m::SNAPSHOT_DELETE | m::SNAPSHOT_ACTIVATE | m::SNAPSHOT_DEACTIVATE => {
            let request: m::SnapshotIdParams = parse(params)?;
            let events = state.event_context(request.events);
            let service =
                state
                    .provider
                    .snapshots()
                    .ok_or(DispatchError::App(Error::unsupported(
                        Capability::Snapshots,
                    )))?;
            let id = SnapshotId::try_new(&request.snapshot_id)
                .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))?;
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
            let service = state
                .provider
                .volumes()
                .ok_or(DispatchError::App(Error::unsupported(Capability::Volumes)))?;
            let id = service.create(&request.spec, events).await?;
            to_value(&m::VolumeIdResult {
                volume_id: id.as_str().to_owned(),
            })
        }
        m::VOLUME_GET => {
            let request: m::VolumeIdParams = parse(params)?;
            let service = state
                .provider
                .volumes()
                .ok_or(DispatchError::App(Error::unsupported(Capability::Volumes)))?;
            let id = VolumeId::try_new(&request.volume_id)
                .map_err(|error| Error::invalid_spec("volume_id", error.to_string()))?;
            let status = service.get(&id).await?;
            to_value(&m::VolumeStatusResult { status })
        }
        m::VOLUME_LIST => {
            let service = state
                .provider
                .volumes()
                .ok_or(DispatchError::App(Error::unsupported(Capability::Volumes)))?;
            let volumes = service.list().await?;
            to_value(&m::VolumeListResult { volumes })
        }
        m::VOLUME_DELETE => {
            let request: m::VolumeIdParams = parse(params)?;
            let events = state.event_context(request.events);
            let service = state
                .provider
                .volumes()
                .ok_or(DispatchError::App(Error::unsupported(Capability::Volumes)))?;
            let id = VolumeId::try_new(&request.volume_id)
                .map_err(|error| Error::invalid_spec("volume_id", error.to_string()))?;
            service.delete(&id, events).await?;
            to_value(&m::Empty)
        }
        _ => Err(DispatchError::UnknownMethod),
    }
}
