//! `sandbox/*`: creation, attach, lifecycle actions, and per-sandbox
//! settings.

use std::sync::Arc;

use sandbox_driver::{Sandbox, SandboxSpec, SandboxStatus};
use serde_json::Value;

use super::{DispatchError, ServerState, parse, sandbox_id, to_value};
use crate::methods as m;

fn handle_info(handle: &Arc<dyn Sandbox>, status: SandboxStatus) -> m::HandleInfo {
    m::HandleInfo {
        status,
        capabilities: handle.capabilities().clone(),
        working_directory: handle.working_directory().to_owned(),
        runtime_directory: handle.runtime_directory().map(str::to_owned),
    }
}

pub(super) async fn dispatch(
    state: &Arc<ServerState>,
    method: &str,
    params: Value,
) -> Result<Value, DispatchError> {
    match method {
        m::SANDBOX_CREATE => {
            let request: m::CreateParams = parse(params)?;
            let events = state.event_context(request.events);
            let spec = SandboxSpec::try_from(request.spec)?;
            let handle = state.provider.create(&spec, events).await?;
            state.remember(&handle);
            let status = handle.describe().await?;
            to_value(&handle_info(&handle, status))
        }
        m::SANDBOX_ATTACH => {
            let request: m::AttachParams = parse(params)?;
            let id = sandbox_id(&request.sandbox_id)?;
            let events = state.event_context(request.events);
            let handle = state.provider.attach(&id, events).await?;
            state.remember(&handle);
            let status = handle.describe().await?;
            to_value(&handle_info(&handle, status))
        }
        m::SANDBOX_LIST => {
            let request: m::ListParams = parse(params)?;
            let sandboxes = state.provider.list(&request.filter).await?;
            to_value(&m::ListResult { sandboxes })
        }
        m::SANDBOX_DESCRIBE => {
            let request: m::SandboxIdParams = parse(params)?;
            let status = state.sandbox(&request.sandbox_id).await?.describe().await?;
            to_value(&m::StatusResult { status })
        }
        m::SANDBOX_PLATFORM_INFO => {
            let request: m::SandboxIdParams = parse(params)?;
            let platform = state
                .sandbox(&request.sandbox_id)
                .await?
                .platform_info()
                .await?;
            to_value(&m::PlatformInfoResult { platform })
        }
        m::SANDBOX_ENVIRONMENT => {
            let request: m::SandboxIdParams = parse(params)?;
            let environment = state
                .sandbox(&request.sandbox_id)
                .await?
                .environment()
                .await?;
            to_value(&m::EnvironmentResult { environment })
        }
        m::SANDBOX_DELETE => {
            // Delete is a provider-level operation by id: no prior attach is
            // needed, and a sandbox no handle can be built for (stopped,
            // wedged, half-created) is still removed. A handle this
            // connection already holds is used so its event route sees the
            // delete.
            let request: m::AttachParams = parse(params)?;
            let remembered = state.handles.get(&request.sandbox_id);
            if let Some(handle) = remembered {
                handle.delete().await?;
            } else {
                let id = sandbox_id(&request.sandbox_id)?;
                let events = state.event_context(request.events);
                state.provider.delete(&id, events).await?;
            }
            state.handles.remove(&request.sandbox_id);
            to_value(&m::Empty)
        }
        m::SANDBOX_START
        | m::SANDBOX_STOP
        | m::SANDBOX_PAUSE
        | m::SANDBOX_RESUME
        | m::SANDBOX_ARCHIVE
        | m::SANDBOX_RECOVER
        | m::SANDBOX_REFRESH_ACTIVITY => {
            let request: m::SandboxIdParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            match method {
                m::SANDBOX_START => handle.start().await?,
                m::SANDBOX_STOP => handle.stop().await?,
                m::SANDBOX_PAUSE => handle.pause().await?,
                m::SANDBOX_RESUME => handle.resume().await?,
                m::SANDBOX_ARCHIVE => handle.archive().await?,
                m::SANDBOX_RECOVER => handle.recover().await?,
                _ => handle.refresh_activity().await?,
            }
            to_value(&m::Empty)
        }
        m::SANDBOX_UNDELETE => {
            let request: m::AttachParams = parse(params)?;
            let id = sandbox_id(&request.sandbox_id)?;
            let events = state.event_context(request.events);
            let handle = state.provider.undelete(&id, events).await?;
            state.remember(&handle);
            let status = handle.describe().await?;
            to_value(&handle_info(&handle, status))
        }
        m::SANDBOX_FORK => {
            let request: m::ForkParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let options = request.options.try_into()?;
            let forked = handle.fork(&options).await?;
            state.remember(&forked);
            let status = forked.describe().await?;
            to_value(&handle_info(&forked, status))
        }
        m::SANDBOX_RESIZE => {
            let request: m::ResizeParams = parse(params)?;
            state
                .sandbox(&request.sandbox_id)
                .await?
                .resize(&request.resources)
                .await?;
            to_value(&m::Empty)
        }
        m::SANDBOX_SNAPSHOT => {
            let request: m::SnapshotParams = parse(params)?;
            let options = request.options.into();
            let snapshot = state
                .sandbox(&request.sandbox_id)
                .await?
                .snapshot(&options)
                .await?;
            to_value(&m::SnapshotResult {
                snapshot_id: snapshot.as_str().to_owned(),
            })
        }
        m::SANDBOX_SET_TIMERS => {
            let request: m::SetTimersParams = parse(params)?;
            state
                .sandbox(&request.sandbox_id)
                .await?
                .set_timers(&request.timers)
                .await?;
            to_value(&m::Empty)
        }
        m::SANDBOX_SET_LABELS => {
            let request: m::SetLabelsParams = parse(params)?;
            state
                .sandbox(&request.sandbox_id)
                .await?
                .set_labels(&request.labels)
                .await?;
            to_value(&m::Empty)
        }
        m::SANDBOX_UPDATE_NETWORK => {
            let request: m::UpdateNetworkParams = parse(params)?;
            state
                .sandbox(&request.sandbox_id)
                .await?
                .update_network(&request.network)
                .await?;
            to_value(&m::Empty)
        }
        _ => Err(DispatchError::UnknownMethod),
    }
}
