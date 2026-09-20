use anyhow::Result;
use sandbox_driver::{
    Capability, EventContext, SandboxProvider, SandboxState, WaitOptions, wait_for_stable_state,
    wait_for_state,
};

use super::{attach, require_capability};
use crate::cli::{OutputFormat, StateChangeArgs};
use crate::output::{write_action, write_status};

#[derive(Clone, Copy)]
pub(super) enum LifecycleAction {
    Start,
    Stop,
    Pause,
    Resume,
    Archive,
    Recover,
}

impl LifecycleAction {
    fn name(self) -> &'static str {
        match self {
            Self::Start => "started",
            Self::Stop => "stopped",
            Self::Pause => "paused",
            Self::Resume => "resumed",
            Self::Archive => "archived",
            Self::Recover => "recovered",
        }
    }

    fn target(self) -> Option<SandboxState> {
        match self {
            Self::Start | Self::Resume => Some(SandboxState::Running),
            Self::Stop => Some(SandboxState::Stopped),
            Self::Pause => Some(SandboxState::Paused),
            Self::Archive => Some(SandboxState::Archived),
            Self::Recover => None,
        }
    }

    fn capability(self) -> Option<Capability> {
        match self {
            Self::Start | Self::Stop => None,
            Self::Pause | Self::Resume => Some(Capability::LifecyclePause),
            Self::Archive => Some(Capability::LifecycleArchive),
            Self::Recover => Some(Capability::LifecycleRecover),
        }
    }
}

pub(super) async fn lifecycle_action(
    provider: &dyn SandboxProvider,
    args: &StateChangeArgs,
    events: Option<EventContext>,
    output: OutputFormat,
    action: LifecycleAction,
) -> Result<u8> {
    let sandbox = attach(provider, &args.id, events).await?;
    if let Some(capability) = action.capability() {
        require_capability(provider, sandbox.as_ref(), capability)?;
    }

    match action {
        LifecycleAction::Start => sandbox.start().await?,
        LifecycleAction::Stop => sandbox.stop().await?,
        LifecycleAction::Pause => sandbox.pause().await?,
        LifecycleAction::Resume => sandbox.resume().await?,
        LifecycleAction::Archive => sandbox.archive().await?,
        LifecycleAction::Recover => sandbox.recover().await?,
    }

    if args.wait {
        let status = match action.target() {
            Some(target) => {
                wait_for_state(sandbox.as_ref(), target, &WaitOptions::default()).await?
            }
            None => wait_for_stable_state(sandbox.as_ref(), &WaitOptions::default()).await?,
        };
        write_status(&status, output).await?;
    } else {
        write_action(
            provider.kind().as_str(),
            sandbox.id().as_str(),
            action.name(),
            output,
        )
        .await?;
    }
    Ok(0)
}
