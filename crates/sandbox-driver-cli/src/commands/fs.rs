use anyhow::Result;
use sandbox_driver::{Capability, EventContext, SandboxProvider};

use super::{attach, require_capability};
use crate::cli::{FsCommand, OutputFormat};
use crate::output::write_action;

pub(super) async fn execute_fs(
    command: &FsCommand,
    provider: &dyn SandboxProvider,
    events: Option<EventContext>,
    output: OutputFormat,
) -> Result<u8> {
    match command {
        FsCommand::Upload { id, local, remote } => {
            let sandbox = attach(provider, id, events).await?;
            require_capability(provider, sandbox.as_ref(), Capability::FsUpload)?;
            sandbox.fs().upload(local, remote).await?;
            write_action(
                provider.kind().as_str(),
                sandbox.id().as_str(),
                "uploaded file to",
                output,
            )
            .await?;
        }
        FsCommand::Download { id, remote, local } => {
            let sandbox = attach(provider, id, events).await?;
            require_capability(provider, sandbox.as_ref(), Capability::FsDownload)?;
            sandbox.fs().download(remote, local).await?;
            write_action(
                provider.kind().as_str(),
                sandbox.id().as_str(),
                "downloaded file from",
                output,
            )
            .await?;
        }
    }
    Ok(0)
}
