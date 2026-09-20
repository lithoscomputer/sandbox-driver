use anyhow::Result;
use sandbox_driver::{Capability, EventContext, SandboxProvider};

use super::act_on_sandbox;
use crate::cli::{FsCommand, OutputFormat};

pub(super) async fn execute_fs(
    command: &FsCommand,
    provider: &dyn SandboxProvider,
    events: Option<EventContext>,
    output: OutputFormat,
) -> Result<u8> {
    match command {
        FsCommand::Upload { id, local, remote } => {
            act_on_sandbox(
                provider,
                id,
                events,
                output,
                Capability::FsUpload,
                "uploaded file to",
                async |sandbox| sandbox.fs().upload(local, remote).await,
            )
            .await
        }
        FsCommand::Download { id, remote, local } => {
            act_on_sandbox(
                provider,
                id,
                events,
                output,
                Capability::FsDownload,
                "downloaded file from",
                async |sandbox| sandbox.fs().download(remote, local).await,
            )
            .await
        }
    }
}
