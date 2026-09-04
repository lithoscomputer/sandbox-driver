use std::fmt::Write as _;
use std::slice::from_ref;
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use async_trait::async_trait;
use sandbox_driver::{
    Capabilities, Capability, Event, EventBody, EventContext, EventObserver, HealthStatus,
    ProviderHealth, SandboxStatus,
};
use serde::Serialize;
use tokio::io::{AsyncWriteExt as _, stderr, stdout};

use crate::cli::{EventFormat, OutputFormat};

const OPTIONAL_CAPABILITIES: &[Capability] = &[
    Capability::LifecyclePause,
    Capability::LifecycleArchive,
    Capability::LifecycleFork,
    Capability::LifecycleResize,
    Capability::LifecycleRecover,
    Capability::LifecycleUndelete,
    Capability::LifecycleRefreshActivity,
    Capability::LifecycleTimers,
    Capability::LifecycleLabels,
    Capability::LifecycleUpdateNetwork,
    Capability::LifecycleSnapshotSandbox,
    Capability::ExecStdin,
    Capability::ExecStop,
    Capability::ExecStdioProcess,
    Capability::FsUpload,
    Capability::FsDownload,
    Capability::FsPermissions,
    Capability::Pty,
    Capability::Logs,
    Capability::PreviewUrls,
    Capability::SignedPreviewUrls,
    Capability::Ssh,
    Capability::SshTtl,
    Capability::SshRevoke,
    Capability::ShellCommandAccess,
    Capability::WebTerminalAccess,
    Capability::VncAccess,
    Capability::Snapshots,
    Capability::SnapshotsContainerFromImage,
    Capability::SnapshotsVmFromImage,
    Capability::SnapshotsContainerFromDockerfile,
    Capability::SnapshotsVmFromDockerfile,
    Capability::SnapshotsFilesystem,
    Capability::SnapshotsLiveProcessState,
    Capability::SnapshotsActivation,
    Capability::Search,
    Capability::Git,
    Capability::Services,
    Capability::Volumes,
];

#[derive(Debug, Serialize)]
pub(crate) struct ProviderListing<'a> {
    pub name:          &'a str,
    pub provider_type: &'a str,
    pub kind:          &'a str,
    pub selected:      bool,
}

pub(crate) fn event_context(format: EventFormat) -> Option<EventContext> {
    if format == EventFormat::Off {
        return None;
    }
    Some(EventContext::new(Arc::new(StderrEventObserver { format })))
}

pub(crate) async fn write_provider_list(
    listings: &[ProviderListing<'_>],
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => write_json(listings).await,
        OutputFormat::Table => {
            let mut rendered = String::from("NAME\tTYPE\tKIND\tDEFAULT\n");
            for listing in listings {
                let default = if listing.selected { "yes" } else { "" };
                let _ = writeln!(
                    rendered,
                    "{}\t{}\t{}\t{default}",
                    listing.name, listing.provider_type, listing.kind
                );
            }
            write_stdout(rendered.as_bytes()).await
        }
        OutputFormat::Id => {
            let mut rendered = String::new();
            for listing in listings {
                rendered.push_str(listing.name);
                rendered.push('\n');
            }
            write_stdout(rendered.as_bytes()).await
        }
    }
}

pub(crate) async fn write_health(
    provider: &str,
    health: &ProviderHealth,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => write_json(health).await,
        OutputFormat::Table => {
            let status = serialized_name(&health.status)?;
            let mut rendered = format!("provider: {provider}\nstatus: {status}\n");
            if let Some(message) = &health.message {
                let _ = writeln!(rendered, "message: {message}");
            }
            if !health.missing_permissions.is_empty() {
                let _ = writeln!(
                    rendered,
                    "missing permissions: {}",
                    health.missing_permissions.join(", ")
                );
            }
            write_stdout(rendered.as_bytes()).await
        }
        OutputFormat::Id => bail!("--output id is not valid for provider health"),
    }
}

pub(crate) async fn write_capabilities(
    provider: &str,
    capabilities: &Capabilities,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => write_json(capabilities).await,
        OutputFormat::Table => {
            let isolation = serialized_name(&capabilities.isolation)?;
            let mut rendered = format!("provider: {provider}\nisolation: {isolation}\n");
            rendered.push_str("optional capabilities:\n");
            for capability in OPTIONAL_CAPABILITIES {
                if capabilities.supports(*capability) {
                    let _ = writeln!(rendered, "  {capability}");
                }
            }
            write_stdout(rendered.as_bytes()).await
        }
        OutputFormat::Id => bail!("--output id is not valid for provider capabilities"),
    }
}

pub(crate) async fn write_statuses(statuses: &[SandboxStatus], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => write_json(statuses).await,
        OutputFormat::Id => {
            let mut rendered = String::new();
            for status in statuses {
                rendered.push_str(status.id.as_str());
                rendered.push('\n');
            }
            write_stdout(rendered.as_bytes()).await
        }
        OutputFormat::Table => {
            let mut rendered = String::from("ID\tNAME\tSTATE\tPROVIDER STATE\tREGION\n");
            for status in statuses {
                let state = serialized_name(&status.state)?;
                let _ = writeln!(
                    rendered,
                    "{}\t{}\t{}\t{}\t{}",
                    status.id,
                    status.name.as_deref().unwrap_or(""),
                    state,
                    status.provider_state,
                    status.region.as_deref().unwrap_or("")
                );
            }
            write_stdout(rendered.as_bytes()).await
        }
    }
}

pub(crate) async fn write_status(status: &SandboxStatus, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => write_json(status).await,
        OutputFormat::Id => write_line(status.id.as_str()).await,
        OutputFormat::Table => write_statuses(from_ref(status), format).await,
    }
}

pub(crate) async fn write_action(
    provider: &str,
    id: &str,
    action: &str,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            write_json(&serde_json::json!({
                "provider": provider,
                "sandbox_id": id,
                "action": action,
            }))
            .await
        }
        OutputFormat::Id => write_line(id).await,
        OutputFormat::Table => write_line(&format!("{action} {id}")).await,
    }
}

pub(crate) async fn write_line(value: &str) -> Result<()> {
    let mut rendered = value.as_bytes().to_vec();
    rendered.push(b'\n');
    write_stdout(&rendered).await
}

pub(crate) async fn write_stdout(bytes: &[u8]) -> Result<()> {
    let mut output = stdout();
    output.write_all(bytes).await.context("writing stdout")?;
    output.flush().await.context("flushing stdout")
}

pub(crate) async fn write_stderr(bytes: &[u8]) -> Result<()> {
    let mut output = stderr();
    output.write_all(bytes).await.context("writing stderr")?;
    output.flush().await.context("flushing stderr")
}

pub(crate) async fn write_json<T>(value: &T) -> Result<()>
where
    T: Serialize + ?Sized,
{
    let mut rendered = serde_json::to_vec_pretty(value).context("serializing JSON output")?;
    rendered.push(b'\n');
    write_stdout(&rendered).await
}

fn serialized_name<T>(value: &T) -> Result<String>
where
    T: Serialize,
{
    let value = serde_json::to_value(value).context("formatting value")?;
    value
        .as_str()
        .map(ToOwned::to_owned)
        .context("serialized value was not a string")
}

struct StderrEventObserver {
    format: EventFormat,
}

#[async_trait]
impl EventObserver for StderrEventObserver {
    async fn observe(&self, event: Event) {
        let rendered = match self.format {
            EventFormat::Json => serde_json::to_vec(&event)
                .map(|mut bytes| {
                    bytes.push(b'\n');
                    bytes
                })
                .context("serializing event"),
            EventFormat::Human => Ok(render_human_event(&event).into_bytes()),
            EventFormat::Off => Ok(Vec::new()),
        };
        match rendered {
            Ok(bytes) if !bytes.is_empty() => {
                if let Err(error) = write_stderr(&bytes).await {
                    tracing::warn!(error = ?error, "event output failed");
                }
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(error = ?error, "event rendering failed"),
        }
    }
}

fn render_human_event(event: &Event) -> String {
    match &event.body {
        EventBody::OperationProgress { progress, .. } => progress
            .message
            .as_ref()
            .map_or_else(String::new, |message| {
                format!("[{0}] {message}\n", event.provider)
            }),
        EventBody::Notice { message, .. } => format!("[{0}] {message}\n", event.provider),
        _ => String::new(),
    }
}

pub(crate) fn health_exit_code(health: &ProviderHealth) -> u8 {
    match health.status {
        HealthStatus::Ok | HealthStatus::Unknown => 0,
        _ => 1,
    }
}
