//! Snapshot management through the Daytona control plane.

use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use daytona_api_client::apis::{sandbox_api, snapshots_api};
use daytona_api_client::models::sandbox::SandboxClass as DaytonaSandboxClass;
use daytona_api_client::models::{
    CreateSandboxSnapshot, SandboxClass as DaytonaCreateSandboxClass, SnapshotDto,
};
use daytona_sdk::{CreateSnapshotParams, DaytonaError, DockerImage, ImageSource};
use sandbox_driver::{
    Action, Capability, Error, EventContext, EventEmitter, EventSubject, LogSink, ProviderError,
    ProviderKind, ResourceKind, Resources, Result, SandboxId, SandboxKind, SandboxState,
    SnapshotFilter, SnapshotId, SnapshotMode, SnapshotProvider, SnapshotSource, SnapshotSpec,
    SnapshotState, SnapshotStatus,
};
use tokio::time;

use crate::sdk::{
    DaytonaClient, daytona_error, daytona_snapshot_class, fetch_error, generated_error, gigabytes,
    is_generated_not_found, is_not_found, is_snapshot_deactivation_in_progress, map_snapshot_state,
    map_state, sandbox_kind_from_sandbox_class, sandbox_kind_from_snapshot_class, to_u64,
};
use crate::{
    CREATE_TIMEOUT, LIST_PAGE_SIZE, SNAPSHOT_ACTIVATE_BUDGET, SNAPSHOT_ACTIVATE_POLL,
    TRANSITION_POLL,
};

pub(crate) fn generated_snapshot_name() -> String {
    format!(
        "sandbox-driver-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    )
}

pub(crate) async fn create_sandbox_snapshot(
    client: &DaytonaClient,
    sandbox_id: &str,
    name: &str,
    mode: SnapshotMode,
) -> Result<SnapshotId> {
    let sdk = client
        .get(sandbox_id)
        .await
        .map_err(|error| daytona_error("fetching sandbox for snapshot", error))?;
    let current = map_state(sdk.state);
    let required = match mode {
        SnapshotMode::Filesystem => SandboxState::Stopped,
        SnapshotMode::LiveProcessState => SandboxState::Running,
        _ => {
            return Err(Error::invalid_spec(
                "mode",
                "unsupported sandbox snapshot mode",
            ));
        }
    };
    if current != required {
        return Err(Error::InvalidState {
            current,
            action: Action::Snapshot,
        });
    }

    let request = CreateSandboxSnapshot {
        name:           name.to_owned(),
        include_memory: Some(mode == SnapshotMode::LiveProcessState),
    };
    sandbox_api::create_sandbox_snapshot(
        client.api_configuration(),
        sandbox_id,
        request,
        client.organization_id(),
    )
    .await
    .map_err(|error| generated_error("snapshotting sandbox", error))?;

    // Wait on the snapshot record itself, not the sandbox state: right
    // after the POST the sandbox may not have entered Snapshotting yet,
    // so watching it can declare completion while the snapshot is still
    // being written — and a caller could delete the sandbox under it.
    let started = Instant::now();
    loop {
        match client.snapshot.get(name).await {
            // The record can appear a beat after the POST.
            Err(error) if is_not_found(&error) => {}
            Err(error) => {
                return Err(daytona_error("waiting for sandbox snapshot", error));
            }
            Ok(dto) => match map_snapshot_state(dto.state) {
                // Inactive counts as written: the org's active-snapshot
                // budget can deactivate a snapshot on arrival, but the
                // data exists and activate() can bring it back.
                SnapshotState::Active | SnapshotState::Inactive => {
                    return SnapshotId::try_new(dto.id)
                        .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()));
                }
                SnapshotState::Error => {
                    return Err(Error::Provider(ProviderError::new(
                        ProviderKind::try_new("daytona").expect("static kind is valid"),
                        dto.error_reason
                            .unwrap_or_else(|| "sandbox snapshot failed".to_owned()),
                    )));
                }
                SnapshotState::Deleting => {
                    return Err(Error::Provider(ProviderError::new(
                        ProviderKind::try_new("daytona").expect("static kind is valid"),
                        "snapshot was removed while being created".to_owned(),
                    )));
                }
                // Building — or a state this crate does not know yet:
                // keep polling; the budget below bounds the wait.
                _ => {}
            },
        }
        let elapsed = started.elapsed();
        if elapsed >= CREATE_TIMEOUT {
            return Err(Error::Timeout {
                operation: "snapshotting sandbox".to_owned(),
                elapsed,
            });
        }
        time::sleep(TRANSITION_POLL).await;
    }
}

async fn created_snapshot_id(client: &DaytonaClient, name: &str) -> Result<SnapshotId> {
    let dto = client
        .snapshot
        .get(name)
        .await
        .map_err(|error| daytona_error("fetching created snapshot", error))?;
    SnapshotId::try_new(dto.id)
        .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))
}

fn sdk_resources(resources: &Resources) -> Option<daytona_sdk::Resources> {
    if *resources == Resources::default() {
        return None;
    }
    Some(daytona_sdk::Resources {
        cpu:    resources
            .cpu_cores
            .and_then(|cores| i32::try_from(cores).ok()),
        gpu:    resources.gpus.and_then(|gpus| i32::try_from(gpus).ok()),
        memory: resources.memory_mb.map(gigabytes),
        disk:   resources.disk_mb.map(gigabytes),
    })
}

fn snapshot_status(dto: SnapshotDto) -> Result<SnapshotStatus> {
    let id = SnapshotId::try_new(dto.id)
        .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))?;
    let mut resources = Resources::default();
    resources.cpu_cores = to_u64(dto.cpu)
        .and_then(|cpu| u32::try_from(cpu).ok())
        .filter(|cpu| *cpu > 0);
    resources.memory_mb = to_u64(dto.mem * 1024.0).filter(|mb| *mb > 0);
    resources.disk_mb = to_u64(dto.disk * 1024.0).filter(|mb| *mb > 0);
    resources.gpus = to_u64(dto.gpu)
        .and_then(|gpu| u32::try_from(gpu).ok())
        .filter(|gpu| *gpu > 0);

    let mut status = SnapshotStatus::new(id, map_snapshot_state(dto.state));
    status.name = Some(dto.name);
    status.sandbox_kind = dto.sandbox_class.map(sandbox_kind_from_snapshot_class);
    status.regions = dto.region_ids.unwrap_or_default();
    status.resources = (resources != Resources::default()).then_some(resources);
    status.error_reason = dto.error_reason;
    status.size_bytes = dto.size.and_then(to_u64);
    Ok(status)
}

pub(crate) struct DaytonaSnapshots {
    pub(crate) client: DaytonaClient,
    pub(crate) kind:   ProviderKind,
}

impl DaytonaSnapshots {
    /// A snapshot built from an image or a Dockerfile, sized by the
    /// spec's resources.
    async fn snapshot_from_image(&self, spec: &SnapshotSpec, name: String) -> Result<SnapshotId> {
        let (image, sandbox_class) = match &spec.source {
            SnapshotSource::Image { reference } => (
                ImageSource::Name(reference.clone()),
                daytona_snapshot_class(spec.sandbox_kind.unwrap_or(SandboxKind::Container))?,
            ),
            SnapshotSource::Dockerfile { content } => {
                if spec.sandbox_kind == Some(SandboxKind::VirtualMachine) {
                    return Err(Error::unsupported(Capability::SnapshotsVmFromDockerfile));
                }
                (
                    ImageSource::Custom(DockerImage::from_dockerfile(content)),
                    DaytonaCreateSandboxClass::CONTAINER,
                )
            }
            _ => return Err(Error::invalid_spec("source", "unsupported snapshot source")),
        };
        let params = CreateSnapshotParams {
            name,
            image,
            region_id: spec.region.clone(),
            sandbox_class: Some(sandbox_class),
            resources: sdk_resources(&spec.resources),
            entrypoint: None,
        };
        let created = self
            .client
            .snapshot
            .create(&params)
            .await
            .map_err(|error| daytona_error("creating snapshot", error))?;
        SnapshotId::try_new(created.id)
            .map_err(|error| Error::invalid_spec("snapshot_id", error.to_string()))
    }

    /// A snapshot of an existing sandbox. The sandbox's kind and region
    /// are inherited, so a spec that names either must agree with them,
    /// and it must not size the snapshot itself.
    async fn snapshot_from_sandbox(
        &self,
        spec: &SnapshotSpec,
        id: &SandboxId,
        mode: SnapshotMode,
        name: &str,
    ) -> Result<SnapshotId> {
        let sdk = self
            .client
            .get(id.as_str())
            .await
            .map_err(|error| daytona_error("fetching sandbox for snapshot", error))?;
        let actual_kind = sdk.sandbox_class.map(sandbox_kind_from_sandbox_class);
        if let Some(requested) = spec.sandbox_kind {
            if actual_kind != Some(requested) {
                return Err(Error::invalid_spec(
                    "sandbox_kind",
                    format!("the source sandbox has kind {actual_kind:?}, not {requested:?}"),
                ));
            }
        }
        if let Some(region) = &spec.region {
            if sdk.target != *region {
                return Err(Error::invalid_spec(
                    "region",
                    format!(
                        "the source sandbox is in region {}, not {region}",
                        sdk.target
                    ),
                ));
            }
        }
        if spec.resources != Resources::default() {
            return Err(Error::invalid_spec(
                "resources",
                "resources are inherited when snapshotting a sandbox",
            ));
        }
        if mode == SnapshotMode::LiveProcessState
            && matches!(
                sdk.sandbox_class,
                Some(DaytonaSandboxClass::CONTAINER | DaytonaSandboxClass::ANDROID)
            )
        {
            return Err(Error::unsupported(Capability::SnapshotsLiveProcessState));
        }
        create_sandbox_snapshot(&self.client, id.as_str(), name, mode).await?;
        created_snapshot_id(&self.client, name).await
    }
}

#[async_trait]
impl SnapshotProvider for DaytonaSnapshots {
    #[tracing::instrument(skip_all, fields(provider_kind = "daytona"), err)]
    async fn create(
        &self,
        spec: &SnapshotSpec,
        events: Option<EventContext>,
    ) -> Result<SnapshotId> {
        spec.validate()?;
        let name = spec.name.clone().unwrap_or_else(generated_snapshot_name);
        let emitter = EventEmitter::new(self.kind.clone(), events);
        emitter
            .run(
                EventSubject::pending_snapshot(Some(name.clone())),
                Action::Create,
                |reporter| async move {
                    reporter
                        .progress(sandbox_driver::Progress::new(
                            sandbox_driver::ProgressCode::SNAPSHOT_BUILD,
                        ))
                        .await;
                    let id = match &spec.source {
                        SnapshotSource::Sandbox { id, mode } => {
                            self.snapshot_from_sandbox(spec, id, *mode, &name).await?
                        }
                        _ => self.snapshot_from_image(spec, name).await?,
                    };
                    reporter.set_subject(EventSubject::snapshot(Some(id.clone())));
                    Ok(id)
                },
            )
            .await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", snapshot_id = %id),
        err
    )]
    async fn get(&self, id: &SnapshotId) -> Result<SnapshotStatus> {
        let dto = self
            .client
            .snapshot
            .get(id.as_str())
            .await
            .map_err(fetch_error(
                ResourceKind::Snapshot,
                id.as_str(),
                "fetching snapshot",
            ))?;
        snapshot_status(dto)
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona"), err)]
    async fn list(&self, filter: &SnapshotFilter) -> Result<Vec<SnapshotStatus>> {
        let mut statuses = Vec::new();
        let mut page_number: i32 = 1;
        loop {
            let page = self
                .client
                .snapshot
                .list(Some(page_number), Some(LIST_PAGE_SIZE))
                .await
                .map_err(|error| daytona_error("listing snapshots", error))?;
            tracing::debug!(
                page_number,
                item_count = page.items.len(),
                "snapshot page received"
            );
            for dto in page.items {
                if let Some(name) = &filter.name {
                    if dto.name != *name {
                        continue;
                    }
                }
                statuses.push(snapshot_status(dto)?);
            }
            if page.total_pages <= f64::from(page_number) {
                break;
            }
            page_number += 1;
        }
        Ok(statuses)
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", snapshot_id = %id),
        err
    )]
    async fn delete(&self, id: &SnapshotId, events: Option<EventContext>) -> Result<()> {
        EventEmitter::new(self.kind.clone(), events)
            .run(
                EventSubject::snapshot(Some(id.clone())),
                Action::Delete,
                |_| async {
                    match self.client.snapshot.delete(id.as_str()).await {
                        Ok(()) => Ok(()),
                        Err(error) if is_not_found(&error) => Ok(()),
                        Err(error) => {
                            // Same asynchronous-deletion idempotency as volumes.
                            if let Ok(dto) = self.client.snapshot.get(id.as_str()).await {
                                if map_snapshot_state(dto.state) == SnapshotState::Deleting {
                                    return Ok(());
                                }
                            }
                            Err(daytona_error("deleting snapshot", error))
                        }
                    }
                },
            )
            .await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", snapshot_id = %id, follow),
        err
    )]
    async fn build_logs(&self, id: &SnapshotId, follow: bool, sink: LogSink) -> Result<()> {
        let sink_error = Arc::new(Mutex::new(None));
        let callback_error = Arc::clone(&sink_error);
        let outcome = self
            .client
            .snapshot
            .stream_build_logs(id.as_str(), follow, move |chunk| {
                let sink = Arc::clone(&sink);
                let callback_error = Arc::clone(&callback_error);
                async move {
                    if let Err(error) = sink(chunk).await {
                        *callback_error.lock().expect("sink error lock") = Some(error);
                        return Err(DaytonaError::general("sandbox-driver log sink failed"));
                    }
                    Ok(())
                }
            })
            .await;
        if let Some(error) = sink_error.lock().expect("sink error lock").take() {
            return Err(error);
        }
        outcome.map_err(|error| daytona_error("following snapshot build logs", error))
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", snapshot_id = %id),
        err
    )]
    async fn activate(&self, id: &SnapshotId, events: Option<EventContext>) -> Result<()> {
        EventEmitter::new(self.kind.clone(), events)
            .run(
                EventSubject::snapshot(Some(id.clone())),
                Action::Activate,
                |_| async {
                    // The SDK resolves ids and names against the ID-only endpoint.
                    let started = Instant::now();
                    let mut attempt = 0_u64;
                    loop {
                        attempt += 1;
                        tracing::debug!(attempt, "snapshot activation requested");
                        match self.client.snapshot.activate(id.as_str()).await {
                            Ok(_) => return Ok(()),
                            Err(error) if is_not_found(&error) => {
                                return Err(Error::NotFound {
                                    resource: ResourceKind::Snapshot,
                                    id:       id.as_str().to_owned(),
                                });
                            }
                            Err(error) if is_snapshot_deactivation_in_progress(&error) => {
                                let elapsed = started.elapsed();
                                if elapsed >= SNAPSHOT_ACTIVATE_BUDGET {
                                    return Err(Error::Timeout {
                                        operation: "waiting to activate snapshot".to_owned(),
                                        elapsed,
                                    });
                                }
                                time::sleep(SNAPSHOT_ACTIVATE_POLL).await;
                            }
                            Err(error) => {
                                return Err(daytona_error("activating snapshot", error));
                            }
                        }
                    }
                },
            )
            .await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", snapshot_id = %id),
        err
    )]
    async fn deactivate(&self, id: &SnapshotId, events: Option<EventContext>) -> Result<()> {
        EventEmitter::new(self.kind.clone(), events)
            .run(
                EventSubject::snapshot(Some(id.clone())),
                Action::Deactivate,
                |_| async {
                    // Deactivation is unwrapped by the reference SDKs (the generated
                    // client has it); the endpoint is ID-only, so resolve a name
                    // through get first, mirroring the SDK's activate resolution.
                    let configuration = self.client.api_configuration();
                    let organization = self.client.organization_id();
                    match snapshots_api::deactivate_snapshot(
                        configuration,
                        id.as_str(),
                        organization,
                    )
                    .await
                    {
                        Ok(()) => return Ok(()),
                        Err(error) if is_generated_not_found(&error) => {}
                        Err(error) => {
                            return Err(generated_error("deactivating snapshot", error));
                        }
                    }
                    let resolved = self
                        .client
                        .snapshot
                        .get(id.as_str())
                        .await
                        .map_err(fetch_error(
                            ResourceKind::Snapshot,
                            id.as_str(),
                            "fetching snapshot",
                        ))?
                        .id;
                    snapshots_api::deactivate_snapshot(configuration, &resolved, organization)
                        .await
                        .map_err(|error| generated_error("deactivating snapshot", error))
                },
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use daytona_api_client::models::SnapshotState as ApiSnapshotState;
    use daytona_api_client::models::snapshot_dto::SandboxClass as DaytonaSnapshotClass;

    use super::*;

    #[test]
    fn snapshot_status_reports_kind_regions_and_resources() {
        let mut dto = SnapshotDto::new(
            "snap-1".to_owned(),
            true,
            "base".to_owned(),
            ApiSnapshotState::Active,
            Some(512.0),
            None,
            2.0,
            1.0,
            4.0,
            20.0,
            None,
            "2026-01-01".to_owned(),
            "2026-01-01".to_owned(),
            None,
            None,
        );
        dto.sandbox_class = Some(DaytonaSnapshotClass::LINUX_VM);
        dto.region_ids = Some(vec!["eu".to_owned(), "us".to_owned()]);

        let status = snapshot_status(dto).expect("maps snapshot status");
        assert_eq!(status.sandbox_kind, Some(SandboxKind::VirtualMachine));
        assert_eq!(status.regions, ["eu", "us"]);
        let resources = status.resources.expect("snapshot resources");
        assert_eq!(resources.cpu_cores, Some(2));
        assert_eq!(resources.memory_mb, Some(4096));
        assert_eq!(resources.disk_mb, Some(20 * 1024));
        assert_eq!(resources.gpus, Some(1));
        assert_eq!(status.size_bytes, Some(512));
    }
}
