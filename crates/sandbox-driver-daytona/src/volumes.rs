//! Volume management through the Daytona control plane.

use async_trait::async_trait;
use daytona_api_client::models::VolumeDto;
use sandbox_driver::{
    Action, Error, EventContext, EventEmitter, EventSubject, ProviderKind, ResourceKind, Result,
    VolumeId, VolumeProvider, VolumeSpec, VolumeState, VolumeStatus,
};

use crate::sdk::{DaytonaClient, daytona_error, is_not_found, map_volume_state};

fn volume_status(dto: VolumeDto) -> Result<VolumeStatus> {
    let id = VolumeId::try_new(dto.id)
        .map_err(|error| Error::invalid_spec("volume_id", error.to_string()))?;
    let mut status = VolumeStatus::new(id, map_volume_state(dto.state));
    status.name = Some(dto.name);
    status.error_reason = dto.error_reason;
    Ok(status)
}

pub(crate) struct DaytonaVolumes {
    pub(crate) client: DaytonaClient,
    pub(crate) kind:   ProviderKind,
}

#[async_trait]
impl VolumeProvider for DaytonaVolumes {
    #[tracing::instrument(skip_all, fields(provider_kind = "daytona"), err)]
    async fn create(&self, spec: &VolumeSpec, events: Option<EventContext>) -> Result<VolumeId> {
        EventEmitter::new(self.kind.clone(), events)
            .run(
                EventSubject::pending_volume(Some(spec.name.clone())),
                Action::Create,
                |reporter| async move {
                    // Daytona volumes are elastic; a requested size is ignored.
                    let dto = self
                        .client
                        .volume
                        .create(&spec.name)
                        .await
                        .map_err(|error| daytona_error("creating volume", error))?;
                    let id = VolumeId::try_new(dto.id)
                        .map_err(|error| Error::invalid_spec("volume_id", error.to_string()))?;
                    reporter.set_subject(EventSubject::volume(Some(id.clone())));
                    Ok(id)
                },
            )
            .await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", volume_id = %id),
        err
    )]
    async fn get(&self, id: &VolumeId) -> Result<VolumeStatus> {
        let dto = self.client.volume.get(id.as_str()).await.map_err(|error| {
            if is_not_found(&error) {
                Error::NotFound {
                    resource: ResourceKind::Volume,
                    id:       id.as_str().to_owned(),
                }
            } else {
                daytona_error("fetching volume", error)
            }
        })?;
        volume_status(dto)
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona"), err)]
    async fn list(&self) -> Result<Vec<VolumeStatus>> {
        let volumes = self
            .client
            .volume
            .list()
            .await
            .map_err(|error| daytona_error("listing volumes", error))?;
        volumes.into_iter().map(volume_status).collect()
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", volume_id = %id),
        err
    )]
    async fn delete(&self, id: &VolumeId, events: Option<EventContext>) -> Result<()> {
        EventEmitter::new(self.kind.clone(), events)
            .run(
                EventSubject::volume(Some(id.clone())),
                Action::Delete,
                |_| async {
                    match self.client.volume.delete(id.as_str()).await {
                        Ok(()) => Ok(()),
                        Err(error) if is_not_found(&error) => Ok(()),
                        Err(error) => {
                            // Deletion is asynchronous: a repeat delete while the
                            // first is processing is rejected. Idempotency means
                            // checking whether deletion is already underway.
                            if let Ok(dto) = self.client.volume.get(id.as_str()).await {
                                if matches!(
                                    map_volume_state(dto.state),
                                    VolumeState::Deleting | VolumeState::Deleted
                                ) {
                                    return Ok(());
                                }
                            }
                            Err(daytona_error("deleting volume", error))
                        }
                    }
                },
            )
            .await
    }
}
