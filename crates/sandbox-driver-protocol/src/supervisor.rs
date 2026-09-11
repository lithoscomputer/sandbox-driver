//! Replacement for new work only. A failed call is never replayed.
use std::collections::btree_map::Entry;
use std::sync::Arc;
use std::time::Duration;
use std::{env, mem};

use async_trait::async_trait;
use sandbox_driver::{
    Capabilities, Capability, Error, EventContext, LogSink, ProviderHealth, ProviderKind, Result,
    Sandbox, SandboxFilter, SandboxId, SandboxProvider, SandboxSpec, SandboxStatus, SnapshotFilter,
    SnapshotId, SnapshotProvider, SnapshotSpec, SnapshotStatus, VolumeId, VolumeProvider,
    VolumeSpec, VolumeStatus,
};
use tokio::sync::Mutex;

use crate::{PluginConfig, PluginProvider, launch_plugin};

/// A plugin provider that survives its executable dying.
///
/// Owns at most one live plugin for one fixed configuration and credential
/// context, and is itself the [`SandboxProvider`]: every call obtains the
/// current generation, and a closed transport is replaced with a fresh
/// launch before the call. Share one for the application's lifetime. A
/// failed call is never replayed after an uncertain result, and sandbox
/// handles obtained from an earlier generation remain tied to it; callers
/// reconstruct them through [`SandboxProvider::attach`] with the persisted
/// sandbox id.
///
/// The application bounds the number of supervisors and authorizes
/// resource IDs.
pub struct PluginSupervisor {
    prefix:       String,
    config:       PluginConfig,
    kind:         ProviderKind,
    capabilities: Capabilities,
    current:      Mutex<Option<Arc<PluginProvider>>>,
}

impl PluginSupervisor {
    /// Launches the first generation now, so a misconfigured plugin fails
    /// here rather than on first use, and the capabilities are known for
    /// preflight. The supervisor's kind is the configured one: the name
    /// the host launched the executable under, which its records and
    /// errors speak of; the kind the plugin declares for itself is on the
    /// generation ([`Self::current`]). Freezes forwarded environment values
    /// so replacements cannot inherit a different credential context from
    /// later environment changes.
    pub async fn launch(prefix: impl Into<String>, mut config: PluginConfig) -> Result<Self> {
        for key in mem::take(&mut config.inherit_env) {
            if let Entry::Vacant(entry) = config.env.entry(key) {
                if let Ok(value) = env::var(entry.key()) {
                    entry.insert(value);
                }
            }
        }
        let prefix = prefix.into();
        let launched = launch_plugin(&prefix, &config).await?;
        let provider = Arc::new(launched.provider);
        Ok(Self {
            prefix,
            kind: config.kind.clone(),
            config,
            capabilities: provider.capabilities().clone(),
            current: Mutex::new(Some(provider)),
        })
    }

    /// The live generation, launching a replacement when the current one
    /// has closed. Serializes startup so concurrent callers share a single
    /// replacement. Failed generations and their calls are never rebound
    /// to the replacement.
    pub async fn current(&self) -> Result<Arc<PluginProvider>> {
        let mut slot = self.current.lock().await;
        if let Some(provider) = slot.as_ref().filter(|provider| !provider.is_closed()) {
            return Ok(Arc::clone(provider));
        }
        if let Some(old) = slot.take() {
            let _ = old.shutdown().await;
        }
        let launched = launch_plugin(&self.prefix, &self.config).await?;
        let provider = Arc::new(launched.provider);
        *slot = Some(Arc::clone(&provider));
        Ok(provider)
    }

    /// Asks the current generation to exit and reaps it. A later call
    /// launches a fresh generation.
    pub async fn shutdown(&self) -> Result<()> {
        let mut slot = self.current.lock().await;
        if let Some(provider) = slot.take() {
            provider.shutdown().await?;
        }
        Ok(())
    }

    /// The current generation's snapshot service.
    async fn snapshot_service(&self) -> Result<SnapshotGeneration> {
        let provider = self.current().await?;
        if provider.snapshots().is_none() {
            return Err(Error::unsupported(Capability::Snapshots));
        }
        Ok(SnapshotGeneration(provider))
    }

    /// The current generation's volume service.
    async fn volume_service(&self) -> Result<VolumeGeneration> {
        let provider = self.current().await?;
        if provider.volumes().is_none() {
            return Err(Error::unsupported(Capability::Volumes));
        }
        Ok(VolumeGeneration(provider))
    }
}

/// A live generation known to serve snapshots.
struct SnapshotGeneration(Arc<PluginProvider>);

impl SnapshotGeneration {
    fn snapshots(&self) -> &dyn SnapshotProvider {
        self.0
            .snapshots()
            .expect("the generation served snapshots when it was obtained")
    }
}

/// A live generation known to serve volumes.
struct VolumeGeneration(Arc<PluginProvider>);

impl VolumeGeneration {
    fn volumes(&self) -> &dyn VolumeProvider {
        self.0
            .volumes()
            .expect("the generation served volumes when it was obtained")
    }
}

#[async_trait]
impl SandboxProvider for PluginSupervisor {
    fn kind(&self) -> &ProviderKind {
        &self.kind
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    async fn create(
        &self,
        spec: &SandboxSpec,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        self.current().await?.create(spec, events).await
    }

    async fn attach(
        &self,
        id: &SandboxId,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        self.current().await?.attach(id, events).await
    }

    async fn undelete(
        &self,
        id: &SandboxId,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        self.current().await?.undelete(id, events).await
    }

    async fn delete(&self, id: &SandboxId, events: Option<EventContext>) -> Result<()> {
        self.current().await?.delete(id, events).await
    }

    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>> {
        self.current().await?.list(filter).await
    }

    async fn health(&self) -> Result<ProviderHealth> {
        self.current().await?.health().await
    }

    /// Present whenever the plugin declared snapshots; each call reaches the
    /// generation live at that moment.
    fn snapshots(&self) -> Option<&dyn SnapshotProvider> {
        self.capabilities
            .snapshots
            .is_some()
            .then_some(self as &dyn SnapshotProvider)
    }

    /// Present whenever the plugin declared volumes; each call reaches the
    /// generation live at that moment.
    fn volumes(&self) -> Option<&dyn VolumeProvider> {
        self.capabilities
            .volumes
            .is_some()
            .then_some(self as &dyn VolumeProvider)
    }
}

#[async_trait]
impl SnapshotProvider for PluginSupervisor {
    async fn create(
        &self,
        spec: &SnapshotSpec,
        events: Option<EventContext>,
    ) -> Result<SnapshotId> {
        self.snapshot_service()
            .await?
            .snapshots()
            .create(spec, events)
            .await
    }

    async fn get(&self, id: &SnapshotId) -> Result<SnapshotStatus> {
        self.snapshot_service().await?.snapshots().get(id).await
    }

    async fn list(&self, filter: &SnapshotFilter) -> Result<Vec<SnapshotStatus>> {
        self.snapshot_service()
            .await?
            .snapshots()
            .list(filter)
            .await
    }

    async fn delete(&self, id: &SnapshotId, events: Option<EventContext>) -> Result<()> {
        self.snapshot_service()
            .await?
            .snapshots()
            .delete(id, events)
            .await
    }

    async fn build_logs(&self, id: &SnapshotId, follow: bool, sink: LogSink) -> Result<()> {
        self.snapshot_service()
            .await?
            .snapshots()
            .build_logs(id, follow, sink)
            .await
    }

    async fn activate(&self, id: &SnapshotId, events: Option<EventContext>) -> Result<()> {
        self.snapshot_service()
            .await?
            .snapshots()
            .activate(id, events)
            .await
    }

    async fn deactivate(&self, id: &SnapshotId, events: Option<EventContext>) -> Result<()> {
        self.snapshot_service()
            .await?
            .snapshots()
            .deactivate(id, events)
            .await
    }

    async fn ensure(
        &self,
        spec: &SnapshotSpec,
        budget: Duration,
        events: Option<EventContext>,
    ) -> Result<SnapshotId> {
        self.snapshot_service()
            .await?
            .snapshots()
            .ensure(spec, budget, events)
            .await
    }
}

#[async_trait]
impl VolumeProvider for PluginSupervisor {
    async fn create(&self, spec: &VolumeSpec, events: Option<EventContext>) -> Result<VolumeId> {
        self.volume_service()
            .await?
            .volumes()
            .create(spec, events)
            .await
    }

    async fn get(&self, id: &VolumeId) -> Result<VolumeStatus> {
        self.volume_service().await?.volumes().get(id).await
    }

    async fn list(&self) -> Result<Vec<VolumeStatus>> {
        self.volume_service().await?.volumes().list().await
    }

    async fn delete(&self, id: &VolumeId, events: Option<EventContext>) -> Result<()> {
        self.volume_service()
            .await?
            .volumes()
            .delete(id, events)
            .await
    }
}
