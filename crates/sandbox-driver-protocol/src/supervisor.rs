//! Replacement for new work only. A failed call is never replayed.
use std::collections::btree_map::Entry;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::{env, mem};

use async_trait::async_trait;
use sandbox_driver::{
    AuthError, Capabilities, Capability, Error, EventContext, HealthStatus, LogSink, ProviderError,
    ProviderHealth, ProviderKind, Result, Sandbox, SandboxFilter, SandboxId, SandboxProvider,
    SandboxSpec, SandboxStatus, SnapshotFilter, SnapshotId, SnapshotProvider, SnapshotSpec,
    SnapshotStatus, VolumeId, VolumeProvider, VolumeSpec, VolumeStatus,
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
/// Every generation is numbered from 1 in launch order
/// ([`PluginGeneration::number`]). An application that keeps handles
/// across calls records the number a handle came from and, when a later
/// call answers from a higher one, treats the handle as dead and fences
/// the resource before resuming on it.
///
/// A generation serves only after its backend answered a health probe:
/// an unreachable backend or a rejected credential ends the launch with
/// the probe's report as the error, and a replacement that reports a
/// different resource namespace ([`ProviderHealth::identity`]) than the
/// first generation is refused, so recovery never continues into another
/// account.
///
/// The application bounds the number of supervisors and authorizes
/// resource IDs.
pub struct PluginSupervisor {
    prefix:       String,
    config:       PluginConfig,
    kind:         ProviderKind,
    capabilities: Capabilities,
    /// The resource namespace the first generation reported. Every later
    /// generation must report the same one.
    identity:     Option<String>,
    generations:  Mutex<Generations>,
}

/// The live generation and the count that numbers the next one.
struct Generations {
    live:   Option<Arc<PluginGeneration>>,
    /// How many generations have served; the next is `served + 1`.
    served: u64,
}

/// One launched plugin process: the provider it serves and the number
/// that distinguishes it from every process launched before it.
pub struct PluginGeneration {
    provider: Arc<PluginProvider>,
    number:   u64,
    path:     PathBuf,
    verified: bool,
    health:   ProviderHealth,
}

impl PluginGeneration {
    /// The provider this process serves. Handles obtained through it stay
    /// tied to this generation.
    pub fn provider(&self) -> &Arc<PluginProvider> {
        &self.provider
    }

    /// The generation's position in launch order, from 1. Higher means
    /// later; every handle from a lower number is dead.
    pub fn number(&self) -> u64 {
        self.number
    }

    /// The executable that was launched.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the executable's checksum was verified against the pin
    /// (`false` only in dev mode).
    pub fn verified(&self) -> bool {
        self.verified
    }

    /// The health report the backend gave when this generation launched,
    /// including the resource namespace it addresses.
    pub fn health(&self) -> &ProviderHealth {
        &self.health
    }

    /// Whether the transport to this process has closed. Once it has,
    /// every call through the provider fails and the supervisor answers
    /// the next call from a replacement.
    pub fn is_closed(&self) -> bool {
        self.provider.is_closed()
    }
}

impl PluginSupervisor {
    /// Launches the first generation now, so a misconfigured plugin or an
    /// unready backend fails here rather than on first use, and the
    /// capabilities are known for preflight. The supervisor's kind is the
    /// configured one: the name the host launched the executable under,
    /// which its records and errors speak of; the kind the plugin declares
    /// for itself is on the generation's provider. Freezes forwarded
    /// environment values so replacements cannot inherit a different
    /// credential context from later environment changes.
    pub async fn launch(prefix: impl Into<String>, mut config: PluginConfig) -> Result<Self> {
        for key in mem::take(&mut config.inherit_env) {
            if let Entry::Vacant(entry) = config.env.entry(key) {
                if let Ok(value) = env::var(entry.key()) {
                    entry.insert(value);
                }
            }
        }
        let prefix = prefix.into();
        let first = launch_generation(&prefix, &config, 1).await?;
        Ok(Self {
            prefix,
            kind: config.kind.clone(),
            capabilities: first.provider.capabilities().clone(),
            identity: first.health.identity.clone(),
            config,
            generations: Mutex::new(Generations {
                served: first.number,
                live:   Some(first),
            }),
        })
    }

    /// The live generation, launching a replacement when the current one
    /// has closed. Serializes startup so concurrent callers share a single
    /// replacement. Failed generations and their calls are never rebound
    /// to the replacement.
    pub async fn current(&self) -> Result<Arc<PluginGeneration>> {
        let mut generations = self.generations.lock().await;
        if let Some(live) = generations
            .live
            .as_ref()
            .filter(|generation| !generation.is_closed())
        {
            return Ok(Arc::clone(live));
        }
        if let Some(closed) = generations.live.take() {
            tracing::warn!(
                provider_kind = %self.kind,
                generation = closed.number,
                "plugin transport closed; launching a replacement"
            );
            let _ = closed.provider.shutdown().await;
        }
        let replacement =
            launch_generation(&self.prefix, &self.config, generations.served + 1).await?;
        if replacement.health.identity != self.identity {
            let _ = replacement.provider.shutdown().await;
            return Err(identity_changed(
                &self.kind,
                self.identity.as_deref(),
                replacement.health.identity.as_deref(),
            ));
        }
        generations.served = replacement.number;
        generations.live = Some(Arc::clone(&replacement));
        Ok(replacement)
    }

    /// Asks the current generation to exit and reaps it. A later call
    /// launches a fresh generation.
    pub async fn shutdown(&self) -> Result<()> {
        let mut generations = self.generations.lock().await;
        if let Some(generation) = generations.live.take() {
            generation.provider.shutdown().await?;
        }
        Ok(())
    }

    /// The current generation's snapshot service.
    async fn snapshot_service(&self) -> Result<SnapshotGeneration> {
        let generation = self.current().await?;
        if generation.provider.snapshots().is_none() {
            return Err(Error::unsupported(Capability::Snapshots));
        }
        Ok(SnapshotGeneration(Arc::clone(&generation.provider)))
    }

    /// The current generation's volume service.
    async fn volume_service(&self) -> Result<VolumeGeneration> {
        let generation = self.current().await?;
        if generation.provider.volumes().is_none() {
            return Err(Error::unsupported(Capability::Volumes));
        }
        Ok(VolumeGeneration(Arc::clone(&generation.provider)))
    }
}

/// Launches generation `number`: resolves, verifies, and starts the
/// executable, then probes the backend. A generation whose backend is
/// unreachable or rejects its credential is shut down and never served.
async fn launch_generation(
    prefix: &str,
    config: &PluginConfig,
    number: u64,
) -> Result<Arc<PluginGeneration>> {
    let launched = launch_plugin(prefix, config).await?;
    let provider = Arc::new(launched.provider);
    let health = match provider.health().await {
        Ok(health) => health,
        Err(error) => {
            let _ = provider.shutdown().await;
            return Err(error);
        }
    };
    if let Some(refusal) = health_refusal(&config.kind, &health) {
        let _ = provider.shutdown().await;
        return Err(refusal);
    }
    tracing::info!(
        provider_kind = %config.kind,
        generation = number,
        path = %launched.path.display(),
        verified = launched.verified,
        "plugin generation launched"
    );
    Ok(Arc::new(PluginGeneration {
        provider,
        number,
        path: launched.path,
        verified: launched.verified,
        health,
    }))
}

/// Why a launched plugin must not serve, from its health report: an
/// unreachable backend is a provider failure, a rejected credential an
/// authentication failure. A healthy backend and a provider without a
/// health check both serve, as the conformance suite allows.
fn health_refusal(kind: &ProviderKind, health: &ProviderHealth) -> Option<Error> {
    let detail = health
        .message
        .as_deref()
        .unwrap_or("the plugin gave no detail");
    match health.status {
        HealthStatus::Unreachable => {
            let mut error = ProviderError::new(
                kind.clone(),
                format!("the plugin's backend is unreachable: {detail}"),
            );
            error.code = Some("unreachable".to_owned());
            Some(Error::Provider(error))
        }
        HealthStatus::Unauthorized => {
            let mut reason = format!("the plugin's backend rejected its credential: {detail}");
            if !health.missing_permissions.is_empty() {
                reason.push_str("; missing permissions: ");
                reason.push_str(&health.missing_permissions.join(", "));
            }
            Some(Error::Auth(AuthError::new(kind.clone(), reason)))
        }
        _ => None,
    }
}

/// The refusal for a replacement that addresses a different resource
/// namespace than the generation it replaces.
fn identity_changed(kind: &ProviderKind, first: Option<&str>, replacement: Option<&str>) -> Error {
    let mut error = ProviderError::new(
        kind.clone(),
        format!(
            "the replacement plugin reports resource namespace {}, but the first generation \
             reported {}; recovery does not continue into another account",
            replacement.unwrap_or("none"),
            first.unwrap_or("none")
        ),
    );
    error.code = Some("identity_changed".to_owned());
    Error::Provider(error)
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
        self.current().await?.provider.create(spec, events).await
    }

    async fn attach(
        &self,
        id: &SandboxId,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        self.current().await?.provider.attach(id, events).await
    }

    async fn undelete(
        &self,
        id: &SandboxId,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        self.current().await?.provider.undelete(id, events).await
    }

    async fn delete(&self, id: &SandboxId, events: Option<EventContext>) -> Result<()> {
        self.current().await?.provider.delete(id, events).await
    }

    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>> {
        self.current().await?.provider.list(filter).await
    }

    async fn health(&self) -> Result<ProviderHealth> {
        self.current().await?.provider.health().await
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

#[cfg(test)]
mod tests {
    use super::*;

    fn kind() -> ProviderKind {
        ProviderKind::try_new("somekind").expect("kind")
    }

    #[test]
    fn a_healthy_backend_and_a_provider_without_a_check_both_serve() {
        for status in [HealthStatus::Ok, HealthStatus::Unknown] {
            assert!(
                health_refusal(&kind(), &ProviderHealth::new(status)).is_none(),
                "{status:?}"
            );
        }
    }

    #[test]
    fn an_unreachable_backend_is_a_provider_failure_carrying_the_detail() {
        let mut health = ProviderHealth::new(HealthStatus::Unreachable);
        health.message = Some("pinging the daemon failed".to_owned());
        let error = health_refusal(&kind(), &health).expect("refused");
        assert!(
            matches!(&error, Error::Provider(provider) if provider.code.as_deref() == Some("unreachable")),
            "{error}"
        );
        assert!(error.to_string().contains("pinging the daemon failed"));
    }

    #[test]
    fn a_rejected_credential_is_an_authentication_failure_naming_the_missing_permissions() {
        let mut health = ProviderHealth::new(HealthStatus::Unauthorized);
        health.missing_permissions =
            vec!["read:sandboxes".to_owned(), "write:sandboxes".to_owned()];
        let error = health_refusal(&kind(), &health).expect("refused");
        assert!(matches!(error, Error::Auth(_)), "{error}");
        let message = error.to_string();
        assert!(message.contains("the plugin gave no detail"), "{message}");
        assert!(
            message.contains("read:sandboxes, write:sandboxes"),
            "{message}"
        );
    }

    #[test]
    fn a_changed_namespace_names_both_sides() {
        let error = identity_changed(&kind(), Some("organization:first"), None);
        assert!(
            matches!(&error, Error::Provider(provider) if provider.code.as_deref() == Some("identity_changed")),
            "{error}"
        );
        let message = error.to_string();
        assert!(message.contains("organization:first"), "{message}");
        assert!(message.contains("namespace none"), "{message}");
    }
}
