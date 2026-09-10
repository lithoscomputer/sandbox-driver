//! Ownership scoping over a provider.
//!
//! A provider's backend is shared: a Docker daemon runs containers for
//! every application on the machine, a Daytona organization holds every
//! team's sandboxes, and a Host registry can be pointed anywhere. A
//! consumer that persists sandbox ids therefore needs proof, before it
//! stops or deletes by id, that the sandbox behind the id is still its
//! own. [`OwnedProvider`] carries that proof as labels: it stamps them on
//! every sandbox it creates, narrows every list to sandboxes that carry
//! them, and refuses to attach to or delete a sandbox that does not.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::capabilities::Capabilities;
use crate::error::{Error, ResourceKind, Result};
use crate::event::EventContext;
use crate::id::{ProviderKind, SandboxId};
use crate::provider::{
    ProviderHealth, SandboxFilter, SandboxProvider, SnapshotProvider, VolumeProvider,
};
use crate::sandbox::Sandbox;
use crate::spec::SandboxSpec;
use crate::state::SandboxStatus;

/// The labels that mark a sandbox as one consumer's.
///
/// A sandbox is owned when it carries every label here with the same
/// value. A consumer widens the set to narrow the scope: one label marks
/// everything it manages, one more pins a single run.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ownership {
    labels: BTreeMap<String, String>,
}

impl Ownership {
    /// Ownership by one label.
    pub fn label(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self::default().and_label(key, value)
    }

    /// Adds a label the sandbox must also carry.
    #[must_use]
    pub fn and_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// The labels an owned sandbox carries.
    pub fn labels(&self) -> &BTreeMap<String, String> {
        &self.labels
    }

    /// Whether `labels` carry every ownership label with its value.
    #[must_use]
    pub fn owns(&self, labels: &BTreeMap<String, String>) -> bool {
        self.labels
            .iter()
            .all(|(key, value)| labels.get(key) == Some(value))
    }

    /// Writes the ownership labels into `labels`, replacing any value a
    /// caller gave for the same key: ownership is not the caller's to set.
    pub fn stamp(&self, labels: &mut BTreeMap<String, String>) {
        for (key, value) in &self.labels {
            labels.insert(key.clone(), value.clone());
        }
    }
}

/// A provider narrowed to the sandboxes an [`Ownership`] marks.
///
/// `create` stamps the ownership labels on the spec. `list` adds them to
/// the filter and drops any sandbox the backend returned without them.
/// `attach`, `undelete`, and `delete` check the sandbox's labels first
/// and fail with [`Error::NotOwned`] when they are missing, so a
/// persisted id that now names someone else's sandbox is never acted
/// on. Snapshots, volumes, health, kind, and capabilities pass through:
/// ownership scopes sandboxes only.
///
/// The handle a checked attach returns is the provider's own; a
/// `set_labels` on it replaces the whole label map, so a consumer that
/// rewrites labels keeps the ownership labels in the map.
pub struct OwnedProvider {
    inner:     Arc<dyn SandboxProvider>,
    ownership: Ownership,
}

impl OwnedProvider {
    pub fn new(inner: Arc<dyn SandboxProvider>, ownership: Ownership) -> Self {
        Self { inner, ownership }
    }

    pub fn ownership(&self) -> &Ownership {
        &self.ownership
    }

    /// The provider underneath, for operations that must see every
    /// sandbox (an operator's inventory, a migration).
    pub fn inner(&self) -> &Arc<dyn SandboxProvider> {
        &self.inner
    }

    async fn checked(&self, sandbox: Arc<dyn Sandbox>) -> Result<Arc<dyn Sandbox>> {
        let status = sandbox.describe().await?;
        if self.ownership.owns(&status.labels) {
            return Ok(sandbox);
        }
        tracing::warn!(
            sandbox_id = %sandbox.id(),
            "refusing a sandbox that does not carry the ownership labels"
        );
        Err(Error::NotOwned {
            resource: ResourceKind::Sandbox,
            id:       sandbox.id().as_str().to_owned(),
        })
    }
}

#[async_trait]
impl SandboxProvider for OwnedProvider {
    fn kind(&self) -> &ProviderKind {
        self.inner.kind()
    }

    fn capabilities(&self) -> &Capabilities {
        self.inner.capabilities()
    }

    async fn create(
        &self,
        spec: &SandboxSpec,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        let mut spec = spec.clone();
        self.ownership.stamp(&mut spec.labels);
        self.inner.create(&spec, events).await
    }

    async fn attach(
        &self,
        id: &SandboxId,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        let sandbox = self.inner.attach(id, events).await?;
        self.checked(sandbox).await
    }

    async fn undelete(
        &self,
        id: &SandboxId,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        let sandbox = self.inner.undelete(id, events).await?;
        self.checked(sandbox).await
    }

    async fn delete(&self, id: &SandboxId, events: Option<EventContext>) -> Result<()> {
        // Through the checked attach, so a foreign id is refused rather
        // than swept; an id nobody knows is still idempotently fine.
        match self.attach(id, events).await {
            Ok(sandbox) => sandbox.delete().await,
            Err(Error::NotFound {
                resource: ResourceKind::Sandbox,
                ..
            }) => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>> {
        let mut filter = filter.clone();
        self.ownership.stamp(&mut filter.labels);
        let statuses = self.inner.list(&filter).await?;
        // A backend that ignores label filters still never leaks a
        // foreign sandbox into an owned listing.
        Ok(statuses
            .into_iter()
            .filter(|status| self.ownership.owns(&status.labels))
            .collect())
    }

    async fn health(&self) -> Result<ProviderHealth> {
        self.inner.health().await
    }

    fn snapshots(&self) -> Option<&dyn SnapshotProvider> {
        self.inner.snapshots()
    }

    fn volumes(&self) -> Option<&dyn VolumeProvider> {
        self.inner.volumes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn ownership_requires_every_label_with_its_value() {
        let ownership =
            Ownership::label("sh.fabro.managed", "true").and_label("sh.fabro.run", "r1");
        assert!(ownership.owns(&labels(&[
            ("sh.fabro.managed", "true"),
            ("sh.fabro.run", "r1"),
            ("team", "platform"),
        ])));
        assert!(!ownership.owns(&labels(&[("sh.fabro.managed", "true")])));
        assert!(!ownership.owns(&labels(&[
            ("sh.fabro.managed", "true"),
            ("sh.fabro.run", "r2"),
        ])));
        assert!(!ownership.owns(&labels(&[("sh.fabro.managed", "false")])));
    }

    #[test]
    fn stamping_overrides_a_callers_value_for_an_ownership_key() {
        let ownership = Ownership::label("sh.fabro.managed", "true");
        let mut given = labels(&[("sh.fabro.managed", "false"), ("team", "platform")]);
        ownership.stamp(&mut given);
        assert_eq!(
            given.get("sh.fabro.managed").map(String::as_str),
            Some("true")
        );
        assert_eq!(given.get("team").map(String::as_str), Some("platform"));
    }
}
