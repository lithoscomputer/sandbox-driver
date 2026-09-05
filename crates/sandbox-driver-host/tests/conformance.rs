//! The host provider against the black-box conformance suite.

use std::sync::Arc;

use sandbox_driver::{
    Capabilities, EventContext, OneShotCaps, ProviderKind, Result, Sandbox, SandboxFilter,
    SandboxId, SandboxProvider, SandboxSource, SandboxSpec, SandboxStatus,
};
use sandbox_driver_conformance::{Conformance, Outcome, SpecFactory};
use sandbox_driver_host::HostProvider;

#[tokio::test(flavor = "multi_thread")]
async fn host_provider_passes_conformance() {
    let provider = Arc::new(HostProvider::new());
    let specs = SpecFactory::new(|| SandboxSpec::new(SandboxSource::HostDirectory));
    let report = Conformance::new(provider, specs).run().await;
    report.assert_pass();
}

/// Models a provider whose other sandbox classes offer optional facets.
struct BroaderProvider {
    host: HostProvider,
    caps: Capabilities,
}

#[async_trait::async_trait]
impl SandboxProvider for BroaderProvider {
    fn kind(&self) -> &ProviderKind {
        self.host.kind()
    }

    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    async fn create(
        &self,
        spec: &SandboxSpec,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        self.host.create(spec, events).await
    }

    async fn attach(
        &self,
        id: &SandboxId,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        self.host.attach(id, events).await
    }

    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>> {
        self.host.list(filter).await
    }
}

#[tokio::test]
async fn conformance_respects_optional_facets_narrowed_by_the_sandbox() {
    let host = HostProvider::new();
    let mut caps = host.capabilities().clone();
    caps.access.ssh = true;
    caps.one_shot = Some(OneShotCaps::default());
    let provider = Arc::new(BroaderProvider { host, caps });
    // No one-shot image: this sandbox has no one-shot facet to exercise.
    let specs = SpecFactory::new(|| SandboxSpec::new(SandboxSource::HostDirectory));
    let report = Conformance::new(provider, specs)
        .run_matching(|name| {
            matches!(
                name,
                "ssh_access_matches_capabilities" | "one_shot_shares_the_sandbox_world"
            )
        })
        .await;
    report.assert_pass();
    assert_eq!(report.results.len(), 2);
    assert!(
        report
            .results
            .iter()
            .all(|check| matches!(check.outcome, Outcome::Skipped { .. }))
    );
}
