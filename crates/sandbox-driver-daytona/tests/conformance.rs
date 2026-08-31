//! The daytona provider against the black-box conformance suite.
//!
//! Live test: requires `DAYTONA_API_KEY` (and creates roughly a dozen
//! short-lived sandboxes from the default snapshot); skipped when no
//! credentials are configured so CI stays green.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use sandbox_driver::{SandboxKind, SandboxSource, SandboxSpec, SnapshotId};
use sandbox_driver_conformance::{Conformance, SpecFactory};
use sandbox_driver_daytona::DaytonaProvider;

mod support;

use support::init_diagnostics;

const TEST_SNAPSHOT: &str = "daytona-medium";

#[tokio::test(flavor = "multi_thread")]
async fn daytona_provider_passes_conformance() {
    if env::var("DAYTONA_API_KEY").is_err() {
        // No credentials; nothing to verify.
        return;
    }
    init_diagnostics();
    let provider = DaytonaProvider::connect()
        .await
        .expect("connect with credentials");
    let specs = SpecFactory::new(default_spec).with_entrypoint_logs(entrypoint_logs_spec);
    let mut conformance = Conformance::new(Arc::new(provider), specs);
    conformance.check_timeout = Duration::from_secs(900);
    conformance.wait.deadline = Some(Duration::from_secs(300));
    let report = conformance.run().await;
    report.assert_pass();
}

fn default_spec() -> SandboxSpec {
    SandboxSpec::new(SandboxSource::Snapshot {
        id: SnapshotId::try_new(TEST_SNAPSHOT).expect("valid snapshot id"),
    })
    .sandbox_kind(SandboxKind::Container)
    .ephemeral(true)
}

fn entrypoint_logs_spec() -> SandboxSpec {
    SandboxSpec::new(SandboxSource::Dockerfile {
        content: r#"FROM debian:stable-slim
ENTRYPOINT ["/bin/sh", "-c", "echo conformance-entrypoint; echo conformance-entrypoint-error >&2; exec sleep 600"]
"#
        .to_owned(),
    })
    .sandbox_kind(SandboxKind::Container)
    .ephemeral(true)
}
