//! Live checks of paths the shared contract cannot drive by itself: boxd
//! putting a machine to sleep, and a snapshot as the source. They reach
//! boxd's API directly to cause those states, so they live in the crate.
//!
//! Live tests: require `BOXD_API_KEY` and create billable machines, each
//! with a delete-after timer. Ignored by default; run them with
//! `mise run test:live:boxd`.

use std::collections::BTreeMap;
use std::env;
use std::io::Cursor;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures_util::FutureExt as _;
use sandbox_driver::{
    CatalogOptions, Environment, EnvironmentName, Error, ExecControls, ExecSpec, ProviderEntry,
    ProviderName, Registry, Sandbox, SandboxSpec, SandboxState, Sandboxes, SecretResolver,
    SnapshotId, Source, StaticEnvironments, Termination,
};
use tokio::io::AsyncReadExt as _;
use tokio::time;
use tokio_util::sync::CancellationToken;

use super::api::{
    CreateSnapshotRequest, DeleteSnapshotRequest, HibernateVmRequest, SuspendVmRequest,
};
use super::connection::{ApiKey, Connection};
use super::{API_KEY, BoxdFactory, spec};

struct Environ;

#[async_trait]
impl SecretResolver for Environ {
    async fn resolve(&self, name: &str) -> Result<Option<String>, Error> {
        Ok(env::var(name).ok())
    }
}

fn catalog(environments: BTreeMap<&str, SandboxSpec>) -> Sandboxes {
    let entry: ProviderEntry = serde_json::from_value(serde_json::json!({
        "plugin": "boxd",
        "secrets": [API_KEY],
    }))
    .expect("valid entry");
    let provider = ProviderName::try_new("boxd").expect("valid name");
    let registry = Registry::new()
        .builtin(BoxdFactory::kind(), Arc::new(BoxdFactory))
        .expect("one registration");
    let environments = environments
        .into_iter()
        .map(|(name, spec)| {
            (
                EnvironmentName::try_new(name).expect("valid name"),
                Environment {
                    provider: provider.clone(),
                    spec,
                },
            )
        })
        .collect();
    Sandboxes::try_new(
        [(provider, entry)],
        Arc::new(StaticEnvironments(environments)),
        &registry,
        Arc::new(Environ),
        CatalogOptions {
            environment: BTreeMap::new(),
            ..CatalogOptions::default()
        },
    )
    .expect("valid catalog")
}

/// boxd's API as the provider reaches it, for causing what the contract
/// cannot.
fn boxd() -> Connection {
    let key = env::var(API_KEY).expect("live gate requires BOXD_API_KEY");
    Connection::new(
        "https://boxd.sh:9443",
        "https://app.boxd.sh/api/v1/auth/token".to_owned(),
        ApiKey(key),
    )
    .expect("connection")
}

fn base() -> SandboxSpec {
    let mut spec = SandboxSpec::new(Source::Image(spec::BASE_IMAGE.to_owned()));
    spec.timers.ttl_ms = Some(60 * 60 * 1000);
    spec
}

fn unique(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    format!("{prefix}-{nanos:x}")
}

async fn read(sandbox: &dyn Sandbox, path: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    sandbox
        .files()
        .get(path, None)
        .await
        .expect("get")
        .read_to_end(&mut bytes)
        .await
        .expect("read");
    bytes
}

async fn state(sandbox: &dyn Sandbox) -> SandboxState {
    sandbox.status().await.expect("status").state
}

async fn until(sandbox: &dyn Sandbox, wanted: SandboxState) {
    for _ in 0..60 {
        if state(sandbox).await == wanted {
            return;
        }
        time::sleep(Duration::from_secs(1)).await;
    }
    panic!("the machine never reached {wanted:?}");
}

/// Runs `checks` against a fresh sandbox and destroys it either way.
async fn with_sandbox(
    sandboxes: &Sandboxes,
    environment: &str,
    checks: impl AsyncFnOnce(&dyn Sandbox),
) {
    let sandbox = sandboxes
        .builder(environment)
        .await
        .expect("environment")
        .label("contract-live", environment)
        .create()
        .await
        .expect("create");
    let result = AssertUnwindSafe(checks(sandbox.as_ref()))
        .catch_unwind()
        .await;
    sandboxes
        .destroy(&sandbox.reference())
        .await
        .expect("destroy confirms removal");
    if let Err(panic) = result {
        panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires BOXD_API_KEY; run with `mise run test:live:boxd`"]
async fn start_brings_back_a_machine_boxd_put_to_sleep() {
    let boxd = boxd();
    let sandboxes = catalog(BTreeMap::from([("sleep", base())]));
    with_sandbox(&sandboxes, "sleep", async |sandbox| {
        let id = sandbox.reference().id.to_string();
        let marker = b"kept while asleep".to_vec();
        sandbox
            .files()
            .put("marker", Box::pin(Cursor::new(marker.clone())))
            .await
            .expect("put");

        let request = boxd.unary(SuspendVmRequest { vm_id: id.clone() }).await;
        boxd.api()
            .suspend_vm(request.unwrap())
            .await
            .expect("suspend");
        assert_eq!(state(sandbox).await, SandboxState::Paused);
        sandbox.start().await.expect("start resumes");
        assert_eq!(read(sandbox, "marker").await, marker);

        let request = boxd.unary(HibernateVmRequest { vm_id: id.clone() }).await;
        boxd.api()
            .hibernate_vm(request.unwrap())
            .await
            .expect("hibernate");
        until(sandbox, SandboxState::Paused).await;
        sandbox.start().await.expect("start wakes");
        assert_eq!(read(sandbox, "marker").await, marker);

        // A sleeping machine is stopped like a running one.
        let request = boxd.unary(SuspendVmRequest { vm_id: id }).await;
        boxd.api()
            .suspend_vm(request.unwrap())
            .await
            .expect("suspend");
        sandbox.stop().await.expect("stop a sleeping machine");
        assert_eq!(state(sandbox).await, SandboxState::Stopped);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires BOXD_API_KEY; run with `mise run test:live:boxd`"]
async fn a_snapshot_is_a_source_and_brings_none_of_its_labels() {
    let boxd = boxd();
    let snapshot = unique("sd-live");
    let sandboxes = catalog(BTreeMap::from([("origin", base())]));
    let checks = with_sandbox(&sandboxes, "origin", async |origin| {
        origin
            .files()
            .put("from-origin", Box::pin(Cursor::new(b"origin".to_vec())))
            .await
            .expect("put");
        let request = boxd
            .unary(CreateSnapshotRequest {
                vm:   origin.reference().id.to_string(),
                name: snapshot.clone(),
            })
            .await
            .unwrap();
        boxd.api().create_snapshot(request).await.expect("snapshot");

        let mut spec = SandboxSpec::new(Source::Snapshot(
            SnapshotId::try_new(snapshot.clone()).expect("snapshot id"),
        ));
        spec.timers.ttl_ms = Some(60 * 60 * 1000);
        let restored = catalog(BTreeMap::from([("restored", spec)]));
        // boxd refuses a snapshot it is still capturing as busy.
        for _ in 0..60 {
            match restored
                .builder("restored")
                .await
                .expect("environment")
                .create()
                .await
            {
                Err(Error::Busy { .. }) => time::sleep(Duration::from_secs(2)).await,
                Ok(copy) => {
                    restored.destroy(&copy.reference()).await.expect("destroy");
                    break;
                }
                Err(error) => panic!("restoring the snapshot: {error}"),
            }
        }
        with_sandbox(&restored, "restored", async |copy| {
            assert_eq!(read(copy, "from-origin").await, b"origin");
            let labels = copy.status().await.expect("status").labels;
            assert_eq!(
                labels,
                BTreeMap::from([("contract-live".to_owned(), "restored".to_owned())])
            );
        })
        .await;
    });
    let result = AssertUnwindSafe(checks).catch_unwind().await;
    let request = boxd
        .unary(DeleteSnapshotRequest {
            name: snapshot,
            ..DeleteSnapshotRequest::default()
        })
        .await
        .unwrap();
    boxd.api()
        .delete_snapshot(request)
        .await
        .expect("delete snapshot");
    if let Err(panic) = result {
        panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires BOXD_API_KEY; run with `mise run test:live:boxd`"]
async fn term_and_kill_are_confirmed_on_images_with_flock() {
    for image in [spec::BASE_IMAGE, "ubuntu:24.04"] {
        let mut spec = base();
        spec.source = Source::Image(image.to_owned());
        let sandboxes = catalog(BTreeMap::from([("stops", spec)]));
        with_sandbox(&sandboxes, "stops", async |sandbox| {
            for (term, expected) in [
                (true, Termination::Terminated),
                (false, Termination::Killed),
            ] {
                let token = CancellationToken::new();
                let mut controls = ExecControls::default();
                if term {
                    controls.term = Some(token.clone());
                } else {
                    controls.kill = Some(token.clone());
                }
                let spec = ExecSpec::argv(["sh", "-c", "sleep 600 & exec sleep 600"]);
                let running = sandbox.exec(spec, controls);
                let stopper = async {
                    time::sleep(Duration::from_secs(2)).await;
                    token.cancel();
                };
                let (outcome, ()) = tokio::join!(running, stopper);
                assert_eq!(outcome.expect("exec").termination, expected, "{image}");
            }
            let mut timed = ExecSpec::argv(["sleep", "600"]);
            timed.timeout_ms = Some(2000);
            let outcome = sandbox
                .exec(timed, ExecControls::default())
                .await
                .expect("exec");
            assert_eq!(outcome.termination, Termination::TimedOut, "{image}");
        })
        .await;
    }
}
