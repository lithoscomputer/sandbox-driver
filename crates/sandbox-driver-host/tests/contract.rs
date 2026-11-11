//! Host registered as the built-in `host` provider and reached through the
//! shared `Sandboxes` API. Each catalog activates its own Host instance, as
//! a separate process would.
#![cfg(target_os = "linux")]

use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, fs};

use async_trait::async_trait;
use sandbox_driver::ProviderKind;
use sandbox_driver::contract::{
    AccessScope, CapabilitySet, CatalogOptions, Durability, Environment, EnvironmentName, Error,
    ExecControls, ExecSpec, Expose, LabelFilter, ProviderEntry, ProviderName, Registry,
    SandboxSpec, SandboxState, Sandboxes, SecretResolver, ServiceSpec, Source, SourceKind,
    StaticEnvironments, Termination,
};
use sandbox_driver_conformance::contract::{Commands, Conformance};
use sandbox_driver_host::contract::HostFactory;
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::time;

struct NoSecrets;
#[async_trait]
impl SecretResolver for NoSecrets {
    async fn resolve(&self, _: &str) -> Result<Option<String>, Error> {
        Ok(None)
    }
}

/// A catalog with the built-in Host entry `local` and the given environments.
fn catalog(environments: Vec<(&str, SandboxSpec)>) -> Sandboxes {
    let entry: ProviderEntry = serde_json::from_value(json!({"plugin": "host"})).expect("entry");
    let provider = ProviderName::try_new("local").expect("name");
    let environments = environments
        .into_iter()
        .map(|(environment, spec)| {
            (
                EnvironmentName::try_new(environment).expect("environment"),
                Environment {
                    provider: provider.clone(),
                    spec,
                },
            )
        })
        .collect();
    let registry = Registry::new()
        .builtin(
            ProviderKind::try_new("host").expect("kind"),
            Arc::new(HostFactory),
        )
        .expect("registry");
    Sandboxes::try_new(
        [(provider, entry)],
        Arc::new(StaticEnvironments(environments)),
        &registry,
        Arc::new(NoSecrets),
        CatalogOptions::default(),
    )
    .expect("catalog")
}

fn scratch() -> Sandboxes {
    catalog(vec![("scratch", SandboxSpec::new(Source::HostDirectory))])
}

fn alive(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        !stat
            .split_once(") ")
            .is_some_and(|(_, rest)| rest.starts_with('Z'))
    })
}

async fn read_pid(path: &Path) -> u32 {
    time::timeout(Duration::from_secs(10), async {
        loop {
            let text = fs::read_to_string(path).unwrap_or_default();
            if let Ok(pid) = text.trim().parse() {
                return pid;
            }
            time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the command wrote its pid")
}

fn refused<T>(result: Result<T, Error>, capability: &str) {
    match result {
        Err(Error::Unsupported { capability: field }) if field == capability => {}
        Err(other) => panic!("expected {capability} to be unsupported, got {other}"),
        Ok(_) => panic!("expected {capability} to be unsupported"),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[expect(
    clippy::print_stderr,
    reason = "the per-check report is the test's evidence"
)]
async fn host_passes_the_shared_contract() {
    let catalog = scratch();
    // A separately activated catalog is a second Host instance: it must
    // refuse the owner's sandboxes rather than join or steal their fence.
    let peer = scratch();
    let report = Conformance::new(catalog.clone(), "scratch", Commands {
        probe:        ExecSpec::argv(["printf", "conformance probe"]),
        probe_output: b"conformance probe".to_vec(),
        long_running: ExecSpec::argv(["sh", "-c", "echo ready; exec sleep 600"]),
    })
    .with_peer(peer.clone())
    .run()
    .await;
    eprintln!("{report}");
    report.assert_pass();
    catalog.shutdown().await.expect("owner shutdown");
    peer.shutdown().await.expect("peer shutdown");
}

#[tokio::test(flavor = "multi_thread")]
async fn host_advertises_an_owner_process_provider_and_refuses_what_it_cannot_do() {
    let catalog = scratch();
    let descriptor = catalog
        .provider("local")
        .expect("entry")
        .describe()
        .await
        .expect("describe");
    assert_eq!(descriptor.schemas.kind.as_str(), "host");
    assert!(descriptor.namespace.id.as_str().starts_with("host:"));
    assert_eq!(descriptor.durability, Durability::Process);
    assert_eq!(descriptor.access, AccessScope::OwnerProcess);
    assert_eq!(descriptor.sources, [SourceKind::HostDirectory].into());
    assert!(descriptor.resources.is_empty());
    assert_eq!(descriptor.capabilities, CapabilitySet::default());

    let builder = || async { catalog.builder("scratch").await.expect("builder") };
    refused(
        builder().await.image("ubuntu:24.04").create().await,
        "source",
    );
    refused(
        builder().await.memory("1GB").create().await,
        "resources.memory_mb",
    );
    let mut spec = SandboxSpec::new(Source::HostDirectory);
    spec.services.insert(
        "db".into(),
        serde_json::from_value::<ServiceSpec>(json!({"image": "postgres:16"})).expect("service"),
    );
    refused(builder().await.spec(spec).create().await, "services");

    let sandbox = builder().await.create().await.expect("host sandbox");
    let mut tty = ExecSpec::argv(["true"]);
    tty.tty = true;
    refused(sandbox.exec(tty, ExecControls::default()).await, "exec.tty");
    refused(
        sandbox
            .ports()
            .expose(8080.try_into().expect("port"), Expose {
                signed: true,
                ttl_ms: None,
            })
            .await,
        "ports.signed",
    );
    assert!(sandbox.lifecycle().is_none() && sandbox.endpoints().is_none());
    assert!(sandbox.containers().is_none());
    catalog
        .destroy(&sandbox.reference())
        .await
        .expect("destroy");
    catalog.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_fences_and_removes_the_instances_sandboxes() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let designated = env::temp_dir().join(format!("host-designated-{nanos}"));
    fs::create_dir(&designated).expect("designated directory");
    let mut spec = SandboxSpec::new(Source::HostDirectory);
    spec.working_directory = Some(designated.to_string_lossy().into());
    let catalog = catalog(vec![
        ("scratch", SandboxSpec::new(Source::HostDirectory)),
        ("checkout", spec),
    ]);
    let create = async |environment: &str| {
        catalog
            .builder(environment)
            .await
            .expect("builder")
            .create()
            .await
    };
    let managed = create("scratch").await.expect("managed");
    let caller_owned = create("checkout").await.expect("designated");
    assert!(
        matches!(create("checkout").await, Err(Error::Busy { .. })),
        "one live owner per designated directory"
    );
    caller_owned
        .files()
        .put("kept.txt", Box::pin(Cursor::new(b"kept".to_vec())))
        .await
        .expect("put");
    let managed_workspace = managed.working_directory().to_owned();
    let exec = tokio::spawn(async move {
        managed
            .exec(
                ExecSpec::argv(["sh", "-c", "echo $$ > pid; exec sleep 600"]),
                ExecControls::default(),
            )
            .await
    });
    let command = read_pid(&managed_workspace.join("pid")).await;

    catalog.shutdown().await.expect("bounded owner cleanup");
    assert!(!alive(command), "shutdown fenced the running command");
    assert!(!managed_workspace.exists(), "managed workspace removed");
    assert_eq!(
        fs::read(designated.join("kept.txt")).expect("kept"),
        b"kept"
    );
    if let Ok(outcome) = exec.await.expect("exec task") {
        assert_ne!(outcome.termination, Termination::Exited);
    }
    fs::remove_dir_all(&designated).expect("cleanup");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_instance_cannot_operate_a_live_owners_sandbox() {
    let owner = scratch();
    let other = scratch();
    let sandbox = owner
        .builder("scratch")
        .await
        .expect("builder")
        .create()
        .await
        .expect("sandbox");
    let reference = sandbox.reference();
    for result in [
        other.attach(&reference).await.map(|_| ()),
        other.destroy(&reference).await,
    ] {
        assert!(
            matches!(result, Err(Error::Busy { .. })),
            "a live owner's sandbox is busy elsewhere: {result:?}"
        );
    }
    assert!(
        other
            .find(LabelFilter::default())
            .await
            .expect("find")
            .sandboxes
            .is_empty(),
        "inventory is per owner"
    );
    assert_eq!(
        sandbox.status().await.expect("status").state,
        SandboxState::Running
    );
    let mut bytes = Vec::new();
    sandbox
        .files()
        .put("note", Box::pin(Cursor::new(b"owner".to_vec())))
        .await
        .expect("put");
    sandbox
        .files()
        .get("note", None)
        .await
        .expect("get")
        .read_to_end(&mut bytes)
        .await
        .expect("read");
    assert_eq!(bytes, b"owner");
    owner.shutdown().await.expect("owner shutdown");
    other.shutdown().await.expect("other shutdown");
}
