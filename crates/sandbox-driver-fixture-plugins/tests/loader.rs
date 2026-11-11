//! The fixture plugin reached the way an application reaches any third-party
//! plugin: a configured entry, credential-free discovery, the ordinary
//! loader, protocol version 3, and the shared `Sandboxes` API. The fixture is
//! the Host runtime under the `test-host` kind, so its sandboxes are real
//! local processes.
#![cfg(target_os = "linux")]

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, fs, process};

use async_trait::async_trait;
use sandbox_driver::contract::{
    AccessScope, CapabilitySet, CatalogOptions, Durability, Environment, EnvironmentName, Error,
    ExecControls, ExecSpec, Expose, LabelFilter, MutationOutcome, ProviderEntry, ProviderName,
    Registry, SandboxSpec, SandboxState, Sandboxes, SecretResolver, ServiceSpec, Source,
    SourceKind, StaticEnvironments, Termination,
};
use sandbox_driver_conformance::contract::{Commands, Conformance};
use sandbox_driver_protocol::{PluginLoader, file_sha256};
use sandbox_driver_testing::contract::FakeProvider;
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::time;

fn plugin_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sandbox-driver-test-host"))
}

struct NoSecrets;
#[async_trait]
impl SecretResolver for NoSecrets {
    async fn resolve(&self, _: &str) -> Result<Option<String>, Error> {
        Ok(None)
    }
}

fn name(text: &str) -> ProviderName {
    ProviderName::try_new(text).expect("name")
}

async fn pinned_entry(path: &Path) -> ProviderEntry {
    let digest = file_sha256(path).await.expect("checksum");
    serde_json::from_value(json!({"plugin": "test-host", "path": path, "sha256": digest}))
        .expect("entry")
}

/// A catalog with the plugin entry `local` and the `scratch` environment, plus
/// any built-in entries the test adds.
fn catalog(
    entries: Vec<(ProviderName, ProviderEntry)>,
    environments: Vec<(&str, &str, SandboxSpec)>,
    registry: &Registry,
) -> Sandboxes {
    let environments = environments
        .into_iter()
        .map(|(environment, provider, spec)| {
            (
                EnvironmentName::try_new(environment).expect("environment"),
                Environment {
                    provider: name(provider),
                    spec,
                },
            )
        })
        .collect();
    Sandboxes::try_new(
        entries,
        Arc::new(StaticEnvironments(environments)),
        registry,
        Arc::new(NoSecrets),
        CatalogOptions::default(),
    )
    .expect("catalog")
}

async fn plugin_catalog() -> Sandboxes {
    let registry = Registry::new().plugins(Arc::new(PluginLoader::default()));
    catalog(
        vec![(name("local"), pinned_entry(&plugin_binary()).await)],
        vec![("scratch", "local", SandboxSpec::new(Source::HostDirectory))],
        &registry,
    )
}

/// Plugin processes this test process started. The kernel truncates
/// the command name to 15 bytes.
fn plugin_children() -> Vec<u32> {
    let parent = process::id().to_string();
    fs::read_dir("/proc")
        .expect("procfs")
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
                return false;
            };
            let Some((comm, rest)) = stat.split_once(") ") else {
                return false;
            };
            let mut fields = rest.split_whitespace();
            let (state, ppid) = (fields.next(), fields.next());
            comm.ends_with("(sandbox-driver-") && state != Some("Z") && ppid == Some(&parent)
        })
        .collect()
}

fn alive(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        !stat
            .split_once(") ")
            .is_some_and(|(_, rest)| rest.starts_with('Z'))
    })
}

async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    time::timeout(Duration::from_secs(10), async {
        while !condition() {
            time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting until {what}"));
}

async fn read_pid(path: &Path) -> u32 {
    wait_until("the command wrote its pid", || path.exists()).await;
    let mut text = String::new();
    while text.trim().is_empty() {
        text = fs::read_to_string(path).expect("pid file");
    }
    text.trim().parse().expect("pid")
}

fn refused<T>(result: Result<T, Error>, capability: &str) {
    match result {
        Err(Error::Unsupported { capability: field }) if field == capability => {}
        Err(other) => panic!("expected {capability} to be unsupported, got {other}"),
        Ok(_) => panic!("expected {capability} to be unsupported"),
    }
}

fn commands() -> Commands {
    Commands {
        probe:        ExecSpec::argv(["printf", "conformance probe"]),
        probe_output: b"conformance probe".to_vec(),
        long_running: ExecSpec::argv(["sh", "-c", "echo ready; exec sleep 600"]),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[expect(
    clippy::print_stderr,
    reason = "the per-check report is the test's evidence"
)]
async fn the_plugin_passes_the_shared_contract_through_the_loader() {
    let catalog = plugin_catalog().await;
    // A separately activated catalog is a second plugin instance: it must
    // refuse the owner's sandboxes rather than join or steal their fence.
    let peer = plugin_catalog().await;
    let report = Conformance::new(catalog.clone(), "scratch", commands())
        .with_peer(peer.clone())
        .run()
        .await;
    eprintln!("{report}");
    report.assert_pass();
    catalog.shutdown().await.expect("owner shutdown");
    peer.shutdown().await.expect("peer shutdown");
}

#[tokio::test(flavor = "multi_thread")]
async fn refusals_and_descriptor_facts_cross_the_process_boundary() {
    let catalog = plugin_catalog().await;
    let descriptor = catalog
        .provider("local")
        .expect("entry")
        .describe()
        .await
        .expect("describe");
    assert_eq!(descriptor.schemas.kind.as_str(), "test-host");
    assert!(descriptor.namespace.id.as_str().starts_with("host:"));
    assert_eq!(descriptor.durability, Durability::Process);
    assert_eq!(descriptor.access, AccessScope::OwnerProcess);
    assert_eq!(descriptor.sources, [SourceKind::HostDirectory].into());
    assert!(descriptor.resources.is_empty());
    assert_eq!(descriptor.capabilities, CapabilitySet::default());
    assert_eq!(plugin_children().len(), 1, "one child per activated entry");

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

    let sandbox = builder().await.create().await.expect("sandbox");
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
async fn plugin_death_is_honest_and_restarting_restores_only_the_transport() {
    let catalog = plugin_catalog().await;
    let sandbox = catalog
        .builder("scratch")
        .await
        .expect("builder")
        .create()
        .await
        .expect("sandbox");
    let reference = sandbox.reference();
    let workspace = sandbox.working_directory().to_owned();
    let script = "echo started >> runs; echo $$ > pid; exec sleep 600";
    let exec = tokio::spawn({
        let catalog = catalog.clone();
        let reference = reference.clone();
        async move {
            let sandbox = catalog.attach(&reference).await.expect("attach");
            sandbox
                .exec(
                    ExecSpec::argv(["sh", "-c", script]),
                    ExecControls::default(),
                )
                .await
        }
    });
    let command = read_pid(&workspace.join("pid")).await;
    let [plugin] = plugin_children()[..] else {
        panic!("expected one plugin child");
    };
    process::Command::new("kill")
        .args(["-KILL", &plugin.to_string()])
        .status()
        .expect("kill plugin");

    // The in-flight command's outcome is unknown, never success or absence.
    match exec.await.expect("exec task") {
        Err(Error::Transport {
            outcome: MutationOutcome::Unknown,
            ..
        }) => {}
        Ok(outcome) => assert_eq!(outcome.termination, Termination::Lost),
        Err(other) => panic!("expected an unknown outcome, got {other}"),
    }
    // Owner death ends the command it owned.
    wait_until("the owner's command died with it", || !alive(command)).await;
    // The old handle belongs to the dead generation.
    assert!(matches!(sandbox.status().await, Err(Error::Stale { .. })));
    // The next call restarts the plugin: same namespace, new owner. The old
    // sandbox is not adopted, and its absence is not claimed either.
    match catalog.attach(&reference).await {
        Err(Error::Unavailable { .. }) => {}
        Err(other) => panic!("expected the dead owner's sandbox to be unavailable, got {other}"),
        Ok(_) => panic!("a restarted instance adopted a dead owner's sandbox"),
    }
    let replacement = catalog
        .builder("scratch")
        .await
        .expect("builder")
        .create()
        .await
        .expect("restarted plugin serves new work");
    assert_eq!(replacement.reference().namespace, reference.namespace);
    assert_ne!(replacement.reference().id, reference.id);
    assert_eq!(
        fs::read_to_string(workspace.join("runs")).expect("runs"),
        "started\n",
        "nothing was replayed"
    );
    catalog.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_fences_and_removes_the_instances_sandboxes() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let designated = env::temp_dir().join(format!("test-host-designated-{nanos}"));
    fs::create_dir(&designated).expect("designated directory");
    let mut spec = SandboxSpec::new(Source::HostDirectory);
    spec.working_directory = Some(designated.to_string_lossy().into());
    let registry = Registry::new().plugins(Arc::new(PluginLoader::default()));
    let catalog = catalog(
        vec![(name("local"), pinned_entry(&plugin_binary()).await)],
        vec![
            ("scratch", "local", SandboxSpec::new(Source::HostDirectory)),
            ("checkout", "local", spec),
        ],
        &registry,
    );
    let managed = catalog
        .builder("scratch")
        .await
        .expect("builder")
        .create()
        .await
        .expect("managed");
    let caller_owned = catalog
        .builder("checkout")
        .await
        .expect("builder")
        .create()
        .await
        .expect("designated");
    assert!(
        matches!(
            catalog
                .builder("checkout")
                .await
                .expect("builder")
                .create()
                .await,
            Err(Error::Busy { .. })
        ),
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
    let [plugin] = plugin_children()[..] else {
        panic!("expected one plugin child");
    };

    catalog.shutdown().await.expect("bounded owner cleanup");
    assert!(!alive(command), "shutdown fenced the running command");
    assert!(!alive(plugin), "the plugin exited");
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
    let owner = plugin_catalog().await;
    let other = plugin_catalog().await;
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

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_or_changed_plugin_is_a_setup_error_that_spares_other_entries() {
    let fake = FakeProvider::new();
    let registry = Registry::new()
        .plugins(Arc::new(PluginLoader::default()))
        .builtin(FakeProvider::schemas().kind, Arc::new(fake.clone()))
        .expect("built-in fake");
    let absent = env::temp_dir().join("no-such-test-host-plugin");
    let missing: ProviderEntry = serde_json::from_value(
        json!({"plugin": "test-host", "path": absent, "sha256": "0".repeat(64)}),
    )
    .expect("entry");
    let changed: ProviderEntry = serde_json::from_value(
        json!({"plugin": "test-host", "path": plugin_binary(), "sha256": "0".repeat(64)}),
    )
    .expect("entry");
    let fake_entry: ProviderEntry =
        serde_json::from_value(json!({"plugin": "fake"})).expect("entry");
    let catalog = catalog(
        vec![
            (name("missing"), missing),
            (name("changed"), changed),
            (name("fake"), fake_entry),
        ],
        vec![
            (
                "missing-env",
                "missing",
                SandboxSpec::new(Source::HostDirectory),
            ),
            (
                "changed-env",
                "changed",
                SandboxSpec::new(Source::HostDirectory),
            ),
            (
                "cloud",
                "fake",
                SandboxSpec::new(Source::Image("fake:workload".into())),
            ),
        ],
        &registry,
    );
    let setup_error = |result: Result<_, Error>, entry: &str, field: &str| match result {
        Err(Error::InvalidConfig {
            entry: named, path, ..
        }) if named.as_str() == entry && path == field => {}
        Err(other) => panic!("expected invalid {field} for {entry}, got {other}"),
        Ok(_) => panic!("expected invalid {field} for {entry}"),
    };
    setup_error(
        catalog
            .builder("missing-env")
            .await
            .expect("builder")
            .create()
            .await,
        "missing",
        "path",
    );
    setup_error(
        catalog
            .builder("changed-env")
            .await
            .expect("builder")
            .create()
            .await,
        "changed",
        "sha256",
    );
    assert!(
        plugin_children().is_empty(),
        "an untrusted plugin never ran"
    );
    let cloud = catalog
        .builder("cloud")
        .await
        .expect("builder")
        .label("job", "1")
        .create()
        .await
        .expect("the built-in entry is unaffected");
    let found = catalog
        .find(LabelFilter::eq("job", "1"))
        .await
        .expect("find");
    assert_eq!(found.sandboxes.len(), 1);
    assert_eq!(found.sandboxes[0].reference, cloud.reference());
    let mut unavailable = found.unavailable.clone();
    unavailable.sort();
    assert_eq!(unavailable, vec![name("changed"), name("missing")]);
    catalog.shutdown().await.expect("shutdown");
}
