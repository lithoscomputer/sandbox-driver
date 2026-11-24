//! The Docker provider through the shared contract's catalog, against a live
//! daemon: the common conformance suite, then the optional capabilities the
//! descriptor declares (services and one-shot containers).

use std::collections::{BTreeMap, HashMap};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bollard::Docker;
use bollard::container::{ListContainersOptions, RemoveContainerOptions};
use bollard::models::ContainerInspectResponse;
use bollard::network::ListNetworksOptions;
use sandbox_driver::{
    AccessScope, CatalogOptions, Durability, Environment, EnvironmentName, Error, ExecControls,
    ExecSpec, LabelFilter, OneShotImage, OneShotSpec, OutputSink, OutputStream, ProviderEntry,
    ProviderKind, ProviderName, ReadinessCheck, Registry, SandboxSpec, SandboxState, Sandboxes,
    SecretResolver, ServiceSpec, Source, StaticEnvironments, TerminalSize, Termination,
};
use sandbox_driver_conformance::{Commands, Conformance};
use sandbox_driver_docker::DockerFactory;
use tokio::io::{self, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time;
use tokio_util::sync::CancellationToken;

const IMAGE: &str = "ghcr.io/fabro-sh/dhi-alpine-base:3.23-dev-2026-06-17";
const SERVICE_IMAGE: &str = "redis:7-alpine";

struct NoSecrets;

#[async_trait]
impl SecretResolver for NoSecrets {
    async fn resolve(&self, _: &str) -> Result<Option<String>, Error> {
        Ok(None)
    }
}

/// A catalog with one `docker` entry and the given environments. Each call
/// activates its own runtime, as a separate process would.
fn catalog(environments: BTreeMap<&str, SandboxSpec>) -> Sandboxes {
    let entry: ProviderEntry =
        serde_json::from_value(serde_json::json!({"plugin": "docker"})).expect("entry");
    let provider = ProviderName::try_new("docker").expect("name");
    let environments = environments
        .into_iter()
        .map(|(name, spec)| {
            (EnvironmentName::try_new(name).expect("name"), Environment {
                provider: provider.clone(),
                spec,
            })
        })
        .collect();
    let registry = Registry::new()
        .builtin(
            ProviderKind::try_new("docker").expect("kind"),
            Arc::new(DockerFactory),
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

/// The daemon the factory connects to by default, whatever `DOCKER_HOST`
/// says, so leftover checks look where the runtime worked.
fn daemon() -> Docker {
    Docker::connect_with_unix("/var/run/docker.sock", 120, bollard::API_DEFAULT_VERSION)
        .expect("docker")
}

fn workload() -> SandboxSpec {
    SandboxSpec::new(Source::Image(IMAGE.to_owned()))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live Docker daemon"]
#[expect(
    clippy::print_stderr,
    reason = "the per-check report is the test's evidence"
)]
async fn docker_passes_the_shared_contract_suite() {
    let catalog = catalog(BTreeMap::from([("default", workload())]));
    let peer = self::catalog(BTreeMap::from([("default", workload())]));
    let descriptor = catalog
        .provider("docker")
        .expect("entry")
        .describe()
        .await
        .expect("describe");
    assert_eq!(descriptor.access, AccessScope::Shared);
    assert_eq!(descriptor.durability, Durability::Machine);
    assert!(descriptor.namespace.id.as_str().starts_with("docker:"));
    let report = Conformance::new(catalog.clone(), "default", Commands {
        probe:        ExecSpec::argv(["printf", "workload\\n"]),
        probe_output: b"workload\n".to_vec(),
        long_running: ExecSpec::argv(["sh", "-c", "echo ready; exec sleep 600"]),
    })
    .with_peer(peer.clone())
    .run()
    .await;
    eprintln!("{report}");
    report.assert_pass();
    peer.shutdown().await.expect("peer shutdown");
    catalog.shutdown().await.expect("shutdown");
}

fn capture() -> (OutputSink, Arc<Mutex<Vec<u8>>>) {
    let output = Arc::new(Mutex::new(Vec::new()));
    let sink_output = Arc::clone(&output);
    let sink: OutputSink = Arc::new(move |_, bytes| {
        sink_output.lock().expect("output").extend(bytes);
        Box::pin(async { Ok(()) })
    });
    (sink, output)
}

/// A service is ready before create returns, reachable by name from a
/// one-shot that shares the workload's workspace, stops with the sandbox,
/// and is ready again after start. Destroy leaves nothing behind.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live Docker daemon"]
async fn services_and_one_shots_share_the_workload() {
    let mut spec = workload();
    let mut redis = ServiceSpec::new(SERVICE_IMAGE);
    redis.ports = vec![NonZeroU16::new(6379).expect("port")];
    redis.ready = Some(ReadinessCheck {
        command:     vec!["redis-cli".to_owned(), "ping".to_owned()],
        interval_ms: NonZeroU64::new(250).expect("interval"),
        timeout_ms:  NonZeroU64::new(2_000).expect("timeout"),
        deadline_ms: NonZeroU64::new(60_000).expect("deadline"),
        retries:     NonZeroU32::new(100).expect("retries"),
    });
    spec.services.insert("cache".to_owned(), redis);
    let catalog = catalog(BTreeMap::from([("services", spec)]));
    let sandbox = catalog
        .builder("services")
        .await
        .expect("builder")
        .label("contract-test", "services")
        .create()
        .await
        .expect("create waits for readiness");
    let reference = sandbox.reference();
    async {
        let status = sandbox.status().await.expect("status");
        let cache = status.services.get("cache").expect("service address");
        assert_eq!(cache.host, "cache");
        assert_eq!(cache.ports.get(&6379), Some(&6379));

        // The one-shot writes into the shared workspace after reaching the
        // service by its name.
        let mut one_shot = OneShotSpec::new(OneShotImage::Image(SERVICE_IMAGE.to_owned()));
        one_shot.entrypoint = Some("sh".to_owned());
        one_shot.args = vec![
            "-c".to_owned(),
            "redis-cli -h cache ping > from-one-shot.txt".to_owned(),
        ];
        let outcome = sandbox
            .containers()
            .expect("containers capability")
            .run(one_shot, ExecControls::default())
            .await
            .expect("one-shot");
        assert_eq!(
            (outcome.termination, outcome.exit_code),
            (Termination::Exited, Some(0))
        );
        let (sink, output) = capture();
        let outcome = sandbox
            .exec(ExecSpec::argv(["cat", "from-one-shot.txt"]), ExecControls {
                sink: Some(sink),
                ..ExecControls::default()
            })
            .await
            .expect("exec");
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(output.lock().expect("output").as_slice(), b"PONG\n");

        sandbox.stop().await.expect("stop");
        let stopped = sandbox.status().await.expect("status");
        assert_eq!(stopped.state, SandboxState::Stopped);
        assert!(
            stopped.services.is_empty(),
            "stopped services are not current"
        );
        sandbox.start().await.expect("start waits for readiness");
        let restarted = sandbox.status().await.expect("status");
        assert!(restarted.services.contains_key("cache"));
    }
    .await;
    catalog.destroy(&reference).await.expect("destroy");
    assert!(matches!(
        catalog.attach(&reference).await.err(),
        Some(Error::NotFound { .. })
    ));
    let docker = daemon();
    let leftovers = docker
        .list_containers(Some(ListContainersOptions::<String> {
            all: true,
            filters: HashMap::from([("label".to_owned(), vec![format!(
                "sh.sandbox-driver.sandbox={}",
                reference.id.as_str()
            )])]),
            ..Default::default()
        }))
        .await
        .expect("list");
    assert!(leftovers.is_empty(), "services left: {leftovers:?}");
}

/// The output a terminal command wrote so far, with the streams it used.
#[derive(Clone, Default)]
struct Screen(Arc<Mutex<(Vec<u8>, Vec<OutputStream>)>>);

impl Screen {
    fn sink(&self) -> OutputSink {
        let screen = self.clone();
        Arc::new(move |stream, bytes| {
            let mut seen = screen.0.lock().expect("screen");
            seen.0.extend(bytes);
            seen.1.push(stream);
            Box::pin(async { Ok(()) })
        })
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("screen").0).into_owned()
    }

    fn streams(&self) -> Vec<OutputStream> {
        self.0.lock().expect("screen").1.clone()
    }

    async fn shows(&self, text: &str) {
        time::timeout(Duration::from_secs(30), async {
            while !self.text().contains(text) {
                time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{text:?} never appeared in {:?}", self.text()));
    }
}

fn size(rows: u16, columns: u16) -> TerminalSize {
    TerminalSize {
        rows:    NonZeroU16::new(rows).expect("rows"),
        columns: NonZeroU16::new(columns).expect("columns"),
    }
}

/// A command run with `tty` has a terminal for its input and output, at
/// the size the caller sets and then at each new size, and its output
/// reaches the sink as the terminal stream.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live Docker daemon"]
async fn a_command_runs_in_a_terminal_that_follows_resizes() {
    let catalog = catalog(BTreeMap::from([("tty", workload())]));
    let sandbox = catalog
        .builder("tty")
        .await
        .expect("builder")
        .label("contract-test", "tty")
        .create()
        .await
        .expect("create");
    let reference = sandbox.reference();
    async {
        let mut spec = ExecSpec::argv([
            "sh",
            "-c",
            "until [ \"$(stty size)\" = '30 100' ]; do sleep 0.1; done; echo first-size; \
             read -r line; \
             until [ \"$(stty size)\" = '40 120' ]; do sleep 0.1; done; echo \"got-$line\"; \
             [ -t 0 ] && [ -t 1 ] && [ -t 2 ] && exit 3",
        ]);
        spec.tty = true;
        spec.timeout_ms = Some(30_000);
        let screen = Screen::default();
        let (mut input, stdin) = io::duplex(1024);
        let (resize, resized) = watch::channel(size(30, 100));
        let exec = sandbox.exec(spec, ExecControls {
            stdin: Some(Box::pin(stdin)),
            sink: Some(screen.sink()),
            resize: Some(resized),
            ..ExecControls::default()
        });
        let typist = async {
            screen.shows("first-size").await;
            resize.send(size(40, 120)).expect("resize");
            input.write_all(b"second\n").await.expect("input");
        };
        let (outcome, ()) = tokio::join!(exec, typist);
        let outcome = outcome.expect("exec");
        assert_eq!(
            (outcome.termination, outcome.exit_code),
            (Termination::Exited, Some(3)),
            "{:?}",
            screen.text()
        );
        assert!(screen.text().contains("got-second"), "{:?}", screen.text());
        let streams = screen.streams();
        assert!(
            !streams.is_empty()
                && streams
                    .iter()
                    .all(|stream| *stream == OutputStream::Terminal),
            "{streams:?}"
        );
    }
    .await;
    catalog.destroy(&reference).await.expect("destroy");
}

/// `term` ends an interactive shell in a terminal, as closing the terminal
/// would, though such a shell ignores SIGTERM, and the hangup also ends
/// the job it runs in the foreground.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live Docker daemon"]
async fn term_ends_an_interactive_shell_in_a_terminal() {
    let catalog = catalog(BTreeMap::from([("tty", workload())]));
    let sandbox = catalog
        .builder("tty")
        .await
        .expect("builder")
        .label("contract-test", "tty-term")
        .create()
        .await
        .expect("create");
    let reference = sandbox.reference();
    async {
        let mut spec = ExecSpec::argv(["sh", "-i"]);
        spec.tty = true;
        let screen = Screen::default();
        let (mut input, stdin) = io::duplex(1024);
        let term = CancellationToken::new();
        let exec = sandbox.exec(spec, ExecControls {
            stdin: Some(Box::pin(stdin)),
            sink: Some(screen.sink()),
            term: Some(term.clone()),
            resize: Some(watch::channel(size(24, 80)).1),
            ..ExecControls::default()
        });
        let user = async {
            input
                .write_all(b"echo started; sleep 600\n")
                .await
                .expect("input");
            screen.shows("started").await;
            term.cancel();
        };
        let (outcome, ()) = tokio::join!(
            async {
                time::timeout(Duration::from_secs(30), exec)
                    .await
                    .expect("the shell ends")
            },
            user
        );
        assert_eq!(
            outcome.expect("exec").termination,
            Termination::Terminated,
            "{:?}",
            screen.text()
        );
        let (sink, output) = capture();
        sandbox
            .exec(ExecSpec::argv(["ps", "-o", "args"]), ExecControls {
                sink: Some(sink),
                ..ExecControls::default()
            })
            .await
            .expect("ps");
        let processes = String::from_utf8_lossy(&output.lock().expect("output")).into_owned();
        assert!(
            !processes.lines().any(|line| line == "sleep 600"),
            "left running: {processes}"
        );
    }
    .await;
    catalog.destroy(&reference).await.expect("destroy");
}

/// Only the caller's labels come back, though the image carries its own,
/// and a stopped sandbox refuses a command instead of reporting it killed.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live Docker daemon"]
async fn labels_round_trip_and_a_stopped_sandbox_refuses_exec() {
    let catalog = catalog(BTreeMap::from([("labels", workload())]));
    let sandbox = catalog
        .builder("labels")
        .await
        .expect("builder")
        .label("contract-test", "labels")
        .create()
        .await
        .expect("create");
    let reference = sandbox.reference();
    async {
        let labels = sandbox.status().await.expect("status").labels;
        assert_eq!(
            labels.get("contract-test").map(String::as_str),
            Some("labels")
        );
        assert!(
            !labels.keys().any(|key| key.starts_with("com.docker.dhi.")),
            "image labels are not the caller's: {labels:?}"
        );
        let found = catalog
            .find(LabelFilter::eq("contract-test", "labels"))
            .await
            .expect("find");
        let [summary] = found.sandboxes.as_slice() else {
            panic!("one sandbox: {found:?}");
        };
        assert_eq!(summary.labels, labels, "list and status agree");
        let by_image_label = catalog
            .find(LabelFilter::eq("com.docker.dhi.shell", "busybox"))
            .await
            .expect("find");
        assert!(
            by_image_label
                .sandboxes
                .iter()
                .all(|found| found.reference != reference),
            "a filter does not match the image's labels"
        );

        sandbox.stop().await.expect("stop");
        let refused = sandbox
            .exec(ExecSpec::argv(["true"]), ExecControls::default())
            .await;
        assert!(refused.is_err(), "exec on a stopped sandbox: {refused:?}");
    }
    .await;
    catalog.destroy(&reference).await.expect("destroy");
}

/// The contract has no resume: `start` brings back a container paused out
/// of band by unpausing it, not by restarting it, and execution resumes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live Docker daemon"]
async fn start_unpauses_a_sandbox_paused_out_of_band() {
    let catalog = catalog(BTreeMap::from([("paused", workload())]));
    let sandbox = catalog
        .builder("paused")
        .await
        .expect("builder")
        .label("contract-test", "paused")
        .create()
        .await
        .expect("create");
    let reference = sandbox.reference();
    let docker = daemon();
    let started_at =
        |inspect: ContainerInspectResponse| inspect.state.and_then(|state| state.started_at);
    async {
        let id = reference.id.as_str();
        let booted = started_at(docker.inspect_container(id, None).await.expect("inspect"));
        docker.pause_container(id).await.expect("pause");
        assert_eq!(
            sandbox.status().await.expect("status").state,
            SandboxState::Paused
        );

        sandbox.start().await.expect("start");
        let inspect = docker.inspect_container(id, None).await.expect("inspect");
        let state = inspect.state.clone().expect("state");
        assert_eq!(state.paused, Some(false));
        assert_eq!(started_at(inspect), booted, "unpaused, not restarted");
        assert_eq!(
            sandbox.status().await.expect("status").state,
            SandboxState::Running
        );
        let (sink, output) = capture();
        let outcome = sandbox
            .exec(ExecSpec::argv(["printf", "resumed"]), ExecControls {
                sink: Some(sink),
                ..ExecControls::default()
            })
            .await
            .expect("exec after start");
        assert_eq!(
            (outcome.termination, outcome.exit_code),
            (Termination::Exited, Some(0))
        );
        assert_eq!(output.lock().expect("output").as_slice(), b"resumed");
    }
    .await;
    catalog.destroy(&reference).await.expect("destroy");
}

/// Unsupported requests fail before anything is created.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live Docker daemon"]
async fn unsupported_requests_are_refused_before_admission() {
    let mut timed = workload();
    timed.timers.auto_stop_ms = Some(60_000);
    let catalog = catalog(BTreeMap::from([("timed", timed)]));
    let error = catalog
        .builder("timed")
        .await
        .expect("builder")
        .label("contract-test", "refused")
        .create()
        .await
        .err();
    assert!(
        matches!(&error, Some(Error::Unsupported { capability }) if capability == "timers.auto_stop_ms"),
        "{error:?}"
    );
    let found = catalog
        .find(LabelFilter::eq("contract-test", "refused"))
        .await
        .expect("find");
    assert!(found.sandboxes.is_empty());
}

/// A primary removed behind the provider's back leaves its services and
/// network. Destroy by ref reconciles them by the owner label instead of
/// reporting an already-absent sandbox as clean.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live Docker daemon"]
async fn destroy_reconciles_services_of_a_vanished_primary() {
    let mut spec = workload();
    spec.services
        .insert("cache".to_owned(), ServiceSpec::new(SERVICE_IMAGE));
    let catalog = catalog(BTreeMap::from([("orphans", spec)]));
    let sandbox = catalog
        .builder("orphans")
        .await
        .expect("builder")
        .create()
        .await
        .expect("create");
    let reference = sandbox.reference();
    let docker = daemon();
    let owned = || async {
        let filter = HashMap::from([("label".to_owned(), vec![format!(
            "sh.sandbox-driver.sandbox={}",
            reference.id.as_str()
        )])]);
        let containers = docker
            .list_containers(Some(ListContainersOptions {
                all: true,
                filters: filter.clone(),
                ..Default::default()
            }))
            .await
            .expect("list containers");
        let networks = docker
            .list_networks(Some(ListNetworksOptions { filters: filter }))
            .await
            .expect("list networks");
        (containers.len(), networks.len())
    };
    assert_eq!(owned().await, (1, 1), "one service on one network");
    docker
        .remove_container(
            reference.id.as_str(),
            Some(RemoveContainerOptions {
                force: true,
                v: true,
                ..Default::default()
            }),
        )
        .await
        .expect("remove primary directly");
    catalog
        .destroy(&reference)
        .await
        .expect("destroy reconciles");
    assert_eq!(owned().await, (0, 0), "services and network removed");
}
