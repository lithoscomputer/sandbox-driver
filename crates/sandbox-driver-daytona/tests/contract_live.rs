//! The Daytona built-in on the shared contract, against a real account.
//!
//! Live tests: require `DAYTONA_API_KEY` and create billable sandboxes.
//! Ignored by default; run them with `mise run test:live`.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{env, future};

use async_trait::async_trait;
use futures_util::FutureExt;
use sandbox_driver::contract::{
    ByteStream, CatalogOptions, Environment, EnvironmentName, Error, ExecControls, ExecSpec,
    LabelFilter, OneShotImage, OneShotSpec, OutputSink, ProviderEntry, ProviderName,
    ReadinessCheck, Registry, Sandbox, SandboxSpec, SandboxState, Sandboxes, SecretResolver,
    ServiceSpec, Source, StaticEnvironments, Termination,
};
use sandbox_driver_conformance::contract::{Commands, Conformance};
use sandbox_driver_daytona::contract::DaytonaFactory;
use tokio::io::AsyncReadExt;
use tokio::time;

mod support;

use support::init_diagnostics;

const WORKLOAD_IMAGE: &str = "buildpack-deps:noble";

struct Environ;

#[async_trait]
impl SecretResolver for Environ {
    async fn resolve(&self, name: &str) -> Result<Option<String>, Error> {
        Ok(env::var(name).ok())
    }
}

fn catalog(environments: BTreeMap<&str, SandboxSpec>) -> Sandboxes {
    env::var("DAYTONA_API_KEY").expect("live gate requires DAYTONA_API_KEY");
    let mut config = serde_json::Map::new();
    for (key, var) in [("api_url", "DAYTONA_API_URL"), ("target", "DAYTONA_TARGET")] {
        if let Ok(value) = env::var(var) {
            config.insert(key.to_owned(), value.into());
        }
    }
    let entry: ProviderEntry = serde_json::from_value(serde_json::json!({
        "plugin": "daytona",
        "config": config,
        "secrets": ["DAYTONA_API_KEY"],
    }))
    .expect("valid entry");
    let provider = ProviderName::try_new("cloud").expect("valid name");
    let registry = Registry::new()
        .builtin(DaytonaFactory::kind(), Arc::new(DaytonaFactory))
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

fn workload() -> SandboxSpec {
    let mut spec = SandboxSpec::new(Source::Image(WORKLOAD_IMAGE.to_owned()));
    spec.working_directory = Some("/home/daytona/contract".to_owned());
    // Leaked sandboxes stop and delete themselves.
    spec.timers.auto_stop_ms = Some(30 * 60 * 1000);
    spec
}

fn with_services() -> SandboxSpec {
    let mut spec = SandboxSpec::new(Source::Image(WORKLOAD_IMAGE.to_owned()));
    let mut redis = ServiceSpec::new("redis:7");
    redis.ports = vec![NonZeroU16::new(6379).expect("non-zero")];
    redis.ready = Some(ReadinessCheck {
        command:     vec!["redis-cli".to_owned(), "ping".to_owned()],
        interval_ms: NonZeroU64::new(1000).expect("non-zero"),
        timeout_ms:  NonZeroU64::new(2000).expect("non-zero"),
        deadline_ms: NonZeroU64::new(120_000).expect("non-zero"),
        retries:     NonZeroU32::new(60).expect("non-zero"),
    });
    spec.services.insert("cache".to_owned(), redis);
    spec.env.insert("CI".to_owned(), "1".to_owned());
    spec.timers.auto_stop_ms = Some(30 * 60 * 1000);
    spec
}

fn commands() -> Commands {
    Commands {
        probe:        ExecSpec::argv(["printf", "conformance"]),
        probe_output: b"conformance".to_vec(),
        long_running: ExecSpec::argv(["sh", "-c", "echo ready; exec sleep 600"]),
    }
}

#[expect(
    clippy::print_stderr,
    reason = "the per-check report is the test's evidence"
)]
async fn conformance(environment: &str, spec: SandboxSpec) {
    init_diagnostics();
    let environments = BTreeMap::from([(environment, spec)]);
    let mut conformance = Conformance::new(catalog(environments.clone()), environment, commands())
        // A separately activated instance must join the same stop fence.
        .with_peer(catalog(environments));
    conformance.timeout = Duration::from_secs(1800);
    let report = conformance.run().await;
    eprintln!("{report}");
    report.assert_pass();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DAYTONA_API_KEY; run with `mise run test:live`"]
async fn a_direct_workload_passes_the_shared_contract() {
    conformance("cloud", workload()).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DAYTONA_API_KEY; run with `mise run test:live`"]
async fn a_workload_with_services_passes_the_shared_contract() {
    conformance("services", with_services()).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DAYTONA_API_KEY; run with `mise run test:live`"]
async fn stdin_reaches_a_direct_workload() {
    init_diagnostics();
    let sandboxes = catalog(BTreeMap::from([("cloud", workload())]));
    let sandbox = sandboxes
        .builder("cloud")
        .await
        .expect("environment")
        .label("contract-live", "stdin")
        .create()
        .await
        .expect("create");
    let reference = sandbox.reference();
    let input: Vec<u8> = (0..=255).chain(b"direct stdin\n".iter().copied()).collect();
    let checks = async {
        let (code, length) = run_with_input(sandbox.as_ref(), &["wc", "-c"], Some(&input)).await;
        assert_eq!((code, length.trim()), (0, input.len().to_string().as_str()));
        let (code, echoed) =
            run_with_input(sandbox.as_ref(), &["cat"], Some(b"direct stdin\n")).await;
        assert_eq!((code, echoed.as_str()), (0, "direct stdin\n"));
    };
    let result = AssertUnwindSafe(checks).catch_unwind().await;
    sandboxes
        .destroy(&reference)
        .await
        .expect("destroy confirms removal");
    if let Err(panic) = result {
        panic::resume_unwind(panic);
    }
}

fn capture() -> (OutputSink, Arc<Mutex<Vec<u8>>>) {
    let output = Arc::new(Mutex::new(Vec::new()));
    let sink_output = Arc::clone(&output);
    let sink: OutputSink = Arc::new(move |_, bytes| {
        sink_output.lock().expect("output lock").extend(bytes);
        Box::pin(future::ready(Ok(())))
    });
    (sink, output)
}

async fn run(sandbox: &dyn Sandbox, argv: &[&str]) -> (i32, String) {
    run_with_input(sandbox, argv, None).await
}

async fn run_with_input(
    sandbox: &dyn Sandbox,
    argv: &[&str],
    input: Option<&[u8]>,
) -> (i32, String) {
    let (sink, output) = capture();
    let outcome = sandbox
        .exec(ExecSpec::argv(argv.iter().copied()), ExecControls {
            sink: Some(sink),
            stdin: input.map(|bytes| -> ByteStream { Box::pin(Cursor::new(bytes.to_vec())) }),
            ..ExecControls::default()
        })
        .await
        .expect("exec admitted");
    assert_eq!(outcome.termination, Termination::Exited, "{argv:?}");
    let text = String::from_utf8_lossy(&output.lock().expect("output lock")).into_owned();
    (outcome.exit_code.expect("exited"), text)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DAYTONA_API_KEY; run with `mise run test:live`"]
async fn services_are_ready_reachable_restarted_and_shared_with_one_shots() {
    init_diagnostics();
    let sandboxes = catalog(BTreeMap::from([("services", with_services())]));
    let sandbox = sandboxes
        .builder("services")
        .await
        .expect("environment")
        .label("contract-live", "services")
        .create()
        .await
        .expect("create waits for readiness");
    let reference = sandbox.reference();
    let checks = async {
        // Exec runs in the caller's image, not the runner.
        let (code, release) = run(sandbox.as_ref(), &["cat", "/etc/os-release"]).await;
        assert_eq!(code, 0);
        assert!(release.contains("noble"), "{release}");
        let (_, env) = run(sandbox.as_ref(), &["printenv", "CI"]).await;
        assert_eq!(env.trim(), "1");
        let (code, echoed) =
            run_with_input(sandbox.as_ref(), &["cat"], Some(b"nested stdin\n")).await;
        assert_eq!((code, echoed.as_str()), (0, "nested stdin\n"));
        let status = sandbox.status().await.expect("status");
        let address = &status.services["cache"];
        assert_eq!(address.ports[&6379], 6379);
        let reach = format!(
            "exec 3<>/dev/tcp/{}/6379 && printf 'PING\\r\\n' >&3 && head -c 7 <&3",
            address.host
        );
        let (code, pong) = run(sandbox.as_ref(), &["bash", "-c", &reach]).await;
        assert_eq!((code, pong.trim()), (0, "+PONG"));

        // A one-shot shares the workspace and reaches the service.
        sandbox
            .files()
            .put(
                "shared/marker.txt",
                Box::pin(Cursor::new(b"from-workload".to_vec())),
            )
            .await
            .expect("put");
        let containers = sandbox.containers().expect("containers capability");
        let (sink, output) = capture();
        let mut one_shot = OneShotSpec::new(OneShotImage::Image("redis:7".to_owned()));
        one_shot.entrypoint = Some("sh".to_owned());
        one_shot.args = vec![
            "-c".to_owned(),
            "cat shared/marker.txt && redis-cli -h 127.0.0.1 ping".to_owned(),
        ];
        let outcome = containers
            .run(one_shot, ExecControls {
                sink: Some(sink),
                ..ExecControls::default()
            })
            .await
            .expect("one-shot");
        assert_eq!(outcome.exit_code, Some(0));
        let text = String::from_utf8_lossy(&output.lock().expect("output lock")).into_owned();
        assert!(
            text.contains("from-workload") && text.contains("PONG"),
            "{text}"
        );

        // A marker in the workload container's own filesystem, outside the
        // shared workspace, read where PID 1 is the container's `--init`:
        // only the same container, running again, shows both.
        let generation = format!("{:016x}", rand::random::<u64>());
        let (code, init) = run(sandbox.as_ref(), &[
            "bash",
            "-c",
            &format!("echo {generation} > /var/tmp/sd-generation && cat /proc/1/comm"),
        ])
        .await;
        assert_eq!((code, init.trim()), (0, "docker-init"));

        // The runner's /var/run survives a stop, and a new generation can
        // reuse the pid its containerd had. Record a pid that always exists
        // after restart (the Daytona daemon), so start must clear the stale
        // file instead of waiting on a containerd that is not there.
        let runner = daytona_sdk::Client::new()
            .await
            .expect("Daytona client")
            .get(reference.id.as_str())
            .await
            .expect("runner");
        let planted = runner
            .process()
            .await
            .expect("runner process service")
            .execute_command(
                "sh -c 'echo 1 > /var/run/docker/containerd/containerd.pid'",
                daytona_sdk::ExecuteCommandOptions::default(),
            )
            .await
            .expect("plant a reused containerd pid");
        assert_eq!(planted.exit_code, 0, "{planted:?}");

        // Stop fences the service with the workload; start restores both.
        sandbox.stop().await.expect("stop");
        assert_eq!(
            sandbox.status().await.expect("status").state,
            SandboxState::Stopped
        );
        assert!(matches!(
            sandbox
                .exec(ExecSpec::argv(["true"]), ExecControls::default())
                .await,
            Err(Error::Busy { .. })
        ));
        sandbox.start().await.expect("start rechecks readiness");
        let (code, resumed) = run(sandbox.as_ref(), &[
            "cat",
            "/var/tmp/sd-generation",
            "/proc/1/comm",
        ])
        .await;
        assert_eq!(
            (code, resumed),
            (0, format!("{generation}\ndocker-init\n")),
            "start resumes the same workload container"
        );
        let (code, pong) = run(sandbox.as_ref(), &["bash", "-c", &reach]).await;
        assert_eq!((code, pong.trim()), (0, "+PONG"));
        let mut kept = Vec::new();
        sandbox
            .files()
            .get("shared/marker.txt", None)
            .await
            .expect("get")
            .read_to_end(&mut kept)
            .await
            .expect("read");
        assert_eq!(kept, b"from-workload");
    };
    let result = AssertUnwindSafe(checks).catch_unwind().await;
    sandboxes
        .destroy(&reference)
        .await
        .expect("destroy confirms removal");
    assert!(matches!(
        sandboxes.attach(&reference).await,
        Err(Error::NotFound { .. })
    ));
    if let Err(panic) = result {
        panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DAYTONA_API_KEY; run with `mise run test:live`"]
async fn a_failed_readiness_check_cleans_up_the_runner() {
    init_diagnostics();
    let mut spec = with_services();
    let ready = spec
        .services
        .get_mut("cache")
        .and_then(|service| service.ready.as_mut())
        .expect("check");
    ready.command = vec!["false".to_owned()];
    ready.deadline_ms = NonZeroU64::new(10_000).expect("non-zero");
    let sandboxes = catalog(BTreeMap::from([("broken", spec)]));
    let marker = format!("{:x}", rand::random::<u64>());
    let error = sandboxes
        .builder("broken")
        .await
        .expect("environment")
        .label("contract-live", &marker)
        .create()
        .await
        .err()
        .expect("readiness fails");
    assert!(matches!(error, Error::Unhealthy { .. }), "{error:?}");
    // Create confirmed removal through the sandbox itself; Daytona's
    // listing catches up within seconds and must then show nothing live.
    let mut listed = Vec::new();
    for _ in 0..30 {
        listed = sandboxes
            .find(LabelFilter::eq("contract-live", &marker))
            .await
            .expect("inventory")
            .sandboxes;
        if listed
            .iter()
            .all(|summary| summary.state == SandboxState::Deleted)
        {
            return;
        }
        time::sleep(Duration::from_secs(2)).await;
    }
    panic!("the failed runner is still listed: {listed:?}");
}
