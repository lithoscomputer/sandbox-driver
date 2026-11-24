//! The boxd built-in on the shared contract, against a real account.
//!
//! Live tests: require `BOXD_API_KEY` and create billable machines, each
//! with a delete-after timer so a leaked one removes itself. Ignored by
//! default; run them with `mise run test:live:boxd`. `BOXD_REGION` selects
//! a region other than the organization's home region.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use std::{env, future, io};

use async_trait::async_trait;
use futures_util::FutureExt;
use futures_util::future::LocalBoxFuture;
use sandbox_driver::{
    ByteStream, CatalogOptions, Environment, EnvironmentName, Error, ExecControls, ExecSpec,
    LabelFilter, NetworkPolicy, OutputSink, ProviderEntry, ProviderName, Registry, Sandbox,
    SandboxSpec, SandboxState, Sandboxes, SecretResolver, Source, StaticEnvironments, Termination,
};
use sandbox_driver_boxd::BoxdFactory;
use sandbox_driver_conformance::{Commands, Conformance};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

/// boxd's own base image, through its fast path.
const BASE_IMAGE: &str = "boxd";
/// A public OCI image, booted as the machine's root filesystem.
const WORKLOAD_IMAGE: &str = "ubuntu:24.04";

struct Environ;

#[async_trait]
impl SecretResolver for Environ {
    async fn resolve(&self, name: &str) -> Result<Option<String>, Error> {
        Ok(env::var(name).ok())
    }
}

fn catalog(environments: BTreeMap<&str, SandboxSpec>) -> Sandboxes {
    env::var("BOXD_API_KEY").expect("live gate requires BOXD_API_KEY");
    let mut config = serde_json::Map::new();
    if let Ok(region) = env::var("BOXD_REGION") {
        config.insert("region".to_owned(), region.into());
    }
    let entry: ProviderEntry = serde_json::from_value(serde_json::json!({
        "plugin": "boxd",
        "config": config,
        "secrets": ["BOXD_API_KEY"],
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

fn workload() -> SandboxSpec {
    image(WORKLOAD_IMAGE)
}

fn image(reference: &str) -> SandboxSpec {
    let mut spec = SandboxSpec::new(Source::Image(reference.to_owned()));
    spec.working_directory = Some("/workspace/contract".to_owned());
    spec.env.insert("CI".to_owned(), "1".to_owned());
    // Leaked machines delete themselves.
    spec.timers.ttl_ms = Some(60 * 60 * 1000);
    spec
}

fn commands() -> Commands {
    Commands {
        probe:        ExecSpec::argv(["printf", "conformance"]),
        probe_output: b"conformance".to_vec(),
        long_running: ExecSpec::argv(["sh", "-c", "echo ready; exec sleep 600"]),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires BOXD_API_KEY; run with `mise run test:live:boxd`"]
async fn a_machine_passes_the_shared_contract() {
    for reference in [BASE_IMAGE, WORKLOAD_IMAGE] {
        conformance(image(reference)).await;
    }
}

#[expect(
    clippy::print_stderr,
    reason = "the per-check report is the test's evidence"
)]
async fn conformance(spec: SandboxSpec) {
    let environments = BTreeMap::from([("cloud", spec)]);
    let mut conformance = Conformance::new(catalog(environments.clone()), "cloud", commands())
        // A separately activated instance must join the same stop fence.
        .with_peer(catalog(environments));
    conformance.timeout = Duration::from_secs(900);
    let report = conformance.run().await;
    eprintln!("{report}");
    report.assert_pass();
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

async fn run(sandbox: &dyn Sandbox, argv: &[&str], input: Option<&[u8]>) -> (i32, String) {
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

/// Creates a sandbox from `spec`, runs `checks`, and destroys it whether or
/// not they pass.
async fn with_sandbox<F>(name: &str, spec: SandboxSpec, checks: F)
where
    F: for<'a> FnOnce(&'a Sandboxes, &'a dyn Sandbox) -> LocalBoxFuture<'a, ()>,
{
    let sandboxes = catalog(BTreeMap::from([(name, spec)]));
    let sandbox = sandboxes
        .builder(name)
        .await
        .expect("environment")
        .label("contract-live", name)
        .create()
        .await
        .expect("create");
    let reference = sandbox.reference();
    let result = AssertUnwindSafe(checks(&sandboxes, sandbox.as_ref()))
        .catch_unwind()
        .await;
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
#[ignore = "requires BOXD_API_KEY; run with `mise run test:live:boxd`"]
async fn the_workload_gets_its_directory_environment_stdin_and_exit_codes() {
    with_sandbox("workload", workload(), |sandboxes, sandbox| {
        Box::pin(async move {
            let (code, pwd) = run(sandbox, &["pwd"], None).await;
            assert_eq!((code, pwd.trim()), (0, "/workspace/contract"));
            let (_, ci) = run(sandbox, &["printenv", "CI"], None).await;
            assert_eq!(ci.trim(), "1");
            let input: Vec<u8> = (0..=255).chain(b"boxd stdin\n".iter().copied()).collect();
            let (code, length) = run(sandbox, &["wc", "-c"], Some(&input)).await;
            assert_eq!((code, length.trim()), (0, input.len().to_string().as_str()));
            let (code, _) = run(sandbox, &["sh", "-c", "exit 7"], None).await;
            assert_eq!(code, 7);
            // Quoting reaches the program untouched.
            let (_, echoed) = run(sandbox, &["printf", "%s", "a b; $HOME 'q'"], None).await;
            assert_eq!(echoed, "a b; $HOME 'q'");

            // A second handle, attached by reference, sees the same machine.
            let attached = sandboxes
                .attach(&sandbox.reference())
                .await
                .expect("attach");
            assert_eq!(attached.working_directory(), sandbox.working_directory());
            assert_eq!(attached.env(), sandbox.env());
            let found = sandboxes
                .find(LabelFilter::eq("contract-live", "workload"))
                .await
                .expect("find");
            assert_eq!(found.sandboxes.len(), 1, "{found:?}");

            // A timeout ends the command.
            let mut spec = ExecSpec::argv(["sleep", "60"]);
            spec.timeout_ms = Some(2000);
            let outcome = sandbox
                .exec(spec, ExecControls::default())
                .await
                .expect("exec");
            assert_eq!(outcome.termination, Termination::TimedOut);

            // Files written are read back, ranges included.
            sandbox
                .files()
                .put("nested/dir/data.bin", Box::pin(Cursor::new(input.clone())))
                .await
                .expect("put");
            let mut read = Vec::new();
            sandbox
                .files()
                .get("nested/dir/data.bin", None)
                .await
                .expect("get")
                .read_to_end(&mut read)
                .await
                .expect("read");
            assert_eq!(read, input);
            let listed = sandbox.files().list("nested", 1).await.expect("list");
            assert!(
                listed
                    .iter()
                    .any(|entry| entry.path.ends_with("nested/dir/data.bin")),
                "{listed:?}"
            );
        })
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires BOXD_API_KEY; run with `mise run test:live:boxd`"]
async fn a_blocked_network_reaches_nothing_and_status_reports_it() {
    let mut spec = workload();
    spec.network = NetworkPolicy::Block;
    with_sandbox("blocked", spec, |_, sandbox| {
        Box::pin(async move {
            let status = sandbox.status().await.expect("status");
            assert_eq!(status.state, SandboxState::Running);
            assert_eq!(status.network, Some(NetworkPolicy::Block));
            let (code, _) = run(sandbox, &["sh", "-c", "exec 3<>/dev/tcp/1.1.1.1/443"], None).await;
            assert_ne!(code, 0, "egress is blocked");
        })
    })
    .await;
}

/// A file input that fails part way: boxd must keep no partial file.
struct Failing(bool);

impl AsyncRead for Failing {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.0 {
            return Poll::Ready(Err(io::Error::other("source failed")));
        }
        self.0 = true;
        buf.put_slice(&[7; 1024]);
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires BOXD_API_KEY; run with `mise run test:live:boxd`"]
async fn a_write_that_fails_part_way_leaves_no_file() {
    with_sandbox("partial", workload(), |_, sandbox| {
        Box::pin(async move {
            let failed = sandbox
                .files()
                .put("partial.bin", Box::pin(Failing(false)))
                .await;
            assert!(failed.is_err(), "{failed:?}");
            assert!(matches!(
                sandbox.files().get("partial.bin", None).await,
                Err(Error::NotFound { .. })
            ));
        })
    })
    .await;
}
