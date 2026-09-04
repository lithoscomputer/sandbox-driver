//! The Docker sandbox's workspace: a volume the sandbox owns, shared with
//! its one-shot containers, and the archive-backed file operations Petri
//! relies on — over the plugin wire and on an Alpine image, which is the
//! smallest userland the image contract promises to serve.
//!
//! Requires a reachable Docker daemon; tests pass trivially without one,
//! as the conformance run does.

use std::collections::HashMap;
use std::process;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bollard::Docker;
use bollard::container::ListContainersOptions;
use sandbox_driver::{
    Error, ExecControls, ExecSpec, OneShotSpec, OutputStream, SandboxFilter, SandboxProvider,
    SandboxSource, SandboxSpec, Termination,
};
use sandbox_driver_docker::DockerProvider;
use sandbox_driver_protocol::{PluginProvider, serve};
use tokio::io::{duplex, split};
use tokio::time;
use tokio_util::sync::CancellationToken;

const ALPINE: &str = "alpine:3.20";
const WORKSPACE: &str = "/workspace";

/// The Docker provider behind the plugin protocol, as Petri drives it.
async fn over_the_wire() -> Option<PluginProvider> {
    let provider = DockerProvider::connect().await.ok()?;
    let (host_side, plugin_side) = duplex(1024 * 1024);
    let (host_read, host_write) = split(host_side);
    let (plugin_read, plugin_write) = split(plugin_side);
    tokio::spawn(serve(Arc::new(provider), plugin_read, plugin_write));
    Some(
        PluginProvider::connect(host_read, host_write)
            .await
            .expect("handshake succeeds"),
    )
}

/// A label value unique to this test process, so a leak check never sees
/// another run's leftovers.
fn marker(label: &str) -> String {
    format!("{label}-{}", process::id())
}

fn alpine_spec(label: &str) -> SandboxSpec {
    SandboxSpec::new(SandboxSource::Image {
        reference: ALPINE.to_owned(),
    })
    .working_directory(WORKSPACE)
    .label("sandbox-driver-workspace-test", marker(label))
}

type Seen = Arc<Mutex<Vec<(OutputStream, Vec<u8>)>>>;

fn recording_controls() -> (ExecControls, Seen) {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let sink_seen = Arc::clone(&seen);
    let controls = ExecControls {
        sink: Some(Arc::new(move |stream, chunk| {
            let seen = Arc::clone(&sink_seen);
            Box::pin(async move {
                seen.lock().expect("seen lock").push((stream, chunk));
                Ok(())
            })
        })),
        ..ExecControls::default()
    };
    (controls, seen)
}

/// Every file operation Petri uses, on Alpine, through the wire: a whole
/// read, a bounded range read, a write into a directory that does not
/// exist yet, binary content, a missing file, and a read past the end.
#[tokio::test(flavor = "multi_thread")]
async fn alpine_file_operations_need_no_bash() {
    let Some(provider) = over_the_wire().await else {
        return;
    };
    let sandbox = provider
        .create(&alpine_spec("files"), None)
        .await
        .expect("create");
    let fs = sandbox.fs();

    let binary: Vec<u8> = (0..70_000u32).map(|i| (i % 253) as u8).collect();
    fs.write("deep/er/dir/blob.bin", &binary)
        .await
        .expect("write into missing parents");
    assert_eq!(fs.read("deep/er/dir/blob.bin").await.expect("read"), binary);
    assert_eq!(
        fs.read_range("deep/er/dir/blob.bin", 65_530, Some(100))
            .await
            .expect("bounded read"),
        binary[65_530..65_630]
    );
    assert_eq!(
        fs.read_range("deep/er/dir/blob.bin", 69_990, None)
            .await
            .expect("read to the end"),
        binary[69_990..]
    );
    assert!(
        fs.read_range("deep/er/dir/blob.bin", 80_000, Some(4))
            .await
            .expect("read past the end")
            .is_empty()
    );
    match fs.read("deep/er/missing.txt").await {
        Err(Error::NotFound { .. }) => {}
        other => panic!("a missing file must be NotFound: {other:?}"),
    }

    // The directories a write created are the container user's, so a
    // later exec can write beside the file without Bash or base64.
    let result = sandbox
        .exec()
        .run(
            &ExecSpec::new("sh")
                .args([
                    "-c",
                    "printf beside > deep/er/dir/beside.txt && ls deep/er/dir",
                ])
                .timeout(Duration::from_secs(30)),
        )
        .await
        .expect("exec");
    assert!(result.success(), "{}", result.stderr_lossy());
    assert_eq!(
        fs.read("deep/er/dir/beside.txt")
            .await
            .expect("read beside"),
        b"beside"
    );
    // An absolute path outside the workspace: the runtime directory is
    // created by the provider's init, its files stay private.
    fs.write("/tmp/sandbox-driver/runtime/new/secret.json", b"{}")
        .await
        .expect("write under the runtime directory");
    let mode = sandbox
        .exec()
        .run(
            &ExecSpec::new("stat")
                .args(["-c", "%a", "/tmp/sandbox-driver/runtime/new/secret.json"])
                .timeout(Duration::from_secs(30)),
        )
        .await
        .expect("stat");
    assert_eq!(mode.stdout_lossy().trim(), "600");

    sandbox.delete().await.expect("delete");
    provider.shutdown().await.expect("shutdown");
}

/// The workspace is the sandbox's own volume: a one-shot container reads
/// what the sandbox wrote and the sandbox reads what the one-shot wrote;
/// `stop` ends a running one-shot; `delete` removes the volume.
#[tokio::test(flavor = "multi_thread")]
async fn a_one_shot_shares_the_workspace_volume() {
    let Some(provider) = over_the_wire().await else {
        return;
    };
    let local = DockerProvider::connect().await.expect("daemon");
    let sandbox = provider
        .create(&alpine_spec("one-shot"), None)
        .await
        .expect("create");
    let one_shot = sandbox.one_shot().expect("docker offers one-shots");

    sandbox
        .fs()
        .write("from-sandbox.txt", b"from-sandbox")
        .await
        .expect("write");
    let (controls, seen) = recording_controls();
    let spec = OneShotSpec::registry(ALPINE)
        .entrypoint("sh")
        .args([
            "-c",
            "cat from-sandbox.txt; printf from-one-shot > from-one-shot.txt; exit 4",
        ])
        .timeout(Duration::from_secs(120));
    let streaming = one_shot.run(&spec, controls).await.expect("one-shot");
    assert_eq!(streaming.result.exit_code, Some(4));
    assert_eq!(streaming.result.termination, Termination::Exited);
    let stdout: Vec<u8> = seen
        .lock()
        .expect("seen lock")
        .iter()
        .filter(|(stream, _)| *stream == OutputStream::Stdout)
        .flat_map(|(_, chunk)| chunk.clone())
        .collect();
    assert_eq!(stdout, b"from-sandbox");
    assert_eq!(
        sandbox
            .fs()
            .read("from-one-shot.txt")
            .await
            .expect("read the one-shot's file"),
        b"from-one-shot"
    );

    // A one-shot still running when the sandbox stops goes with it: the
    // run resolves (its container was killed and removed under it, which
    // reads as a foreign kill or an unobserved end, never a success) and
    // nothing of it is left on the daemon.
    let (controls, _) = recording_controls();
    let sleeper = tokio::spawn({
        let sandbox = Arc::clone(&sandbox);
        async move {
            let spec = OneShotSpec::registry(ALPINE)
                .entrypoint("sleep")
                .args(["300"])
                .timeout(Duration::from_secs(300));
            sandbox
                .one_shot()
                .expect("facet")
                .run(&spec, controls)
                .await
        }
    });
    time::sleep(Duration::from_secs(2)).await;
    assert!(
        !one_shot_containers(sandbox.id().as_str()).await.is_empty(),
        "the sleeping one-shot is running"
    );
    sandbox.stop().await.expect("stop");
    let outcome = time::timeout(Duration::from_secs(60), sleeper)
        .await
        .expect("the one-shot run resolves once its container is gone")
        .expect("join");
    assert!(
        outcome.is_err() || outcome.is_ok_and(|s| !s.result.success()),
        "a swept one-shot does not report a clean exit"
    );
    assert!(
        one_shot_containers(sandbox.id().as_str()).await.is_empty(),
        "stop swept the one-shot container"
    );

    // A term from the caller ends a one-shot the way it ends an exec.
    sandbox.start().await.expect("start");
    let token = CancellationToken::new();
    let stop_after = token.clone();
    tokio::spawn(async move {
        time::sleep(Duration::from_millis(500)).await;
        stop_after.cancel();
    });
    let controls = ExecControls {
        term: Some(token),
        ..ExecControls::default()
    };
    let spec = OneShotSpec::registry(ALPINE)
        .entrypoint("sleep")
        .args(["300"])
        .timeout(Duration::from_secs(120));
    let streaming = one_shot
        .run(&spec, controls)
        .await
        .expect("termed one-shot");
    assert_eq!(streaming.result.termination, Termination::Cancelled);

    let volume = workspace_volume(sandbox.id().as_str()).await;
    assert!(volume.is_some(), "the workspace is a volume");
    sandbox.delete().await.expect("delete");
    let remaining = local
        .list(&{
            let mut filter = SandboxFilter::default();
            filter
                .labels
                .insert("sandbox-driver-workspace-test".into(), marker("one-shot"));
            filter
        })
        .await
        .expect("list");
    assert!(
        remaining.is_empty(),
        "the sandbox is gone: {:?}",
        remaining
            .iter()
            .map(|status| (
                status.id.as_str().to_owned(),
                status.state,
                status.name.clone()
            ))
            .collect::<Vec<_>>()
    );
    let volumes = Docker::connect_with_local_defaults()
        .expect("docker")
        .list_volumes::<String>(None)
        .await
        .expect("volumes");
    let name = volume.expect("volume name");
    assert!(
        !volumes
            .volumes
            .unwrap_or_default()
            .iter()
            .any(|v| v.name == name),
        "delete removed the workspace volume"
    );
    provider.shutdown().await.expect("shutdown");
}

/// A one-shot built from a Dockerfile inside the workspace.
#[tokio::test(flavor = "multi_thread")]
async fn a_one_shot_builds_from_the_workspace() {
    let Some(provider) = over_the_wire().await else {
        return;
    };
    let sandbox = provider
        .create(&alpine_spec("build"), None)
        .await
        .expect("create");
    sandbox
        .fs()
        .write(
            "action/Dockerfile",
            b"FROM alpine:3.20\nCOPY greeting.txt /greeting.txt\nENTRYPOINT [\"cat\", \"/greeting.txt\"]\n",
        )
        .await
        .expect("write dockerfile");
    sandbox
        .fs()
        .write("action/greeting.txt", b"built-greeting")
        .await
        .expect("write context file");
    let tag = format!("sandbox-driver-one-shot-build:{}", process::id());
    let (controls, seen) = recording_controls();
    let spec = OneShotSpec::new(sandbox_driver::OneShotImage::Build {
        context:    "action".to_owned(),
        dockerfile: None,
        tag:        tag.clone(),
        reuse:      false,
    })
    .timeout(Duration::from_secs(300));
    let streaming = sandbox
        .one_shot()
        .expect("facet")
        .run(&spec, controls)
        .await
        .expect("built one-shot");
    assert!(streaming.result.success(), "{:?}", streaming.result);
    let stdout: Vec<u8> = seen
        .lock()
        .expect("seen lock")
        .iter()
        .flat_map(|(_, chunk)| chunk.clone())
        .collect();
    assert_eq!(stdout, b"built-greeting");
    sandbox.delete().await.expect("delete");
    let _ = Docker::connect_with_local_defaults()
        .expect("docker")
        .remove_image(&tag, None, None)
        .await;
    provider.shutdown().await.expect("shutdown");
}

async fn one_shot_containers(sandbox_id: &str) -> Vec<String> {
    let docker = Docker::connect_with_local_defaults().expect("docker");
    let mut filters = HashMap::new();
    filters.insert("label".to_owned(), vec![format!(
        "sh.sandbox-driver.one-shot={sandbox_id}"
    )]);
    docker
        .list_containers(Some(ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        }))
        .await
        .expect("list")
        .into_iter()
        .filter_map(|c| c.id)
        .collect()
}

async fn workspace_volume(sandbox_id: &str) -> Option<String> {
    let docker = Docker::connect_with_local_defaults().expect("docker");
    let inspect = docker
        .inspect_container(sandbox_id, None)
        .await
        .expect("inspect");
    inspect.mounts?.into_iter().find_map(|mount| {
        (mount.destination.as_deref() == Some(WORKSPACE))
            .then_some(mount.name)
            .flatten()
    })
}
