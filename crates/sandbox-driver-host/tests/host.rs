//! End-to-end tests of the host provider against real processes and a
//! real filesystem, doubling as the first conformance exercise of the
//! exec contract, the bash probe, and the exec-derived facets.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, process};

use sandbox_driver::{
    DerivedGit, DerivedSearch, Error, ExecControls, ExecSpec, Git, GitCommitOptions, GrepOptions,
    OutputStream, SandboxFilter, SandboxId, SandboxProvider, SandboxSource, SandboxSpec, Search,
    SpawnSpec, StdioProcessHandle, Termination, WaitOptions, WalkOptions, WorkspaceOwnership,
    activate,
};
use sandbox_driver_host::HostProvider;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::{fs as tokio_fs, time};
use tokio_util::sync::CancellationToken;

type SeenChunks = Arc<Mutex<Vec<(OutputStream, Vec<u8>)>>>;

fn host_spec() -> SandboxSpec {
    SandboxSpec::new(SandboxSource::HostDirectory)
}

#[tokio::test]
async fn managed_workspace_is_created_and_removed() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");
    let status = sandbox.describe().await.expect("describe");
    assert_eq!(
        status.workspace_ownership,
        Some(WorkspaceOwnership::Managed)
    );

    let workspace = PathBuf::from(sandbox.working_directory());
    assert!(workspace.is_dir());

    sandbox.delete().await.expect("delete");
    assert!(!workspace.exists());
    sandbox.delete().await.expect("delete is idempotent");
}

#[tokio::test]
async fn designated_workspace_survives_delete() {
    let root = env::temp_dir().join(format!("sd-designated-{}", process::id()));
    tokio_fs::create_dir_all(&root).await.expect("mkdir");
    tokio_fs::write(root.join("keep.txt"), b"precious")
        .await
        .expect("write");

    let provider = HostProvider::new();
    let spec = host_spec().working_directory(root.to_string_lossy());
    let sandbox = provider.create(&spec, None).await.expect("create");
    let status = sandbox.describe().await.expect("describe");
    assert_eq!(
        status.workspace_ownership,
        Some(WorkspaceOwnership::Designated)
    );

    sandbox.delete().await.expect("delete");
    assert!(
        root.join("keep.txt").exists(),
        "delete must never touch a designated directory"
    );
    tokio_fs::remove_dir_all(&root).await.expect("cleanup");
}

#[tokio::test]
async fn activate_passes_the_bash_probe() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");
    activate(sandbox.as_ref(), &WaitOptions::default())
        .await
        .expect("bash probe passes");
    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn exec_honors_env_working_dir_and_stdin() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    let spec = ExecSpec::new("echo \"$GREETING $(basename \"$PWD\")\"; cat")
        .env_var("GREETING", "hello")
        .stdin(b"from-stdin".to_vec())
        .timeout(Duration::from_secs(10));
    let result = sandbox.exec().run(&spec).await.expect("exec");
    assert!(result.success(), "stderr: {}", result.stderr_lossy());
    let stdout = result.stdout_lossy();
    assert!(stdout.starts_with("hello "), "stdout: {stdout}");
    assert!(stdout.contains("from-stdin"));

    sandbox.delete().await.expect("delete");
}

#[expect(
    unsafe_code,
    reason = "the inherited-env filter is only observable by mutating the test process \
              environment; Nextest runs each test in its own process"
)]
#[tokio::test]
async fn exec_filters_inherited_secrets_but_trusts_spec_env() {
    // SAFETY: no other thread reads the environment at this point.
    unsafe { env::set_var("SD_TEST_WORKER_TOKEN", "worker-secret") };

    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    let spec = ExecSpec::new(
        "echo \"${SD_TEST_WORKER_TOKEN:-absent} ${SPEC_DEPLOY_TOKEN:-absent} ${HOME:+home}\"",
    )
    .env_var("SPEC_DEPLOY_TOKEN", "explicit")
    .timeout(Duration::from_secs(10));
    let result = sandbox.exec().run(&spec).await.expect("exec");
    assert!(result.success(), "stderr: {}", result.stderr_lossy());
    assert_eq!(result.stdout_lossy().trim(), "absent explicit home");

    sandbox.delete().await.expect("delete");
}

#[expect(
    unsafe_code,
    reason = "the inherited BASH_ENV drop is only observable by mutating the test process \
              environment; Nextest runs each test in its own process"
)]
#[tokio::test]
async fn exec_never_sources_bash_env() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");
    sandbox
        .fs()
        .write("startup.sh", b"echo startup-ran\n")
        .await
        .expect("write");
    let startup = format!("{}/startup.sh", sandbox.working_directory());
    // SAFETY: no other thread reads the environment at this point.
    unsafe { env::set_var("BASH_ENV", &startup) };

    // Both the inherited and the spec-provided BASH_ENV must be dropped.
    let spec = ExecSpec::new("echo ok")
        .env_var("BASH_ENV", &startup)
        .timeout(Duration::from_secs(10));
    let result = sandbox.exec().run(&spec).await.expect("exec");
    assert!(result.success(), "stderr: {}", result.stderr_lossy());
    assert_eq!(result.stdout_lossy(), "ok\n");

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn exec_timeout_kills_the_process_tree() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    let spec = ExecSpec::new("sleep 30").timeout(Duration::from_millis(300));
    let started = Instant::now();
    let result = sandbox.exec().run(&spec).await.expect("exec resolves");
    assert_eq!(result.termination, Termination::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(10));

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn exec_timeout_lets_the_process_run_its_term_trap() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    // `wait` (unlike a foreground `sleep`) lets bash handle the trap as
    // soon as SIGTERM arrives.
    let spec = ExecSpec::new("trap 'echo cleaned >&2; exit 0' TERM; sleep 30 & wait")
        .timeout(Duration::from_millis(300));
    let result = sandbox.exec().run(&spec).await.expect("exec resolves");
    assert_eq!(result.termination, Termination::TimedOut);
    assert!(
        result.stderr_lossy().contains("cleaned"),
        "the TERM trap must run before SIGKILL; stderr: {}",
        result.stderr_lossy()
    );

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn exec_timeout_fires_after_output_streams_close() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    // `exec >/dev/null 2>&1` drops the pipe write ends, so both output
    // streams reach EOF while the process keeps running — the shape of
    // any daemonizing command. The timeout must still fire.
    let spec = ExecSpec::new("exec >/dev/null 2>&1; sleep 30").timeout(Duration::from_millis(300));
    let started = Instant::now();
    let result = sandbox.exec().run(&spec).await.expect("exec resolves");
    assert_eq!(result.termination, Termination::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(10));

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn exec_cancellation_resolves_with_cancelled() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    let token = CancellationToken::new();
    let controls = ExecControls {
        cancel: Some(token.clone()),
        ..ExecControls::default()
    };
    let cancel_after = token.clone();
    tokio::spawn(async move {
        time::sleep(Duration::from_millis(200)).await;
        cancel_after.cancel();
    });
    let spec = ExecSpec::new("sleep 30");
    let result = sandbox
        .exec()
        .run_streaming(&spec, controls)
        .await
        .expect("exec resolves");
    assert_eq!(result.result.termination, Termination::Cancelled);

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn streaming_separates_streams_and_caps_retention() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    let chunks: SeenChunks = Arc::new(Mutex::new(Vec::new()));
    let sink_chunks = Arc::clone(&chunks);
    let controls = ExecControls {
        sink: Some(Arc::new(move |stream, chunk| {
            let chunks = Arc::clone(&sink_chunks);
            Box::pin(async move {
                chunks.lock().expect("chunks lock").push((stream, chunk));
                Ok(())
            })
        })),
        retained_output_limit: Some(1000),
        ..ExecControls::default()
    };
    let spec = ExecSpec::new("echo err-line >&2; for i in $(seq 1 2000); do echo payload-$i; done")
        .timeout(Duration::from_secs(30));
    let result = sandbox
        .exec()
        .run_streaming(&spec, controls)
        .await
        .expect("exec");

    assert!(result.streams_separated);
    assert!(result.live_streaming);
    assert!(
        result.stdout_capture.omitted_bytes > 0,
        "cap must omit output"
    );
    assert!(result.result.stdout.len() <= 1000);
    // The sink saw everything, including what the buffer omitted.
    let seen = chunks.lock().expect("chunks lock").clone();
    let stderr_seen: Vec<u8> = seen
        .iter()
        .filter(|(stream, _)| *stream == OutputStream::Stderr)
        .flat_map(|(_, chunk)| chunk.clone())
        .collect();
    assert!(String::from_utf8_lossy(&stderr_seen).contains("err-line"));
    let stdout_total: usize = seen
        .iter()
        .filter(|(stream, _)| *stream == OutputStream::Stdout)
        .map(|(_, chunk)| chunk.len())
        .sum();
    assert_eq!(stdout_total, result.stdout_capture.observed_bytes);
    drop(seen);

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn spawn_stdio_round_trips_lines() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    let mut process = sandbox
        .exec()
        .spawn_stdio(&SpawnSpec::new("cat"))
        .await
        .expect("spawn cat");
    process.stdin.write_all(b"ping\n").await.expect("write");
    process.stdin.flush().await.expect("flush");
    let mut reader = BufReader::new(process.stdout);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read");
    assert_eq!(line, "ping\n");

    process.handle.terminate().await;
    let (termination, _code) = process.handle.wait().await;
    assert_eq!(termination, Termination::Cancelled);

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn spawn_stdio_terminate_interrupts_an_inflight_wait() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    let process = sandbox
        .exec()
        .spawn_stdio(&SpawnSpec::new("sleep 30"))
        .await
        .expect("spawn");
    let handle: Arc<dyn StdioProcessHandle> = Arc::from(process.handle);
    let waiter = {
        let handle = Arc::clone(&handle);
        tokio::spawn(async move { handle.wait().await })
    };
    time::sleep(Duration::from_millis(100)).await;

    let started = Instant::now();
    handle.terminate().await;
    let (termination, _code) = waiter.await.expect("waiter");
    assert_eq!(termination, Termination::Cancelled);
    assert!(started.elapsed() < Duration::from_secs(10));

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn filesystem_round_trips() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");
    let fs = sandbox.fs();

    fs.write("nested/dir/file.txt", b"content")
        .await
        .expect("write creates parents");
    assert!(fs.exists("nested/dir/file.txt").await.expect("exists"));
    assert_eq!(
        fs.read("nested/dir/file.txt").await.expect("read"),
        b"content"
    );

    let metadata = fs.metadata("nested/dir/file.txt").await.expect("metadata");
    assert_eq!(metadata.size, 7);

    fs.set_permissions("nested/dir/file.txt", 0o600)
        .await
        .expect("chmod");
    let metadata = fs.metadata("nested/dir/file.txt").await.expect("metadata");
    assert_eq!(metadata.mode, Some(0o600));

    let entries = fs.list_dir(".", 3).await.expect("list");
    assert!(entries.iter().any(|entry| entry.path.ends_with("file.txt")));

    fs.rename("nested/dir/file.txt", "nested/dir/renamed.txt")
        .await
        .expect("rename");
    assert!(!fs.exists("nested/dir/file.txt").await.expect("exists"));
    fs.delete("nested", true).await.expect("recursive delete");
    assert!(!fs.exists("nested").await.expect("exists"));

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn derived_search_works_over_host_exec() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");
    let fs = sandbox.fs();
    fs.write("src/main.rs", b"fn main() { needle(); }\n")
        .await
        .expect("write");
    fs.write("src/lib.rs", b"pub fn other() {}\n")
        .await
        .expect("write");
    fs.write("README.md", b"needle in docs\n")
        .await
        .expect("write");

    let search = DerivedSearch::new(sandbox.exec());
    let matches = search
        .grep("needle", ".", &GrepOptions::default())
        .await
        .expect("grep");
    assert_eq!(matches.len(), 2, "matches: {matches:?}");

    let files = search
        .walk(".", &WalkOptions::default())
        .await
        .expect("walk");
    assert!(files.iter().any(|file| file.path.ends_with("main.rs")));

    let paths = search.glob("src/*.rs", ".").await.expect("glob");
    assert_eq!(paths.len(), 2);

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn derived_git_drives_a_real_repository() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");
    let exec = sandbox.exec();
    let workspace = sandbox.working_directory().to_owned();

    let init = ExecSpec::new("git init -q -b main repo").timeout(Duration::from_secs(30));
    let result = exec.run(&init).await.expect("git init");
    assert!(result.success(), "stderr: {}", result.stderr_lossy());
    let repo = format!("{workspace}/repo");

    let git = DerivedGit::new(exec);
    sandbox
        .fs()
        .write("repo/hello.txt", b"hi\n")
        .await
        .expect("write");
    git.add(&repo, &["hello.txt".to_owned()])
        .await
        .expect("git add");
    let sha = git
        .commit(
            &repo,
            &GitCommitOptions::new("initial commit", "Test", "test@example.com"),
        )
        .await
        .expect("git commit");
    assert_eq!(sha.len(), 40, "sha: {sha}");

    let status = git.status(&repo).await.expect("git status");
    assert_eq!(status.current_branch.as_deref(), Some("main"));
    assert!(
        status.dirty_paths.is_empty(),
        "dirty: {:?}",
        status.dirty_paths
    );

    let branches = git.branches(&repo).await.expect("git branches");
    assert_eq!(branches.current.as_deref(), Some("main"));

    git.checkout(&repo, "feature", true)
        .await
        .expect("git checkout -b");
    let status = git.status(&repo).await.expect("git status");
    assert_eq!(status.current_branch.as_deref(), Some("feature"));

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn attach_and_list_use_the_registry() {
    let provider = HostProvider::new();
    let spec = host_spec().label("run", "42");
    let sandbox = provider.create(&spec, None).await.expect("create");

    let attached = provider.attach(sandbox.id(), None).await.expect("attach");
    assert_eq!(attached.id(), sandbox.id());

    let mut filter = SandboxFilter::default();
    filter.labels.insert("run".into(), "42".into());
    let listed = provider.list(&filter).await.expect("list");
    assert_eq!(listed.len(), 1);

    let missing = SandboxId::try_new("host-unknown").expect("id");
    let Err(error) = provider.attach(&missing, None).await else {
        panic!("attach to an unknown id must fail");
    };
    assert!(
        matches!(error, Error::NotFound { .. }),
        "unexpected: {error}"
    );

    sandbox.delete().await.expect("delete");
}
