//! End-to-end tests of the host provider against real processes and a
//! real filesystem, doubling as the first conformance exercise of the
//! exec contract, the bash probe, and the exec-derived facets.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, process};

use async_trait::async_trait;
use sandbox_driver::{
    Action, Capability, Error, Event, EventBody, EventContext, EventObserver, ExecControls,
    ExecSpec, Git, GitCommitOptions, GrepOptions, NetworkPolicy, OutputStream, OwnedProvider,
    Ownership, SandboxFilter, SandboxId, SandboxProvider, SandboxSource, SandboxSpec, Search,
    SpawnSpec, StdioProcessHandle, Termination, WaitOptions, WalkOptions, WorkspaceOwnership,
    activate,
};
use sandbox_driver_host::HostProvider;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::{fs as tokio_fs, time};
use tokio_util::sync::CancellationToken;

type SeenChunks = Arc<Mutex<Vec<(OutputStream, Vec<u8>)>>>;

#[derive(Default)]
struct RecordingEventObserver {
    events: Mutex<Vec<Event>>,
}

#[async_trait]
impl EventObserver for RecordingEventObserver {
    async fn observe(&self, event: Event) {
        self.events.lock().expect("events lock").push(event);
    }
}

fn host_spec() -> SandboxSpec {
    SandboxSpec::new(SandboxSource::HostDirectory)
}

#[tokio::test]
async fn owned_provider_scopes_create_list_attach_and_delete() {
    let plain: Arc<dyn SandboxProvider> = Arc::new(HostProvider::new());
    // A key no other test uses, so the shared registry cannot leak
    // sandboxes into the owned listing.
    let ownership = Ownership::label("sh.test.owned-scope", "true");
    let owned = OwnedProvider::new(Arc::clone(&plain), ownership.clone());

    // A sandbox created through the scope carries the labels, whatever
    // the caller put under the same key.
    let mut spec = host_spec();
    spec.labels
        .insert("sh.test.owned-scope".to_owned(), "false".to_owned());
    spec.labels.insert("team".to_owned(), "platform".to_owned());
    let mine = owned.create(&spec, None).await.expect("owned create");
    let status = mine.describe().await.expect("describe");
    assert!(
        ownership.owns(&status.labels),
        "labels: {:?}",
        status.labels
    );
    assert_eq!(
        status.labels.get("team").map(String::as_str),
        Some("platform")
    );

    // A sandbox created outside the scope is invisible to it.
    let foreign = plain
        .create(&host_spec(), None)
        .await
        .expect("plain create");
    let listed = owned
        .list(&SandboxFilter::default())
        .await
        .expect("owned list");
    assert_eq!(listed.len(), 1, "listed: {listed:?}");
    assert_eq!(listed[0].id, *mine.id());

    let refused = owned
        .attach(foreign.id(), None)
        .await
        .map(|_| ())
        .expect_err("foreign attach is refused");
    assert!(
        matches!(&refused, Error::NotOwned { id, .. } if id == foreign.id().as_str()),
        "{refused}"
    );
    let refused = owned
        .delete(foreign.id(), None)
        .await
        .expect_err("foreign delete is refused");
    assert!(matches!(refused, Error::NotOwned { .. }), "{refused}");
    assert!(
        plain.attach(foreign.id(), None).await.is_ok(),
        "the refused delete left the foreign sandbox alone"
    );

    // Owned operations go through, and an unknown id stays idempotent.
    owned.attach(mine.id(), None).await.expect("owned attach");
    owned.delete(mine.id(), None).await.expect("owned delete");
    owned
        .delete(
            &SandboxId::try_new("host-never-existed").expect("valid id"),
            None,
        )
        .await
        .expect("unknown id deletes idempotently");
    assert!(
        owned
            .list(&SandboxFilter::default())
            .await
            .expect("list")
            .is_empty()
    );

    foreign.delete().await.expect("cleanup");
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
    assert_eq!(sandbox.runtime_directory(), None);

    sandbox.delete().await.expect("delete");
    assert!(!workspace.exists());
    sandbox.delete().await.expect("delete is idempotent");
}

#[tokio::test]
async fn exec_recreates_a_managed_workspace_the_os_cleaned_up() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");
    let workspace = PathBuf::from(sandbox.working_directory());

    // The OS periodically cleans temp directories out from under
    // long-lived workers (macOS /var/folders, systemd-tmpfiles).
    tokio_fs::remove_dir_all(&workspace)
        .await
        .expect("simulate temp cleanup");

    let result = sandbox
        .exec()
        .run(&ExecSpec::new("pwd").timeout(Duration::from_secs(10)))
        .await
        .expect("exec self-heals the workspace");
    assert!(result.success(), "exec failed: {result:?}");
    assert!(workspace.is_dir(), "workspace was recreated");

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn unsupported_creation_fields_return_invalid_spec() {
    let provider = HostProvider::new();
    let mut cases = Vec::new();

    let mut spec = host_spec();
    spec.resources.cpu_cores = Some(1);
    cases.push(("resources", spec));

    let mut spec = host_spec();
    spec.user = Some("sandbox".to_owned());
    cases.push(("user", spec));

    let mut spec = host_spec();
    spec.network = NetworkPolicy::AllowAll;
    cases.push(("network", spec));

    let mut spec = host_spec();
    spec.timers.auto_stop_after_idle = Some(Duration::from_secs(60));
    cases.push(("timers", spec));

    let mut spec = host_spec();
    spec.ephemeral = true;
    cases.push(("ephemeral", spec));

    let mut spec = host_spec();
    spec.public = Some(false);
    cases.push(("public", spec));

    let mut spec = host_spec();
    spec.region = Some("local".to_owned());
    cases.push(("region", spec));

    let mut spec = host_spec();
    spec.provider_config = serde_json::json!({});
    cases.push(("provider_config", spec));

    for (expected_field, spec) in cases {
        let Err(error) = provider.create(&spec, None).await else {
            panic!("unsupported field {expected_field} created a sandbox");
        };
        assert!(
            matches!(&error, Error::InvalidSpec { field, .. } if field == expected_field),
            "expected InvalidSpec for {expected_field}, got {error}"
        );
    }
}

#[tokio::test]
async fn failed_create_pairs_started_with_failed() {
    let observer = Arc::new(RecordingEventObserver::default());
    let context = EventContext::new(observer.clone());

    let provider = HostProvider::new();
    let missing = env::temp_dir().join(format!("sd-missing-{}", process::id()));
    let spec = host_spec().working_directory(missing.to_string_lossy());
    let result = provider.create(&spec, Some(context)).await;
    assert!(
        result.is_err(),
        "create with a missing designated directory must fail"
    );

    let events = observer.events.lock().expect("events lock");
    assert!(
        matches!(
            events.first(),
            Some(Event {
                body: EventBody::OperationStarted {
                    action: Action::Create,
                },
                ..
            })
        ),
        "first event was {:?}",
        events.first()
    );
    assert!(
        matches!(
            events.last(),
            Some(Event {
                body: EventBody::OperationFailed {
                    action: Action::Create,
                    ..
                },
                ..
            })
        ),
        "last event was {:?}",
        events.last()
    );
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

    let spec = ExecSpec::bash("echo \"$GREETING $(basename \"$PWD\")\"; cat")
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

    let spec = ExecSpec::bash(
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

    // The helper blanks BASH_ENV itself; a hand-built `bash -c` relies on
    // the inherited variable being dropped from the effective environment.
    for spec in [
        ExecSpec::bash("echo ok"),
        ExecSpec::new("bash").args(["-c", "echo ok"]),
    ] {
        let result = sandbox
            .exec()
            .run(&spec.timeout(Duration::from_secs(10)))
            .await
            .expect("exec");
        assert!(result.success(), "stderr: {}", result.stderr_lossy());
        assert_eq!(result.stdout_lossy(), "ok\n");
    }

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn exec_resolves_the_program_through_the_spec_path() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    // A bare program comes from the command's own PATH, so a spec that
    // sets PATH chooses where its program is found.
    let bin = format!("{}/bin", sandbox.working_directory());
    sandbox
        .fs()
        .write("bin/hello", b"#!/bin/sh\nprintf from-spec-path\n")
        .await
        .expect("write");
    sandbox
        .fs()
        .set_permissions("bin/hello", 0o755)
        .await
        .expect("chmod");
    let spec = ExecSpec::new("hello")
        .env_var("PATH", &bin)
        .timeout(Duration::from_secs(10));
    let result = sandbox.exec().run(&spec).await.expect("exec");
    assert!(result.success(), "stderr: {}", result.stderr_lossy());
    assert_eq!(result.stdout_lossy(), "from-spec-path");

    // An absolute program needs no PATH at all.
    let spec = ExecSpec::new("/bin/echo")
        .arg("ok")
        .env_var("PATH", "/nonexistent")
        .timeout(Duration::from_secs(10));
    let result = sandbox.exec().run(&spec).await.expect("exec");
    assert_eq!(result.stdout_lossy(), "ok\n");

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn exec_timeout_kills_the_process_tree() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    let spec = ExecSpec::new("sleep")
        .arg("30")
        .timeout(Duration::from_millis(300));
    let started = Instant::now();
    let result = sandbox
        .exec()
        .run_streaming(&spec, ExecControls::buffered())
        .await
        .expect("exec resolves")
        .result;
    assert_eq!(result.termination, Termination::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(10));

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn exec_timeout_kills_a_command_that_left_its_process_group() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    // The immediate child replaces itself with a TERM-ignoring process
    // that joins the test runner's process group, so both group signals
    // (aimed at the child's original group, now empty) miss. Only the
    // direct kill fallback ends it before the sleep does.
    let spec = ExecSpec::bash(
        r#"exec perl -e '$SIG{TERM} = "IGNORE"; use POSIX (); POSIX::setpgid(0, getpgrp(getppid())); sleep 30'"#,
    )
    .timeout(Duration::from_millis(300));
    let started = Instant::now();
    let result = sandbox
        .exec()
        .run_streaming(&spec, ExecControls::buffered())
        .await
        .expect("exec resolves")
        .result;
    assert_eq!(result.termination, Termination::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(10));

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn exec_term_lets_the_process_run_its_term_trap() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    // `wait` (unlike a foreground `sleep`) lets bash handle the trap as
    // soon as SIGTERM arrives. The term is the caller's signal; a timeout
    // would kill instead.
    let term = CancellationToken::new();
    let term_after = term.clone();
    tokio::spawn(async move {
        time::sleep(Duration::from_millis(300)).await;
        term_after.cancel();
    });
    let controls = ExecControls {
        term: Some(term),
        ..ExecControls::buffered()
    };
    let spec = ExecSpec::bash("trap 'echo cleaned >&2; exit 0' TERM; sleep 30 & wait");
    let result = sandbox
        .exec()
        .run_streaming(&spec, controls)
        .await
        .expect("exec resolves")
        .result;
    assert_eq!(result.termination, Termination::Cancelled);
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
    let spec = ExecSpec::bash("exec >/dev/null 2>&1; sleep 30").timeout(Duration::from_millis(300));
    let started = Instant::now();
    let result = sandbox
        .exec()
        .run_streaming(&spec, ExecControls::buffered())
        .await
        .expect("exec resolves")
        .result;
    assert_eq!(result.termination, Termination::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(10));

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn exec_term_resolves_with_cancelled() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");

    let token = CancellationToken::new();
    let controls = ExecControls {
        term: Some(token.clone()),
        ..ExecControls::buffered()
    };
    let cancel_after = token.clone();
    tokio::spawn(async move {
        time::sleep(Duration::from_millis(200)).await;
        cancel_after.cancel();
    });
    let spec = ExecSpec::new("sleep").arg("30");
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
        ..ExecControls::buffered()
    };
    let spec =
        ExecSpec::bash("echo err-line >&2; for i in $(seq 1 2000); do echo payload-$i; done")
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
        .spawn_stdio(&SpawnSpec::new("sleep").arg("30"))
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
async fn normalized_search_works_over_host_exec() {
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

    assert!(sandbox.capabilities().supports(Capability::Search));
    assert!(!sandbox.capabilities().search.native);
    let search = sandbox.search().expect("search facet");
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

    // A missing root is an empty result, not an error.
    let missing = search
        .walk("does-not-exist", &WalkOptions::default())
        .await
        .expect("walk of a missing root");
    assert!(missing.is_empty());
    let missing = search
        .glob("*.rs", "does-not-exist")
        .await
        .expect("glob under a missing root");
    assert!(missing.is_empty());

    // Excluding a directory name must not hide a regular file with
    // that name.
    fs.write("node_modules", b"a file, not a directory\n")
        .await
        .expect("write");
    let options = {
        let mut options = WalkOptions::default();
        options.exclude_dirs.push("node_modules".to_owned());
        options
    };
    let files = search.walk(".", &options).await.expect("walk");
    assert!(
        files.iter().any(|file| file.path == "node_modules"),
        "files: {files:?}"
    );

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn pinned_clone_attaches_the_admitted_branch() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");
    let exec = sandbox.exec();
    let workspace = sandbox.working_directory().to_owned();

    // A source repo whose main advanced past the commit being pinned.
    let setup = ExecSpec::bash(
        "git init -q -b main src && cd src && \
         git -c user.name=T -c user.email=t@example.com commit -q --allow-empty -m one && \
         git rev-parse HEAD && \
         git -c user.name=T -c user.email=t@example.com commit -q --allow-empty -m two && \
         git config uploadpack.allowReachableSHA1InWant true",
    )
    .timeout(Duration::from_secs(30));
    let result = exec.run(&setup).await.expect("source repo setup");
    assert!(result.success(), "stderr: {}", result.stderr_lossy());
    let pinned = result.stdout_lossy().trim().to_owned();
    assert_eq!(pinned.len(), 40, "sha: {pinned}");

    let git = sandbox.git().expect("git facet");
    let mut options = sandbox_driver::GitCloneOptions::default();
    options.branch = Some("main".to_owned());
    options.commit = Some(pinned.clone());
    options.depth = Some(1);
    git.clone_repo(&format!("file://{workspace}/src"), "dst", &options)
        .await
        .expect("pinned clone");

    let repo = format!("{workspace}/dst");
    let status = git.status(&repo).await.expect("git status");
    assert_eq!(status.current_branch.as_deref(), Some("main"));
    assert!(!status.detached);
    let head = exec
        .run(
            &ExecSpec::new("git")
                .args(["-C", &repo, "rev-parse", "HEAD"])
                .timeout(Duration::from_secs(10)),
        )
        .await
        .expect("rev-parse");
    assert_eq!(head.stdout_lossy().trim(), pinned);

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn tag_pinned_clone_attaches_the_admitted_branch() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");
    let exec = sandbox.exec();
    let workspace = sandbox.working_directory().to_owned();

    // A source repo whose main advanced past the tagged commit, with a
    // branch that shares the tag's name so a short-name lookup would
    // pick the wrong revision.
    let setup = ExecSpec::bash(
        "git init -q -b main src && cd src && \
         git -c user.name=T -c user.email=t@example.com commit -q --allow-empty -m one && \
         git -c user.name=T -c user.email=t@example.com tag -a -m release v1.0.0 && \
         git rev-parse HEAD^{commit} && \
         git -c user.name=T -c user.email=t@example.com commit -q --allow-empty -m two && \
         git branch v1.0.0 HEAD",
    )
    .timeout(Duration::from_secs(30));
    let result = exec.run(&setup).await.expect("source repo setup");
    assert!(result.success(), "stderr: {}", result.stderr_lossy());
    let tagged = result.stdout_lossy().trim().to_owned();
    assert_eq!(tagged.len(), 40, "sha: {tagged}");

    let git = sandbox.git().expect("git facet");
    let mut options = sandbox_driver::GitCloneOptions::default();
    options.branch = Some("main".to_owned());
    options.tag = Some("v1.0.0".to_owned());
    options.depth = Some(1);
    git.clone_repo(&format!("file://{workspace}/src"), "dst", &options)
        .await
        .expect("tag clone");

    let repo = format!("{workspace}/dst");
    let status = git.status(&repo).await.expect("git status");
    assert_eq!(status.current_branch.as_deref(), Some("main"));
    assert!(!status.detached);
    let head = exec
        .run(
            &ExecSpec::new("git")
                .args(["-C", &repo, "rev-parse", "HEAD"])
                .timeout(Duration::from_secs(10)),
        )
        .await
        .expect("rev-parse");
    assert_eq!(head.stdout_lossy().trim(), tagged);

    // A missing tag fails instead of leaving a branch-head checkout.
    let mut missing = sandbox_driver::GitCloneOptions::default();
    missing.branch = Some("main".to_owned());
    missing.tag = Some("v9.9.9".to_owned());
    git.clone_repo(&format!("file://{workspace}/src"), "missing", &missing)
        .await
        .expect_err("missing tag fails");
    let leftover = exec
        .run(
            &ExecSpec::new("git")
                .args([
                    "-C",
                    &format!("{workspace}/missing"),
                    "rev-parse",
                    "--verify",
                    "HEAD",
                ])
                .timeout(Duration::from_secs(10)),
        )
        .await
        .expect("rev-parse");
    assert!(!leftover.success(), "a failed tag clone left a checkout");

    sandbox.delete().await.expect("delete");
}

#[tokio::test]
async fn normalized_git_drives_a_real_repository() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");
    let exec = sandbox.exec();
    let workspace = sandbox.working_directory().to_owned();

    let init = ExecSpec::new("git")
        .args(["init", "-q", "-b", "main", "repo"])
        .timeout(Duration::from_secs(30));
    let result = exec.run(&init).await.expect("git init");
    assert!(result.success(), "stderr: {}", result.stderr_lossy());
    let repo = format!("{workspace}/repo");

    assert!(sandbox.capabilities().supports(Capability::Git));
    assert!(!sandbox.capabilities().git.native);
    let git = sandbox.git().expect("git facet");
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

#[tokio::test]
async fn explicitly_managed_named_workspace_is_owned_across_registry_restarts() {
    let root = env::temp_dir().join(format!("host-managed-{}", process::id()));
    let workspace = root.join("named-workspace");
    let provider = HostProvider::with_registry(root.join("registry"))
        .await
        .expect("registry");
    let mut spec = host_spec().working_directory(workspace.to_string_lossy());
    spec.workspace_ownership = Some(WorkspaceOwnership::Managed);
    let sandbox = provider
        .create(&spec, None)
        .await
        .expect("managed create makes the directory");
    let id = sandbox.id().clone();
    sandbox.fs().write("keep", b"hello").await.expect("write");
    sandbox.stop().await.expect("stop");
    drop(sandbox);
    drop(provider);
    let provider = HostProvider::with_registry(root.join("registry"))
        .await
        .expect("reopen registry");
    let sandbox = provider
        .attach(&id, None)
        .await
        .expect("attach stopped record");
    let bytes = sandbox.fs().read("keep").await.expect("retained bytes");
    sandbox.start().await.expect("restart");
    sandbox
        .delete()
        .await
        .expect("provider deletes its explicitly owned directory");
    assert_eq!(bytes, b"hello");
    assert!(!workspace.exists());
    tokio_fs::remove_dir_all(root)
        .await
        .expect("registry cleanup");
}

#[tokio::test]
async fn exec_and_stdio_preserve_high_exit_codes() {
    let provider = HostProvider::new();
    let sandbox = provider.create(&host_spec(), None).await.expect("create");
    for code in [129, 130, 143, 255] {
        let script = format!("exit {code}");
        let result = sandbox
            .exec()
            .run(&ExecSpec::bash(&script))
            .await
            .expect("exec");
        let process = sandbox
            .exec()
            .spawn_stdio(&SpawnSpec::new("sh").args(["-c", &script]))
            .await
            .expect("stdio");
        assert_eq!(result.exit_code, Some(code));
        assert_eq!(
            process.handle.wait().await,
            (Termination::Exited, Some(code))
        );
    }
    sandbox.delete().await.expect("cleanup");
}
