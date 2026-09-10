//! The doubles honour the driver contracts a consumer relies on.

use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{env, process};

use sandbox_driver::{
    Error, ExecControls, ExecSpec, OutputStream, OwnedProvider, Ownership, Sandbox, SandboxFilter,
    SandboxProvider, SandboxSource, SandboxSpec, SandboxState, Search, StdinSource, Termination,
    WaitOptions, WalkOptions, WalkedFile, activate,
};
use sandbox_driver_testing::{
    ScriptedExec, ScriptedProvider, ScriptedSandbox, ScriptedStdioProcess,
};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn activate_passes_the_probe_without_recording_it() {
    let sandbox = ScriptedSandbox::new().state(SandboxState::Stopped);
    activate(&sandbox, &WaitOptions::default())
        .await
        .expect("activate");
    assert_eq!(sandbox.start_count(), 1);
    assert_eq!(sandbox.current_state(), SandboxState::Running);
    assert!(sandbox.scripted_exec().commands().is_empty());
}

#[tokio::test]
async fn a_failing_probe_makes_activation_fail() {
    let sandbox = ScriptedSandbox::new();
    sandbox.scripted_exec().fail_probe(true);
    let error = activate(&sandbox, &WaitOptions::default())
        .await
        .expect_err("probe fails");
    assert!(matches!(error, Error::Exec(_)), "{error}");
}

#[tokio::test]
async fn scripted_results_answer_in_order_then_the_default() {
    let sandbox = ScriptedSandbox::new();
    let exec = sandbox.scripted_exec();
    exec.push_result(ScriptedExec::ok("first"))
        .push_failure("daemon went away")
        .set_default(ScriptedExec::failed(3, "nope"));

    let first = sandbox
        .exec()
        .run(&ExecSpec::bash("echo first"))
        .await
        .expect("first");
    assert_eq!(first.stdout_lossy(), "first");
    let error = sandbox
        .exec()
        .run(&ExecSpec::new("git").arg("status"))
        .await
        .expect_err("scripted failure");
    assert!(matches!(error, Error::Transport(_)), "{error}");
    let fallback = sandbox
        .exec()
        .run(&ExecSpec::new("ls"))
        .await
        .expect("default");
    assert_eq!(fallback.exit_code, Some(3));
    assert!(!fallback.success());
    assert_eq!(exec.commands(), ["echo first", "git status", "ls"]);
    assert_eq!(exec.recorded()[1].program, "git");
}

#[tokio::test]
async fn an_unreachable_sandbox_fails_every_unscripted_command() {
    let sandbox = ScriptedSandbox::new();
    sandbox
        .scripted_exec()
        .push_result(ScriptedExec::ok("once"))
        .fail_by_default("daemon went away");
    assert!(sandbox.exec().run(&ExecSpec::new("ls")).await.is_ok());
    let error = sandbox
        .exec()
        .run(&ExecSpec::new("ls"))
        .await
        .expect_err("default failure");
    assert!(matches!(error, Error::Transport(_)), "{error}");
}

#[tokio::test]
async fn a_responder_answers_by_spec_before_the_queue() {
    let sandbox = ScriptedSandbox::new();
    sandbox
        .scripted_exec()
        .respond_with(|spec| {
            spec.args
                .iter()
                .any(|arg| arg.contains("remote set-url"))
                .then(|| ScriptedExec::failed(2, "set-url refused"))
        })
        .push_result(ScriptedExec::ok("pushed"));
    let set_url = sandbox
        .exec()
        .run(&ExecSpec::bash("git remote set-url origin x"))
        .await
        .expect("set-url");
    assert_eq!(set_url.exit_code, Some(2));
    let push = sandbox
        .exec()
        .run(&ExecSpec::bash("git push origin main"))
        .await
        .expect("push");
    assert_eq!(push.stdout_lossy(), "pushed");
    assert_eq!(sandbox.scripted_exec().commands().len(), 2);
}

#[tokio::test]
async fn streaming_delivers_output_and_captures_stdin() {
    let sandbox = ScriptedSandbox::new();
    let mut result = ScriptedExec::ok("out");
    result.stderr = b"err".to_vec();
    sandbox.scripted_exec().push_result(result);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink_seen = Arc::clone(&seen);
    let controls = ExecControls {
        stdin: Some(StdinSource::new(Cursor::new(b"input".to_vec()))),
        sink: Some(Arc::new(move |stream: OutputStream, chunk: Vec<u8>| {
            let seen = Arc::clone(&sink_seen);
            Box::pin(async move {
                seen.lock().expect("seen").push((stream, chunk));
                Ok(())
            })
        })),
        ..ExecControls::buffered()
    };
    let streaming = sandbox
        .exec()
        .run_streaming(&ExecSpec::new("cat"), controls)
        .await
        .expect("stream");
    assert_eq!(streaming.result.termination, Termination::Exited);
    assert_eq!(*seen.lock().expect("seen"), vec![
        (OutputStream::Stdout, b"out".to_vec()),
        (OutputStream::Stderr, b"err".to_vec()),
    ]);
    assert_eq!(sandbox.scripted_exec().captured_stdin(), vec![
        b"input".to_vec()
    ]);
}

#[tokio::test]
async fn streaming_keeps_only_what_the_retention_cap_allows() {
    let sandbox = ScriptedSandbox::new();
    sandbox
        .scripted_exec()
        .push_result(ScriptedExec::ok("0123456789ABCDEF"));
    let controls = ExecControls {
        retained_output_limit: Some(8),
        ..ExecControls::default()
    };
    let streaming = sandbox
        .exec()
        .run_streaming(&ExecSpec::bash("seq"), controls)
        .await
        .expect("stream");
    assert_eq!(streaming.result.stdout_lossy(), "0123CDEF");
    assert_eq!(streaming.stdout_capture.observed_bytes, 16);
    assert_eq!(streaming.stdout_capture.retained_bytes, 8);
    assert_eq!(streaming.stdout_capture.omitted_bytes, 8);
    assert_eq!(streaming.stderr_capture.observed_bytes, 0);
}

#[tokio::test]
async fn streaming_records_whether_a_term_stop_was_given() {
    let sandbox = ScriptedSandbox::new();
    let with_term = ExecControls {
        term: Some(CancellationToken::new()),
        ..ExecControls::buffered()
    };
    sandbox
        .exec()
        .run_streaming(&ExecSpec::bash("true"), with_term)
        .await
        .expect("stream");
    sandbox
        .exec()
        .run_streaming(&ExecSpec::bash("true"), ExecControls::buffered())
        .await
        .expect("stream");
    assert_eq!(sandbox.scripted_exec().term_stops(), vec![true, false]);
}

#[tokio::test]
async fn memory_fs_records_deletes_and_counts_existence_probes() {
    let sandbox = ScriptedSandbox::new().file("notes.txt", "n");
    let fs = sandbox.fs();
    assert!(fs.exists("notes.txt").await.expect("exists"));
    assert!(!fs.exists("missing.txt").await.expect("exists"));
    fs.delete("notes.txt", false).await.expect("delete");
    let memory = sandbox.memory_fs();
    assert_eq!(memory.exists_calls(), 2);
    assert_eq!(memory.deletes(), vec![memory.resolve("notes.txt")]);
}

#[tokio::test]
async fn memory_fs_uploads_and_downloads_local_files() {
    let sandbox = ScriptedSandbox::new().file("out/report.md", "report");
    let fs = sandbox.fs();
    let local = env::temp_dir().join(format!(
        "sandbox-driver-testing-{}-{}",
        process::id(),
        line!()
    ));
    let downloaded = local.join("nested").join("report.md");
    fs.download("out/report.md", &downloaded)
        .await
        .expect("download");
    assert_eq!(
        fs::read(&downloaded).await.expect("read download"),
        b"report"
    );
    fs.upload(&downloaded, "in/report.md")
        .await
        .expect("upload");
    assert_eq!(
        sandbox.memory_fs().contents("in/report.md"),
        Some(b"report".to_vec())
    );
    fs::remove_dir_all(&local).await.expect("clean up");
}

#[tokio::test]
async fn memory_fs_round_trips_relative_paths_and_records_writes() {
    let sandbox = ScriptedSandbox::new().file("src/main.rs", "fn main() {}");
    let fs = sandbox.fs();
    assert!(fs.exists("src/main.rs").await.expect("exists"));
    assert!(
        fs.exists("/work/src/main.rs")
            .await
            .expect("exists absolute")
    );
    fs.write("notes/todo.txt", b"later").await.expect("write");
    assert_eq!(
        fs.read("/work/notes/todo.txt").await.expect("read"),
        b"later"
    );
    let listed = fs.list_dir(".", 1).await.expect("list");
    let names: Vec<&str> = listed.iter().map(|entry| entry.path.as_str()).collect();
    assert_eq!(names, ["notes", "src"]);
    let deep = fs.list_dir("/work", 2).await.expect("list deep");
    assert!(deep.iter().any(|entry| entry.path == "src/main.rs"));
    fs.delete("src", true).await.expect("delete");
    assert!(!fs.exists("src/main.rs").await.expect("gone"));
    let error = fs.read("missing.txt").await.expect_err("missing");
    assert!(matches!(error, Error::NotFound { .. }), "{error}");
    assert_eq!(sandbox.memory_fs().writes(), vec![(
        "/work/notes/todo.txt".to_owned(),
        b"later".to_vec()
    )]);
}

#[tokio::test]
async fn walks_and_globs_read_the_memory_filesystem_unless_canned() {
    let sandbox = ScriptedSandbox::new()
        .file("skills/commit/SKILL.md", "commit")
        .file("skills/review/SKILL.md", "review")
        .file("skills/README.md", "readme")
        .file("target/junk.md", "junk");
    let search = sandbox.search().expect("search facet");
    let mut walked: Vec<String> = search
        .walk("skills", &WalkOptions::default())
        .await
        .expect("walk")
        .into_iter()
        .map(|file| file.path)
        .collect();
    walked.sort();
    assert_eq!(walked, ["README.md", "commit/SKILL.md", "review/SKILL.md"]);
    let mut options = WalkOptions::default();
    options.exclude_dirs = vec!["target".to_owned()];
    let everything = search.walk(".", &options).await.expect("walk all");
    assert!(
        everything
            .iter()
            .all(|file| !file.path.starts_with("target/"))
    );
    assert_eq!(everything.len(), 3);

    let mut globbed = search
        .glob("*/SKILL.md", "/work/skills")
        .await
        .expect("glob");
    globbed.sort();
    assert_eq!(globbed, [
        "/work/skills/commit/SKILL.md",
        "/work/skills/review/SKILL.md"
    ]);
    let deep = search.glob("**/*.md", ".").await.expect("glob deep");
    assert_eq!(deep.len(), 4);
    sandbox
        .scripted_search()
        .set_glob(vec!["canned".to_owned()]);
    assert_eq!(search.glob("*", ".").await.expect("canned"), ["canned"]);
}

#[tokio::test]
async fn search_returns_canned_results_through_the_facet() {
    let sandbox = ScriptedSandbox::new();
    sandbox.scripted_search().set_walk(vec![
        WalkedFile::new("a.rs", Some(1)),
        WalkedFile::new("docs/guide.md", Some(2)),
        WalkedFile::new("docs/target/out.md", Some(3)),
    ]);
    let search = sandbox.search().expect("search facet");
    let files = search
        .walk(".", &WalkOptions::default())
        .await
        .expect("walk");
    assert_eq!(files.len(), 3);
    // A walk below a base sees only the canned files under it, relative to
    // it, with excluded directories pruned.
    let mut options = WalkOptions::default();
    options.exclude_dirs = vec!["target".to_owned()];
    let below: Vec<(String, Option<u64>)> = search
        .walk("docs", &options)
        .await
        .expect("walk docs")
        .into_iter()
        .map(|file| (file.path, file.size))
        .collect();
    assert_eq!(below, [("guide.md".to_owned(), Some(2))]);
    assert_eq!(sandbox.scripted_search().walk_calls(), 2);
    sandbox.scripted_search().set_walk_error("no walker");
    assert!(search.walk(".", &WalkOptions::default()).await.is_err());
}

#[tokio::test]
async fn stdio_processes_are_driven_by_the_test() {
    let sandbox = ScriptedSandbox::new();
    sandbox.scripted_exec().set_stdio_process(
        ScriptedStdioProcess::new(|mut stdin, mut stdout, stderr| {
            tokio::spawn(async move {
                let mut line = vec![0_u8; 5];
                stdin.read_exact(&mut line).await.expect("read request");
                stderr.push(b"working\n");
                stdout.write_all(b"pong:").await.expect("write");
                stdout.write_all(&line).await.expect("write");
                stdout.shutdown().await.expect("close");
            });
        })
        .exit_code(Some(7))
        .wait_delay(Duration::from_millis(5)),
    );
    let mut process = sandbox
        .exec()
        .spawn_stdio(&sandbox_driver::SpawnSpec::new("agent"))
        .await
        .expect("spawn");
    process.stdin.write_all(b"ping!").await.expect("send");
    let mut reply = Vec::new();
    process.stdout.read_to_end(&mut reply).await.expect("reply");
    assert_eq!(reply, b"pong:ping!");
    assert_eq!(process.handle.wait().await, (Termination::Exited, Some(7)));
    assert!(process.stderr_tail.to_string_lossy().contains("working"));
}

#[tokio::test]
async fn provider_creates_attaches_lists_and_deletes() {
    let provider = ScriptedProvider::new("scripted");
    let spec = SandboxSpec::new(SandboxSource::HostDirectory).label("run", "1");
    let created = provider.create(&spec, None).await.expect("create");
    assert_eq!(
        created.working_directory(),
        format!("/work/{}", created.id())
    );
    let attached = provider.attach(created.id(), None).await.expect("attach");
    assert_eq!(attached.id(), created.id());

    let mut filter = SandboxFilter::default();
    filter.labels.insert("run".into(), "1".into());
    assert_eq!(provider.list(&filter).await.expect("list").len(), 1);
    filter.labels.insert("run".into(), "2".into());
    assert!(provider.list(&filter).await.expect("list").is_empty());

    provider.delete(created.id(), None).await.expect("delete");
    assert_eq!(provider.sandboxes()[0].delete_count(), 1);
    let error = provider
        .attach(created.id(), None)
        .await
        .map(|_| ())
        .expect_err("deleted");
    assert!(matches!(error, Error::NotFound { .. }), "{error}");
}

#[tokio::test]
async fn an_ownership_scope_works_over_the_double() {
    let plain: Arc<dyn SandboxProvider> = Arc::new(ScriptedProvider::default());
    let owned = OwnedProvider::new(Arc::clone(&plain), Ownership::label("owner", "me"));
    let mine = owned
        .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
        .await
        .expect("owned create");
    let theirs = plain
        .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
        .await
        .expect("plain create");
    assert_eq!(
        owned
            .list(&SandboxFilter::default())
            .await
            .expect("list")
            .len(),
        1
    );
    assert!(owned.attach(mine.id(), None).await.is_ok());
    let refused = owned
        .attach(theirs.id(), None)
        .await
        .map(|_| ())
        .expect_err("foreign");
    assert!(matches!(refused, Error::NotOwned { .. }), "{refused}");
}
