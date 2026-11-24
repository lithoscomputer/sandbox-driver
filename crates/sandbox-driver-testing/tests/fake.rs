use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use sandbox_driver::{
    Activation, Error, ExecControls, ExecSpec, MutationOutcome, OutputLoss, OutputSink, Provider,
    ProviderFactory, ProviderName, Sandbox, SandboxSpec, SandboxState, SecretValues, Source,
    WorkloadAdmission, run_captured,
};
use sandbox_driver_testing::{FakeExec, FakeProvider};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::time;

#[tokio::test]
async fn dropping_exec_ends_simulated_work_without_replay() {
    let (fake, _runtime, sandbox) = long_running().await;
    let (sink, mut receiver) = signalling_sink();
    let mut exec = Box::pin(sandbox.exec(ExecSpec::argv(["long"]), ExecControls {
        sink: Some(sink),
        ..ExecControls::default()
    }));
    tokio::select! {
        result = &mut exec => panic!("unexpected result: {result:?}"),
        _ = receiver.recv() => {}
    }
    drop(exec);
    time::timeout(Duration::from_secs(1), sandbox.stop())
        .await
        .expect("bounded stop")
        .expect("fenced");
    sandbox.start().await.expect("start");
    assert_eq!(
        sandbox.status().await.expect("status").state,
        SandboxState::Running
    );
    assert_eq!(
        fake.calls()
            .await
            .iter()
            .filter(|call| call.operation == "exec")
            .count(),
        1
    );
}

#[tokio::test]
async fn shutdown_does_not_report_inflight_exec_as_not_started() {
    let (_fake, runtime, sandbox) = long_running().await;
    let (sink, mut receiver) = signalling_sink();
    let exec = sandbox.exec(ExecSpec::argv(["long"]), ExecControls {
        sink: Some(sink),
        ..ExecControls::default()
    });
    let shutdown = async {
        receiver.recv().await.expect("admitted");
        runtime.shutdown().await.expect("shutdown");
    };
    let (result, ()) = tokio::join!(exec, shutdown);
    assert!(matches!(
        result,
        Err(Error::Stale {
            outcome: MutationOutcome::Unknown,
        })
    ));
}

#[tokio::test]
async fn fake_files_resolve_against_workspace_and_list_implicit_parents() {
    let runtime = activate(&FakeProvider::new()).await;
    let sandbox = create(&runtime).await;
    sandbox
        .files()
        .put("nested/./file", Box::pin(Cursor::new(vec![1, 0, 255])))
        .await
        .expect("write");
    let mut bytes = Vec::new();
    sandbox
        .files()
        .get("/workspace/nested/file", None)
        .await
        .expect("read")
        .read_to_end(&mut bytes)
        .await
        .expect("complete");
    assert_eq!(bytes, [1, 0, 255]);
    let entries = sandbox.files().list("/workspace", 0).await.expect("list");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "/workspace/nested");
}

#[tokio::test]
async fn sandboxes_on_separate_fakes_have_separate_ids() {
    let first = sandbox_driver_testing::fake();
    let second = sandbox_driver_testing::fake();
    let mut ids = Vec::new();
    for catalog in [&first, &second, &first] {
        let sandbox = catalog
            .builder("default")
            .await
            .expect("builder")
            .create()
            .await
            .expect("create");
        ids.push(sandbox.reference().id);
    }
    assert_ne!(ids[0], ids[1]);
    assert_ne!(ids[1], ids[2]);
    assert_ne!(ids[0], ids[2]);
}

#[tokio::test]
async fn the_newest_script_that_answers_a_command_decides_its_result() {
    let fake = FakeProvider::new();
    fake.script(|spec| {
        Some(FakeExec {
            stdout: format!("any {}", spec.argv.join(" ")).into_bytes(),
            ..FakeExec::default()
        })
    });
    let mut loss = OutputLoss::default();
    loss.dropped_frames = 2;
    fake.script(move |spec| {
        spec.argv
            .last()
            .filter(|arg| arg.contains("diff"))
            .map(|_| FakeExec {
                stdout: b"patch".to_vec(),
                exit_code: 1,
                output_loss: loss,
                ..FakeExec::default()
            })
    });
    let catalog = fake.sandboxes();
    let sandbox = catalog
        .builder("default")
        .await
        .expect("builder")
        .create()
        .await
        .expect("create");

    let diff = run_captured(
        sandbox.as_ref(),
        ExecSpec::argv(["bash", "-c", "git diff HEAD"]),
    )
    .await
    .expect("answered by the newer script");
    assert_eq!(diff.stdout.bytes, b"patch");
    assert_eq!(diff.outcome.exit_code, Some(1));
    assert_eq!(diff.outcome.output_loss.dropped_frames, 2);

    let other = run_captured(sandbox.as_ref(), ExecSpec::argv(["git", "log"]))
        .await
        .expect("answered by the older script");
    assert_eq!(other.stdout.bytes, b"any git log");
    assert_eq!(other.outcome.exit_code, Some(0));
}

#[tokio::test]
async fn a_command_no_script_answers_fails() {
    let fake = FakeProvider::new();
    fake.script(|spec| (spec.argv == ["known"]).then(FakeExec::default));
    let catalog = fake.sandboxes();
    let sandbox = catalog
        .builder("default")
        .await
        .expect("builder")
        .create()
        .await
        .expect("create");
    let error = sandbox
        .exec(ExecSpec::argv(["unknown"]), ExecControls::default())
        .await
        .expect_err("unscripted");
    assert!(matches!(error, Error::Unsupported { .. }), "{error:?}");
}

/// A sandbox whose `long` command emits one output chunk and then waits for
/// stop, cancellation or shutdown.
async fn long_running() -> (FakeProvider, Arc<dyn Provider>, Box<dyn Sandbox>) {
    let fake = FakeProvider::new();
    fake.script(|spec| {
        (spec.argv == ["long"]).then(|| FakeExec {
            stdout: vec![1],
            wait_for_stop: true,
            ..FakeExec::default()
        })
    });
    let runtime = activate(&fake).await;
    let sandbox = create(&runtime).await;
    (fake, runtime, sandbox)
}

/// A sink that signals the receiver once output arrives.
fn signalling_sink() -> (OutputSink, mpsc::Receiver<()>) {
    let (sender, receiver) = mpsc::channel(1);
    let sink: OutputSink = Arc::new(move |_, _| {
        let sender = sender.clone();
        Box::pin(async move {
            let _ = sender.try_send(());
            Ok(())
        })
    });
    (sink, receiver)
}

async fn activate(fake: &FakeProvider) -> Arc<dyn Provider> {
    fake.activate(Activation {
        name:        ProviderName::try_new("fake").expect("name"),
        entry:       serde_json::from_value(serde_json::json!({"plugin": "fake"})).expect("entry"),
        schemas:     FakeProvider::schemas(),
        environment: BTreeMap::new(),
        secrets:     SecretValues::default(),
    })
    .await
    .expect("activate")
}

async fn create(runtime: &Arc<dyn Provider>) -> Box<dyn Sandbox> {
    runtime
        .create(WorkloadAdmission {
            spec:        SandboxSpec::new(Source::Image("fake:workload".into())),
            credentials: SecretValues::default(),
        })
        .await
        .expect("create")
}
