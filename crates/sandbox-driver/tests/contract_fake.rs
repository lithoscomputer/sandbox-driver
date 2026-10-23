use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use sandbox_driver::contract::{
    Error, ExecControls, ExecSpec, FakeExec, FakeProvider, MutationOutcome, OutputSink,
    SandboxState,
};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::time;

#[tokio::test]
async fn dropping_exec_ends_simulated_work_without_replay() {
    let fake = FakeProvider::new();
    fake.script(["long"], FakeExec {
        stdout: vec![1],
        wait_for_stop: true,
        ..FakeExec::default()
    })
    .await;
    let catalog = fake.sandboxes();
    let sandbox = catalog
        .builder("default")
        .await
        .expect("builder")
        .create()
        .await
        .expect("create");
    let (sender, mut receiver) = mpsc::channel(1);
    let sink: OutputSink = Arc::new(move |_, _| {
        let sender = sender.clone();
        Box::pin(async move {
            let _ = sender.try_send(());
            Ok(())
        })
    });
    let mut exec = Box::pin(sandbox.exec(ExecSpec::argv(["long"]), ExecControls {
        sink: Some(sink),
        ..ExecControls::default()
    }));
    tokio::select! {result=&mut exec => panic!("unexpected result: {result:?}"), _=receiver.recv()=>{}}
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
    let fake = FakeProvider::new();
    fake.script(["long"], FakeExec {
        stdout: vec![1],
        wait_for_stop: true,
        ..FakeExec::default()
    })
    .await;
    let catalog = fake.sandboxes();
    let sandbox = catalog
        .builder("default")
        .await
        .expect("builder")
        .create()
        .await
        .expect("create");
    let (sender, mut receiver) = mpsc::channel(1);
    let sink: OutputSink = Arc::new(move |_, _| {
        let sender = sender.clone();
        Box::pin(async move {
            let _ = sender.try_send(());
            Ok(())
        })
    });
    let exec = sandbox.exec(ExecSpec::argv(["long"]), ExecControls {
        sink: Some(sink),
        ..ExecControls::default()
    });
    let shutdown = async {
        receiver.recv().await.expect("admitted");
        catalog.shutdown().await.expect("shutdown");
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
    let catalog = FakeProvider::new().sandboxes();
    let sandbox = catalog
        .builder("default")
        .await
        .expect("builder")
        .create()
        .await
        .expect("create");
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
