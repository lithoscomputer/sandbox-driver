//! Local transport verification plus an explicit live nested-Docker gate.

use std::env;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use daytona_sdk::Client;
use futures_util::FutureExt;
use sandbox_driver::{
    ExecControls, ExecSpec, OneShotImage, OneShotSpec, SandboxKind, SandboxProvider, SandboxSource,
    SandboxSpec, SnapshotId, Termination,
};
use sandbox_driver_daytona::{
    DaytonaProvider, DaytonaProviderConfig, DockerExecutionTarget, NestedDockerConfig,
};
use sandbox_driver_docker::{Health, Sidecar};
use support::init_diagnostics;
use tokio::fs;
use tokio_util::sync::CancellationToken;

mod support;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DAYTONA_API_KEY and SANDBOX_DRIVER_DAYTONA_DIND_SNAPSHOT"]
async fn nested_job_sidecars_one_shots_and_restart_share_the_sandbox_lifecycle() {
    init_diagnostics();
    env::var("DAYTONA_API_KEY").expect("live gate requires DAYTONA_API_KEY");
    let snapshot = env::var("SANDBOX_DRIVER_DAYTONA_DIND_SNAPSHOT")
        .expect("set a snapshot with start-docker, Python 3, at least 2 CPU and 4 GiB");
    let kind = match env::var("SANDBOX_DRIVER_DAYTONA_KIND").as_deref() {
        Ok("virtual_machine") => SandboxKind::VirtualMachine,
        Ok("container") | Err(_) => SandboxKind::Container,
        Ok(_) => panic!("SANDBOX_DRIVER_DAYTONA_KIND must be container or virtual_machine"),
    };
    let provider = DaytonaProvider::connect().await.unwrap();
    let mut spec = SandboxSpec::new(SandboxSource::Snapshot {
        id: SnapshotId::try_new(snapshot).unwrap(),
    })
    .sandbox_kind(kind)
    .working_directory("/workspace");
    spec.user = Some("root".to_owned());
    spec.timers.auto_stop_after_idle = Some(Duration::ZERO);
    let mut service = Sidecar::new("service", "alpine:3.20");
    service.entrypoint = Some(vec![
        "sh".to_owned(),
        "-c".to_owned(),
        "while true; do printf 'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nready\n' | nc -l -p 8080; done".to_owned(),
    ]);
    service.health = Some(Health::new("wget -qO- http://127.0.0.1:8080"));
    let mut options = sandbox_driver_docker::DockerProviderConfig::default();
    options.sidecars.push(service);
    spec.provider_config = DaytonaProviderConfig {
        docker: Some(NestedDockerConfig {
            image: "alpine:3.20".to_owned(),
            target: DockerExecutionTarget::Container,
            user: None,
            options,
        }),
        ..Default::default()
    }
    .into_value();
    let sandbox = provider.create(&spec, None).await.unwrap();
    let outcome =
        AssertUnwindSafe(async {
            // Test a runner bootstrap fix before publishing a replacement image.
            // The normal gate uses only the selected snapshot's own helper.
            if let Some(path) = env::var_os("SANDBOX_DRIVER_DAYTONA_START_DOCKER") {
                let script = fs::read(path).await.expect("read bootstrap override");
                let native = Client::new().await.expect("native Daytona client");
                let outer = native
                    .get(sandbox.id().as_str())
                    .await
                    .expect("outer sandbox");
                outer
                    .fs()
                    .await
                    .expect("outer files")
                    .upload_file_bytes("/usr/local/bin/start-docker", &script)
                    .await
                    .expect("install bootstrap override");
                tracing::info!("nested live gate uses a runner bootstrap source override");
            }
            tracing::info!("nested live gate: files");
            sandbox
                .fs()
                .write_from("binary", &mut [0, 255, 128, 10].as_slice(), 4)
                .await?;
            let mut binary = Vec::new();
            sandbox.fs().read_to("binary", &mut binary).await?;
            assert_eq!(binary, [0, 255, 128, 10]);
            sandbox.fs().write("append-target", b"prefix").await?;
            let setup = sandbox
                .exec()
                .run(&ExecSpec::new("/bin/sh").args([
                    "-c",
                    "chmod 0600 append-target && chown 1234:1234 append-target && \
                 ln -s append-target append-link && rm -f /bin/base64 /usr/bin/base64",
                ]))
                .await?;
            assert_eq!(setup.exit_code, Some(0));
            sandbox
                .fs()
                .write_append("append-link", &[0, 255, 128, 10])
                .await?;
            sandbox.fs().write_append("append-link", &[]).await?;
            assert_eq!(
                sandbox.fs().read("append-target").await?,
                b"prefix\0\xff\x80\n"
            );
            let properties = sandbox
                .exec()
                .run(&ExecSpec::new("/bin/sh").args([
                    "-c",
                    "stat -c '%a %u:%g' append-target && readlink append-link",
                ]))
                .await?;
            assert_eq!(properties.exit_code, Some(0));
            assert_eq!(
                properties.stdout_lossy().trim(),
                "600 1234:1234\nappend-target"
            );
            tracing::info!("nested live gate: exec");
            let result = sandbox
                .exec()
                .run_streaming(
                    &ExecSpec::new("sh").args([
                        "-c",
                        "wget -qO- http://service:8080; cat /etc/alpine-release",
                    ]),
                    ExecControls::default(),
                )
                .await?;
            assert_eq!(result.result.exit_code, Some(0));
            assert!(result.result.stdout_lossy().contains("ready"));
            tracing::info!("nested live gate: one-shot");
            let result = sandbox
                .one_shot()
                .unwrap()
                .run(
                    &OneShotSpec::registry("alpine:3.20").entrypoint("sh").args([
                        "-c",
                        "wget -qO- http://service:8080; printf kept > one-shot",
                    ]),
                    ExecControls::default(),
                )
                .await?;
            assert_eq!(result.result.exit_code, Some(0));
            assert_eq!(sandbox.fs().read("one-shot").await?, b"kept");
            tracing::info!("nested live gate: Dockerfile action and binary streams");
            let dockerfile = format!(
                "FROM alpine:3.20\nENTRYPOINT {}\n",
                serde_json::json!([
                    "/bin/sh",
                    "-c",
                    "cat /workspace/one-shot; printf '\\000\\377'; printf build-error >&2"
                ])
            );
            sandbox
                .fs()
                .write("action/Dockerfile", dockerfile.as_bytes())
                .await?;
            let built = sandbox
                .one_shot()
                .unwrap()
                .run(
                    &OneShotSpec::new(OneShotImage::Build {
                        context:    "action".to_owned(),
                        dockerfile: None,
                        tag:        "sandbox-driver-live-build".to_owned(),
                        reuse:      false,
                    }),
                    ExecControls::default(),
                )
                .await?;
            assert_eq!(built.result.exit_code, Some(0));
            assert_eq!(built.result.stdout, b"kept\0\xff");
            assert_eq!(built.result.stderr, b"build-error");
            tracing::info!("nested live gate: action TERM reaches its entrypoint");
            let term = CancellationToken::new();
            let cancel = term.clone();
            let stopped = sandbox.one_shot().unwrap().run(
            &OneShotSpec::registry("alpine:3.20").entrypoint("/bin/sh").args([
                "-c", "trap 'printf term; exit 0' TERM; printf ready; while :; do sleep 1; done",
            ]),
            ExecControls { term: Some(term), sink: Some(Arc::new(move |_, _| {
                cancel.cancel();
                Box::pin(async { Ok(()) })
            })), ..Default::default() },
        ).await?;
            assert_eq!(stopped.result.termination, Termination::Cancelled);
            assert!(stopped.result.stdout_lossy().contains("term"));
            tracing::info!("nested live gate: restart");
            sandbox.stop().await?;
            let attached = provider.attach(sandbox.id(), None).await?;
            attached.start().await?;
            assert_eq!(attached.fs().read("binary").await?, [0, 255, 128, 10]);
            assert_eq!(attached.fs().read("one-shot").await?, b"kept");
            Ok::<_, sandbox_driver::Error>(())
        })
        .catch_unwind()
        .await;
    let cleanup = sandbox.delete().await;
    cleanup.expect("delete the live sandbox even when an assertion fails");
    outcome.unwrap().unwrap();
}
