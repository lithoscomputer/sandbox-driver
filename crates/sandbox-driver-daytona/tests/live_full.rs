//! Deep live exercise of the Daytona provider: the positive paths the
//! conformance suite only presence-checks. Requires a full-access
//! `DAYTONA_API_KEY`; skipped otherwise. Every resource this test
//! creates is deleted before it returns, on success and failure paths.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{env, process};

use sandbox_driver::{
    Capability, Error, ExecSpec, LifecycleAction, LifecycleTimers, LogSink, LogSource,
    NetworkPolicy, Resources, SandboxProvider, SandboxSnapshotOptions, SandboxSource, SandboxSpec,
    SandboxState, SnapshotMode, SnapshotSource, SnapshotSpec, SnapshotState, WaitOptions,
    wait_for_state,
};
use sandbox_driver_daytona::DaytonaProvider;
use tokio::time;

const TEST_SNAPSHOT: &str = "daytona-medium";
const TEST_VM_SNAPSHOT: &str = "daytona-vm-small";

fn unique(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    format!("{prefix}-{}-{nanos:x}", process::id())
}

fn wait() -> WaitOptions {
    WaitOptions {
        interval: Duration::from_secs(2),
        deadline: Some(Duration::from_secs(300)),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn labels_timers_access_round_trip() {
    if env::var("DAYTONA_API_KEY").is_err() {
        return;
    }
    let provider = DaytonaProvider::connect().await.expect("connect");
    let spec = SandboxSpec::new(SandboxSource::Snapshot {
        name: TEST_SNAPSHOT.to_owned(),
    })
    .ephemeral(true);
    let sandbox = provider.create(&spec, None).await.expect("create");

    let outcome = async {
        // Labels: set and read back through describe.
        let mut labels = BTreeMap::new();
        labels.insert("sd-live".to_owned(), "yes".to_owned());
        sandbox
            .set_labels(&labels)
            .await
            .map_err(|error| format!("set_labels: {error}"))?;
        let status = sandbox
            .describe()
            .await
            .map_err(|error| format!("describe: {error}"))?;
        if status.labels.get("sd-live").map(String::as_str) != Some("yes") {
            return Err(format!("labels not visible after set: {:?}", status.labels));
        }

        // Timers: set auto-stop and auto-archive.
        let mut timers = LifecycleTimers::default();
        timers.auto_stop_after_idle = Some(Duration::from_secs(30 * 60));
        timers.auto_archive_after_stop = Some(Duration::from_secs(60 * 60));
        sandbox
            .set_timers(&timers)
            .await
            .map_err(|error| format!("set_timers: {error}"))?;

        // Keepalive.
        sandbox
            .refresh_activity()
            .await
            .map_err(|error| format!("refresh_activity: {error}"))?;

        // Preview URLs.
        let preview = sandbox.preview_urls().expect("facet declared");
        let url = preview
            .preview_url(3000)
            .await
            .map_err(|error| format!("preview_url: {error}"))?;
        if !url.url.starts_with("https://") {
            return Err(format!("preview url looks wrong: {}", url.url));
        }
        if !url.headers.contains_key("x-daytona-preview-token") {
            return Err("preview url missing auth header".to_owned());
        }
        let signed = preview
            .signed_preview_url(3000, Duration::from_secs(120))
            .await
            .map_err(|error| format!("signed_preview_url: {error}"))?;
        if !signed.url.starts_with("https://") {
            return Err(format!("signed preview url looks wrong: {}", signed.url));
        }

        // SSH: mint, sanity-check, revoke.
        let ssh = sandbox.ssh().expect("facet declared");
        let access = ssh
            .ssh_access(Some(Duration::from_secs(10 * 60)))
            .await
            .map_err(|error| format!("ssh_access: {error}"))?;
        if !access.command.contains("ssh") {
            return Err(format!("ssh command looks wrong: {}", access.command));
        }
        let token = access.token.clone().ok_or("ssh access returned no token")?;
        ssh.revoke_ssh_access(&token)
            .await
            .map_err(|error| format!("revoke_ssh_access: {error}"))?;

        // Browser terminal: Daytona exposes the service on port 22222.
        let terminal = sandbox
            .web_terminal()
            .expect("web terminal facet declared")
            .web_terminal_url()
            .await
            .map_err(|error| format!("web_terminal_url: {error}"))?;
        if !terminal.starts_with("https://") {
            return Err(format!("web terminal URL looks wrong: {terminal}"));
        }

        // VNC: starting Computer Use must yield a signed noVNC viewer.
        let vnc = sandbox
            .vnc()
            .expect("vnc facet declared")
            .vnc_connection()
            .await
            .map_err(|error| format!("vnc_connection: {error}"))?;
        if !vnc.url.starts_with("https://") || !vnc.url.contains("/vnc.html") {
            return Err(format!("VNC URL looks wrong: {}", vnc.url));
        }
        Ok(())
    }
    .await;

    sandbox.delete().await.expect("delete");
    outcome.expect("live access round trip");
}

#[tokio::test(flavor = "multi_thread")]
async fn cidr_egress_limits_apply_at_create_and_runtime() {
    if env::var("DAYTONA_API_KEY").is_err() {
        return;
    }
    let provider = DaytonaProvider::connect().await.expect("connect");
    let spec = SandboxSpec::new(SandboxSource::Snapshot {
        name: TEST_SNAPSHOT.to_owned(),
    })
    .network(NetworkPolicy::CidrAllowList {
        // TEST-NET-3 cannot contain Cloudflare's public endpoint.
        cidrs: vec!["203.0.113.0/24".to_owned()],
    })
    .ephemeral(true);
    let sandbox = provider.create(&spec, None).await.expect("create");

    let outcome = async {
        let blocked = tcp_probe(sandbox.as_ref()).await?;
        if blocked != "blocked" {
            return Err(format!(
                "creation-time CIDR policy did not block egress: {blocked:?}"
            ));
        }

        sandbox
            .update_network(&NetworkPolicy::CidrAllowList {
                cidrs: vec!["1.1.1.1/32".to_owned()],
            })
            .await
            .map_err(|error| format!("update_network: {error}"))?;
        for _ in 0..12 {
            if tcp_probe(sandbox.as_ref()).await? == "reachable" {
                return Ok(());
            }
            time::sleep(Duration::from_secs(5)).await;
        }
        Err("runtime CIDR update did not allow the endpoint within 60 seconds".to_owned())
    }
    .await;

    sandbox.delete().await.expect("delete");
    outcome.expect("live CIDR egress policy");
}

async fn tcp_probe(sandbox: &dyn sandbox_driver::Sandbox) -> Result<String, String> {
    let result = sandbox
        .exec()
        .run(
            &ExecSpec::new(
                "if timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; \
                 then printf reachable; else printf blocked; fi",
            )
            .timeout(Duration::from_secs(15)),
        )
        .await
        .map_err(|error| format!("egress probe: {error}"))?;
    if !result.success() {
        return Err(format!("egress probe failed: {result:?}"));
    }
    String::from_utf8(result.stdout).map_err(|error| format!("egress probe output: {error}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_resize_archive_restore_lifecycle() {
    if env::var("DAYTONA_API_KEY").is_err() {
        return;
    }
    let provider = DaytonaProvider::connect().await.expect("connect");
    // Non-ephemeral: an ephemeral sandbox deletes itself on stop, and
    // archive requires a stopped sandbox.
    let spec = SandboxSpec::new(SandboxSource::Snapshot {
        name: TEST_SNAPSHOT.to_owned(),
    })
    .name(unique("sd-live-lifecycle"));
    let sandbox = provider.create(&spec, None).await.expect("create");

    let outcome = async {
        sandbox
            .stop()
            .await
            .map_err(|error| format!("stop: {error}"))?;
        wait_for_state(sandbox.as_ref(), SandboxState::Stopped, &wait())
            .await
            .map_err(|error| format!("waiting for Stopped: {error}"))?;

        // Resize: grow disk by 1 GB from the current allocation.
        let current = sandbox
            .describe()
            .await
            .map_err(|error| format!("describe: {error}"))?
            .resources
            .unwrap_or_default();
        let mut resources = Resources::default();
        resources.cpu_cores = current.cpu_cores;
        resources.memory_mb = current.memory_mb;
        resources.disk_mb = current.disk_mb.map(|disk| disk + 1024);
        if resources.disk_mb.is_some() && sandbox.capabilities().lifecycle.resize {
            sandbox
                .resize(&resources)
                .await
                .map_err(|error| format!("resize: {error}"))?;
            let deadline = Instant::now() + Duration::from_secs(300);
            loop {
                let state = sandbox
                    .describe()
                    .await
                    .map_err(|error| format!("describe: {error}"))?
                    .state;
                match state {
                    SandboxState::Stopped => break,
                    SandboxState::Error => return Err("resize entered error state".to_owned()),
                    _ if Instant::now() >= deadline => {
                        return Err(format!("resize never settled (state {state:?})"));
                    }
                    _ => time::sleep(Duration::from_secs(2)).await,
                }
            }
        }

        // Archive, then restore via start. Archiving copies the
        // filesystem to object storage and exceeds the generic wait
        // live (a 300s wait timed out on 2026-08-30), so it gets its
        // own budget.
        sandbox
            .archive()
            .await
            .map_err(|error| format!("archive: {error}"))?;
        let archive_wait = WaitOptions {
            interval: Duration::from_secs(2),
            deadline: Some(Duration::from_secs(900)),
        };
        wait_for_state(sandbox.as_ref(), SandboxState::Archived, &archive_wait)
            .await
            .map_err(|error| format!("waiting for Archived: {error}"))?;
        sandbox
            .start()
            .await
            .map_err(|error| format!("start from archive: {error}"))?;
        wait_for_state(sandbox.as_ref(), SandboxState::Running, &wait())
            .await
            .map_err(|error| format!("waiting for Running after restore: {error}"))?;

        // The sandbox must still work after the full cycle.
        let result = sandbox
            .exec()
            .run(&sandbox_driver::ExecSpec::new("echo restored").timeout(Duration::from_secs(60)))
            .await
            .map_err(|error| format!("exec after restore: {error}"))?;
        if !result.success() || !result.stdout_lossy().contains("restored") {
            return Err(format!(
                "exec after restore failed: {}",
                result.stdout_lossy()
            ));
        }
        Ok(())
    }
    .await;

    sandbox.delete().await.expect("delete");
    outcome.expect("lifecycle round trip");
}

#[tokio::test(flavor = "multi_thread")]
async fn fork_and_snapshot_modes_preserve_their_declared_state() {
    if env::var("DAYTONA_API_KEY").is_err() {
        return;
    }
    let provider = DaytonaProvider::connect().await.expect("connect");
    let mut source_spec = SandboxSpec::new(SandboxSource::Snapshot {
        name: TEST_VM_SNAPSHOT.to_owned(),
    })
    .name(unique("sd-live-vm-state"));
    source_spec.region = Some("eu".to_owned());
    let source = match provider.create(&source_spec, None).await {
        Ok(source) => source,
        Err(Error::Provider(provider_error))
            if provider_error.code.as_deref() == Some("400")
                && provider_error.message.contains("not available in region") =>
        {
            return;
        }
        Err(error) => panic!("create VM: {error}"),
    };
    let snapshots = provider.snapshots().expect("snapshot provider declared");
    let mut created_sandboxes: Vec<Arc<dyn sandbox_driver::Sandbox>> = Vec::new();
    let mut created_snapshots = Vec::new();

    let outcome = async {
        if !source.capabilities().lifecycle.fork
            || !source
                .capabilities()
                .snapshots
                .as_ref()
                .is_some_and(|caps| caps.live_process_state_from_sandbox)
        {
            return Err("VM sandbox did not declare fork and hot snapshots".to_owned());
        }
        let setup = source
            .exec()
            .run(
                &ExecSpec::new(
                    "printf preserved > /tmp/sd-state-marker; \
                     nohup bash -c 'exec -a sandbox-driver-live-process sleep 3600' \
                     </dev/null >/dev/null 2>&1 & \
                     echo $! > /tmp/sd-state-pid; cat /tmp/sd-state-pid",
                )
                .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("start live process: {error}"))?;
        if !setup.success() {
            return Err(format!("start live process: {}", setup.stderr_lossy()));
        }
        let source_pid = setup.stdout_lossy().trim().to_owned();

        let forked = source
            .fork(&sandbox_driver::ForkOptions::default())
            .await
            .map_err(|error| format!("fork: {error}"))?;
        created_sandboxes.push(Arc::clone(&forked));
        assert_live_process(forked.as_ref(), &source_pid).await?;

        let hot_name = unique("sd-live-hot");
        let mut hot_options = SandboxSnapshotOptions::default();
        hot_options.name = Some(hot_name.clone());
        hot_options.mode = SnapshotMode::LiveProcessState;
        let hot_id = source
            .snapshot(&hot_options)
            .await
            .map_err(|error| format!("hot snapshot: {error}"))?;
        created_snapshots.push(hot_id.clone());
        wait_for_snapshot_state(snapshots, &hot_id, SnapshotState::Active).await?;
        let mut hot_restore_spec =
            SandboxSpec::new(SandboxSource::Snapshot { name: hot_name }).ephemeral(true);
        hot_restore_spec.region = Some("eu".to_owned());
        let hot_restore = provider
            .create(&hot_restore_spec, None)
            .await
            .map_err(|error| format!("restore hot snapshot: {error}"))?;
        created_sandboxes.push(Arc::clone(&hot_restore));
        assert_live_process(hot_restore.as_ref(), &source_pid).await?;

        let mut cold_while_running = SandboxSnapshotOptions::default();
        cold_while_running.mode = SnapshotMode::Filesystem;
        if !matches!(
            source.snapshot(&cold_while_running).await,
            Err(Error::InvalidState {
                current: SandboxState::Running,
                action:  LifecycleAction::SnapshotSandbox,
            })
        ) {
            return Err("filesystem snapshot did not require a stopped sandbox".to_owned());
        }

        source
            .stop()
            .await
            .map_err(|error| format!("stop source: {error}"))?;
        wait_for_state(source.as_ref(), SandboxState::Stopped, &wait())
            .await
            .map_err(|error| format!("waiting for stopped source: {error}"))?;
        if !matches!(
            source.fork(&sandbox_driver::ForkOptions::default()).await,
            Err(Error::InvalidState {
                current: SandboxState::Stopped,
                action:  LifecycleAction::Fork,
            })
        ) {
            return Err("fork did not require a running source".to_owned());
        }

        let cold_name = unique("sd-live-cold");
        let mut cold_options = SandboxSnapshotOptions::default();
        cold_options.name = Some(cold_name.clone());
        cold_options.mode = SnapshotMode::Filesystem;
        let cold_id = source
            .snapshot(&cold_options)
            .await
            .map_err(|error| format!("filesystem snapshot: {error}"))?;
        created_snapshots.push(cold_id.clone());
        wait_for_snapshot_state(snapshots, &cold_id, SnapshotState::Active).await?;
        let mut cold_restore_spec =
            SandboxSpec::new(SandboxSource::Snapshot { name: cold_name }).ephemeral(true);
        cold_restore_spec.region = Some("eu".to_owned());
        let cold_restore = provider
            .create(&cold_restore_spec, None)
            .await
            .map_err(|error| format!("restore filesystem snapshot: {error}"))?;
        created_sandboxes.push(Arc::clone(&cold_restore));
        let cold_check = cold_restore
            .exec()
            .run(
                &ExecSpec::new(
                    "test \"$(cat /tmp/sd-state-marker)\" = preserved; \
                     pid=$(cat /tmp/sd-state-pid); \
                     if test -r \"/proc/$pid/cmdline\" && \
                        tr '\\0' ' ' < \"/proc/$pid/cmdline\" | \
                        grep -q sandbox-driver-live-process; then exit 23; fi",
                )
                .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("check filesystem snapshot: {error}"))?;
        if !cold_check.success() {
            return Err(format!(
                "filesystem snapshot restored a live process or lost its files: {cold_check:?}"
            ));
        }
        Ok(())
    }
    .await;

    for sandbox in created_sandboxes.iter().rev() {
        let _ = sandbox.delete().await;
    }
    let _ = source.delete().await;
    for snapshot in created_snapshots.iter().rev() {
        let _ = snapshots.delete(snapshot).await;
    }
    outcome.expect("fork and snapshot mode behavior");
}

#[tokio::test(flavor = "multi_thread")]
async fn filesystem_snapshot_restores_files_without_processes() {
    if env::var("DAYTONA_API_KEY").is_err() {
        return;
    }
    let provider = DaytonaProvider::connect().await.expect("connect");
    let source_spec = SandboxSpec::new(SandboxSource::Snapshot {
        name: TEST_SNAPSHOT.to_owned(),
    })
    .name(unique("sd-live-filesystem-source"));
    let source = provider.create(&source_spec, None).await.expect("create");
    let snapshots = provider.snapshots().expect("snapshot provider declared");
    let mut restored = None;
    let mut snapshot_id = None;

    let outcome = async {
        let snapshot_caps = source
            .capabilities()
            .snapshots
            .as_ref()
            .ok_or("snapshot capabilities absent")?;
        if !snapshot_caps.filesystem_from_sandbox || snapshot_caps.live_process_state_from_sandbox {
            return Err(format!(
                "container snapshot modes are wrong: filesystem={}, live={}",
                snapshot_caps.filesystem_from_sandbox,
                snapshot_caps.live_process_state_from_sandbox
            ));
        }
        let mut hot_options = SandboxSnapshotOptions::default();
        hot_options.mode = SnapshotMode::LiveProcessState;
        if !matches!(
            source.snapshot(&hot_options).await,
            Err(Error::Unsupported {
                capability: Capability::SnapshotsLiveProcessState,
            })
        ) {
            return Err("container accepted a live-process-state snapshot".to_owned());
        }

        let setup = source
            .exec()
            .run(
                &ExecSpec::new(
                    "printf preserved > /tmp/sd-cold-marker; \
                     nohup bash -c 'exec -a sandbox-driver-cold-process sleep 3600' \
                     </dev/null >/dev/null 2>&1 & \
                     echo $! > /tmp/sd-cold-pid",
                )
                .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("start process: {error}"))?;
        if !setup.success() {
            return Err(format!("start process: {}", setup.stderr_lossy()));
        }
        source
            .stop()
            .await
            .map_err(|error| format!("stop source: {error}"))?;
        wait_for_state(source.as_ref(), SandboxState::Stopped, &wait())
            .await
            .map_err(|error| format!("wait for stopped source: {error}"))?;

        let name = unique("sd-live-filesystem");
        let mut options = SandboxSnapshotOptions::default();
        options.name = Some(name.clone());
        options.mode = SnapshotMode::Filesystem;
        let id = source
            .snapshot(&options)
            .await
            .map_err(|error| format!("filesystem snapshot: {error}"))?;
        snapshot_id = Some(id.clone());
        wait_for_snapshot_state(snapshots, &id, SnapshotState::Active).await?;

        let sandbox = provider
            .create(
                &SandboxSpec::new(SandboxSource::Snapshot { name }).ephemeral(true),
                None,
            )
            .await
            .map_err(|error| format!("restore filesystem snapshot: {error}"))?;
        restored = Some(Arc::clone(&sandbox));
        let check = sandbox
            .exec()
            .run(
                &ExecSpec::new(
                    "test \"$(cat /tmp/sd-cold-marker)\" = preserved; \
                     pid=$(cat /tmp/sd-cold-pid); \
                     if test -r \"/proc/$pid/cmdline\" && \
                        tr '\\0' ' ' < \"/proc/$pid/cmdline\" | \
                        grep -q sandbox-driver-cold-process; then exit 23; fi",
                )
                .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("check restored filesystem snapshot: {error}"))?;
        if !check.success() {
            return Err(format!(
                "filesystem snapshot lost files or restored a process: {check:?}"
            ));
        }
        Ok(())
    }
    .await;

    if let Some(restored) = restored {
        let _ = restored.delete().await;
    }
    let _ = source.delete().await;
    if let Some(snapshot_id) = snapshot_id {
        let _ = snapshots.delete(&snapshot_id).await;
    }
    outcome.expect("filesystem snapshot behavior");
}

async fn assert_live_process(
    sandbox: &dyn sandbox_driver::Sandbox,
    expected_pid: &str,
) -> Result<(), String> {
    let result = sandbox
        .exec()
        .run(
            &ExecSpec::new(
                "pid=$(cat /tmp/sd-state-pid); \
                 test -r \"/proc/$pid/cmdline\"; \
                 tr '\\0' ' ' < \"/proc/$pid/cmdline\" | \
                 grep -q sandbox-driver-live-process; \
                 printf '%s %s' \"$pid\" \"$(cat /tmp/sd-state-marker)\"",
            )
            .timeout(Duration::from_secs(30)),
        )
        .await
        .map_err(|error| format!("check live process: {error}"))?;
    let expected = format!("{expected_pid} preserved");
    if !result.success() || result.stdout_lossy() != expected {
        return Err(format!(
            "live process state mismatch: got {:?}, expected {expected:?}, stderr {:?}",
            result.stdout_lossy(),
            result.stderr_lossy()
        ));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_provider_round_trip() {
    if env::var("DAYTONA_API_KEY").is_err() {
        return;
    }
    let provider = DaytonaProvider::connect().await.expect("connect");
    let snapshots = provider.snapshots().expect("snapshot provider declared");

    let name = unique("sd-live-snap");
    let mut spec = SnapshotSpec::new(SnapshotSource::Image {
        reference: "debian:stable-slim".to_owned(),
    });
    spec.name = Some(name.clone());
    spec.resources.cpu_cores = Some(1);
    spec.resources.memory_mb = Some(1024);
    spec.resources.disk_mb = Some(1024);
    let id = snapshots.create(&spec).await.expect("snapshot create");

    let outcome = async {
        // Poll until the build settles.
        let deadline = Instant::now() + Duration::from_secs(600);
        loop {
            let status = snapshots
                .get(&id)
                .await
                .map_err(|error| format!("snapshot get: {error}"))?;
            match status.state {
                SnapshotState::Active => break,
                SnapshotState::Error => {
                    return Err(format!("snapshot build failed: {:?}", status.error_reason));
                }
                _ if Instant::now() >= deadline => {
                    return Err(format!("snapshot never became active ({:?})", status.state));
                }
                _ => time::sleep(Duration::from_secs(5)).await,
            }
        }
        // It must appear in a name-filtered list.
        let mut filter = sandbox_driver::SnapshotFilter::default();
        filter.name = Some(name.clone());
        let listed = snapshots
            .list(&filter)
            .await
            .map_err(|error| format!("snapshot list: {error}"))?;
        if listed.len() != 1 {
            return Err(format!("name filter returned {} snapshots", listed.len()));
        }

        // A sandbox must boot from it.
        let spec = SandboxSpec::new(SandboxSource::Snapshot { name: name.clone() }).ephemeral(true);
        let sandbox = provider
            .create(&spec, None)
            .await
            .map_err(|error| format!("create from snapshot: {error}"))?;
        let result = sandbox
            .exec()
            .run(
                &sandbox_driver::ExecSpec::new("cat /etc/debian_version")
                    .timeout(Duration::from_secs(60)),
            )
            .await;
        sandbox
            .delete()
            .await
            .map_err(|error| format!("delete snapshot sandbox: {error}"))?;
        wait_for_state(sandbox.as_ref(), SandboxState::Deleted, &wait())
            .await
            .map_err(|error| format!("waiting for snapshot sandbox deletion: {error}"))?;
        let result = result.map_err(|error| format!("exec on snapshot sandbox: {error}"))?;
        if !result.success() {
            return Err(format!(
                "exec on snapshot sandbox failed: {}",
                result.stdout_lossy()
            ));
        }

        snapshots
            .deactivate(&id)
            .await
            .map_err(|error| format!("snapshot deactivate: {error}"))?;
        wait_for_snapshot_state(snapshots, &id, SnapshotState::Inactive).await?;
        snapshots
            .activate(&id)
            .await
            .map_err(|error| format!("snapshot activate: {error}"))?;
        wait_for_snapshot_state(snapshots, &id, SnapshotState::Active).await?;
        Ok(())
    }
    .await;

    snapshots.delete(&id).await.expect("snapshot delete");
    snapshots
        .delete(&id)
        .await
        .expect("snapshot delete is idempotent");
    outcome.expect("snapshot round trip");
}

#[tokio::test(flavor = "multi_thread")]
async fn dockerfile_snapshot_build_and_entrypoint_logs() {
    if env::var("DAYTONA_API_KEY").is_err() {
        return;
    }
    let provider = DaytonaProvider::connect().await.expect("connect");
    let snapshots = provider.snapshots().expect("snapshot provider declared");
    let name = unique("sd-live-dockerfile");
    let mut spec = SnapshotSpec::new(SnapshotSource::Dockerfile {
        content: r#"FROM debian:stable-slim
ENTRYPOINT ["/bin/sh", "-c", "echo sandbox-driver-entrypoint; echo sandbox-driver-entrypoint-error >&2; sleep 2"]
"#
        .to_owned(),
    });
    spec.name = Some(name.clone());
    spec.resources.cpu_cores = Some(1);
    spec.resources.memory_mb = Some(1024);
    spec.resources.disk_mb = Some(1024);
    let id = snapshots
        .create(&spec)
        .await
        .expect("Dockerfile snapshot create");

    let outcome = async {
        let build_output = Arc::new(Mutex::new(Vec::new()));
        snapshots
            .build_logs(&id, true, collecting_sink(Arc::clone(&build_output)))
            .await
            .map_err(|error| format!("snapshot build logs: {error}"))?;
        if build_output.lock().expect("build output lock").is_empty() {
            return Err("snapshot build log stream was empty".to_owned());
        }
        wait_for_snapshot_state(snapshots, &id, SnapshotState::Active).await?;

        let sandbox = provider
            .create(
                &SandboxSpec::new(SandboxSource::Snapshot { name: name.clone() }).ephemeral(true),
                None,
            )
            .await
            .map_err(|error| format!("create from Dockerfile snapshot: {error}"))?;
        let entrypoint_output = Arc::new(Mutex::new(Vec::new()));
        let logs = sandbox.logs().expect("entrypoint logs facet declared");
        let followed = time::timeout(
            Duration::from_secs(60),
            logs.follow(
                LogSource::Entrypoint,
                collecting_sink(Arc::clone(&entrypoint_output)),
            ),
        )
        .await;
        let _ = sandbox.delete().await;
        followed
            .map_err(|_| "entrypoint log stream timed out".to_owned())?
            .map_err(|error| format!("entrypoint logs: {error}"))?;
        let output = entrypoint_output.lock().expect("entrypoint output lock");
        let output = String::from_utf8_lossy(&output);
        if !output.contains("sandbox-driver-entrypoint")
            || !output.contains("sandbox-driver-entrypoint-error")
        {
            return Err(format!("entrypoint logs missing markers: {output:?}"));
        }
        Ok(())
    }
    .await;

    snapshots.delete(&id).await.expect("snapshot delete");
    outcome.expect("Dockerfile snapshot and entrypoint logs");
}

fn collecting_sink(output: Arc<Mutex<Vec<u8>>>) -> LogSink {
    Arc::new(move |chunk| {
        let output = Arc::clone(&output);
        Box::pin(async move {
            output.lock().expect("log output lock").extend(chunk);
            Ok(())
        })
    })
}

async fn wait_for_snapshot_state(
    snapshots: &dyn sandbox_driver::SnapshotProvider,
    id: &sandbox_driver::SnapshotId,
    expected: SnapshotState,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(600);
    loop {
        let status = snapshots
            .get(id)
            .await
            .map_err(|error| format!("snapshot get: {error}"))?;
        if status.state == expected {
            return Ok(());
        }
        if status.state == SnapshotState::Error {
            return Err(format!("snapshot failed: {:?}", status.error_reason));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "snapshot did not reach {expected:?} (state {:?})",
                status.state
            ));
        }
        time::sleep(Duration::from_secs(5)).await;
    }
}
