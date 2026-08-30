//! Deep live exercise of the Daytona provider: the positive paths the
//! conformance suite only presence-checks. Requires a full-access
//! `DAYTONA_API_KEY`; skipped otherwise. Every resource this test
//! creates is deleted before it returns, on success and failure paths.

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{env, process};

use sandbox_driver::{
    LifecycleTimers, Resources, SandboxProvider, SandboxSource, SandboxSpec, SandboxState,
    SnapshotSource, SnapshotSpec, SnapshotState, WaitOptions, wait_for_state,
};
use sandbox_driver_daytona::DaytonaProvider;
use tokio::time;

const TEST_SNAPSHOT: &str = "daytona-medium";

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
            .create_ssh_access(Some(Duration::from_secs(10 * 60)))
            .await
            .map_err(|error| format!("create_ssh_access: {error}"))?;
        if !access.command.contains("ssh") {
            return Err(format!("ssh command looks wrong: {}", access.command));
        }
        let token = access.token.clone().ok_or("ssh access returned no token")?;
        ssh.revoke_ssh_access(&token)
            .await
            .map_err(|error| format!("revoke_ssh_access: {error}"))?;
        Ok(())
    }
    .await;

    sandbox.delete().await.expect("delete");
    outcome.expect("live access round trip");
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
        let _ = sandbox.delete().await;
        let result = result.map_err(|error| format!("exec on snapshot sandbox: {error}"))?;
        if !result.success() {
            return Err(format!(
                "exec on snapshot sandbox failed: {}",
                result.stdout_lossy()
            ));
        }
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
