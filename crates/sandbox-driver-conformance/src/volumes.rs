//! The volumes service: create, settle, list, mount across sandbox
//! deletion, and delete.

use std::process;
use std::time::{Duration, Instant};

use sandbox_driver::{Error, SandboxState, VolumeId, VolumeMount, wait_for_state};
use tokio::time;

use crate::Conformance;
use crate::check::{CheckOutcome, PASS, fail, nonce, skip};

pub(super) async fn volume_round_trip(ctx: &Conformance) -> CheckOutcome {
    let Some(volumes) = ctx.provider.volumes() else {
        return skip("volumes service not declared");
    };
    let name = format!("conformance-{}-{}", process::id(), nonce());
    let id = match volumes
        .create(&sandbox_driver::VolumeSpec::new(name.clone()), None)
        .await
    {
        Ok(id) => id,
        // Capabilities describe the backend, not the credential; a
        // permission-scoped key skips rather than fails this check.
        Err(Error::Provider(provider))
            if provider.code.as_deref() == Some("403")
                || provider.code.as_deref() == Some("401") =>
        {
            return skip("credential lacks volume permissions");
        }
        Err(Error::Auth(_)) => {
            return skip("credential lacks volume permissions");
        }
        Err(error) => return fail(format!("volume create failed: {error}")),
    };

    let outcome = async {
        // Poll briefly for a settled state; elastic backends are quick.
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let status = volumes
                .get(&id)
                .await
                .map_err(|error| format!("volume get failed: {error}"))?;
            match status.state {
                sandbox_driver::VolumeState::Ready => break,
                sandbox_driver::VolumeState::Error => {
                    return fail(format!(
                        "volume entered error state: {:?}",
                        status.error_reason
                    ));
                }
                _ if Instant::now() >= deadline => {
                    return fail("volume never became ready");
                }
                _ => time::sleep(Duration::from_secs(2)).await,
            }
        }

        let listed = volumes
            .list()
            .await
            .map_err(|error| format!("volume list failed: {error}"))?;
        if !listed.iter().any(|status| status.id == id) {
            return fail("created volume missing from list");
        }
        if ctx
            .caps()
            .volumes
            .as_ref()
            .is_some_and(|caps| caps.create_time_attach)
        {
            mounted_volume_survives_sandbox_deletion(ctx, &id).await?;
        }
        PASS
    }
    .await;
    let deleted = volumes
        .delete(&id, None)
        .await
        .map_err(|error| format!("volume delete failed: {error}"));
    outcome?;
    deleted?;
    volumes
        .delete(&id, None)
        .await
        .map_err(|error| format!("second volume delete failed: {error}"))?;
    PASS
}

async fn mounted_volume_survives_sandbox_deletion(
    ctx: &Conformance,
    volume: &VolumeId,
) -> CheckOutcome {
    const MOUNT_PATH: &str = "/mnt/sandbox-driver-conformance-volume";
    const FILE_PATH: &str = "/mnt/sandbox-driver-conformance-volume/persisted.bin";
    let payload = [0, 1, 2, 255, 254, b'\n', b'\r', 0];
    let spec = ctx
        .specs
        .spec()
        .volume(VolumeMount::new(volume.as_str(), MOUNT_PATH));

    let first = ctx.ready_from_spec(&spec).await?;
    tracing::info!(%volume, sandbox_id = %first.id(), "writing mounted volume");
    let written = first
        .fs()
        .write(FILE_PATH, &payload)
        .await
        .map_err(|error| format!("write mounted volume failed: {error}"));
    let deleted = ctx
        .delete(&first)
        .await
        .map_err(|error| format!("delete first volume sandbox failed: {error}"));
    written?;
    deleted?;
    wait_for_state(first.as_ref(), SandboxState::Deleted, &ctx.wait)
        .await
        .map_err(|error| format!("wait for first volume sandbox deletion failed: {error}"))?;

    let second = ctx.ready_from_spec(&spec).await?;
    tracing::info!(%volume, sandbox_id = %second.id(), "reading volume in replacement sandbox");
    let outcome = async {
        if first.id() == second.id() {
            return fail("volume persistence reused the deleted sandbox");
        }
        let read = second
            .fs()
            .read(FILE_PATH)
            .await
            .map_err(|error| format!("read remounted volume failed: {error}"))?;
        if read != payload {
            return fail(format!(
                "remounted volume returned different bytes: {read:?}"
            ));
        }
        PASS
    }
    .await;
    let deleted = ctx
        .delete(&second)
        .await
        .map_err(|error| format!("delete second volume sandbox failed: {error}"));
    outcome?;
    deleted?;
    wait_for_state(second.as_ref(), SandboxState::Deleted, &ctx.wait)
        .await
        .map_err(|error| format!("wait for second volume sandbox deletion failed: {error}"))?;
    PASS
}
