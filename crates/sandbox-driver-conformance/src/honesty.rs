//! Capability honesty: undeclared verbs, snapshot modes, and facets
//! must say `Unsupported`, and declared ones must be present.

use std::collections::BTreeMap;
use std::time::Duration;

use sandbox_driver::{
    Capability, Error, ExecControls, ExecSpec, NetworkPolicy, Resources, SnapshotMode,
};
use tokio_util::sync::CancellationToken;

use crate::Conformance;
use crate::check::{CheckOutcome, PASS, cleanup, fail};

pub(super) async fn unsupported_actions_say_so(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.create().await?;
    // The per-sandbox set is authoritative: a provider may narrow its
    // upper bound by sandbox class (Daytona masks VM-only verbs on
    // container sandboxes), and honesty is judged against the handle.
    let caps = sandbox.capabilities().clone();
    let outcome = async {
        let mut wrong: Vec<String> = Vec::new();
        let mut check = |name: &str, declared: bool, result: Result<(), Error>| match result {
            Err(Error::Unsupported { .. }) if declared => {
                wrong.push(format!("{name}: declared but returned Unsupported"));
            }
            Err(Error::Unsupported { .. }) => {}
            _ if declared => {}
            Ok(()) => wrong.push(format!("{name}: undeclared but succeeded")),
            // A non-Unsupported error for an undeclared capability is
            // wrong too, but tolerated: some providers reject earlier.
            Err(_) => {}
        };
        check("pause", caps.lifecycle.pause, sandbox.pause().await);
        check("archive", caps.lifecycle.archive, sandbox.archive().await);
        check("recover", caps.lifecycle.recover, sandbox.recover().await);
        check(
            "refresh_activity",
            caps.lifecycle.refresh_activity,
            sandbox.refresh_activity().await,
        );
        check(
            "resize",
            caps.lifecycle.resize,
            sandbox
                .resize(&{
                    let mut resources = Resources::default();
                    resources.cpu_cores = Some(1);
                    resources
                })
                .await,
        );
        check(
            "set_timers",
            caps.lifecycle.timers,
            sandbox
                .set_timers(&sandbox_driver::LifecycleTimers::default())
                .await,
        );
        check(
            "set_labels",
            caps.lifecycle.labels,
            sandbox.set_labels(&BTreeMap::new()).await,
        );
        check(
            "update_network",
            caps.lifecycle.update_network,
            sandbox.update_network(&NetworkPolicy::AllowAll).await,
        );
        check(
            "undelete",
            caps.lifecycle.undelete,
            ctx.provider.undelete(sandbox.id(), None).await.map(|_| ()),
        );
        // Handle-producing verbs are exercised only in the undeclared
        // direction: expect a clean Unsupported, never a real resource.
        if !caps.lifecycle.fork {
            match sandbox.fork(&sandbox_driver::ForkOptions::default()).await {
                Err(Error::Unsupported { .. }) => {}
                Err(error) => wrong.push(format!("fork: expected Unsupported, got {error}")),
                Ok(forked) => {
                    let _ = forked.delete().await;
                    wrong.push("fork: undeclared but succeeded".to_owned());
                }
            }
        }
        if !caps.lifecycle.snapshot_sandbox {
            match sandbox
                .snapshot(&sandbox_driver::SandboxSnapshotOptions::default())
                .await
            {
                Err(Error::Unsupported { .. }) => {}
                Err(error) => {
                    wrong.push(format!("snapshot: expected Unsupported, got {error}"));
                }
                Ok(_) => wrong.push("snapshot: undeclared but succeeded".to_owned()),
            }
        }
        if wrong.is_empty() {
            PASS
        } else {
            fail(wrong.join("; "))
        }
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

pub(super) async fn snapshot_modes_are_honest(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().lifecycle.snapshot_sandbox {
        return Ok(Some(
            "capability lifecycle.snapshot_sandbox not declared".to_owned(),
        ));
    }
    let sandbox = ctx.ready().await?;
    let snapshot_caps = sandbox.capabilities().snapshots.clone().unwrap_or_default();
    let modes = [
        (
            SnapshotMode::Filesystem,
            snapshot_caps.filesystem_from_sandbox,
            Capability::SnapshotsFilesystem,
        ),
        (
            SnapshotMode::LiveProcessState,
            snapshot_caps.live_process_state_from_sandbox,
            Capability::SnapshotsLiveProcessState,
        ),
    ];
    let mut checked = false;
    let mut failure = None;
    for (mode, declared, capability) in modes {
        if declared {
            continue;
        }
        checked = true;
        let mut options = sandbox_driver::SandboxSnapshotOptions::default();
        options.mode = mode;
        match sandbox.snapshot(&options).await {
            Err(Error::Unsupported { capability: actual }) if actual == capability => {}
            Err(error) => {
                failure = Some(format!(
                    "{mode:?}: expected Unsupported({capability}), got {error}"
                ));
                break;
            }
            Ok(id) => {
                failure = Some(format!(
                    "undeclared snapshot mode {mode:?} created snapshot {id}"
                ));
                break;
            }
        }
    }
    cleanup(&sandbox).await;
    if let Some(failure) = failure {
        fail(failure)
    } else if checked {
        PASS
    } else {
        Ok(Some("all sandbox snapshot modes are declared".to_owned()))
    }
}

pub(super) async fn services_match_capabilities(ctx: &Conformance) -> CheckOutcome {
    let caps = ctx.caps();
    let mut wrong: Vec<String> = Vec::new();
    if caps.snapshots.is_some() != ctx.provider.snapshots().is_some() {
        wrong.push(format!(
            "snapshots service presence ({}) disagrees with capabilities ({})",
            ctx.provider.snapshots().is_some(),
            caps.snapshots.is_some()
        ));
    }
    if caps.volumes.is_some() != ctx.provider.volumes().is_some() {
        wrong.push(format!(
            "volumes service presence ({}) disagrees with capabilities ({})",
            ctx.provider.volumes().is_some(),
            caps.volumes.is_some()
        ));
    }
    let sandbox = ctx.create().await?;
    let sandbox_caps = sandbox.capabilities();
    if sandbox_caps.access.preview_urls != sandbox.preview_urls().is_some() {
        wrong.push("preview_urls facet presence disagrees with capabilities".to_owned());
    }
    if sandbox_caps.access.ssh != sandbox.ssh().is_some() {
        wrong.push("ssh facet presence disagrees with capabilities".to_owned());
    }
    if sandbox_caps.access.shell_command != sandbox.shell_command().is_some() {
        wrong.push("shell_command facet presence disagrees with capabilities".to_owned());
    }
    if sandbox_caps.pty.is_some() != sandbox.pty().is_some() {
        wrong.push("pty facet presence disagrees with capabilities".to_owned());
    }
    if sandbox_caps.logs.is_some() != sandbox.logs().is_some() {
        wrong.push("logs facet presence disagrees with capabilities".to_owned());
    }
    if sandbox_caps.supports(Capability::Search) != sandbox.search().is_some() {
        wrong.push("search facet presence disagrees with capabilities".to_owned());
    }
    if sandbox_caps.search.native != sandbox.provider_search().is_some() {
        wrong.push("search provider override disagrees with search.native".to_owned());
    }
    if sandbox_caps.supports(Capability::Git) != sandbox.git().is_some() {
        wrong.push("git facet presence disagrees with capabilities".to_owned());
    }
    if sandbox_caps.git.native != sandbox.provider_git().is_some() {
        wrong.push("git provider override disagrees with git.native".to_owned());
    }
    if sandbox_caps.supports(Capability::Services) != sandbox.services().is_some() {
        wrong.push("services facet presence disagrees with capabilities".to_owned());
    }
    if sandbox_caps.services.native != sandbox.provider_services().is_some() {
        wrong.push("services provider override disagrees with services.native".to_owned());
    }
    if sandbox_caps.access.web_terminal != sandbox.web_terminal().is_some() {
        wrong.push("web_terminal facet presence disagrees with capabilities".to_owned());
    }
    if sandbox_caps.access.vnc != sandbox.vnc().is_some() {
        wrong.push("vnc facet presence disagrees with capabilities".to_owned());
    }
    cleanup(&sandbox).await;
    if wrong.is_empty() {
        PASS
    } else {
        fail(wrong.join("; "))
    }
}

pub(super) async fn ssh_access_matches_capabilities(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().access.ssh {
        return Ok(Some("capability access.ssh not declared".to_owned()));
    }
    let sandbox = ctx.ready().await?;
    let caps = sandbox.capabilities().access.clone();
    if !caps.ssh {
        let has_facet = sandbox.ssh().is_some();
        cleanup(&sandbox).await;
        return if has_facet {
            fail("SSH facet is present but not declared for this sandbox")
        } else {
            Ok(Some("access.ssh not declared for this sandbox".to_owned()))
        };
    }
    let Some(ssh) = sandbox.ssh() else {
        cleanup(&sandbox).await;
        return fail("access.ssh is declared but the SSH facet is absent");
    };

    let outcome = async {
        let access = if caps.ssh_ttl {
            ssh.ssh_access(Some(Duration::from_secs(120)))
                .await
                .map_err(|error| format!("TTL SSH access failed: {error}"))?
        } else {
            match ssh.ssh_access(Some(Duration::from_secs(120))).await {
                Err(Error::Unsupported {
                    capability: Capability::SshTtl,
                }) => {}
                Err(error) => {
                    return fail(format!(
                        "undeclared SSH TTL: expected Unsupported(access.ssh.ttl), got {error}"
                    ));
                }
                Ok(_) => return fail("undeclared SSH TTL was accepted"),
            }
            ssh.ssh_access(None)
                .await
                .map_err(|error| format!("SSH access without TTL failed: {error}"))?
        };

        if access.command.trim().is_empty() {
            return fail("SSH access returned an empty command");
        }
        if caps.ssh_revoke {
            let Some(token) = access.token.as_deref() else {
                return fail("access.ssh.revoke is declared but SSH access returned no token");
            };
            ssh.revoke_ssh_access(token)
                .await
                .map_err(|error| format!("SSH revoke failed: {error}"))?;
            PASS
        } else {
            match ssh.revoke_ssh_access("sandbox-driver-conformance").await {
                Err(Error::Unsupported {
                    capability: Capability::SshRevoke,
                }) => PASS,
                Err(error) => fail(format!(
                    "undeclared SSH revoke: expected Unsupported(access.ssh.revoke), got {error}"
                )),
                Ok(()) => fail("undeclared SSH revoke succeeded"),
            }
        }
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

pub(super) async fn shell_command_access_matches_capabilities(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().access.shell_command {
        return Ok(Some(
            "capability access.shell_command not declared".to_owned(),
        ));
    }
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let Some(access) = sandbox.shell_command() else {
            return fail("access.shell_command is declared but the ShellCommand facet is absent");
        };
        let command = access
            .shell_command()
            .await
            .map_err(|error| format!("shell command access failed: {error}"))?;
        if command.trim().is_empty() {
            return fail("ShellCommand returned an empty command");
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

/// A spec field the capability set disclaims must be rejected with the
/// matching `Unsupported`, never silently dropped.
pub(super) async fn exec_rejects_undeclared_stdin_and_stop(ctx: &Conformance) -> CheckOutcome {
    let caps = ctx.caps();
    if caps.exec.stdin && caps.exec.stop {
        return Ok(Some(
            "exec.stdin and exec.stop are both declared".to_owned(),
        ));
    }
    let sandbox = ctx.ready().await?;
    let outcome = async {
        if !caps.exec.stdin {
            let spec = ExecSpec::new("cat")
                .stdin(b"dropped?".to_vec())
                .timeout(Duration::from_secs(30));
            match sandbox
                .exec()
                .run_streaming(&spec, ExecControls::buffered())
                .await
            {
                Err(Error::Unsupported {
                    capability: Capability::ExecStdin,
                }) => {}
                Err(other) => {
                    return fail(format!("stdin: expected Unsupported(exec.stdin): {other}"));
                }
                Ok(_) => return fail("undeclared stdin was accepted (or dropped)"),
            }
        }
        if !caps.exec.stop {
            let controls = ExecControls {
                term: Some(CancellationToken::new()),
                ..ExecControls::buffered()
            };
            let spec = ExecSpec::new("true").timeout(Duration::from_secs(30));
            match sandbox.exec().run_streaming(&spec, controls).await {
                Err(Error::Unsupported {
                    capability: Capability::ExecStop,
                }) => {}
                Err(other) => {
                    return fail(format!("stop: expected Unsupported(exec.stop): {other}"));
                }
                Ok(_) => return fail("undeclared stop token was accepted (or ignored)"),
            }
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}
