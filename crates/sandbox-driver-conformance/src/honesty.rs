//! Capability honesty: undeclared verbs, snapshot modes, and facets
//! must say `Unsupported`, and declared ones must be present.

use std::collections::BTreeMap;
use std::time::Duration;

use sandbox_driver::{
    Capability, Error, ExecControls, ExecSpec, NetworkPolicy, Resources, SnapshotMode,
};
use tokio_util::sync::CancellationToken;

use crate::check::{COMMAND_TIMEOUT, CheckOutcome, PASS, fail, skip};
use crate::{Conformance, Provision};

pub(super) async fn unsupported_actions_say_so(ctx: &Conformance) -> CheckOutcome {
    ctx.with_sandbox(Provision::Created, |sandbox| async move {
        // The per-sandbox set is authoritative: a provider may narrow its
        // upper bound by sandbox class (Daytona masks VM-only verbs on
        // container sandboxes), and honesty is judged against the handle.
        let caps = sandbox.capabilities().clone();
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
    })
    .await
}

pub(super) async fn snapshot_modes_are_honest(ctx: &Conformance) -> CheckOutcome {
    ctx.require(Capability::LifecycleSnapshotSandbox)?;
    ctx.with_ready(|sandbox| async move {
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
                    return fail(format!(
                        "{mode:?}: expected Unsupported({capability}), got {error}"
                    ));
                }
                Ok(id) => {
                    return fail(format!(
                        "undeclared snapshot mode {mode:?} created snapshot {id}"
                    ));
                }
            }
        }
        if checked {
            PASS
        } else {
            skip("all sandbox snapshot modes are declared")
        }
    })
    .await
}

pub(super) async fn services_match_capabilities(ctx: &Conformance) -> CheckOutcome {
    let caps = ctx.caps();
    let mut wrong: Vec<String> = Vec::new();
    let services = [
        (
            "snapshots",
            caps.snapshots.is_some(),
            ctx.provider.snapshots().is_some(),
        ),
        (
            "volumes",
            caps.volumes.is_some(),
            ctx.provider.volumes().is_some(),
        ),
    ];
    for (service, declared, present) in services {
        if declared != present {
            wrong.push(format!(
                "{service} service presence ({present}) disagrees with capabilities ({declared})"
            ));
        }
    }
    let sandbox = ctx.create().await?;
    ctx.lease(&sandbox);
    let sandbox_caps = sandbox.capabilities();
    // (what disagrees, declared, present)
    let facets = [
        (
            "preview_urls facet presence disagrees with capabilities",
            sandbox_caps.access.preview_urls,
            sandbox.preview_urls().is_some(),
        ),
        (
            "ssh facet presence disagrees with capabilities",
            sandbox_caps.access.ssh,
            sandbox.ssh().is_some(),
        ),
        (
            "shell_command facet presence disagrees with capabilities",
            sandbox_caps.access.shell_command,
            sandbox.shell_command().is_some(),
        ),
        (
            "pty facet presence disagrees with capabilities",
            sandbox_caps.pty.is_some(),
            sandbox.pty().is_some(),
        ),
        (
            "logs facet presence disagrees with capabilities",
            sandbox_caps.logs.is_some(),
            sandbox.logs().is_some(),
        ),
        (
            "search facet presence disagrees with capabilities",
            sandbox_caps.supports(Capability::Search),
            sandbox.search().is_some(),
        ),
        (
            "search provider override disagrees with search.native",
            sandbox_caps.search.native,
            sandbox.provider_search().is_some(),
        ),
        (
            "git facet presence disagrees with capabilities",
            sandbox_caps.supports(Capability::Git),
            sandbox.git().is_some(),
        ),
        (
            "git provider override disagrees with git.native",
            sandbox_caps.git.native,
            sandbox.provider_git().is_some(),
        ),
        (
            "services facet presence disagrees with capabilities",
            sandbox_caps.supports(Capability::Services),
            sandbox.services().is_some(),
        ),
        (
            "services provider override disagrees with services.native",
            sandbox_caps.services.native,
            sandbox.provider_services().is_some(),
        ),
        (
            "web_terminal facet presence disagrees with capabilities",
            sandbox_caps.access.web_terminal,
            sandbox.web_terminal().is_some(),
        ),
        (
            "vnc facet presence disagrees with capabilities",
            sandbox_caps.access.vnc,
            sandbox.vnc().is_some(),
        ),
    ];
    for (message, declared, present) in facets {
        if declared != present {
            wrong.push(message.to_owned());
        }
    }
    ctx.cleanup(&sandbox).await;
    if wrong.is_empty() {
        PASS
    } else {
        fail(wrong.join("; "))
    }
}

pub(super) async fn ssh_access_matches_capabilities(ctx: &Conformance) -> CheckOutcome {
    ctx.require(Capability::Ssh)?;
    ctx.with_ready(|sandbox| async move {
        let caps = sandbox.capabilities().access.clone();
        if !caps.ssh {
            return if sandbox.ssh().is_some() {
                fail("SSH facet is present but not declared for this sandbox")
            } else {
                skip("access.ssh not declared for this sandbox")
            };
        }
        let Some(ssh) = sandbox.ssh() else {
            return fail("access.ssh is declared but the SSH facet is absent");
        };

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
    })
    .await
}

pub(super) async fn shell_command_access_matches_capabilities(ctx: &Conformance) -> CheckOutcome {
    ctx.require(Capability::ShellCommandAccess)?;
    ctx.with_ready(|sandbox| async move {
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
    })
    .await
}

/// A spec field the capability set disclaims must be rejected with the
/// matching `Unsupported`, never silently dropped.
pub(super) async fn exec_rejects_undeclared_stdin_and_stop(ctx: &Conformance) -> CheckOutcome {
    let caps = ctx.caps();
    if caps.exec.stdin && caps.exec.stop {
        return skip("exec.stdin and exec.stop are both declared");
    }
    ctx.with_ready(|sandbox| async move {
        if !caps.exec.stdin {
            let spec = ExecSpec::new("cat")
                .stdin(b"dropped?".to_vec())
                .timeout(COMMAND_TIMEOUT);
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
            let spec = ExecSpec::new("true").timeout(COMMAND_TIMEOUT);
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
    })
    .await
}
