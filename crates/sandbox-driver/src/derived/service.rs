use std::fmt::Write as _;
use std::time::Duration;

use async_trait::async_trait;

use crate::derived::shell_quote;
use crate::error::{Error, ExecFailure, Result};
use crate::exec::{Exec, ExecResult, ExecSpec};
use crate::id::ServiceId;
use crate::service::{ServiceSpec, ServiceStatus, Services};

const SERVICE_TIMEOUT: Duration = Duration::from_secs(60);
/// Stop grace: TERM, then up to ~2 seconds for traps to run, then KILL.
const STOP_GRACE_POLLS: usize = 10;

/// Every service directory the derived implementation creates matches
/// this `mktemp` template under `/tmp`; the basename is the service id.
const SERVICE_DIR_PREFIX: &str = "sandbox-driver-service-";

/// Exec-derived [`Services`] for providers without a native
/// background-process API — the `setsid`-and-pidfile pattern.
///
/// Each service gets a sandbox-side directory
/// `/tmp/sandbox-driver-service-XXXXXXXXXX` holding its process-group id
/// (`pid`), combined output (`log`), and exit code (`exit`). The service
/// runs in its own session (`setsid`), so it survives the spawning exec
/// and a group kill reaches every descendant. State is per-boot: a
/// sandbox restart clears `/tmp` and ids from the previous boot report
/// not running.
///
/// Like [`crate::DerivedSearch`], borrows the exec facet so it works ad
/// hoc over any sandbox handle: `DerivedServices::new(sandbox.exec())`.
pub struct DerivedServices<'e> {
    exec: &'e dyn Exec,
}

impl<'e> DerivedServices<'e> {
    pub fn new(exec: &'e dyn Exec) -> Self {
        Self { exec }
    }

    async fn run(&self, label: &'static str, command: String) -> Result<ExecResult> {
        let spec = ExecSpec::bash(command).timeout(SERVICE_TIMEOUT);
        let result = self.exec.run(&spec).await?;
        if result.success() {
            return Ok(result);
        }
        Err(Error::Exec(
            ExecFailure::new(
                label,
                result.termination,
                result.exit_code,
                result.stdout,
                result.stderr,
            )
            .with_duration(result.duration),
        ))
    }
}

/// Whether an id names a directory this implementation could have
/// created. Ids are caller input that gets embedded in a `/tmp` path, so
/// anything but our own `mktemp` shape (prefix plus an alphanumeric
/// suffix) is rejected before it can traverse elsewhere.
fn is_our_service_id(id: &ServiceId) -> bool {
    let Some(suffix) = id.as_str().strip_prefix(SERVICE_DIR_PREFIX) else {
        return false;
    };
    !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_alphanumeric())
}

fn service_dir(id: &ServiceId) -> String {
    format!("/tmp/{}", id.as_str())
}

#[async_trait]
impl Services for DerivedServices<'_> {
    async fn spawn(&self, spec: &ServiceSpec) -> Result<ServiceId> {
        // The sandbox itself mints the id (mktemp), so no local
        // randomness is needed and the directory cannot collide. The
        // service runs in its own session; the recorder appends the exit
        // code when the command ends (best-effort — a command that
        // `exec`s away skips it, and status falls back to the pid).
        let mut script = String::new();
        let _ = writeln!(
            script,
            "dir=$(mktemp -d /tmp/{SERVICE_DIR_PREFIX}XXXXXXXXXX) || exit 9"
        );
        if let Some(dir) = &spec.working_dir {
            let _ = writeln!(script, "cd -- {} || exit 8", shell_quote(dir));
        }
        for (key, value) in &spec.env {
            // Quote the key as well as the value: a malformed key must
            // corrupt nothing but its own export, never the script.
            let _ = writeln!(script, "export {}={}", shell_quote(key), shell_quote(value));
        }
        script.push_str("export SANDBOX_DRIVER_SERVICE_DIR=\"$dir\"\n");
        // The exit record is what status trusts: a sandbox whose PID 1
        // does not reap orphans (the Docker provider's `sleep` init)
        // leaves a killed service as a zombie, and `kill -0` on a zombie
        // still succeeds — so a TERM must write the record before dying.
        let supervised = format!(
            "trap 'echo 143 > \"$SANDBOX_DRIVER_SERVICE_DIR/exit\"; exit 143' TERM\n\
             {{ {}\n}}; echo $? > \"$SANDBOX_DRIVER_SERVICE_DIR/exit\"",
            spec.command
        );
        // setsid gives the service its own session so a group kill
        // reaches every descendant; a userland without it (macOS host)
        // falls back to a plain background job, and stop falls back to
        // a single-pid kill.
        let quoted = shell_quote(&supervised);
        let _ = writeln!(
            script,
            "if command -v setsid > /dev/null 2>&1; then\n\
             setsid bash -c {quoted} < /dev/null >> \"$dir/log\" 2>&1 &\n\
             else\n\
             bash -c {quoted} < /dev/null >> \"$dir/log\" 2>&1 &\n\
             fi"
        );
        script.push_str("echo $! > \"$dir/pid\"\n");
        script.push_str("basename \"$dir\"\n");

        let result = self.run("service spawn", script).await?;
        let stdout = result.stdout_lossy();
        let name = stdout.trim().lines().next_back().unwrap_or("").trim();
        let id = ServiceId::try_new(name)
            .map_err(|error| Error::invalid_spec("service_id", error.to_string()))?;
        if !is_our_service_id(&id) {
            return Err(Error::invalid_spec(
                "service_id",
                format!("unexpected spawn output {name:?}"),
            ));
        }
        Ok(id)
    }

    async fn status(&self, id: &ServiceId) -> Result<ServiceStatus> {
        if !is_our_service_id(id) {
            return Ok(ServiceStatus::new(id.clone(), false));
        }
        let dir = service_dir(id);
        let command = format!(
            "dir={dir}\n\
             if [ -f \"$dir/exit\" ]; then echo \"exited $(cat -- \"$dir/exit\")\"; \
             elif [ -f \"$dir/pid\" ] && kill -0 \"$(cat -- \"$dir/pid\")\" 2>/dev/null; \
             then echo running; \
             else echo unknown; fi"
        );
        let result = self.run("service status", command).await?;
        let stdout = result.stdout_lossy();
        let text = stdout.trim();
        let mut status = ServiceStatus::new(id.clone(), text == "running");
        if let Some(code) = text.strip_prefix("exited ") {
            status.exit_code = code.trim().parse().ok();
        }
        Ok(status)
    }

    async fn logs(&self, id: &ServiceId, tail_bytes: usize) -> Result<Vec<u8>> {
        if !is_our_service_id(id) {
            return Ok(Vec::new());
        }
        let dir = service_dir(id);
        let command = format!("if [ -f {dir}/log ]; then tail -c {tail_bytes} -- {dir}/log; fi");
        let result = self.run("service logs", command).await?;
        Ok(result.stdout)
    }

    async fn stop(&self, id: &ServiceId) -> Result<()> {
        if !is_our_service_id(id) {
            return Ok(());
        }
        let dir = service_dir(id);
        // TERM the whole process group, wait for the leader to go, then
        // KILL what remains. Every step tolerates an already-gone
        // process, so stop is idempotent.
        let command = format!(
            "dir={dir}\n\
             [ -f \"$dir/pid\" ] || exit 0\n\
             pid=$(cat -- \"$dir/pid\")\n\
             case \"$pid\" in ''|*[!0-9]*) exit 0;; esac\n\
             kill -TERM -- \"-$pid\" 2>/dev/null || kill -TERM -- \"$pid\" 2>/dev/null || true\n\
             for _ in $(seq 1 {STOP_GRACE_POLLS}); do\n\
               [ -f \"$dir/exit\" ] && exit 0\n\
               kill -0 \"$pid\" 2>/dev/null || exit 0\n\
               sleep 0.2\n\
             done\n\
             kill -KILL -- \"-$pid\" 2>/dev/null || kill -KILL -- \"$pid\" 2>/dev/null || true\n\
             [ -f \"$dir/exit\" ] || echo 137 > \"$dir/exit\"\n\
             exit 0"
        );
        self.run("service stop", command).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_exec::ScriptedExec;

    #[tokio::test]
    async fn spawn_quotes_env_keys_as_well_as_values() {
        let exec = ScriptedExec::new(vec![ScriptedExec::ok("sandbox-driver-service-Ab3dEf01\n")]);
        let services = DerivedServices::new(&exec);
        let spec = ServiceSpec::new("run-server").env_var("BAD KEY; touch /pwned", "x");
        services.spawn(&spec).await.expect("spawn");

        let command = &exec.commands()[0];
        // The whole assignment stays inside the export word: a hostile
        // key corrupts only its own export, never the script.
        assert!(
            command.contains("export 'BAD KEY; touch /pwned'='x'"),
            "script: {command}"
        );
        assert!(
            !command.contains("export BAD KEY"),
            "unquoted key must not reach the script: {command}"
        );
    }

    #[test]
    fn foreign_ids_are_rejected_before_reaching_a_path() {
        let ours = ServiceId::try_new("sandbox-driver-service-Ab3dEf01").expect("valid id");
        assert!(is_our_service_id(&ours));
        for bad in [
            "sandbox-driver-service-",
            "sandbox-driver-service-../../etc",
            "other-prefix-abc",
            "sandbox-driver-service-a/b",
        ] {
            let id = ServiceId::try_new(bad).expect("shape is a valid id");
            assert!(!is_our_service_id(&id), "{bad} must be rejected");
        }
    }
}
