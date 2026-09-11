use std::fmt::Write as _;
use std::time::Duration;

use async_trait::async_trait;

use crate::derived::shell_quote;
use crate::error::{Error, ExecFailure, Result};
use crate::exec::{Exec, ExecResult, ExecSpec};
use crate::id::ServiceId;
use crate::service::{ListeningPort, ServiceSpec, ServiceStatus, Services};

const SERVICE_TIMEOUT: Duration = Duration::from_secs(60);
/// Stop grace: TERM, then up to ~2 seconds for traps to run, then KILL.
const STOP_GRACE_POLLS: usize = 10;
/// How often a port wait tries to connect.
const PORT_POLL: Duration = Duration::from_millis(500);
/// Lists listening TCP sockets with whatever the sandbox has: `ss`, then
/// `/proc/net/tcp*`, then `lsof` (a macOS host).
const LISTENING_PORTS_SCRIPT: &str = r#"if command -v ss >/dev/null 2>&1; then
  echo "SANDBOX_DRIVER_PORTS ss"
  ss -H -ltnp
  exit 0
fi
if [ -r /proc/net/tcp ] || [ -r /proc/net/tcp6 ]; then
  for file in /proc/net/tcp /proc/net/tcp6; do
    if [ -r "$file" ]; then
      echo "SANDBOX_DRIVER_PORTS procfs $file"
      cat -- "$file"
    fi
  done
  exit 0
fi
if command -v lsof >/dev/null 2>&1; then
  echo "SANDBOX_DRIVER_PORTS lsof"
  lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null
  exit 0
fi
echo "SANDBOX_DRIVER_PORTS none"
"#;

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

    async fn wait_for_port(&self, port: u16, timeout: Duration) -> Result<()> {
        // Bash's /dev/tcp connects without any network tool in the image;
        // the loop is bounded by the caller's timeout on the exec too.
        let polls = (timeout.as_millis() / PORT_POLL.as_millis()).max(1);
        let script = format!(
            "for _ in $(seq 1 {polls}); do\n\
             if (exec 3<>/dev/tcp/127.0.0.1/{port}) 2>/dev/null; then exit 0; fi\n\
             sleep {}\n\
             done\n\
             exit 7",
            PORT_POLL.as_secs_f64()
        );
        let spec = ExecSpec::bash(script).timeout(timeout + SERVICE_TIMEOUT);
        let result = self.exec.run(&spec).await?;
        match result.exit_code {
            Some(0) => Ok(()),
            Some(7) => Err(Error::Timeout {
                operation: format!("waiting for port {port}"),
                elapsed:   timeout,
            }),
            _ => Err(Error::Exec(
                ExecFailure::new(
                    "service port wait",
                    result.termination,
                    result.exit_code,
                    result.stdout,
                    result.stderr,
                )
                .with_duration(result.duration),
            )),
        }
    }

    async fn listening_ports(&self) -> Result<Vec<ListeningPort>> {
        let result = self
            .run("service ports", LISTENING_PORTS_SCRIPT.to_owned())
            .await?;
        Ok(parse_listening_ports(&result.stdout_lossy()))
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

/// Parses [`LISTENING_PORTS_SCRIPT`] output: the source marker, then that
/// tool's lines. Ports are reported once each, lowest first.
fn parse_listening_ports(output: &str) -> Vec<ListeningPort> {
    let mut lines = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let Some(marker) = lines.next() else {
        return Vec::new();
    };
    let mut ports: Vec<ListeningPort> = match marker.strip_prefix("SANDBOX_DRIVER_PORTS ") {
        Some("ss") => lines.filter_map(parse_ss_line).collect(),
        Some(procfs) if procfs.starts_with("procfs") => parse_procfs(lines),
        Some("lsof") => lines.filter_map(parse_lsof_line).collect(),
        _ => Vec::new(),
    };
    ports.sort_by_key(|entry| entry.port);
    ports.dedup_by_key(|entry| entry.port);
    ports
}

/// `ss -H -ltnp`: `LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*
/// users:(("node",pid=12,fd=18))`.
fn parse_ss_line(line: &str) -> Option<ListeningPort> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let address = *fields.get(3)?;
    let port = address.rsplit_once(':')?.1.parse::<u16>().ok()?;
    let process = fields
        .get(5..)
        .filter(|rest| !rest.is_empty())
        .map(|rest| rest.join(" "))
        .and_then(|users| ss_process_name(&users));
    let mut entry = ListeningPort::new(port, address);
    entry.process = process;
    Some(entry)
}

/// The first process name in `users:(("node",pid=12,fd=18),...)`.
fn ss_process_name(users: &str) -> Option<String> {
    let start = users.find("((\"")? + 3;
    let end = users[start..].find('"')? + start;
    Some(users[start..end].to_owned())
}

/// `/proc/net/tcp` and `tcp6`: hex `local_address` and state `0A` (LISTEN).
fn parse_procfs<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<ListeningPort> {
    let mut ports = Vec::new();
    let mut ipv6 = false;
    for line in lines {
        if let Some(path) = line.strip_prefix("SANDBOX_DRIVER_PORTS procfs ") {
            ipv6 = path.ends_with("tcp6");
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first().is_some_and(|first| *first == "sl") {
            continue;
        }
        let (Some(local), Some(state)) = (fields.get(1), fields.get(3)) else {
            continue;
        };
        if *state != "0A" {
            continue;
        }
        let Some((address_hex, port_hex)) = local.rsplit_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        let address = if ipv6 {
            format!("[{}]:{port}", procfs_ipv6(address_hex))
        } else {
            format!("{}:{port}", procfs_ipv4(address_hex))
        };
        ports.push(ListeningPort::new(port, address));
    }
    ports
}

/// A little-endian hex IPv4 address from procfs (`0100007F` is 127.0.0.1).
fn procfs_ipv4(hex: &str) -> String {
    let Ok(value) = u32::from_str_radix(hex, 16) else {
        return hex.to_owned();
    };
    let bytes = value.to_le_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// A procfs IPv6 address: four little-endian 32-bit words in hex. Rendered
/// as the words' groups without compression.
fn procfs_ipv6(hex: &str) -> String {
    if hex.len() != 32 {
        return hex.to_owned();
    }
    let mut groups = Vec::with_capacity(8);
    for word in 0..4 {
        let Ok(value) = u32::from_str_radix(&hex[word * 8..word * 8 + 8], 16) else {
            return hex.to_owned();
        };
        let bytes = value.to_le_bytes();
        groups.push(format!("{:x}", u16::from_be_bytes([bytes[0], bytes[1]])));
        groups.push(format!("{:x}", u16::from_be_bytes([bytes[2], bytes[3]])));
    }
    groups.join(":")
}

/// `lsof -nP -iTCP -sTCP:LISTEN`: `node 12 user 18u IPv4 0x... 0t0 TCP *:8080
/// (LISTEN)`.
fn parse_lsof_line(line: &str) -> Option<ListeningPort> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.first().is_some_and(|first| *first == "COMMAND") {
        return None;
    }
    let name = fields.iter().rev().nth(1)?;
    let port = name.rsplit_once(':')?.1.parse::<u16>().ok()?;
    let mut entry = ListeningPort::new(port, (*name).to_owned());
    entry.process = fields.first().map(|command| (*command).to_owned());
    Some(entry)
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

    #[test]
    fn listening_ports_parse_every_source() {
        let ss = "SANDBOX_DRIVER_PORTS ss\n\
                  LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:((\"node\",pid=12,fd=18))\n\
                  LISTEN 0 128 [::]:22 [::]:*\n";
        let ports = parse_listening_ports(ss);
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].port, 22);
        assert_eq!(ports[1].port, 8080);
        assert_eq!(ports[1].process.as_deref(), Some("node"));

        let procfs = "SANDBOX_DRIVER_PORTS procfs /proc/net/tcp\n\
                      sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n\
                      0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1 0000000000000000 100 0 0 10 0\n\
                      1: 0100007F:1F91 00000000:0000 01 00000000:00000000 00:00000000 00000000 0 0 1 1 0000000000000000 100 0 0 10 0\n\
                      SANDBOX_DRIVER_PORTS procfs /proc/net/tcp6\n\
                      sl local_address rem_address st\n\
                      0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1 0000000000000000 100 0 0 10 0\n";
        let ports = parse_listening_ports(procfs);
        assert_eq!(ports.len(), 2, "{ports:?}");
        assert_eq!(ports[0].port, 22);
        assert_eq!(ports[0].address, "[0:0:0:0:0:0:0:0]:22");
        assert_eq!(ports[1].port, 8080);
        assert_eq!(ports[1].address, "127.0.0.1:8080");

        let lsof = "SANDBOX_DRIVER_PORTS lsof\n\
                    COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n\
                    python3 41 user 3u IPv4 0x1 0t0 TCP 127.0.0.1:3000 (LISTEN)\n";
        let ports = parse_listening_ports(lsof);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 3000);
        assert_eq!(ports[0].process.as_deref(), Some("python3"));

        assert!(parse_listening_ports("SANDBOX_DRIVER_PORTS none\n").is_empty());
    }
}
