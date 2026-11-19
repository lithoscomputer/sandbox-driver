//! Live black-box workflows for the `lithos-sandbox` binary against the
//! built-in Docker and Daytona providers, reached through the default
//! catalog exactly as a person at a terminal reaches them.
//!
//! Docker runs only when its daemon is reachable, unless
//! `LITHOS_CLI_E2E_REQUIRE_LIVE` demands it. Daytona is ignored by default;
//! `mise run test:live` runs it with credentials from the process
//! environment or the workspace `.env` file. Every created sandbox carries
//! a unique label and a cleanup guard.
//!
//! The process-level checks that need no backend run against Host.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{env, fs, thread};

use serde_json::Value;

const DAYTONA_ENV: &[&str] = &[
    "DAYTONA_API_KEY",
    "DAYTONA_JWT_TOKEN",
    "DAYTONA_ORGANIZATION_ID",
    "DAYTONA_API_URL",
    "DAYTONA_TARGET",
];
const REQUIRE_LIVE_ENV: &str = "LITHOS_CLI_E2E_REQUIRE_LIVE";
const TEST_IMAGE: &str = "ghcr.io/lithoscomputer/ubuntu-24.04:slim-df708f910111";
/// How long a provider's listing may lag behind the sandbox itself.
const LISTING_LAG: Duration = Duration::from_secs(60);
const LISTING_POLL: Duration = Duration::from_secs(1);

#[test]
fn docker_cli_workflow() {
    let cli = CliRunner::new();
    if !provider_is_healthy(&cli, "docker") {
        assert!(
            !live_providers_required(),
            "Docker is required, but its daemon is unreachable"
        );
        return;
    }
    workflow(&cli, "docker", "machine");
}

#[test]
#[ignore = "requires Daytona credentials; run with `mise run test:live`"]
fn daytona_cli_workflow() {
    let cli = CliRunner::new();
    assert!(
        cli.has_daytona_credentials(),
        "Daytona is required, but no API key or JWT token is available"
    );
    assert!(provider_is_healthy(&cli, "daytona"), "Daytona is unhealthy");
    workflow(&cli, "daytona", "remote");
}

/// Everything a person checks by hand: describe, one-shot runs, then a
/// persistent sandbox through find, exec, files, stop/start and destroy.
/// The command decides when `--stdin` ends: a terminal or pipe that stays
/// open after the command exits must not hold the CLI open with it.
#[test]
fn a_finished_command_exits_while_local_stdin_stays_open() {
    let mut child = CliRunner::new()
        .command()
        .args(["run", "host", "--stdin", "--", "echo", "done"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("lithos-sandbox process starts");
    let held_open = child.stdin.take().expect("child stdin is piped");

    let deadline = Instant::now() + Duration::from_secs(30);
    let exited = loop {
        if child.try_wait().expect("poll lithos-sandbox").is_some() {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        thread::sleep(Duration::from_millis(50));
    };
    if !exited {
        child.kill().expect("stop the stuck lithos-sandbox");
    }
    let output = child.wait_with_output().expect("wait for lithos-sandbox");
    drop(held_open);

    assert!(
        exited,
        "the CLI waited for stdin to close: {}",
        diagnostic(&output)
    );
    assert_success(&output, "host run with stdin held open");
    assert_eq!(stdout_text(&output), "done\n");
}

fn workflow(cli: &CliRunner, provider: &str, durability: &str) {
    let describe = successful_json(
        &run(cli
            .command()
            .args(["--output", "json", "provider", "describe", provider])),
        "provider describe",
    );
    assert_eq!(describe["durability"], durability, "{describe}");
    assert_eq!(describe["schemas"]["kind"], provider, "{describe}");

    run_one_shot(cli, provider);
    persistent_workflow(cli, provider);
}

fn run_one_shot(cli: &CliRunner, provider: &str) {
    let label = unique("cli-run");
    let output = run(cli.command().args([
        "run",
        provider,
        "--image",
        TEST_IMAGE,
        "--label",
        &format!("cli-test={label}"),
        "-e",
        "GREETING=hello",
        "--",
        "sh",
        "-c",
        "printf '%s\\n' \"$GREETING\"; printf 'to stderr\\n' >&2; exit 3",
    ]));
    assert_eq!(output.status.code(), Some(3), "{}", diagnostic(&output));
    assert_eq!(stdout_text(&output), "hello\n");
    assert!(
        stderr_text(&output).contains("to stderr"),
        "{}",
        diagnostic(&output)
    );
    // `run` destroys its sandbox, also when the command fails.
    let left = find_until(cli, &label, none_live);
    assert!(none_live(&left), "run left its sandbox behind: {left:?}");
}

fn persistent_workflow(cli: &CliRunner, provider: &str) {
    let label = unique("cli-persistent");
    let name = unique("lithos-cli");
    let created = run(cli.command().args([
        "create",
        provider,
        "--image",
        TEST_IMAGE,
        "--name",
        &name,
        "--label",
        &format!("cli-test={label}"),
    ]));
    assert_success(&created, "create");
    let reference = stdout_text(&created).trim().to_owned();
    assert!(
        reference.starts_with(&format!("{provider}/")),
        "create printed {reference:?}"
    );
    let mut guard = SandboxGuard::new(cli, reference.clone());

    let found = find_until(cli, &label, |found| {
        found.len() == 1 && found[0]["state"] == "running"
    });
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0]["name"], name.as_str());
    assert_eq!(found[0]["state"], "running");

    let status = successful_json(
        &run(cli
            .command()
            .args(["--output", "json", "status", &reference])),
        "status",
    );
    assert_eq!(status["state"], "running", "{status}");
    assert_eq!(status["labels"]["cli-test"], label.as_str(), "{status}");

    // Exec: working directory, environment, stdin and exit codes.
    let exec = run(cli.command().args([
        "exec",
        &reference,
        "-w",
        "/tmp",
        "-e",
        "A=b",
        "--",
        "sh",
        "-c",
        "pwd; echo $A",
    ]));
    assert_success(&exec, "exec");
    assert_eq!(stdout_text(&exec), "/tmp\nb\n");
    let echoed = run_with_stdin(
        cli.command().args(["exec", "-i", &reference, "--", "cat"]),
        b"streamed stdin\n",
    );
    assert_success(&echoed, "exec with stdin");
    assert_eq!(stdout_text(&echoed), "streamed stdin\n");
    let failed = run(cli
        .command()
        .args(["exec", &reference, "--", "sh", "-c", "exit 9"]));
    assert_eq!(failed.status.code(), Some(9), "{}", diagnostic(&failed));
    let timed_out =
        run(cli
            .command()
            .args(["exec", &reference, "--timeout", "1s", "--", "sleep", "30"]));
    assert_eq!(
        timed_out.status.code(),
        Some(124),
        "{}",
        diagnostic(&timed_out)
    );
    let json_exec = run(cli
        .command()
        .args(["--output", "json", "exec", &reference, "--", "true"]));
    assert!(!json_exec.status.success());

    // Files: upload, list, download to a file and to stdout.
    let directory = TestDirectory::new(&unique("files"));
    let local = directory.path.join("upload.txt");
    fs::write(&local, b"payload\n").expect("write upload");
    let remote = format!("{reference}:/tmp/cli-test/upload.txt");
    assert_success(
        &run(cli.command().arg("cp").arg(&local).arg(&remote)),
        "cp upload",
    );
    let listing = successful_json(
        &run(cli.command().args([
            "--output",
            "json",
            "ls",
            &format!("{reference}:/tmp/cli-test"),
        ])),
        "ls",
    );
    assert!(
        listing
            .as_array()
            .is_some_and(|entries| entries.iter().any(|entry| entry["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("upload.txt")))),
        "{listing}"
    );
    let downloaded = directory.path.join("download.txt");
    assert_success(
        &run(cli.command().arg("cp").arg(&remote).arg(&downloaded)),
        "cp download",
    );
    assert_eq!(fs::read(&downloaded).expect("read download"), b"payload\n");
    let streamed = run(cli.command().args(["cp", &remote, "-"]));
    assert_success(&streamed, "cp to stdout");
    assert_eq!(stdout_text(&streamed), "payload\n");

    // Stop fences commands; start brings the sandbox back with its files.
    assert_success(&run(cli.command().args(["stop", &reference])), "stop");
    let stopped = successful_json(
        &run(cli
            .command()
            .args(["--output", "json", "status", &reference])),
        "status after stop",
    );
    assert_eq!(stopped["state"], "stopped", "{stopped}");
    assert!(
        !run(cli.command().args(["exec", &reference, "--", "true"]))
            .status
            .success()
    );
    assert_success(&run(cli.command().args(["start", &reference])), "start");
    let kept =
        run(cli
            .command()
            .args(["exec", &reference, "--", "cat", "/tmp/cli-test/upload.txt"]));
    assert_success(&kept, "exec after start");
    assert_eq!(stdout_text(&kept), "payload\n");

    // The JSON reference from `--output json` works wherever a ref does.
    let json_ref = serde_json::to_string(&status["reference"]).expect("reference");
    assert_success(
        &run(cli.command().args(["status", &json_ref])),
        "status by JSON ref",
    );

    assert_success(&run(cli.command().args(["destroy", &reference])), "destroy");
    guard.disarm();
    let left = find_until(cli, &label, none_live);
    assert!(
        none_live(&left),
        "destroyed sandbox is still listed: {left:?}"
    );
    assert!(
        !run(cli.command().args(["status", &reference]))
            .status
            .success()
    );
}

fn find(cli: &CliRunner, label: &str) -> Vec<Value> {
    let found = successful_json(
        &run(cli.command().args([
            "--output",
            "json",
            "find",
            "--label",
            &format!("cli-test={label}"),
        ])),
        "find",
    );
    found.as_array().cloned().expect("find returns a list")
}

/// Lists the label's sandboxes until `settled` accepts the listing or
/// [`LISTING_LAG`] has passed, and returns the last listing. `create`, `run`
/// and `destroy` confirm their outcome through the sandbox itself; a
/// provider's listing may catch up seconds later, as Daytona's does.
fn find_until(cli: &CliRunner, label: &str, settled: impl Fn(&[Value]) -> bool) -> Vec<Value> {
    let deadline = Instant::now() + LISTING_LAG;
    loop {
        let found = find(cli, label);
        if settled(&found) || Instant::now() >= deadline {
            return found;
        }
        thread::sleep(LISTING_POLL);
    }
}

/// Whether the listing shows no sandbox other than ones already deleted.
fn none_live(found: &[Value]) -> bool {
    found.iter().all(|sandbox| sandbox["state"] == "deleted")
}

fn provider_is_healthy(cli: &CliRunner, provider: &str) -> bool {
    let output = run(cli
        .command()
        .args(["--output", "json", "provider", "health", provider]));
    serde_json::from_slice::<Value>(&output.stdout)
        .is_ok_and(|health| health["healthy"] == true && output.status.success())
}

fn successful_json(output: &Output, context: &str) -> Value {
    assert_success(output, context);
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{context} was not JSON: {error}; {}", diagnostic(output)))
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed: {}",
        diagnostic(output)
    );
}

fn diagnostic(output: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout_text(output),
        stderr_text(output)
    )
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn unique(prefix: &str) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock follows the Unix epoch")
        .as_nanos();
    format!("{prefix}-{}-{timestamp}", process::id())
}

struct CliRunner {
    extra_env: BTreeMap<&'static str, OsString>,
}

impl CliRunner {
    fn new() -> Self {
        Self {
            extra_env: load_daytona_dotenv(),
        }
    }

    /// The CLI with no catalog file, so it uses its built-in entries.
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lithos-sandbox"));
        command
            .current_dir(workspace_root())
            .env_remove("SANDBOX_DRIVER_CONFIG")
            .env("NO_COLOR", "1")
            .env(
                "XDG_CONFIG_HOME",
                workspace_root().join("target/cli-e2e/no-config"),
            )
            .envs(&self.extra_env);
        command
    }

    fn has_daytona_credentials(&self) -> bool {
        ["DAYTONA_API_KEY", "DAYTONA_JWT_TOKEN"].iter().any(|name| {
            has_nonempty_env(name)
                || self
                    .extra_env
                    .get(name)
                    .is_some_and(|value| !value.is_empty())
        })
    }
}

fn run(command: &mut Command) -> Output {
    command.output().expect("lithos-sandbox process starts")
}

fn run_with_stdin(command: &mut Command, input: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("lithos-sandbox process starts");
    child
        .stdin
        .take()
        .expect("child stdin is piped")
        .write_all(input)
        .expect("write child stdin");
    child.wait_with_output().expect("wait for lithos-sandbox")
}

fn load_daytona_dotenv() -> BTreeMap<&'static str, OsString> {
    let Ok(contents) = fs::read_to_string(workspace_root().join(".env")) else {
        return BTreeMap::new();
    };
    DAYTONA_ENV
        .iter()
        .filter(|name| !has_nonempty_env(name))
        .filter_map(|&name| Some((name, OsString::from(dotenv_value(&contents, name)?))))
        .collect()
}

fn dotenv_value(contents: &str, name: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let line = line.trim().strip_prefix("export ").unwrap_or(line.trim());
        let (key, value) = line.split_once('=')?;
        if key.trim() != name {
            return None;
        }
        let value = value.trim();
        let unquoted = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|value| value.strip_suffix('\''))
            })
            .unwrap_or(value);
        (!unquoted.is_empty()).then(|| unquoted.to_owned())
    })
}

fn has_nonempty_env(name: &str) -> bool {
    env::var_os(name).is_some_and(|value| !value.is_empty())
}

fn live_providers_required() -> bool {
    has_nonempty_env(REQUIRE_LIVE_ENV)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Destroys the sandbox if the test fails before it does.
struct SandboxGuard<'a> {
    cli:       &'a CliRunner,
    reference: String,
    armed:     bool,
}

impl<'a> SandboxGuard<'a> {
    fn new(cli: &'a CliRunner, reference: String) -> Self {
        Self {
            cli,
            reference,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SandboxGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self
                .cli
                .command()
                .args(["destroy", &self.reference])
                .output();
        }
    }
}

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(name: &str) -> Self {
        let path = workspace_root().join("target/cli-e2e").join(name);
        fs::create_dir_all(&path).expect("create CLI test directory");
        Self { path }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
