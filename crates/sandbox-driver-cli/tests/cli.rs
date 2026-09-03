use std::env;
use std::process::{self, Command, Output};

fn lithos_sandbox() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lithos-sandbox"));
    command.env_remove("SANDBOX_DRIVER_CONFIG");
    command.env(
        "XDG_CONFIG_HOME",
        env::temp_dir().join(format!("sandbox-driver-cli-test-{}", process::id())),
    );
    command
}

#[test]
fn help_names_the_resource_groups() {
    let output = lithos_sandbox().arg("--help").output().expect("CLI runs");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help is UTF-8");
    assert!(stdout.contains("provider"));
    assert!(stdout.contains("sandbox"));
}

#[test]
fn host_capabilities_are_available_as_json() {
    let output = lithos_sandbox()
        .args([
            "--provider",
            "host",
            "--output",
            "json",
            "provider",
            "capabilities",
        ])
        .output()
        .expect("CLI runs");

    assert!(output.status.success());
    let capabilities: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("capabilities are JSON");
    assert_eq!(capabilities["isolation"], "none");
    assert_eq!(capabilities["exec"]["live_streaming"], true);
}

#[test]
fn host_run_executes_in_one_process() {
    let workspace = env::current_dir().expect("current directory exists");
    let output = lithos_sandbox()
        .args(["--provider", "host", "sandbox", "run", "--workspace"])
        .arg(workspace)
        .args(["--", "printf", "%s", "hello from host"])
        .output()
        .expect("CLI runs");

    assert!(output.status.success(), "stderr: {}", stderr_text(&output));
    assert_eq!(output.stdout, b"hello from host");
}

#[test]
fn host_run_forwards_the_command_exit_code() {
    let output = lithos_sandbox()
        .args([
            "--provider",
            "host",
            "sandbox",
            "run",
            "--",
            "bash",
            "-lc",
            "exit 7",
        ])
        .output()
        .expect("CLI runs");

    assert_eq!(output.status.code(), Some(7));
}

#[test]
fn host_persistent_commands_explain_the_process_boundary() {
    let output = lithos_sandbox()
        .args([
            "--provider",
            "host",
            "sandbox",
            "create",
            "--host-directory",
        ])
        .output()
        .expect("CLI runs");

    assert!(!output.status.success());
    assert!(stderr_text(&output).contains("do not survive CLI process exit"));
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
