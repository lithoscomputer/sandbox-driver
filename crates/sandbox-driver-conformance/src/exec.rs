//! Buffered exec: exit codes, environment, literal argv, binary-safe
//! output, sanitization, and stdin.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use sandbox_driver::{ExecControls, ExecSpec, OutputSanitization, Termination};

use crate::Conformance;
use crate::check::{CheckOutcome, PASS, SeenChunks, cleanup, fail};

/// A relative exec `working_dir` resolves against the sandbox working
/// directory on every provider.
pub(super) async fn relative_working_dir_resolves(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let mkdir = sandbox
            .exec()
            .run(
                &ExecSpec::new("mkdir")
                    .args(["-p", "cwd-probe"])
                    .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("mkdir failed: {error}"))?;
        if !mkdir.success() {
            return fail(format!("mkdir failed: {}", mkdir.stderr_lossy()));
        }
        let result = sandbox
            .exec()
            .run(
                &ExecSpec::new("pwd")
                    .working_dir("cwd-probe")
                    .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        let pwd = result.stdout_lossy().trim().to_owned();
        let expected = format!(
            "{}/cwd-probe",
            sandbox.working_directory().trim_end_matches('/')
        );
        if pwd != expected {
            return fail(format!("pwd is {pwd:?}, expected {expected:?}"));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

pub(super) async fn exec_reports_exit_codes(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let result = sandbox
            .exec()
            .run(&ExecSpec::bash("exit 7").timeout(Duration::from_secs(30)))
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if result.exit_code != Some(7) {
            return fail(format!("expected exit code 7, got {:?}", result.exit_code));
        }
        if result.termination != Termination::Exited {
            return fail(format!("expected Exited, got {:?}", result.termination));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

pub(super) async fn exec_env_vars_apply(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let spec = ExecSpec::bash("printf '%s' \"$CONFORMANCE_VALUE\"")
            .env_var("CONFORMANCE_VALUE", "expected-value")
            .timeout(Duration::from_secs(30));
        let result = sandbox
            .exec()
            .run(&spec)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if result.stdout_lossy() != "expected-value" {
            return fail(format!(
                "environment variable missing: {:?}",
                result.stdout_lossy()
            ));
        }
        // A name that is not a shell identifier must reach the program
        // too (GitHub Actions passes `INPUT_INCLUDE-HIDDEN-FILES`); a
        // provider that routes env through a POSIX shell's own
        // environment drops it.
        let spec = ExecSpec::new("printenv")
            .arg("CONFORMANCE-DASHED")
            .env_var("CONFORMANCE-DASHED", "dashed-value")
            .timeout(Duration::from_secs(30));
        let result = sandbox
            .exec()
            .run(&spec)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if result.stdout_lossy().trim() != "dashed-value" {
            return fail(format!(
                "non-identifier environment variable missing: {:?} (exit {:?})",
                result.stdout_lossy(),
                result.exit_code
            ));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

/// The exec contract: arguments reach the program unchanged. A provider
/// that routes argv through a shell must quote it so nothing expands.
/// The Bash helper's `BASH_ENV` blank wins over a caller's value: a startup
/// file named in the spec env never runs ahead of a `bash -c` script, on
/// every provider, however the provider composes the environment.
pub(super) async fn bash_helper_ignores_a_caller_bash_env(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        sandbox
            .fs()
            .write("conformance-startup.sh", b"echo INJECTED\n")
            .await
            .map_err(|error| format!("writing the startup file failed: {error}"))?;
        let root = sandbox.working_directory().trim_end_matches('/');
        let spec = ExecSpec::bash("echo ran")
            .env_var("BASH_ENV", format!("{root}/conformance-startup.sh"))
            .timeout(Duration::from_secs(30));
        let result = sandbox
            .exec()
            .run(&spec)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        let stdout = result.stdout_lossy();
        if !result.success() || !stdout.contains("ran") {
            return fail(format!(
                "the helper did not run: exit {:?}, stdout {stdout:?}",
                result.exit_code
            ));
        }
        if stdout.contains("INJECTED") {
            return fail(format!(
                "a caller-supplied BASH_ENV ran ahead of the script: {stdout:?}"
            ));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

pub(super) async fn exec_argv_is_literal(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let hostile = "$CONFORMANCE_VALUE `id` $(id) * ; it's \"quoted\"";
        let spec = ExecSpec::new("printf")
            .args(["%s|%s", hostile, "second arg"])
            .env_var("CONFORMANCE_VALUE", "expanded")
            .timeout(Duration::from_secs(30));
        let result = sandbox
            .exec()
            .run(&spec)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        let expected = format!("{hostile}|second arg");
        if result.stdout_lossy() != expected {
            return fail(format!(
                "argv was not literal: {:?} (expected {expected:?})",
                result.stdout_lossy()
            ));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

pub(super) async fn exec_output_is_binary_safe(ctx: &Conformance) -> CheckOutcome {
    use std::fmt::Write as _;

    let sandbox = ctx.ready().await?;
    let outcome = async {
        // All byte values, repeated across transport chunk boundaries, with
        // adjacent NULs and no final newline. No text conversion is lossless.
        let mut octal = String::new();
        for byte in 0..=255 {
            write!(octal, "\\{byte:03o}").expect("writing to a String");
        }
        let command = format!("for i in {{1..8}}; do printf '{octal}'; done; printf '\\0\\0x'");
        let expected: Vec<u8> = (0..=255).cycle().take(2048).chain([0, 0, b'x']).collect();
        let spec = ExecSpec::bash(command).timeout(Duration::from_secs(30));
        let result = sandbox
            .exec()
            .run(&spec)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if result.stdout != expected {
            return fail(format!("binary output mangled: {:?}", result.stdout));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

pub(super) async fn exec_output_sanitization_is_consistent(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let command = "printf '\\033[31mred\\033[0m\\007\\001\\n'";

        let raw = sandbox
            .exec()
            .run(&ExecSpec::bash(command))
            .await
            .map_err(|error| format!("raw exec failed: {error}"))?;
        if raw.stdout != b"\x1b[31mred\x1b[0m\x07\x01\n" {
            return fail(format!("raw output changed: {:?}", raw.stdout));
        }

        let ansi = sandbox
            .exec()
            .run(&ExecSpec::bash(command).output_sanitization(OutputSanitization::StripAnsi))
            .await
            .map_err(|error| format!("StripAnsi exec failed: {error}"))?;
        if ansi.stdout != b"red\x07\x01\n" {
            return fail(format!(
                "StripAnsi returned wrong output: {:?}",
                ansi.stdout
            ));
        }

        let chunks: SeenChunks = Arc::new(Mutex::new(Vec::new()));
        let sink_chunks = Arc::clone(&chunks);
        let controls = ExecControls {
            sink: Some(Arc::new(move |stream, chunk| {
                let chunks = Arc::clone(&sink_chunks);
                Box::pin(async move {
                    chunks.lock().expect("chunks lock").push((stream, chunk));
                    Ok(())
                })
            })),
            ..ExecControls::buffered()
        };
        let spec =
            ExecSpec::bash("printf '\\033'; sleep 0.05; printf '[31mred\\033[0m\\007\\001\\n'")
                .output_sanitization(OutputSanitization::StripAll)
                .timeout(Duration::from_secs(30));
        let all = sandbox
            .exec()
            .run_streaming(&spec, controls)
            .await
            .map_err(|error| format!("StripAll streaming exec failed: {error}"))?;
        if !all.result.success() {
            return fail(format!(
                "StripAll streaming command failed: {}",
                all.result.stderr_lossy()
            ));
        }
        if all.result.stdout != b"red\n" {
            return fail(format!(
                "StripAll returned wrong output: {:?}",
                all.result.stdout
            ));
        }
        let streamed: Vec<u8> = chunks
            .lock()
            .expect("chunks lock")
            .iter()
            .flat_map(|(_, chunk)| chunk.clone())
            .collect();
        if streamed != b"red\n" {
            return fail(format!("StripAll sink saw wrong output: {streamed:?}"));
        }
        if all.stdout_capture.observed_bytes != b"red\n".len() {
            return fail(format!(
                "capture stats counted pre-sanitization bytes: {:?}",
                all.stdout_capture
            ));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

pub(super) async fn exec_stdin_round_trips(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().exec.stdin {
        return Ok(Some("capability exec.stdin not declared".to_owned()));
    }
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let spec = ExecSpec::new("cat")
            .stdin(b"stdin-payload".to_vec())
            .timeout(Duration::from_secs(30));
        let result = sandbox
            .exec()
            .run(&spec)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if result.stdout != b"stdin-payload" {
            return fail(format!("stdin not delivered: {:?}", result.stdout_lossy()));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

pub(super) async fn exec_reports_a_foreign_signal(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        // The command signals its own process; the provider reports the
        // signal number even though the shell only sees `128 + N`.
        let spec = ExecSpec::bash("kill -TERM $$; sleep 5").timeout(Duration::from_secs(30));
        let result = sandbox
            .exec()
            .run(&spec)
            .await
            .map_err(|error| format!("exec failed: {error}"))?;
        if result.signal != Some(15) {
            return fail(format!(
                "expected signal 15, got signal {:?} (code {:?}, {:?})",
                result.signal, result.exit_code, result.termination
            ));
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

pub(super) async fn exec_reports_environment(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().exec.environment {
        return Ok(Some("capability exec.environment not declared".to_owned()));
    }
    let mut spec = ctx.specs.spec();
    spec.env
        .insert("CONFORMANCE_ENV".to_owned(), "present".to_owned());
    let sandbox = ctx
        .provider
        .create(&spec, None)
        .await
        .map_err(|error| format!("create failed: {error}"))?;
    let outcome = async {
        let env = sandbox
            .environment()
            .await
            .map_err(|error| format!("environment failed: {error}"))?;
        if env.get("CONFORMANCE_ENV").map(String::as_str) != Some("present") {
            return fail("spec env not reflected in the effective environment");
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}
