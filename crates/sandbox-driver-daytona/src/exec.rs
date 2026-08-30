use std::time::{Duration, Instant};

use async_trait::async_trait;
use daytona_sdk::{ExecuteCommandOptions, ProcessService};
use sandbox_driver::{
    Capability, Error, Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult,
    OutputCaptureBuffer, OutputStream, Result, Termination,
};
use tokio::sync::OnceCell;
use tokio::time;

use crate::{DaytonaClient, daytona_error, is_server_timeout, shell_quote};

/// Extra client-side wait beyond the server-side command timeout.
const TIMEOUT_GRACE: Duration = Duration::from_secs(10);

/// The server-side timeout sent when the spec has none. Omitting the
/// field does not mean "no deadline" — the toolbox applies its own
/// 10-second default and kills the command — so an untimed spec must
/// cross the wire as an explicit, effectively unbounded timeout. One
/// year fits comfortably in the API's `i32` seconds.
const UNBOUNDED_TIMEOUT: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// The server-side timeout for a spec: its own, or the unbounded
/// stand-in — never an omitted field.
fn wire_timeout(spec_timeout: Option<Duration>) -> Duration {
    spec_timeout.unwrap_or(UNBOUNDED_TIMEOUT)
}

/// Buffered command execution through the Daytona toolbox.
///
/// Honesty flags are load-bearing here: the toolbox `execute` API returns
/// combined output after completion, so results report
/// `streams_separated: false` and `live_streaming: false`, and stderr is
/// always empty. The Bash contract is enforced by wrapping every command
/// in `exec /bin/bash -c …` with `BASH_ENV` unset; environment variables
/// cross as `export` statements because the API's `envs` field is not
/// reliably applied.
pub struct DaytonaExec {
    client:      DaytonaClient,
    sandbox_id:  String,
    working_dir: String,
    process:     OnceCell<ProcessService>,
}

impl DaytonaExec {
    pub(crate) fn new(client: DaytonaClient, sandbox_id: String, working_dir: String) -> Self {
        Self {
            client,
            sandbox_id,
            working_dir,
            process: OnceCell::new(),
        }
    }

    async fn process(&self) -> Result<&ProcessService> {
        self.process
            .get_or_try_init(|| async {
                let sandbox = self
                    .client
                    .get(&self.sandbox_id)
                    .await
                    .map_err(|error| daytona_error("fetching sandbox", &error))?;
                sandbox
                    .process()
                    .await
                    .map_err(|error| daytona_error("connecting to the toolbox", &error))
            })
            .await
    }

    /// Resolves a relative working directory against the sandbox
    /// working directory, matching the fs facet — the toolbox daemon
    /// would otherwise resolve it against its own cwd.
    fn resolve_dir(&self, dir: Option<&str>) -> String {
        match dir {
            None => self.working_dir.clone(),
            Some(dir) if dir.starts_with('/') => dir.to_owned(),
            Some(dir) => format!("{}/{}", self.working_dir.trim_end_matches('/'), dir),
        }
    }

    fn compose(spec: &ExecSpec) -> String {
        let mut program = String::from("unset BASH_ENV\n");
        for (key, value) in &spec.env {
            // The unset above runs first, so a spec-provided BASH_ENV
            // would re-arm startup-file injection into the inner bash;
            // the exec contract strips it on every transport.
            if key == "BASH_ENV" {
                continue;
            }
            // Quote the key as well as the value: a malformed key must
            // corrupt nothing but its own export.
            program.push_str("export ");
            program.push_str(&shell_quote(key));
            program.push('=');
            program.push_str(&shell_quote(value));
            program.push('\n');
        }
        program.push_str("exec /bin/bash -c ");
        program.push_str(&shell_quote(&spec.command));
        program
    }
}

#[async_trait]
impl Exec for DaytonaExec {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
        let streaming = self.run_streaming(spec, ExecControls::default()).await?;
        Ok(streaming.result)
    }

    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        // Unsupported inputs must fail fast, never run the command with
        // stdin dropped or a cancel token silently ignored.
        if spec.stdin.is_some() {
            return Err(Error::unsupported(Capability::ExecStdin));
        }
        if controls.cancel.is_some() {
            return Err(Error::unsupported(Capability::ExecCancel));
        }
        let started = Instant::now();
        let process = self.process().await?;
        let options = ExecuteCommandOptions {
            cwd:     Some(self.resolve_dir(spec.working_dir.as_deref())),
            env:     None,
            timeout: Some(wire_timeout(spec.timeout)),
        };
        let program = Self::compose(spec);
        let call = process.execute_command(&program, options);

        // A server-side timeout comes back as a 408 error rather than a
        // response, and a client-side deadline elapses as None; both mean
        // the command was killed for exceeding its timeout.
        let response = match spec.timeout {
            Some(timeout) => match time::timeout(timeout + TIMEOUT_GRACE, call).await {
                Ok(Ok(response)) => Some(response),
                Ok(Err(error)) if is_server_timeout(&error) => None,
                Ok(Err(error)) => return Err(daytona_error("executing command", &error)),
                Err(_) => None,
            },
            None => match call.await {
                Ok(response) => Some(response),
                // The unbounded stand-in is still finite server-side, so
                // its expiry is a timeout kill, not a provider failure.
                Err(error) if is_server_timeout(&error) => None,
                Err(error) => return Err(daytona_error("executing command", &error)),
            },
        };

        // A response is a completed command, whatever its exit code and
        // however close to the deadline it arrived — classifying a
        // genuine failure as TimedOut would trip retry-on-timeout logic
        // on non-idempotent commands. Timeouts are only ever the 408 or
        // client-deadline paths above.
        let (termination, exit_code, stdout) = match response {
            None => (Termination::TimedOut, None, Vec::new()),
            Some(response) => (
                Termination::Exited,
                Some(response.exit_code),
                response.result.into_bytes(),
            ),
        };

        if let Some(sink) = &controls.sink {
            if !stdout.is_empty() {
                // The buffered transport delivers after completion, so
                // there is nothing left to cancel — but a failed sink
                // must surface: the caller would otherwise believe the
                // output was delivered.
                sink(OutputStream::Stdout, stdout.clone()).await?;
            }
        }
        let mut capture = OutputCaptureBuffer::new(controls.retained_output_limit);
        capture.push(&stdout);
        let (retained, stats) = capture.into_parts();

        let mut result = ExecResult::new(termination, exit_code, started.elapsed());
        result.stdout = retained;
        let mut streaming = ExecStreamingResult::new(result);
        streaming.streams_separated = false;
        streaming.live_streaming = false;
        streaming.stdout_capture = stats;
        Ok(streaming)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_strips_a_spec_provided_bash_env() {
        let spec = ExecSpec::new("true").env_var("BASH_ENV", "/tmp/startup");
        let program = DaytonaExec::compose(&spec);
        assert!(program.starts_with("unset BASH_ENV\n"));
        assert!(!program.contains("export BASH_ENV"));
    }

    #[test]
    fn compose_quotes_env_keys_and_values() {
        let spec = ExecSpec::new("true").env_var("X;injected", "a b");
        let program = DaytonaExec::compose(&spec);
        // A metacharacter in a key corrupts only its own export instead
        // of splicing extra shell before the command.
        assert!(program.contains("export 'X;injected'='a b'\n"), "{program}");
    }

    #[test]
    fn untimed_specs_send_the_unbounded_timeout_explicitly() {
        // An omitted field would let the toolbox kill the command at its
        // 10-second default.
        assert_eq!(wire_timeout(None), UNBOUNDED_TIMEOUT);
        assert_eq!(
            wire_timeout(Some(Duration::from_secs(30))),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn unbounded_timeout_survives_the_wire_conversion() {
        // The SDK converts with `as_secs() as i32`; a value past i32::MAX
        // would truncate into garbage.
        assert!(i32::try_from(UNBOUNDED_TIMEOUT.as_secs()).is_ok());
    }
}
