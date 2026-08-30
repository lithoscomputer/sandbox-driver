use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{mem, process};

use async_trait::async_trait;
use daytona_sdk::{ExecuteCommandOptions, FileSystemService, ProcessService};
use sandbox_driver::{
    Capability, Error, Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult,
    OutputCaptureBuffer, OutputStream, Result, Termination,
};
use tokio::runtime::Handle;
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

/// Bound on deleting a stdin temp file, so cleanup can never stall a
/// command that already completed.
const STDIN_CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);

/// A temporary sandbox file carrying exact stdin bytes.
///
/// The toolbox execute API has no stdin channel, so write-then-EOF is
/// delivered as a file redirection: arbitrary bytes survive verbatim
/// and the command sees EOF, without embedding the data in shell
/// source. fabro's `DaytonaStdinFile`, ported.
struct StdinFile {
    fs:   Option<FileSystemService>,
    path: String,
}

impl StdinFile {
    async fn create(client: &DaytonaClient, sandbox_id: &str, bytes: &[u8]) -> Result<Self> {
        let sandbox = client
            .get(sandbox_id)
            .await
            .map_err(|error| daytona_error("fetching sandbox", &error))?;
        let fs = sandbox
            .fs()
            .await
            .map_err(|error| daytona_error("connecting to the toolbox", &error))?;
        // Nanosecond nonce plus host pid: unique enough that a stale
        // file from a crashed driver can never feed a later command.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let path = format!("/tmp/.sandbox-driver-stdin-{}-{nonce}", process::id());
        fs.upload_file_bytes(&path, bytes)
            .await
            .map_err(|error| daytona_error("uploading exec stdin", &error))?;
        Ok(Self { fs: Some(fs), path })
    }

    /// Bounded, best-effort deletion. Failures are swallowed: cleanup
    /// must never fail a command that already ran.
    async fn close(&mut self) {
        let Some(fs) = self.fs.as_ref() else {
            return;
        };
        let _ = time::timeout(STDIN_CLEANUP_TIMEOUT, fs.delete_file(&self.path, false)).await;
        self.fs.take();
    }
}

impl Drop for StdinFile {
    /// Safety net for a caller that drops the exec future mid-await:
    /// spawn the deletion when a runtime is available.
    fn drop(&mut self) {
        let Some(fs) = self.fs.take() else {
            return;
        };
        let path = mem::take(&mut self.path);
        if let Ok(handle) = Handle::try_current() {
            handle.spawn(async move {
                let _ = time::timeout(STDIN_CLEANUP_TIMEOUT, fs.delete_file(&path, false)).await;
            });
        }
    }
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

    fn compose(spec: &ExecSpec, stdin_path: Option<&str>) -> String {
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
        // Write-then-EOF as a file redirection on the inner bash.
        if let Some(path) = stdin_path {
            program.push_str(" < ");
            program.push_str(&shell_quote(path));
        }
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
        // Unsupported controls must fail fast, never run the command
        // with a cancel token silently ignored.
        if controls.cancel.is_some() {
            return Err(Error::unsupported(Capability::ExecCancel));
        }
        let started = Instant::now();
        let process = self.process().await?;
        let mut stdin_file = match &spec.stdin {
            Some(bytes) => Some(StdinFile::create(&self.client, &self.sandbox_id, bytes).await?),
            None => None,
        };
        let options = ExecuteCommandOptions {
            cwd:     Some(self.resolve_dir(spec.working_dir.as_deref())),
            env:     None,
            timeout: Some(wire_timeout(spec.timeout)),
        };
        let program = Self::compose(spec, stdin_file.as_ref().map(|file| file.path.as_str()));
        let call = process.execute_command(&program, options);

        // A server-side timeout comes back as a 408 error rather than a
        // response, and a client-side deadline elapses as None; both mean
        // the command was killed for exceeding its timeout.
        let response = match spec.timeout {
            Some(timeout) => match time::timeout(timeout + TIMEOUT_GRACE, call).await {
                Ok(Ok(response)) => Ok(Some(response)),
                Ok(Err(error)) if is_server_timeout(&error) => Ok(None),
                Ok(Err(error)) => Err(daytona_error("executing command", &error)),
                Err(_) => Ok(None),
            },
            None => match call.await {
                Ok(response) => Ok(Some(response)),
                // The unbounded stand-in is still finite server-side, so
                // its expiry is a timeout kill, not a provider failure.
                Err(error) if is_server_timeout(&error) => Ok(None),
                Err(error) => Err(daytona_error("executing command", &error)),
            },
        };
        // Clean up before propagating any failure, so an errored command
        // does not strand its stdin file.
        if let Some(file) = stdin_file.as_mut() {
            file.close().await;
        }
        let response = response?;

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
        let program = DaytonaExec::compose(&spec, None);
        assert!(program.starts_with("unset BASH_ENV\n"));
        assert!(!program.contains("export BASH_ENV"));
    }

    #[test]
    fn compose_quotes_env_keys_and_values() {
        let spec = ExecSpec::new("true").env_var("X;injected", "a b");
        let program = DaytonaExec::compose(&spec, None);
        // A metacharacter in a key corrupts only its own export instead
        // of splicing extra shell before the command.
        assert!(program.contains("export 'X;injected'='a b'\n"), "{program}");
    }

    #[test]
    fn compose_redirects_stdin_from_the_temp_file() {
        let spec = ExecSpec::new("wc -c");
        let program = DaytonaExec::compose(&spec, Some("/tmp/.sandbox-driver-stdin-1-2"));
        assert!(
            program.ends_with("exec /bin/bash -c 'wc -c' < '/tmp/.sandbox-driver-stdin-1-2'"),
            "{program}"
        );
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
