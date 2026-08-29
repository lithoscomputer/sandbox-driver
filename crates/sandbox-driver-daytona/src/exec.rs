use std::time::{Duration, Instant};

use async_trait::async_trait;
use daytona_sdk::{ExecuteCommandOptions, ProcessService};
use sandbox_driver::{
    Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult, OutputCaptureBuffer,
    OutputStream, Result, Termination,
};
use tokio::sync::OnceCell;
use tokio::time;

use crate::{DaytonaClient, daytona_error, is_server_timeout, shell_quote};

/// Extra client-side wait beyond the server-side command timeout.
const TIMEOUT_GRACE: Duration = Duration::from_secs(10);

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

    fn compose(spec: &ExecSpec) -> String {
        let mut program = String::from("unset BASH_ENV\n");
        for (key, value) in &spec.env {
            program.push_str("export ");
            program.push_str(key);
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
        let started = Instant::now();
        let process = self.process().await?;
        let options = ExecuteCommandOptions {
            cwd:     Some(
                spec.working_dir
                    .clone()
                    .unwrap_or_else(|| self.working_dir.clone()),
            ),
            env:     None,
            timeout: spec.timeout,
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
            None => Some(
                call.await
                    .map_err(|error| daytona_error("executing command", &error))?,
            ),
        };

        let (termination, exit_code, stdout) = match response {
            None => (Termination::TimedOut, None, Vec::new()),
            Some(response) => {
                let elapsed = started.elapsed();
                // The server kills timed-out commands but reports only an
                // exit code; classify by elapsed time and failure.
                let timed_out = spec
                    .timeout
                    .is_some_and(|timeout| elapsed >= timeout && response.exit_code != 0);
                let termination = if timed_out {
                    Termination::TimedOut
                } else {
                    Termination::Exited
                };
                (
                    termination,
                    Some(response.exit_code),
                    response.result.into_bytes(),
                )
            }
        };

        if let Some(sink) = &controls.sink {
            if !stdout.is_empty() {
                let _ = sink(OutputStream::Stdout, stdout.clone()).await;
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
