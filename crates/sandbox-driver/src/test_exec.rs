//! Scripted [`Exec`] for unit-testing exec-derived implementations.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;

use crate::error::{Error, Result};
use crate::exec::{Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult, Termination};

/// Replays a queue of canned results while recording every command.
pub(crate) struct ScriptedExec {
    responses: Mutex<VecDeque<ExecResult>>,
    commands:  Mutex<Vec<String>>,
}

impl ScriptedExec {
    pub(crate) fn new(responses: Vec<ExecResult>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            commands:  Mutex::new(Vec::new()),
        }
    }

    /// A success result with the given stdout text.
    pub(crate) fn ok(stdout: &str) -> ExecResult {
        Self::ok_bytes(stdout.as_bytes().to_vec())
    }

    /// A success result with raw stdout bytes.
    pub(crate) fn ok_bytes(stdout: Vec<u8>) -> ExecResult {
        let mut result = ExecResult::new(Termination::Exited, Some(0), Duration::from_millis(1));
        result.stdout = stdout;
        result
    }

    /// A clean exit with a non-zero code.
    pub(crate) fn failed(code: i32) -> ExecResult {
        ExecResult::new(Termination::Exited, Some(code), Duration::from_millis(1))
    }

    /// Every command run so far, in order.
    pub(crate) fn commands(&self) -> Vec<String> {
        self.commands.lock().expect("commands lock").clone()
    }
}

#[async_trait]
impl Exec for ScriptedExec {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
        self.commands
            .lock()
            .expect("commands lock")
            .push(spec.command.clone());
        self.responses
            .lock()
            .expect("responses lock")
            .pop_front()
            .ok_or_else(|| Error::invalid_spec("test", "no scripted response left"))
    }

    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        _controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        Ok(ExecStreamingResult::new(self.run(spec).await?))
    }
}
