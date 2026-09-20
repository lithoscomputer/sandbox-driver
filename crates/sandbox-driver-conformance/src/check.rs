//! Shared check plumbing: the outcome type, the pass and fail helpers,
//! sandbox cleanup, and the small fixtures several check modules use.

use std::future::Future;
use std::pin::Pin;
use std::process;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sandbox_driver::{
    Capabilities, Capability, ExecResult, ExecSpec, OutputSink, OutputStream, Sandbox,
};
use tokio::time;

use crate::Conformance;

/// The budget every short command in the suite runs under.
pub(crate) const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) type CheckFn =
    fn(&Conformance) -> Pin<Box<dyn Future<Output = CheckOutcome> + Send + '_>>;

/// Why a check did not pass. A `String` converts into `Failed`, so the
/// `map_err(|error| format!(..))?` lines in the checks keep working, and
/// a skip is an error too, so it can be raised with `?` from any depth.
#[derive(Debug)]
pub(crate) enum Verdict {
    Skipped(String),
    Failed(String),
}

impl From<String> for Verdict {
    fn from(reason: String) -> Self {
        Self::Failed(reason)
    }
}

impl Verdict {
    /// Names the phase of a check a failure came from; a skip is left
    /// alone, since it already says why.
    pub(crate) fn in_phase(self, phase: &str) -> Self {
        match self {
            Self::Failed(reason) => Self::Failed(format!("{phase}: {reason}")),
            skipped @ Self::Skipped(_) => skipped,
        }
    }
}

/// Runs one named phase of a check, so a failure in a long check says
/// where it happened.
pub(crate) async fn phase<T>(
    name: &str,
    step: impl Future<Output = Result<T, Verdict>>,
) -> Result<T, Verdict> {
    step.await.map_err(|verdict| verdict.in_phase(name))
}

/// `Ok(())` = passed; the error says whether the check skipped or failed.
pub(crate) type CheckOutcome = Result<(), Verdict>;

pub(crate) fn fail<T>(message: impl Into<String>) -> Result<T, Verdict> {
    Err(Verdict::Failed(message.into()))
}

pub(crate) fn skip<T>(reason: impl Into<String>) -> Result<T, Verdict> {
    Err(Verdict::Skipped(reason.into()))
}

pub(crate) const PASS: CheckOutcome = Ok(());

/// Skips unless `caps` declares `capability`. The provider-level form is
/// [`Conformance::require`]; this one judges a sandbox's own set, which
/// a provider may narrow by sandbox class.
pub(crate) fn require_on(caps: &Capabilities, capability: Capability) -> Result<(), Verdict> {
    if caps.supports(capability) {
        Ok(())
    } else {
        skip(format!("capability {capability} not declared"))
    }
}

pub(crate) const SIGKILL: i32 = 9;
pub(crate) const SIGTERM: i32 = 15;

/// `1\n2\n…count\n`, what `seq 1 count` prints.
pub(crate) fn numbered_lines(count: usize) -> Vec<u8> {
    let mut lines = String::new();
    for n in 1..=count {
        lines.push_str(&n.to_string());
        lines.push('\n');
    }
    lines.into_bytes()
}

/// Runs `spec` buffered and demands success. A transport failure or a
/// non-zero exit fails the check, naming `label` and the command's
/// stderr.
pub(crate) async fn run_ok(
    sandbox: &dyn Sandbox,
    label: &str,
    spec: &ExecSpec,
) -> Result<ExecResult, Verdict> {
    let result = sandbox
        .exec()
        .run(spec)
        .await
        .map_err(|error| format!("{label} failed: {error}"))?;
    if !result.success() {
        return fail(format!(
            "{label} exited {:?}: {}",
            result.exit_code,
            result.stderr_lossy()
        ));
    }
    Ok(result)
}

/// The sub-second part of the clock, for names and ports that must not
/// collide with another conformance run on this machine.
pub(crate) fn nonce() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos())
}

/// A port unlikely to collide with another sandbox on a shared machine
/// (the Host provider's sandboxes share this machine's ports).
pub(crate) fn scratch_port() -> u16 {
    20_000 + u16::try_from((nonce() ^ process::id()) % 40_000).unwrap_or(0)
}

/// Chunks a sink saw, each tagged with its stream, in arrival order.
type Chunks = Arc<Mutex<Vec<(OutputStream, Vec<u8>)>>>;

/// Records what an exec sink sees, for checks that judge the streamed
/// bytes as well as the buffered result.
#[derive(Clone, Default)]
pub(crate) struct RecordedOutput {
    chunks: Chunks,
}

impl RecordedOutput {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// A sink that records every chunk. `delay` is how long the sink is
    /// busy before it accepts a chunk, to model a consumer under load;
    /// zero accepts at once.
    pub(crate) fn sink(&self, delay: Duration) -> OutputSink {
        let chunks = Arc::clone(&self.chunks);
        Arc::new(move |stream, chunk| {
            let chunks = Arc::clone(&chunks);
            Box::pin(async move {
                if !delay.is_zero() {
                    time::sleep(delay).await;
                }
                chunks.lock().expect("chunks lock").push((stream, chunk));
                Ok(())
            })
        })
    }

    /// Every byte the sink saw, both streams in arrival order.
    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.chunks
            .lock()
            .expect("chunks lock")
            .iter()
            .flat_map(|(_, chunk)| chunk.clone())
            .collect()
    }

    /// The bytes the sink saw on `stream`, in arrival order.
    pub(crate) fn stream(&self, stream: OutputStream) -> Vec<u8> {
        self.chunks
            .lock()
            .expect("chunks lock")
            .iter()
            .filter(|(seen, _)| *seen == stream)
            .flat_map(|(_, chunk)| chunk.clone())
            .collect()
    }

    /// The stdout bytes the sink saw, in arrival order.
    pub(crate) fn stdout(&self) -> Vec<u8> {
        self.stream(OutputStream::Stdout)
    }

    /// Every byte the sink saw, as text.
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes()).into_owned()
    }
}
