//! Whole-command helpers over [`Sandbox::exec`]: run a command to completion
//! and keep what it wrote. They are library code, not a provider capability,
//! so they work unchanged on every provider and plugin.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use std::{error, fmt, future, mem};

use tokio::time::Instant;

use super::{
    Error, ExecControls, ExecOutcome, ExecSpec, OutputSink, OutputStream, Sandbox, Termination,
};

/// How much of each stream [`run_captured`] and [`run_bash`] keep.
pub const DEFAULT_CAPTURE_BYTES: usize = 16 * 1024 * 1024;

/// One stream of a captured command.
#[derive(Clone, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct CapturedOutput {
    /// The stream's first bytes followed by its newest ones. It is the whole
    /// stream when `omitted_bytes` is zero.
    pub bytes:         Vec<u8>,
    /// Bytes dropped between the first and the newest to stay within the
    /// limit.
    pub omitted_bytes: u64,
    /// How many of `bytes` are the stream's first ones. The omitted bytes
    /// fall after them, and the stream's newest bytes are the rest.
    pub head_bytes:    usize,
}

impl CapturedOutput {
    /// Bytes the command wrote to this stream, kept or not.
    pub fn observed_bytes(&self) -> u64 {
        (self.bytes.len() as u64).saturating_add(self.omitted_bytes)
    }

    /// The last `max_bytes` the command wrote to this stream, or fewer when
    /// fewer were kept, and how many bytes it wrote before them.
    pub(crate) fn newest(&self, max_bytes: usize) -> (&[u8], u64) {
        // With a gap, the first bytes are not contiguous with the newest.
        let newest = if self.omitted_bytes == 0 {
            &self.bytes[..]
        } else {
            &self.bytes[self.head_bytes.min(self.bytes.len())..]
        };
        let newest = &newest[newest.len().saturating_sub(max_bytes)..];
        (
            newest,
            self.observed_bytes().saturating_sub(newest.len() as u64),
        )
    }
}

// Command output can carry credentials, as `ExecSpec::argv` can.
impl fmt::Debug for CapturedOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedOutput")
            .field("retained_bytes", &self.bytes.len())
            .field("omitted_bytes", &self.omitted_bytes)
            .field("head_bytes", &self.head_bytes)
            .finish()
    }
}

/// A finished command and the output it wrote.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Captured {
    pub outcome:  ExecOutcome,
    /// Also holds the single terminal stream of a command run with
    /// [`ExecSpec::tty`].
    pub stdout:   CapturedOutput,
    pub stderr:   CapturedOutput,
    /// How long the caller waited for the command: from the request to the
    /// provider until its outcome came back, measured here and not by the
    /// provider. It includes the provider's own setup and the time the
    /// caller's sink took.
    pub duration: Duration,
}

#[cfg(test)]
impl Captured {
    /// The one fixture for this crate's tests: a command that ended as
    /// `termination` after 1500 ms and wrote `stdout` and `stderr`, all of
    /// it kept.
    pub(crate) fn ended(
        termination: Termination,
        exit_code: Option<i32>,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Self {
        let whole = |bytes: &[u8]| CapturedOutput {
            bytes:         bytes.to_vec(),
            omitted_bytes: 0,
            head_bytes:    bytes.len(),
        };
        Self {
            outcome:  ExecOutcome {
                termination,
                exit_code,
                signal: None,
                output_loss: super::OutputLoss::default(),
            },
            stdout:   whole(stdout),
            stderr:   whole(stderr),
            duration: Duration::from_millis(1500),
        }
    }
}

impl Captured {
    /// Whether the command exited on its own with code zero. A command that
    /// was stopped or timed out is not a success, whatever code it reports.
    pub fn success(&self) -> bool {
        self.outcome.termination == Termination::Exited && self.outcome.exit_code == Some(0)
    }

    /// Whether `stdout` and `stderr` hold every byte the command wrote, as
    /// far as the provider can tell: the command exited on its own, nothing
    /// was omitted to stay within the limit, and the provider reported no
    /// output loss. A command that was stopped, timed out, or lost is never
    /// complete, because nothing reads the rest of its output.
    pub fn is_complete(&self) -> bool {
        self.outcome.termination == Termination::Exited
            && self.stdout.omitted_bytes == 0
            && self.stderr.omitted_bytes == 0
            && !self.outcome.output_loss.is_lossy()
    }

    /// Returns the capture only when it [is complete](Self::is_complete).
    /// Call this before parsing the output, so a short read is an error
    /// and not a wrong answer.
    ///
    /// # Errors
    ///
    /// [`IncompleteOutput`], which still holds the capture.
    pub fn into_complete(self) -> Result<Self, IncompleteOutput> {
        if self.is_complete() {
            Ok(self)
        } else {
            Err(IncompleteOutput {
                captured: Box::new(self),
            })
        }
    }
}

/// A command that finished without its output being captured whole. The
/// message gives sizes only; `captured` holds what was kept.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct IncompleteOutput {
    pub captured: Box<Captured>,
}

impl fmt::Display for IncompleteOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Captured {
            stdout,
            stderr,
            outcome,
            ..
        } = &*self.captured;
        let mut separator = "command output is incomplete: ";
        if outcome.termination != Termination::Exited {
            write!(f, "{separator}the command did not exit on its own")?;
            separator = "; ";
        }
        if stdout.omitted_bytes != 0 || stderr.omitted_bytes != 0 {
            write!(
                f,
                "{separator}{} bytes of stdout and {} of stderr were omitted",
                stdout.omitted_bytes, stderr.omitted_bytes
            )?;
            separator = "; ";
        }
        if outcome.output_loss.is_lossy() {
            write!(f, "{separator}the provider lost output")?;
        }
        Ok(())
    }
}

impl error::Error for IncompleteOutput {}

/// Runs `spec` to completion and keeps up to [`DEFAULT_CAPTURE_BYTES`] of
/// each stream.
///
/// A command that fails is not an error: the result carries its exit code
/// and output, and [`Captured::success`] says whether it exited with zero.
///
/// # Errors
///
/// Whatever [`Sandbox::exec`] returns. The command may have had effects.
pub async fn run_captured(sandbox: &dyn Sandbox, spec: ExecSpec) -> Result<Captured, Error> {
    run_captured_with(
        sandbox,
        spec,
        ExecControls::default(),
        DEFAULT_CAPTURE_BYTES,
    )
    .await
}

/// [`run_captured`] with the caller's controls and its own limit.
///
/// `limit` is the bytes kept per stream: the first half of it from the start
/// of the stream, the rest from its end. Output beyond it is still read, so
/// the command never blocks on a full buffer, and is counted in
/// [`CapturedOutput::omitted_bytes`]. A limit of zero keeps nothing and
/// counts everything.
///
/// `controls.sink`, when set, also receives every chunk as it arrives, after
/// the chunk is captured. An error from it ends the command as it does for
/// [`Sandbox::exec`].
///
/// # Errors
///
/// Whatever [`Sandbox::exec`] returns. The command may have had effects, and
/// the output captured before the failure is not returned.
pub async fn run_captured_with(
    sandbox: &dyn Sandbox,
    spec: ExecSpec,
    mut controls: ExecControls,
    limit: usize,
) -> Result<Captured, Error> {
    let streams = Arc::new(Mutex::new(Streams::new(limit)));
    let forward = controls.sink.take();
    let sink: OutputSink = {
        let streams = Arc::clone(&streams);
        Arc::new(move |stream, bytes| {
            lock(&streams).push(stream, &bytes);
            match &forward {
                Some(forward) => forward(stream, bytes),
                None => Box::pin(future::ready(Ok(()))),
            }
        })
    };
    controls.sink = Some(sink);
    let started = Instant::now();
    let outcome = sandbox.exec(spec, controls).await?;
    let duration = started.elapsed();
    // A provider may still hold the sink, so the buffers are taken, not
    // unwrapped.
    let mut streams = lock(&streams);
    Ok(Captured {
        outcome,
        stdout: streams.stdout.take(),
        stderr: streams.stderr.take(),
        duration,
    })
}

/// Runs `script` through [`ExecSpec::bash`] and captures it as
/// [`run_captured`] does.
///
/// # Errors
///
/// Whatever [`Sandbox::exec`] returns. The script may have had effects.
pub async fn run_bash(sandbox: &dyn Sandbox, script: &str) -> Result<Captured, Error> {
    run_captured(sandbox, ExecSpec::bash(script)).await
}

/// The buffers hold plain bytes and counts, so a panic elsewhere while the
/// lock was held leaves nothing to repair.
fn lock(streams: &Mutex<Streams>) -> MutexGuard<'_, Streams> {
    streams.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Streams {
    stdout: Retained,
    stderr: Retained,
}

impl Streams {
    fn new(limit: usize) -> Self {
        Self {
            stdout: Retained::new(limit),
            stderr: Retained::new(limit),
        }
    }

    fn push(&mut self, stream: OutputStream, chunk: &[u8]) {
        match stream {
            OutputStream::Stdout | OutputStream::Terminal => self.stdout.push(chunk),
            OutputStream::Stderr => self.stderr.push(chunk),
        }
    }
}

/// A stable head plus a rolling tail. The gap, when there is one, sits
/// between them.
struct Retained {
    head_limit: usize,
    tail_limit: usize,
    head:       Vec<u8>,
    tail:       VecDeque<u8>,
    omitted:    u64,
}

impl Retained {
    fn new(limit: usize) -> Self {
        let head_limit = limit / 2;
        Self {
            head_limit,
            tail_limit: limit - head_limit,
            head: Vec::new(),
            tail: VecDeque::new(),
            omitted: 0,
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        let (head, rest) = chunk.split_at(chunk.len().min(self.head_limit - self.head.len()));
        self.head.extend_from_slice(head);
        // Whatever the tail cannot hold once `rest` is appended falls out of
        // its front, or never enters it when `rest` alone overflows it.
        let overflow = (self.tail.len() + rest.len()).saturating_sub(self.tail_limit);
        let evicted = overflow.min(self.tail.len());
        self.tail.drain(..evicted);
        self.tail.extend(&rest[overflow - evicted..]);
        self.omitted = self.omitted.saturating_add(overflow as u64);
    }

    fn take(&mut self) -> CapturedOutput {
        let mut bytes = mem::take(&mut self.head);
        let head_bytes = bytes.len();
        // Taking the tail frees its buffer even while a provider keeps the
        // sink alive.
        let tail = mem::take(&mut self.tail);
        let (front, back) = tail.as_slices();
        bytes.reserve_exact(tail.len());
        bytes.extend_from_slice(front);
        bytes.extend_from_slice(back);
        CapturedOutput {
            bytes,
            omitted_bytes: mem::take(&mut self.omitted),
            head_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OutputLoss;

    fn retain(limit: usize, chunks: &[&[u8]]) -> CapturedOutput {
        let mut retained = Retained::new(limit);
        for chunk in chunks {
            retained.push(chunk);
        }
        retained.take()
    }

    #[test]
    fn output_within_the_limit_is_kept_whole() {
        let output = retain(5, &[b"01", b"234"]);
        assert_eq!(output.bytes, b"01234");
        assert_eq!(output.omitted_bytes, 0);
        assert_eq!(output.head_bytes, 2);
    }

    #[test]
    fn the_gap_falls_between_the_head_and_the_newest_bytes() {
        // An odd limit gives the tail the extra byte: head 2, tail 3.
        for chunks in [
            &[b"0123456789".as_slice()][..],
            &[b"0", b"1234", b"5", b"6789"],
            &[b"012345", b"67", b"8", b"9"],
        ] {
            let output = retain(5, chunks);
            assert_eq!(output.bytes, b"01789", "{chunks:?}");
            assert_eq!(output.omitted_bytes, 5, "{chunks:?}");
            assert_eq!(output.head_bytes, 2, "{chunks:?}");
            assert_eq!(output.observed_bytes(), 10, "{chunks:?}");
        }
    }

    #[test]
    fn the_newest_bytes_never_reach_back_across_the_gap() {
        // Whole stream: the newest bytes are a plain suffix.
        let whole = retain(10, &[b"0123456789"]);
        assert_eq!(whole.newest(3), (b"789".as_slice(), 7));
        assert_eq!(whole.newest(99), (b"0123456789".as_slice(), 0));
        // Limit 5 keeps "01" and "789" around a gap of five bytes. Asking for
        // more than the three after the gap must not return "1789".
        let gapped = retain(5, &[b"0123456789"]);
        assert_eq!(gapped.newest(4), (b"789".as_slice(), 7));
        assert_eq!(gapped.newest(2), (b"89".as_slice(), 8));
        assert_eq!(gapped.newest(0), (b"".as_slice(), 10));
    }

    #[test]
    fn a_zero_limit_counts_output_without_keeping_it() {
        let output = retain(0, &[b"hello ", b"world"]);
        assert!(output.bytes.is_empty());
        assert_eq!(output.omitted_bytes, 11);
    }

    fn captured(stdout: CapturedOutput, output_loss: OutputLoss) -> Captured {
        let mut captured = Captured::ended(Termination::Exited, Some(0), b"", b"");
        captured.stdout = stdout;
        captured.outcome.output_loss = output_loss;
        captured
    }

    #[test]
    fn a_whole_capture_converts_and_a_short_one_is_an_error_that_keeps_it() {
        let whole = captured(retain(5, &[b"01234"]), OutputLoss::default());
        assert_eq!(whole.clone().into_complete(), Ok(whole));

        let over_limit = captured(retain(4, &[b"0123456789"]), OutputLoss::default());
        let error = over_limit
            .clone()
            .into_complete()
            .expect_err("omitted bytes");
        assert_eq!(*error.captured, over_limit);
        assert_eq!(
            error.to_string(),
            "command output is incomplete: 6 bytes of stdout and 0 of stderr were omitted"
        );
    }

    #[test]
    fn output_the_provider_stopped_reading_is_incomplete_though_nothing_was_omitted() {
        let truncated = captured(retain(5, &[b"01"]), OutputLoss {
            truncated: true,
            ..OutputLoss::default()
        });
        assert!(truncated.success());
        assert!(!truncated.is_complete());
        let error = truncated.into_complete().expect_err("provider loss");
        assert_eq!(
            error.to_string(),
            "command output is incomplete: the provider lost output"
        );
    }

    #[test]
    fn a_command_that_did_not_exit_on_its_own_is_incomplete() {
        for termination in [
            Termination::TimedOut,
            Termination::Terminated,
            Termination::Killed,
            Termination::Lost,
        ] {
            let mut stopped = captured(retain(5, &[b"01"]), OutputLoss::default());
            stopped.outcome.termination = termination;
            stopped.outcome.exit_code = None;
            let error = stopped.into_complete().expect_err("stopped command");
            assert_eq!(
                error.to_string(),
                "command output is incomplete: the command did not exit on its own",
                "{termination:?}"
            );
        }
    }

    #[test]
    fn a_limit_of_one_keeps_the_newest_byte() {
        let output = retain(1, &[b"ab", b"c"]);
        assert_eq!(output.bytes, b"c");
        assert_eq!(output.omitted_bytes, 2);
    }
}
