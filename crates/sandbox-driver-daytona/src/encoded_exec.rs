//! Preserve exact exec bytes through Daytona's text-only command output.
//! Bash emits bounded, ASCII-only records before bytes reach the toolbox.
//! Decoding happens before sanitization, delivery, and retention accounting.
//!
//! The toolbox is lossy under a fast run of small writes: a record arrives
//! without its leading tag, two records arrive glued together, or the
//! output ends inside one. The decoder never fails the exec for that. It
//! discards the unreadable record through its newline, resyncs on the next
//! record, and counts every discarded record and byte into
//! [`ExecStreamingResult::output_loss`]; a loss also marks both captures
//! truncated, because the torn record's stream is unknown. The loss is
//! reported, never hidden. A tear that happens to leave a well-formed
//! record is not detectable and decodes to wrong bytes.

use std::result::Result as StdResult;
use std::sync::Arc;

use sandbox_driver::{
    Capability, Error, Exec, ExecControls, ExecSpec, ExecStreamingResult, OutputCaptureBuffer,
    OutputLoss, OutputSanitization, OutputSanitizer, OutputSink, OutputStream, Result,
};
use tokio::sync::Mutex;

// Each encoder writes one record smaller than POSIX PIPE_BUF (512 bytes).
// Neither concurrent output stream can split the other's record.
const MAX_FRAME_BYTES: usize = 512;

const ENCODE_OUTPUT: &str = r#"
encode() {
    local LC_ALL=C chunk= byte status count=96
    # Timed reads can consume a NUL just as the timeout fires, then report
    # a timeout instead of the delimiter. Read bytes without a timer and
    # use a non-consuming readiness check to flush short, live output.
    # Bash 3 does not support that readiness check.
    if (( BASH_VERSINFO[0] < 4 )); then count=1; fi
    while :; do
        byte=
        IFS= read -r -d '' -n 1 byte
        status=$?
        if (( status != 0 )); then
            if [[ -n $chunk ]]; then printf '%s%q\n' "$1" "$chunk"; fi
            if (( status == 1 )); then return 0; fi
            return "$status"
        fi
        if [[ -z $byte ]]; then
            if [[ -n $chunk ]]; then printf '%s%q\n' "$1" "$chunk"; fi
            chunk=
            printf '%s%s\n' "$1" "$'\0'"
        else
            chunk+=$byte
            if (( ${#chunk} >= count )) || ! read -t 0; then
                printf '%s%q\n' "$1" "$chunk"
                chunk=
            fi
        fi
    done
}
exec 3> >(encode O)
stdout_encoder=$!
exec 4> >(encode E 3>&-)
stderr_encoder=$!
{ command "$@" >&3 2>&4 3>&- 4>&-; status=$?; } 2>&4
exec 3>&- 4>&-
# Older Bash can forget already-finished process substitution children.
# Wait for any still running without leaking its bookkeeping diagnostics.
wait "$stdout_encoder" 2>/dev/null
wait "$stderr_encoder" 2>/dev/null
exit "$status"
"#;

fn encoded_spec(spec: &ExecSpec) -> ExecSpec {
    let mut encoded =
        ExecSpec::new("/bin/bash").args(["-c", ENCODE_OUTPUT, "sandbox-driver-output", "env"]);
    // Apply caller variables to its program, after the encoder's Bash.
    // Bash itself drops environment names that are not shell identifiers.
    encoded.args.extend(
        spec.launch_env()
            .iter()
            .map(|(key, value)| format!("{key}={value}")),
    );
    encoded.args.push(spec.program.clone());
    encoded.args.extend(spec.args.iter().cloned());
    encoded.timeout = spec.timeout;
    encoded.stop_grace = spec.stop_grace;
    encoded.working_dir.clone_from(&spec.working_dir);
    encoded.stdin.clone_from(&spec.stdin);
    encoded
}

/// The stream a record's leading tag names: `O` for stdout, `E` for
/// stderr. The encoder writes exactly these two tags.
fn stream_tag(tag: u8) -> Option<OutputStream> {
    match tag {
        b'O' => Some(OutputStream::Stdout),
        b'E' => Some(OutputStream::Stderr),
        _ => None,
    }
}

/// Decode the ASCII subset emitted by Bash printf %q with LC_ALL=C.
/// This is data decoding; no shell evaluates returned command output.
/// The error names what made the body unreadable; the caller counts it.
/// printf %q writes one of two forms: a plain word with each special
/// character backslash-escaped, or an ANSI-C `$'…'` string when the
/// bytes include anything unprintable.
fn decode_quoted(input: &[u8]) -> StdResult<Vec<u8>, &'static str> {
    if input == b"''" {
        return Ok(Vec::new());
    }
    match input.strip_prefix(b"$'") {
        Some(body) => decode_ansi_c(
            body.strip_suffix(b"'")
                .ok_or("unterminated quoted output")?,
        ),
        None => decode_plain(input),
    }
}

/// A byte of a quoted body outside an escape: printable ASCII only.
fn printable(byte: u8) -> StdResult<u8, &'static str> {
    if (0x20..=0x7e).contains(&byte) {
        Ok(byte)
    } else {
        Err("non-ASCII output frame")
    }
}

/// The plain form: a backslash escapes the next byte literally.
fn decode_plain(input: &[u8]) -> StdResult<Vec<u8>, &'static str> {
    let mut decoded = Vec::with_capacity(input.len());
    let mut bytes = input.iter().copied();
    while let Some(byte) = bytes.next() {
        if byte == b'\\' {
            decoded.push(bytes.next().ok_or("incomplete output escape")?);
        } else {
            decoded.push(printable(byte)?);
        }
    }
    Ok(decoded)
}

/// The ANSI-C form: the body of a `$'…'` string, with Bash's named
/// escapes and up to three octal digits per byte.
fn decode_ansi_c(input: &[u8]) -> StdResult<Vec<u8>, &'static str> {
    let mut decoded = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let byte = input[i];
        i += 1;
        if byte != b'\\' {
            decoded.push(printable(byte)?);
            continue;
        }
        let escaped = *input.get(i).ok_or("incomplete output escape")?;
        i += 1;
        let value = match escaped {
            b'a' => 7,
            b'b' => 8,
            b't' => 9,
            b'n' => 10,
            b'v' => 11,
            b'f' => 12,
            b'r' => 13,
            b'e' | b'E' => 27,
            b'\\' | b'\'' | b'"' => escaped,
            b'0'..=b'7' => {
                let mut value = u16::from(escaped - b'0');
                for _ in 0..2 {
                    match input.get(i) {
                        Some(next @ b'0'..=b'7') => {
                            value = value * 8 + u16::from(next - b'0');
                            i += 1;
                        }
                        _ => break,
                    }
                }
                u8::try_from(value).map_err(|_| "output escape exceeds a byte")?
            }
            _ => return Err("unknown output escape"),
        };
        decoded.push(value);
    }
    Ok(decoded)
}

// Why the decoder discarded a record. The first fault of an exec is
// logged with its reason; the totals are logged when the exec finishes.
/// Longer than any record the encoder writes: records glued together.
const OVERSIZED_FRAME: &str = "output frame is too large";
/// The leading stream tag is missing: the record's head was lost.
const MISSING_TAG: &str = "output frame has no stream tag";
/// The output ended inside a record.
const UNTERMINATED_FRAME: &str = "output ended inside a frame";

struct FramedOutput {
    pending:    Vec<u8>,
    /// A discarded record has not reached its newline yet; the bytes up
    /// to and including it belong to the same loss.
    discarding: bool,
    loss:       OutputLoss,
    streams:    [(OutputSanitizer, OutputCaptureBuffer); 2],
    sink:       Option<OutputSink>,
}

impl FramedOutput {
    fn new(policy: OutputSanitization, controls: &ExecControls) -> Self {
        Self {
            pending:    Vec::new(),
            discarding: false,
            loss:       OutputLoss::default(),
            streams:    [0, 1].map(|_| {
                (
                    OutputSanitizer::new(policy),
                    OutputCaptureBuffer::new(controls.retained_output_limit),
                )
            }),
            sink:       controls.sink.clone(),
        }
    }

    /// Counts one discarded record of `bytes` encoded bytes. The exec
    /// goes on; the loss reaches the result and the log.
    fn discard(&mut self, reason: &'static str, bytes: usize) {
        if !self.loss.is_lossy() {
            tracing::warn!(
                reason,
                frame_bytes = bytes,
                "output frame discarded; decoding resynced at the next newline"
            );
        }
        self.loss.dropped_frames += 1;
        self.loss.dropped_bytes += u64::try_from(bytes).unwrap_or(u64::MAX);
    }

    async fn emit(&mut self, stream: OutputStream, raw: &[u8]) -> Result<()> {
        let (sanitizer, capture) = &mut self.streams[stream as usize];
        let bytes = sanitizer.push(raw);
        capture.push(&bytes);
        if !bytes.is_empty() {
            if let Some(sink) = &self.sink {
                sink(stream, bytes).await?;
            }
        }
        Ok(())
    }

    /// Decodes encoded stdout. A record the decoder cannot read is
    /// discarded through its newline and counted; decoding resumes at
    /// the next record, so the exec never fails for a torn transport.
    async fn push(&mut self, stream: OutputStream, mut bytes: &[u8]) -> Result<()> {
        if stream == OutputStream::Stderr {
            // Wrapper startup failures remain ordinary stderr diagnostics.
            return self.emit(OutputStream::Stderr, bytes).await;
        }
        while !bytes.is_empty() {
            let end = bytes.iter().position(|byte| *byte == b'\n');
            let take = end.map_or(bytes.len(), |end| end + 1);
            let segment = &bytes[..take];
            bytes = &bytes[take..];
            if self.discarding {
                self.loss.dropped_bytes += u64::try_from(take).unwrap_or(u64::MAX);
                self.discarding = end.is_none();
                continue;
            }
            if self.pending.len() + take > MAX_FRAME_BYTES {
                self.discard(OVERSIZED_FRAME, self.pending.len() + take);
                self.pending.clear();
                self.discarding = end.is_none();
                continue;
            }
            self.pending.extend_from_slice(segment);
            if end.is_none() {
                continue;
            }
            if self.pending == b"\n" {
                self.pending.clear();
                continue;
            }
            let decoded = self
                .pending
                .first()
                .copied()
                .and_then(stream_tag)
                .map(|stream| {
                    (
                        stream,
                        decode_quoted(&self.pending[1..self.pending.len() - 1]),
                    )
                });
            let record_bytes = self.pending.len();
            self.pending.clear();
            match decoded {
                Some((stream, Ok(raw))) => self.emit(stream, &raw).await?,
                Some((_, Err(reason))) => self.discard(reason, record_bytes),
                None => self.discard(MISSING_TAG, record_bytes),
            }
        }
        Ok(())
    }

    async fn finish(&mut self, mut result: ExecStreamingResult) -> Result<ExecStreamingResult> {
        if !self.pending.is_empty() {
            let bytes = self.pending.len();
            self.pending.clear();
            self.discard(UNTERMINATED_FRAME, bytes);
        }
        for stream in [OutputStream::Stdout, OutputStream::Stderr] {
            let (sanitizer, capture) = &mut self.streams[stream as usize];
            let final_bytes = sanitizer.finish();
            capture.push(&final_bytes);
            if !final_bytes.is_empty() {
                if let Some(sink) = &self.sink {
                    sink(stream, final_bytes).await?;
                }
            }
        }
        result.result.stdout = self.streams[OutputStream::Stdout as usize].1.to_bytes();
        result.result.stderr = self.streams[OutputStream::Stderr as usize].1.to_bytes();
        // A discarded record's stream is unknown, so a loss truncates both.
        let truncated = result.stdout_capture.truncated
            || result.stderr_capture.truncated
            || self.loss.is_lossy();
        result.stdout_capture = self.streams[OutputStream::Stdout as usize].1.stats();
        result.stderr_capture = self.streams[OutputStream::Stderr as usize].1.stats();
        result.stdout_capture.truncated |= truncated;
        result.stderr_capture.truncated |= truncated;
        result.output_loss = self.loss;
        result.streams_separated = true;
        if self.loss.is_lossy() {
            tracing::warn!(
                dropped_frames = self.loss.dropped_frames,
                dropped_bytes = self.loss.dropped_bytes,
                "output decoding lost frames; the captures are marked truncated"
            );
        }
        Ok(result)
    }
}

/// Wrap one transport operation without replaying the caller's command.
pub(super) async fn run(
    transport: &dyn Exec,
    spec: &ExecSpec,
    controls: ExecControls,
) -> Result<ExecStreamingResult> {
    if controls.stdin.is_some() {
        return Err(Error::unsupported(Capability::ExecStdinStream));
    }
    let output = Arc::new(Mutex::new(FramedOutput::new(
        spec.output_sanitization,
        &controls,
    )));
    let encoded = encoded_spec(spec);
    let streaming = controls.sink.is_some() || controls.term.is_some() || controls.kill.is_some();
    let result = if streaming {
        let sink: OutputSink = Arc::new({
            let output = Arc::clone(&output);
            move |stream, bytes| {
                let output = Arc::clone(&output);
                Box::pin(async move { output.lock().await.push(stream, &bytes).await })
            }
        });
        transport
            .run_streaming(&encoded, ExecControls {
                term: controls.term,
                kill: controls.kill,
                sink: Some(sink),
                retained_output_limit: Some(0),
                ..ExecControls::default()
            })
            .await?
    } else {
        let result = transport
            .run_streaming(&encoded, ExecControls::buffered())
            .await?;
        let mut output = output.lock().await;
        output
            .push(OutputStream::Stdout, &result.result.stdout)
            .await?;
        output
            .push(OutputStream::Stderr, &result.result.stderr)
            .await?;
        result
    };
    output.lock().await.finish(result).await
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use sandbox_driver::{ExecResult, Termination};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::process::Command as TokioCommand;
    use tokio::task::spawn_blocking;
    use tokio::time::timeout;

    use super::*;

    #[tokio::test]
    async fn short_binary_output_arrives_before_the_command_needs_input() {
        let spec = ExecSpec::new("python3").args([
            "-c",
            r"import os; os.write(1, b'\0\xff'); assert os.read(0, 1) == b'x'",
        ]);
        let encoded = encoded_spec(&spec);
        let mut child = TokioCommand::new(encoded.program)
            .args(encoded.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("command wrapper");
        timeout(Duration::from_secs(5), async {
            let mut output = BufReader::new(child.stdout.take().expect("output pipe"));
            let mut decoded = Vec::new();
            while decoded.len() < 2 {
                let mut line = Vec::new();
                assert_ne!(output.read_until(b'\n', &mut line).await.expect("frame"), 0);
                assert_eq!(line.first(), Some(&b'O'));
                decoded.extend(decode_quoted(&line[1..line.len() - 1]).expect("quoted bytes"));
            }
            assert_eq!(decoded, [0, 255]);
            child
                .stdin
                .take()
                .expect("input pipe")
                .write_all(b"x")
                .await
                .expect("acknowledge output");
            assert!(child.wait().await.expect("command completed").success());
        })
        .await
        .expect("short output must arrive while the command is still running");
    }

    #[tokio::test]
    async fn all_bytes_and_literal_arguments_survive_concurrent_streams() {
        let literal = "$VALUE `id` $(id) * ; it's \"quoted\"\n";
        let spec = ExecSpec::new("python3")
            .args([
                "-c",
                r"
import os, sys, threading, time
assert os.environ['dash-key'] == sys.argv[1]
assert os.environ['LC_ALL'] == 'C'
out = bytes(range(256)) * 8 + b'\0\0x'
err = bytes(reversed(range(256))) * 8 + b'\n\n'
def write(fd, data):
    for offset in range(0, len(data), 256):
        # Exercise idle reads followed by NULs at the old timeout boundary.
        time.sleep(0.05)
        os.write(fd, data[offset:offset + 256])
threads = [threading.Thread(target=write, args=pair) for pair in [(1, out), (2, err)]]
for thread in threads: thread.start()
for thread in threads: thread.join()
sys.exit(7)
",
                literal,
            ])
            .env_var("dash-key", literal)
            .env_var("LC_ALL", "C");
        let encoded = encoded_spec(&spec);
        let output = spawn_blocking(move || {
            Command::new(encoded.program)
                .args(encoded.args)
                .output()
                .expect("Bash command wrapper")
        })
        .await
        .expect("command joined");
        assert_eq!(output.status.code(), Some(7), "{:?}", output.stderr);
        assert!(output.stderr.is_empty(), "stderr must also be encoded");
        let mut framed = FramedOutput::new(OutputSanitization::Raw, &ExecControls::buffered());
        for fragment in output.stdout.chunks(79) {
            framed
                .push(OutputStream::Stdout, fragment)
                .await
                .expect("fragment decoded");
        }
        let result = framed
            .finish(ExecStreamingResult::new(ExecResult::new(
                Termination::Exited,
                output.status.code(),
                Duration::ZERO,
            )))
            .await
            .expect("capture completed");
        let stdout: Vec<u8> = (0..=255).cycle().take(2048).chain([0, 0, b'x']).collect();
        let stderr: Vec<u8> = (0..=255)
            .rev()
            .cycle()
            .take(2048)
            .chain([b'\n'; 2])
            .collect();
        assert_eq!(result.result.stdout, stdout);
        assert_eq!(result.result.stderr, stderr);
        assert_eq!(result.stdout_capture.observed_bytes, stdout.len());
        assert_eq!(result.stderr_capture.observed_bytes, stderr.len());
        assert!(!result.stdout_capture.truncated);
        assert!(!result.stderr_capture.truncated);
    }

    #[tokio::test]
    async fn fragmented_native_frames_preserve_binary_streams_and_retention() {
        let spec = ExecSpec::new("python3").args([
            "-c",
            "import os; os.write(1, bytes([0,255,128,10,65])); os.write(2, bytes([254,0,66]))",
        ]);
        let encoded = encoded_spec(&spec);
        let output = spawn_blocking(move || {
            Command::new(encoded.program)
                .args(encoded.args)
                .output()
                .expect("Bash command wrapper")
        })
        .await
        .expect("command joined");
        assert!(output.status.success(), "{:?}", output.stderr);
        let observed = Arc::new(Mutex::new([Vec::new(), Vec::new()]));
        let sink: OutputSink = Arc::new({
            let observed = Arc::clone(&observed);
            move |stream, bytes| {
                let observed = Arc::clone(&observed);
                Box::pin(async move {
                    let index = usize::from(stream == OutputStream::Stderr);
                    observed.lock().await[index].extend(bytes);
                    Ok(())
                })
            }
        });
        let mut framed = FramedOutput::new(OutputSanitization::Raw, &ExecControls {
            sink: Some(sink),
            retained_output_limit: Some(2),
            ..ExecControls::buffered()
        });
        for fragment in output.stdout.chunks(3) {
            framed
                .push(OutputStream::Stdout, fragment)
                .await
                .expect("fragment decoded");
        }
        let mut native = ExecStreamingResult::new(ExecResult::new(
            Termination::Exited,
            Some(0),
            Duration::ZERO,
        ));
        // The transport retained no encoded bytes; all were delivered to the
        // decoder. Deliberate transport omission is not decoded truncation.
        native.stdout_capture.observed_bytes = output.stdout.len();
        native.stdout_capture.omitted_bytes = output.stdout.len();
        let result = framed.finish(native).await.expect("capture completed");
        assert_eq!(*observed.lock().await, [vec![0, 255, 128, 10, 65], vec![
            254, 0, 66
        ]]);
        assert_eq!(result.result.stdout, [0, 65]);
        assert_eq!(result.result.stderr, [254, 66]);
        assert_eq!(result.stdout_capture.observed_bytes, 5);
        assert_eq!(result.stdout_capture.retained_bytes, 2);
        assert_eq!(result.stdout_capture.omitted_bytes, 3);
        assert!(!result.stdout_capture.truncated);
        assert!(!result.stderr_capture.truncated);
        assert!(result.streams_separated);
    }

    #[tokio::test]
    async fn fixed_binary_stdin_reaches_the_command_and_closes_for_eof() {
        let spec = ExecSpec::new("cat").stdin(vec![0, 255, 128, 10]);
        let encoded = encoded_spec(&spec);
        let output = spawn_blocking(move || {
            let mut child = Command::new(encoded.program)
                .args(encoded.args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("command wrapper");
            child
                .stdin
                .take()
                .expect("stdin pipe")
                .write_all(encoded.stdin.as_deref().expect("fixed input"))
                .expect("stdin delivered");
            child.wait_with_output().expect("command observed EOF")
        })
        .await
        .expect("command joined");
        assert!(output.status.success());
        let mut framed = FramedOutput::new(OutputSanitization::Raw, &ExecControls::buffered());
        framed
            .push(OutputStream::Stdout, &output.stdout)
            .await
            .expect("output decoded");
        let result = framed
            .finish(ExecStreamingResult::new(ExecResult::new(
                Termination::Exited,
                output.status.code(),
                Duration::ZERO,
            )))
            .await
            .expect("capture completed");
        assert_eq!(result.result.stdout, spec.stdin.expect("fixed input"));
    }

    /// Feeds a scripted encoded stream to a fresh decoder, `chunk` bytes
    /// per push, and finishes it as a clean exit.
    async fn decode(stream: &[u8], chunk: usize) -> ExecStreamingResult {
        let mut framed = FramedOutput::new(OutputSanitization::Raw, &ExecControls::buffered());
        for fragment in stream.chunks(chunk) {
            framed
                .push(OutputStream::Stdout, fragment)
                .await
                .expect("a torn stream never fails the exec");
        }
        framed
            .finish(ExecStreamingResult::new(ExecResult::new(
                Termination::Exited,
                Some(0),
                Duration::ZERO,
            )))
            .await
            .expect("capture completed")
    }

    fn assert_loss(result: &ExecStreamingResult, frames: u64, bytes: u64) {
        assert_eq!(result.output_loss.dropped_frames, frames, "{result:?}");
        assert_eq!(result.output_loss.dropped_bytes, bytes, "{result:?}");
        assert!(result.stdout_capture.truncated);
        assert!(result.stderr_capture.truncated);
        assert!(result.result.success(), "the exec still completes");
        assert!(
            result.clone().into_complete().is_err(),
            "a lossy result is not a complete value"
        );
    }

    #[tokio::test]
    async fn a_clean_stream_reports_zero_loss() {
        for chunk in [1, 2, 7, 64] {
            let result = decode(b"Oabc\nE$'x\\n'\nOdef\n", chunk).await;
            assert_eq!(result.result.stdout, b"abcdef", "chunk {chunk}");
            assert_eq!(result.result.stderr, b"x\n", "chunk {chunk}");
            assert_eq!(result.output_loss, OutputLoss::default());
            assert!(!result.output_loss.is_lossy());
            assert!(!result.stdout_capture.truncated);
            assert!(!result.stderr_capture.truncated);
            assert_eq!(result.stdout_capture.observed_bytes, 6);
            assert_eq!(result.stderr_capture.observed_bytes, 2);
            result.into_complete().expect("a clean stream is complete");
        }
    }

    #[tokio::test]
    async fn a_record_missing_its_tag_is_dropped_and_decoding_resyncs() {
        // The toolbox dropped the head of the second record.
        for chunk in [1, 3, 64] {
            let result = decode(b"Oabc\nbc'\nOdef\nEerr\n", chunk).await;
            assert_eq!(result.result.stdout, b"abcdef", "chunk {chunk}");
            assert_eq!(result.result.stderr, b"err", "chunk {chunk}");
            assert_loss(&result, 1, 4);
            assert_eq!(result.stdout_capture.observed_bytes, 6);
        }
    }

    #[tokio::test]
    async fn a_torn_record_glued_to_the_next_is_dropped_once() {
        // The tail of one record was lost, so the next record's bytes
        // land inside its quoted body; both are one unreadable line.
        for chunk in [1, 5, 64] {
            let result = decode(b"Oabc\nO$'a\\nbOdef\nOghi\n", chunk).await;
            assert_eq!(result.result.stdout, b"abcghi", "chunk {chunk}");
            assert_loss(&result, 1, 12);
        }
    }

    #[tokio::test]
    async fn an_oversized_line_is_dropped_through_its_newline() {
        let mut stream = vec![b'A'; MAX_FRAME_BYTES + 88];
        stream.extend_from_slice(b"\nOend\n");
        // Fed piecemeal, the line is given up on before its newline
        // arrives; the rest of it is still counted, never decoded.
        for chunk in [1, 100, stream.len()] {
            let result = decode(&stream, chunk).await;
            assert_eq!(result.result.stdout, b"end", "chunk {chunk}");
            assert_loss(&result, 1, MAX_FRAME_BYTES as u64 + 89);
        }
    }

    #[tokio::test]
    async fn a_garbled_quoted_body_is_dropped() {
        // An escape printf %q never writes, then a byte outside ASCII.
        for chunk in [1, 4, 64] {
            let result = decode(b"O$'ab\\q'\nO\xff\nOok\n", chunk).await;
            assert_eq!(result.result.stdout, b"ok", "chunk {chunk}");
            assert_loss(&result, 2, 12);
        }
    }

    #[tokio::test]
    async fn output_ending_inside_a_record_counts_as_loss() {
        let result = decode(b"Oabc\nOw", 64).await;
        assert_eq!(result.result.stdout, b"abc");
        assert_loss(&result, 1, 2);
    }
}
