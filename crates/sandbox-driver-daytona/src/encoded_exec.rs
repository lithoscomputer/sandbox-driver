//! Preserve exact exec bytes through Daytona's text-only command output.
//! Bash emits bounded, ASCII-only records before bytes reach the toolbox.
//! Decoding happens before sanitization, delivery, and retention accounting.

use std::io;
use std::sync::Arc;

use sandbox_driver::{
    Capability, Error, Exec, ExecControls, ExecSpec, ExecStreamingResult, OutputCaptureBuffer,
    OutputSanitization, OutputSanitizer, OutputSink, OutputStream, Result,
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

fn invalid_frame(message: &'static str) -> Error {
    Error::io(
        "decoding Daytona output",
        io::Error::new(io::ErrorKind::InvalidData, message),
    )
}

/// Decode the ASCII subset emitted by Bash printf %q with LC_ALL=C.
/// This is data decoding; no shell evaluates returned command output.
fn decode_quoted(mut input: &[u8]) -> Result<Vec<u8>> {
    if input == b"''" {
        return Ok(Vec::new());
    }
    let ansi = input.starts_with(b"$'");
    if ansi {
        input = input
            .strip_prefix(b"$'")
            .and_then(|value| value.strip_suffix(b"'"))
            .ok_or_else(|| invalid_frame("unterminated quoted output"))?;
    }
    let mut decoded = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let byte = input[i];
        i += 1;
        if byte != b'\\' {
            if !(0x20..=0x7e).contains(&byte) {
                return Err(invalid_frame("non-ASCII output frame"));
            }
            decoded.push(byte);
            continue;
        }
        let escaped = *input
            .get(i)
            .ok_or_else(|| invalid_frame("incomplete output escape"))?;
        i += 1;
        if !ansi {
            decoded.push(escaped);
            continue;
        }
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
                u8::try_from(value).map_err(|_| invalid_frame("output escape exceeds a byte"))?
            }
            _ => return Err(invalid_frame("unknown output escape")),
        };
        decoded.push(value);
    }
    Ok(decoded)
}

struct FramedOutput {
    pending: Vec<u8>,
    streams: [(OutputSanitizer, OutputCaptureBuffer); 2],
    sink:    Option<OutputSink>,
}

impl FramedOutput {
    fn new(policy: OutputSanitization, controls: &ExecControls) -> Self {
        Self {
            pending: Vec::new(),
            streams: [0, 1].map(|_| {
                (
                    OutputSanitizer::new(policy),
                    OutputCaptureBuffer::new(controls.retained_output_limit),
                )
            }),
            sink:    controls.sink.clone(),
        }
    }

    async fn emit(&mut self, index: usize, raw: &[u8]) -> Result<()> {
        let (sanitizer, capture) = &mut self.streams[index];
        let bytes = sanitizer.push(raw);
        capture.push(&bytes);
        if !bytes.is_empty() {
            if let Some(sink) = &self.sink {
                let stream = [OutputStream::Stdout, OutputStream::Stderr][index];
                sink(stream, bytes).await?;
            }
        }
        Ok(())
    }

    async fn push(&mut self, stream: OutputStream, mut bytes: &[u8]) -> Result<()> {
        if stream == OutputStream::Stderr {
            // Wrapper startup failures remain ordinary stderr diagnostics.
            return self.emit(1, bytes).await;
        }
        while !bytes.is_empty() {
            let end = bytes.iter().position(|byte| *byte == b'\n');
            let take = end.map_or(bytes.len(), |end| end + 1);
            if self.pending.len() + take > MAX_FRAME_BYTES {
                return Err(Error::io(
                    "decoding Daytona output",
                    io::Error::new(io::ErrorKind::InvalidData, "output frame is too large"),
                ));
            }
            self.pending.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if end.is_some() {
                if self.pending == b"\n" {
                    self.pending.clear();
                    continue;
                }
                let index = match self.pending.first() {
                    Some(b'O') => 0,
                    Some(b'E') => 1,
                    _ => {
                        return Err(Error::io(
                            "decoding Daytona output",
                            io::Error::new(io::ErrorKind::InvalidData, "invalid output frame"),
                        ));
                    }
                };
                let raw = decode_quoted(&self.pending[1..self.pending.len() - 1])?;
                self.pending.clear();
                self.emit(index, &raw).await?;
            }
        }
        Ok(())
    }

    async fn finish(&mut self, mut result: ExecStreamingResult) -> Result<ExecStreamingResult> {
        for (index, (sanitizer, capture)) in self.streams.iter_mut().enumerate() {
            let final_bytes = sanitizer.finish();
            capture.push(&final_bytes);
            if !final_bytes.is_empty() {
                if let Some(sink) = &self.sink {
                    sink(
                        [OutputStream::Stdout, OutputStream::Stderr][index],
                        final_bytes,
                    )
                    .await?;
                }
            }
        }
        result.result.stdout = self.streams[0].1.to_bytes();
        result.result.stderr = self.streams[1].1.to_bytes();
        let truncated = result.stdout_capture.truncated
            || result.stderr_capture.truncated
            || !self.pending.is_empty();
        result.stdout_capture = self.streams[0].1.stats();
        result.stderr_capture = self.streams[1].1.stats();
        result.stdout_capture.truncated |= truncated;
        result.stderr_capture.truncated |= truncated;
        result.streams_separated = true;
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

    #[tokio::test]
    async fn incomplete_frames_report_loss_and_oversized_frames_are_bounded() {
        let mut framed = FramedOutput::new(OutputSanitization::Raw, &ExecControls::buffered());
        framed
            .push(OutputStream::Stdout, b"Ow")
            .await
            .expect("partial frame");
        let result = framed
            .finish(ExecStreamingResult::new(ExecResult::new(
                Termination::Exited,
                Some(0),
                Duration::ZERO,
            )))
            .await
            .expect("partial capture reports loss");
        assert!(result.stdout_capture.truncated);
        assert!(
            framed
                .push(OutputStream::Stdout, &vec![b'A'; MAX_FRAME_BYTES])
                .await
                .is_err()
        );
    }
}
