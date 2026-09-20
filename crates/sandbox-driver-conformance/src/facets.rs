//! Optional facets: preview URLs, stdio processes, PTYs, logs,
//! services, and one-shot containers.

use std::process;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sandbox_driver::{
    Capability, Error, ExecControls, ExecSpec, LogSink, LogSource, OneShotSpec, PtyOptions,
    PtySize, ServiceSpec, Services, SpawnSpec, Termination,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::check::{CheckOutcome, PASS, SeenChunks, fail, require_on, skip};
use crate::{Conformance, Provision};

/// A Bash script that answers one HTTP request on `port` with `body` and
/// exits: Perl where the image has it (Debian, Ubuntu, macOS), else
/// BusyBox or OpenBSD `nc`.
fn one_request_server(port: u16, body: &str) -> String {
    format!(
        r#"if command -v perl >/dev/null 2>&1; then
  exec perl -e 'use IO::Socket::INET; my $s = IO::Socket::INET->new(LocalAddr => "127.0.0.1", LocalPort => $ARGV[0], Listen => 5, ReuseAddr => 1) or exit 3; my $c = $s->accept or exit 4; my $b = $ARGV[1]; print $c "HTTP/1.0 200 OK
Content-Length: " . length($b) . "
Connection: close

$b"; close $c;' {port} {body}
fi
resp="$(printf 'HTTP/1.0 200 OK
Content-Length: {len}
Connection: close

{body}')"
if nc --help 2>&1 | grep -qi busybox; then printf '%s' "$resp" | nc -l -p {port}
else printf '%s' "$resp" | nc -l 127.0.0.1 {port}; fi"#,
        len = body.len(),
    )
}

/// A port a process inside the sandbox listens on is reachable through the
/// sandbox's preview URL when that URL points at this machine; releasing
/// the URL succeeds. Remote (HTTPS) preview URLs are the provider's live
/// tests' business and are skipped here.
pub(super) async fn preview_url_reaches_a_listening_port(ctx: &Conformance) -> CheckOutcome {
    ctx.require(Capability::PreviewUrls)?;
    ctx.with_ready(|sandbox| async move {
        let Some(preview) = sandbox.preview_urls() else {
            return fail("access.preview_urls is declared but the facet is absent");
        };
        let can_listen = sandbox
            .exec()
            .run(
                &ExecSpec::bash("command -v perl || command -v nc")
                    .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("probe failed: {error}"))?;
        if !can_listen.success() {
            return skip("the sandbox has neither perl nor nc to listen with");
        }
        // A port unlikely to collide with another sandbox on a shared
        // machine (the Host provider's sandboxes share this machine's ports).
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let port = 20_000 + u16::try_from((nanos ^ process::id()) % 40_000).unwrap_or(0);
        let body = "preview-ok";
        let script = one_request_server(port, body);
        let server_sandbox = Arc::clone(&sandbox);
        let kill = CancellationToken::new();
        let server_kill = kill.clone();
        let server = tokio::spawn(async move {
            server_sandbox
                .exec()
                .run_streaming(
                    &ExecSpec::bash(script).timeout(Duration::from_secs(120)),
                    ExecControls {
                        kill: Some(server_kill),
                        ..ExecControls::buffered()
                    },
                )
                .await
        });
        let url = preview
            .preview_url(port)
            .await
            .map_err(|error| format!("preview_url failed: {error}"))?;
        let Some(address) = url
            .url
            .strip_prefix("http://")
            .filter(|rest| rest.starts_with("127.0.0.1:") || rest.starts_with("localhost:"))
            .map(|rest| rest.trim_end_matches('/').to_owned())
        else {
            kill.cancel();
            let _ = server.await;
            let _ = preview.release_preview_url(port).await;
            return skip(format!(
                "preview URL {} is not on this machine; reachability is the provider's live test",
                url.url
            ));
        };
        // The server takes a moment to listen; a forward accepts before the
        // container port does and then closes, so retry until the body arrives.
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut response = String::new();
        loop {
            if let Ok(Ok(mut stream)) =
                time::timeout(Duration::from_secs(5), TcpStream::connect(&address)).await
            {
                let _ = stream
                    .write_all(b"GET / HTTP/1.0\r\nHost: sandbox\r\n\r\n")
                    .await;
                let mut bytes = Vec::new();
                let _ = time::timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes)).await;
                response = String::from_utf8_lossy(&bytes).into_owned();
                if response.contains(body) {
                    break;
                }
            }
            if Instant::now() >= deadline {
                break;
            }
            time::sleep(Duration::from_millis(200)).await;
        }
        kill.cancel();
        let _ = server.await;
        preview
            .release_preview_url(port)
            .await
            .map_err(|error| format!("release_preview_url failed: {error}"))?;
        if !response.contains(body) {
            return fail(format!(
                "no response through {address}; last response: {response:?}"
            ));
        }
        PASS
    })
    .await
}

pub(super) async fn stdio_process_round_trips(ctx: &Conformance) -> CheckOutcome {
    if !ctx.caps().exec.stdio_process {
        // The default must be a clean Unsupported.
        return ctx
            .with_sandbox(Provision::Created, |sandbox| async move {
                match sandbox.exec().spawn_stdio(&SpawnSpec::new("cat")).await {
                    Err(Error::Unsupported { .. }) => {
                        skip("capability exec.stdio_process not declared")
                    }
                    Err(other) => fail(format!("expected Unsupported, got {other}")),
                    Ok(_) => fail("stdio_process undeclared but spawn succeeded"),
                }
            })
            .await;
    }
    ctx.with_ready(|sandbox| async move {
        if !sandbox.capabilities().exec.stdio_process {
            return skip("exec.stdio_process masked for this sandbox");
        }
        let mut process = sandbox
            .exec()
            .spawn_stdio(&SpawnSpec::new("cat"))
            .await
            .map_err(|error| format!("spawn failed: {error}"))?;
        process
            .stdin
            .write_all(b"ping\n")
            .await
            .map_err(|error| format!("write failed: {error}"))?;
        process
            .stdin
            .flush()
            .await
            .map_err(|error| format!("flush failed: {error}"))?;
        let mut buffer = [0u8; 5];
        process
            .stdout
            .read_exact(&mut buffer)
            .await
            .map_err(|error| format!("read failed: {error}"))?;
        if &buffer != b"ping\n" {
            return fail(format!("round trip mismatch: {buffer:?}"));
        }
        process.handle.terminate().await;
        let _ = process.handle.wait().await;
        PASS
    })
    .await
}

pub(super) async fn pty_is_bidirectional(ctx: &Conformance) -> CheckOutcome {
    if ctx.caps().pty.is_none() {
        return skip("pty not declared");
    }
    ctx.with_ready(|sandbox| async move {
        let Some(pty) = sandbox.pty() else {
            return fail("pty declared but facet is absent");
        };
        let session = pty
            .open(&PtyOptions::default())
            .await
            .map_err(|error| format!("open failed: {error}"))?;
        let marker = format!("pty-conformance-{}", process::id());
        let exchange = async {
            let input = async {
                if sandbox
                    .capabilities()
                    .pty
                    .as_ref()
                    .is_some_and(|caps| caps.resize)
                {
                    session
                        .resize(PtySize {
                            rows: 40,
                            cols: 100,
                        })
                        .await
                        .map_err(|error| format!("resize failed: {error}"))?;
                }
                session
                    .write_input(format!("printf '{marker}\\n'; exit\n").as_bytes())
                    .await
                    .map_err(|error| format!("input failed: {error}"))
            };
            let output = async {
                let mut output = Vec::new();
                while let Some(chunk) = session
                    .read_output()
                    .await
                    .map_err(|error| format!("output failed: {error}"))?
                {
                    output.extend(chunk);
                    if String::from_utf8_lossy(&output).contains(&marker) {
                        return Ok::<_, String>(());
                    }
                }
                Err("PTY ended before the marker appeared".to_owned())
            };
            let (input, output) = tokio::join!(input, output);
            input?;
            output
        };
        time::timeout(Duration::from_secs(30), exchange)
            .await
            .map_err(|_| "PTY exchange timed out".to_owned())??;
        session
            .close()
            .await
            .map_err(|error| format!("close failed: {error}"))?;
        PASS
    })
    .await
}

pub(super) async fn logs_follow_streams_and_cancels(ctx: &Conformance) -> CheckOutcome {
    if ctx.caps().logs.is_none() {
        return skip("logs not declared");
    }
    let Some(spec) = ctx.specs.entrypoint_logs_spec() else {
        return fail("logs declared but no entrypoint-log spec was configured");
    };
    ctx.with_sandbox(Provision::CreatedFrom(&spec), |sandbox| async move {
        if sandbox.capabilities().logs.is_none() {
            return skip("logs not declared for this sandbox");
        }
        let Some(logs) = sandbox.logs() else {
            return fail("logs declared but facet is absent");
        };

        // A follow stream is long-lived. Timing it out drops the future,
        // which must cancel the provider-side stream without wedging the
        // sandbox or a plugin connection.
        let discard: LogSink = Arc::new(|_| Box::pin(async { Ok(()) }));
        match time::timeout(
            Duration::from_secs(5),
            logs.follow(LogSource::Entrypoint, discard),
        )
        .await
        {
            Err(_) => {}
            Ok(Ok(())) => return fail("log follow ended before it could be cancelled"),
            Ok(Err(error)) => {
                return fail(format!("log follow failed before cancellation: {error}"));
            }
        }

        time::timeout(Duration::from_secs(30), sandbox.describe())
            .await
            .map_err(|_| "describe timed out after cancelling log follow".to_owned())?
            .map_err(|error| format!("describe failed after cancelling log follow: {error}"))?;

        // A sink error must stop the stream and reach the caller unchanged.
        // Saving the chunk first also proves that bytes reached the sink.
        let output = Arc::new(Mutex::new(Vec::new()));
        let sink_output = Arc::clone(&output);
        let rejecting_sink: LogSink = Arc::new(move |chunk| {
            sink_output.lock().expect("log output lock").extend(chunk);
            Box::pin(async { Err(Error::invalid_spec("log_sink", "conformance sentinel")) })
        });
        match time::timeout(
            Duration::from_secs(30),
            logs.follow(LogSource::Entrypoint, rejecting_sink),
        )
        .await
        {
            Ok(Err(Error::InvalidSpec { field, reason }))
                if field == "log_sink" && reason == "conformance sentinel" => {}
            Ok(Err(error)) => return fail(format!("log sink error changed: {error}")),
            Ok(Ok(())) => return fail("log follow ignored the sink error"),
            Err(_) => return fail("entrypoint logs produced no output within 30 seconds"),
        }
        if output.lock().expect("log output lock").is_empty() {
            return fail("entrypoint log sink received an empty chunk");
        }
        PASS
    })
    .await
}

/// A service that listens on a port is awaited by that port and shows up
/// in the listening-port list; once stopped, the port wait times out. The
/// listener is whatever the image offers, python3 or nc; without either
/// the check is skipped.
pub(super) async fn services_wait_for_ports_and_list_them(ctx: &Conformance) -> CheckOutcome {
    ctx.with_ready(|sandbox| async move {
        require_on(sandbox.capabilities(), Capability::Services)?;
        let Some(services) = sandbox.services() else {
            return fail("services are declared but the facet is absent");
        };
        let probe = sandbox
            .exec()
            .run(
                &ExecSpec::bash(
                    "if command -v python3 >/dev/null 2>&1; then echo python3; \
                     elif command -v nc >/dev/null 2>&1; then echo nc; else echo none; fi",
                )
                .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("listener probe failed: {error}"))?;
        // Conformance runs for Host-backed providers share this machine's
        // ports with every other run in flight, so the port is per process.
        let port: u16 = 30_000 + u16::try_from(process::id() % 20_000).unwrap_or(0);
        let command = match probe.stdout_lossy().trim() {
            "python3" => format!("exec python3 -m http.server {port} --bind 127.0.0.1"),
            "nc" => format!("while true; do nc -l 127.0.0.1 {port} < /dev/null; done"),
            _ => return skip("no listener program in the image"),
        };
        let id = services
            .spawn(&ServiceSpec::new(command))
            .await
            .map_err(|error| format!("spawn failed: {error}"))?;
        let result = async {
            services
                .wait_for_port(port, Duration::from_secs(30))
                .await
                .map_err(|error| format!("wait_for_port failed: {error}"))?;
            let ports = services
                .listening_ports()
                .await
                .map_err(|error| format!("listening_ports failed: {error}"))?;
            if !ports.iter().any(|entry| entry.port == port) {
                return fail(format!("port {port} is not listed: {ports:?}"));
            }
            services
                .stop(&id)
                .await
                .map_err(|error| format!("stop failed: {error}"))?;
            // The listener may take a moment to let go of the port.
            let closed_by = Instant::now() + Duration::from_secs(10);
            loop {
                match services.wait_for_port(port, Duration::from_secs(1)).await {
                    Err(Error::Timeout { .. }) => break,
                    Ok(()) if Instant::now() < closed_by => {
                        time::sleep(Duration::from_millis(250)).await;
                    }
                    Ok(()) => return fail("the port still answered after stop"),
                    Err(error) => {
                        return fail(format!(
                            "wait_for_port after stop failed unexpectedly: {error}"
                        ));
                    }
                }
            }
            PASS
        }
        .await;
        let _ = services.stop(&id).await;
        result
    })
    .await
}

/// Background services: spawn outlives its exec, reports status, serves
/// logs, and stops idempotently through the provider-selected implementation.
pub(super) async fn background_services_round_trip(ctx: &Conformance) -> CheckOutcome {
    ctx.with_ready(|sandbox| async move {
        require_on(sandbox.capabilities(), Capability::Services)?;
        let Some(services) = sandbox.services() else {
            return fail("services are declared but the facet is absent");
        };

        let spec = ServiceSpec::new("while true; do echo tick; sleep 0.2; done");
        let id = services
            .spawn(&spec)
            .await
            .map_err(|error| format!("spawn failed: {error}"))?;
        // The service must be observable as running and produce logs.
        let mut running = false;
        for _ in 0..20 {
            let status = services
                .status(&id)
                .await
                .map_err(|error| format!("status failed: {error}"))?;
            if status.running {
                running = true;
                break;
            }
            time::sleep(Duration::from_millis(250)).await;
        }
        if !running {
            return fail("service never reported running");
        }
        let mut saw_logs = false;
        for _ in 0..20 {
            let logs = services
                .logs(&id, 4096)
                .await
                .map_err(|error| format!("logs failed: {error}"))?;
            if String::from_utf8_lossy(&logs).contains("tick") {
                saw_logs = true;
                break;
            }
            time::sleep(Duration::from_millis(250)).await;
        }
        if !saw_logs {
            return fail("service logs never surfaced output");
        }

        services
            .stop(&id)
            .await
            .map_err(|error| format!("stop failed: {error}"))?;
        let mut stopped = false;
        for _ in 0..20 {
            let status = services
                .status(&id)
                .await
                .map_err(|error| format!("status after stop failed: {error}"))?;
            if !status.running {
                stopped = true;
                break;
            }
            time::sleep(Duration::from_millis(250)).await;
        }
        if !stopped {
            return fail("service still running after stop");
        }
        // Stop is idempotent, and an unknown id reports not running.
        services
            .stop(&id)
            .await
            .map_err(|error| format!("second stop failed: {error}"))?;
        let unknown = sandbox_driver::ServiceId::try_new("conformance-unknown-service")
            .map_err(|error| error.to_string())?;
        let status = services
            .status(&unknown)
            .await
            .map_err(|error| format!("status of unknown id failed: {error}"))?;
        if status.running {
            return fail("unknown service id reported running");
        }
        PASS
    })
    .await
}

/// A one-shot container runs in the sandbox's world: it reads a file the
/// sandbox wrote, its output and exit code come back, the file it writes
/// is visible to the sandbox, and a `term` ends a long one.
pub(super) async fn one_shot_shares_the_sandbox_world(ctx: &Conformance) -> CheckOutcome {
    if ctx.caps().one_shot.is_none() {
        return skip("capability one_shot not declared");
    }
    ctx.with_ready(|sandbox| async move {
        if sandbox.capabilities().one_shot.is_none() {
            if sandbox.one_shot().is_some() {
                return fail("one_shot facet is present but not declared for this sandbox");
            }
            return skip("one_shot not declared for this sandbox");
        }
        let Some(image) = ctx.specs.one_shot_image() else {
            return fail("one_shot is declared but no one-shot image was configured");
        };
        let Some(one_shot) = sandbox.one_shot() else {
            return fail("one_shot is declared but the facet is absent");
        };
        sandbox
            .fs()
            .write("one-shot/in.txt", b"shared-in")
            .await
            .map_err(|error| format!("write failed: {error}"))?;
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
        let spec = OneShotSpec::registry(image)
            .entrypoint("sh")
            .args([
                "-c",
                "cat one-shot/in.txt; printf shared-out > one-shot/out.txt; exit 4",
            ])
            .timeout(Duration::from_secs(120));
        let streaming = one_shot
            .run(&spec, controls)
            .await
            .map_err(|error| format!("one-shot run failed: {error}"))?;
        if streaming.result.termination != Termination::Exited
            || streaming.result.exit_code != Some(4)
        {
            return fail(format!(
                "expected exit 4, got {:?} with code {:?}: {}",
                streaming.result.termination,
                streaming.result.exit_code,
                streaming.result.stderr_lossy()
            ));
        }
        let seen: Vec<u8> = chunks
            .lock()
            .expect("chunks lock")
            .iter()
            .flat_map(|(_, chunk)| chunk.clone())
            .collect();
        if !String::from_utf8_lossy(&seen).contains("shared-in") {
            return fail(format!(
                "the one-shot did not see the sandbox's file: {:?}",
                String::from_utf8_lossy(&seen)
            ));
        }
        let written = sandbox
            .fs()
            .read("one-shot/out.txt")
            .await
            .map_err(|error| format!("reading the one-shot's file failed: {error}"))?;
        if written != b"shared-out" {
            return fail(format!(
                "the sandbox did not see the one-shot's file: {written:?}"
            ));
        }

        let token = CancellationToken::new();
        let stop_after = token.clone();
        tokio::spawn(async move {
            time::sleep(Duration::from_millis(500)).await;
            stop_after.cancel();
        });
        let controls = ExecControls {
            term: Some(token),
            ..ExecControls::buffered()
        };
        let spec = OneShotSpec::registry(image)
            .entrypoint("sleep")
            .args(["300"])
            .timeout(Duration::from_secs(120));
        let started = Instant::now();
        let streaming = one_shot
            .run(&spec, controls)
            .await
            .map_err(|error| format!("one-shot term run failed: {error}"))?;
        if streaming.result.termination != Termination::Cancelled {
            return fail(format!(
                "expected Cancelled after term, got {:?}",
                streaming.result.termination
            ));
        }
        if started.elapsed() > Duration::from_secs(60) {
            return fail("the term took over a minute to end the one-shot");
        }
        PASS
    })
    .await
}
