//! A container port is reachable through the sandbox's preview URL: a
//! forward on the plugin's loopback bridged into the container, closed by
//! release and by the sandbox's own lifecycle.
//!
//! Requires a reachable Docker daemon; passes trivially without one.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sandbox_driver::{
    ExecControls, ExecSpec, SandboxProvider, SandboxSource, SandboxSpec, SandboxState, WaitOptions,
    activate, wait_for_state,
};
use sandbox_driver_docker::DockerProvider;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;
use tokio_util::sync::CancellationToken;

/// The image the conformance suite uses: Bash for the bridge and Perl for
/// the test server.
const IMAGE: &str = "ghcr.io/lithoscomputer/ubuntu-24.04:slim-df708f910111";
const PORT: u16 = 8123;

fn spec() -> SandboxSpec {
    SandboxSpec::new(SandboxSource::Image {
        reference: IMAGE.to_owned(),
    })
    .working_directory("/workspace")
}

/// Starts a one-request HTTP responder on `PORT` inside the sandbox.
fn serve_once(sandbox: &Arc<dyn sandbox_driver::Sandbox>, body: &str) -> CancellationToken {
    let kill = CancellationToken::new();
    let script = format!(
        r#"exec perl -e 'use IO::Socket::INET; my $s = IO::Socket::INET->new(LocalAddr => "127.0.0.1", LocalPort => {PORT}, Listen => 5, ReuseAddr => 1) or exit 3; my $c = $s->accept or exit 4; my $b = "{body}"; print $c "HTTP/1.0 200 OK\r\nContent-Length: " . length($b) . "\r\nConnection: close\r\n\r\n$b"; close $c;'"#
    );
    let sandbox = Arc::clone(sandbox);
    let controls = ExecControls {
        kill: Some(kill.clone()),
        ..ExecControls::buffered()
    };
    tokio::spawn(async move {
        let _ = sandbox
            .exec()
            .run_streaming(
                &ExecSpec::bash(script).timeout(Duration::from_secs(60)),
                controls,
            )
            .await;
    });
    kill
}

/// One HTTP/1.0 request through `address`; `None` when nothing answered.
async fn fetch(address: &str) -> Option<String> {
    let mut stream = time::timeout(Duration::from_secs(5), TcpStream::connect(address))
        .await
        .ok()?
        .ok()?;
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: sandbox\r\n\r\n")
        .await
        .ok()?;
    let mut bytes = Vec::new();
    let _ = time::timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes)).await;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

async fn fetch_until(address: &str, body: &str) -> Option<String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(response) = fetch(address).await {
            if response.contains(body) {
                return Some(response);
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        time::sleep(Duration::from_millis(200)).await;
    }
}

fn address_of(url: &str) -> String {
    url.strip_prefix("http://")
        .expect("forwards are plain http on this machine")
        .to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn preview_url_forwards_a_container_port_and_release_closes_it() {
    let Ok(provider) = DockerProvider::connect().await else {
        return;
    };
    let sandbox = provider.create(&spec(), None).await.expect("create");
    let outcome = async {
        activate(sandbox.as_ref(), &WaitOptions::default())
            .await
            .map_err(|error| format!("activate: {error}"))?;
        let preview = sandbox.preview_urls().ok_or("preview facet")?;

        // Reuse: the same port maps to the same local address.
        let first = preview.preview_url(PORT).await.map_err(|e| e.to_string())?;
        let again = preview.preview_url(PORT).await.map_err(|e| e.to_string())?;
        if first.url != again.url {
            return Err(format!("two opens differ: {} vs {}", first.url, again.url));
        }
        let address = address_of(&first.url);
        if !address.starts_with("127.0.0.1:") {
            return Err(format!("forward is not on loopback: {address}"));
        }

        // Before anything listens inside, a connection closes without a body.
        let empty = fetch(&address).await.ok_or("connect to the forward")?;
        if empty.contains("preview-ok") {
            return Err("a response before the server started".to_owned());
        }

        let kill = serve_once(&sandbox, "preview-ok");
        let response = fetch_until(&address, "preview-ok")
            .await
            .ok_or("no response through the forward")?;
        if !response.starts_with("HTTP/1.0 200 OK") {
            return Err(format!("unexpected response: {response:?}"));
        }
        kill.cancel();

        // Release closes the listener; the next open gets a fresh one.
        preview
            .release_preview_url(PORT)
            .await
            .map_err(|e| e.to_string())?;
        if TcpStream::connect(&address).await.is_ok() {
            return Err("the released forward still accepts connections".to_owned());
        }
        let reopened = preview.preview_url(PORT).await.map_err(|e| e.to_string())?;
        let reopened = address_of(&reopened.url);
        TcpStream::connect(&reopened)
            .await
            .map_err(|error| format!("reopened forward refuses connections: {error}"))?;

        // Stopping the sandbox closes every forward.
        sandbox.stop().await.map_err(|e| e.to_string())?;
        if TcpStream::connect(&reopened).await.is_ok() {
            return Err("a stopped sandbox still forwards".to_owned());
        }
        Ok::<(), String>(())
    }
    .await;
    sandbox.delete().await.expect("delete");
    outcome.expect("forward round trip");
}

/// An image with neither Bash nor `nc` cannot run a bridge: the request
/// says so, instead of handing out a forward whose connections close empty.
#[tokio::test(flavor = "multi_thread")]
async fn preview_url_fails_when_the_image_has_neither_bash_nor_nc() {
    let Ok(provider) = DockerProvider::connect().await else {
        return;
    };
    // The Alpine image has no Bash; its `nc` is a BusyBox link that is
    // removed here to leave the image with neither tool.
    let spec = SandboxSpec::new(SandboxSource::Image {
        reference: "ghcr.io/fabro-sh/dhi-alpine-base:3.23-dev-2026-06-17".to_owned(),
    })
    .working_directory("/workspace");
    let sandbox = provider.create(&spec, None).await.expect("create");
    let outcome = async {
        // Not `activate`: its Bash probe would fail first on this image.
        sandbox
            .start()
            .await
            .map_err(|error| format!("start: {error}"))?;
        wait_for_state(
            sandbox.as_ref(),
            SandboxState::Running,
            &WaitOptions::default(),
        )
        .await
        .map_err(|error| format!("wait for running: {error}"))?;
        let removed = sandbox
            .exec()
            .run(&ExecSpec::new("/bin/sh").args(["-c", "rm -f /usr/bin/nc && ! command -v nc"]))
            .await
            .map_err(|error| format!("remove nc: {error}"))?;
        if !removed.success() {
            return Err("nc is still present after removal".to_owned());
        }
        let preview = sandbox.preview_urls().ok_or("preview facet")?;
        match preview.preview_url(PORT).await {
            Err(sandbox_driver::Error::Provider(error)) if error.message.contains("bash or nc") => {
                Ok(())
            }
            Err(error) => Err(format!("unexpected error: {error}")),
            Ok(preview) => Err(format!("a forward was opened anyway: {}", preview.url)),
        }
    }
    .await;
    sandbox.delete().await.expect("delete");
    outcome.expect("missing bridge tools are reported at the request");
}
