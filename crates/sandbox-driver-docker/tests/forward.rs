//! A container port is reachable through the sandbox's preview URL: a
//! forward on the plugin's loopback bridged into the container, closed by
//! release and by the sandbox's own lifecycle.
//!
//! Requires a reachable Docker daemon; passes trivially without one.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sandbox_driver::{
    ExecControls, ExecSpec, SandboxProvider, SandboxSource, SandboxSpec, WaitOptions, activate,
};
use sandbox_driver_docker::DockerProvider;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;
use tokio_util::sync::CancellationToken;

/// The image the conformance suite uses: Bash for the bridge and Perl for
/// the test server.
const IMAGE: &str = "buildpack-deps:noble";
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
