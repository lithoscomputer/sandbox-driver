//! Port forwards into a container: `preview_url(port)` opens a listener on
//! the plugin's own loopback interface and bridges each accepted connection
//! into the container through a stdio process that connects to the port
//! from inside. Nothing is published on the daemon, so the forward works
//! the same on a local daemon, a remote one, and a daemon whose container
//! addresses the plugin's machine cannot route to (Docker Desktop).
//!
//! A forward lives until it is released, the sandbox stops or is deleted,
//! or the handle is dropped.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::{Error, Exec, PreviewUrl, PreviewUrls, Result, SpawnSpec, StdioProcess};
use tokio::io::{AsyncWriteExt, copy};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::exec::{DockerExec, POSIX_SH};

/// After the client has closed its side, how long the container side may
/// still send (a response to a request the client half-closed after).
const LINGER: Duration = Duration::from_secs(30);
/// How long closing waits for the bridges of a forward to end their
/// container processes.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
/// Pause after a failed accept, so a transient error is not a hot loop.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// Runs inside the container for one accepted connection: connects to the
/// port on the container's loopback and relays both directions. Bash's
/// `/dev/tcp` when the image has Bash, else BusyBox or OpenBSD `nc`; the
/// bridge exits when the container side closes, so the caller sees EOF.
const BRIDGE_SCRIPT: &str = r#"port="$1"
if command -v bash >/dev/null 2>&1; then
  exec bash -c 'exec 4<>"/dev/tcp/127.0.0.1/$1" || exit 1
cat <&4 & reader=$!
cat >&4
wait "$reader"' sandbox-driver-forward "$port"
fi
if command -v nc >/dev/null 2>&1; then
  exec nc 127.0.0.1 "$port"
fi
echo 'sandbox-driver: the container image must provide bash or nc to forward a port' >&2
exit 127
"#;

struct Forward {
    address: SocketAddr,
    cancel:  CancellationToken,
    task:    JoinHandle<()>,
}

/// The open forwards of one container sandbox.
pub(crate) struct DockerForwards {
    exec:     Arc<DockerExec>,
    forwards: Mutex<HashMap<u16, Forward>>,
}

impl DockerForwards {
    pub(crate) fn new(exec: Arc<DockerExec>) -> Self {
        Self {
            exec,
            forwards: Mutex::new(HashMap::new()),
        }
    }

    /// The local address forwarding to `port`, opening one when none is.
    async fn open(&self, port: u16) -> Result<SocketAddr> {
        if let Some(address) = self.address_of(port) {
            return Ok(address);
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|error| Error::io("binding a port forward", error))?;
        let address = listener
            .local_addr()
            .map_err(|error| Error::io("reading the port forward address", error))?;
        let cancel = CancellationToken::new();
        let task = tokio::spawn(serve(
            listener,
            Arc::clone(&self.exec),
            port,
            cancel.clone(),
        ));
        let mut forwards = self.forwards.lock().unwrap_or_else(PoisonError::into_inner);
        match forwards.entry(port) {
            // Two callers raced to open the same port: the first one wins
            // and the second listener is closed before anyone learns of it.
            Entry::Occupied(existing) => {
                cancel.cancel();
                task.abort();
                Ok(existing.get().address)
            }
            Entry::Vacant(slot) => {
                slot.insert(Forward {
                    address,
                    cancel,
                    task,
                });
                Ok(address)
            }
        }
    }

    fn address_of(&self, port: u16) -> Option<SocketAddr> {
        self.forwards
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&port)
            .map(|forward| forward.address)
    }

    /// Closes the forward for `port`, if any, and waits for its bridges to
    /// end their container processes.
    pub(crate) async fn close(&self, port: u16) {
        let forward = self
            .forwards
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&port);
        if let Some(forward) = forward {
            Self::finish(vec![forward]).await;
        }
    }

    /// Closes every forward: the sandbox is stopping or going away.
    pub(crate) async fn close_all(&self) {
        let forwards: Vec<Forward> = self
            .forwards
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
            .map(|(_, forward)| forward)
            .collect();
        Self::finish(forwards).await;
    }

    async fn finish(forwards: Vec<Forward>) {
        for forward in &forwards {
            forward.cancel.cancel();
        }
        for forward in forwards {
            if time::timeout(CLOSE_TIMEOUT, forward.task).await.is_err() {
                tracing::warn!(
                    provider_kind = "docker",
                    address = %forward.address,
                    "port forward bridges did not end within the close timeout"
                );
            }
        }
    }
}

impl Drop for DockerForwards {
    fn drop(&mut self) {
        // The listener tasks own the sockets; cancelling lets each bridge
        // terminate its container process on its own.
        for forward in self
            .forwards
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
        {
            forward.cancel.cancel();
        }
    }
}

#[async_trait]
impl PreviewUrls for DockerForwards {
    #[tracing::instrument(skip_all, fields(provider_kind = "docker", port), err)]
    async fn preview_url(&self, port: u16) -> Result<PreviewUrl> {
        if port == 0 {
            return Err(Error::invalid_spec("port", "a port forward needs a port"));
        }
        let address = self.open(port).await?;
        Ok(PreviewUrl::new(format!("http://{address}")))
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", port))]
    async fn release_preview_url(&self, port: u16) -> Result<()> {
        self.close(port).await;
        Ok(())
    }
}

/// Accepts connections for one forward until cancelled, bridging each into
/// the container; on cancellation waits for the bridges to end.
async fn serve(listener: TcpListener, exec: Arc<DockerExec>, port: u16, cancel: CancellationToken) {
    let mut bridges = JoinSet::new();
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    bridges.spawn(bridge(Arc::clone(&exec), port, stream, cancel.child_token()));
                }
                Err(error) => {
                    tracing::warn!(provider_kind = "docker", port, error = %error, "port forward accept failed");
                    time::sleep(ACCEPT_BACKOFF).await;
                }
            },
            Some(_) = bridges.join_next(), if !bridges.is_empty() => {}
        }
    }
    drop(listener);
    while bridges.join_next().await.is_some() {}
}

/// Relays one accepted connection through a bridge process in the container.
async fn bridge(exec: Arc<DockerExec>, port: u16, client: TcpStream, cancel: CancellationToken) {
    let spec = SpawnSpec::new(POSIX_SH).args([
        "-c",
        BRIDGE_SCRIPT,
        "sandbox-driver-forward",
        &port.to_string(),
    ]);
    let process = match exec.spawn_stdio(&spec).await {
        Ok(process) => process,
        Err(error) => {
            tracing::warn!(provider_kind = "docker", port, error = %error, "port forward bridge failed to start");
            return;
        }
    };
    let StdioProcess {
        mut stdin,
        mut stdout,
        stderr_tail,
        handle,
    } = process;
    let (mut client_read, mut client_write) = client.into_split();
    let relay = async {
        let to_container = async {
            let _ = copy(&mut client_read, &mut stdin).await;
            let _ = stdin.shutdown().await;
            // The client is done sending; let the container side finish
            // answering, but not forever.
            time::sleep(LINGER).await;
        };
        let to_client = async {
            let _ = copy(&mut stdout, &mut client_write).await;
            let _ = client_write.shutdown().await;
        };
        tokio::select! {
            () = to_client => {},
            () = to_container => {},
        }
    };
    tokio::select! {
        () = relay => {},
        () = cancel.cancelled() => {},
    }
    handle.terminate().await;
    let tail = stderr_tail.to_string_lossy();
    if !tail.trim().is_empty() {
        tracing::debug!(provider_kind = "docker", port, tail = %tail.trim(), "port forward bridge ended with diagnostics");
    }
}
