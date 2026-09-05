//! The data transport: one private Unix-socket connection per operation.
//!
//! Control messages stay on the plugin's stdio. Every byte stream — exec
//! output and stdin, stdio and PTY traffic, logs, file contents — rides a
//! connection of its own to a listener the host owns, so a slow consumer
//! of one stream backpressures only that stream and never a control
//! response. Frames are binary: a one-byte kind, a four-byte big-endian
//! payload length, the payload. The receiver rejects a frame over the
//! negotiated limit before it allocates the payload.
//!
//! The plugin opens each connection: its first frame is [`FrameKind::Open`]
//! carrying the channel id and one-use token the host sent in the request
//! that needs the channel. The host matches them and hands the connection
//! to the waiting operation; anything else is closed unanswered.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, fmt, fs, io, process};

use sandbox_driver::{Error, Result, TransportError};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::{ClientDiagnostics, TransportLimits, limits};

/// The largest payload one frame may carry. Negotiated at `initialize`;
/// this implementation offers and accepts exactly this value.
pub const MAX_FRAME_BYTES: u32 = 64 * 1024;

const HEADER_LEN: usize = 5;

/// What a frame carries. Any other byte closes the connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    /// The plugin's first frame: a JSON [`ChannelRequest`].
    Open   = 0,
    /// Bytes from the plugin: a command's stdout, PTY output, a log or file
    /// chunk.
    Stdout = 1,
    /// Bytes from the plugin: a command's stderr.
    Stderr = 2,
    /// Bytes from the host: a command's or PTY's input, a file to write.
    Stdin  = 3,
    /// The sender has no more data. Each side sends one when it is done
    /// writing; the connection closes after both.
    Eof    = 4,
}

impl FrameKind {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Open),
            1 => Some(Self::Stdout),
            2 => Some(Self::Stderr),
            3 => Some(Self::Stdin),
            4 => Some(Self::Eof),
            _ => None,
        }
    }
}

/// What a request carries to name its channel: the id the host will look
/// the connection up by, and the one-use token that proves the plugin
/// read the request.
#[derive(Clone, Serialize, Deserialize)]
pub struct ChannelRequest {
    pub channel_id: u64,
    pub token:      String,
}

impl fmt::Debug for ChannelRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelRequest")
            .field("channel_id", &self.channel_id)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Identity allowed to open data channels. Spawned plugins use their exact PID.
#[derive(Clone, Copy, Debug)]
pub enum TrustedPeer {
    Process(u32),
    /// Explicit policy for transports whose peer can use several processes.
    User(u32),
}

#[derive(Serialize, Deserialize)]
struct OpenFrame {
    #[serde(flatten)]
    request:     ChannelRequest,
    #[serde(default)]
    acknowledge: bool,
}

/// The data transport the host announces at `initialize`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataTransport {
    pub socket_path:     PathBuf,
    /// The largest frame payload either side may send.
    pub max_frame_bytes: u32,
    /// Request an open acknowledgment before any data or provider work.
    #[serde(default)]
    pub open_ack:        bool,
}

fn transport_error(context: &'static str, error: io::Error) -> Error {
    Error::Transport(TransportError::with_source(context, error))
}

/// Writes frames to one half of a channel connection.
pub struct FrameWriter<W> {
    writer:           W,
    max_bytes:        usize,
    permit:           Option<Arc<OwnedSemaphorePermit>>,
    finished:         bool,
    progress_timeout: Duration,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    pub fn new(writer: W, max_frame_bytes: u32) -> Self {
        Self {
            writer,
            max_bytes: max_frame_bytes as usize,
            permit: None,
            finished: false,
            progress_timeout: Duration::from_secs(30),
        }
    }

    /// Writes `payload` as one or more frames of `kind`, split at the
    /// negotiated limit so a large chunk never becomes an oversized frame.
    pub async fn write(&mut self, kind: FrameKind, payload: &[u8]) -> Result<()> {
        if self.finished || self.max_bytes == 0 || self.max_bytes > MAX_FRAME_BYTES as usize {
            return Err(Error::invalid_spec(
                "frame",
                "invalid frame limit or write after EOF",
            ));
        }
        if matches!(kind, FrameKind::Eof) && !payload.is_empty() {
            return Err(Error::invalid_spec(
                "frame",
                "EOF must have an empty payload",
            ));
        }
        if kind == FrameKind::Open && payload.len() > self.max_bytes {
            return Err(Error::invalid_spec("frame", "open cannot span frames"));
        }
        if payload.is_empty() {
            return self.write_one(kind, payload).await;
        }
        for chunk in payload.chunks(self.max_bytes) {
            self.write_one(kind, chunk).await?;
        }
        Ok(())
    }

    async fn write_one(&mut self, kind: FrameKind, payload: &[u8]) -> Result<()> {
        let length = u32::try_from(payload.len())
            .map_err(|_| Error::invalid_spec("frame", "payload exceeds the frame size"))?;
        let mut header = [0u8; HEADER_LEN];
        header[0] = kind as u8;
        header[1..].copy_from_slice(&length.to_be_bytes());
        self.deliver(&header).await?;
        self.deliver(payload).await?;
        Ok(())
    }

    async fn deliver(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            let written = time::timeout(self.progress_timeout, self.writer.write(bytes))
                .await
                .map_err(|_| {
                    Error::Transport(TransportError::new(
                        "data output made no progress; delivery is incomplete",
                    ))
                })?
                .map_err(|error| transport_error("writing data frame", error))?;
            if written == 0 {
                return Err(transport_error(
                    "writing data frame",
                    io::ErrorKind::WriteZero.into(),
                ));
            }
            bytes = &bytes[written..];
        }
        Ok(())
    }

    /// Sends this side's `Eof`.
    pub async fn finish(&mut self) -> Result<()> {
        self.write(FrameKind::Eof, &[]).await?;
        self.finished = true;
        time::timeout(self.progress_timeout, self.writer.flush())
            .await
            .map_err(|_| {
                Error::Transport(TransportError::new("data channel flush made no progress"))
            })?
            .map_err(|error| transport_error("flushing data channel", error))
    }
}

/// Reads frames from one half of a channel connection.
pub struct FrameReader<R> {
    reader:    R,
    max_bytes: usize,
    permit:    Option<Arc<OwnedSemaphorePermit>>,
    finished:  bool,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(reader: R, max_frame_bytes: u32) -> Self {
        Self {
            reader,
            max_bytes: max_frame_bytes as usize,
            permit: None,
            finished: false,
        }
    }

    /// The next frame, or `None` when the connection closed cleanly.
    pub async fn read(&mut self) -> Result<Option<(FrameKind, Vec<u8>)>> {
        if self.finished {
            return Ok(None);
        }
        if self.max_bytes == 0 || self.max_bytes > MAX_FRAME_BYTES as usize {
            return Err(Error::invalid_spec("frame", "invalid frame limit"));
        }
        let mut header = [0u8; HEADER_LEN];
        if self
            .reader
            .read(&mut header[..1])
            .await
            .map_err(|error| transport_error("reading data frame header", error))?
            == 0
        {
            return Err(Error::Transport(TransportError::new(
                "data channel closed before EOF; delivery is incomplete",
            )));
        }
        self.reader
            .read_exact(&mut header[1..])
            .await
            .map_err(|error| transport_error("reading data frame header", error))?;
        let kind = FrameKind::from_byte(header[0])
            .ok_or_else(|| Error::invalid_spec("frame", format!("unknown kind {}", header[0])))?;
        let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if length > self.max_bytes {
            return Err(Error::invalid_spec(
                "frame",
                format!(
                    "payload of {length} bytes exceeds the {} limit",
                    self.max_bytes
                ),
            ));
        }
        if kind == FrameKind::Eof {
            if length != 0 {
                return Err(Error::invalid_spec(
                    "frame",
                    "EOF must have an empty payload",
                ));
            }
            self.finished = true;
        }
        let mut payload = vec![0u8; length];
        self.reader
            .read_exact(&mut payload)
            .await
            .map_err(|error| transport_error("reading data frame", error))?;
        Ok(Some((kind, payload)))
    }
}

/// One accepted and authenticated channel connection, split for
/// independent reading and writing.
pub struct Channel {
    pub reader: FrameReader<OwnedReadHalf>,
    pub writer: FrameWriter<OwnedWriteHalf>,
}

impl fmt::Debug for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Channel").finish_non_exhaustive()
    }
}

impl Channel {
    pub(crate) fn progress_timeout(&mut self, timeout: Duration) {
        self.writer.progress_timeout = timeout;
    }

    pub(crate) fn hold(&mut self, permit: Arc<OwnedSemaphorePermit>) {
        self.reader.permit = Some(Arc::clone(&permit));
        self.writer.permit = Some(permit);
    }
    fn from_stream(stream: UnixStream, max_frame_bytes: u32) -> Self {
        let (read, write) = stream.into_split();
        Self {
            reader: FrameReader::new(read, max_frame_bytes),
            writer: FrameWriter::new(write, max_frame_bytes),
        }
    }
}

const SETUP_SAMPLES: usize = 4096;

#[derive(Default)]
struct Measurements {
    setup_us: Mutex<VecDeque<u64>>,
    opened:   AtomicU64,
    lost:     AtomicU64,
    backoffs: AtomicU64,
}

struct Pending {
    started:          Instant,
    measurements:     Arc<Measurements>,
    token:            String,
    sender:           oneshot::Sender<Channel>,
    io_permit:        Arc<OwnedSemaphorePermit>,
    _open_permit:     OwnedSemaphorePermit,
    progress_timeout: Duration,
}

/// The host's listener: a Unix socket in a private directory, an accept
/// task that authenticates each connection, and the registry of channels
/// operations are waiting on.
pub struct ChannelListener {
    directory:        PathBuf,
    socket_path:      PathBuf,
    max_frame:        u32,
    next_channel:     AtomicU64,
    pending:          Arc<Mutex<HashMap<u64, Pending>>>,
    accept_task:      JoinHandle<()>,
    failed:           CancellationToken,
    limits:           TransportLimits,
    io_budget:        Arc<Semaphore>,
    open_budget:      Arc<Semaphore>,
    handshake_budget: Arc<Semaphore>,
    measurements:     Arc<Measurements>,
}

impl fmt::Debug for ChannelListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelListener")
            .field("socket_path", &self.socket_path)
            .finish_non_exhaustive()
    }
}

impl ChannelListener {
    /// Binds a fresh socket under a private temporary directory.
    pub fn bind() -> Result<Self> {
        Self::bind_with_limits(
            TransportLimits::default(),
            TrustedPeer::Process(process::id()),
        )
    }

    pub fn bind_with_limits(limits: TransportLimits, peer: TrustedPeer) -> Result<Self> {
        limits.validate()?;
        let directory = env::temp_dir().join(format!(
            "sandbox-driver-{}-{:016x}",
            process::id(),
            rand::random::<u64>()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|error| transport_error("creating private data transport directory", error))?;
        let socket_path = directory.join("data.sock");
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = fs::remove_dir(&directory);
                return Err(transport_error("binding data transport socket", error));
            }
        };
        let pending: Arc<Mutex<HashMap<u64, Pending>>> = Arc::new(Mutex::new(HashMap::new()));
        let accept_pending = Arc::clone(&pending);
        let max_frame = MAX_FRAME_BYTES;
        let handshake_budget = Arc::new(Semaphore::new(limits.unauthenticated_handshakes));
        let accept_budget = Arc::clone(&handshake_budget);
        let measurements = Arc::new(Measurements::default());
        let accept_measurements = Arc::clone(&measurements);
        let open_timeout = limits.open_timeout;
        let failed = CancellationToken::new();
        let accept_failed = failed.clone();
        let accept_task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                // Reap completed handshakes before accepting another socket.
                // A continuous invalid-connection burst must not retain their
                // completed task records.
                while connections.try_join_next().is_some() {}
                let accepted = tokio::select! {
                    accepted = listener.accept() => accepted,
                    _ = connections.join_next(), if !connections.is_empty() => continue,
                };
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        // Fail pending opens explicitly on a fatal listener error.
                        // Resource exhaustion is transient; backoff bounds retries.
                        if matches!(error.raw_os_error(), Some(23 | 24))
                            || matches!(
                                error.kind(),
                                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                            )
                        {
                            accept_measurements.backoffs.fetch_add(1, Ordering::Relaxed);
                            time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                        accept_failed.cancel();
                        accept_pending
                            .lock()
                            .expect("pending channels lock")
                            .clear();
                        break;
                    }
                };
                let Ok(permit) = Arc::clone(&accept_budget).try_acquire_owned() else {
                    continue;
                };
                let pending = Arc::clone(&accept_pending);
                connections.spawn(async move {
                    let _permit = permit;
                    // Invalid connections are untrusted; never log their payloads.
                    let _ = admit(stream, &pending, max_frame, peer, open_timeout).await;
                });
            }
        });
        Ok(Self {
            directory,
            socket_path,
            max_frame,
            next_channel: AtomicU64::new(1),
            pending,
            accept_task,
            failed,
            handshake_budget,
            measurements,
            io_budget: Arc::new(Semaphore::new(limits.active_io)),
            open_budget: Arc::new(Semaphore::new(limits.pending_opens)),
            limits,
        })
    }

    pub(crate) fn diagnostics(&self) -> ClientDiagnostics {
        ClientDiagnostics {
            active_io: self.limits.active_io - self.io_budget.available_permits(),
            pending_opens: self.limits.pending_opens - self.open_budget.available_permits(),
            handshakes: self.limits.unauthenticated_handshakes
                - self.handshake_budget.available_permits(),
            accept_backoffs: self.measurements.backoffs.load(Ordering::Relaxed),
            authenticated_opens: self.measurements.opened.load(Ordering::Relaxed),
            setup_samples_lost: self.measurements.lost.load(Ordering::Relaxed),
            ..ClientDiagnostics::default()
        }
    }

    /// Drain at most 4096 recent admission-to-authentication measurements.
    /// Sampling does not include waiting for the caller to poll acceptance.
    pub fn take_setup_samples_us(&self) -> Vec<u64> {
        self.measurements
            .setup_us
            .lock()
            .expect("setup samples lock")
            .drain(..)
            .collect()
    }

    pub(crate) fn failure_signal(&self) -> CancellationToken {
        self.failed.clone()
    }

    pub fn transport(&self) -> DataTransport {
        DataTransport {
            socket_path:     self.socket_path.clone(),
            max_frame_bytes: self.max_frame,
            open_ack:        true,
        }
    }

    pub fn max_frame_bytes(&self) -> u32 {
        self.max_frame
    }

    /// Registers a channel an operation is about to request and returns
    /// the request to send plus the receiver the connection arrives on.
    pub fn expect(&self) -> Result<(ChannelRequest, ChannelReceiver)> {
        let started = Instant::now();
        if self.accept_task.is_finished() {
            return Err(Error::Transport(TransportError::new(
                "data listener failed",
            )));
        }
        let io_permit = Arc::new(limits::acquire(&self.io_budget, "active_io")?);
        let open_permit = limits::acquire(&self.open_budget, "pending_opens")?;
        let channel_id = self.next_channel.fetch_add(1, Ordering::Relaxed);
        let token = random_token();
        let (sender, receiver) = oneshot::channel();
        self.pending
            .lock()
            .expect("pending channels lock")
            .insert(channel_id, Pending {
                started,
                measurements: Arc::clone(&self.measurements),
                token: token.clone(),
                sender,
                io_permit: Arc::clone(&io_permit),
                _open_permit: open_permit,
                progress_timeout: self.limits.output_progress_timeout,
            });
        Ok((ChannelRequest { channel_id, token }, ChannelReceiver {
            channel_id,
            receiver,
            pending: Arc::clone(&self.pending),
            io_permit,
            timeout: self.limits.open_timeout,
        }))
    }
}

impl Drop for ChannelListener {
    fn drop(&mut self) {
        self.accept_task.abort();
        self.pending.lock().expect("pending channels lock").clear();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// The host side of one expected channel: resolves when the plugin
/// connects, and forgets the expectation when dropped.
pub struct ChannelReceiver {
    io_permit:  Arc<OwnedSemaphorePermit>,
    channel_id: u64,
    receiver:   oneshot::Receiver<Channel>,
    pending:    Arc<Mutex<HashMap<u64, Pending>>>,
    timeout:    Duration,
}

impl ChannelReceiver {
    pub(crate) fn io_permit(&self) -> Arc<OwnedSemaphorePermit> {
        Arc::clone(&self.io_permit)
    }

    /// Waits for the plugin's connection.
    pub async fn accept(mut self) -> Result<Channel> {
        let outcome = time::timeout(self.timeout, &mut self.receiver)
            .await
            .map_err(|_| Error::Transport(TransportError::new("data channel open timed out")))?;
        outcome.map_err(|_| {
            Error::Transport(TransportError::new(
                "the data channel was dropped before the plugin connected",
            ))
        })
    }

    /// Waits at most the configured open timeout for the plugin connection, for
    /// a caller that already holds the operation's response.
    pub async fn accept_soon(self) -> Result<Channel> {
        match time::timeout(self.timeout, self.accept()).await {
            Ok(outcome) => outcome,
            Err(_) => Err(Error::Transport(TransportError::new(
                "the plugin answered an operation without opening its data channel",
            ))),
        }
    }
}

impl Drop for ChannelReceiver {
    fn drop(&mut self) {
        self.pending
            .lock()
            .expect("pending channels lock")
            .remove(&self.channel_id);
    }
}

async fn admit(
    stream: UnixStream,
    pending: &Mutex<HashMap<u64, Pending>>,
    max_frame: u32,
    peer: TrustedPeer,
    open_timeout: Duration,
) -> Result<()> {
    let credentials = stream
        .peer_cred()
        .map_err(|error| transport_error("reading data peer credentials", error))?;
    let allowed = match peer {
        TrustedPeer::Process(pid) => {
            credentials
                .pid()
                .and_then(|value| u32::try_from(value).ok())
                == Some(pid)
        }
        TrustedPeer::User(uid) => credentials.uid() == uid,
    };
    if !allowed {
        return Err(Error::invalid_spec("peer", "unexpected data channel peer"));
    }
    let mut channel = Channel::from_stream(stream, max_frame);
    let opened = time::timeout(open_timeout, channel.reader.read())
        .await
        .map_err(|_| Error::Transport(TransportError::new("data channel open timed out")))??;
    let Some((FrameKind::Open, payload)) = opened else {
        return Err(Error::invalid_spec(
            "frame",
            "the first frame on a data channel must be open",
        ));
    };
    let open: OpenFrame = serde_json::from_slice(&payload).map_err(|error| {
        Error::invalid_spec(
            "frame",
            format!(
                "invalid open frame at line {} column {}",
                error.line(),
                error.column()
            ),
        )
    })?;
    let acknowledge = open.acknowledge;
    let open = open.request;
    let expected = match pending
        .lock()
        .expect("pending channels lock")
        .entry(open.channel_id)
    {
        Entry::Occupied(entry) if entry.get().token == open.token => entry.remove(),
        Entry::Occupied(_) => {
            return Err(Error::invalid_spec("token", "data channel token mismatch"));
        }
        Entry::Vacant(_) => {
            return Err(Error::invalid_spec(
                "channel_id",
                format!("no operation is waiting on channel {}", open.channel_id),
            ));
        }
    };
    channel.hold(expected.io_permit);
    channel.progress_timeout(expected.progress_timeout);
    if acknowledge {
        channel.writer.write(FrameKind::Open, &[]).await?;
    }
    let elapsed = u64::try_from(expected.started.elapsed().as_micros()).unwrap_or(u64::MAX);
    if expected.sender.send(channel).is_err() {
        return Err(Error::Transport(TransportError::new(
            "the operation stopped waiting for its data channel",
        )));
    }
    expected.measurements.opened.fetch_add(1, Ordering::Relaxed);
    let mut samples = expected
        .measurements
        .setup_us
        .lock()
        .expect("setup samples lock");
    if samples.len() == SETUP_SAMPLES {
        samples.pop_front();
        expected.measurements.lost.fetch_add(1, Ordering::Relaxed);
    }
    samples.push_back(elapsed);
    Ok(())
}

/// The plugin side: opens the connection for one request's channel.
pub async fn open(transport: &DataTransport, request: &ChannelRequest) -> Result<Channel> {
    let stream = UnixStream::connect(&transport.socket_path)
        .await
        .map_err(|error| transport_error("connecting to the host data socket", error))?;
    let mut channel = Channel::from_stream(stream, transport.max_frame_bytes);
    let payload = serde_json::to_vec(&OpenFrame {
        request:     request.clone(),
        acknowledge: transport.open_ack,
    })
    .expect("open frame contains only serializable values");
    channel.writer.write(FrameKind::Open, &payload).await?;
    if transport.open_ack {
        match time::timeout(Duration::from_secs(10), channel.reader.read()).await {
            Ok(Ok(Some((FrameKind::Open, payload)))) if payload.is_empty() => {}
            _ => {
                return Err(Error::Transport(TransportError::new(
                    "data channel authentication was not acknowledged",
                )));
            }
        }
    }
    Ok(channel)
}

fn random_token() -> String {
    let bytes = rand::random::<[u8; 32]>();
    let mut hex = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    /// RLIMIT changes happen only in a dedicated subprocess, never in the
    /// test runner or another concurrently running test's process.
    #[test]
    fn descriptor_exhaustion_recovers_after_fd_pressure() {
        use std::io::{BufRead as _, Write as _};
        use std::process::{Command, Stdio};

        use nix::sys::resource::{Resource, getrlimit, setrlimit};
        use tokio::runtime::Builder;
        const ROLE: &str = "SANDBOX_DRIVER_FD_PRESSURE_ROLE";
        const NAME: &str = "channel::tests::descriptor_exhaustion_recovers_after_fd_pressure";
        match env::var(ROLE).as_deref() {
            Ok("peer") => {
                let mut line = String::new();
                io::BufReader::new(io::stdin())
                    .read_line(&mut line)
                    .expect("peer line");
                let (transport, request): (DataTransport, ChannelRequest) =
                    serde_json::from_str(&line).expect("peer input");
                Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("peer runtime")
                    .block_on(async {
                        // macOS may close a queued connection when accept hits
                        // EMFILE. Retry only this test handshake; no provider
                        // operation has started or is replayed.
                        let mut channel = time::timeout(Duration::from_secs(5), async {
                            loop {
                                if let Ok(channel) = open(&transport, &request).await {
                                    break channel;
                                }
                                time::sleep(Duration::from_millis(50)).await;
                            }
                        })
                        .await
                        .expect("peer authenticated after recovery");
                        assert!(matches!(
                            channel.reader.read().await.expect("peer EOF"),
                            Some((FrameKind::Eof, _))
                        ));
                    });
            }
            Ok("listener") => {
                let (_, hard) = getrlimit(Resource::RLIMIT_NOFILE).expect("rlimit");
                setrlimit(Resource::RLIMIT_NOFILE, 128.min(hard), hard)
                    .expect("child descriptor limit");
                Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("listener runtime")
                    .block_on(async {
                        let mut peer = Command::new(env::current_exe().expect("test executable"))
                            .args(["--exact", NAME, "--nocapture"])
                            .env(ROLE, "peer")
                            .stdin(Stdio::piped())
                            .stdout(Stdio::piped())
                            .spawn()
                            .expect("peer process");
                        let listener = ChannelListener::bind_with_limits(
                            TransportLimits::default(),
                            TrustedPeer::Process(peer.id()),
                        )
                        .expect("listener");
                        let directory = listener.directory.clone();
                        let (request, receiver) = listener.expect().expect("expectation");
                        let mut files = Vec::new();
                        loop {
                            match fs::File::open("/dev/null") {
                                Ok(file) => files.push(file),
                                Err(error) => {
                                    assert_eq!(error.raw_os_error(), Some(24));
                                    break;
                                }
                            }
                        }
                        let mut input = peer.stdin.take().expect("peer stdin");
                        serde_json::to_writer(&mut input, &(listener.transport(), request))
                            .expect("release peer");
                        input.write_all(b"\n").expect("peer newline");
                        input.flush().expect("peer flush");
                        time::timeout(Duration::from_secs(3), async {
                            while listener.diagnostics().accept_backoffs < 3 {
                                time::sleep(Duration::from_millis(10)).await;
                            }
                        })
                        .await
                        .unwrap_or_else(|_| panic!("no accept retries: failed={}, backoffs={}, pending={}, open_files={}", listener.failed.is_cancelled(), listener.diagnostics().accept_backoffs, listener.diagnostics().pending_opens, files.len()));
                        assert_eq!(listener.diagnostics().pending_opens, 1);
                        drop(files);
                        drop(input);
                        let mut channel = time::timeout(Duration::from_secs(3), receiver.accept())
                            .await
                            .expect("listener recovers")
                            .expect("authenticated");
                        channel.writer.finish().await.expect("finish");
                        drop(channel);
                        assert!(peer.wait().expect("join peer").success());
                        assert_eq!(listener.diagnostics().active_io, 0);
                        drop(listener);
                        assert!(!directory.exists());
                    });
            }
            _ => {
                let output = Command::new(env::current_exe().expect("test executable"))
                    .args(["--exact", NAME, "--nocapture"])
                    .env(ROLE, "listener")
                    .output()
                    .expect("isolated descriptor test");
                assert!(
                    output.status.success(),
                    "{}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }

    use tokio::io::{duplex, split};

    use super::*;

    #[tokio::test]
    async fn frames_round_trip_and_split_at_the_limit() {
        let (client, server) = duplex(1024);
        let (server_read, _server_write) = split(server);
        let (_client_read, client_write) = split(client);
        let mut writer = FrameWriter::new(client_write, 4);
        let mut reader = FrameReader::new(server_read, 4);
        writer
            .write(FrameKind::Stdout, b"0123456789")
            .await
            .expect("write");
        writer.finish().await.expect("finish");
        let mut seen = Vec::new();
        while let Some((kind, payload)) = reader.read().await.expect("read") {
            if kind == FrameKind::Eof {
                break;
            }
            assert_eq!(kind, FrameKind::Stdout);
            assert!(payload.len() <= 4);
            seen.extend(payload);
        }
        assert_eq!(seen, b"0123456789");
    }

    #[tokio::test]
    async fn an_oversized_frame_is_refused_before_allocation() {
        let (client, server) = duplex(1024);
        let (server_read, _server_write) = split(server);
        let (_client_read, mut client_write) = split(client);
        let mut header = [0u8; HEADER_LEN];
        header[0] = FrameKind::Stdout as u8;
        header[1..].copy_from_slice(&(1_000_000u32).to_be_bytes());
        client_write.write_all(&header).await.expect("header");
        let mut reader = FrameReader::new(server_read, MAX_FRAME_BYTES);
        let error = reader.read().await.expect_err("oversized frame refused");
        assert!(matches!(error, Error::InvalidSpec { .. }), "{error}");
    }

    #[tokio::test]
    async fn the_listener_matches_channels_by_id_and_token() {
        let listener = ChannelListener::bind().expect("bind");
        let transport = listener.transport();
        let (request, receiver) = listener.expect().expect("admitted");
        let plugin = tokio::spawn(async move {
            let mut channel = open(&transport, &request).await.expect("open");
            channel
                .writer
                .write(FrameKind::Stdout, b"hello")
                .await
                .expect("write");
            channel.writer.finish().await.expect("finish");
        });
        let mut channel = receiver.accept().await.expect("accept");
        let (kind, payload) = channel.reader.read().await.expect("read").expect("frame");
        assert_eq!(kind, FrameKind::Stdout);
        assert_eq!(payload, b"hello");
        plugin.await.expect("plugin side");
    }

    #[tokio::test]
    async fn a_wrong_token_is_refused() {
        let listener = ChannelListener::bind().expect("bind");
        let transport = listener.transport();
        let (request, receiver) = listener.expect().expect("admitted");
        let forged = ChannelRequest {
            channel_id: request.channel_id,
            token:      "not-the-token".to_owned(),
        };
        assert!(open(&transport, &forged).await.is_err());
        // A refused connection must not consume another operation's token.
        let _legitimate = open(&transport, &request)
            .await
            .expect("legitimate connect");
        receiver
            .accept_soon()
            .await
            .expect("legitimate channel accepted");
    }

    #[tokio::test]
    async fn invalid_connection_bursts_preserve_admission_and_recover() {
        let limits = TransportLimits {
            unauthenticated_handshakes: 2,
            open_timeout: Duration::from_millis(100),
            ..TransportLimits::default()
        };
        let listener =
            ChannelListener::bind_with_limits(limits, TrustedPeer::Process(process::id()))
                .expect("bind");
        let transport = listener.transport();
        let (healthy_request, healthy_receiver) = listener.expect().expect("healthy expectation");
        let mut healthy = open(&transport, &healthy_request)
            .await
            .expect("healthy open");
        let mut healthy_accepted = healthy_receiver.accept().await.expect("healthy accepted");
        let (request, receiver) = listener.expect().expect("legitimate expectation");
        let mut stalled = Vec::new();
        for _ in 0..32 {
            stalled.push(
                UnixStream::connect(&transport.socket_path)
                    .await
                    .expect("connect"),
            );
            assert!(listener.diagnostics().handshakes <= 2);
            healthy
                .writer
                .write(FrameKind::Stdout, b"healthy")
                .await
                .expect("healthy write");
            assert_eq!(
                time::timeout(Duration::from_secs(1), healthy_accepted.reader.read())
                    .await
                    .expect("healthy channel progresses during stalled opens")
                    .expect("read")
                    .expect("frame")
                    .1,
                b"healthy"
            );
        }
        assert_eq!(listener.diagnostics().pending_opens, 1);
        drop(stalled);
        time::timeout(Duration::from_secs(2), async {
            while listener.diagnostics().handshakes != 0 {
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("stalled handshakes drain");
        for index in 0..1000 {
            let forged = ChannelRequest {
                channel_id: if index % 2 == 0 {
                    request.channel_id
                } else {
                    u64::MAX
                },
                token:      "invalid".to_owned(),
            };
            assert!(open(&transport, &forged).await.is_err());
            assert!(listener.diagnostics().handshakes <= 2);
            assert_eq!(listener.diagnostics().pending_opens, 1);
            if index % 50 == 0 {
                healthy
                    .writer
                    .write(FrameKind::Stdout, b"healthy")
                    .await
                    .expect("healthy write");
                assert_eq!(
                    time::timeout(Duration::from_secs(1), healthy_accepted.reader.read())
                        .await
                        .expect("healthy channel progresses during invalid opens")
                        .expect("read")
                        .expect("frame")
                        .1,
                    b"healthy"
                );
            }
        }
        let mut legitimate = open(&transport, &request).await.expect("legitimate open");
        let mut accepted = receiver.accept().await.expect("legitimate accept");
        legitimate
            .writer
            .write(FrameKind::Stdout, b"still available")
            .await
            .expect("write");
        assert_eq!(
            accepted
                .reader
                .read()
                .await
                .expect("read")
                .expect("frame")
                .1,
            b"still available"
        );
    }

    #[tokio::test]
    async fn malformed_opens_do_not_consume_a_legitimate_registration() {
        let listener = ChannelListener::bind().expect("bind");
        let transport = listener.transport();
        let (request, receiver) = listener.expect().expect("legitimate expectation");
        let malformed: &[&[u8]] = &[&[255, 0, 0, 0, 0], &[FrameKind::Open as u8, 0, 1, 0, 1], &[
            FrameKind::Open as u8,
            0,
            0,
            0,
            1,
            b'{',
        ]];
        for bytes in malformed {
            let mut socket = UnixStream::connect(&transport.socket_path)
                .await
                .expect("connect");
            socket.write_all(bytes).await.expect("malformed open");
            let mut byte = [0];
            let read = time::timeout(Duration::from_secs(1), socket.read(&mut byte))
                .await
                .expect("malformed peer is closed");
            assert!(matches!(read, Ok(0) | Err(_)), "unexpected reply: {read:?}");
            assert_eq!(listener.diagnostics().pending_opens, 1);
        }
        let _channel = open(&transport, &request).await.expect("legitimate open");
        receiver.accept().await.expect("legitimate accepted");
    }

    #[tokio::test]
    async fn partial_frame_headers_are_transport_errors() {
        let header = [FrameKind::Stdout as u8, 0, 0, 0, 0];
        for length in 0..header.len() {
            let (mut writer, reader) = duplex(16);
            writer
                .write_all(&header[..length])
                .await
                .expect("header prefix");
            writer.shutdown().await.expect("close");
            let mut reader = FrameReader::new(reader, MAX_FRAME_BYTES);
            let result = reader.read().await;
            if length == 0 {
                assert!(matches!(result, Err(Error::Transport(_))));
            } else {
                assert!(matches!(result, Err(Error::Transport(_))), "{result:?}");
            }
        }
    }

    #[tokio::test]
    async fn io_capacity_includes_pending_opens_and_both_channel_halves() {
        let limits = TransportLimits {
            active_io: 1,
            pending_opens: 1,
            ..TransportLimits::default()
        };
        let listener =
            ChannelListener::bind_with_limits(limits, TrustedPeer::Process(process::id()))
                .expect("bind");
        let (request, receiver) = listener.expect().expect("first admitted");
        for _ in 0..10_000 {
            assert!(
                matches!(listener.expect(), Err(Error::Overloaded { limit }) if limit == "active_io")
            );
        }
        let plugin = open(&listener.transport(), &request)
            .await
            .expect("authenticated");
        let Channel { reader, writer } = receiver.accept().await.expect("accept");
        drop(reader);
        assert!(matches!(listener.expect(), Err(Error::Overloaded { .. })));
        drop(writer);
        drop(plugin);
        assert!(
            listener.expect().is_ok(),
            "capacity returns after both halves close"
        );
    }

    #[tokio::test]
    async fn peer_identity_permissions_and_replayed_tokens_are_checked() {
        use std::os::unix::fs::PermissionsExt;
        let listener = ChannelListener::bind().expect("bind");
        assert_eq!(
            fs::metadata(&listener.directory)
                .expect("directory")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let directory = listener.directory.clone();
        let (request, receiver) = listener.expect().expect("admit");
        assert!(!format!("{request:?}").contains(&request.token));
        let channel = open(&listener.transport(), &request).await.expect("open");
        let accepted = receiver.accept().await.expect("accepted");
        assert!(
            open(&listener.transport(), &request).await.is_err(),
            "one-use token"
        );
        drop(channel);
        drop(accepted);
        drop(listener);
        assert!(!directory.exists());
        let listener = ChannelListener::bind_with_limits(
            TransportLimits::default(),
            TrustedPeer::Process(u32::MAX),
        )
        .expect("bind");
        let (request, _receiver) = listener.expect().expect("admit");
        assert!(
            open(&listener.transport(), &request).await.is_err(),
            "unexpected process refused"
        );
    }

    #[tokio::test]
    async fn eof_payload_and_zero_frame_limit_are_rejected() {
        let bytes = [FrameKind::Eof as u8, 0, 0, 0, 1];
        assert!(
            FrameReader::new(&bytes[..], MAX_FRAME_BYTES)
                .read()
                .await
                .is_err()
        );
        let (write, _) = duplex(64);
        assert!(
            FrameWriter::new(write, 0)
                .write(FrameKind::Stdout, b"x")
                .await
                .is_err()
        );
    }

    #[test]
    fn failed_socket_binding_removes_the_private_directory() {
        use std::process::Command;

        use tokio::runtime::Builder;

        const ROLE: &str = "SANDBOX_DRIVER_LONG_SOCKET_TEST";
        const NAME: &str = "channel::tests::failed_socket_binding_removes_the_private_directory";
        if env::var_os(ROLE).is_some() {
            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let _entered = runtime.enter();
            assert!(
                ChannelListener::bind().is_err(),
                "Unix socket path is too long"
            );
            assert_eq!(
                fs::read_dir(env::temp_dir())
                    .expect("temporary directory")
                    .count(),
                0
            );
            return;
        }
        let root = env::temp_dir().join(format!("socket-bind-test-{:016x}", rand::random::<u64>()));
        let long = root.join("x".repeat(100));
        fs::create_dir_all(&long).expect("long parent");
        let output = Command::new(env::current_exe().expect("test executable"))
            .args(["--exact", NAME, "--nocapture"])
            .env(ROLE, "1")
            .env("TMPDIR", &long)
            .output()
            .expect("isolated bind test");
        fs::remove_dir_all(root).expect("remove test parent");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    async fn dropping_the_listener_releases_waiting_operations() {
        let listener = ChannelListener::bind().expect("bind");
        let (_, receiver) = listener.expect().expect("admitted");
        drop(listener);
        assert!(receiver.accept().await.is_err());
    }
}
