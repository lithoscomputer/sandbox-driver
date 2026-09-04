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

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{env, fmt, fs, io, process};

use sandbox_driver::{Error, Result, TransportError};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time;

/// The largest payload one frame may carry. Negotiated at `initialize`;
/// this implementation offers and accepts exactly this value.
pub const MAX_FRAME_BYTES: u32 = 64 * 1024;

/// How long the host waits for a plugin's `Open` frame after a connection
/// is accepted, and how long a plugin has to connect once the host has
/// answered the operation it belongs to.
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

const HEADER_LEN: usize = 5;

/// What a frame carries. Any other byte closes the connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    /// The plugin's first frame: a JSON [`OpenFrame`].
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

/// The `Open` frame's payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct OpenFrame {
    pub channel_id: u64,
    pub token:      String,
}

/// What a request carries to name its channel: the id the host will look
/// the connection up by, and the one-use token that proves the plugin
/// read the request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelRequest {
    pub channel_id: u64,
    pub token:      String,
}

/// The data transport the host announces at `initialize`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataTransport {
    pub socket_path:     PathBuf,
    /// The largest frame payload either side may send.
    pub max_frame_bytes: u32,
}

fn transport(context: &'static str, error: io::Error) -> Error {
    Error::Transport(TransportError::with_source(context, error))
}

/// Writes frames to one half of a channel connection.
pub struct FrameWriter<W> {
    writer:    W,
    max_bytes: usize,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    pub fn new(writer: W, max_frame_bytes: u32) -> Self {
        Self {
            writer,
            max_bytes: max_frame_bytes as usize,
        }
    }

    /// Writes `payload` as one or more frames of `kind`, split at the
    /// negotiated limit so a large chunk never becomes an oversized frame.
    pub async fn write(&mut self, kind: FrameKind, payload: &[u8]) -> Result<()> {
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
        self.writer
            .write_all(&header)
            .await
            .map_err(|error| transport("writing data frame header", error))?;
        self.writer
            .write_all(payload)
            .await
            .map_err(|error| transport("writing data frame", error))?;
        Ok(())
    }

    /// Sends this side's `Eof`.
    pub async fn finish(&mut self) -> Result<()> {
        self.write_one(FrameKind::Eof, &[]).await?;
        self.writer
            .flush()
            .await
            .map_err(|error| transport("flushing data channel", error))
    }
}

/// Reads frames from one half of a channel connection.
pub struct FrameReader<R> {
    reader:    R,
    max_bytes: usize,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(reader: R, max_frame_bytes: u32) -> Self {
        Self {
            reader,
            max_bytes: max_frame_bytes as usize,
        }
    }

    /// The next frame, or `None` when the connection closed cleanly.
    pub async fn read(&mut self) -> Result<Option<(FrameKind, Vec<u8>)>> {
        let mut header = [0u8; HEADER_LEN];
        match self.reader.read_exact(&mut header).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(transport("reading data frame header", error)),
        }
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
        let mut payload = vec![0u8; length];
        self.reader
            .read_exact(&mut payload)
            .await
            .map_err(|error| transport("reading data frame", error))?;
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
    fn from_stream(stream: UnixStream, max_frame_bytes: u32) -> Self {
        let (read, write) = stream.into_split();
        Self {
            reader: FrameReader::new(read, max_frame_bytes),
            writer: FrameWriter::new(write, max_frame_bytes),
        }
    }
}

struct Pending {
    token:  String,
    sender: oneshot::Sender<Channel>,
}

/// The host's listener: a Unix socket in a private directory, an accept
/// task that authenticates each connection, and the registry of channels
/// operations are waiting on.
pub struct ChannelListener {
    directory:    PathBuf,
    socket_path:  PathBuf,
    max_frame:    u32,
    next_channel: AtomicU64,
    pending:      Arc<Mutex<HashMap<u64, Pending>>>,
    accept_task:  JoinHandle<()>,
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
        let directory = env::temp_dir().join(format!(
            "sandbox-driver-{}-{:016x}",
            process::id(),
            random_u64()
        ));
        fs::create_dir_all(&directory)
            .map_err(|error| transport("creating data transport directory", error))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(|error| transport("securing data transport directory", error))?;
        }
        let socket_path = directory.join("data.sock");
        let listener = UnixListener::bind(&socket_path)
            .map_err(|error| transport("binding data transport socket", error))?;
        let pending: Arc<Mutex<HashMap<u64, Pending>>> = Arc::new(Mutex::new(HashMap::new()));
        let accept_pending = Arc::clone(&pending);
        let max_frame = MAX_FRAME_BYTES;
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let pending = Arc::clone(&accept_pending);
                tokio::spawn(async move {
                    if let Err(error) = admit(stream, &pending, max_frame).await {
                        tracing::warn!(error = %error, "data channel connection refused");
                    }
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
        })
    }

    pub fn transport(&self) -> DataTransport {
        DataTransport {
            socket_path:     self.socket_path.clone(),
            max_frame_bytes: self.max_frame,
        }
    }

    pub fn max_frame_bytes(&self) -> u32 {
        self.max_frame
    }

    /// Registers a channel an operation is about to request and returns
    /// the request to send plus the receiver the connection arrives on.
    pub fn expect(&self) -> (ChannelRequest, ChannelReceiver) {
        let channel_id = self.next_channel.fetch_add(1, Ordering::Relaxed);
        let token = random_token();
        let (sender, receiver) = oneshot::channel();
        self.pending
            .lock()
            .expect("pending channels lock")
            .insert(channel_id, Pending {
                token: token.clone(),
                sender,
            });
        (ChannelRequest { channel_id, token }, ChannelReceiver {
            channel_id,
            receiver,
            pending: Arc::clone(&self.pending),
        })
    }
}

impl Drop for ChannelListener {
    fn drop(&mut self) {
        self.accept_task.abort();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// The host side of one expected channel: resolves when the plugin
/// connects, and forgets the expectation when dropped.
pub struct ChannelReceiver {
    channel_id: u64,
    receiver:   oneshot::Receiver<Channel>,
    pending:    Arc<Mutex<HashMap<u64, Pending>>>,
}

impl ChannelReceiver {
    /// Waits for the plugin's connection.
    pub async fn accept(mut self) -> Result<Channel> {
        let outcome = (&mut self.receiver).await;
        outcome.map_err(|_| {
            Error::Transport(TransportError::new(
                "the data channel was dropped before the plugin connected",
            ))
        })
    }

    /// Waits at most [`OPEN_TIMEOUT`] for the plugin's connection, for a
    /// caller that already holds the operation's response.
    pub async fn accept_soon(self) -> Result<Channel> {
        match time::timeout(OPEN_TIMEOUT, self.accept()).await {
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
) -> Result<()> {
    let mut channel = Channel::from_stream(stream, max_frame);
    let opened = time::timeout(OPEN_TIMEOUT, channel.reader.read())
        .await
        .map_err(|_| Error::Transport(TransportError::new("data channel open timed out")))??;
    let Some((FrameKind::Open, payload)) = opened else {
        return Err(Error::invalid_spec(
            "frame",
            "the first frame on a data channel must be open",
        ));
    };
    let open: OpenFrame = serde_json::from_slice(&payload)
        .map_err(|error| Error::invalid_spec("frame", format!("bad open frame: {error}")))?;
    let expected = pending
        .lock()
        .expect("pending channels lock")
        .remove(&open.channel_id);
    let Some(expected) = expected else {
        return Err(Error::invalid_spec(
            "channel_id",
            format!("no operation is waiting on channel {}", open.channel_id),
        ));
    };
    if expected.token != open.token {
        return Err(Error::invalid_spec("token", "data channel token mismatch"));
    }
    if expected.sender.send(channel).is_err() {
        return Err(Error::Transport(TransportError::new(
            "the operation stopped waiting for its data channel",
        )));
    }
    Ok(())
}

/// The plugin side: opens the connection for one request's channel.
pub async fn open(transport: &DataTransport, request: &ChannelRequest) -> Result<Channel> {
    let stream = UnixStream::connect(&transport.socket_path)
        .await
        .map_err(|error| transport_error("connecting to the host data socket", error))?;
    let mut channel = Channel::from_stream(stream, transport.max_frame_bytes);
    let payload = serde_json::to_vec(&OpenFrame {
        channel_id: request.channel_id,
        token:      request.token.clone(),
    })
    .expect("open frame contains only serializable values");
    channel.writer.write(FrameKind::Open, &payload).await?;
    Ok(channel)
}

fn transport_error(context: &'static str, error: io::Error) -> Error {
    transport(context, error)
}

fn random_u64() -> u64 {
    rand::random::<u64>()
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
        let (request, receiver) = listener.expect();
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
        let (request, receiver) = listener.expect();
        let forged = ChannelRequest {
            channel_id: request.channel_id,
            token:      "not-the-token".to_owned(),
        };
        let mut channel = open(&transport, &forged).await.expect("connect");
        // The host closes the connection without binding it.
        let closed = channel.reader.read().await;
        assert!(matches!(closed, Ok(None) | Err(_)));
        // The waiting operation is still waiting: its expectation is gone
        // (consumed by the refused attempt), so a later accept fails.
        drop(listener);
        assert!(receiver.accept().await.is_err());
    }
}
