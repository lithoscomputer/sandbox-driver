//! A byte stream fed chunk by chunk from a data channel. Unlike a pipe, the
//! end of a transfer is explicit: a stream whose producer disappears without
//! confirming completion fails to read rather than looking like a short file.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::task::AbortOnDropHandle;

pub(crate) enum Chunk {
    Data(Vec<u8>),
    /// The whole transfer arrived.
    Done,
    Failed(String),
}

/// Chunks buffered between the channel and the reader; the socket provides
/// the rest of the backpressure.
const CAPACITY: usize = 4;

pub(crate) fn chunk_stream() -> (mpsc::Sender<Chunk>, ChunkReader) {
    let (sender, receiver) = mpsc::channel(CAPACITY);
    (sender, ChunkReader {
        receiver,
        buffer: Vec::new(),
        offset: 0,
        finished: false,
        producer: None,
    })
}

pub(crate) struct ChunkReader {
    receiver: mpsc::Receiver<Chunk>,
    buffer:   Vec<u8>,
    offset:   usize,
    finished: bool,
    /// Dropping the reader abandons the transfer that feeds it.
    producer: Option<AbortOnDropHandle<()>>,
}

impl ChunkReader {
    pub(crate) fn owning(mut self, producer: AbortOnDropHandle<()>) -> Self {
        self.producer = Some(producer);
        self
    }
}

impl AsyncRead for ChunkReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.offset < self.buffer.len() {
                let take = out.remaining().min(self.buffer.len() - self.offset);
                let start = self.offset;
                out.put_slice(&self.buffer[start..start + take]);
                self.offset += take;
                return Poll::Ready(Ok(()));
            }
            if self.finished {
                return Poll::Ready(Ok(()));
            }
            match self.receiver.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Chunk::Data(bytes))) => {
                    self.buffer = bytes;
                    self.offset = 0;
                }
                Poll::Ready(Some(Chunk::Done)) => self.finished = true,
                Poll::Ready(Some(Chunk::Failed(message))) => {
                    return Poll::Ready(Err(io::Error::other(message)));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "transfer ended before it was complete",
                    )));
                }
            }
        }
    }
}
