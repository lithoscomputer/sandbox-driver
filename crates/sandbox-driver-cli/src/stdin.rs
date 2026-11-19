//! Local stdin as a stream the runtime never waits on.
//!
//! `tokio::io::stdin` reads on a runtime blocking thread, and a blocked read
//! there cannot be cancelled: the runtime waits for it when it shuts down.
//! A command that finished while stdin was still open, such as a terminal,
//! would then hold the CLI open until the next keypress or end of input.
//! The reader here owns a plain thread instead, which process exit ends.

use std::io::{self, Read as _};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::thread;

use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::mpsc::{Receiver, channel};

const CHUNK_BYTES: usize = 64 * 1024;

/// This process's stdin. Dropping the reader abandons a read in progress.
pub(crate) fn local_stdin() -> LocalStdin {
    // One chunk in flight: the thread reads ahead no further than that.
    let (sender, chunks) = channel(1);
    thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        let mut buffer = vec![0; CHUNK_BYTES];
        loop {
            let chunk = match stdin.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => Ok(buffer[..read].to_vec()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => Err(error),
            };
            let failed = chunk.is_err();
            if sender.blocking_send(chunk).is_err() || failed {
                break;
            }
        }
    });
    LocalStdin {
        chunks,
        pending: Vec::new(),
        consumed: 0,
    }
}

pub(crate) struct LocalStdin {
    chunks:   Receiver<io::Result<Vec<u8>>>,
    pending:  Vec<u8>,
    consumed: usize,
}

impl AsyncRead for LocalStdin {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.consumed == self.pending.len() {
            match ready!(self.chunks.poll_recv(cx)) {
                Some(Ok(chunk)) => {
                    self.pending = chunk;
                    self.consumed = 0;
                }
                Some(Err(error)) => return Poll::Ready(Err(error)),
                // The thread saw end of input.
                None => return Poll::Ready(Ok(())),
            }
        }
        let rest = &self.pending[self.consumed..];
        let taken = rest.len().min(buf.remaining());
        buf.put_slice(&rest[..taken]);
        self.consumed += taken;
        Poll::Ready(Ok(()))
    }
}
