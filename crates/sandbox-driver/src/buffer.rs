//! Bounded whole-value collection for convenience APIs.
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;

use crate::{Error, Result};

/// Maximum buffered output per stream, or bytes in one buffered file value.
pub const DEFAULT_BUFFER_BYTES: usize = 16 * 1024 * 1024;

/// An output destination that refuses a chunk before exceeding its byte cap.
/// `finish` reports a typed limit error, including after a producer wraps the
/// destination's I/O error. A failed transfer may already have other effects.
#[derive(Debug)]
pub struct BoundedBuffer {
    bytes:    Vec<u8>,
    max:      usize,
    exceeded: bool,
}
impl BoundedBuffer {
    pub fn new(max: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max,
            exceeded: false,
        }
    }
    pub fn finish(self, outcome: Result<()>) -> Result<Vec<u8>> {
        if self.exceeded {
            return Err(Error::LimitExceeded {
                limit:     "buffered_value_bytes".into(),
                max_bytes: self.max,
            });
        }
        outcome?;
        Ok(self.bytes)
    }
}
impl AsyncWrite for BoundedBuffer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.len() > self.max.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Poll::Ready(Err(io::Error::other("buffered value limit exceeded")));
        }
        self.bytes.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
