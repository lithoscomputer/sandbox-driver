//! Bounded control encoding, line reading, and byte-accounted priority
//! delivery.
use std::io::{self, Write};
use std::mem;
use std::sync::Arc;
use std::time::Duration;

use sandbox_driver::{Error, Result, TransportError};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time;

use crate::wire::Message;
use crate::{TransportLimits, methods};

/// Cancellation-safe: the caller retains the partial line between polls.
pub(crate) async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    partial: &mut Vec<u8>,
    max: usize,
) -> io::Result<Option<Vec<u8>>> {
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if partial.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete control message",
                ))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if take > max.saturating_sub(partial.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "control message limit exceeded",
            ));
        }
        partial.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            return Ok(Some(mem::take(partial)));
        }
    }
}

struct MessageSize {
    bytes: usize,
    max:   usize,
}
impl Write for MessageSize {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.max.saturating_sub(self.bytes) {
            return Err(io::Error::other("control message limit exceeded"));
        }
        self.bytes += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn message_size(message: &Message, max: usize) -> Result<usize> {
    let mut size = MessageSize { bytes: 0, max };
    serde_json::to_writer(&mut size, message).map_err(|_| Error::LimitExceeded {
        limit:     "control_message_bytes".into(),
        max_bytes: max,
    })?;
    size.write_all(b"\n").map_err(|_| Error::LimitExceeded {
        limit:     "control_message_bytes".into(),
        max_bytes: max,
    })?;
    Ok(size.bytes)
}

fn encode(message: &Message, count: usize, permit: OwnedSemaphorePermit) -> Encoded {
    let mut bytes = Vec::with_capacity(count);
    serde_json::to_writer(&mut bytes, message)
        .expect("message was validated by the counting writer");
    bytes.push(b'\n');
    Encoded {
        bytes,
        _permit: permit,
    }
}

pub(crate) struct Encoded {
    pub bytes: Vec<u8>,
    _permit:   OwnedSemaphorePermit,
}

#[derive(Clone)]
pub(crate) struct ControlSender {
    normal:         mpsc::Sender<Encoded>,
    events:         mpsc::Sender<Encoded>,
    event_bytes:    Arc<Semaphore>,
    priority:       mpsc::Sender<Encoded>,
    normal_bytes:   Arc<Semaphore>,
    priority_bytes: Arc<Semaphore>,
    max_message:    usize,
}

pub(crate) struct ControlReceiver {
    normal:   mpsc::Receiver<Encoded>,
    events:   mpsc::Receiver<Encoded>,
    priority: mpsc::Receiver<Encoded>,
}

pub(crate) fn queue(limits: &TransportLimits) -> (ControlSender, ControlReceiver) {
    let (events, event_rx) = mpsc::channel(limits.event_queue_messages);
    let (normal, normal_rx) = mpsc::channel(limits.provider_requests);
    let (priority, priority_rx) = mpsc::channel(limits.reserved_requests);
    (
        ControlSender {
            normal,
            events,
            event_bytes: Arc::new(Semaphore::new(limits.event_queue_bytes)),
            priority,
            normal_bytes: Arc::new(Semaphore::new(limits.queued_control_bytes)),
            priority_bytes: Arc::new(Semaphore::new(limits.reserved_control_bytes)),
            max_message: limits.control_message_bytes,
        },
        ControlReceiver {
            normal:   normal_rx,
            events:   event_rx,
            priority: priority_rx,
        },
    )
}

impl ControlSender {
    /// Bounded reply delivery. Request admission already limits the number of
    /// callers that can wait here; no provider work waits to start in this
    /// path.
    pub(crate) async fn deliver(
        &self,
        message: &Message,
        priority: bool,
        timeout: Duration,
    ) -> Result<()> {
        let bytes = message_size(message, self.max_message)?;
        let (sender, budget) = if priority {
            (&self.priority, &self.priority_bytes)
        } else {
            (&self.normal, &self.normal_bytes)
        };
        let count = u32::try_from(bytes).expect("bounded message");
        time::timeout(timeout, async {
            let permit = Arc::clone(budget)
                .acquire_many_owned(count)
                .await
                .map_err(|_| Error::Transport(TransportError::new("control byte budget closed")))?;
            sender
                .send(encode(message, bytes, permit))
                .await
                .map_err(|_| Error::Transport(TransportError::new("control writer closed")))
        })
        .await
        .map_err(|_| Error::Transport(TransportError::new("control response delivery timed out")))?
    }

    /// Only callers that have not sent a request can expose this overload
    /// as an admission rejection. A failed reply delivery fails the transport.
    pub(crate) fn send(&self, message: &Message, priority: bool) -> Result<()> {
        let bytes = message_size(message, self.max_message)?;
        let (sender, budget) = if message.method.as_deref() == Some(methods::HOST_EVENT) {
            (&self.events, &self.event_bytes)
        } else if priority {
            (&self.priority, &self.priority_bytes)
        } else {
            (&self.normal, &self.normal_bytes)
        };
        let count = u32::try_from(bytes).expect("validated message budget");
        let permit = Arc::clone(budget)
            .try_acquire_many_owned(count)
            .map_err(|_| Error::Overloaded {
                limit: "queued_control_bytes".into(),
            })?;
        sender
            .try_send(encode(message, bytes, permit))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => Error::Overloaded {
                    limit: "queued_control_messages".into(),
                },
                mpsc::error::TrySendError::Closed(_) => {
                    Error::Transport(TransportError::new("control writer closed"))
                }
            })
    }
}

impl ControlReceiver {
    pub(crate) async fn recv(&mut self) -> Option<Encoded> {
        tokio::select! {
            biased;
            Some(message) = self.priority.recv() => Some(message),
            Some(message) = self.normal.recv() => Some(message),
            Some(message) = self.events.recv() => Some(message),
            else => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt, BufReader, duplex};

    use super::*;

    #[tokio::test]
    async fn refuses_unterminated_oversize_message_and_partial_eof() {
        let (mut write, read) = duplex(64);
        write.write_all(b"123456789").await.expect("write");
        let mut reader = BufReader::new(read);
        let mut partial = Vec::new();
        assert!(read_line(&mut reader, &mut partial, 8).await.is_err());
        assert!(partial.len() <= 8);
        let mut reader = BufReader::new(&b"{}"[..]);
        assert_eq!(
            read_line(&mut reader, &mut Vec::new(), 8)
                .await
                .expect_err("partial")
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn priority_capacity_survives_full_normal_queue() {
        let limits = TransportLimits {
            provider_requests: 1,
            ..TransportLimits::default()
        };
        let (send, mut receive) = queue(&limits);
        send.send(&Message::response(1, serde_json::Value::Null), false)
            .expect("normal");
        assert!(matches!(
            send.send(&Message::response(2, serde_json::Value::Null), false),
            Err(Error::Overloaded { .. })
        ));
        send.send(&Message::response(3, serde_json::Value::Null), true)
            .expect("reserved");
        let first = receive.recv().await.expect("priority response");
        assert_eq!(
            serde_json::from_slice::<Message>(&first.bytes)
                .expect("message")
                .id,
            Some(3)
        );
    }
}
