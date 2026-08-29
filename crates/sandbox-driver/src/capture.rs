use std::collections::VecDeque;

use crate::exec::CaptureStats;

/// Bounded output retention: a stable head plus a rolling tail.
///
/// Fabro's capture policy, moved here: with a cap of `n` bytes, the first
/// `n / 2` bytes are kept verbatim (the head) and the rest of the budget
/// holds the newest bytes (the tail). Everything is still *drained* — a
/// process is never blocked by the cap — and dropped bytes are counted in
/// [`CaptureStats::omitted_bytes`]. The gap, when there is one, sits
/// between head and tail.
#[derive(Debug)]
pub struct OutputCaptureBuffer {
    cap:      Option<usize>,
    head_cap: usize,
    head:     Vec<u8>,
    tail:     VecDeque<u8>,
    observed: usize,
    omitted:  usize,
}

impl OutputCaptureBuffer {
    /// `cap = None` retains everything.
    pub fn new(cap: Option<usize>) -> Self {
        Self {
            cap,
            head_cap: cap.map_or(0, |c| c / 2),
            head: Vec::new(),
            tail: VecDeque::new(),
            observed: 0,
            omitted: 0,
        }
    }

    /// Consumes a chunk of output.
    pub fn push(&mut self, chunk: &[u8]) {
        self.observed += chunk.len();
        let Some(cap) = self.cap else {
            self.head.extend_from_slice(chunk);
            return;
        };
        let mut rest = chunk;
        if self.head.len() < self.head_cap {
            let take = (self.head_cap - self.head.len()).min(rest.len());
            self.head.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
        }
        let tail_cap = cap - self.head_cap;
        for &byte in rest {
            if tail_cap == 0 {
                self.omitted += 1;
                continue;
            }
            if self.tail.len() == tail_cap {
                self.tail.pop_front();
                self.omitted += 1;
            }
            self.tail.push_back(byte);
        }
    }

    /// The retained bytes (head then tail) and the accounting.
    pub fn into_parts(self) -> (Vec<u8>, CaptureStats) {
        let mut bytes = self.head;
        bytes.extend(self.tail);
        let stats = CaptureStats {
            observed_bytes: self.observed,
            retained_bytes: bytes.len(),
            omitted_bytes:  self.omitted,
        };
        (bytes, stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_everything_without_a_cap() {
        let mut buffer = OutputCaptureBuffer::new(None);
        buffer.push(b"hello ");
        buffer.push(b"world");
        let (bytes, stats) = buffer.into_parts();
        assert_eq!(bytes, b"hello world");
        assert_eq!(stats.observed_bytes, 11);
        assert_eq!(stats.omitted_bytes, 0);
    }

    #[test]
    fn keeps_stable_head_and_rolling_tail() {
        let mut buffer = OutputCaptureBuffer::new(Some(8));
        buffer.push(b"0123456789ABCDEF");
        let (bytes, stats) = buffer.into_parts();
        // Head: first 4 bytes; tail: newest 4 bytes.
        assert_eq!(bytes, b"0123CDEF");
        assert_eq!(stats.observed_bytes, 16);
        assert_eq!(stats.retained_bytes, 8);
        assert_eq!(stats.omitted_bytes, 8);
    }

    #[test]
    fn under_cap_output_is_untouched() {
        let mut buffer = OutputCaptureBuffer::new(Some(16));
        buffer.push(b"short");
        let (bytes, stats) = buffer.into_parts();
        assert_eq!(bytes, b"short");
        assert_eq!(stats.omitted_bytes, 0);
    }
}
