use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Pseudo-terminal support inside a sandbox.
#[async_trait]
pub trait Pty: Send + Sync {
    /// Opens an interactive terminal session.
    async fn open(&self, options: &PtyOptions) -> Result<Box<dyn PtySession>>;
}

/// Terminal dimensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PtySize {
    pub rows: u16,
    pub cols: u16,
}

impl Default for PtySize {
    fn default() -> Self {
        Self { rows: 24, cols: 80 }
    }
}

/// Options for [`Pty::open`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PtyOptions {
    pub size:        PtySize,
    pub working_dir: Option<String>,
    pub env:         BTreeMap<String, String>,
}

/// A live terminal session (fabro's `TerminalSession`, made async).
#[async_trait]
pub trait PtySession: Send + Sync {
    /// Writes input bytes to the terminal.
    async fn write_input(&mut self, bytes: &[u8]) -> Result<()>;

    /// Reads the next chunk of output; `None` when the session ended.
    async fn read_output(&mut self) -> Result<Option<Vec<u8>>>;

    /// Resizes the terminal. Capability-gated on `pty.resize`.
    async fn resize(&mut self, size: PtySize) -> Result<()>;

    /// Closes the session.
    async fn close(&mut self) -> Result<()>;
}
