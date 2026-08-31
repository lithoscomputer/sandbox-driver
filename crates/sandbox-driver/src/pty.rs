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
        // fabro's terminal default: modern TUIs render poorly at the
        // historical 80x24.
        Self {
            rows: 32,
            cols: 120,
        }
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
    async fn write_input(&self, bytes: &[u8]) -> Result<()>;

    /// Reads the next chunk of output; `None` when the session ended.
    async fn read_output(&self) -> Result<Option<Vec<u8>>>;

    /// Resizes the terminal. Capability-gated on `pty.resize`.
    async fn resize(&self, size: PtySize) -> Result<()>;

    /// Closes the session.
    async fn close(&self) -> Result<()>;
}
