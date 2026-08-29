use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Provider-side logs for a sandbox. Follow-style streams only in v1;
/// historical querying is a later capability.
#[async_trait]
pub trait Logs: Send + Sync {
    /// Streams a log source through `sink` until it ends or is cancelled
    /// by dropping the future.
    async fn follow(&self, source: LogSource, sink: LogSink) -> Result<()>;
}

/// Which provider-side log to follow.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LogSource {
    /// Provisioning / build output (image pull, snapshot build).
    Provision,
    /// The sandbox's entrypoint process output.
    Entrypoint,
}

/// Async sink for log chunks.
pub type LogSink =
    Arc<dyn Fn(Vec<u8>) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;
