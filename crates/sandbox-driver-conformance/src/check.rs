//! Shared check plumbing: the outcome type, the pass and fail helpers,
//! sandbox cleanup, and the small fixtures several check modules use.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use sandbox_driver::{OutputStream, Sandbox};

use crate::Conformance;

pub(crate) type SeenChunks = Arc<Mutex<Vec<(OutputStream, Vec<u8>)>>>;

pub(crate) type CheckFn =
    fn(&Conformance) -> Pin<Box<dyn Future<Output = Result<Option<String>, String>> + Send + '_>>;

/// `Ok(None)` = passed, `Ok(Some(reason))` = skipped, `Err` = failed.
pub(crate) type CheckOutcome = Result<Option<String>, String>;

pub(crate) fn fail(message: impl Into<String>) -> CheckOutcome {
    Err(message.into())
}

pub(crate) const PASS: CheckOutcome = Ok(None);

pub(crate) async fn cleanup(sandbox: &Arc<dyn Sandbox>) {
    let _ = sandbox.delete().await;
}

pub(crate) const SIGKILL: i32 = 9;
pub(crate) const SIGTERM: i32 = 15;

/// `1\n2\n…count\n`, what `seq 1 count` prints.
pub(crate) fn numbered_lines(count: usize) -> Vec<u8> {
    let mut lines = String::new();
    for n in 1..=count {
        lines.push_str(&n.to_string());
        lines.push('\n');
    }
    lines.into_bytes()
}
