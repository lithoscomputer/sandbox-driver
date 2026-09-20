//! Shared check plumbing: the outcome type, the pass and fail helpers,
//! sandbox cleanup, and the small fixtures several check modules use.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use sandbox_driver::{Capabilities, Capability, OutputStream};

use crate::Conformance;

pub(crate) type SeenChunks = Arc<Mutex<Vec<(OutputStream, Vec<u8>)>>>;

pub(crate) type CheckFn =
    fn(&Conformance) -> Pin<Box<dyn Future<Output = CheckOutcome> + Send + '_>>;

/// Why a check did not pass. A `String` converts into `Failed`, so the
/// `map_err(|error| format!(..))?` lines in the checks keep working, and
/// a skip is an error too, so it can be raised with `?` from any depth.
#[derive(Debug)]
pub(crate) enum Verdict {
    Skipped(String),
    Failed(String),
}

impl From<String> for Verdict {
    fn from(reason: String) -> Self {
        Self::Failed(reason)
    }
}

/// `Ok(())` = passed; the error says whether the check skipped or failed.
pub(crate) type CheckOutcome = Result<(), Verdict>;

pub(crate) fn fail<T>(message: impl Into<String>) -> Result<T, Verdict> {
    Err(Verdict::Failed(message.into()))
}

pub(crate) fn skip<T>(reason: impl Into<String>) -> Result<T, Verdict> {
    Err(Verdict::Skipped(reason.into()))
}

pub(crate) const PASS: CheckOutcome = Ok(());

/// Skips unless `caps` declares `capability`. The provider-level form is
/// [`Conformance::require`]; this one judges a sandbox's own set, which
/// a provider may narrow by sandbox class.
pub(crate) fn require_on(caps: &Capabilities, capability: Capability) -> Result<(), Verdict> {
    if caps.supports(capability) {
        Ok(())
    } else {
        skip(format!("capability {capability} not declared"))
    }
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
