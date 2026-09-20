//! Process ownership for host commands, one backend per platform. Both
//! backends present the same `ProcessGroups` and `HostChild` API and the same
//! `exec_result` constructor, so the lifecycle and exec code above them holds
//! no platform conditionals.
//!
//! - [`sentinel`] (Linux and macOS): a sentinel pins each process group until
//!   stop, records survive a provider crash, and stop fences all work.
//! - [`direct`] (other platforms): each command runs directly and dies with its
//!   handle. Nothing is recorded and stop fences nothing.
//!
//! `HostChild` exposes `term`, `kill`, `terminate(grace)`, and `wait`;
//! `ProcessGroups` exposes `new`, `start`, `spawn`, and `stop`.

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod direct;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod observation;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod sentinel;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) use direct::{HostChild, ProcessGroups, exec_result};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use sentinel::{HostChild, ProcessGroups, exec_result};
