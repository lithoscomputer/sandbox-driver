//! JSON-RPC plugin protocol for sandbox-driver providers.
//!
//! The symmetry at the heart of the design: [`serve`] exposes any
//! in-process [`sandbox_driver::SandboxProvider`] over newline-delimited
//! JSON-RPC 2.0, and [`PluginProvider`] adapts a served plugin back into
//! the same trait. A provider implemented once therefore runs in-process
//! or out-of-process unchanged, and one conformance suite covers both.
//!
//! Protocol v1 (see `methods::PROTOCOL_VERSION`): lifecycle, exec
//! (buffered and streamed via `exec/output` notifications with
//! client-generated exec ids), filesystem, list/attach, snapshot and
//! volume services, preview-URL and SSH access facets, plugin→host
//! `host/event` notifications, and plugin binaries spawned over stdio
//! ([`serve_stdio`], [`PluginProvider::spawn`]). Deferred to a later
//! version: the stdio side-channel transport (long-lived bidirectional
//! processes), PTY, logs, native search/git passthrough, the reserved
//! access facets, and `host/credentials` — the client masks all of
//! these out of the capabilities it reports.
//!
//! Transport trust — checksums, environment scrubbing, deny-by-default
//! discovery — is host policy and lives with the embedding application,
//! not here.

mod client;
pub mod discovery;
mod server;
mod wire;

pub mod methods;

pub use client::PluginProvider;
pub use discovery::{PluginConfig, PluginLaunch, file_sha256, launch_plugin};
pub use server::{serve, serve_stdio};
pub use wire::{Message, WireError, WireErrorData};
