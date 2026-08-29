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
//! client-generated exec ids), filesystem, list/attach, and plugin→host
//! `host/event` notifications. Deferred to a later version: the stdio
//! side-channel transport, snapshot/volume services over the wire, PTY,
//! logs, access facets, and `host/credentials`.
//!
//! Transport trust — checksums, environment scrubbing, deny-by-default
//! discovery — is host policy and lives with the embedding application,
//! not here.

mod client;
mod server;
mod wire;

pub mod methods;

pub use client::PluginProvider;
pub use server::{serve, serve_stdio};
pub use wire::{Message, WireError, WireErrorData};
