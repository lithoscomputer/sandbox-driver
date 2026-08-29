//! The host provider served as a sandbox-driver plugin.
//!
//! A reference plugin binary and a working one: speaks the JSON-RPC
//! plugin protocol on stdin/stdout and drives directory-backed sandboxes
//! on the machine it runs on. Stdout belongs to the protocol; logs go to
//! stderr.

use std::sync::Arc;

use sandbox_driver_host::HostProvider;
use sandbox_driver_protocol::serve_stdio;

#[tokio::main]
async fn main() -> sandbox_driver::Result<()> {
    serve_stdio(Arc::new(HostProvider::new())).await
}
