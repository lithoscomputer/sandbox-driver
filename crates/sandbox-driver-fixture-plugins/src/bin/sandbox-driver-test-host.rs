//! The Host runtime as a third-party plugin of kind `test-host`.

use std::sync::Arc;

use sandbox_driver_fixture_plugins::serve_renamed;
use sandbox_driver_host::{HostFactory, schemas};

#[tokio::main]
async fn main() -> sandbox_driver::Result<()> {
    serve_renamed("test-host", schemas(), Arc::new(HostFactory)).await
}
