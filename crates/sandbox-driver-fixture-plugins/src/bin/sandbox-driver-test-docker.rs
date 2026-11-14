//! The Docker runtime as a third-party plugin of kind `test-docker`.

use std::sync::Arc;

use sandbox_driver_docker::DockerFactory;
use sandbox_driver_fixture_plugins::serve_renamed;

#[tokio::main]
async fn main() -> sandbox_driver::Result<()> {
    serve_renamed(
        "test-docker",
        DockerFactory::schemas(),
        Arc::new(DockerFactory),
    )
    .await
}
