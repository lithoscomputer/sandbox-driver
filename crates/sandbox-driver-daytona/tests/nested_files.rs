//! The archive command must preserve binary data with a minimal job image.

use std::path::Path;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

#[tokio::test]
async fn docker_cli_files_preserve_binary_ranges_and_ownership() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/nested_files.py");
    let result = timeout(
        Duration::from_secs(120),
        Command::new("python3")
            .arg("-B")
            .arg(script)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("bounded CLI file test")
    .expect("Python is available");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
