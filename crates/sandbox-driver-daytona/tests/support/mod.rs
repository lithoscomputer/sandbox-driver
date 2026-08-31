use std::sync::Once;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

static DIAGNOSTICS: Once = Once::new();

pub(crate) fn init_diagnostics() {
    DIAGNOSTICS.call_once(|| {
        let filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_test_writer()
            .try_init()
            .expect("the Daytona test process should own the tracing subscriber");
    });
}
