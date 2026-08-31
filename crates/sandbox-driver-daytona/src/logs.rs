//! Provider-side entrypoint logs from the Daytona toolbox.

use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use daytona_sdk::DaytonaError;
use sandbox_driver::{Capability, Error, LogSink, LogSource, Logs, Result};

use crate::{DaytonaClient, daytona_error};

/// Provider logs for one Daytona sandbox.
pub struct DaytonaLogs {
    client:     DaytonaClient,
    sandbox_id: String,
}

impl DaytonaLogs {
    pub(crate) fn new(client: DaytonaClient, sandbox_id: String) -> Self {
        Self { client, sandbox_id }
    }
}

#[async_trait]
impl Logs for DaytonaLogs {
    async fn follow(&self, source: LogSource, sink: LogSink) -> Result<()> {
        if source != LogSource::Entrypoint {
            return Err(Error::unsupported(Capability::Logs));
        }
        let sandbox = self
            .client
            .get(&self.sandbox_id)
            .await
            .map_err(|error| daytona_error("fetching sandbox", &error))?;
        let process = sandbox
            .process()
            .await
            .map_err(|error| daytona_error("connecting to the toolbox", &error))?;

        // The SDK callback error type cannot carry sandbox-driver's
        // typed sink error. Save it and use a sentinel SDK error to stop
        // the WebSocket loop, then return the original error unchanged.
        let sink_error = Arc::new(Mutex::new(None));
        let stdout_sink = Arc::clone(&sink);
        let stdout_error = Arc::clone(&sink_error);
        let stderr_error = Arc::clone(&sink_error);
        let outcome = process
            .get_entrypoint_logs_stream(
                move |chunk| {
                    let sink = Arc::clone(&stdout_sink);
                    let sink_error = Arc::clone(&stdout_error);
                    async move { forward(&sink, &sink_error, chunk).await }
                },
                move |chunk| {
                    let sink = Arc::clone(&sink);
                    let sink_error = Arc::clone(&stderr_error);
                    async move { forward(&sink, &sink_error, chunk).await }
                },
            )
            .await;
        if let Some(error) = sink_error.lock().expect("sink error lock").take() {
            return Err(error);
        }
        outcome.map_err(|error| daytona_error("following entrypoint logs", &error))
    }
}

async fn forward(
    sink: &LogSink,
    sink_error: &Mutex<Option<Error>>,
    chunk: String,
) -> StdResult<(), DaytonaError> {
    if let Err(error) = sink(chunk.into_bytes()).await {
        *sink_error.lock().expect("sink error lock") = Some(error);
        return Err(DaytonaError::general("sandbox-driver log sink failed"));
    }
    Ok(())
}
