//! Interactive terminals over the Daytona toolbox PTY WebSocket.
//!
//! Built on the SDK's `PtyHandle` (the daemon's `create-connect`
//! protocol): input crosses as binary frames, output arrives on a
//! bounded channel, resize and kill delegate to the toolbox REST
//! endpoints.

use std::collections::HashMap;
use std::process;

use async_trait::async_trait;
use daytona_sdk::{PtyCreateOptions, PtyHandle};
use sandbox_driver::{Pty, PtyOptions, PtySession, PtySize, Result};
use tokio::sync::{Mutex, RwLock, mpsc};

use crate::{DaytonaClient, daytona_error};

/// The PTY facet of one Daytona sandbox.
pub struct DaytonaPty {
    client:      DaytonaClient,
    sandbox_id:  String,
    working_dir: String,
}

impl DaytonaPty {
    pub(crate) fn new(client: DaytonaClient, sandbox_id: String, working_dir: String) -> Self {
        Self {
            client,
            sandbox_id,
            working_dir,
        }
    }

    fn resolve_dir(&self, dir: Option<&str>) -> String {
        match dir {
            None => self.working_dir.clone(),
            Some(dir) if dir.starts_with('/') => dir.to_owned(),
            Some(dir) => format!("{}/{}", self.working_dir.trim_end_matches('/'), dir),
        }
    }
}

#[async_trait]
impl Pty for DaytonaPty {
    async fn open(&self, options: &PtyOptions) -> Result<Box<dyn PtySession>> {
        let sandbox = self
            .client
            .get(&self.sandbox_id)
            .await
            .map_err(|error| daytona_error("fetching sandbox", &error))?;
        let process = sandbox
            .process()
            .await
            .map_err(|error| daytona_error("connecting to the toolbox", &error))?;

        // Random nonce plus host pid, like sessions: never collides with
        // a concurrent or crashed driver's terminal.
        let nonce: u64 = rand::random();
        let id = format!("sandbox-driver-{}-{nonce:016x}", process::id());
        let envs: HashMap<String, String> = options
            .env
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let create = PtyCreateOptions {
            cwd:  Some(self.resolve_dir(options.working_dir.as_deref())),
            envs: (!envs.is_empty()).then_some(envs),
            size: Some(daytona_sdk::PtySize {
                rows: options.size.rows,
                cols: options.size.cols,
            }),
        };
        let mut handle = process
            .create_pty(&id, create)
            .await
            .map_err(|error| daytona_error("opening pty", &error))?;
        let output = handle
            .take_output_receiver()
            .expect("a newly created PTY owns its output receiver");
        Ok(Box::new(DaytonaPtySession {
            handle: RwLock::new(handle),
            output: Mutex::new(output),
        }))
    }
}

struct DaytonaPtySession {
    /// Input and resize take a shared guard. Close takes the exclusive
    /// guard. Output has its own lock so a blocked read never prevents
    /// input, resize, or close.
    handle: RwLock<PtyHandle>,
    output: Mutex<mpsc::Receiver<Vec<u8>>>,
}

#[async_trait]
impl PtySession for DaytonaPtySession {
    async fn write_input(&self, bytes: &[u8]) -> Result<()> {
        self.handle
            .read()
            .await
            .send_input(bytes)
            .await
            .map_err(|error| daytona_error("writing pty input", &error))
    }

    async fn read_output(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.output.lock().await.recv().await)
    }

    async fn resize(&self, size: PtySize) -> Result<()> {
        self.handle
            .read()
            .await
            .resize(size.cols, size.rows)
            .await
            .map(|_| ())
            .map_err(|error| daytona_error("resizing pty", &error))
    }

    async fn close(&self) -> Result<()> {
        // Kill the terminal process (fabro's DELETE-on-close semantics),
        // tolerating an already-dead session, then drop the socket.
        let mut handle = self.handle.write().await;
        let _ = handle.kill().await;
        let _ = handle.disconnect().await;
        Ok(())
    }
}
