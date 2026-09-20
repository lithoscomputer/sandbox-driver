//! Native commands must finish before deleting files they may still publish.

use std::future::Future;
use std::io;
use std::time::Duration;

use sandbox_driver::{Error, Exec, ExecControls, ExecResult, ExecSpec, Result};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_util::sync::CancellationToken;

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
const CANCEL_REPORT_AFTER: Duration = Duration::from_secs(30);

/// Session controls stop preparatory commands when their owner is cancelled.
/// A caller must still check the command's reported exit status.
pub(super) async fn run_command(
    exec: &dyn Exec,
    spec: &ExecSpec,
    cancel: &CancellationToken,
) -> Result<ExecResult> {
    if cancel.is_cancelled() {
        return Err(Error::io(
            "preparing nested resource",
            io::Error::from(io::ErrorKind::Interrupted),
        ));
    }
    Ok(exec
        .run_streaming(spec, ExecControls {
            kill: Some(cancel.clone()),
            retained_output_limit: Some(256 * 1024),
            ..ExecControls::buffered()
        })
        .await?
        .result)
}

/// Own the native operation through cancellation, then clean its resources.
/// The operation passes its token to native Exec controls. Cancellation never
/// drops an accepted command before cleanup: a late login, copy, or create
/// must not republish resources after they were deleted.
pub(super) async fn run_owned<T, F, C, Work, Cleanup>(operation: F, cleanup: C) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(CancellationToken) -> Work + Send + 'static,
    C: FnOnce() -> Cleanup + Send + 'static,
    Work: Future<Output = Result<T>> + Send + 'static,
    Cleanup: Future<Output = Result<()>> + Send + 'static,
{
    let cancel = CancellationToken::new();
    let task = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            let result = operation(cancel).await;
            let cleanup = time::timeout(CLEANUP_TIMEOUT, cleanup())
                .await
                .map_err(|_| {
                    Error::io(
                        "cleaning nested operation",
                        io::Error::other("cleanup timed out"),
                    )
                })
                .and_then(|result| result);
            if let Err(error) = &cleanup {
                tracing::warn!(error = %error, "nested operation cleanup failed");
            }
            match (result, cleanup) {
                (Ok(value), Ok(())) => Ok(value),
                (Ok(_), Err(error)) | (Err(error), _) => Err(error),
            }
        }
    });
    let mut owned = OwnedOperation {
        cancel,
        task: Some(task),
    };
    let result = owned
        .task
        .as_mut()
        .expect("the operation owns its task until joined")
        .await
        .map_err(|error| Error::io("joining nested operation", io::Error::other(error)));
    owned.task.take();
    result?
}

struct OwnedOperation<T: Send + 'static> {
    cancel: CancellationToken,
    task:   Option<JoinHandle<Result<T>>>,
}

impl<T: Send + 'static> Drop for OwnedOperation<T> {
    fn drop(&mut self) {
        let Some(mut task) = self.task.take() else {
            return;
        };
        self.cancel.cancel();
        if let Ok(runtime) = Handle::try_current() {
            runtime.spawn(async move {
                let joined = if let Ok(joined) = time::timeout(CANCEL_REPORT_AFTER, &mut task).await
                {
                    joined
                } else {
                    // Aborting here would recreate the late-publication
                    // race. Keep ownership while the native RPC settles.
                    tracing::warn!("cancelled nested operation is still finishing before cleanup");
                    task.await
                };
                if let Err(error) = joined {
                    tracing::warn!(error = %error, "cancelled nested operation task failed");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use tokio::sync::{Notify, oneshot};

    use super::*;

    #[tokio::test]
    async fn cancellation_joins_late_publication_before_cleanup() {
        let late_write = Arc::new(Notify::new());
        let written = Arc::new(AtomicBool::new(false));
        let (started, start) = oneshot::channel();
        let (cancelled, cancel) = oneshot::channel();
        let (cleaned, mut clean) = oneshot::channel();
        let run = tokio::spawn(run_owned(
            {
                let late_write = Arc::clone(&late_write);
                let written = Arc::clone(&written);
                move |token| async move {
                    let _ = started.send(());
                    token.cancelled().await;
                    let _ = cancelled.send(());
                    late_write.notified().await;
                    written.store(true, Ordering::Release);
                    Ok(())
                }
            },
            move || async move {
                assert!(
                    written.load(Ordering::Acquire),
                    "cleanup follows the accepted write"
                );
                let _ = cleaned.send(());
                Ok(())
            },
        ));
        start.await.expect("operation started");
        run.abort();
        assert!(matches!(run.await, Err(error) if error.is_cancelled()));
        time::timeout(Duration::from_secs(1), cancel)
            .await
            .expect("cancellation requested")
            .expect("operation observed cancellation");
        assert!(matches!(
            clean.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        late_write.notify_one();
        time::timeout(Duration::from_secs(1), clean)
            .await
            .expect("cleanup finished")
            .expect("resource cleaned after late publication");
    }
}
