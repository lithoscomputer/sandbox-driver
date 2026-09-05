//! Container file bytes cross Daytona's native file API, never its text logs.
//! Docker's CLI archive commands preserve the job image's POSIX contract.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::{
    DerivedFs, DirEntry, Error, Exec, ExecFailure, ExecSpec, FileMetadata, Filesystem,
    ResourceKind, Result,
};
use serde::Deserialize;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::runtime::Handle;
use tokio::sync::OnceCell;
use tokio::time::timeout;

use crate::nested_docker::{CONTAINER_NAME, DockerCli};
use crate::shell_quote;

const COMMAND: &str = include_str!("nested_files.py");
const CHUNK: usize = 1024 * 1024;
const FILE_TIMEOUT: Duration = Duration::from_secs(120);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default, Deserialize)]
#[serde(default)]
struct FileResult {
    missing: bool,
    size:    Option<u64>,
}

pub(super) struct NestedFs {
    cli:     Arc<DockerCli>,
    exec:    Arc<dyn Exec>,
    derived: DerivedFs,
    owner:   OnceCell<(String, String)>,
}

impl NestedFs {
    pub(super) fn new(cli: Arc<DockerCli>, exec: Arc<dyn Exec>) -> Self {
        Self {
            cli,
            derived: DerivedFs::new(Arc::clone(&exec)),
            exec,
            owner: OnceCell::new(),
        }
    }

    async fn command(&self, args: Vec<String>) -> Result<FileResult> {
        let mut spec = ExecSpec::new("python3")
            .args(["-c", COMMAND])
            .timeout(FILE_TIMEOUT);
        spec.args.extend(args);
        let result = self.cli.run_spec(&spec).await?;
        serde_json::from_slice(&result.stdout).map_err(|error| {
            Error::io(
                "decoding nested file result",
                io::Error::new(io::ErrorKind::InvalidData, error),
            )
        })
    }

    async fn owner(&self) -> Result<&(String, String)> {
        self.owner
            .get_or_try_init(|| async {
                let id = |flag| async move {
                    let result = self
                        .exec
                        .run(&ExecSpec::new("id").arg(flag).timeout(FILE_TIMEOUT))
                        .await?;
                    let id = result.stdout_lossy().trim().to_owned();
                    if !result.success() || id.parse::<u64>().is_err() {
                        return Err(Error::invalid_spec(
                            "container user",
                            "id returned no numeric identity",
                        ));
                    }
                    Ok(id)
                };
                tokio::try_join!(id("-u"), id("-g"))
            })
            .await
    }

    async fn stage_read(
        &self,
        path: &str,
        offset: u64,
        length: Option<u64>,
        file: &RemoteFile,
    ) -> Result<u64> {
        let result = self
            .command(vec![
                "read".to_owned(),
                CONTAINER_NAME.to_owned(),
                self.cli.resolve(path),
                file.path.clone(),
                offset.to_string(),
                length.map_or_else(|| "all".to_owned(), |n| n.to_string()),
            ])
            .await?;
        if result.missing {
            return Err(Error::NotFound {
                resource: ResourceKind::File,
                id:       path.to_owned(),
            });
        }
        result
            .size
            .ok_or_else(|| Error::invalid_spec("file result", "missing byte count"))
    }

    async fn publish(&self, path: &str, file: &RemoteFile) -> Result<()> {
        let (uid, gid) = self.owner().await?;
        self.command(vec![
            "write".to_owned(),
            CONTAINER_NAME.to_owned(),
            self.cli.resolve(path),
            file.path.clone(),
            uid.clone(),
            gid.clone(),
        ])
        .await?;
        Ok(())
    }
}

/// A staging file belongs to this operation. Cancellation schedules cleanup;
/// deleting the outer sandbox is the final recovery boundary.
struct RemoteFile {
    cli:  Arc<DockerCli>,
    path: String,
}

impl RemoteFile {
    fn new(cli: &Arc<DockerCli>) -> Self {
        Self {
            cli:  Arc::clone(cli),
            path: format!("/tmp/.sandbox-driver-file-{:032x}", rand::random::<u128>()),
        }
    }

    async fn close(&mut self) {
        match timeout(CLEANUP_TIMEOUT, self.cli.fs.delete(&self.path, false)).await {
            Ok(Ok(())) => self.path.clear(),
            Ok(Err(error)) => tracing::warn!(error = ?error, "nested file staging cleanup failed"),
            Err(_) => tracing::warn!("nested file staging cleanup timed out"),
        }
    }
}

impl Drop for RemoteFile {
    fn drop(&mut self) {
        if self.path.is_empty() {
            return;
        }
        if let Ok(runtime) = Handle::try_current() {
            let cli = Arc::clone(&self.cli);
            let path = self.path.clone();
            runtime.spawn(async move {
                let result = timeout(CLEANUP_TIMEOUT, cli.fs.delete(&path, false)).await;
                if !matches!(result, Ok(Ok(()))) {
                    tracing::warn!("cancelled nested file staging cleanup failed");
                }
            });
        }
    }
}

#[async_trait]
impl Filesystem for NestedFs {
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        self.read_range(path, 0, None).await
    }

    async fn read_range(&self, path: &str, offset: u64, length: Option<u64>) -> Result<Vec<u8>> {
        let mut file = RemoteFile::new(&self.cli);
        self.stage_read(path, offset, length, &file).await?;
        let result = self.cli.fs.read(&file.path).await;
        file.close().await;
        result
    }

    async fn read_to(
        &self,
        path: &str,
        output: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<()> {
        let mut file = RemoteFile::new(&self.cli);
        let length = self.stage_read(path, 0, None, &file).await?;
        let mut chunk = RemoteFile::new(&self.cli);
        let mut offset = 0;
        while offset < length {
            self.command(vec![
                "slice".to_owned(),
                file.path.clone(),
                chunk.path.clone(),
                offset.to_string(),
            ])
            .await?;
            let bytes = self.cli.fs.read(&chunk.path).await?;
            if bytes.is_empty() {
                return Err(Error::io(
                    "reading staged Docker file",
                    io::Error::from(io::ErrorKind::UnexpectedEof),
                ));
            }
            output
                .write_all(&bytes)
                .await
                .map_err(|error| Error::io("writing file output", error))?;
            offset += bytes.len() as u64;
        }
        chunk.close().await;
        file.close().await;
        output
            .flush()
            .await
            .map_err(|error| Error::io("flushing file output", error))
    }

    async fn write(&self, path: &str, content: &[u8]) -> Result<()> {
        let mut file = RemoteFile::new(&self.cli);
        self.cli.fs.write(&file.path, content).await?;
        self.publish(path, &file).await?;
        file.close().await;
        Ok(())
    }

    async fn write_from(
        &self,
        path: &str,
        input: &mut (dyn AsyncRead + Unpin + Send),
        length: u64,
    ) -> Result<()> {
        let mut file = RemoteFile::new(&self.cli);
        let mut chunk = RemoteFile::new(&self.cli);
        let mut input = input.take(length);
        let mut buffer = vec![0; CHUNK];
        let mut written = 0;
        loop {
            let count = input
                .read(&mut buffer)
                .await
                .map_err(|error| Error::io("reading file input", error))?;
            if count == 0 {
                break;
            }
            if written == 0 {
                self.cli.fs.write(&file.path, &buffer[..count]).await?;
            } else {
                self.cli.fs.write(&chunk.path, &buffer[..count]).await?;
                self.command(vec![
                    "append".to_owned(),
                    chunk.path.clone(),
                    file.path.clone(),
                ])
                .await?;
            }
            written += count as u64;
        }
        if written != length {
            return Err(Error::io(
                "reading file input",
                io::Error::from(io::ErrorKind::UnexpectedEof),
            ));
        }
        if length == 0 {
            self.cli.fs.write(&file.path, &[]).await?;
        }
        self.publish(path, &file).await?;
        chunk.close().await;
        file.close().await;
        Ok(())
    }

    async fn write_append(&self, path: &str, content: &[u8]) -> Result<()> {
        let path = self.cli.resolve(path);
        let (parent, _) = path
            .rsplit_once('/')
            .ok_or_else(|| Error::invalid_spec("path", "expected an absolute file path"))?;
        // Append through an open file descriptor. Replacing an archive would
        // lose concurrent appends, overwrite symlinks, and reset permissions.
        // Fixed stdin uses Daytona's binary file upload, not its text input.
        let script = format!(
            "mkdir -p -- {} && cat >> {}",
            shell_quote(if parent.is_empty() { "/" } else { parent }),
            shell_quote(&path)
        );
        let mut spec = ExecSpec::new("/bin/sh")
            .args(["-c", &script])
            .timeout(FILE_TIMEOUT);
        spec.stdin = Some(content.to_vec());
        let result = self.exec.run(&spec).await?;
        if !result.success() {
            return Err(Error::Exec(
                ExecFailure::new(
                    "appending nested file",
                    result.termination,
                    result.exit_code,
                    result.stdout,
                    result.stderr,
                )
                .with_duration(result.duration),
            ));
        }
        Ok(())
    }

    async fn delete(&self, path: &str, recursive: bool) -> Result<()> {
        self.derived.delete(path, recursive).await
    }
    async fn exists(&self, path: &str) -> Result<bool> {
        self.derived.exists(path).await
    }
    async fn metadata(&self, path: &str) -> Result<FileMetadata> {
        self.derived.metadata(path).await
    }
    async fn list_dir(&self, path: &str, depth: usize) -> Result<Vec<DirEntry>> {
        self.derived.list_dir(path, depth).await
    }
    async fn create_dir(&self, path: &str) -> Result<()> {
        self.derived.create_dir(path).await
    }
    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.derived.rename(from, to).await
    }
    async fn set_permissions(&self, path: &str, mode: u32) -> Result<()> {
        self.derived.set_permissions(path, mode).await
    }

    async fn upload(&self, local: &Path, remote: &str) -> Result<()> {
        let mut input = fs::File::open(local)
            .await
            .map_err(|error| Error::io("opening upload file", error))?;
        let length = input
            .metadata()
            .await
            .map_err(|error| Error::io("reading upload file metadata", error))?
            .len();
        self.write_from(remote, &mut input, length).await
    }

    async fn download(&self, remote: &str, local: &Path) -> Result<()> {
        if let Some(parent) = local.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|error| Error::io("creating download directory", error))?;
        }
        let mut output = fs::File::create(local)
            .await
            .map_err(|error| Error::io("creating download file", error))?;
        self.read_to(remote, &mut output).await
    }
}
