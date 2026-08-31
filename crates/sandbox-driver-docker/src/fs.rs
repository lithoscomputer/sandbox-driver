//! Hybrid filesystem for Docker sandboxes.
//!
//! File **content** moves through the daemon's archive API — one call
//! per transfer regardless of size, an explicit file mode, and reads
//! that work on stopped containers — while metadata operations
//! (exists, metadata, list, mkdir, rename, delete, permissions) stay
//! exec-derived. Writes try the archive upload first and fall back to
//! an exec `mkdir -p` only when the parent directory is missing, so a
//! write into an existing directory also works on a stopped container.

use std::io;
use std::io::{Cursor, Read};
use std::path::Path;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bollard::Docker;
use bollard::container::{DownloadFromContainerOptions, UploadToContainerOptions};
use bollard::errors::Error as DockerApiError;
use futures_util::StreamExt;
use sandbox_driver::{
    DerivedFs, DirEntry, Error, Exec, ExecSpec, FileMetadata, Filesystem, Result,
};
use tokio::fs;

use crate::exec::{docker_error, is_not_found, shell_quote};

const MKDIR_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct DockerFs {
    docker:       Docker,
    container_id: String,
    working_dir:  String,
    exec:         Arc<dyn Exec>,
    derived:      DerivedFs,
}

impl DockerFs {
    pub(crate) fn new(
        docker: Docker,
        container_id: String,
        working_dir: String,
        exec: Arc<dyn Exec>,
    ) -> Self {
        let derived = DerivedFs::new(Arc::clone(&exec));
        Self {
            docker,
            container_id,
            working_dir,
            exec,
            derived,
        }
    }

    fn resolve(&self, path: &str) -> String {
        if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("{}/{}", self.working_dir.trim_end_matches('/'), path)
        }
    }

    async fn upload_tar(&self, parent: &str, archive: Vec<u8>) -> StdResult<(), DockerApiError> {
        let options = UploadToContainerOptions {
            path:                     parent.to_owned(),
            no_overwrite_dir_non_dir: "false".to_owned(),
        };
        self.docker
            .upload_to_container(&self.container_id, Some(options), archive.into())
            .await
    }
}

/// Splits a resolved container path into its parent directory and file
/// name for the archive upload.
fn split_container_path(container_path: &str) -> Result<(String, String)> {
    let path = Path::new(container_path);
    let file_name = path
        .file_name()
        .ok_or_else(|| Error::invalid_spec("path", format!("no file name in {container_path:?}")))?
        .to_string_lossy()
        .into_owned();
    let parent = path
        .parent()
        .map_or_else(|| "/".to_owned(), |p| p.to_string_lossy().into_owned());
    Ok((parent, file_name))
}

/// One regular file, tar-encoded for the archive upload.
fn single_file_tar(file_name: &str, bytes: &[u8], mode: u32) -> Result<Vec<u8>> {
    let tar_io = |error| Error::io("building upload archive", error);
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path(file_name).map_err(tar_io)?;
    header.set_size(bytes.len() as u64);
    header.set_mode(mode);
    header.set_cksum();
    builder.append(&header, bytes).map_err(tar_io)?;
    builder.into_inner().map_err(tar_io)
}

/// The regular file inside a single-resource archive download; `None`
/// when the archive holds no regular file (a directory, or a symlink —
/// the archive API returns links as-is instead of following them).
fn file_from_tar(archive: &[u8]) -> Result<Option<Vec<u8>>> {
    let tar_io = |error| Error::io("reading download archive", error);
    let mut archive = tar::Archive::new(Cursor::new(archive));
    for entry in archive.entries().map_err(tar_io)? {
        let mut entry = entry.map_err(tar_io)?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(tar_io)?;
        return Ok(Some(bytes));
    }
    Ok(None)
}

#[async_trait]
impl Filesystem for DockerFs {
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let container_path = self.resolve(path);
        let options = DownloadFromContainerOptions {
            path: container_path.clone(),
        };
        let mut stream = self
            .docker
            .download_from_container(&self.container_id, Some(options));
        let mut archive = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| docker_error("downloading file", error))?;
            archive.extend_from_slice(&chunk);
        }
        match file_from_tar(&archive)? {
            Some(bytes) => Ok(bytes),
            // A symlink (returned as-is by the archive API) or any other
            // non-regular resource: the exec-derived read follows it.
            None => self.derived.read(path).await,
        }
    }

    async fn write(&self, path: &str, content: &[u8]) -> Result<()> {
        let container_path = self.resolve(path);
        let (parent, file_name) = split_container_path(&container_path)?;
        let archive = single_file_tar(&file_name, content, 0o644)?;
        match self.upload_tar(&parent, archive.clone()).await {
            Ok(()) => Ok(()),
            // Missing parent directories: create them (needs exec, so a
            // running container) and retry once.
            Err(error) if is_not_found(&error) => {
                let mkdir = format!("mkdir -p -- {}", shell_quote(&parent));
                let spec = ExecSpec::new(mkdir).timeout(MKDIR_TIMEOUT);
                let result = self.exec.run(&spec).await?;
                if !result.success() {
                    return Err(Error::io(
                        format!("creating parent directory {parent}"),
                        io::Error::other(result.stderr_lossy()),
                    ));
                }
                self.upload_tar(&parent, archive)
                    .await
                    .map_err(|error| docker_error("uploading file", error))
            }
            Err(error) => Err(docker_error("uploading file", error)),
        }
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

    async fn read_range(&self, path: &str, offset: u64, length: Option<u64>) -> Result<Vec<u8>> {
        // The archive API only moves whole files; the exec-derived range
        // read avoids materializing the file for one slice.
        self.derived.read_range(path, offset, length).await
    }

    async fn write_append(&self, path: &str, content: &[u8]) -> Result<()> {
        self.derived.write_append(path, content).await
    }

    async fn upload(&self, local: &Path, remote: &str) -> Result<()> {
        let bytes = fs::read(local)
            .await
            .map_err(|error| Error::io(format!("reading {}", local.display()), error))?;
        self.write(remote, &bytes).await
    }

    async fn download(&self, remote: &str, local: &Path) -> Result<()> {
        let bytes = self.read(remote).await?;
        if let Some(parent) = local.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|error| Error::io(format!("creating {}", parent.display()), error))?;
        }
        fs::write(local, bytes)
            .await
            .map_err(|error| Error::io(format!("writing {}", local.display()), error))
    }
}
