use std::path::Path;
use std::time::SystemTime;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::capabilities::Capability;
use crate::error::{Error, Result};

/// File operations inside a sandbox. Paths are sandbox-side strings
/// (POSIX); local paths in transfer methods are host-side.
///
/// Providers without a native filesystem API derive these from exec
/// (base64 `cat`/`tee`), declared via `Capabilities::fs.native = false`.
#[async_trait]
pub trait Filesystem: Send + Sync {
    /// Reads a file's bytes. Output is bytes: content is not guaranteed
    /// UTF-8.
    async fn read(&self, path: &str) -> Result<Vec<u8>>;

    /// Writes a file, creating parent directories.
    async fn write(&self, path: &str, content: &[u8]) -> Result<()>;

    /// Deletes a file or directory (recursively when `recursive`).
    async fn delete(&self, path: &str, recursive: bool) -> Result<()>;

    async fn exists(&self, path: &str) -> Result<bool>;

    async fn metadata(&self, path: &str) -> Result<FileMetadata>;

    /// Lists a directory to the given depth (`1` = immediate children).
    async fn list_dir(&self, path: &str, depth: usize) -> Result<Vec<DirEntry>>;

    async fn create_dir(&self, path: &str) -> Result<()>;

    /// Moves or renames a file or directory.
    async fn rename(&self, from: &str, to: &str) -> Result<()>;

    /// Sets POSIX permissions. Capability-gated on `fs.permissions`.
    async fn set_permissions(&self, path: &str, mode: u32) -> Result<()> {
        let _ = (path, mode);
        Err(Error::unsupported(Capability::FsPermissions))
    }

    /// Uploads a local file into the sandbox (binary-safe, chunked above
    /// transport limits). Capability-gated on `fs.upload`.
    async fn upload(&self, local: &Path, remote: &str) -> Result<()> {
        let _ = (local, remote);
        Err(Error::unsupported(Capability::FsUpload))
    }

    /// Downloads a sandbox file to a local path. Capability-gated on
    /// `fs.download`.
    async fn download(&self, remote: &str, local: &Path) -> Result<()> {
        let _ = (remote, local);
        Err(Error::unsupported(Capability::FsDownload))
    }
}

/// Kind of a directory entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    Other,
}

/// One entry from [`Filesystem::list_dir`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DirEntry {
    /// Path relative to the listed directory.
    pub path: String,
    pub kind: FileKind,
    pub size: Option<u64>,
}

impl DirEntry {
    pub fn new(path: impl Into<String>, kind: FileKind) -> Self {
        Self {
            path: path.into(),
            kind,
            size: None,
        }
    }
}

/// Metadata from [`Filesystem::metadata`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FileMetadata {
    pub kind:        FileKind,
    pub size:        u64,
    pub mode:        Option<u32>,
    pub modified_at: Option<SystemTime>,
}

impl FileMetadata {
    pub fn new(kind: FileKind, size: u64) -> Self {
        Self {
            kind,
            size,
            mode: None,
            modified_at: None,
        }
    }
}
