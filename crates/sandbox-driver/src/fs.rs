use std::io;
use std::path::Path;
use std::time::SystemTime;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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

    /// Copies a file's bytes to `output` and flushes it without closing it.
    /// Read and output failures are returned to the caller. On failure,
    /// `output` may already contain part of the file.
    ///
    /// The provided default buffers the whole file through [`Self::read`].
    /// Providers with a streaming filesystem override this method to keep
    /// memory use bounded independently of file size.
    async fn read_to(
        &self,
        path: &str,
        output: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<()> {
        let content = self.read(path).await?;
        output
            .write_all(&content)
            .await
            .map_err(|error| Error::io("writing file output", error))?;
        output
            .flush()
            .await
            .map_err(|error| Error::io("flushing file output", error))
    }

    /// Reads `length` bytes (or to end of file when `None`) starting at
    /// `offset`. Reading at or past the end returns empty bytes.
    ///
    /// The provided default reads the whole file and slices — correct
    /// everywhere; providers with random access override it. This is
    /// what chunked downloads build on.
    async fn read_range(&self, path: &str, offset: u64, length: Option<u64>) -> Result<Vec<u8>> {
        let content = self.read(path).await?;
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(content.len());
        let end = match length {
            Some(length) => start
                .saturating_add(usize::try_from(length).unwrap_or(usize::MAX))
                .min(content.len()),
            None => content.len(),
        };
        Ok(content[start..end].to_vec())
    }

    /// Writes a file, creating parent directories.
    async fn write(&self, path: &str, content: &[u8]) -> Result<()>;

    /// Writes exactly `length` bytes from `input`, creating parent
    /// directories. Bytes after `length` remain unread. An input that ends
    /// early returns an I/O error with [`io::ErrorKind::UnexpectedEof`].
    /// On failure, the destination may have been created or partly written.
    ///
    /// The provided default buffers all `length` bytes, then calls
    /// [`Self::write`]. Providers with a streaming filesystem override this
    /// method to keep memory use bounded independently of file size.
    async fn write_from(
        &self,
        path: &str,
        input: &mut (dyn AsyncRead + Unpin + Send),
        length: u64,
    ) -> Result<()> {
        if length > crate::DEFAULT_BUFFER_BYTES as u64 {
            return Err(Error::LimitExceeded {
                limit:     "buffered_value_bytes".into(),
                max_bytes: crate::DEFAULT_BUFFER_BYTES,
            });
        }
        let mut content = Vec::new();
        input
            .take(length)
            .read_to_end(&mut content)
            .await
            .map_err(|error| Error::io("reading file input", error))?;
        if content.len() as u64 != length {
            return Err(Error::io(
                "reading file input",
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "file input ended before its length",
                ),
            ));
        }
        self.write(path, &content).await
    }

    /// Appends to a file, creating it (and parent directories) when
    /// missing.
    ///
    /// The provided default reads, concatenates, and rewrites — correct
    /// everywhere but quadratic over many appends; providers override
    /// with a real append. This is what chunked uploads build on.
    async fn write_append(&self, path: &str, content: &[u8]) -> Result<()> {
        let mut combined = if self.exists(path).await? {
            self.read(path).await?
        } else {
            Vec::new()
        };
        if content.len() > crate::DEFAULT_BUFFER_BYTES.saturating_sub(combined.len()) {
            return Err(Error::LimitExceeded {
                limit:     "buffered_value_bytes".into(),
                max_bytes: crate::DEFAULT_BUFFER_BYTES,
            });
        }
        combined.extend_from_slice(content);
        self.write(path, &combined).await
    }

    /// Deletes a file or directory (recursively when `recursive`).
    ///
    /// Idempotent: deleting a path that does not exist succeeds, so
    /// retry and cleanup paths need no not-found guard. Callers that
    /// must distinguish "was present" check [`Filesystem::exists`]
    /// first.
    async fn delete(&self, path: &str, recursive: bool) -> Result<()>;

    async fn exists(&self, path: &str) -> Result<bool>;

    async fn metadata(&self, path: &str) -> Result<FileMetadata>;

    /// Lists a directory to the given depth (`1` = immediate children).
    ///
    /// Entries are sorted lexicographically by full relative path — a
    /// flat order, not a tree order: a directory's children need not
    /// directly follow it (`foo-bar` sorts between `foo` and `foo/x`).
    /// Consumers rendering trees group by path themselves.
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
    #[serde(default)]
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
    #[serde(default)]
    pub mode:        Option<u32>,
    #[serde(default, with = "crate::wire_time::option")]
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
