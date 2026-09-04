//! Hybrid filesystem for Docker sandboxes.
//!
//! File **content** moves through the daemon's archive API — reads that
//! stream and stop at the requested range, writes that carry their missing
//! parent directories, an explicit file mode, and both working on a
//! stopped container — while metadata operations (exists, metadata, list,
//! mkdir, rename, delete, permissions) stay exec-derived. The content paths
//! run no command in the image except `readlink`, to follow a symlink, and
//! `id`, once, to own what they create as the container's user; so a
//! program that needs only these — Petri's step runner, say — runs on any
//! Linux image with a POSIX userland.

use std::io::{self, Cursor};
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
    DerivedFs, DirEntry, Error, Exec, ExecSpec, FileMetadata, Filesystem, ResourceKind, Result,
};
use tokio::fs;
use tokio::sync::OnceCell;

use crate::exec::{docker_error, is_not_found};

const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const TAR_BLOCK: usize = 512;

pub(crate) struct DockerFs {
    docker:       Docker,
    container_id: String,
    working_dir:  String,
    exec:         Arc<dyn Exec>,
    derived:      DerivedFs,
    /// The container user's numeric identity, for what the archive
    /// uploads create. Cached after a successful lookup.
    owner:        OnceCell<Owner>,
}

/// A numeric uid and gid.
#[derive(Clone, Copy, Debug, Default)]
struct Owner {
    uid: u64,
    gid: u64,
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
            owner: OnceCell::new(),
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

    /// Who the container runs as. A stopped container answers nothing,
    /// and root is then the honest default: the daemon extracts as root.
    /// Failed lookups are retried on the next write.
    async fn owner(&self) -> Owner {
        self.owner
            .get_or_try_init(|| async {
                let lookup = |flag| async move {
                    let spec = ExecSpec::new("id").arg(flag).timeout(PROBE_TIMEOUT);
                    let result = self.exec.run(&spec).await.map_err(|_| ())?;
                    if !result.success() {
                        return Err(());
                    }
                    result.stdout_lossy().trim().parse::<u64>().map_err(|_| ())
                };
                let (uid, gid) = tokio::join!(lookup("-u"), lookup("-g"));
                Ok::<_, ()>(Owner {
                    uid: uid?,
                    gid: gid?,
                })
            })
            .await
            .copied()
            .unwrap_or_default()
    }

    /// The path a symlink at `container_path` finally points at, through
    /// `readlink -f`, which busybox and coreutils both provide.
    async fn resolve_link(&self, container_path: &str) -> Result<String> {
        let spec = ExecSpec::new("readlink")
            .args(["-f", container_path])
            .timeout(PROBE_TIMEOUT);
        let result = self.exec.run(&spec).await?;
        let target = result.stdout_lossy().trim().to_owned();
        if !result.success() || target.is_empty() {
            return Err(Error::NotFound {
                resource: ResourceKind::File,
                id:       container_path.to_owned(),
            });
        }
        Ok(target)
    }

    /// Streams the archive of `container_path` and returns the bytes of
    /// its first regular file within `offset` and `length`, or `None`
    /// when the archived resource is not a regular file (a symlink, which
    /// the archive API returns as-is, or a directory).
    async fn read_archived(
        &self,
        container_path: &str,
        offset: u64,
        length: Option<u64>,
    ) -> Result<Option<Vec<u8>>> {
        let options = DownloadFromContainerOptions {
            path: container_path.to_owned(),
        };
        let mut stream = self
            .docker
            .download_from_container(&self.container_id, Some(options));
        let mut scanner = TarScanner::new(offset, length);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| {
                if is_not_found(&error) {
                    Error::NotFound {
                        resource: ResourceKind::File,
                        id:       container_path.to_owned(),
                    }
                } else {
                    docker_error("downloading file", error)
                }
            })?;
            if scanner.feed(&chunk)? {
                // Everything wanted is in hand; the rest of the archive is
                // dropped with the stream.
                break;
            }
        }
        scanner.finish()
    }
}

/// An incremental reader over a tar stream that finds the first regular
/// file and keeps only the requested range of its content.
struct TarScanner {
    offset:     u64,
    length:     Option<u64>,
    header:     [u8; TAR_BLOCK],
    header_len: usize,
    state:      ScanState,
    collected:  Vec<u8>,
    found:      bool,
}

enum ScanState {
    /// Reading a 512-byte header block.
    Header,
    /// Skipping `remaining` bytes of an entry nobody wants, plus padding.
    Skip {
        remaining: u64,
    },
    /// Inside the wanted file: `position` bytes of it seen so far, `size`
    /// in total.
    Content {
        position: u64,
        size:     u64,
    },
    Done,
}

impl TarScanner {
    fn new(offset: u64, length: Option<u64>) -> Self {
        Self {
            offset,
            length,
            header: [0; TAR_BLOCK],
            header_len: 0,
            state: ScanState::Header,
            collected: Vec::new(),
            found: false,
        }
    }

    /// The last byte of the file this read wants, exclusive.
    fn end(&self) -> u64 {
        self.length
            .map_or(u64::MAX, |length| self.offset.saturating_add(length))
    }

    fn padded(size: u64) -> Result<u64> {
        let padding = (TAR_BLOCK as u64 - size % TAR_BLOCK as u64) % TAR_BLOCK as u64;
        size.checked_add(padding).ok_or_else(|| {
            Error::io(
                "reading download archive",
                io::Error::new(io::ErrorKind::InvalidData, "archive entry size overflows"),
            )
        })
    }

    /// Consumes `chunk`; `true` once nothing further is wanted.
    fn feed(&mut self, mut chunk: &[u8]) -> Result<bool> {
        loop {
            match self.state {
                ScanState::Done => return Ok(true),
                ScanState::Header => {
                    let take = (TAR_BLOCK - self.header_len).min(chunk.len());
                    self.header[self.header_len..self.header_len + take]
                        .copy_from_slice(&chunk[..take]);
                    self.header_len += take;
                    chunk = &chunk[take..];
                    if self.header_len < TAR_BLOCK {
                        return Ok(false);
                    }
                    self.header_len = 0;
                    if self.header.iter().all(|byte| *byte == 0) {
                        // End-of-archive marker: no regular file came.
                        self.state = ScanState::Done;
                        return Ok(true);
                    }
                    let header = tar::Header::from_byte_slice(&self.header);
                    let size = header
                        .entry_size()
                        .map_err(|error| Error::io("reading download archive", error))?;
                    let kind = header.entry_type();
                    if kind.is_file() {
                        self.found = true;
                        self.state = ScanState::Content { position: 0, size };
                    } else if kind.is_dir() || kind.is_symlink() || kind.is_hard_link() {
                        // The archived resource itself is not a regular
                        // file; the caller follows or refuses it.
                        self.state = ScanState::Done;
                        return Ok(true);
                    } else {
                        // A pax or long-name header, or something
                        // exotic: skip its data and read on.
                        self.state = ScanState::Skip {
                            remaining: Self::padded(size)?,
                        };
                    }
                }
                ScanState::Skip { remaining } => {
                    let take = usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .min(chunk.len());
                    chunk = &chunk[take..];
                    let remaining = remaining - take as u64;
                    if remaining > 0 {
                        self.state = ScanState::Skip { remaining };
                        return Ok(false);
                    }
                    self.state = ScanState::Header;
                }
                ScanState::Content { position, size } => {
                    let available = chunk.len() as u64;
                    let file_left = size.saturating_sub(position);
                    let take = available.min(file_left);
                    let end = self.end();
                    // Keep the slice of this chunk inside [offset, end).
                    let keep_from = self.offset.saturating_sub(position).min(take);
                    let keep_to = end.saturating_sub(position).min(take);
                    if keep_to > keep_from {
                        let from = usize::try_from(keep_from).unwrap_or(usize::MAX);
                        let to = usize::try_from(keep_to).unwrap_or(usize::MAX);
                        self.collected.extend_from_slice(&chunk[from..to]);
                    }
                    let position = position + take;
                    if position >= size || position >= end {
                        self.state = ScanState::Done;
                        return Ok(true);
                    }
                    self.state = ScanState::Content { position, size };
                    return Ok(false);
                }
            }
        }
    }

    fn finish(self) -> Result<Option<Vec<u8>>> {
        if !matches!(self.state, ScanState::Done) {
            return Err(Error::io(
                "reading download archive",
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "archive ended before the requested file data was complete",
                ),
            ));
        }
        Ok(self.found.then_some(self.collected))
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

/// Whether `container_path` lies in the runtime directory tree.
fn is_runtime_path(container_path: &str) -> bool {
    container_path
        .strip_prefix(crate::RUNTIME_DIRECTORY)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// One archive to upload at `root`: the directories `dirs` (relative to
/// `root`, shallowest first, each with `dir_mode`) and then one regular
/// file at `file` (relative to `root`).
fn upload_archive(
    dirs: &[String],
    dir_mode: u32,
    file: &str,
    bytes: &[u8],
    file_mode: u32,
    owner: Owner,
) -> Result<Vec<u8>> {
    let tar_io = |error| Error::io("building upload archive", error);
    let mut builder = tar::Builder::new(Vec::new());
    for dir in dirs {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(dir_mode);
        header.set_uid(owner.uid);
        header.set_gid(owner.gid);
        builder
            .append_data(&mut header, format!("{dir}/"), io::empty())
            .map_err(tar_io)?;
    }
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(file_mode);
    header.set_uid(owner.uid);
    header.set_gid(owner.gid);
    builder
        .append_data(&mut header, file, Cursor::new(bytes))
        .map_err(tar_io)?;
    builder.into_inner().map_err(tar_io)
}

#[async_trait]
impl Filesystem for DockerFs {
    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "docker", sandbox_id = %self.container_id),
        err
    )]
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        self.read_range(path, 0, None).await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "docker", sandbox_id = %self.container_id, offset),
        err
    )]
    async fn read_range(&self, path: &str, offset: u64, length: Option<u64>) -> Result<Vec<u8>> {
        let container_path = self.resolve(path);
        if let Some(bytes) = self.read_archived(&container_path, offset, length).await? {
            return Ok(bytes);
        }
        // A symlink comes back from the archive API as-is: follow it once.
        let target = self.resolve_link(&container_path).await?;
        match self.read_archived(&target, offset, length).await? {
            Some(bytes) => Ok(bytes),
            None => Err(Error::invalid_spec(
                "path",
                format!("{path:?} is not a regular file"),
            )),
        }
    }

    #[tracing::instrument(
        skip_all,
        fields(
            provider_kind = "docker",
            sandbox_id = %self.container_id,
            byte_count = content.len()
        ),
        err
    )]
    async fn write(&self, path: &str, content: &[u8]) -> Result<()> {
        let container_path = self.resolve(path);
        let (parent, file_name) = split_container_path(&container_path)?;
        // Runtime files stay owner-private (fabro's rule): they can hold
        // materialized secrets, and per-file 0600 keeps protecting them
        // even if an ancestor's 0700 is ever loosened.
        let runtime_path = is_runtime_path(&container_path);
        let (file_mode, dir_mode) = if runtime_path {
            (0o600, 0o700)
        } else {
            (0o644, 0o755)
        };
        let owner = self.owner().await;
        // Upload at the deepest existing ancestor, carrying only the
        // directories below it, so an existing directory is never
        // re-written with the archive's mode and ownership.
        for root in Path::new(&parent).ancestors() {
            let root = root.to_string_lossy();
            let below = parent
                .strip_prefix(root.as_ref())
                .unwrap_or_default()
                .trim_matches('/');
            let mut dirs: Vec<String> = Vec::new();
            for component in below.split('/').filter(|part| !part.is_empty()) {
                let dir = match dirs.last() {
                    Some(previous) => format!("{previous}/{component}"),
                    None => component.to_owned(),
                };
                dirs.push(dir);
            }
            let file = match dirs.last() {
                Some(deepest) => format!("{deepest}/{file_name}"),
                None => file_name.clone(),
            };
            let archive = upload_archive(&dirs, dir_mode, &file, content, file_mode, owner)?;
            match self.upload_tar(&root, archive).await {
                Ok(()) => return Ok(()),
                Err(error) if is_not_found(&error) => {}
                Err(error) => return Err(docker_error("uploading file", error)),
            }
        }
        Err(Error::io(
            format!("creating parent directory {parent}"),
            io::Error::other("no existing ancestor accepted the upload"),
        ))
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "docker", sandbox_id = %self.container_id, recursive),
        err
    )]
    async fn delete(&self, path: &str, recursive: bool) -> Result<()> {
        self.derived.delete(path, recursive).await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.container_id), err)]
    async fn exists(&self, path: &str) -> Result<bool> {
        self.derived.exists(path).await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.container_id), err)]
    async fn metadata(&self, path: &str) -> Result<FileMetadata> {
        self.derived.metadata(path).await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "docker", sandbox_id = %self.container_id, depth),
        err
    )]
    async fn list_dir(&self, path: &str, depth: usize) -> Result<Vec<DirEntry>> {
        self.derived.list_dir(path, depth).await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.container_id), err)]
    async fn create_dir(&self, path: &str) -> Result<()> {
        self.derived.create_dir(path).await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.container_id), err)]
    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.derived.rename(from, to).await
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "docker", sandbox_id = %self.container_id, mode),
        err
    )]
    async fn set_permissions(&self, path: &str, mode: u32) -> Result<()> {
        self.derived.set_permissions(path, mode).await
    }

    #[tracing::instrument(
        skip_all,
        fields(
            provider_kind = "docker",
            sandbox_id = %self.container_id,
            byte_count = content.len()
        ),
        err
    )]
    async fn write_append(&self, path: &str, content: &[u8]) -> Result<()> {
        self.derived.write_append(path, content).await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.container_id), err)]
    async fn upload(&self, local: &Path, remote: &str) -> Result<()> {
        let bytes = fs::read(local)
            .await
            .map_err(|error| Error::io(format!("reading {}", local.display()), error))?;
        self.write(remote, &bytes).await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "docker", sandbox_id = %self.container_id), err)]
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use sandbox_driver::{ExecControls, ExecResult, ExecStreamingResult, Termination};

    use super::*;

    fn single_file_tar(name: &str, bytes: &[u8]) -> Vec<u8> {
        upload_archive(&[], 0o755, name, bytes, 0o644, Owner::default()).expect("tar builds")
    }

    #[test]
    fn runtime_paths_are_detected_by_tree_membership() {
        assert!(is_runtime_path("/tmp/sandbox-driver/runtime"));
        assert!(is_runtime_path("/tmp/sandbox-driver/runtime/blob.json"));
        assert!(!is_runtime_path("/tmp/sandbox-driver/runtime-extra/x"));
        assert!(!is_runtime_path("/workspace/file.txt"));
    }

    #[test]
    fn upload_archive_carries_modes_and_directories() {
        let owner = Owner {
            uid: 1000,
            gid: 1000,
        };
        let bytes = upload_archive(
            &["a".to_owned(), "a/b".to_owned()],
            0o700,
            "a/b/blob.json",
            b"{}",
            0o600,
            owner,
        )
        .expect("tar builds");
        let mut archive = tar::Archive::new(bytes.as_slice());
        let entries: Vec<_> = archive
            .entries()
            .expect("entries")
            .map(|entry| entry.expect("valid entry"))
            .map(|entry| {
                let header = entry.header();
                (
                    entry.path().expect("path").to_string_lossy().into_owned(),
                    header.entry_type(),
                    header.mode().expect("mode"),
                    header.uid().expect("uid"),
                )
            })
            .collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0, "a/");
        assert!(entries[0].1.is_dir());
        assert_eq!(entries[0].2, 0o700);
        assert_eq!(entries[2].0, "a/b/blob.json");
        assert!(entries[2].1.is_file());
        assert_eq!(entries[2].2, 0o600);
        assert_eq!(entries[2].3, 1000);
    }

    #[test]
    fn the_scanner_slices_a_file_in_arbitrary_chunks() {
        let payload: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let archive = single_file_tar("file.bin", &payload);
        for (offset, length, expected) in [
            (0, None, payload.clone()),
            (2, Some(5), payload[2..7].to_vec()),
            (2990, None, payload[2990..].to_vec()),
            (5000, Some(4), Vec::new()),
            (0, Some(0), Vec::new()),
        ] {
            for chunk_size in [1usize, 7, 512, 1000, 100_000] {
                let mut scanner = TarScanner::new(offset, length);
                let mut done = false;
                for chunk in archive.chunks(chunk_size) {
                    if scanner.feed(chunk).expect("feed") {
                        done = true;
                        break;
                    }
                }
                assert!(
                    done || length.is_none(),
                    "chunk {chunk_size} never finished"
                );
                assert_eq!(
                    scanner
                        .finish()
                        .expect("the requested data is complete")
                        .expect("a file was found"),
                    expected,
                    "offset {offset} length {length:?} chunk {chunk_size}"
                );
            }
        }
    }

    #[test]
    fn the_scanner_reports_a_symlink_as_not_a_file() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        builder
            .append_link(&mut header, "link", "target")
            .expect("link");
        let archive = builder.into_inner().expect("tar");
        let mut scanner = TarScanner::new(0, None);
        scanner.feed(&archive).expect("feed");
        assert!(scanner.finish().expect("complete symlink header").is_none());
    }

    #[test]
    fn the_scanner_rejects_incomplete_headers_and_requested_content() {
        let archive = single_file_tar("file.bin", b"0123456789");
        for end in [0, 1, TAR_BLOCK - 1, TAR_BLOCK, TAR_BLOCK + 6] {
            let mut scanner = TarScanner::new(2, Some(5));
            assert!(!scanner.feed(&archive[..end]).expect("valid prefix"));
            assert!(
                scanner.finish().is_err(),
                "accepted a prefix of {end} bytes"
            );
        }
    }

    #[test]
    fn the_scanner_finishes_as_soon_as_the_requested_content_arrives() {
        let archive = single_file_tar("file.bin", b"0123456789");
        for (offset, length, end, expected) in [
            (2, Some(5), TAR_BLOCK + 7, b"23456".as_slice()),
            (0, None, TAR_BLOCK + 10, b"0123456789".as_slice()),
            (0, Some(0), TAR_BLOCK, b"".as_slice()),
        ] {
            let mut scanner = TarScanner::new(offset, length);
            assert!(scanner.feed(&archive[..end]).expect("valid archive prefix"));
            assert_eq!(
                scanner.finish().expect("complete range").expect("file"),
                expected
            );
        }
    }

    #[test]
    fn the_scanner_rejects_an_incomplete_extended_header() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::GNULongName);
        header.set_size(4);
        header.set_mode(0o644);
        builder
            .append_data(&mut header, "././@LongLink", b"abc\0".as_slice())
            .expect("extended header");
        let archive = builder.into_inner().expect("archive");
        for end in [TAR_BLOCK + 2, TAR_BLOCK * 2] {
            let mut scanner = TarScanner::new(0, None);
            assert!(!scanner.feed(&archive[..end]).expect("valid prefix"));
            assert!(scanner.finish().is_err());
        }
        let mut scanner = TarScanner::new(0, None);
        assert!(scanner.feed(&archive).expect("complete archive"));
        assert!(scanner.finish().expect("archive with no file").is_none());
    }

    struct UserLookup {
        ready:             AtomicBool,
        calls:             AtomicUsize,
        transport_failure: bool,
    }

    #[async_trait]
    impl Exec for UserLookup {
        async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            assert_eq!(spec.program, "id");
            let ready = self.ready.load(Ordering::Relaxed);
            if !ready && self.transport_failure {
                return Err(Error::io(
                    "looking up user",
                    io::Error::other("container stopped"),
                ));
            }
            let mut result =
                ExecResult::new(Termination::Exited, Some(i32::from(!ready)), Duration::ZERO);
            result.stdout = match spec.args[0].as_str() {
                "-u" => b"1000\n".to_vec(),
                "-g" => b"1001\n".to_vec(),
                other => panic!("unexpected id argument {other}"),
            };
            Ok(result)
        }

        async fn run_streaming(
            &self,
            _spec: &ExecSpec,
            _controls: ExecControls,
        ) -> Result<ExecStreamingResult> {
            panic!("user lookups use buffered exec")
        }
    }

    #[tokio::test]
    async fn failed_user_lookups_are_retried_and_successful_ones_are_cached() {
        for transport_failure in [false, true] {
            let exec = Arc::new(UserLookup {
                ready: AtomicBool::new(false),
                calls: AtomicUsize::new(0),
                transport_failure,
            });
            let fs = DockerFs::new(
                Docker::connect_with_http("http://127.0.0.1:1", 1, bollard::API_DEFAULT_VERSION)
                    .expect("docker client"),
                "test-container".to_owned(),
                "/workspace".to_owned(),
                exec.clone(),
            );
            let fallback = fs.owner().await;
            assert_eq!((fallback.uid, fallback.gid), (0, 0));

            exec.ready.store(true, Ordering::Relaxed);
            let owner = fs.owner().await;
            assert_eq!((owner.uid, owner.gid), (1000, 1001));

            exec.ready.store(false, Ordering::Relaxed);
            let cached = fs.owner().await;
            assert_eq!((cached.uid, cached.gid), (1000, 1001));
            assert_eq!(exec.calls.load(Ordering::Relaxed), 4);
        }
    }
}
