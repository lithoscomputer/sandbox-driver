use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::fs as tokio_fs;

use crate::derived::shell_quote;
use crate::error::{Error, ExecFailure, Result};
use crate::exec::{Exec, ExecResult, ExecSpec};
use crate::fs::{DirEntry, FileKind, FileMetadata, Filesystem};

const FS_TIMEOUT: Duration = Duration::from_secs(60);
/// Raw bytes per write command. The base64 payload (4/3 expansion, so
/// ~87KB per chunk) travels inside a single `bash -c` argument, and
/// Linux caps one execve argument at `MAX_ARG_STRLEN` (128KiB) — the
/// chunk must leave room for that plus provider wrapper overhead.
const WRITE_CHUNK_BYTES: usize = 64 * 1024;

/// Exec-derived [`Filesystem`] for providers without a native file API.
///
/// Assumes a Linux userland inside the sandbox (GNU or busybox `stat`,
/// `find`, `base64`) — which is what the exec-derived data plane targets;
/// reads are raw `cat` output (binary-safe through the exec transport)
/// and writes cross as base64 chunks inside the command string, so no
/// stdin capability is required.
///
/// Unlike the borrowing [`crate::DerivedSearch`]/[`crate::DerivedGit`],
/// this type owns an `Arc<dyn Exec>` so a provider can store it and
/// return it from [`crate::Sandbox::fs`].
pub struct DerivedFs {
    exec: Arc<dyn Exec>,
}

impl DerivedFs {
    pub fn new(exec: Arc<dyn Exec>) -> Self {
        Self { exec }
    }

    async fn run(&self, label: &'static str, command: String) -> Result<ExecResult> {
        let spec = ExecSpec::bash(command).timeout(FS_TIMEOUT);
        let result = self.exec.run(&spec).await?;
        if result.success() {
            return Ok(result);
        }
        Err(Error::Exec(
            ExecFailure::new(
                label,
                result.termination,
                result.exit_code,
                result.stdout,
                result.stderr,
            )
            .with_duration(result.duration),
        ))
    }
}

fn parse_kind(text: &str) -> FileKind {
    match text {
        "regular file" | "regular empty file" => FileKind::File,
        "directory" => FileKind::Directory,
        "symbolic link" => FileKind::Symlink,
        _ => FileKind::Other,
    }
}

/// Minimal standard-alphabet base64, avoiding a protocol-crate
/// dependency for one encoder.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18) as usize & 63] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(triple >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[triple as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[async_trait]
impl Filesystem for DerivedFs {
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let result = self
            .run("fs read", format!("cat -- {}", shell_quote(path)))
            .await?;
        Ok(result.stdout)
    }

    async fn read_range(&self, path: &str, offset: u64, length: Option<u64>) -> Result<Vec<u8>> {
        let quoted = shell_quote(path);
        // tail -c +K is 1-based; head applies the length bound only when
        // one was given. Reading past EOF yields empty output.
        let command = match length {
            Some(length) => format!(
                "tail -c +{} -- {quoted} | head -c {length}",
                offset.saturating_add(1)
            ),
            None => format!("tail -c +{} -- {quoted}", offset.saturating_add(1)),
        };
        let result = self.run("fs read_range", command).await?;
        Ok(result.stdout)
    }

    async fn write_append(&self, path: &str, content: &[u8]) -> Result<()> {
        let quoted = shell_quote(path);
        let mkdir = format!("dir=$(dirname -- {quoted}); mkdir -p -- \"$dir\"");
        if content.is_empty() {
            self.run("fs append", format!("{mkdir} && touch -- {quoted}"))
                .await?;
            return Ok(());
        }
        let mut first = true;
        for chunk in content.chunks(WRITE_CHUNK_BYTES) {
            let encoded = base64_encode(chunk);
            let prefix = if first {
                format!("{mkdir} && ")
            } else {
                String::new()
            };
            self.run(
                "fs append",
                format!("{prefix}printf '%s' '{encoded}' | base64 -d >> {quoted}"),
            )
            .await?;
            first = false;
        }
        Ok(())
    }

    async fn write(&self, path: &str, content: &[u8]) -> Result<()> {
        let quoted = shell_quote(path);
        let mkdir = format!("dir=$(dirname -- {quoted}); mkdir -p -- \"$dir\"");
        if content.is_empty() {
            self.run("fs write", format!("{mkdir} && : > {quoted}"))
                .await?;
            return Ok(());
        }
        let mut first = true;
        for chunk in content.chunks(WRITE_CHUNK_BYTES) {
            let encoded = base64_encode(chunk);
            let redirect = if first { ">" } else { ">>" };
            let prefix = if first {
                format!("{mkdir} && ")
            } else {
                String::new()
            };
            self.run(
                "fs write",
                format!("{prefix}printf '%s' '{encoded}' | base64 -d {redirect} {quoted}"),
            )
            .await?;
            first = false;
        }
        Ok(())
    }

    async fn delete(&self, path: &str, recursive: bool) -> Result<()> {
        let quoted = shell_quote(path);
        let command = if recursive {
            format!("rm -rf -- {quoted}")
        } else {
            format!(
                "if [ ! -e {quoted} ]; then exit 0; \
                 elif [ -d {quoted} ]; then rmdir -- {quoted}; \
                 else rm -f -- {quoted}; fi"
            )
        };
        self.run("fs delete", command).await?;
        Ok(())
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        let spec = ExecSpec::bash(format!("[ -e {} ]", shell_quote(path))).timeout(FS_TIMEOUT);
        let result = self.exec.run(&spec).await?;
        Ok(result.exit_code == Some(0))
    }

    async fn metadata(&self, path: &str) -> Result<FileMetadata> {
        let result = self
            .run(
                "fs metadata",
                format!("stat -c '%F|%s|%a|%Y' -- {}", shell_quote(path)),
            )
            .await?;
        let text = result.stdout_lossy();
        let mut fields = text.trim().splitn(4, '|');
        let (Some(kind), Some(size), Some(mode), Some(mtime)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(Error::invalid_spec(
                "stat",
                format!("unparseable output: {text:?}"),
            ));
        };
        let mut metadata = FileMetadata::new(parse_kind(kind), size.parse().unwrap_or_default());
        metadata.mode = u32::from_str_radix(mode, 8).ok();
        metadata.modified_at = mtime
            .parse::<u64>()
            .ok()
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs));
        Ok(metadata)
    }

    async fn list_dir(&self, path: &str, depth: usize) -> Result<Vec<DirEntry>> {
        // NUL-terminated records end to end (`find -print0`, `stat
        // --printf '…\0'`): a file name containing a newline stays one
        // verbatim record, where newline-split parsing corrupted the
        // entry and its neighbors.
        let command = format!(
            "cd -- {} && find . -mindepth 1 -maxdepth {depth} -print0 \
             | xargs -0 -r stat --printf '%F|%s|%n\\0' --",
            shell_quote(path)
        );
        let result = self.run("fs list_dir", command).await?;
        let text = result.stdout_lossy();
        let mut entries = Vec::new();
        for line in text.split('\0') {
            let mut fields = line.splitn(3, '|');
            let (Some(kind), Some(size), Some(name)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            let kind = parse_kind(kind);
            let mut entry = DirEntry::new(name.strip_prefix("./").unwrap_or(name).to_owned(), kind);
            if kind == FileKind::File {
                entry.size = size.parse().ok();
            }
            entries.push(entry);
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    async fn create_dir(&self, path: &str) -> Result<()> {
        self.run(
            "fs create_dir",
            format!("mkdir -p -- {}", shell_quote(path)),
        )
        .await?;
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.run(
            "fs rename",
            format!("mv -- {} {}", shell_quote(from), shell_quote(to)),
        )
        .await?;
        Ok(())
    }

    async fn set_permissions(&self, path: &str, mode: u32) -> Result<()> {
        self.run(
            "fs chmod",
            format!("chmod {mode:o} -- {}", shell_quote(path)),
        )
        .await?;
        Ok(())
    }

    async fn upload(&self, local: &Path, remote: &str) -> Result<()> {
        let content = tokio_fs::read(local)
            .await
            .map_err(|error| Error::io(format!("reading {}", local.display()), error))?;
        self.write(remote, &content).await
    }

    async fn download(&self, remote: &str, local: &Path) -> Result<()> {
        let content = self.read(remote).await?;
        if let Some(parent) = local.parent() {
            tokio_fs::create_dir_all(parent).await.map_err(|error| {
                Error::io(format!("creating parent of {}", local.display()), error)
            })?;
        }
        tokio_fs::write(local, content)
            .await
            .map_err(|error| Error::io(format!("writing {}", local.display()), error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard_alphabet() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(&[0, 255, 16]), "AP8Q");
    }

    #[tokio::test]
    async fn list_dir_keeps_special_character_names_intact() {
        use crate::test_exec::ScriptedExec;
        let exec = Arc::new(ScriptedExec::new(vec![ScriptedExec::ok(
            "regular file|3|./a|b\0regular file|5|./line\nbreak.txt\0directory|0|./sub\0",
        )]));
        let fs = DerivedFs::new(exec);
        let entries = fs.list_dir("/dir", 1).await.expect("list");
        let names: Vec<&str> = entries.iter().map(|entry| entry.path.as_str()).collect();
        // NUL records keep a newline or '|' in a name verbatim instead
        // of corrupting the entry and its neighbors.
        assert_eq!(names, vec!["a|b", "line\nbreak.txt", "sub"]);
    }

    #[test]
    fn stat_kinds_map_to_file_kinds() {
        assert_eq!(parse_kind("regular file"), FileKind::File);
        assert_eq!(parse_kind("directory"), FileKind::Directory);
        assert_eq!(parse_kind("symbolic link"), FileKind::Symlink);
        assert_eq!(parse_kind("socket"), FileKind::Other);
    }
}
