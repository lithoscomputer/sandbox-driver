use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use daytona_sdk::{FileSystemService, SetFilePermissionsOptions};
use sandbox_driver::{DirEntry, Error, FileKind, FileMetadata, Filesystem, ResourceKind, Result};
use tokio::fs as tokio_fs;
use tokio::sync::OnceCell;

use crate::{DaytonaClient, daytona_error, is_not_found};

/// Native filesystem access through the Daytona toolbox file API.
///
/// Relative paths resolve against the sandbox working directory.
pub struct DaytonaFs {
    client:      DaytonaClient,
    sandbox_id:  String,
    working_dir: String,
    service:     OnceCell<FileSystemService>,
}

impl DaytonaFs {
    pub(crate) fn new(client: DaytonaClient, sandbox_id: String, working_dir: String) -> Self {
        Self {
            client,
            sandbox_id,
            working_dir,
            service: OnceCell::new(),
        }
    }

    async fn service(&self) -> Result<&FileSystemService> {
        self.service
            .get_or_try_init(|| async {
                let sandbox = self
                    .client
                    .get(&self.sandbox_id)
                    .await
                    .map_err(|error| daytona_error("fetching sandbox", error))?;
                sandbox
                    .fs()
                    .await
                    .map_err(|error| daytona_error("connecting to the toolbox", error))
            })
            .await
    }

    fn resolve(&self, path: &str) -> String {
        if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("{}/{}", self.working_dir.trim_end_matches('/'), path)
        }
    }
}

fn parse_mode(mode: &str) -> Option<u32> {
    // The toolbox reports either octal digits or an `-rwxr-xr-x` string.
    if mode.chars().all(|c| c.is_ascii_digit()) {
        return u32::from_str_radix(mode, 8).ok();
    }
    let bits: Vec<char> = mode.chars().collect();
    if bits.len() < 10 {
        return None;
    }
    let mut value = 0u32;
    for (index, offset) in (1..10).zip([8, 7, 6, 5, 4, 3, 2, 1, 0]) {
        if bits[index] != '-' {
            value |= 1 << offset;
        }
    }
    Some(value)
}

#[async_trait]
impl Filesystem for DaytonaFs {
    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", sandbox_id = %self.sandbox_id),
        err
    )]
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        self.service()
            .await?
            .download_file(&self.resolve(path))
            .await
            .map_err(|error| {
                if is_not_found(&error) {
                    Error::NotFound {
                        resource: ResourceKind::File,
                        id:       path.to_owned(),
                    }
                } else {
                    daytona_error("reading file", error)
                }
            })
    }

    #[tracing::instrument(
        skip_all,
        fields(
            provider_kind = "daytona",
            sandbox_id = %self.sandbox_id,
            byte_count = content.len()
        ),
        err
    )]
    async fn write(&self, path: &str, content: &[u8]) -> Result<()> {
        let full = self.resolve(path);
        let service = self.service().await?;
        // Upload first: the common case has an existing parent, and
        // some toolbox versions error on creating one that exists. On
        // failure, create the parent (best-effort — the retried upload
        // is the arbiter) and try once more.
        match service.upload_file_bytes(&full, content).await {
            Ok(()) => return Ok(()),
            Err(first_error) => {
                let Some((parent, _)) = full.rsplit_once('/') else {
                    return Err(daytona_error("writing file", first_error));
                };
                if parent.is_empty() {
                    return Err(daytona_error("writing file", first_error));
                }
                let _ = service.create_folder(parent, Some("0755")).await;
            }
        }
        service
            .upload_file_bytes(&full, content)
            .await
            .map_err(|error| daytona_error("writing file", error))
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", sandbox_id = %self.sandbox_id, recursive),
        err
    )]
    async fn delete(&self, path: &str, recursive: bool) -> Result<()> {
        match self
            .service()
            .await?
            .delete_file(&self.resolve(path), recursive)
            .await
        {
            Ok(()) => Ok(()),
            Err(error) if is_not_found(&error) => Ok(()),
            Err(error) => Err(daytona_error("deleting file", error)),
        }
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.sandbox_id), err)]
    async fn exists(&self, path: &str) -> Result<bool> {
        match self
            .service()
            .await?
            .get_file_info(&self.resolve(path))
            .await
        {
            Ok(_) => Ok(true),
            Err(error) if is_not_found(&error) => Ok(false),
            // The toolbox reports missing paths as a plain 400/500 in some
            // versions; treat any error mentioning existence as absence.
            Err(error) if error.to_string().contains("no such file") => Ok(false),
            Err(error) => Err(daytona_error("checking file existence", error)),
        }
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.sandbox_id), err)]
    async fn metadata(&self, path: &str) -> Result<FileMetadata> {
        let info = self
            .service()
            .await?
            .get_file_info(&self.resolve(path))
            .await
            .map_err(|error| daytona_error("reading file metadata", error))?;
        let kind = if info.is_dir {
            FileKind::Directory
        } else {
            FileKind::File
        };
        let mut metadata = FileMetadata::new(kind, u64::try_from(info.size).unwrap_or_default());
        metadata.mode = parse_mode(&info.mode);
        metadata.modified_at =
            parse_rfc3339_epoch(&info.mod_time).map(|secs| UNIX_EPOCH + Duration::from_secs(secs));
        Ok(metadata)
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", sandbox_id = %self.sandbox_id, depth),
        err
    )]
    async fn list_dir(&self, path: &str, depth: usize) -> Result<Vec<DirEntry>> {
        let depth = i32::try_from(depth.max(1)).unwrap_or(i32::MAX);
        let files = self
            .service()
            .await?
            .list_files_with_depth(&self.resolve(path), Some(depth))
            .await
            .map_err(|error| daytona_error("listing directory", error))?;
        let mut entries: Vec<DirEntry> = files
            .into_iter()
            .map(|info| {
                let kind = if info.is_dir {
                    FileKind::Directory
                } else {
                    FileKind::File
                };
                let mut entry = DirEntry::new(info.name, kind);
                if kind == FileKind::File {
                    entry.size = u64::try_from(info.size).ok();
                }
                entry
            })
            .collect();
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.sandbox_id), err)]
    async fn create_dir(&self, path: &str) -> Result<()> {
        self.service()
            .await?
            .create_folder(&self.resolve(path), Some("0755"))
            .await
            .map_err(|error| daytona_error("creating directory", error))
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.sandbox_id), err)]
    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.service()
            .await?
            .move_files(&self.resolve(from), &self.resolve(to))
            .await
            .map_err(|error| daytona_error("renaming", error))
    }

    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", sandbox_id = %self.sandbox_id, mode),
        err
    )]
    async fn set_permissions(&self, path: &str, mode: u32) -> Result<()> {
        let options = SetFilePermissionsOptions {
            mode:  Some(format!("{mode:o}")),
            owner: None,
            group: None,
        };
        self.service()
            .await?
            .set_file_permissions(&self.resolve(path), options)
            .await
            .map_err(|error| daytona_error("setting permissions", error))
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.sandbox_id), err)]
    async fn upload(&self, local: &Path, remote: &str) -> Result<()> {
        let content = tokio_fs::read(local)
            .await
            .map_err(|error| Error::io(format!("reading {}", local.display()), error))?;
        self.write(remote, &content).await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "daytona", sandbox_id = %self.sandbox_id), err)]
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

/// Parses an RFC 3339 timestamp to epoch seconds without a date library:
/// good enough for metadata display.
fn parse_rfc3339_epoch(text: &str) -> Option<u64> {
    let date = text.get(0..10)?;
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    let hour: i64 = text.get(11..13)?.parse().ok()?;
    let minute: i64 = text.get(14..16)?.parse().ok()?;
    let second: i64 = text.get(17..19)?.parse().ok()?;
    // Days since epoch via the civil-days algorithm.
    let year_adjusted = if month <= 2 { year - 1 } else { year };
    let era = year_adjusted.div_euclid(400);
    let year_of_era = year_adjusted - era * 400;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    u64::try_from(days * 86_400 + hour * 3_600 + minute * 60 + second).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_octal_and_symbolic_modes() {
        assert_eq!(parse_mode("600"), Some(0o600));
        assert_eq!(parse_mode("-rw-------"), Some(0o600));
        assert_eq!(parse_mode("drwxr-xr-x"), Some(0o755));
    }

    #[test]
    fn parses_rfc3339_to_epoch() {
        assert_eq!(parse_rfc3339_epoch("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_epoch("2026-01-01T00:00:00Z"),
            Some(1_767_225_600)
        );
    }
}
