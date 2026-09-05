//! Durable Host records. The caller owns the registry directory and must use
//! one provider process at a time. Records contain explicit sandbox env, so
//! directories and files are private to that user.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{io, process};

use sandbox_driver::{
    Error, ResourceKind, Result, SandboxId, SandboxState, SandboxStatus, WorkspaceOwnership,
};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::AsyncWriteExt;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Record {
    pub(crate) version:    u32,
    pub(crate) id:         SandboxId,
    pub(crate) name:       Option<String>,
    pub(crate) workspace:  PathBuf,
    pub(crate) ownership:  WorkspaceOwnership,
    pub(crate) env:        BTreeMap<String, String>,
    pub(crate) labels:     BTreeMap<String, String>,
    pub(crate) state:      SandboxState,
    pub(crate) created_at: SystemTime,
}

impl Record {
    /// The reported view of a record. `state` is the live value when a
    /// handle exists and the stored one when only the record does, so
    /// `describe` and `list` report a sandbox identically.
    pub(crate) fn status(&self, state: SandboxState) -> SandboxStatus {
        let mut status = SandboxStatus::new(self.id.clone(), state);
        status.name.clone_from(&self.name);
        status.provider_state = format!("{state:?}").to_lowercase();
        status.labels.clone_from(&self.labels);
        status.workspace_ownership = Some(self.ownership);
        status.created_at = Some(self.created_at);
        status
    }
}

pub(crate) fn fresh_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!(
        "g{nanos:x}-{}-{}",
        process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

pub(crate) async fn private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder
        .create(path)
        .await
        .map_err(|e| Error::io("creating host registry directory", e))
}

pub(crate) fn resource_dir(root: &Path, id: &SandboxId) -> Result<PathBuf> {
    let text = id.as_str();
    if !text.starts_with("host-") || !text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(missing(id));
    }
    Ok(root.join(text))
}

pub(crate) fn missing(id: &SandboxId) -> Error {
    Error::NotFound {
        resource: ResourceKind::Sandbox,
        id:       id.as_str().to_owned(),
    }
}

pub(crate) async fn read(root: &Path, id: &SandboxId) -> Result<Record> {
    let directory = resource_dir(root, id)?;
    let bytes = fs::read(directory.join("record.json")).await.map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            missing(id)
        } else {
            Error::io("reading host sandbox record", e)
        }
    })?;
    let record: Record = serde_json::from_slice(&bytes)
        .map_err(|e| Error::io("decoding host sandbox record", e.into()))?;
    if record.version != 1 || &record.id != id || !record.workspace.is_absolute() {
        return Err(Error::io(
            "invalid host sandbox record",
            io::Error::other("record identity, version, or workspace differs"),
        ));
    }
    Ok(record)
}

pub(crate) async fn write(root: &Path, record: &Record) -> Result<()> {
    let directory = resource_dir(root, &record.id)?;
    private_directory(&directory).await?;
    let path = directory.join(format!("{}.tmp", fresh_id()));
    let bytes = serde_json::to_vec(record)
        .map_err(|e| Error::io("encoding host sandbox record", e.into()))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&path)
        .await
        .map_err(|e| Error::io("creating host sandbox record", e))?;
    file.write_all(&bytes)
        .await
        .map_err(|e| Error::io("writing host sandbox record", e))?;
    file.sync_all()
        .await
        .map_err(|e| Error::io("syncing host sandbox record", e))?;
    fs::rename(&path, directory.join("record.json"))
        .await
        .map_err(|e| Error::io("publishing host sandbox record", e))?;
    #[cfg(unix)]
    fs::File::open(&directory)
        .await
        .map_err(|e| Error::io("opening host registry directory", e))?
        .sync_all()
        .await
        .map_err(|e| Error::io("syncing host registry directory", e))?;
    Ok(())
}
