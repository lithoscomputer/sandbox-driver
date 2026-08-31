use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::capabilities::Capability;
use crate::error::{Error, Result};

/// Preview URLs for ports inside a sandbox.
#[async_trait]
pub trait PreviewUrls: Send + Sync {
    /// A preview URL for a port, with any headers required to reach it.
    async fn preview_url(&self, port: u16) -> Result<PreviewUrl>;

    /// A signed, expiring preview URL requiring no headers.
    /// Capability-gated on `access.preview_urls.signed`.
    async fn signed_preview_url(&self, port: u16, expires_in: Duration) -> Result<PreviewUrl> {
        let _ = (port, expires_in);
        Err(Error::unsupported(Capability::SignedPreviewUrls))
    }
}

/// A URL plus the headers needed to use it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PreviewUrl {
    pub url:        String,
    pub headers:    BTreeMap<String, String>,
    pub expires_at: Option<SystemTime>,
}

impl PreviewUrl {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url:        url.into(),
            headers:    BTreeMap::new(),
            expires_at: None,
        }
    }
}

/// Real SSH access minted by the provider.
#[async_trait]
pub trait SshAccess: Send + Sync {
    /// Mints time-limited SSH access; returns a ready-to-run command.
    async fn create_ssh_access(&self, ttl: Option<Duration>) -> Result<SshAccessInfo>;

    /// Revokes previously minted access by its token.
    async fn revoke_ssh_access(&self, token: &str) -> Result<()>;
}

/// Minted SSH access.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SshAccessInfo {
    /// Ready-to-run command, e.g. `ssh user@gateway -p 2222`.
    pub command:    String,
    pub token:      Option<String>,
    pub expires_at: Option<SystemTime>,
}

impl SshAccessInfo {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command:    command.into(),
            token:      None,
            expires_at: None,
        }
    }
}

/// A local command that opens a shell in the sandbox — Docker's
/// `docker exec -it …`. Honest about not being SSH.
#[async_trait]
pub trait ShellCommand: Send + Sync {
    /// The local command string that opens an interactive shell.
    async fn shell_command(&self) -> Result<String>;
}

/// Browser-based terminal.
#[async_trait]
pub trait WebTerminal: Send + Sync {
    async fn web_terminal_url(&self) -> Result<String>;
}

/// Desktop viewing connection info. Reserved surface: connection info
/// only in v1.
#[async_trait]
pub trait Vnc: Send + Sync {
    async fn vnc_connection(&self) -> Result<VncConnection>;
}

/// How to reach a sandbox's VNC endpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VncConnection {
    pub url:      String,
    pub password: Option<String>,
}

impl VncConnection {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url:      url.into(),
            password: None,
        }
    }
}
