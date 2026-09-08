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

    /// Ends the caller's use of `preview_url(port)`.
    ///
    /// A provider that holds resources for the port on the caller's behalf
    /// (the Docker provider's local port forward) closes them; one whose
    /// URLs hold nothing returns `Ok`. Releasing a port that was never
    /// requested, or twice, succeeds. Every port is released when the
    /// sandbox stops or is deleted.
    async fn release_preview_url(&self, port: u16) -> Result<()> {
        let _ = port;
        Ok(())
    }
}

/// A URL plus the headers needed to use it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PreviewUrl {
    pub url:        String,
    #[serde(default)]
    pub headers:    BTreeMap<String, String>,
    #[serde(default)]
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
    /// Returns ready-to-run SSH access.
    ///
    /// With no TTL, the provider may return stable access or use its
    /// default temporary lifetime. With a TTL, the provider must honor it
    /// and declare `access.ssh.ttl`, or return `Unsupported` for that
    /// capability.
    async fn ssh_access(&self, ttl: Option<Duration>) -> Result<SshAccessInfo>;

    /// Revokes previously returned access by its token.
    async fn revoke_ssh_access(&self, token: &str) -> Result<()> {
        let _ = token;
        Err(Error::unsupported(Capability::SshRevoke))
    }
}

/// Minted SSH access.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SshAccessInfo {
    /// Ready-to-run command, e.g. `ssh user@gateway -p 2222`.
    pub command:    String,
    #[serde(default)]
    pub token:      Option<String>,
    #[serde(default)]
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
    #[serde(default)]
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
