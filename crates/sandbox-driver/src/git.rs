use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Low-level git plumbing inside a sandbox, with per-call credentials.
///
/// This is deliberately plumbing only: credential leasing, push retry
/// engines, clone orchestration, and repo layout live above this crate.
/// The library will ship an exec-derived implementation; providers with a
/// native git API declare `Capabilities::git.native = true`.
#[async_trait]
pub trait Git: Send + Sync {
    async fn clone_repo(
        &self,
        url: &str,
        target_path: &str,
        options: &GitCloneOptions,
    ) -> Result<()>;

    async fn status(&self, repo_path: &str) -> Result<GitStatus>;

    async fn add(&self, repo_path: &str, paths: &[String]) -> Result<()>;

    /// Commits staged changes; returns the new commit SHA.
    async fn commit(&self, repo_path: &str, options: &GitCommitOptions) -> Result<String>;

    async fn push(&self, repo_path: &str, options: &GitPushOptions) -> Result<()>;

    async fn pull(&self, repo_path: &str, credentials: Option<&GitCredentials>) -> Result<()>;

    async fn branches(&self, repo_path: &str) -> Result<GitBranches>;

    async fn checkout(&self, repo_path: &str, branch: &str, create: bool) -> Result<()>;
}

/// Per-call git credentials (a PAT travels as the password).
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitCredentials {
    pub username: String,
    pub password: String,
}

impl GitCredentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

impl fmt::Debug for GitCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitCloneOptions {
    pub branch:      Option<String>,
    pub commit:      Option<String>,
    pub depth:       Option<u32>,
    pub credentials: Option<GitCredentials>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitCommitOptions {
    pub message:      String,
    pub author_name:  String,
    pub author_email: String,
    pub allow_empty:  bool,
}

impl GitCommitOptions {
    pub fn new(
        message: impl Into<String>,
        author_name: impl Into<String>,
        author_email: impl Into<String>,
    ) -> Self {
        Self {
            message:      message.into(),
            author_name:  author_name.into(),
            author_email: author_email.into(),
            allow_empty:  false,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitPushOptions {
    pub remote:       Option<String>,
    pub branch:       Option<String>,
    pub set_upstream: bool,
    pub credentials:  Option<GitCredentials>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitStatus {
    pub current_branch: Option<String>,
    pub detached:       bool,
    pub ahead:          u32,
    pub behind:         u32,
    /// Paths with uncommitted changes.
    pub dirty_paths:    Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitBranches {
    pub current:  Option<String>,
    pub branches: Vec<String>,
}
