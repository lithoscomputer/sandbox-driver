use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::derived::DerivedGit;
use crate::error::Result;
use crate::exec::Exec;

/// Low-level git plumbing inside a sandbox, with per-call credentials.
///
/// This is deliberately plumbing only: credential leasing, push retry
/// engines, clone orchestration, and repo layout live above this crate.
/// Providers own the choice of transport. They can use their native API,
/// [`DerivedGit`], or a hybrid of both without exposing that choice to callers.
///
/// When a sandbox declares `Capabilities::git.supported`, its image, snapshot,
/// or host environment must provide a `git` executable on `PATH`. Providers do
/// not probe for it. This prerequisite also applies to hybrid providers because
/// any operation they derive through [`crate::Exec`] invokes that executable.
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

    async fn checkout(&self, repo_path: &str, options: &GitCheckoutOptions) -> Result<()>;
}

/// A sandbox's normalized git facet.
///
/// This facade hides whether the provider supplies a custom native or hybrid
/// implementation, or uses the shared exec-derived implementation.
pub struct GitFacet<'a> {
    implementation: GitImplementation<'a>,
}

enum GitImplementation<'a> {
    Provider(&'a dyn Git),
    Derived(DerivedGit<'a>),
}

impl<'a> GitFacet<'a> {
    pub(crate) fn provider(git: &'a dyn Git) -> Self {
        Self {
            implementation: GitImplementation::Provider(git),
        }
    }

    pub(crate) fn derived(exec: &'a dyn Exec) -> Self {
        Self {
            implementation: GitImplementation::Derived(DerivedGit::new(exec)),
        }
    }

    fn implementation(&self) -> &dyn Git {
        match &self.implementation {
            GitImplementation::Provider(git) => *git,
            GitImplementation::Derived(git) => git,
        }
    }
}

#[async_trait]
impl Git for GitFacet<'_> {
    async fn clone_repo(
        &self,
        url: &str,
        target_path: &str,
        options: &GitCloneOptions,
    ) -> Result<()> {
        self.implementation()
            .clone_repo(url, target_path, options)
            .await
    }

    async fn status(&self, repo_path: &str) -> Result<GitStatus> {
        self.implementation().status(repo_path).await
    }

    async fn add(&self, repo_path: &str, paths: &[String]) -> Result<()> {
        self.implementation().add(repo_path, paths).await
    }

    async fn commit(&self, repo_path: &str, options: &GitCommitOptions) -> Result<String> {
        self.implementation().commit(repo_path, options).await
    }

    async fn push(&self, repo_path: &str, options: &GitPushOptions) -> Result<()> {
        self.implementation().push(repo_path, options).await
    }

    async fn pull(&self, repo_path: &str, credentials: Option<&GitCredentials>) -> Result<()> {
        self.implementation().pull(repo_path, credentials).await
    }

    async fn branches(&self, repo_path: &str) -> Result<GitBranches> {
        self.implementation().branches(repo_path).await
    }

    async fn checkout(&self, repo_path: &str, options: &GitCheckoutOptions) -> Result<()> {
        self.implementation().checkout(repo_path, options).await
    }
}

/// Per-call git credentials (a PAT travels as the password).
///
/// Credentials are applied per network operation via command-line
/// configuration, so they are visible to processes that can read the
/// git command's arguments: inside a Docker or Daytona sandbox that
/// means the sandboxed workload itself; on the Host provider it means
/// **every user on the machine** (`ps`). Supply Host-provider
/// credentials only on single-user machines, or rely on ambient
/// authentication (an SSH agent, a configured credential helper)
/// instead of this struct.
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
    /// Full commit SHA to pin the checkout to. With `branch` set, the
    /// checkout ends attached to that branch pointing at the pinned
    /// commit; without one it is left detached. The pin is fetched
    /// directly, so it works with any `depth` and never falls back to
    /// the branch head; `branch` names no constraint on which revision
    /// is fetched.
    pub commit:      Option<String>,
    /// Tag to pin the checkout to, named without the `refs/tags/`
    /// prefix. The tag is fetched by its fully qualified ref, so a
    /// branch of the same name is never selected by mistake, and the
    /// checkout behaves as a `commit` pin at the tagged commit: attached
    /// to `branch` when one is set, detached otherwise. `tag` and
    /// `commit` are alternative pins; setting both is invalid.
    pub tag:         Option<String>,
    pub depth:       Option<u32>,
    pub credentials: Option<GitCredentials>,
}

impl GitCloneOptions {
    /// Checks the options' own invariants: a pinned commit must be a
    /// full 40-hex SHA, a tag or branch cannot be flag-shaped, and at
    /// most one pin is set. Implementations call this before running
    /// anything, so a bad pin fails immediately instead of after the
    /// network operation — and a flag-shaped value can never be read as
    /// an option.
    pub fn validate(&self) -> Result<(), crate::Error> {
        if let Some(commit) = &self.commit {
            if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(crate::Error::invalid_spec(
                    "commit",
                    "must be a full 40-character hex commit SHA",
                ));
            }
        }
        if let Some(tag) = &self.tag {
            validate_ref_name("tag", tag)?;
            if self.commit.is_some() {
                return Err(crate::Error::invalid_spec(
                    "tag",
                    "cannot be combined with commit; a clone has one pin",
                ));
            }
        }
        if let Some(branch) = &self.branch {
            validate_branch_name(branch)?;
        }
        Ok(())
    }
}

/// Rejects branch names git itself would refuse, before they can be
/// read as flags: empty, or beginning with `-` (never a valid ref).
pub(crate) fn validate_branch_name(branch: &str) -> Result<(), crate::Error> {
    validate_ref_name("branch", branch)
}

/// Rejects a push refspec git would misread: each side of `<src>:<dst>`
/// must be a reference name (or `HEAD`), and the whole must not begin
/// with `-`. An optional leading `+` forces the update. A refspec with an
/// empty source deletes the destination and is refused: deletion is not
/// a push.
fn validate_refspec(refspec: &str) -> Result<(), crate::Error> {
    let body = refspec.strip_prefix('+').unwrap_or(refspec);
    let (source, destination) = match body.split_once(':') {
        Some((source, destination)) => (source, Some(destination)),
        None => (body, None),
    };
    if source.is_empty() {
        return Err(crate::Error::invalid_spec(
            "refspec",
            "must name a source; a deletion is not a push",
        ));
    }
    for side in [Some(source), destination].into_iter().flatten() {
        if side != "HEAD" {
            validate_ref_name("refspec", side)?;
        }
    }
    Ok(())
}

/// Rejects a short ref name (a branch or tag) git itself would refuse,
/// before it can be read as a flag or escape its namespace: empty,
/// beginning with `-`, or containing a path component git forbids.
fn validate_ref_name(field: &'static str, name: &str) -> Result<(), crate::Error> {
    if name.is_empty() || name.starts_with('-') {
        return Err(crate::Error::invalid_spec(
            field,
            "must not be empty or begin with '-'",
        ));
    }
    if name.split('/').any(|component| {
        component.is_empty()
            || component == "."
            || component == ".."
            || component.strip_suffix(".lock").is_some()
    }) || name.ends_with('.')
        || name.contains("..")
        || name.contains("@{")
        || name
            .chars()
            .any(|c| c.is_ascii_control() || " ~^:?*[\\".contains(c))
    {
        return Err(crate::Error::invalid_spec(
            field,
            "is not a valid git reference name",
        ));
    }
    Ok(())
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
    /// The branch to push, by its short name.
    pub branch:       Option<String>,
    /// Sets the pushed branch's upstream; requires `branch`.
    pub set_upstream: bool,
    /// An explicit refspec to push instead of a branch: `<src>:<dst>` with
    /// an optional leading `+`, or a single ref. Lets a caller push a
    /// commit to a differently named remote branch or to a ref outside
    /// `refs/heads`. Cannot be combined with `branch`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refspec:      Option<String>,
    pub credentials:  Option<GitCredentials>,
}

impl GitPushOptions {
    pub fn validate(&self) -> Result<(), crate::Error> {
        if let Some(branch) = &self.branch {
            validate_branch_name(branch)?;
        }
        if let Some(refspec) = &self.refspec {
            if self.branch.is_some() {
                return Err(crate::Error::invalid_spec(
                    "refspec",
                    "cannot be combined with branch",
                ));
            }
            validate_refspec(refspec)?;
        }
        if self.set_upstream && self.branch.is_none() {
            return Err(crate::Error::invalid_spec(
                "set_upstream",
                "requires a branch",
            ));
        }
        Ok(())
    }
}

/// Which branch a checkout attaches to, and how it comes to exist.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitCheckoutOptions {
    pub branch:      String,
    /// Creates the branch (`-b`) instead of requiring it to exist.
    pub create:      bool,
    /// With `create`, moves the branch to the start point when it already
    /// exists (`-B`) instead of failing.
    pub reset:       bool,
    /// The revision a created branch starts at: a commit, a branch, or a
    /// fully qualified ref. `HEAD` when absent. Requires `create`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_point: Option<String>,
}

impl GitCheckoutOptions {
    /// Attaches to an existing `branch`.
    pub fn new(branch: impl Into<String>) -> Self {
        Self {
            branch:      branch.into(),
            create:      false,
            reset:       false,
            start_point: None,
        }
    }

    /// Creates `branch` (`-b`), at `HEAD` unless a start point is set.
    #[must_use]
    pub fn create(mut self) -> Self {
        self.create = true;
        self
    }

    /// Creates `branch`, or moves it when it exists (`-B`).
    #[must_use]
    pub fn create_or_reset(mut self) -> Self {
        self.create = true;
        self.reset = true;
        self
    }

    #[must_use]
    pub fn start_point(mut self, revision: impl Into<String>) -> Self {
        self.start_point = Some(revision.into());
        self
    }

    pub fn validate(&self) -> Result<(), crate::Error> {
        validate_branch_name(&self.branch)?;
        if self.reset && !self.create {
            return Err(crate::Error::invalid_spec("reset", "requires create"));
        }
        if let Some(start_point) = &self.start_point {
            if !self.create {
                return Err(crate::Error::invalid_spec("start_point", "requires create"));
            }
            validate_ref_name("start_point", start_point)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitStatus {
    pub current_branch: Option<String>,
    /// The commit `HEAD` points at; `None` on an unborn branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head:           Option<String>,
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
