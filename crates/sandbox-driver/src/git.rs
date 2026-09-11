use std::fmt;
use std::time::{Duration, SystemTime};

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
/// Credentials reach a repository two ways. Every network operation takes
/// them per call and applies them to that one command. A workload that
/// runs its own git commands inside the sandbox gets them through
/// [`Git::set_ambient_credentials`], which installs a credential store the
/// repository's helper configuration points at. Neither path writes a
/// credential into a remote URL.
///
/// When a sandbox declares `Capabilities::git.supported`, its image, snapshot,
/// or host environment must provide a `git` executable on `PATH`. Providers do
/// not probe for it. This prerequisite also applies to hybrid providers because
/// any operation they derive through [`crate::Exec`] invokes that executable.
/// A command that fails because the executable is missing is classified as
/// [`crate::GitFailureKind::GitUnavailable`].
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

    /// Installs credentials that every git command run inside the sandbox
    /// picks up for the repository's `origin` remote, or removes them.
    ///
    /// The credentials are written to a git credential store file — under
    /// the sandbox's runtime directory when it has one, otherwise inside
    /// the repository's git directory — and the repository's local
    /// `credential.helper` points at it. The remote URL is never rewritten,
    /// so `git remote -v` and the repository configuration stay free of
    /// secrets. Calling again replaces the stored credentials in place;
    /// git reads the store at each network operation, so an operation
    /// already running is not disturbed. `None` removes the file and the
    /// helper entry and leaves any other configured helper alone.
    ///
    /// Use the same `repo_path` spelling to install and to remove: the
    /// store file's name is derived from it.
    ///
    /// # Errors
    ///
    /// `Some` credentials for a repository whose `origin` is not an
    /// http(s) URL fail with [`crate::Error::InvalidSpec`]; ambient
    /// credentials apply to http(s) remotes only.
    async fn set_ambient_credentials(
        &self,
        repo_path: &str,
        credentials: Option<&GitCredentials>,
    ) -> Result<()>;

    /// Fetches from a remote, with per-call credentials.
    async fn fetch(&self, repo_path: &str, options: &GitFetchOptions) -> Result<()>;

    /// The full object name `revision` resolves to.
    async fn rev_parse(&self, repo_path: &str, revision: &str) -> Result<String>;

    /// Whether `ancestor` is reachable from `descendant`. Both revisions
    /// must exist; an unknown one is an error, not `false`.
    async fn is_ancestor(&self, repo_path: &str, ancestor: &str, descendant: &str) -> Result<bool>;

    /// The paths a range changed, one entry per path, with modes and blobs.
    async fn diff_entries(
        &self,
        repo_path: &str,
        options: &GitDiffOptions,
    ) -> Result<Vec<GitDiffEntry>>;

    /// Lines added and removed per path over a range; binary paths report
    /// neither.
    async fn diff_numstat(
        &self,
        repo_path: &str,
        options: &GitDiffOptions,
    ) -> Result<Vec<GitNumstat>>;

    /// The unified diff of a range, with paths unquoted.
    async fn diff_patch(&self, repo_path: &str, options: &GitDiffOptions) -> Result<String>;

    /// The commits of a range.
    async fn log(&self, repo_path: &str, options: &GitLogOptions) -> Result<Vec<GitCommit>>;

    /// The size of each blob, in the order given; `None` for a blob the
    /// repository does not have.
    async fn blob_sizes(&self, repo_path: &str, blobs: &[String]) -> Result<Vec<Option<u64>>>;

    /// The contents of each blob, in the order given; `None` for a blob the
    /// repository does not have or one larger than `max_bytes`.
    async fn blobs(
        &self,
        repo_path: &str,
        blobs: &[String],
        max_bytes: u64,
    ) -> Result<Vec<Option<Vec<u8>>>>;

    /// Sets one value in the repository's local configuration.
    async fn config_set(&self, repo_path: &str, key: &str, value: &str) -> Result<()>;

    /// Paths in the working tree that git neither tracks nor ignores.
    async fn untracked_files(&self, repo_path: &str) -> Result<Vec<String>>;

    /// Stages every change under `pathspecs` (the whole tree when empty),
    /// including deletions and untracked files.
    async fn add_all(&self, repo_path: &str, pathspecs: &[String]) -> Result<()>;
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

    /// The shared exec-derived implementation. `runtime_directory` is the
    /// sandbox's, when it has one; ambient credential stores live there.
    pub(crate) fn derived(exec: &'a dyn Exec, runtime_directory: Option<&'a str>) -> Self {
        let mut git = DerivedGit::new(exec);
        if let Some(runtime_directory) = runtime_directory {
            git = git.with_runtime_directory(runtime_directory);
        }
        Self {
            implementation: GitImplementation::Derived(git),
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

    async fn set_ambient_credentials(
        &self,
        repo_path: &str,
        credentials: Option<&GitCredentials>,
    ) -> Result<()> {
        self.implementation()
            .set_ambient_credentials(repo_path, credentials)
            .await
    }

    async fn fetch(&self, repo_path: &str, options: &GitFetchOptions) -> Result<()> {
        self.implementation().fetch(repo_path, options).await
    }

    async fn rev_parse(&self, repo_path: &str, revision: &str) -> Result<String> {
        self.implementation().rev_parse(repo_path, revision).await
    }

    async fn is_ancestor(&self, repo_path: &str, ancestor: &str, descendant: &str) -> Result<bool> {
        self.implementation()
            .is_ancestor(repo_path, ancestor, descendant)
            .await
    }

    async fn diff_entries(
        &self,
        repo_path: &str,
        options: &GitDiffOptions,
    ) -> Result<Vec<GitDiffEntry>> {
        self.implementation().diff_entries(repo_path, options).await
    }

    async fn diff_numstat(
        &self,
        repo_path: &str,
        options: &GitDiffOptions,
    ) -> Result<Vec<GitNumstat>> {
        self.implementation().diff_numstat(repo_path, options).await
    }

    async fn diff_patch(&self, repo_path: &str, options: &GitDiffOptions) -> Result<String> {
        self.implementation().diff_patch(repo_path, options).await
    }

    async fn log(&self, repo_path: &str, options: &GitLogOptions) -> Result<Vec<GitCommit>> {
        self.implementation().log(repo_path, options).await
    }

    async fn blob_sizes(&self, repo_path: &str, blobs: &[String]) -> Result<Vec<Option<u64>>> {
        self.implementation().blob_sizes(repo_path, blobs).await
    }

    async fn blobs(
        &self,
        repo_path: &str,
        blobs: &[String],
        max_bytes: u64,
    ) -> Result<Vec<Option<Vec<u8>>>> {
        self.implementation()
            .blobs(repo_path, blobs, max_bytes)
            .await
    }

    async fn config_set(&self, repo_path: &str, key: &str, value: &str) -> Result<()> {
        self.implementation()
            .config_set(repo_path, key, value)
            .await
    }

    async fn untracked_files(&self, repo_path: &str) -> Result<Vec<String>> {
        self.implementation().untracked_files(repo_path).await
    }

    async fn add_all(&self, repo_path: &str, pathspecs: &[String]) -> Result<()> {
        self.implementation().add_all(repo_path, pathspecs).await
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
    pub username:  String,
    pub password:  String,
    /// When the credential was minted, for a short-lived token. A remote
    /// can reject a token for a few seconds after its mint while it
    /// replicates; [`crate::retry_git`] retries a rejection only while the
    /// credential is that fresh. `None` is a fixed credential, which
    /// waiting cannot make valid.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::wire_time::option"
    )]
    pub minted_at: Option<SystemTime>,
}

impl GitCredentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username:  username.into(),
            password:  password.into(),
            minted_at: None,
        }
    }

    /// Records when a short-lived token was minted; see the field.
    #[must_use]
    pub fn minted_at(mut self, minted_at: SystemTime) -> Self {
        self.minted_at = Some(minted_at);
        self
    }
}

impl fmt::Debug for GitCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("minted_at", &self.minted_at)
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
    /// How long the push may run before the provider stops it. The
    /// provider's network default when absent. A caller retrying under a
    /// budget sets what remains of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout:      Option<Duration>,
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

/// Options for [`Git::fetch`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitFetchOptions {
    /// The remote to fetch from; `origin` when absent.
    pub remote:      Option<String>,
    /// Refspecs to fetch; the remote's configured refspecs when empty.
    pub refspecs:    Vec<String>,
    pub depth:       Option<u32>,
    pub credentials: Option<GitCredentials>,
    /// Cap on the whole fetch; the implementation's network timeout when
    /// absent.
    pub timeout:     Option<Duration>,
}

impl GitFetchOptions {
    /// Checks that no remote name or refspec is flag-shaped, so nothing a
    /// caller passes can be read as an option.
    pub fn validate(&self) -> Result<(), crate::Error> {
        if let Some(remote) = &self.remote {
            validate_argument("remote", remote)?;
        }
        for refspec in &self.refspecs {
            validate_argument("refspecs", refspec.trim_start_matches('+'))?;
        }
        Ok(())
    }
}

/// The revisions a diff or log spans, from `base` to `head`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitRevisionRange {
    pub base: String,
    /// The end of the range. A diff without one compares `base` with the
    /// working tree; a log without one ends at `HEAD`.
    pub head: Option<String>,
}

impl GitRevisionRange {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            head: None,
        }
    }

    #[must_use]
    pub fn to(mut self, head: impl Into<String>) -> Self {
        self.head = Some(head.into());
        self
    }

    pub fn validate(&self) -> Result<(), crate::Error> {
        validate_argument("base", &self.base)?;
        if let Some(head) = &self.head {
            validate_argument("head", head)?;
        }
        Ok(())
    }

    /// The range as git reads it, `base..head`, ending at `default_head`
    /// when the range names no head and one is given.
    #[must_use]
    pub fn spec(&self, default_head: Option<&str>) -> String {
        match self.head.as_deref().or(default_head) {
            Some(head) => format!("{}..{head}", self.base),
            None => self.base.clone(),
        }
    }
}

/// Options for [`Git::diff_entries`], [`Git::diff_numstat`], and
/// [`Git::diff_patch`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitDiffOptions {
    pub range:        GitRevisionRange,
    /// Rename detection threshold in percent; renames are reported as a
    /// delete and an add when absent.
    pub find_renames: Option<u8>,
    /// Cap on the command; the implementation's default when absent.
    pub timeout:      Option<Duration>,
}

impl GitDiffOptions {
    pub fn new(range: GitRevisionRange) -> Self {
        Self {
            range,
            find_renames: None,
            timeout: None,
        }
    }

    #[must_use]
    pub fn find_renames(mut self, percent: u8) -> Self {
        self.find_renames = Some(percent);
        self
    }

    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn validate(&self) -> Result<(), crate::Error> {
        self.range.validate()?;
        if self.find_renames.is_some_and(|percent| percent > 100) {
            return Err(crate::Error::invalid_spec(
                "find_renames",
                "is a percentage",
            ));
        }
        Ok(())
    }
}

/// What happened to a path in a diff.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GitChange {
    Added,
    Copied,
    Deleted,
    Modified,
    Renamed,
    /// The path changed kind: file, symlink, or submodule.
    TypeChanged,
    Unmerged,
    /// A status this crate does not know.
    #[serde(other)]
    Unknown,
}

/// One path of a diff, as `git diff --raw` reports it. Modes are git's
/// octal strings (`100644`, `100755`, `120000` for a symlink, `160000` for
/// a submodule); a mode or blob absent on one side is `None`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitDiffEntry {
    pub change:     GitChange,
    /// The path after the change: the new path of a rename or copy.
    pub path:       String,
    /// The path before a rename or copy.
    pub old_path:   Option<String>,
    pub old_mode:   Option<String>,
    pub new_mode:   Option<String>,
    pub old_blob:   Option<String>,
    pub new_blob:   Option<String>,
    /// Similarity of a rename or copy, in percent.
    pub similarity: Option<u8>,
}

/// Lines added and removed on one path, as `git diff --numstat` reports
/// them; both `None` for a binary path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitNumstat {
    /// The path after the change.
    pub path:      String,
    /// The path before a rename.
    pub old_path:  Option<String>,
    pub additions: Option<u64>,
    pub deletions: Option<u64>,
}

/// Options for [`Git::log`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitLogOptions {
    pub range:        GitRevisionRange,
    /// Follow only the first parent of a merge.
    pub first_parent: bool,
    /// Oldest first.
    pub reverse:      bool,
    pub max_count:    Option<u64>,
    /// Cap on the command; the implementation's default when absent.
    pub timeout:      Option<Duration>,
}

impl GitLogOptions {
    pub fn new(range: GitRevisionRange) -> Self {
        Self {
            range,
            first_parent: false,
            reverse: false,
            max_count: None,
            timeout: None,
        }
    }

    #[must_use]
    pub fn first_parent(mut self) -> Self {
        self.first_parent = true;
        self
    }

    #[must_use]
    pub fn reverse(mut self) -> Self {
        self.reverse = true;
        self
    }

    #[must_use]
    pub fn max_count(mut self, count: u64) -> Self {
        self.max_count = Some(count);
        self
    }

    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn validate(&self) -> Result<(), crate::Error> {
        self.range.validate()
    }
}

/// Who wrote or committed a commit, and when (ISO 8601, as git's `%aI`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitIdentity {
    pub name:  String,
    pub email: String,
    pub date:  String,
}

/// One commit of a log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitCommit {
    pub sha:       String,
    pub tree:      String,
    pub parents:   Vec<String>,
    pub author:    GitIdentity,
    pub committer: GitIdentity,
    /// The full message, subject and body, as git stores it.
    pub message:   String,
}

/// Rejects an empty or flag-shaped argument, so a value a caller supplies
/// can never be read as an option.
pub(crate) fn validate_argument(field: &'static str, value: &str) -> Result<(), crate::Error> {
    if value.is_empty() || value.starts_with('-') {
        return Err(crate::Error::invalid_spec(
            field,
            "must not be empty or begin with '-'",
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(crate::Error::invalid_spec(
            field,
            "must not contain control characters",
        ));
    }
    Ok(())
}

/// Rejects anything but a full object name: 40 (SHA-1) or 64 (SHA-256)
/// hex digits.
pub(crate) fn validate_object_name(field: &'static str, value: &str) -> Result<(), crate::Error> {
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(crate::Error::invalid_spec(
            field,
            "must be a full hex object name",
        ));
    }
    Ok(())
}

/// Rejects a configuration key git would not accept: it needs a section
/// and a name, and only letters, digits, `.`, and `-`.
pub(crate) fn validate_config_key(key: &str) -> Result<(), crate::Error> {
    let shape = key.contains('.')
        && !key.starts_with(['.', '-'])
        && !key.ends_with('.')
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if !shape {
        return Err(crate::Error::invalid_spec(
            "key",
            "is not a git configuration key",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitBranches {
    pub current:  Option<String>,
    pub branches: Vec<String>,
}
