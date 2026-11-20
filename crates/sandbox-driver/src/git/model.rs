//! What the git helpers take and return.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::Error;

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

    /// # Errors
    ///
    /// [`Error::InvalidSpec`] for a revision git could read as an option.
    pub fn validate(&self) -> Result<(), Error> {
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

/// Options for [`git_diff_entries`](super::git_diff_entries),
/// [`git_diff_numstat`](super::git_diff_numstat) and
/// [`git_diff_patch`](super::git_diff_patch).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitDiffOptions {
    pub range:        GitRevisionRange,
    /// Rename detection threshold in percent. When absent, the
    /// repository's own `diff.renames` setting decides, which detects
    /// renames unless it was turned off.
    pub find_renames: Option<u8>,
    /// Cap on the command; 60 seconds when absent.
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

    /// # Errors
    ///
    /// [`Error::InvalidSpec`] for a revision git could read as an option,
    /// or a threshold above 100.
    pub fn validate(&self) -> Result<(), Error> {
        self.range.validate()?;
        if self.find_renames.is_some_and(|percent| percent > 100) {
            return Err(Error::invalid_spec("find_renames", "is a percentage"));
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
    /// Full object names, which the blob helpers take as they are.
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

/// Options for [`git_log`](super::git_log).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GitLogOptions {
    pub range:        GitRevisionRange,
    /// Follow only the first parent of a merge.
    pub first_parent: bool,
    /// Oldest first.
    pub reverse:      bool,
    pub max_count:    Option<u64>,
    /// Cap on the command; 60 seconds when absent.
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

    /// # Errors
    ///
    /// [`Error::InvalidSpec`] for a revision git could read as an option.
    pub fn validate(&self) -> Result<(), Error> {
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
fn validate_argument(field: &str, value: &str) -> Result<(), Error> {
    if value.is_empty() || value.starts_with('-') {
        return Err(Error::invalid_spec(
            field,
            "must not be empty or begin with '-'",
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(Error::invalid_spec(
            field,
            "must not contain control characters",
        ));
    }
    Ok(())
}

/// Rejects anything but a full object name: 40 (SHA-1) or 64 (SHA-256)
/// hex digits.
pub(super) fn validate_object_name(field: &str, value: &str) -> Result<(), Error> {
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::invalid_spec(field, "must be a full hex object name"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_range_renders_as_git_reads_it() {
        let open = GitRevisionRange::new("main");
        assert_eq!(open.spec(None), "main");
        assert_eq!(open.spec(Some("HEAD")), "main..HEAD");
        assert_eq!(open.to("topic").spec(Some("HEAD")), "main..topic");
    }

    #[test]
    fn a_value_git_could_read_as_an_option_is_refused() {
        let invalid = |result: Result<(), Error>| matches!(result, Err(Error::InvalidSpec { .. }));
        for revision in ["", "-x", "--output=/tmp/x", "a\nb"] {
            assert!(
                invalid(GitRevisionRange::new(revision).validate()),
                "{revision:?}"
            );
            assert!(
                invalid(GitRevisionRange::new("main").to(revision).validate()),
                "{revision:?}"
            );
        }
        assert!(invalid(
            GitDiffOptions::new(GitRevisionRange::new("main"))
                .find_renames(101)
                .validate()
        ));
        assert_eq!(
            GitDiffOptions::new(GitRevisionRange::new("main").to("v1.0^{commit}"))
                .find_renames(100)
                .validate(),
            Ok(())
        );
        for name in ["abc", "g".repeat(40).as_str(), "a".repeat(41).as_str()] {
            assert!(invalid(validate_object_name("blobs", name)), "{name}");
        }
        for name in ["a".repeat(40), "0".repeat(64)] {
            assert_eq!(validate_object_name("blobs", &name), Ok(()));
        }
    }
}
