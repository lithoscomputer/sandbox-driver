//! Reading a git repository inside a sandbox, derived over
//! [`Sandbox::exec`]. These are library code, not a provider capability, so
//! they work unchanged on every provider and plugin whose workload has
//! Bash and `git`.
//!
//! Every command runs hardened: no background maintenance, no repository
//! hooks, no fsmonitor daemon, no external diff driver, no terminal prompt,
//! and no fetch through a local path. Paths come back as git stores them,
//! unquoted. A relative `repo` resolves against the sandbox's working
//! directory.

use std::fmt::Write as _;
use std::time::Duration;

use super::file_ops::{quoted, shell_quote};
use super::{Captured, CommandFailure, ExecSpec, Sandbox, run_captured};

mod failure;
mod model;
mod parse;

pub use failure::{GitError, GitFailure, GitFailureKind};
pub use model::{
    GitChange, GitCommit, GitDiffEntry, GitDiffOptions, GitIdentity, GitLogOptions, GitNumstat,
    GitRevisionRange,
};

/// The budget of a command whose options name none.
const TIMEOUT: Duration = Duration::from_secs(60);

/// What every command here runs as.
const GIT: &str = "git -c maintenance.auto=0 -c gc.auto=0 -c core.hooksPath=/dev/null -c \
                   core.fsmonitor=false -c core.quotePath=false -c commit.gpgsign=false -c \
                   tag.gpgsign=false -c protocol.file.allow=never";

/// The paths a diff between two revisions touches, with each side's mode
/// and blob, as `git diff --raw` reports them.
///
/// # Errors
///
/// [`GitError::Failed`] when git refused, with
/// [`GitFailureKind::RefNotFound`] for a revision that does not exist.
pub async fn git_diff_entries(
    sandbox: &dyn Sandbox,
    repo: &str,
    options: &GitDiffOptions,
) -> Result<Vec<GitDiffEntry>, GitError> {
    options.validate()?;
    // Full blob names, so a caller can hand them straight to the blob
    // helpers.
    let mut words = vec!["diff", "--no-ext-diff", "--raw", "--no-abbrev", "-z"];
    let (renames, range) = (rename_flag(options), options.range.spec(None));
    words.extend(renames.as_deref());
    words.push(&range);
    let label = "git diff --raw";
    let captured = run(sandbox, label, command(repo, &words)?, options.timeout).await?;
    parse::parse_raw_diff(&captured.stdout.bytes).ok_or_else(|| unreadable(label, &captured))
}

/// Lines added and removed per path between two revisions.
///
/// # Errors
///
/// As [`git_diff_entries`].
pub async fn git_diff_numstat(
    sandbox: &dyn Sandbox,
    repo: &str,
    options: &GitDiffOptions,
) -> Result<Vec<GitNumstat>, GitError> {
    options.validate()?;
    let mut words = vec!["diff", "--no-ext-diff", "--numstat", "-z"];
    let (renames, range) = (rename_flag(options), options.range.spec(None));
    words.extend(renames.as_deref());
    words.push(&range);
    let label = "git diff --numstat";
    let captured = run(sandbox, label, command(repo, &words)?, options.timeout).await?;
    parse::parse_numstat(&captured.stdout.bytes).ok_or_else(|| unreadable(label, &captured))
}

/// The diff between two revisions as a patch, without colour. Bytes that
/// are not UTF-8 are replaced.
///
/// # Errors
///
/// As [`git_diff_entries`], and [`GitError::UnexpectedOutput`] for a patch
/// larger than one command's output keeps.
pub async fn git_diff_patch(
    sandbox: &dyn Sandbox,
    repo: &str,
    options: &GitDiffOptions,
) -> Result<String, GitError> {
    options.validate()?;
    let mut words = vec!["diff", "--no-ext-diff", "--no-color"];
    let (renames, range) = (rename_flag(options), options.range.spec(None));
    words.extend(renames.as_deref());
    words.push(&range);
    let captured = run(sandbox, "git diff", command(repo, &words)?, options.timeout).await?;
    Ok(String::from_utf8_lossy(&captured.stdout.bytes).into_owned())
}

/// The commits in a range, newest first unless the options reverse them.
/// The range's `base` itself is not included.
///
/// # Errors
///
/// As [`git_diff_entries`].
pub async fn git_log(
    sandbox: &dyn Sandbox,
    repo: &str,
    options: &GitLogOptions,
) -> Result<Vec<GitCommit>, GitError> {
    options.validate()?;
    let format = format!("--format={}", parse::LOG_FORMAT);
    let mut words = vec!["log", format.as_str()];
    if options.first_parent {
        words.push("--first-parent");
    }
    if options.reverse {
        words.push("--reverse");
    }
    let max_count = options
        .max_count
        .map(|count| format!("--max-count={count}"));
    words.extend(max_count.as_deref());
    let range = options.range.spec(Some("HEAD"));
    words.push(&range);
    let label = "git log";
    let captured = run(sandbox, label, command(repo, &words)?, options.timeout).await?;
    parse::parse_log(&String::from_utf8_lossy(&captured.stdout.bytes))
        .ok_or_else(|| unreadable(label, &captured))
}

/// The size of each object in `blobs`, in their order; `None` for one the
/// repository does not have. Each name is a full hex object name, as
/// [`GitDiffEntry`] carries.
///
/// # Errors
///
/// [`Error::InvalidSpec`](super::Error::InvalidSpec) inside
/// [`GitError::Sandbox`] for anything but a full object name.
pub async fn git_blob_sizes(
    sandbox: &dyn Sandbox,
    repo: &str,
    blobs: &[String],
) -> Result<Vec<Option<u64>>, GitError> {
    if blobs.is_empty() {
        return Ok(Vec::new());
    }
    let label = "git cat-file --batch-check";
    let script = cat_file(repo, blobs, "--batch-check")?;
    let captured = run(sandbox, label, script, None).await?;
    parse::parse_batch_check(
        &String::from_utf8_lossy(&captured.stdout.bytes),
        blobs.len(),
    )
    .ok_or_else(|| unreadable(label, &captured))
}

/// The content of each object in `blobs`, in their order; `None` for one
/// the repository does not have, and for one larger than `max_bytes`.
///
/// Git prints every object whole, so the objects together must fit in what
/// one command's output keeps. Read sizes with [`git_blob_sizes`] first
/// and ask only for the ones you will use.
///
/// # Errors
///
/// As [`git_blob_sizes`], and [`GitError::UnexpectedOutput`] when the
/// objects together were too large.
pub async fn git_blobs(
    sandbox: &dyn Sandbox,
    repo: &str,
    blobs: &[String],
    max_bytes: u64,
) -> Result<Vec<Option<Vec<u8>>>, GitError> {
    if blobs.is_empty() {
        return Ok(Vec::new());
    }
    let label = "git cat-file --batch";
    let captured = run(sandbox, label, cat_file(repo, blobs, "--batch")?, None).await?;
    parse::parse_batch(&captured.stdout.bytes, blobs.len(), max_bytes)
        .ok_or_else(|| unreadable(label, &captured))
}

/// `--find-renames=<n>%`, when rename detection was asked for.
fn rename_flag(options: &GitDiffOptions) -> Option<String> {
    options
        .find_renames
        .map(|percent| format!("--find-renames={percent}%"))
}

/// The hardened git in `repo`, then each word of the command quoted.
fn command(repo: &str, words: &[&str]) -> Result<String, super::Error> {
    let mut script = format!("{GIT} -C {}", quoted("repo", repo)?);
    for word in words {
        let _ = write!(script, " {}", shell_quote(word));
    }
    Ok(script)
}

/// `cat-file <mode>` fed every name in `blobs`, one to a line.
fn cat_file(repo: &str, blobs: &[String], mode: &str) -> Result<String, super::Error> {
    let mut script = String::from("printf '%s\\n'");
    for blob in blobs {
        model::validate_object_name("blobs", blob)?;
        let _ = write!(script, " {}", shell_quote(blob));
    }
    let _ = write!(script, " | {}", command(repo, &["cat-file", mode])?);
    Ok(script)
}

/// Runs one git command to a successful, complete result.
async fn run(
    sandbox: &dyn Sandbox,
    label: &str,
    script: String,
    timeout: Option<Duration>,
) -> Result<Captured, GitError> {
    let mut spec = ExecSpec::bash(script);
    spec.env
        .insert("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned());
    let timeout = timeout.unwrap_or(TIMEOUT).as_millis();
    spec.timeout_ms = Some(u64::try_from(timeout).unwrap_or(u64::MAX));
    let captured = run_captured(sandbox, spec).await?;
    if !captured.success() {
        return Err(GitFailure::new(label, &captured).into());
    }
    if !captured.is_complete() {
        return Err(unreadable(label, &captured));
    }
    Ok(captured)
}

fn unreadable(label: &str, captured: &Captured) -> GitError {
    GitError::UnexpectedOutput(Box::new(CommandFailure::new(label, captured)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_runs_hardened_in_the_repository_with_every_word_quoted() {
        assert_eq!(
            command("it's a repo", &["diff", "--raw", "a..b"]).ok(),
            Some(format!("{GIT} -C 'it'\\''s a repo' 'diff' '--raw' 'a..b'"))
        );
        for setting in [
            "core.hooksPath=/dev/null",
            "core.fsmonitor=false",
            "protocol.file.allow=never",
        ] {
            assert!(GIT.contains(setting), "{setting}");
        }
        assert!(matches!(
            command("", &["log"]),
            Err(super::super::Error::InvalidSpec { .. })
        ));
    }

    #[test]
    fn only_full_object_names_are_fed_to_cat_file() {
        let name = "a".repeat(40);
        assert_eq!(
            cat_file("repo", &[name.clone(), name.clone()], "--batch").ok(),
            Some(format!(
                "printf '%s\\n' '{name}' '{name}' | {GIT} -C 'repo' 'cat-file' '--batch'"
            ))
        );
        assert!(matches!(
            cat_file("repo", &["HEAD; rm -rf /".to_owned()], "--batch"),
            Err(super::super::Error::InvalidSpec { .. })
        ));
    }
}
