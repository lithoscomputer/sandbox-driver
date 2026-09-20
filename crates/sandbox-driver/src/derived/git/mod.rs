mod clone;
mod command;
mod credentials;
mod parse;

use std::time::Duration;

use async_trait::async_trait;

use self::command::{
    GIT_READ, GIT_TIMEOUT, GitCommand, NETWORK_TIMEOUT, feed_object_names, git_failure, git_spec,
    lossy,
};
use self::parse::{
    LOG_FORMAT, batch_header, count_mismatch, parse_batch, parse_log, parse_numstat,
    parse_raw_diff, parse_status_v2,
};
use crate::error::Result;
use crate::exec::{Exec, ExecResult, Termination};
use crate::git::{
    Git, GitBranches, GitCheckoutOptions, GitCloneOptions, GitCommit, GitCommitOptions,
    GitCredentials, GitDiffEntry, GitDiffOptions, GitFetchOptions, GitLogOptions, GitNumstat,
    GitPushOptions, GitStatus, validate_argument, validate_config_key, validate_object_name,
};

/// Exec-derived [`Git`]: plumbing over the `git` CLI.
///
/// The sandbox environment must provide a `git` executable on `PATH`.
///
/// Credentials are applied per call. For `https` remotes they are
/// embedded into the URL used for that one network operation — never
/// written into the repository configuration. Ambient credentials go to
/// a git credential store file under the sandbox's runtime directory, or
/// inside the repository's git directory when the sandbox has none.
pub struct DerivedGit<'e> {
    exec:              &'e dyn Exec,
    runtime_directory: Option<&'e str>,
}

impl<'e> DerivedGit<'e> {
    pub fn new(exec: &'e dyn Exec) -> Self {
        Self {
            exec,
            runtime_directory: None,
        }
    }

    /// Names the sandbox's run-scoped private directory, so ambient
    /// credential stores live outside the repository.
    #[must_use]
    pub fn with_runtime_directory(mut self, directory: &'e str) -> Self {
        self.runtime_directory = Some(directory);
        self
    }

    /// Runs one git command in `repo` and reports a failed one as a
    /// classified git failure under the command's label.
    async fn run(&self, repo: Option<&str>, command: GitCommand) -> Result<ExecResult> {
        self.run_script(command.label, repo, command.script(), None, command.timeout)
            .await
    }

    /// Runs a Bash script and reports a failed one as a classified git
    /// failure under `label`. `secret` travels in the command's
    /// environment, never in its text.
    async fn run_script(
        &self,
        label: &str,
        repo: Option<&str>,
        script: String,
        secret: Option<(&str, &str)>,
        timeout: Duration,
    ) -> Result<ExecResult> {
        let result = self
            .exec
            .run(&git_spec(script, repo, secret, timeout))
            .await?;
        if result.success() {
            return Ok(result);
        }
        Err(git_failure(label, result))
    }

    /// `cat-file <mode>` (`--batch` or `--batch-check`) fed every name in
    /// `blobs`, once each has been validated; the caller reads stdout.
    async fn cat_file_batch(
        &self,
        repo_path: &str,
        blobs: &[String],
        mode: &str,
    ) -> Result<ExecResult> {
        for blob in blobs {
            validate_object_name("blobs", blob)?;
        }
        let script = format!("{} | {GIT_READ} cat-file {mode}", feed_object_names(blobs));
        self.run_script(
            &format!("git cat-file {mode}"),
            Some(repo_path),
            script,
            None,
            GIT_TIMEOUT,
        )
        .await
    }
}

/// `--find-renames=<n>%`, when rename detection was asked for.
fn rename_flag(options: &GitDiffOptions) -> Option<String> {
    options
        .find_renames
        .map(|percent| format!("--find-renames={percent}%"))
}

#[async_trait]
impl Git for DerivedGit<'_> {
    async fn clone_repo(
        &self,
        url: &str,
        target_path: &str,
        options: &GitCloneOptions,
    ) -> Result<()> {
        self.clone_into(url, target_path, options).await
    }

    async fn status(&self, repo_path: &str) -> Result<GitStatus> {
        // `-z` delimits entries with NUL and keeps paths verbatim —
        // without it git C-quotes special-character paths and a newline
        // in a path corrupts adjacent entries.
        let status =
            GitCommand::new("git status", "status").args(["--porcelain=v2", "-z", "--branch"]);
        let result = self.run(Some(repo_path), status).await?;
        Ok(parse_status_v2(&result.stdout_lossy()))
    }

    async fn add(&self, repo_path: &str, paths: &[String]) -> Result<()> {
        let add = GitCommand::new("git add", "add").arg("--").args(paths);
        self.run(Some(repo_path), add).await?;
        Ok(())
    }

    async fn commit(&self, repo_path: &str, options: &GitCommitOptions) -> Result<String> {
        let commit = GitCommand::new("git commit", "commit")
            .config(format!("user.name={}", options.author_name))
            .config(format!("user.email={}", options.author_email))
            .arg("-m")
            .arg(&options.message)
            .flag_if(options.allow_empty, "--allow-empty");
        self.run(Some(repo_path), commit).await?;
        let sha = self
            .run(
                Some(repo_path),
                GitCommand::new("git rev-parse", "rev-parse").arg("HEAD"),
            )
            .await?
            .stdout_lossy();
        Ok(sha.trim().to_owned())
    }

    async fn push(&self, repo_path: &str, options: &GitPushOptions) -> Result<()> {
        options.validate()?;
        let remote = options.remote.as_deref().unwrap_or("origin");
        let rewrite = self
            .credential_rewrite(repo_path, remote, options.credentials.as_ref())
            .await?;
        let push = GitCommand::new("git push", "push")
            .configs(rewrite)
            .flag_if(options.set_upstream, "--set-upstream")
            .arg(remote)
            .args(options.refspec.as_ref().or(options.branch.as_ref()))
            .timeout(options.timeout.unwrap_or(NETWORK_TIMEOUT));
        self.run(Some(repo_path), push).await?;
        Ok(())
    }

    async fn pull(&self, repo_path: &str, credentials: Option<&GitCredentials>) -> Result<()> {
        let rewrite = self
            .credential_rewrite(repo_path, "origin", credentials)
            .await?;
        let pull = GitCommand::new("git pull", "pull")
            .configs(rewrite)
            .arg("origin")
            .timeout(NETWORK_TIMEOUT);
        self.run(Some(repo_path), pull).await?;
        Ok(())
    }

    async fn branches(&self, repo_path: &str) -> Result<GitBranches> {
        // `for-each-ref` lists only real branches; `git branch` would
        // emit a "(HEAD detached at …)" pseudo-entry in detached state.
        let list = self
            .run(
                Some(repo_path),
                GitCommand::new("git for-each-ref", "for-each-ref")
                    .args(["--format=%(refname:short)", "refs/heads"]),
            )
            .await?
            .stdout_lossy();
        let head = self
            .run(
                Some(repo_path),
                GitCommand::new("git rev-parse", "rev-parse").args(["--abbrev-ref", "HEAD"]),
            )
            .await?
            .stdout_lossy();
        let head = head.trim();
        Ok(GitBranches {
            current:  (head != "HEAD").then(|| head.to_owned()),
            branches: list.lines().map(str::to_owned).collect(),
        })
    }

    async fn set_ambient_credentials(
        &self,
        repo_path: &str,
        credentials: Option<&GitCredentials>,
    ) -> Result<()> {
        self.apply_ambient_credentials(repo_path, credentials).await
    }

    async fn fetch(&self, repo_path: &str, options: &GitFetchOptions) -> Result<()> {
        options.validate()?;
        let remote = options.remote.as_deref().unwrap_or("origin");
        let rewrite = self
            .credential_rewrite(repo_path, remote, options.credentials.as_ref())
            .await?;
        let fetch = GitCommand::new("git fetch", "fetch")
            .configs(rewrite)
            .option("--depth", options.depth)
            .arg(remote)
            .args(&options.refspecs)
            .timeout(options.timeout.unwrap_or(NETWORK_TIMEOUT));
        self.run(Some(repo_path), fetch).await?;
        Ok(())
    }

    async fn rev_parse(&self, repo_path: &str, revision: &str) -> Result<String> {
        validate_argument("revision", revision)?;
        let rev_parse = GitCommand::new("git rev-parse", "rev-parse")
            .read_only()
            .args(["--verify", "--end-of-options", revision]);
        let output = self.run(Some(repo_path), rev_parse).await?.stdout_lossy();
        Ok(output.trim().to_owned())
    }

    async fn is_ancestor(&self, repo_path: &str, ancestor: &str, descendant: &str) -> Result<bool> {
        validate_argument("ancestor", ancestor)?;
        validate_argument("descendant", descendant)?;
        // Exit 0 and 1 are the two answers; anything else is a failure.
        let merge_base = GitCommand::new("git merge-base", "merge-base")
            .read_only()
            .args(["--is-ancestor", ancestor, descendant]);
        let result = self
            .exec
            .run(&git_spec(
                merge_base.script(),
                Some(repo_path),
                None,
                merge_base.timeout,
            ))
            .await?;
        match result.exit_code {
            Some(0) if result.termination == Termination::Exited => Ok(true),
            Some(1) if result.termination == Termination::Exited => Ok(false),
            _ => Err(git_failure(merge_base.label, result)),
        }
    }

    async fn diff_entries(
        &self,
        repo_path: &str,
        options: &GitDiffOptions,
    ) -> Result<Vec<GitDiffEntry>> {
        options.validate()?;
        let diff = GitCommand::new("git diff --raw", "diff")
            .read_only()
            .args(["--no-ext-diff", "--raw"])
            // Full blob names, so a caller can hand them straight back to the
            // blob verbs.
            .args(["--no-abbrev", "-z"])
            .args(rename_flag(options))
            .arg(options.range.spec(None))
            .timeout(options.timeout.unwrap_or(GIT_TIMEOUT));
        let result = self.run(Some(repo_path), diff).await?;
        parse_raw_diff(&result.stdout)
    }

    async fn diff_numstat(
        &self,
        repo_path: &str,
        options: &GitDiffOptions,
    ) -> Result<Vec<GitNumstat>> {
        options.validate()?;
        let diff = GitCommand::new("git diff --numstat", "diff")
            .read_only()
            .args(["--no-ext-diff", "--numstat", "-z"])
            .args(rename_flag(options))
            .arg(options.range.spec(None))
            .timeout(options.timeout.unwrap_or(GIT_TIMEOUT));
        let result = self.run(Some(repo_path), diff).await?;
        parse_numstat(&result.stdout)
    }

    async fn diff_patch(&self, repo_path: &str, options: &GitDiffOptions) -> Result<String> {
        options.validate()?;
        let diff = GitCommand::new("git diff", "diff")
            .read_only()
            .args(["--no-ext-diff", "--no-color"])
            .args(rename_flag(options))
            .arg(options.range.spec(None))
            .timeout(options.timeout.unwrap_or(GIT_TIMEOUT));
        let result = self.run(Some(repo_path), diff).await?;
        Ok(result.stdout_lossy())
    }

    async fn log(&self, repo_path: &str, options: &GitLogOptions) -> Result<Vec<GitCommit>> {
        options.validate()?;
        let log = GitCommand::new("git log", "log")
            .read_only()
            .arg(format!("--format={LOG_FORMAT}"))
            .flag_if(options.first_parent, "--first-parent")
            .flag_if(options.reverse, "--reverse")
            .args(
                options
                    .max_count
                    .map(|count| format!("--max-count={count}")),
            )
            .arg(options.range.spec(Some("HEAD")))
            .timeout(options.timeout.unwrap_or(GIT_TIMEOUT));
        let result = self.run(Some(repo_path), log).await?;
        parse_log(&result.stdout_lossy())
    }

    async fn blob_sizes(&self, repo_path: &str, blobs: &[String]) -> Result<Vec<Option<u64>>> {
        if blobs.is_empty() {
            return Ok(Vec::new());
        }
        let result = self
            .cat_file_batch(repo_path, blobs, "--batch-check")
            .await?;
        let sizes = result
            .stdout_lossy()
            .lines()
            .map(|line| {
                batch_header(line)
                    .map(|size| size.map(|size| u64::try_from(size).unwrap_or(u64::MAX)))
            })
            .collect::<Result<Vec<_>>>()?;
        if sizes.len() != blobs.len() {
            return Err(count_mismatch(
                "git cat-file --batch-check",
                sizes.len(),
                blobs.len(),
            ));
        }
        Ok(sizes)
    }

    async fn blobs(
        &self,
        repo_path: &str,
        blobs: &[String],
        max_bytes: u64,
    ) -> Result<Vec<Option<Vec<u8>>>> {
        if blobs.is_empty() {
            return Ok(Vec::new());
        }
        let result = self.cat_file_batch(repo_path, blobs, "--batch").await?;
        parse_batch(&result.stdout, blobs.len(), max_bytes)
    }

    async fn config_set(&self, repo_path: &str, key: &str, value: &str) -> Result<()> {
        validate_config_key(key)?;
        let config = GitCommand::new("git config", "config").args(["--local", "--", key, value]);
        self.run(Some(repo_path), config).await?;
        Ok(())
    }

    async fn untracked_files(&self, repo_path: &str) -> Result<Vec<String>> {
        let ls_files = GitCommand::new("git ls-files", "ls-files")
            .read_only()
            .args(["--others", "--exclude-standard", "-z"]);
        let result = self.run(Some(repo_path), ls_files).await?;
        Ok(result
            .stdout
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
            .map(lossy)
            .collect())
    }

    async fn add_all(&self, repo_path: &str, pathspecs: &[String]) -> Result<()> {
        let add = GitCommand::new("git add", "add").args(["-A", "--"]);
        let add = if pathspecs.is_empty() {
            add.arg(".")
        } else {
            add.args(pathspecs)
        };
        self.run(Some(repo_path), add).await?;
        Ok(())
    }

    async fn checkout(&self, repo_path: &str, options: &GitCheckoutOptions) -> Result<()> {
        options.validate()?;
        let mut checkout = GitCommand::new("git checkout", "checkout");
        if options.create {
            checkout = checkout.arg(if options.reset { "-B" } else { "-b" });
        }
        let checkout = checkout
            .arg(&options.branch)
            .args(options.start_point.as_ref())
            // Forces branch interpretation: a branch that also matches a
            // path would otherwise restore the file instead.
            .arg("--");
        self.run(Some(repo_path), checkout).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use self::command::GIT;
    use super::*;
    use crate::error::Error;
    use crate::test_exec::ScriptedExec;

    #[tokio::test]
    async fn push_addresses_the_remote_by_name_with_a_per_call_rewrite() {
        let exec = ScriptedExec::new(vec![
            ScriptedExec::ok("https://github.com/org/repo.git\n"),
            ScriptedExec::ok(""),
        ]);
        let git = DerivedGit::new(&exec);
        let options = GitPushOptions {
            remote:       None,
            branch:       Some("main".to_owned()),
            set_upstream: true,
            refspec:      None,
            credentials:  Some(GitCredentials::new("user", "pass")),
            timeout:      None,
        };
        git.push("/repo", &options).await.expect("push succeeds");

        let commands = exec.commands();
        assert!(commands[0].contains("'remote' 'get-url' 'origin'"));
        // Credentials travel only in the per-call insteadOf rewrite; the
        // push target stays the remote name, so --set-upstream can never
        // write a credentialed URL into .git/config.
        let push = &commands[1];
        assert!(
            push.contains(
                "'-c' 'url.https://user:pass@github.com/org/repo.git.insteadOf=https://github.com/org/repo.git'"
            ),
            "push: {push}"
        );
        assert!(
            push.contains("'push' '--set-upstream' 'origin' 'main'"),
            "push: {push}"
        );
    }

    #[tokio::test]
    async fn push_sends_a_refspec_in_place_of_a_branch() {
        let exec = ScriptedExec::new(vec![ScriptedExec::ok("")]);
        let git = DerivedGit::new(&exec);
        let options = GitPushOptions {
            refspec: Some("+HEAD:refs/heads/run/42".to_owned()),
            timeout: Some(Duration::from_secs(7)),
            ..GitPushOptions::default()
        };
        git.push("/repo", &options).await.expect("push succeeds");
        assert!(
            exec.commands()[0].contains("'push' 'origin' '+HEAD:refs/heads/run/42'"),
            "push: {}",
            exec.commands()[0]
        );
        assert_eq!(
            exec.timeouts()[0],
            Some(Duration::from_secs(7)),
            "the caller's budget bounds the push"
        );

        let both = GitPushOptions {
            branch: Some("main".to_owned()),
            refspec: Some("HEAD:refs/heads/main".to_owned()),
            ..GitPushOptions::default()
        };
        assert!(both.validate().is_err(), "branch and refspec together");
        let deletion = GitPushOptions {
            refspec: Some(":refs/heads/main".to_owned()),
            ..GitPushOptions::default()
        };
        assert!(deletion.validate().is_err(), "a deletion is not a push");
        let flag = GitPushOptions {
            refspec: Some("--force".to_owned()),
            ..GitPushOptions::default()
        };
        assert!(flag.validate().is_err(), "a refspec cannot be a flag");
        let upstream = GitPushOptions {
            set_upstream: true,
            ..GitPushOptions::default()
        };
        assert!(upstream.validate().is_err(), "set_upstream needs a branch");
    }

    #[tokio::test]
    async fn checkout_creates_or_resets_at_a_start_point() {
        let exec = ScriptedExec::new(ScriptedExec::succeeding(2));
        let git = DerivedGit::new(&exec);
        git.checkout(
            "/repo",
            &GitCheckoutOptions::new("run/42")
                .create_or_reset()
                .start_point("0123456789abcdef0123456789abcdef01234567"),
        )
        .await
        .expect("checkout succeeds");
        git.checkout("/repo", &GitCheckoutOptions::new("main"))
            .await
            .expect("plain checkout succeeds");
        let commands = exec.commands();
        assert!(
            commands[0].contains(
                "'checkout' '-B' 'run/42' '0123456789abcdef0123456789abcdef01234567' '--'"
            ),
            "checkout: {}",
            commands[0]
        );
        assert!(
            commands[1].contains("'checkout' 'main' '--'"),
            "checkout: {}",
            commands[1]
        );

        assert!(
            GitCheckoutOptions::new("main")
                .start_point("HEAD~1")
                .validate()
                .is_err(),
            "a start point needs create"
        );
        let reset_only = GitCheckoutOptions {
            reset: true,
            ..GitCheckoutOptions::new("main")
        };
        assert!(reset_only.validate().is_err(), "reset needs create");
        assert!(
            GitCheckoutOptions::new("main")
                .create()
                .start_point("--detach")
                .validate()
                .is_err(),
            "a start point cannot be a flag"
        );
    }

    #[tokio::test]
    async fn checkout_rejects_a_flag_shaped_branch() {
        let exec = ScriptedExec::new(vec![]);
        let git = DerivedGit::new(&exec);
        let error = git
            .checkout("/repo", &GitCheckoutOptions::new("-q"))
            .await
            .expect_err("flag-shaped branch is rejected");
        assert!(matches!(error, Error::InvalidSpec { .. }), "{error}");
        assert!(exec.commands().is_empty(), "no command may run");
    }

    #[tokio::test]
    async fn commit_reports_the_new_sha() {
        let exec = ScriptedExec::new(vec![ScriptedExec::ok(""), ScriptedExec::ok("abc123\n")]);
        let git = DerivedGit::new(&exec);
        let sha = git
            .commit(
                "/repo",
                &GitCommitOptions::new("msg", "Author", "a@example.com"),
            )
            .await
            .expect("commit succeeds");
        assert_eq!(sha, "abc123");
        let commands = exec.commands();
        assert!(commands[0].contains("'user.name=Author'"));
        assert!(commands[0].contains("'commit' '-m' 'msg'"));
        assert!(commands[1].contains("'rev-parse' 'HEAD'"));
    }

    #[tokio::test]
    async fn read_verbs_run_hardened_and_refuse_the_file_transport() {
        let exec = ScriptedExec::new(vec![ScriptedExec::ok("abc\n")]);
        let git = DerivedGit::new(&exec);
        assert_eq!(
            git.rev_parse("/repo", "HEAD").await.expect("rev-parse"),
            "abc"
        );
        let command = &exec.commands()[0];
        assert!(command.starts_with(GIT_READ), "{command}");
        assert!(command.contains("core.hooksPath=/dev/null"), "{command}");
        assert!(command.contains("protocol.file.allow=never"), "{command}");
        assert!(
            command.contains("'rev-parse' '--verify' '--end-of-options' 'HEAD'"),
            "{command}"
        );
        let env = &exec.envs()[0];
        assert_eq!(
            env.get("GIT_TERMINAL_PROMPT").map(String::as_str),
            Some("0")
        );
        assert!(
            git.rev_parse("/repo", "--output=/etc/passwd")
                .await
                .is_err(),
            "flag-shaped revisions are refused before any command"
        );
        assert_eq!(exec.commands().len(), 1);
    }

    #[tokio::test]
    async fn mutating_verbs_run_hardened_without_refusing_the_file_transport() {
        let exec = ScriptedExec::new(ScriptedExec::succeeding(3));
        let git = DerivedGit::new(&exec);
        git.fetch("/repo", &GitFetchOptions {
            refspecs: vec!["+refs/heads/main:refs/remotes/origin/main".into()],
            ..GitFetchOptions::default()
        })
        .await
        .expect("fetch");
        git.config_set("/repo", "user.name", "Fabro Bot")
            .await
            .expect("config");
        git.add_all("/repo", &[]).await.expect("add");
        let commands = exec.commands();
        assert!(commands[0].starts_with(GIT), "{}", commands[0]);
        assert!(
            !commands[0].contains("protocol.file.allow"),
            "{}",
            commands[0]
        );
        assert!(
            commands[0].contains("'fetch' 'origin' '+refs/heads/main:refs/remotes/origin/main'"),
            "{}",
            commands[0]
        );
        assert!(
            commands[1].contains("'config' '--local' '--' 'user.name' 'Fabro Bot'"),
            "{}",
            commands[1]
        );
        assert!(
            commands[2].contains("'add' '-A' '--' '.'"),
            "{}",
            commands[2]
        );
        assert!(
            git.config_set("/repo", "--file=/etc/x", "y").await.is_err(),
            "a flag-shaped key is refused"
        );
    }

    #[tokio::test]
    async fn is_ancestor_reads_both_answers_and_fails_otherwise() {
        let exec = ScriptedExec::new(vec![
            ScriptedExec::ok(""),
            ScriptedExec::failed(1),
            ScriptedExec::failed_with_stderr(128, "fatal: Not a valid object name nope"),
        ]);
        let git = DerivedGit::new(&exec);
        assert!(git.is_ancestor("/repo", "base", "head").await.expect("yes"));
        assert!(!git.is_ancestor("/repo", "head", "base").await.expect("no"));
        assert!(git.is_ancestor("/repo", "nope", "head").await.is_err());
        assert!(
            exec.commands()[0].contains("'merge-base' '--is-ancestor' 'base' 'head'"),
            "{}",
            exec.commands()[0]
        );
    }
}
