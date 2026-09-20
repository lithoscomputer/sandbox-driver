//! Cloning: a plain branch clone, or a clone pinned to a commit or tag.

use super::DerivedGit;
use super::command::{CLONE_TIMEOUT, GitCommand};
use super::credentials::authed_url;
use crate::error::Result;
use crate::git::{GitCloneOptions, validate_branch_name};

/// The revision a clone is pinned to: a commit SHA or a tag.
#[derive(Clone, Copy)]
enum Pin<'a> {
    Commit(&'a str),
    Tag(&'a str),
}

impl Pin<'_> {
    /// What `git fetch` is asked for. A commit is fetched by SHA; a tag
    /// by its fully qualified ref into the same local ref, so a branch
    /// of the same name is never selected and the tag remains
    /// resolvable in the checkout.
    fn fetch_refspec(&self) -> String {
        match self {
            Self::Commit(commit) => (*commit).to_owned(),
            Self::Tag(tag) => format!("+refs/tags/{tag}:refs/tags/{tag}"),
        }
    }

    /// The revision the checkout attaches to or detaches at.
    fn revision(&self) -> String {
        match self {
            Self::Commit(commit) => (*commit).to_owned(),
            Self::Tag(tag) => format!("refs/tags/{tag}"),
        }
    }
}

impl DerivedGit<'_> {
    /// The body of [`Git::clone_repo`](crate::git::Git::clone_repo).
    pub(super) async fn clone_into(
        &self,
        url: &str,
        target_path: &str,
        options: &GitCloneOptions,
    ) -> Result<()> {
        options.validate()?;
        // Credentials travel in a per-call insteadOf rewrite, exactly as
        // push/pull do. The rewrite applies wherever the plain URL is
        // fetched from — positional or via the configured remote — while
        // `remote.origin.url` stays plain.
        let rewrite = options
            .credentials
            .as_ref()
            .and_then(|credentials| authed_url(url, credentials))
            .map(|authed| format!("url.{authed}.insteadOf={url}"));

        let pin = match (&options.commit, &options.tag) {
            (Some(commit), _) => Some(Pin::Commit(commit)),
            (None, Some(tag)) => Some(Pin::Tag(tag)),
            (None, None) => None,
        };
        if let Some(pin) = pin {
            return self
                .clone_pinned(url, target_path, options, pin, rewrite.as_deref())
                .await;
        }

        let clone = GitCommand::new("git clone", "clone")
            .configs(rewrite)
            .option("--depth", options.depth)
            .option("--branch", options.branch.as_deref())
            // git implies --single-branch only under --depth; without
            // it a branch clone would still fetch every other branch.
            .flag_if(options.branch.is_some(), "--single-branch")
            .arg("--no-tags")
            // End option parsing so a URL or path starting with `-` cannot
            // be read as a flag.
            .args(["--", url, target_path])
            .timeout(CLONE_TIMEOUT);
        self.run(None, clone).await?;
        Ok(())
    }

    /// Pinned clone: init, add the remote, fetch the pinned revision
    /// directly, and check it out.
    ///
    /// A plain clone only fetches the tip of one branch under
    /// `--depth`/`--single-branch`, so a pinned commit outside that
    /// window was never fetched and the checkout fails. Fetching the
    /// SHA or tag itself keeps the pin independent of both depth and
    /// branch; an unavailable revision fails rather than falling back to
    /// the branch head.
    async fn clone_pinned(
        &self,
        url: &str,
        target_path: &str,
        options: &GitCloneOptions,
        pin: Pin<'_>,
        rewrite: Option<&str>,
    ) -> Result<()> {
        self.run(
            None,
            GitCommand::new("git init", "init").args(["--", target_path]),
        )
        .await?;
        self.run(
            Some(target_path),
            GitCommand::new("git remote add", "remote").args(["add", "--", "origin", url]),
        )
        .await?;

        let fetch = GitCommand::new("git fetch", "fetch")
            .configs(rewrite)
            .option("--depth", options.depth)
            .args(["--no-tags", "origin", "--"])
            .arg(pin.fetch_refspec())
            .timeout(CLONE_TIMEOUT);
        self.run(Some(target_path), fetch).await?;

        let revision = pin.revision();
        if let Some(branch) = &options.branch {
            return self
                .attach_pinned_branch(target_path, branch, &revision)
                .await;
        }
        let checkout = GitCommand::new("git checkout", "checkout")
            .arg("--detach")
            .arg(revision)
            // Forces revision interpretation: a bare name that also
            // matches a path would otherwise be ambiguous.
            .arg("--");
        self.run(Some(target_path), checkout).await?;
        Ok(())
    }

    /// Points `branch` at `revision` (a commit SHA or a fully qualified
    /// ref) and attaches HEAD to it (`checkout -B`), so callers that
    /// read the current branch back out of the workspace see the
    /// requested name instead of a detached HEAD — and a later push of
    /// that branch carries the work done since the clone. fabro attached
    /// pinned checkouts on every provider for exactly this reason.
    pub async fn attach_pinned_branch(
        &self,
        repo_path: &str,
        branch: &str,
        revision: &str,
    ) -> Result<()> {
        validate_branch_name(branch)?;
        let checkout = GitCommand::new("git checkout", "checkout")
            .arg("-B")
            .arg(branch)
            .arg(revision)
            .arg("--");
        self.run(Some(repo_path), checkout).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Error, GitFailureKind};
    use crate::git::{Git, GitCredentials};
    use crate::test_exec::ScriptedExec;

    #[tokio::test]
    async fn clone_stays_single_branch_without_tags() {
        let exec = ScriptedExec::new(vec![ScriptedExec::ok("")]);
        let git = DerivedGit::new(&exec);
        let options = GitCloneOptions {
            branch: Some("main".to_owned()),
            ..GitCloneOptions::default()
        };
        git.clone_repo("https://github.com/org/repo.git", "/dst", &options)
            .await
            .expect("clone succeeds");
        let command = &exec.commands()[0];
        // Without --depth, git only fetches one branch under an explicit
        // --single-branch; --no-tags and the -- separator complete the
        // pinned shape.
        assert!(
            command.contains("'--branch' 'main' '--single-branch' '--no-tags' '--'"),
            "clone: {command}"
        );
    }

    #[tokio::test]
    async fn pinned_clone_fetches_the_commit_directly() {
        let exec = ScriptedExec::new(ScriptedExec::succeeding(4));
        let git = DerivedGit::new(&exec);
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let options = GitCloneOptions {
            branch: Some("main".to_owned()),
            commit: Some(sha.to_owned()),
            depth: Some(1),
            credentials: Some(GitCredentials::new("user", "pass")),
            ..GitCloneOptions::default()
        };
        git.clone_repo("https://github.com/org/repo.git", "/dst", &options)
            .await
            .expect("pinned clone succeeds");

        let commands = exec.commands();
        assert!(
            commands[0].contains("'init' '--' '/dst'"),
            "{}",
            commands[0]
        );
        assert!(
            commands[1].contains("'remote' 'add' '--' 'origin' 'https://github.com/org/repo.git'"),
            "{}",
            commands[1]
        );
        // The SHA is fetched directly — a branch or depth never
        // constrains which revision arrives — with credentials in the
        // per-call rewrite only.
        assert!(
            commands[2].contains(
                "'-c' 'url.https://user:pass@github.com/org/repo.git.insteadOf=https://github.com/org/repo.git'"
            ),
            "{}",
            commands[2]
        );
        assert!(
            commands[2].contains(&format!(
                "'fetch' '--depth' '1' '--no-tags' 'origin' '--' '{sha}'"
            )),
            "{}",
            commands[2]
        );
        // With a branch given, the checkout attaches the admitted
        // branch at the pinned commit instead of detaching.
        assert!(
            commands[3].contains(&format!("'checkout' '-B' 'main' '{sha}' '--'")),
            "{}",
            commands[3]
        );
    }

    #[tokio::test]
    async fn pinned_clone_without_a_branch_stays_detached() {
        let exec = ScriptedExec::new(ScriptedExec::succeeding(4));
        let git = DerivedGit::new(&exec);
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let options = GitCloneOptions {
            commit: Some(sha.to_owned()),
            ..GitCloneOptions::default()
        };
        git.clone_repo("https://github.com/org/repo.git", "/dst", &options)
            .await
            .expect("pinned clone succeeds");
        let commands = exec.commands();
        assert!(
            commands[3].contains(&format!("'checkout' '--detach' '{sha}' '--'")),
            "{}",
            commands[3]
        );
    }

    #[tokio::test]
    async fn tag_clone_fetches_the_qualified_tag_ref_and_attaches_the_branch() {
        let exec = ScriptedExec::new(ScriptedExec::succeeding(4));
        let git = DerivedGit::new(&exec);
        let options = GitCloneOptions {
            branch: Some("main".to_owned()),
            tag: Some("v1.2.0".to_owned()),
            depth: Some(1),
            ..GitCloneOptions::default()
        };
        git.clone_repo("https://github.com/org/repo.git", "/dst", &options)
            .await
            .expect("tag clone succeeds");

        let commands = exec.commands();
        assert!(
            commands[0].contains("'init' '--' '/dst'"),
            "{}",
            commands[0]
        );
        // The tag is fetched by its fully qualified ref into the same
        // local ref: a branch named v1.2.0 can never be selected, and
        // the tag stays resolvable in the checkout.
        assert!(
            commands[2].contains(
                "'fetch' '--depth' '1' '--no-tags' 'origin' '--' '+refs/tags/v1.2.0:refs/tags/v1.2.0'"
            ),
            "{}",
            commands[2]
        );
        assert!(
            commands[3].contains("'checkout' '-B' 'main' 'refs/tags/v1.2.0' '--'"),
            "{}",
            commands[3]
        );
    }

    #[tokio::test]
    async fn tag_clone_without_a_branch_stays_detached() {
        let exec = ScriptedExec::new(ScriptedExec::succeeding(4));
        let git = DerivedGit::new(&exec);
        let options = GitCloneOptions {
            tag: Some("v1".to_owned()),
            ..GitCloneOptions::default()
        };
        git.clone_repo("https://github.com/org/repo.git", "/dst", &options)
            .await
            .expect("tag clone succeeds");
        let commands = exec.commands();
        assert!(
            commands[3].contains("'checkout' '--detach' 'refs/tags/v1' '--'"),
            "{}",
            commands[3]
        );
    }

    #[tokio::test]
    async fn clone_rejects_a_tag_combined_with_a_commit() {
        let exec = ScriptedExec::new(vec![]);
        let git = DerivedGit::new(&exec);
        let options = GitCloneOptions {
            commit: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
            tag: Some("v1".to_owned()),
            ..GitCloneOptions::default()
        };
        let error = git
            .clone_repo("https://github.com/org/repo.git", "/dst", &options)
            .await
            .expect_err("two pins are rejected");
        assert!(matches!(error, Error::InvalidSpec { .. }), "{error}");
        assert!(exec.commands().is_empty(), "no command may run");
    }

    #[tokio::test]
    async fn clone_rejects_a_malformed_tag_before_any_command() {
        let exec = ScriptedExec::new(vec![]);
        let git = DerivedGit::new(&exec);
        for tag in [
            "-q",
            "",
            "a..b",
            "release/",
            "v1.lock",
            "has space",
            "v1^{}",
        ] {
            let options = GitCloneOptions {
                tag: Some(tag.to_owned()),
                ..GitCloneOptions::default()
            };
            let error = git
                .clone_repo("https://github.com/org/repo.git", "/dst", &options)
                .await
                .expect_err("malformed tag is rejected");
            assert!(
                matches!(error, Error::InvalidSpec { .. }),
                "{tag:?}: {error}"
            );
        }
        assert!(exec.commands().is_empty(), "no command may run");
    }

    #[tokio::test]
    async fn failed_commands_surface_as_classified_git_failures() {
        let exec = ScriptedExec::new(vec![ScriptedExec::failed_with_stderr(
            128,
            "remote: Repository not found.\nfatal: repository 'https://github.com/o/r.git/' not found",
        )]);
        let git = DerivedGit::new(&exec);
        let options = GitCloneOptions {
            branch: Some("main".to_owned()),
            depth: Some(1),
            ..GitCloneOptions::default()
        };
        let error = git
            .clone_repo("https://github.com/o/r.git", "/dst", &options)
            .await
            .expect_err("clone fails");
        let Error::Git(failure) = error else {
            panic!("expected a git failure, got {error}");
        };
        assert_eq!(failure.operation(), "git clone");
        assert_eq!(failure.kind(), GitFailureKind::AuthRejected);
        let output = failure.output().expect("command output is attached");
        assert_eq!(output.exit_code(), Some(128));
        assert!(
            String::from_utf8_lossy(output.stderr()).contains("Repository not found"),
            "raw stderr is reachable through the accessor"
        );
        assert!(
            !failure.to_string().contains("github.com"),
            "display never carries raw output: {failure}"
        );
    }

    #[tokio::test]
    async fn a_missing_tag_is_a_ref_not_found_failure() {
        let exec = ScriptedExec::new(vec![
            ScriptedExec::ok(""),
            ScriptedExec::ok(""),
            ScriptedExec::failed_with_stderr(
                128,
                "fatal: couldn't find remote ref refs/tags/v9.9.9",
            ),
        ]);
        let git = DerivedGit::new(&exec);
        let options = GitCloneOptions {
            tag: Some("v9.9.9".to_owned()),
            ..GitCloneOptions::default()
        };
        let error = git
            .clone_repo("https://github.com/o/r.git", "/dst", &options)
            .await
            .expect_err("clone fails");
        assert!(
            matches!(&error, Error::Git(failure)
                if failure.kind() == GitFailureKind::RefNotFound && failure.operation() == "git fetch"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn clone_rejects_a_flag_shaped_commit_before_any_command() {
        let exec = ScriptedExec::new(vec![]);
        let git = DerivedGit::new(&exec);
        let options = GitCloneOptions {
            // Parsed as a flag by the old code: `checkout --detach -q`
            // exited 0 at the branch tip while pinning nothing.
            commit: Some("-q".to_owned()),
            ..GitCloneOptions::default()
        };
        let error = git
            .clone_repo("https://github.com/org/repo.git", "/dst", &options)
            .await
            .expect_err("flag-shaped commit is rejected");
        assert!(matches!(error, Error::InvalidSpec { .. }), "{error}");
        assert!(exec.commands().is_empty(), "no command may run");
    }

    #[tokio::test]
    async fn clone_credentials_travel_in_the_rewrite_not_the_url() {
        let exec = ScriptedExec::new(vec![ScriptedExec::ok("")]);
        let git = DerivedGit::new(&exec);
        let options = GitCloneOptions {
            credentials: Some(GitCredentials::new("user", "pass")),
            ..GitCloneOptions::default()
        };
        git.clone_repo("https://github.com/org/repo.git", "/dst", &options)
            .await
            .expect("clone succeeds");
        let command = &exec.commands()[0];
        assert!(
            command.contains(
                "'-c' 'url.https://user:pass@github.com/org/repo.git.insteadOf=https://github.com/org/repo.git'"
            ),
            "clone: {command}"
        );
        // The positional URL stays plain, so git records a plain
        // `remote.origin.url` and the credentials never reach
        // .git/config.
        assert!(
            command.contains("'--' 'https://github.com/org/repo.git' '/dst'"),
            "clone: {command}"
        );
    }
}
