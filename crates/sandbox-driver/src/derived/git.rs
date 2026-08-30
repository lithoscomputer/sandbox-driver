use std::fmt::Write as _;
use std::time::Duration;

use async_trait::async_trait;

use crate::derived::shell_quote;
use crate::error::{Error, ExecFailure, Result};
use crate::exec::{Exec, ExecResult, ExecSpec};
use crate::git::{
    Git, GitBranches, GitCloneOptions, GitCommitOptions, GitCredentials, GitPushOptions, GitStatus,
};

const GIT_TIMEOUT: Duration = Duration::from_secs(60);
const CLONE_TIMEOUT: Duration = Duration::from_secs(600);
const NETWORK_TIMEOUT: Duration = Duration::from_secs(300);

/// Internal git calls disable background maintenance, as fabro does.
const GIT: &str = "git -c maintenance.auto=0 -c gc.auto=0";

/// Exec-derived [`Git`]: plumbing over the `git` CLI.
///
/// Credentials are applied per call. For `https` remotes they are
/// embedded into the URL used for that one network operation — never
/// written into the repository configuration.
pub struct DerivedGit<'e> {
    exec: &'e dyn Exec,
}

impl<'e> DerivedGit<'e> {
    pub fn new(exec: &'e dyn Exec) -> Self {
        Self { exec }
    }

    async fn run(
        &self,
        label: &str,
        repo: Option<&str>,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecResult> {
        let mut command = String::from(GIT);
        for arg in args {
            command.push(' ');
            command.push_str(&shell_quote(arg));
        }
        let mut spec = ExecSpec::new(command).timeout(timeout);
        if let Some(repo) = repo {
            spec = spec.working_dir(repo.to_owned());
        }
        let result = self.exec.run(&spec).await?;
        if result.success() {
            return Ok(result);
        }
        Err(Error::Exec(ExecFailure::new(
            label,
            result.termination,
            result.exit_code,
            result.stdout,
            result.stderr,
        )))
    }

    /// A per-call config value (`url.<authed>.insteadOf=<plain>`) that
    /// embeds credentials for one network operation via `-c`. The
    /// command still addresses the remote by name, so upstream and
    /// remote-tracking bookkeeping stay on the named remote and the
    /// credentialed URL is never written into the repository
    /// configuration. `None` when the remote is not http(s).
    async fn credential_rewrite(
        &self,
        repo: &str,
        remote: &str,
        credentials: Option<&GitCredentials>,
    ) -> Result<Option<String>> {
        let Some(credentials) = credentials else {
            return Ok(None);
        };
        let url = self
            .run(
                "git remote get-url",
                Some(repo),
                &["remote".into(), "get-url".into(), remote.to_owned()],
                GIT_TIMEOUT,
            )
            .await?
            .stdout_lossy();
        let url = url.trim();
        Ok(authed_url(url, credentials).map(|authed| format!("url.{authed}.insteadOf={url}")))
    }
}

/// Embeds credentials into an http(s) URL; `None` for other schemes.
fn authed_url(url: &str, credentials: &GitCredentials) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    // Existing userinfo ends at the last `@` inside the authority only —
    // an `@` in the path (`/org/repo@v2.git`) is part of the path.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let rest = match rest[..authority_end].rfind('@') {
        Some(at) => &rest[at + 1..],
        None => rest,
    };
    Some(format!(
        "{scheme}://{}:{}@{rest}",
        encode_userinfo(&credentials.username),
        encode_userinfo(&credentials.password),
    ))
}

fn encode_userinfo(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            other => {
                let _ = write!(encoded, "%{other:02X}");
            }
        }
    }
    encoded
}

#[async_trait]
impl Git for DerivedGit<'_> {
    async fn clone_repo(
        &self,
        url: &str,
        target_path: &str,
        options: &GitCloneOptions,
    ) -> Result<()> {
        let mut args: Vec<String> = vec!["clone".into()];
        if let Some(depth) = options.depth {
            args.push("--depth".into());
            args.push(depth.to_string());
        }
        if let Some(branch) = &options.branch {
            args.push("--branch".into());
            args.push(branch.clone());
        }
        let url = options
            .credentials
            .as_ref()
            .and_then(|credentials| authed_url(url, credentials))
            .unwrap_or_else(|| url.to_owned());
        args.push(url);
        args.push(target_path.to_owned());
        self.run("git clone", None, &args, CLONE_TIMEOUT).await?;

        if let Some(commit) = &options.commit {
            self.run(
                "git checkout",
                Some(target_path),
                &["checkout".into(), "--detach".into(), commit.clone()],
                GIT_TIMEOUT,
            )
            .await?;
        }
        Ok(())
    }

    async fn status(&self, repo_path: &str) -> Result<GitStatus> {
        let result = self
            .run(
                "git status",
                Some(repo_path),
                &["status".into(), "--porcelain=v2".into(), "--branch".into()],
                GIT_TIMEOUT,
            )
            .await?;
        Ok(parse_status_v2(&result.stdout_lossy()))
    }

    async fn add(&self, repo_path: &str, paths: &[String]) -> Result<()> {
        let mut args: Vec<String> = vec!["add".into(), "--".into()];
        args.extend(paths.iter().cloned());
        self.run("git add", Some(repo_path), &args, GIT_TIMEOUT)
            .await?;
        Ok(())
    }

    async fn commit(&self, repo_path: &str, options: &GitCommitOptions) -> Result<String> {
        let mut args: Vec<String> = vec![
            "-c".into(),
            format!("user.name={}", options.author_name),
            "-c".into(),
            format!("user.email={}", options.author_email),
            "commit".into(),
            "-m".into(),
            options.message.clone(),
        ];
        if options.allow_empty {
            args.push("--allow-empty".into());
        }
        self.run("git commit", Some(repo_path), &args, GIT_TIMEOUT)
            .await?;
        let sha = self
            .run(
                "git rev-parse",
                Some(repo_path),
                &["rev-parse".into(), "HEAD".into()],
                GIT_TIMEOUT,
            )
            .await?
            .stdout_lossy();
        Ok(sha.trim().to_owned())
    }

    async fn push(&self, repo_path: &str, options: &GitPushOptions) -> Result<()> {
        let remote = options.remote.as_deref().unwrap_or("origin");
        let mut args: Vec<String> = Vec::new();
        if let Some(rewrite) = self
            .credential_rewrite(repo_path, remote, options.credentials.as_ref())
            .await?
        {
            args.push("-c".into());
            args.push(rewrite);
        }
        args.push("push".into());
        if options.set_upstream {
            args.push("--set-upstream".into());
        }
        args.push(remote.to_owned());
        if let Some(branch) = &options.branch {
            args.push(branch.clone());
        }
        self.run("git push", Some(repo_path), &args, NETWORK_TIMEOUT)
            .await?;
        Ok(())
    }

    async fn pull(&self, repo_path: &str, credentials: Option<&GitCredentials>) -> Result<()> {
        let mut args: Vec<String> = Vec::new();
        if let Some(rewrite) = self
            .credential_rewrite(repo_path, "origin", credentials)
            .await?
        {
            args.push("-c".into());
            args.push(rewrite);
        }
        args.push("pull".into());
        args.push("origin".into());
        self.run("git pull", Some(repo_path), &args, NETWORK_TIMEOUT)
            .await?;
        Ok(())
    }

    async fn branches(&self, repo_path: &str) -> Result<GitBranches> {
        let list = self
            .run(
                "git branch",
                Some(repo_path),
                &["branch".into(), "--format=%(refname:short)".into()],
                GIT_TIMEOUT,
            )
            .await?
            .stdout_lossy();
        let head = self
            .run(
                "git rev-parse",
                Some(repo_path),
                &["rev-parse".into(), "--abbrev-ref".into(), "HEAD".into()],
                GIT_TIMEOUT,
            )
            .await?
            .stdout_lossy();
        let head = head.trim();
        Ok(GitBranches {
            current:  (head != "HEAD").then(|| head.to_owned()),
            branches: list.lines().map(str::to_owned).collect(),
        })
    }

    async fn checkout(&self, repo_path: &str, branch: &str, create: bool) -> Result<()> {
        let mut args: Vec<String> = vec!["checkout".into()];
        if create {
            args.push("-b".into());
        }
        args.push(branch.to_owned());
        self.run("git checkout", Some(repo_path), &args, GIT_TIMEOUT)
            .await?;
        Ok(())
    }
}

fn parse_status_v2(output: &str) -> GitStatus {
    let mut status = GitStatus {
        current_branch: None,
        detached:       false,
        ahead:          0,
        behind:         0,
        dirty_paths:    Vec::new(),
    };
    for line in output.lines() {
        if let Some(head) = line.strip_prefix("# branch.head ") {
            if head == "(detached)" {
                status.detached = true;
            } else {
                status.current_branch = Some(head.to_owned());
            }
        } else if let Some(ab) = line.strip_prefix("# branch.ab ") {
            for part in ab.split_whitespace() {
                if let Some(ahead) = part.strip_prefix('+') {
                    status.ahead = ahead.parse().unwrap_or(0);
                } else if let Some(behind) = part.strip_prefix('-') {
                    status.behind = behind.parse().unwrap_or(0);
                }
            }
        } else if let Some(entry) = line.strip_prefix("1 ") {
            // 8 fixed fields after the marker, then the path.
            if let Some(path) = entry.splitn(8, ' ').nth(7) {
                status.dirty_paths.push(path.to_owned());
            }
        } else if let Some(entry) = line.strip_prefix("2 ") {
            // Rename/copy: path then tab then original path.
            if let Some(path) = entry.splitn(9, ' ').nth(8) {
                let path = path.split('\t').next().unwrap_or(path);
                status.dirty_paths.push(path.to_owned());
            }
        } else if let Some(path) = line.strip_prefix("? ") {
            status.dirty_paths.push(path.to_owned());
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_exec::ScriptedExec;

    #[test]
    fn authed_url_embeds_encoded_credentials() {
        let credentials = GitCredentials::new("x-access-token", "p@ss/word");
        let url = authed_url("https://github.com/org/repo.git", &credentials).expect("https url");
        assert_eq!(
            url,
            "https://x-access-token:p%40ss%2Fword@github.com/org/repo.git"
        );
        assert!(authed_url("git@github.com:org/repo.git", &credentials).is_none());
        // Existing userinfo is replaced, not doubled.
        let url = authed_url("https://old@github.com/org/repo.git", &credentials).expect("url");
        assert!(url.contains("github.com/org/repo.git"));
        assert!(!url.contains("old@"));
    }

    #[test]
    fn authed_url_keeps_an_at_sign_in_the_path() {
        let credentials = GitCredentials::new("user", "pass");
        let url =
            authed_url("https://gitlab.com/org/repo@v2.git", &credentials).expect("https url");
        assert_eq!(url, "https://user:pass@gitlab.com/org/repo@v2.git");
        let url = authed_url("https://old@gitlab.com/org/repo@v2.git", &credentials).expect("url");
        assert_eq!(url, "https://user:pass@gitlab.com/org/repo@v2.git");
    }

    #[test]
    fn parses_porcelain_v2_status() {
        let status = parse_status_v2(concat!(
            "# branch.oid 1234\n",
            "# branch.head main\n",
            "# branch.upstream origin/main\n",
            "# branch.ab +2 -1\n",
            "1 .M N... 100644 100644 100644 aaaa bbbb src/lib.rs\n",
            "? notes.txt\n",
        ));
        assert_eq!(status.current_branch.as_deref(), Some("main"));
        assert!(!status.detached);
        assert_eq!(status.ahead, 2);
        assert_eq!(status.behind, 1);
        assert_eq!(status.dirty_paths, vec![
            "src/lib.rs".to_owned(),
            "notes.txt".to_owned()
        ]);
    }

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
            credentials:  Some(GitCredentials::new("user", "pass")),
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
}
