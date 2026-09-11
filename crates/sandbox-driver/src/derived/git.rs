use std::fmt::Write as _;
use std::time::Duration;

use async_trait::async_trait;

use crate::derived::shell_quote;
use crate::error::{Error, ExecFailure, GitFailure, Result};
use crate::exec::{Exec, ExecResult, ExecSpec};
use crate::git::{
    Git, GitBranches, GitCheckoutOptions, GitCloneOptions, GitCommitOptions, GitCredentials,
    GitPushOptions, GitStatus, validate_branch_name,
};

const GIT_TIMEOUT: Duration = Duration::from_secs(60);
const CLONE_TIMEOUT: Duration = Duration::from_secs(600);
const NETWORK_TIMEOUT: Duration = Duration::from_secs(300);

/// Internal git calls disable background maintenance, as fabro does.
const GIT: &str = "git -c maintenance.auto=0 -c gc.auto=0";

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
        self.run_script(label, repo, command, None, timeout).await
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
        let mut spec = ExecSpec::bash(script).timeout(timeout);
        if let Some(repo) = repo {
            spec = spec.working_dir(repo.to_owned());
        }
        if let Some((key, value)) = secret {
            spec = spec.env_var(key, value);
        }
        let result = self.exec.run(&spec).await?;
        if result.success() {
            return Ok(result);
        }
        // A command that ran and failed is a git failure, classified from
        // its output; a failure to run it at all (transport, timeout)
        // passed through above unchanged.
        Err(Error::Git(GitFailure::from_command(
            label,
            ExecFailure::new(
                label,
                result.termination,
                result.exit_code,
                result.stdout,
                result.stderr,
            )
            .with_duration(result.duration),
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
        let url = self.remote_url(repo, remote).await?;
        Ok(authed_url(&url, credentials).map(|authed| format!("url.{authed}.insteadOf={url}")))
    }

    async fn remote_url(&self, repo: &str, remote: &str) -> Result<String> {
        let url = self
            .run(
                "git remote get-url",
                Some(repo),
                &["remote".into(), "get-url".into(), remote.to_owned()],
                GIT_TIMEOUT,
            )
            .await?
            .stdout_lossy();
        Ok(url.trim().to_owned())
    }

    /// Where the repository's ambient credential store lives: under the
    /// runtime directory when the sandbox has one, otherwise inside the
    /// repository's git directory, resolved so the helper configuration
    /// carries an absolute path.
    async fn credential_store_path(&self, repo: &str) -> Result<String> {
        if let Some(runtime_directory) = self.runtime_directory {
            return Ok(format!(
                "{}/git-credentials/{}",
                runtime_directory.trim_end_matches('/'),
                store_file_name(repo)
            ));
        }
        let git_dir = self
            .run(
                "git rev-parse",
                Some(repo),
                &["rev-parse".into(), "--absolute-git-dir".into()],
                GIT_TIMEOUT,
            )
            .await?
            .stdout_lossy();
        Ok(format!("{}/sandbox-driver-credentials", git_dir.trim()))
    }
}

/// Environment variable the credential store line travels in while the
/// file is written, so the secret never appears in a command's text.
const CREDENTIAL_ENV: &str = "SANDBOX_DRIVER_GIT_CREDENTIAL";

/// `git config --unset-all` exits 5 when the key has no such value.
const CONFIG_KEY_ABSENT: &str = "[ $? -eq 5 ]";

/// The `credential.helper` value that reads `store_path`. The path is
/// shell-quoted because git runs helper commands through the shell.
fn store_helper(store_path: &str) -> String {
    format!("store --file={}", shell_quote(store_path))
}

/// A stable file name for a repository's credential store: the last path
/// component, kept to safe characters, plus a hash of the whole path so
/// two spellings that sanitize alike stay apart.
fn store_file_name(repo_path: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in repo_path.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    let stem = repo_path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|stem| !stem.is_empty())
        .unwrap_or("repo");
    let readable: String = stem
        .chars()
        .take(40)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{readable}-{hash:016x}")
}

/// The git-credential-store line for `url`'s host: `scheme://user:pass@host`,
/// percent-encoded like the per-call rewrite. `None` for other schemes.
fn store_entry(url: &str, credentials: &GitCredentials) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    Some(format!(
        "{scheme}://{}:{}@{host}",
        encode_userinfo(&credentials.username),
        encode_userinfo(&credentials.password),
    ))
}

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
            "git init",
            None,
            &["init".into(), "--".into(), target_path.to_owned()],
            GIT_TIMEOUT,
        )
        .await?;
        self.run(
            "git remote add",
            Some(target_path),
            &[
                "remote".into(),
                "add".into(),
                "--".into(),
                "origin".into(),
                url.to_owned(),
            ],
            GIT_TIMEOUT,
        )
        .await?;

        let mut args: Vec<String> = Vec::new();
        if let Some(rewrite) = rewrite {
            args.push("-c".into());
            args.push(rewrite.to_owned());
        }
        args.push("fetch".into());
        if let Some(depth) = options.depth {
            args.push("--depth".into());
            args.push(depth.to_string());
        }
        args.push("--no-tags".into());
        args.push("origin".into());
        args.push("--".into());
        args.push(pin.fetch_refspec());
        self.run("git fetch", Some(target_path), &args, CLONE_TIMEOUT)
            .await?;

        let revision = pin.revision();
        if let Some(branch) = &options.branch {
            return self
                .attach_pinned_branch(target_path, branch, &revision)
                .await;
        }
        self.run(
            "git checkout",
            Some(target_path),
            &[
                "checkout".into(),
                "--detach".into(),
                revision,
                // Forces revision interpretation: a bare name that also
                // matches a path would otherwise be ambiguous.
                "--".into(),
            ],
            GIT_TIMEOUT,
        )
        .await?;
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
        self.run(
            "git checkout",
            Some(repo_path),
            &[
                "checkout".into(),
                "-B".into(),
                branch.to_owned(),
                revision.to_owned(),
                "--".into(),
            ],
            GIT_TIMEOUT,
        )
        .await?;
        Ok(())
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

        let mut args: Vec<String> = Vec::new();
        if let Some(rewrite) = &rewrite {
            args.push("-c".into());
            args.push(rewrite.clone());
        }
        args.push("clone".into());
        if let Some(depth) = options.depth {
            args.push("--depth".into());
            args.push(depth.to_string());
        }
        if let Some(branch) = &options.branch {
            args.push("--branch".into());
            args.push(branch.clone());
            // git implies --single-branch only under --depth; without
            // it a branch clone would still fetch every other branch.
            args.push("--single-branch".into());
        }
        args.push("--no-tags".into());
        // End option parsing so a URL or path starting with `-` cannot
        // be read as a flag.
        args.push("--".into());
        args.push(url.to_owned());
        args.push(target_path.to_owned());
        self.run("git clone", None, &args, CLONE_TIMEOUT).await?;
        Ok(())
    }

    async fn status(&self, repo_path: &str) -> Result<GitStatus> {
        // `-z` delimits entries with NUL and keeps paths verbatim —
        // without it git C-quotes special-character paths and a newline
        // in a path corrupts adjacent entries.
        let result = self
            .run(
                "git status",
                Some(repo_path),
                &[
                    "status".into(),
                    "--porcelain=v2".into(),
                    "-z".into(),
                    "--branch".into(),
                ],
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
        options.validate()?;
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
        if let Some(target) = options.refspec.as_ref().or(options.branch.as_ref()) {
            args.push(target.clone());
        }
        let timeout = options.timeout.unwrap_or(NETWORK_TIMEOUT);
        self.run("git push", Some(repo_path), &args, timeout)
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
        // `for-each-ref` lists only real branches; `git branch` would
        // emit a "(HEAD detached at …)" pseudo-entry in detached state.
        let list = self
            .run(
                "git for-each-ref",
                Some(repo_path),
                &[
                    "for-each-ref".into(),
                    "--format=%(refname:short)".into(),
                    "refs/heads".into(),
                ],
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

    async fn set_ambient_credentials(
        &self,
        repo_path: &str,
        credentials: Option<&GitCredentials>,
    ) -> Result<()> {
        let entry = match credentials {
            Some(credentials) => {
                let url = self.remote_url(repo_path, "origin").await?;
                Some(store_entry(&url, credentials).ok_or_else(|| {
                    Error::invalid_spec(
                        "credentials",
                        "ambient credentials apply to http(s) remotes only; origin is not an \
                         http(s) URL",
                    )
                })?)
            }
            None => None,
        };
        let store = self.credential_store_path(repo_path).await?;
        let helper = shell_quote(&store_helper(&store));
        let path = shell_quote(&store);
        let temp = shell_quote(&format!("{store}.tmp"));
        // Replace only this facet's own helper entry, so a helper the
        // environment configured stays in place.
        let forget_helper = format!(
            "({GIT} config --local --fixed-value --unset-all credential.helper {helper} || \
             {CONFIG_KEY_ABSENT})"
        );
        match entry {
            Some(entry) => {
                let directory = shell_quote(store.rsplit_once('/').map_or("/", |(dir, _)| dir));
                self.run_script(
                    "git credential store",
                    None,
                    format!(
                        "umask 077 && mkdir -p -- {directory} && \
                         printf '%s\\n' \"${CREDENTIAL_ENV}\" > {temp} && mv -f -- {temp} {path}"
                    ),
                    Some((CREDENTIAL_ENV, &entry)),
                    GIT_TIMEOUT,
                )
                .await?;
                self.run_script(
                    "git config credential.helper",
                    Some(repo_path),
                    format!(
                        "{forget_helper} && {GIT} config --local --add credential.helper {helper}"
                    ),
                    None,
                    GIT_TIMEOUT,
                )
                .await?;
            }
            None => {
                self.run_script(
                    "git config credential.helper",
                    Some(repo_path),
                    format!("rm -f -- {temp} {path} && {forget_helper}"),
                    None,
                    GIT_TIMEOUT,
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn checkout(&self, repo_path: &str, options: &GitCheckoutOptions) -> Result<()> {
        options.validate()?;
        let mut args: Vec<String> = vec!["checkout".into()];
        if options.create {
            args.push(if options.reset { "-B" } else { "-b" }.into());
        }
        args.push(options.branch.clone());
        if let Some(start_point) = &options.start_point {
            args.push(start_point.clone());
        }
        // Forces branch interpretation: a branch that also matches a
        // path would otherwise restore the file instead.
        args.push("--".into());
        self.run("git checkout", Some(repo_path), &args, GIT_TIMEOUT)
            .await?;
        Ok(())
    }
}

/// Parses `git status --porcelain=v2 -z --branch` output: entries are
/// NUL-separated with verbatim paths, and a rename/copy entry is
/// followed by one extra NUL-separated field (the original path).
fn parse_status_v2(output: &str) -> GitStatus {
    let mut status = GitStatus {
        current_branch: None,
        head:           None,
        detached:       false,
        ahead:          0,
        behind:         0,
        dirty_paths:    Vec::new(),
    };
    let mut entries = output.split('\0');
    while let Some(entry) = entries.next() {
        if let Some(oid) = entry.strip_prefix("# branch.oid ") {
            status.head = (oid != "(initial)").then(|| oid.to_owned());
        } else if let Some(head) = entry.strip_prefix("# branch.head ") {
            if head == "(detached)" {
                status.detached = true;
            } else {
                status.current_branch = Some(head.to_owned());
            }
        } else if let Some(ab) = entry.strip_prefix("# branch.ab ") {
            for part in ab.split_whitespace() {
                if let Some(ahead) = part.strip_prefix('+') {
                    status.ahead = ahead.parse().unwrap_or(0);
                } else if let Some(behind) = part.strip_prefix('-') {
                    status.behind = behind.parse().unwrap_or(0);
                }
            }
        } else if let Some(entry) = entry.strip_prefix("1 ") {
            // 8 fixed fields after the marker, then the path.
            if let Some(path) = entry.splitn(8, ' ').nth(7) {
                status.dirty_paths.push(path.to_owned());
            }
        } else if let Some(entry) = entry.strip_prefix("2 ") {
            // Rename/copy: 9 fields, the new path, then the original
            // path as its own NUL-separated field.
            if let Some(path) = entry.splitn(9, ' ').nth(8) {
                status.dirty_paths.push(path.to_owned());
            }
            let _original_path = entries.next();
        } else if let Some(entry) = entry.strip_prefix("u ") {
            // Unmerged (conflict): 10 fields, then the path. A repo
            // mid-merge must not pass a "workspace clean" check.
            if let Some(path) = entry.splitn(10, ' ').nth(9) {
                status.dirty_paths.push(path.to_owned());
            }
        } else if let Some(path) = entry.strip_prefix("? ") {
            status.dirty_paths.push(path.to_owned());
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GitFailureKind;
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
        // `-z` output, shapes verified against live git: a rename entry
        // is followed by the original path as its own NUL field, and
        // special-character paths arrive verbatim, not C-quoted.
        let status = parse_status_v2(concat!(
            "# branch.oid 1234\0",
            "# branch.head main\0",
            "# branch.upstream origin/main\0",
            "# branch.ab +2 -1\0",
            "1 .M N... 100644 100644 100644 aaaa bbbb src/lib.rs\0",
            "2 RM N... 100644 100644 100644 aaaa bbbb R100 new.txt\0old.txt\0",
            "u UU N... 100644 100644 100644 100644 aaaa bbbb cccc conflicted.rs\0",
            "? na\u{ef}ve notes.txt\0",
        ));
        assert_eq!(status.current_branch.as_deref(), Some("main"));
        assert_eq!(status.head.as_deref(), Some("1234"));
        assert!(!status.detached);
        assert_eq!(status.ahead, 2);
        assert_eq!(status.behind, 1);
        assert_eq!(status.dirty_paths, vec![
            "src/lib.rs".to_owned(),
            "new.txt".to_owned(),
            "conflicted.rs".to_owned(),
            "na\u{ef}ve notes.txt".to_owned(),
        ]);
    }

    #[test]
    fn an_unborn_branch_has_no_head() {
        let status = parse_status_v2("# branch.oid (initial)\0# branch.head main\0");
        assert_eq!(status.head, None);
        assert_eq!(status.current_branch.as_deref(), Some("main"));
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
        let exec = ScriptedExec::new(vec![ScriptedExec::ok(""), ScriptedExec::ok("")]);
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
    async fn clone_stays_single_branch_without_tags() {
        let exec = ScriptedExec::new(vec![ScriptedExec::ok("")]);
        let git = DerivedGit::new(&exec);
        let options = GitCloneOptions {
            branch:      Some("main".to_owned()),
            commit:      None,
            tag:         None,
            depth:       None,
            credentials: None,
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
        let exec = ScriptedExec::new(vec![
            ScriptedExec::ok(""),
            ScriptedExec::ok(""),
            ScriptedExec::ok(""),
            ScriptedExec::ok(""),
        ]);
        let git = DerivedGit::new(&exec);
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let options = GitCloneOptions {
            branch:      Some("main".to_owned()),
            commit:      Some(sha.to_owned()),
            tag:         None,
            depth:       Some(1),
            credentials: Some(GitCredentials::new("user", "pass")),
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
        let exec = ScriptedExec::new(vec![
            ScriptedExec::ok(""),
            ScriptedExec::ok(""),
            ScriptedExec::ok(""),
            ScriptedExec::ok(""),
        ]);
        let git = DerivedGit::new(&exec);
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let options = GitCloneOptions {
            branch:      None,
            commit:      Some(sha.to_owned()),
            tag:         None,
            depth:       None,
            credentials: None,
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
        let exec = ScriptedExec::new(vec![
            ScriptedExec::ok(""),
            ScriptedExec::ok(""),
            ScriptedExec::ok(""),
            ScriptedExec::ok(""),
        ]);
        let git = DerivedGit::new(&exec);
        let options = GitCloneOptions {
            branch:      Some("main".to_owned()),
            commit:      None,
            tag:         Some("v1.2.0".to_owned()),
            depth:       Some(1),
            credentials: None,
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
        let exec = ScriptedExec::new(vec![
            ScriptedExec::ok(""),
            ScriptedExec::ok(""),
            ScriptedExec::ok(""),
            ScriptedExec::ok(""),
        ]);
        let git = DerivedGit::new(&exec);
        let options = GitCloneOptions {
            branch:      None,
            commit:      None,
            tag:         Some("v1".to_owned()),
            depth:       None,
            credentials: None,
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
            branch:      None,
            commit:      Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
            tag:         Some("v1".to_owned()),
            depth:       None,
            credentials: None,
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
                branch:      None,
                commit:      None,
                tag:         Some(tag.to_owned()),
                depth:       None,
                credentials: None,
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
            branch:      Some("main".to_owned()),
            commit:      None,
            tag:         None,
            depth:       Some(1),
            credentials: None,
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
            branch:      None,
            commit:      None,
            tag:         Some("v9.9.9".to_owned()),
            depth:       None,
            credentials: None,
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
            branch:      None,
            // Parsed as a flag by the old code: `checkout --detach -q`
            // exited 0 at the branch tip while pinning nothing.
            commit:      Some("-q".to_owned()),
            tag:         None,
            depth:       None,
            credentials: None,
        };
        let error = git
            .clone_repo("https://github.com/org/repo.git", "/dst", &options)
            .await
            .expect_err("flag-shaped commit is rejected");
        assert!(matches!(error, Error::InvalidSpec { .. }), "{error}");
        assert!(exec.commands().is_empty(), "no command may run");
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
    async fn clone_credentials_travel_in_the_rewrite_not_the_url() {
        let exec = ScriptedExec::new(vec![ScriptedExec::ok("")]);
        let git = DerivedGit::new(&exec);
        let options = GitCloneOptions {
            branch:      None,
            commit:      None,
            tag:         None,
            depth:       None,
            credentials: Some(GitCredentials::new("user", "pass")),
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

    #[tokio::test]
    async fn ambient_credentials_store_outside_the_repository_and_point_the_helper_at_it() {
        let exec = ScriptedExec::new(vec![
            ScriptedExec::ok("https://github.com/org/repo.git\n"),
            ScriptedExec::ok(""),
            ScriptedExec::ok(""),
        ]);
        let git = DerivedGit::new(&exec).with_runtime_directory("/tmp/sandbox-driver/runtime/");
        let credentials = GitCredentials::new("x-access-token", "s3cr3t/tok=en");
        git.set_ambient_credentials("/workspace/repo", Some(&credentials))
            .await
            .expect("credentials install");

        let commands = exec.commands();
        assert_eq!(commands.len(), 3, "{commands:#?}");
        assert!(
            commands[0].contains("'remote' 'get-url' 'origin'"),
            "{}",
            commands[0]
        );
        let store = format!(
            "/tmp/sandbox-driver/runtime/git-credentials/{}",
            store_file_name("/workspace/repo")
        );
        assert!(
            commands[1].starts_with(
                "umask 077 && mkdir -p -- '/tmp/sandbox-driver/runtime/git-credentials'"
            ),
            "{}",
            commands[1]
        );
        assert!(
            commands[1].contains(&format!("mv -f -- '{store}.tmp' '{store}'")),
            "{}",
            commands[1]
        );
        assert!(
            !commands[1].contains("s3cr3t"),
            "the secret never enters the command text: {}",
            commands[1]
        );
        assert_eq!(
            exec.envs()[1].get(CREDENTIAL_ENV).map(String::as_str),
            Some("https://x-access-token:s3cr3t%2Ftok%3Den@github.com")
        );
        let helper = shell_quote(&store_helper(&store));
        assert!(
            commands[2].contains(&format!(
                "--fixed-value --unset-all credential.helper {helper}"
            )),
            "{}",
            commands[2]
        );
        assert!(
            commands[2].contains(&format!("config --local --add credential.helper {helper}")),
            "{}",
            commands[2]
        );
        assert!(
            !commands[2].contains("s3cr3t"),
            "the helper points at the store, not the secret: {}",
            commands[2]
        );
    }

    #[tokio::test]
    async fn ambient_credentials_fall_back_to_the_git_directory_without_a_runtime_directory() {
        let exec = ScriptedExec::new(vec![
            ScriptedExec::ok("https://github.com/org/repo.git\n"),
            ScriptedExec::ok("/work/my repo/.git\n"),
            ScriptedExec::ok(""),
            ScriptedExec::ok(""),
        ]);
        let git = DerivedGit::new(&exec);
        git.set_ambient_credentials("my repo", Some(&GitCredentials::new("u", "p")))
            .await
            .expect("credentials install");

        let commands = exec.commands();
        assert_eq!(commands.len(), 4, "{commands:#?}");
        assert!(
            commands[1].contains("'rev-parse' '--absolute-git-dir'"),
            "{}",
            commands[1]
        );
        assert!(
            commands[2].contains(
                "mv -f -- '/work/my repo/.git/sandbox-driver-credentials.tmp' \
                 '/work/my repo/.git/sandbox-driver-credentials'"
            ),
            "{}",
            commands[2]
        );
        assert!(
            commands[3].contains("--add credential.helper"),
            "{}",
            commands[3]
        );
    }

    #[tokio::test]
    async fn ambient_credentials_reject_a_non_http_origin_before_writing_anything() {
        let exec = ScriptedExec::new(vec![ScriptedExec::ok("git@github.com:org/repo.git\n")]);
        let git = DerivedGit::new(&exec).with_runtime_directory("/run");
        let error = git
            .set_ambient_credentials("/workspace/repo", Some(&GitCredentials::new("u", "p")))
            .await
            .expect_err("an ssh origin is rejected");
        assert!(matches!(error, Error::InvalidSpec { .. }), "{error}");
        assert_eq!(exec.commands().len(), 1, "only the URL lookup ran");
    }

    #[tokio::test]
    async fn removing_ambient_credentials_deletes_the_store_and_only_this_helper_entry() {
        let exec = ScriptedExec::new(vec![ScriptedExec::ok("")]);
        let git = DerivedGit::new(&exec).with_runtime_directory("/run");
        git.set_ambient_credentials("/workspace/repo", None)
            .await
            .expect("credentials removal");

        let commands = exec.commands();
        assert_eq!(commands.len(), 1, "{commands:#?}");
        let store = format!(
            "/run/git-credentials/{}",
            store_file_name("/workspace/repo")
        );
        assert!(
            commands[0].starts_with(&format!("rm -f -- '{store}.tmp' '{store}'")),
            "{}",
            commands[0]
        );
        assert!(
            commands[0].contains("--fixed-value --unset-all credential.helper"),
            "{}",
            commands[0]
        );
        assert!(!commands[0].contains("--add"), "{}", commands[0]);
        assert!(
            commands[0].contains(CONFIG_KEY_ABSENT),
            "a missing entry is not a failure: {}",
            commands[0]
        );
    }

    #[test]
    fn store_entries_name_the_host_only() {
        let credentials = GitCredentials::new("x-access-token", "p@ss/word");
        assert_eq!(
            store_entry("https://github.com/org/repo.git", &credentials).as_deref(),
            Some("https://x-access-token:p%40ss%2Fword@github.com")
        );
        assert_eq!(
            store_entry(
                "https://old@git.example.com:8443/org/repo@v2.git",
                &credentials
            )
            .as_deref(),
            Some("https://x-access-token:p%40ss%2Fword@git.example.com:8443")
        );
        assert!(store_entry("git@github.com:org/repo.git", &credentials).is_none());
        assert!(store_entry("file:///tmp/remote.git", &credentials).is_none());
    }

    #[test]
    fn store_file_names_are_stable_readable_and_distinct() {
        let name = store_file_name("conformance-git/clone");
        assert!(name.starts_with("clone-"), "{name}");
        assert_eq!(name, store_file_name("conformance-git/clone"));
        assert_ne!(name, store_file_name("conformance-git_clone"));
        assert!(store_file_name("/").starts_with("repo-"));
        let odd = store_file_name("/work/my repo é");
        assert!(odd.starts_with("my_repo__-"), "{odd}");
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
