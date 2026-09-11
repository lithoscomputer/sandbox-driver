use std::fmt::Write as _;
use std::time::Duration;
use std::{fmt, io};

use async_trait::async_trait;

use crate::derived::shell_quote;
use crate::error::{Error, ExecFailure, GitFailure, Result};
use crate::exec::{Exec, ExecResult, ExecSpec, Termination};
use crate::git::{
    Git, GitBranches, GitChange, GitCheckoutOptions, GitCloneOptions, GitCommit, GitCommitOptions,
    GitCredentials, GitDiffEntry, GitDiffOptions, GitFetchOptions, GitIdentity, GitLogOptions,
    GitNumstat, GitPushOptions, GitStatus, validate_argument, validate_branch_name,
    validate_config_key, validate_object_name,
};

const GIT_TIMEOUT: Duration = Duration::from_secs(60);
const CLONE_TIMEOUT: Duration = Duration::from_secs(600);
const NETWORK_TIMEOUT: Duration = Duration::from_secs(300);

/// Every derived git call runs hardened: no background maintenance, no
/// repository hooks, no fsmonitor daemon, paths unquoted, and no commit
/// or tag signing. The environment also disables terminal prompts
/// ([`GIT_ENV`]), and the diff verbs pass `--no-ext-diff` so a configured
/// external diff driver never runs.
const GIT: &str = "git -c maintenance.auto=0 -c gc.auto=0 -c core.hooksPath=/dev/null \
                   -c core.fsmonitor=false -c core.quotePath=false -c commit.gpgsign=false \
                   -c tag.gpgsign=false";
/// Read verbs additionally refuse the file transport, so a diff or log
/// can never fetch through a local path.
const GIT_READ: &str = "git -c maintenance.auto=0 -c gc.auto=0 -c core.hooksPath=/dev/null \
                        -c core.fsmonitor=false -c core.quotePath=false -c commit.gpgsign=false \
                        -c tag.gpgsign=false -c protocol.file.allow=never";
/// Environment every derived git call runs with: never a terminal prompt.
const GIT_ENV: &[(&str, &str)] = &[("GIT_TERMINAL_PROMPT", "0")];
/// Git's separator format for one commit of a log: unit separator between
/// fields, record separator between commits.
const LOG_FORMAT: &str = "%H%x1f%T%x1f%P%x1f%an%x1f%ae%x1f%aI%x1f%cn%x1f%ce%x1f%cI%x1f%B%x1e";

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
        self.run_prefixed(GIT, label, repo, args, timeout).await
    }

    /// A read-only command, which also refuses the file transport.
    async fn run_read(
        &self,
        label: &str,
        repo: Option<&str>,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecResult> {
        self.run_prefixed(GIT_READ, label, repo, args, timeout)
            .await
    }

    async fn run_prefixed(
        &self,
        prefix: &str,
        label: &str,
        repo: Option<&str>,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecResult> {
        self.run_script(label, repo, git_command(prefix, args), None, timeout)
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

/// The shell command for `prefix` and quoted `args`.
fn git_command(prefix: &str, args: &[String]) -> String {
    let mut command = String::from(prefix);
    for arg in args {
        command.push(' ');
        command.push_str(&shell_quote(arg));
    }
    command
}

/// The spec every derived git script runs as: the Bash helper, the git
/// environment, the repository as working directory, and an optional
/// secret in the environment.
fn git_spec(
    script: String,
    repo: Option<&str>,
    secret: Option<(&str, &str)>,
    timeout: Duration,
) -> ExecSpec {
    let mut spec = ExecSpec::bash(script).timeout(timeout);
    for (key, value) in GIT_ENV {
        spec = spec.env_var(*key, *value);
    }
    if let Some(repo) = repo {
        spec = spec.working_dir(repo.to_owned());
    }
    if let Some((key, value)) = secret {
        spec = spec.env_var(key, value);
    }
    spec
}

/// A command that ran and failed, classified from its output. A failure
/// to run it at all (transport, timeout) is passed through by the caller
/// unchanged.
fn git_failure(label: &str, result: ExecResult) -> Error {
    Error::Git(GitFailure::from_command(
        label,
        ExecFailure::new(
            label,
            result.termination,
            result.exit_code,
            result.stdout,
            result.stderr,
        )
        .with_duration(result.duration),
    ))
}

/// Output that git could not be trusted to have produced whole, or that
/// does not parse: an internal failure of the derived implementation, not
/// a classified git outcome.
fn malformed(what: &str, detail: impl fmt::Display) -> Error {
    Error::io(
        format!("parsing {what}"),
        io::Error::other(detail.to_string()),
    )
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `--find-renames=<n>%`, when rename detection was asked for.
fn rename_flag(options: &GitDiffOptions) -> Option<String> {
    options
        .find_renames
        .map(|percent| format!("--find-renames={percent}%"))
}

/// A blob or mode git prints as all zeros is absent on that side.
fn present(value: &str) -> Option<String> {
    (!value.is_empty() && !value.bytes().all(|byte| byte == b'0')).then(|| value.to_owned())
}

/// Parses `git diff --raw -z` output: per entry a header
/// `:<old mode> <new mode> <old blob> <new blob> <status>` and one path, or
/// two for a rename or copy, each NUL-terminated.
fn parse_raw_diff(output: &[u8]) -> Result<Vec<GitDiffEntry>> {
    let mut entries = Vec::new();
    let mut fields = output.split(|byte| *byte == 0).peekable();
    while let Some(header) = fields.next() {
        if header.is_empty() {
            continue;
        }
        let header = lossy(header);
        let Some(rest) = header.strip_prefix(':') else {
            return Err(malformed(
                "git diff --raw",
                format!("unexpected entry {header:?}"),
            ));
        };
        let parts: Vec<&str> = rest.split(' ').collect();
        let [old_mode, new_mode, old_blob, new_blob, status] = parts[..] else {
            return Err(malformed(
                "git diff --raw",
                format!("short header {header:?}"),
            ));
        };
        let mut letters = status.chars();
        let (change, similarity) = match letters.next() {
            Some('A') => (GitChange::Added, None),
            Some('C') => (GitChange::Copied, letters.as_str().parse().ok()),
            Some('D') => (GitChange::Deleted, None),
            Some('M') => (GitChange::Modified, None),
            Some('R') => (GitChange::Renamed, letters.as_str().parse().ok()),
            Some('T') => (GitChange::TypeChanged, None),
            Some('U') => (GitChange::Unmerged, None),
            _ => (GitChange::Unknown, None),
        };
        let first = fields
            .next()
            .ok_or_else(|| malformed("git diff --raw", "entry without a path"))?;
        let (old_path, path) = if matches!(change, GitChange::Renamed | GitChange::Copied) {
            let second = fields
                .next()
                .ok_or_else(|| malformed("git diff --raw", "rename without a new path"))?;
            (Some(lossy(first)), lossy(second))
        } else {
            (None, lossy(first))
        };
        entries.push(GitDiffEntry {
            change,
            path,
            old_path,
            old_mode: present(old_mode),
            new_mode: present(new_mode),
            old_blob: present(old_blob),
            new_blob: present(new_blob),
            similarity,
        });
    }
    Ok(entries)
}

/// Parses `git diff --numstat -z` output: `<added>\t<removed>\t<path>` per
/// entry, `-` for both counts on a binary path, and for a rename an empty
/// path followed by the old and new paths as their own fields.
fn parse_numstat(output: &[u8]) -> Result<Vec<GitNumstat>> {
    let mut entries = Vec::new();
    let mut fields = output.split(|byte| *byte == 0);
    while let Some(entry) = fields.next() {
        if entry.is_empty() {
            continue;
        }
        let entry = lossy(entry);
        let mut parts = entry.splitn(3, '\t');
        let (Some(added), Some(removed), Some(path)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(malformed(
                "git diff --numstat",
                format!("short entry {entry:?}"),
            ));
        };
        let count = |text: &str| -> Result<Option<u64>> {
            if text == "-" {
                return Ok(None);
            }
            text.parse()
                .map(Some)
                .map_err(|_| malformed("git diff --numstat", format!("bad count {text:?}")))
        };
        let (old_path, path) = if path.is_empty() {
            let old = fields
                .next()
                .ok_or_else(|| malformed("git diff --numstat", "rename without an old path"))?;
            let new = fields
                .next()
                .ok_or_else(|| malformed("git diff --numstat", "rename without a new path"))?;
            (Some(lossy(old)), lossy(new))
        } else {
            (None, path.to_owned())
        };
        entries.push(GitNumstat {
            path,
            old_path,
            additions: count(added)?,
            deletions: count(removed)?,
        });
    }
    Ok(entries)
}

/// Parses a log in [`LOG_FORMAT`].
fn parse_log(output: &str) -> Result<Vec<GitCommit>> {
    let mut commits = Vec::new();
    for record in output.split('\x1e') {
        let record = record.trim_start_matches('\n');
        if record.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = record.splitn(10, '\x1f').collect();
        let [
            sha,
            tree,
            parents,
            author_name,
            author_email,
            author_date,
            committer_name,
            committer_email,
            committer_date,
            message,
        ] = fields[..]
        else {
            return Err(malformed("git log", format!("short record {record:?}")));
        };
        commits.push(GitCommit {
            sha:       sha.to_owned(),
            tree:      tree.to_owned(),
            parents:   parents.split_whitespace().map(str::to_owned).collect(),
            author:    GitIdentity {
                name:  author_name.to_owned(),
                email: author_email.to_owned(),
                date:  author_date.to_owned(),
            },
            committer: GitIdentity {
                name:  committer_name.to_owned(),
                email: committer_email.to_owned(),
                date:  committer_date.to_owned(),
            },
            message:   message.trim_end_matches('\n').to_owned(),
        });
    }
    Ok(commits)
}

/// The header of one `cat-file --batch` or `--batch-check` entry: the
/// size when the object exists, `None` when git says `missing`.
fn batch_header(line: &str) -> Result<Option<usize>> {
    let mut parts = line.split(' ');
    let _name = parts.next();
    match (parts.next(), parts.next()) {
        (Some("missing"), None) => Ok(None),
        (Some(_kind), Some(size)) => size
            .parse()
            .map(Some)
            .map_err(|_| malformed("git cat-file", format!("bad size in {line:?}"))),
        _ => Err(malformed("git cat-file", format!("bad header {line:?}"))),
    }
}

/// Parses `git cat-file --batch` output: a header line, the object's
/// bytes, and a newline, per requested object, in request order.
fn parse_batch(output: &[u8], count: usize, max_bytes: u64) -> Result<Vec<Option<Vec<u8>>>> {
    let mut blobs = Vec::with_capacity(count);
    let mut position = 0;
    while position < output.len() && blobs.len() < count {
        let Some(newline) = output[position..].iter().position(|byte| *byte == b'\n') else {
            break;
        };
        let header = lossy(&output[position..position + newline]);
        position += newline + 1;
        let Some(size) = batch_header(&header)? else {
            blobs.push(None);
            continue;
        };
        let end = position + size;
        if end > output.len() {
            return Err(malformed(
                "git cat-file",
                format!(
                    "stream ends {} bytes into a {size} byte object",
                    output.len() - position
                ),
            ));
        }
        blobs.push(
            (u64::try_from(size).unwrap_or(u64::MAX) <= max_bytes)
                .then(|| output[position..end].to_vec()),
        );
        position = end;
        if output.get(position) == Some(&b'\n') {
            position += 1;
        }
    }
    if blobs.len() != count {
        return Err(malformed(
            "git cat-file",
            format!("{} objects answered for {count} requested", blobs.len()),
        ));
    }
    Ok(blobs)
}

/// The `printf` that feeds object names to a batch command.
fn feed_object_names(names: &[String]) -> String {
    let mut command = String::from("printf '%s\\n'");
    for name in names {
        command.push(' ');
        command.push_str(&shell_quote(name));
    }
    command
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

    async fn fetch(&self, repo_path: &str, options: &GitFetchOptions) -> Result<()> {
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
        args.push("fetch".into());
        if let Some(depth) = options.depth {
            args.push("--depth".into());
            args.push(depth.to_string());
        }
        args.push(remote.to_owned());
        args.extend(options.refspecs.iter().cloned());
        self.run(
            "git fetch",
            Some(repo_path),
            &args,
            options.timeout.unwrap_or(NETWORK_TIMEOUT),
        )
        .await?;
        Ok(())
    }

    async fn rev_parse(&self, repo_path: &str, revision: &str) -> Result<String> {
        validate_argument("revision", revision)?;
        let output = self
            .run_read(
                "git rev-parse",
                Some(repo_path),
                &[
                    "rev-parse".into(),
                    "--verify".into(),
                    "--end-of-options".into(),
                    revision.to_owned(),
                ],
                GIT_TIMEOUT,
            )
            .await?
            .stdout_lossy();
        Ok(output.trim().to_owned())
    }

    async fn is_ancestor(&self, repo_path: &str, ancestor: &str, descendant: &str) -> Result<bool> {
        validate_argument("ancestor", ancestor)?;
        validate_argument("descendant", descendant)?;
        // Exit 0 and 1 are the two answers; anything else is a failure.
        let script = git_command(GIT_READ, &[
            "merge-base".into(),
            "--is-ancestor".into(),
            ancestor.to_owned(),
            descendant.to_owned(),
        ]);
        let result = self
            .exec
            .run(&git_spec(script, Some(repo_path), None, GIT_TIMEOUT))
            .await?;
        match result.exit_code {
            Some(0) if result.termination == Termination::Exited => Ok(true),
            Some(1) if result.termination == Termination::Exited => Ok(false),
            _ => Err(git_failure("git merge-base", result)),
        }
    }

    async fn diff_entries(
        &self,
        repo_path: &str,
        options: &GitDiffOptions,
    ) -> Result<Vec<GitDiffEntry>> {
        options.validate()?;
        let mut args: Vec<String> = vec![
            "diff".into(),
            "--no-ext-diff".into(),
            "--raw".into(),
            // Full blob names, so a caller can hand them straight back to the
            // blob verbs.
            "--no-abbrev".into(),
            "-z".into(),
        ];
        args.extend(rename_flag(options));
        args.push(options.range.spec(None));
        let result = self
            .run_read(
                "git diff --raw",
                Some(repo_path),
                &args,
                options.timeout.unwrap_or(GIT_TIMEOUT),
            )
            .await?;
        parse_raw_diff(&result.stdout)
    }

    async fn diff_numstat(
        &self,
        repo_path: &str,
        options: &GitDiffOptions,
    ) -> Result<Vec<GitNumstat>> {
        options.validate()?;
        let mut args: Vec<String> = vec![
            "diff".into(),
            "--no-ext-diff".into(),
            "--numstat".into(),
            "-z".into(),
        ];
        args.extend(rename_flag(options));
        args.push(options.range.spec(None));
        let result = self
            .run_read(
                "git diff --numstat",
                Some(repo_path),
                &args,
                options.timeout.unwrap_or(GIT_TIMEOUT),
            )
            .await?;
        parse_numstat(&result.stdout)
    }

    async fn diff_patch(&self, repo_path: &str, options: &GitDiffOptions) -> Result<String> {
        options.validate()?;
        let mut args: Vec<String> =
            vec!["diff".into(), "--no-ext-diff".into(), "--no-color".into()];
        args.extend(rename_flag(options));
        args.push(options.range.spec(None));
        let result = self
            .run_read(
                "git diff",
                Some(repo_path),
                &args,
                options.timeout.unwrap_or(GIT_TIMEOUT),
            )
            .await?;
        Ok(result.stdout_lossy())
    }

    async fn log(&self, repo_path: &str, options: &GitLogOptions) -> Result<Vec<GitCommit>> {
        options.validate()?;
        let mut args: Vec<String> = vec!["log".into(), format!("--format={LOG_FORMAT}")];
        if options.first_parent {
            args.push("--first-parent".into());
        }
        if options.reverse {
            args.push("--reverse".into());
        }
        if let Some(count) = options.max_count {
            args.push(format!("--max-count={count}"));
        }
        args.push(options.range.spec(Some("HEAD")));
        let result = self
            .run_read(
                "git log",
                Some(repo_path),
                &args,
                options.timeout.unwrap_or(GIT_TIMEOUT),
            )
            .await?;
        parse_log(&result.stdout_lossy())
    }

    async fn blob_sizes(&self, repo_path: &str, blobs: &[String]) -> Result<Vec<Option<u64>>> {
        if blobs.is_empty() {
            return Ok(Vec::new());
        }
        for blob in blobs {
            validate_object_name("blobs", blob)?;
        }
        let script = format!(
            "{} | {GIT_READ} cat-file --batch-check",
            feed_object_names(blobs)
        );
        let result = self
            .run_script(
                "git cat-file --batch-check",
                Some(repo_path),
                script,
                None,
                GIT_TIMEOUT,
            )
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
            return Err(malformed(
                "git cat-file --batch-check",
                format!(
                    "{} objects answered for {} requested",
                    sizes.len(),
                    blobs.len()
                ),
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
        for blob in blobs {
            validate_object_name("blobs", blob)?;
        }
        let script = format!("{} | {GIT_READ} cat-file --batch", feed_object_names(blobs));
        let result = self
            .run_script(
                "git cat-file --batch",
                Some(repo_path),
                script,
                None,
                GIT_TIMEOUT,
            )
            .await?;
        parse_batch(&result.stdout, blobs.len(), max_bytes)
    }

    async fn config_set(&self, repo_path: &str, key: &str, value: &str) -> Result<()> {
        validate_config_key(key)?;
        self.run(
            "git config",
            Some(repo_path),
            &[
                "config".into(),
                "--local".into(),
                "--".into(),
                key.to_owned(),
                value.to_owned(),
            ],
            GIT_TIMEOUT,
        )
        .await?;
        Ok(())
    }

    async fn untracked_files(&self, repo_path: &str) -> Result<Vec<String>> {
        let result = self
            .run_read(
                "git ls-files",
                Some(repo_path),
                &[
                    "ls-files".into(),
                    "--others".into(),
                    "--exclude-standard".into(),
                    "-z".into(),
                ],
                GIT_TIMEOUT,
            )
            .await?;
        Ok(result
            .stdout
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
            .map(lossy)
            .collect())
    }

    async fn add_all(&self, repo_path: &str, pathspecs: &[String]) -> Result<()> {
        let mut args: Vec<String> = vec!["add".into(), "-A".into(), "--".into()];
        if pathspecs.is_empty() {
            args.push(".".into());
        } else {
            args.extend(pathspecs.iter().cloned());
        }
        self.run("git add", Some(repo_path), &args, GIT_TIMEOUT)
            .await?;
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

    #[test]
    fn raw_diff_entries_parse_every_status_and_zero_sides() {
        let output = concat!(
            ":000000 100644 0000000000000000000000000000000000000000 ",
            "1111111111111111111111111111111111111111 A\0added.txt\0",
            ":100644 100644 2222222222222222222222222222222222222222 ",
            "3333333333333333333333333333333333333333 M\0changed.txt\0",
            ":100644 100644 4444444444444444444444444444444444444444 ",
            "4444444444444444444444444444444444444444 R087\0old/name.rs\0new/name.rs\0",
            ":100644 000000 5555555555555555555555555555555555555555 ",
            "0000000000000000000000000000000000000000 D\0gone.txt\0",
        );
        let entries = parse_raw_diff(output.as_bytes()).expect("parses");
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].change, GitChange::Added);
        assert_eq!(entries[0].path, "added.txt");
        assert_eq!(entries[0].old_mode, None);
        assert_eq!(entries[0].new_mode.as_deref(), Some("100644"));
        assert_eq!(entries[0].old_blob, None);
        assert_eq!(entries[1].change, GitChange::Modified);
        assert_eq!(entries[2].change, GitChange::Renamed);
        assert_eq!(entries[2].old_path.as_deref(), Some("old/name.rs"));
        assert_eq!(entries[2].path, "new/name.rs");
        assert_eq!(entries[2].similarity, Some(87));
        assert_eq!(entries[3].change, GitChange::Deleted);
        assert_eq!(entries[3].new_blob, None);
        assert!(parse_raw_diff(b"garbage\0").is_err());
    }

    #[test]
    fn numstat_parses_counts_binaries_and_renames() {
        let output = "3\t1\tsrc/lib.rs\0-\t-\timage.png\x002\t0\t\0old.rs\0new.rs\0";
        let entries = parse_numstat(output.as_bytes()).expect("parses");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].additions, Some(3));
        assert_eq!(entries[0].deletions, Some(1));
        assert_eq!(entries[1].additions, None);
        assert_eq!(entries[1].deletions, None);
        assert_eq!(entries[2].old_path.as_deref(), Some("old.rs"));
        assert_eq!(entries[2].path, "new.rs");
    }

    #[test]
    fn logs_parse_separator_records_with_multiline_messages() {
        let output = concat!(
            "aaaa\x1ftttt\x1fpppp qqqq\x1fAda\x1fada@example.com\x1f2026-01-01T00:00:00+00:00",
            "\x1fBob\x1fbob@example.com\x1f2026-01-02T00:00:00+00:00\x1fsubject\n\nbody line\n\x1e\n",
            "bbbb\x1fuuuu\x1f\x1fAda\x1fada@example.com\x1f2026-01-03T00:00:00+00:00",
            "\x1fAda\x1fada@example.com\x1f2026-01-03T00:00:00+00:00\x1froot\n\x1e\n",
        );
        let commits = parse_log(output).expect("parses");
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].sha, "aaaa");
        assert_eq!(commits[0].parents, ["pppp", "qqqq"]);
        assert_eq!(commits[0].author.name, "Ada");
        assert_eq!(commits[0].committer.email, "bob@example.com");
        assert_eq!(commits[0].message, "subject\n\nbody line");
        assert!(commits[1].parents.is_empty());
        assert_eq!(commits[1].message, "root");
    }

    #[test]
    fn batch_output_yields_bytes_missing_and_capped_objects() {
        let output = b"1111111111111111111111111111111111111111 blob 6\nhello\n\n\
                       2222222222222222222222222222222222222222 missing\n\
                       3333333333333333333333333333333333333333 blob 3\nbig\n";
        let blobs = parse_batch(output, 3, 4).expect("parses");
        assert_eq!(blobs[0], None, "over the cap");
        assert_eq!(blobs[1], None, "missing");
        assert_eq!(blobs[2].as_deref(), Some(&b"big"[..]));
        let blobs = parse_batch(output, 3, 100).expect("parses");
        assert_eq!(blobs[0].as_deref(), Some(&b"hello\n"[..]));
        assert!(
            parse_batch(output, 4, 100).is_err(),
            "fewer answers than requests"
        );
        assert!(
            parse_batch(
                b"1111111111111111111111111111111111111111 blob 9\nshort\n",
                1,
                100
            )
            .is_err(),
            "a truncated stream is refused"
        );
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
        let exec = ScriptedExec::new(vec![
            ScriptedExec::ok(""),
            ScriptedExec::ok(""),
            ScriptedExec::ok(""),
        ]);
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
