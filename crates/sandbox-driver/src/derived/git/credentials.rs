//! Credentials for derived git: per-call URL rewrites for one network
//! operation, and the ambient credential store.

use std::fmt::Write as _;

use super::DerivedGit;
use super::command::{GIT, GIT_TIMEOUT};
use crate::derived::shell_quote;
use crate::error::{Error, Result};
use crate::git::GitCredentials;

impl DerivedGit<'_> {
    /// A per-call config value (`url.<authed>.insteadOf=<plain>`) that
    /// embeds credentials for one network operation via `-c`. The
    /// command still addresses the remote by name, so upstream and
    /// remote-tracking bookkeeping stay on the named remote and the
    /// credentialed URL is never written into the repository
    /// configuration. `None` when the remote is not http(s).
    pub(super) async fn credential_rewrite(
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
pub(super) const CREDENTIAL_ENV: &str = "SANDBOX_DRIVER_GIT_CREDENTIAL";

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

/// Embeds credentials into an http(s) URL; `None` for other schemes.
pub(super) fn authed_url(url: &str, credentials: &GitCredentials) -> Option<String> {
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

impl DerivedGit<'_> {
    /// Installs or removes the repository's ambient credentials; the body
    /// of [`Git::set_ambient_credentials`](crate::git::Git::set_ambient_credentials).
    pub(super) async fn apply_ambient_credentials(
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::Git;
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
}
