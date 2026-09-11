//! Hybrid git operations for Daytona sandboxes.
//!
//! A branch clone uses Daytona's toolbox git API, matching Fabro's
//! established path. A clone pinned to a commit or a tag runs the shared
//! exec-derived pinned clone instead: the toolbox has no tag selector, and
//! its commit pin clones the branch first and checks the commit out
//! afterwards, so a pin outside a shallow window fails after a checkout
//! at the branch head exists — and it fails outright for a local remote.
//! The derived clone fetches the pin itself, whatever the depth. The
//! remaining operations use the shared exec-derived implementation, which
//! preserves Fabro's command semantics and per-call credential handling.

use std::sync::Arc;

use async_trait::async_trait;
use daytona_sdk::GitCloneOptions as DaytonaGitCloneOptions;
use sandbox_driver::{
    DerivedGit, Error, Git, GitBranches, GitCheckoutOptions, GitCloneOptions, GitCommit,
    GitCommitOptions, GitCredentials, GitDiffEntry, GitDiffOptions, GitFailure, GitFailureKind,
    GitFetchOptions, GitLogOptions, GitNumstat, GitPushOptions, GitStatus, ProviderError, Result,
};

use crate::exec::DaytonaExec;
use crate::{DaytonaClient, daytona_error};

/// Daytona's provider-owned hybrid git implementation.
pub struct DaytonaGit {
    client:       DaytonaClient,
    sandbox_id:   String,
    working_dir:  String,
    derived_exec: DaytonaExec,
}

impl DaytonaGit {
    pub(crate) fn new(client: DaytonaClient, sandbox_id: String, working_dir: String) -> Self {
        Self {
            derived_exec: DaytonaExec::new(
                Arc::clone(&client),
                sandbox_id.clone(),
                working_dir.clone(),
            ),
            client,
            sandbox_id,
            working_dir,
        }
    }

    fn resolve_path(&self, path: &str) -> String {
        if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("{}/{}", self.working_dir.trim_end_matches('/'), path)
        }
    }

    fn derived(&self) -> DerivedGit<'_> {
        DerivedGit::new(&self.derived_exec).with_runtime_directory(crate::RUNTIME_DIRECTORY)
    }
}

/// Turns the toolbox clone's failure into the classified git failure the
/// derived clone produces, so both transports and every provider report
/// a rejected credential or a missing revision the same way. The
/// toolbox answers a rejected git credential with an authentication
/// status, which [`daytona_error`] maps to [`Error::Auth`]; the remote
/// rejected the git credential, not Daytona the API key, so that becomes
/// [`GitFailureKind::AuthRejected`]. Rate limits, timeouts, and
/// transport failures are not git outcomes and pass through.
fn classify_native_clone(error: Error) -> Error {
    match error {
        Error::Auth(auth) => {
            let mut provider = ProviderError::new(auth.provider.clone(), auth.reason.clone());
            provider.code = Some("auth".to_owned());
            Error::Git(GitFailure::classified(
                "git clone",
                GitFailureKind::AuthRejected,
                Some(provider),
            ))
        }
        Error::Provider(provider) if provider.code.as_deref() != Some("timeout") => {
            Error::Git(GitFailure::from_provider("git clone", provider))
        }
        other => other,
    }
}

fn clone_options(options: &GitCloneOptions) -> Result<DaytonaGitCloneOptions> {
    let depth = options
        .depth
        .map(|depth| {
            i32::try_from(depth).map_err(|_| {
                sandbox_driver::Error::invalid_spec(
                    "git.clone.depth",
                    "Daytona requires a depth no greater than i32::MAX",
                )
            })
        })
        .transpose()?;
    let (username, password) = options
        .credentials
        .as_ref()
        .map(|credentials| {
            (
                Some(credentials.username.clone()),
                Some(credentials.password.clone()),
            )
        })
        .unwrap_or_default();
    Ok(DaytonaGitCloneOptions {
        branch: options.branch.clone(),
        // Pinned clones never reach the toolbox; see the module docs.
        commit_id: None,
        username,
        password,
        insecure_skip_tls: None,
        depth,
    })
}

#[async_trait]
impl Git for DaytonaGit {
    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "daytona", sandbox_id = %self.sandbox_id),
        err
    )]
    async fn clone_repo(
        &self,
        url: &str,
        target_path: &str,
        options: &GitCloneOptions,
    ) -> Result<()> {
        options.validate()?;
        if options.tag.is_some() || options.commit.is_some() {
            // The derived pinned clone fetches the commit or the qualified
            // tag ref directly and attaches the branch; see the module
            // docs for why the toolbox's pin is not used.
            return self.derived().clone_repo(url, target_path, options).await;
        }
        let sandbox = self
            .client
            .get(&self.sandbox_id)
            .await
            .map_err(|error| daytona_error("fetching sandbox for git clone", error))?;
        let git = sandbox
            .git()
            .await
            .map_err(|error| daytona_error("connecting to the git toolbox", error))?;
        let repo_path = self.resolve_path(target_path);
        git.clone(url, &repo_path, clone_options(options)?)
            .await
            .map_err(|error| {
                classify_native_clone(daytona_error("cloning git repository", error))
            })?;
        Ok(())
    }

    async fn status(&self, repo_path: &str) -> Result<GitStatus> {
        self.derived().status(repo_path).await
    }

    async fn add(&self, repo_path: &str, paths: &[String]) -> Result<()> {
        self.derived().add(repo_path, paths).await
    }

    async fn commit(&self, repo_path: &str, options: &GitCommitOptions) -> Result<String> {
        self.derived().commit(repo_path, options).await
    }

    async fn push(&self, repo_path: &str, options: &GitPushOptions) -> Result<()> {
        self.derived().push(repo_path, options).await
    }

    async fn pull(&self, repo_path: &str, credentials: Option<&GitCredentials>) -> Result<()> {
        self.derived().pull(repo_path, credentials).await
    }

    async fn branches(&self, repo_path: &str) -> Result<GitBranches> {
        self.derived().branches(repo_path).await
    }

    async fn checkout(&self, repo_path: &str, options: &GitCheckoutOptions) -> Result<()> {
        self.derived().checkout(repo_path, options).await
    }

    async fn set_ambient_credentials(
        &self,
        repo_path: &str,
        credentials: Option<&GitCredentials>,
    ) -> Result<()> {
        self.derived()
            .set_ambient_credentials(repo_path, credentials)
            .await
    }

    async fn fetch(&self, repo_path: &str, options: &GitFetchOptions) -> Result<()> {
        self.derived().fetch(repo_path, options).await
    }

    async fn rev_parse(&self, repo_path: &str, revision: &str) -> Result<String> {
        self.derived().rev_parse(repo_path, revision).await
    }

    async fn is_ancestor(&self, repo_path: &str, ancestor: &str, descendant: &str) -> Result<bool> {
        self.derived()
            .is_ancestor(repo_path, ancestor, descendant)
            .await
    }

    async fn diff_entries(
        &self,
        repo_path: &str,
        options: &GitDiffOptions,
    ) -> Result<Vec<GitDiffEntry>> {
        self.derived().diff_entries(repo_path, options).await
    }

    async fn diff_numstat(
        &self,
        repo_path: &str,
        options: &GitDiffOptions,
    ) -> Result<Vec<GitNumstat>> {
        self.derived().diff_numstat(repo_path, options).await
    }

    async fn diff_patch(&self, repo_path: &str, options: &GitDiffOptions) -> Result<String> {
        self.derived().diff_patch(repo_path, options).await
    }

    async fn log(&self, repo_path: &str, options: &GitLogOptions) -> Result<Vec<GitCommit>> {
        self.derived().log(repo_path, options).await
    }

    async fn blob_sizes(&self, repo_path: &str, blobs: &[String]) -> Result<Vec<Option<u64>>> {
        self.derived().blob_sizes(repo_path, blobs).await
    }

    async fn blobs(
        &self,
        repo_path: &str,
        blobs: &[String],
        max_bytes: u64,
    ) -> Result<Vec<Option<Vec<u8>>>> {
        self.derived().blobs(repo_path, blobs, max_bytes).await
    }

    async fn config_set(&self, repo_path: &str, key: &str, value: &str) -> Result<()> {
        self.derived().config_set(repo_path, key, value).await
    }

    async fn untracked_files(&self, repo_path: &str) -> Result<Vec<String>> {
        self.derived().untracked_files(repo_path).await
    }

    async fn add_all(&self, repo_path: &str, pathspecs: &[String]) -> Result<()> {
        self.derived().add_all(repo_path, pathspecs).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_clone_options_preserve_branch_depth_and_credentials() {
        let mut options = GitCloneOptions::default();
        options.branch = Some("main".to_owned());
        options.depth = Some(7);
        options.credentials = Some(GitCredentials::new("user", "secret"));
        let mapped = clone_options(&options).expect("options map");
        assert_eq!(mapped.branch.as_deref(), Some("main"));
        assert_eq!(mapped.commit_id, None);
        assert_eq!(mapped.depth, Some(7));
        assert_eq!(mapped.username.as_deref(), Some("user"));
        assert_eq!(mapped.password.as_deref(), Some("secret"));
        assert_eq!(mapped.insecure_skip_tls, None);
    }

    #[test]
    fn native_clone_failures_are_classified_git_failures() {
        let kind = sandbox_driver::ProviderKind::try_new("daytona").expect("static kind");
        let auth = Error::Auth(sandbox_driver::AuthError::new(kind.clone(), "cloning"));
        assert!(matches!(
            classify_native_clone(auth),
            Error::Git(failure) if failure.kind() == GitFailureKind::AuthRejected
        ));

        let mut not_found = ProviderError::new(kind.clone(), "reference not found");
        not_found.code = Some("400".to_owned());
        let Error::Git(failure) = classify_native_clone(Error::Provider(not_found)) else {
            panic!("expected a git failure");
        };
        assert_eq!(failure.kind(), GitFailureKind::Unclassified);
        assert_eq!(
            failure.provider().and_then(|p| p.code.as_deref()),
            Some("400")
        );

        let mut timeout = ProviderError::new(kind, "cloning git repository");
        timeout.code = Some("timeout".to_owned());
        assert!(
            matches!(
                classify_native_clone(Error::Provider(timeout)),
                Error::Provider(_)
            ),
            "an unknown outcome is not a git classification"
        );
    }

    #[test]
    fn native_clone_rejects_depths_that_do_not_fit_the_sdk() {
        let mut options = GitCloneOptions::default();
        options.depth = Some(u32::MAX);
        clone_options(&options).expect_err("oversized depth is invalid");
    }
}
