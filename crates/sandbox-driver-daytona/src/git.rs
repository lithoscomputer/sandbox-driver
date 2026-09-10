//! Hybrid git operations for Daytona sandboxes.
//!
//! Clone uses Daytona's toolbox git API, matching Fabro's established path.
//! The toolbox selects a branch (`refs/heads/<name>`) or a commit and has no
//! tag selector, so a clone pinned to a tag runs the shared exec-derived
//! pinned clone instead. The remaining operations use the shared
//! exec-derived implementation, which preserves Fabro's command semantics
//! and per-call credential handling.

use std::sync::Arc;

use async_trait::async_trait;
use daytona_sdk::GitCloneOptions as DaytonaGitCloneOptions;
use sandbox_driver::{
    DerivedGit, Error, Git, GitBranches, GitCloneOptions, GitCommitOptions, GitCredentials,
    GitFailure, GitFailureKind, GitPushOptions, GitStatus, ProviderError, Result,
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
        DerivedGit::new(&self.derived_exec)
    }

    /// Best-effort removal of a clone target after the clone failed. The
    /// clone error is what the caller sees; a cleanup failure is logged
    /// because it leaves a partial checkout that a retry would trip over.
    async fn remove_failed_clone(&self, sandbox: &daytona_sdk::Sandbox, repo_path: &str) {
        let fs = match sandbox.fs().await {
            Ok(fs) => fs,
            Err(error) => {
                tracing::warn!(error = %error, "failed clone cleanup could not reach the toolbox");
                return;
            }
        };
        match fs.delete_file(repo_path, true).await {
            Ok(()) => {}
            Err(error) if crate::is_not_found(&error) => {}
            Err(error) => {
                tracing::warn!(error = %error, "failed clone left a partial checkout behind");
            }
        }
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
        commit_id: options.commit.clone(),
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
        if options.tag.is_some() {
            // The toolbox has no tag selector; the derived pinned clone
            // fetches the qualified tag ref and attaches the branch.
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
        let cloned = git
            .clone(url, &repo_path, clone_options(options)?)
            .await
            .map_err(|error| classify_native_clone(daytona_error("cloning git repository", error)));
        if let Err(error) = cloned {
            // The toolbox clones the branch first and pins afterwards, so a
            // failed pin leaves a checkout at the branch head. The contract
            // says an unavailable commit fails outright, never substitutes
            // the head, so remove whatever the failed clone wrote.
            self.remove_failed_clone(&sandbox, &repo_path).await;
            return Err(error);
        }
        // The toolbox leaves a pinned clone detached; attach the
        // requested branch for cross-provider consistency (fabro ran
        // the same step after every native pinned clone).
        if let (Some(branch), Some(commit)) = (&options.branch, &options.commit) {
            self.derived()
                .attach_pinned_branch(&repo_path, branch, commit)
                .await?;
        }
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

    async fn checkout(&self, repo_path: &str, branch: &str, create: bool) -> Result<()> {
        self.derived().checkout(repo_path, branch, create).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_clone_options_preserve_branch_commit_depth_and_credentials() {
        let mut options = GitCloneOptions::default();
        options.branch = Some("main".to_owned());
        options.commit = Some("abc123".to_owned());
        options.depth = Some(7);
        options.credentials = Some(GitCredentials::new("user", "secret"));
        let mapped = clone_options(&options).expect("options map");
        assert_eq!(mapped.branch.as_deref(), Some("main"));
        assert_eq!(mapped.commit_id.as_deref(), Some("abc123"));
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
