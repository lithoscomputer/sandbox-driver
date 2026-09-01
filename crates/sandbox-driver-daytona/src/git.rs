//! Hybrid git operations for Daytona sandboxes.
//!
//! Clone uses Daytona's toolbox git API, matching Fabro's established path.
//! The remaining operations use the shared exec-derived implementation, which
//! preserves Fabro's command semantics and per-call credential handling.

use std::sync::Arc;

use async_trait::async_trait;
use daytona_sdk::GitCloneOptions as DaytonaGitCloneOptions;
use sandbox_driver::{
    DerivedGit, Git, GitBranches, GitCloneOptions, GitCommitOptions, GitCredentials,
    GitPushOptions, GitStatus, Result,
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
            .map_err(|error| daytona_error("cloning git repository", error))?;
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
    fn native_clone_rejects_depths_that_do_not_fit_the_sdk() {
        let mut options = GitCloneOptions::default();
        options.depth = Some(u32::MAX);
        clone_options(&options).expect_err("oversized depth is invalid");
    }
}
