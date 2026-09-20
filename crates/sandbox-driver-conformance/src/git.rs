//! The Git facet over a sandbox-local bare remote: pinned clones,
//! ambient credentials, typed verbs, and the branch/commit/push/pull
//! round trip.

use std::time::Duration;

use sandbox_driver::{
    Capability, Error, ExecSpec, Git, GitChange, GitCheckoutOptions, GitCloneOptions,
    GitCommitOptions, GitCredentials, GitDiffOptions, GitFailureKind, GitFetchOptions,
    GitLogOptions, GitPushOptions, GitRevisionRange,
};

use crate::Conformance;
use crate::check::{CheckOutcome, PASS, fail, require_on};

/// A clone pinned to a tag checks out the tagged commit on the admitted
/// branch, whatever the provider's clone implementation is. The fixture
/// advances `main` past the tag and adds a branch that shares the tag's
/// name, so only a clone that fetches the fully qualified tag ref passes.
pub(super) async fn git_clone_pins_a_tag(ctx: &Conformance) -> CheckOutcome {
    ctx.with_ready(|sandbox| async move {
        require_on(sandbox.capabilities(), Capability::Git)?;
        let Some(git) = sandbox.git() else {
            return fail("git is declared but the facet is absent");
        };

        let setup = sandbox
            .exec()
            .run(
                &ExecSpec::bash(
                    "rm -rf conformance-tag && \
                     mkdir conformance-tag && \
                     cd conformance-tag && \
                     git init -q --bare remote.git && \
                     git init -q -b main seed && \
                     cd seed && \
                     git -c user.name=Conformance \
                         -c user.email=conformance@example.com \
                         commit -q --allow-empty -m tagged && \
                     git -c user.name=Conformance \
                         -c user.email=conformance@example.com \
                         tag -a -m release v1.0.0 && \
                     git rev-parse 'HEAD^{commit}' && \
                     git -c user.name=Conformance \
                         -c user.email=conformance@example.com \
                         commit -q --allow-empty -m later && \
                     git branch v1.0.0 HEAD && \
                     git remote add origin ../remote.git && \
                     git push -q origin refs/heads/main refs/heads/v1.0.0 refs/tags/v1.0.0 && \
                     git --git-dir=../remote.git symbolic-ref HEAD refs/heads/main",
                )
                .timeout(Duration::from_secs(60)),
            )
            .await
            .map_err(|error| format!("tag fixture setup failed: {error}"))?;
        if !setup.success() {
            return fail(format!(
                "tag fixture setup exited {:?}: {}",
                setup.exit_code,
                setup.stderr_lossy()
            ));
        }
        let tagged = setup.stdout_lossy().trim().to_owned();
        if tagged.len() != 40 {
            return fail(format!("tag fixture printed no commit SHA: {tagged:?}"));
        }

        let root = sandbox.working_directory().trim_end_matches('/');
        let remote_url = format!("file://{root}/conformance-tag/remote.git");
        let mut options = GitCloneOptions::default();
        options.branch = Some("main".to_owned());
        options.tag = Some("v1.0.0".to_owned());
        options.depth = Some(1);
        git.clone_repo(&remote_url, "conformance-tag/clone", &options)
            .await
            .map_err(|error| format!("tag clone failed: {error}"))?;

        let repo = "conformance-tag/clone";
        let status = git
            .status(repo)
            .await
            .map_err(|error| format!("tag clone status failed: {error}"))?;
        if status.current_branch.as_deref() != Some("main") || status.detached {
            return fail(format!("tag clone status is wrong: {status:?}"));
        }
        let head = sandbox
            .exec()
            .run(
                &ExecSpec::new("git")
                    .args(["rev-parse", "HEAD"])
                    .working_dir(repo)
                    .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("tag clone rev-parse failed: {error}"))?;
        if !head.success() || head.stdout_lossy().trim() != tagged {
            return fail(format!(
                "tag clone checked out {:?}, not the tagged commit {tagged}",
                head.stdout_lossy().trim()
            ));
        }

        let mut missing = GitCloneOptions::default();
        missing.branch = Some("main".to_owned());
        missing.tag = Some("v9.9.9".to_owned());
        match git
            .clone_repo(&remote_url, "conformance-tag/missing", &missing)
            .await
        {
            Ok(()) => return fail("a clone pinned to a missing tag succeeded"),
            Err(Error::Git(failure)) if failure.kind() == GitFailureKind::RefNotFound => {}
            Err(error) => {
                return fail(format!(
                    "missing tag failed with an unexpected kind: {error}"
                ));
            }
        }
        let leftover = sandbox
            .exec()
            .run(
                &ExecSpec::new("git")
                    .args(["rev-parse", "--verify", "HEAD"])
                    .working_dir("conformance-tag/missing")
                    .timeout(Duration::from_secs(30)),
            )
            .await;
        if leftover.is_ok_and(|result| result.success()) {
            return fail("a failed tag clone left a checkout at the branch head");
        }
        PASS
    })
    .await
}

/// What `git credential fill` answers for the fixture's origin host when
/// only the repository's own configuration is consulted: the helper
/// output, or nothing when no helper answers and prompting is off.
async fn credential_fill(exec: &dyn sandbox_driver::Exec, repo: &str) -> Result<String, String> {
    let result = exec
        .run(
            &ExecSpec::bash(
                "printf 'protocol=https\\nhost=git.example.invalid\\n\\n' | git credential fill",
            )
            .working_dir(repo)
            .env_var("GIT_TERMINAL_PROMPT", "0")
            .env_var("GIT_CONFIG_NOSYSTEM", "1")
            .env_var("GIT_CONFIG_GLOBAL", "/dev/null")
            .timeout(Duration::from_secs(30)),
        )
        .await
        .map_err(|error| format!("credential fill failed to run: {error}"))?;
    Ok(result.stdout_lossy())
}

/// Ambient credentials reach a workload's own git commands through a
/// credential store, never through the remote URL. After installation
/// `git credential fill` answers for the origin host with only the
/// repository's configuration consulted, the origin URL is unchanged, and
/// the store is private and lives under the runtime directory when the
/// sandbox has one. Rotation replaces the secret in place; removal leaves
/// nothing for `fill` to answer with.
pub(super) async fn git_ambient_credentials_apply(ctx: &Conformance) -> CheckOutcome {
    ctx.with_ready(|sandbox| async move {
        require_on(sandbox.capabilities(), Capability::Git)?;
        let Some(git) = sandbox.git() else {
            return fail("git is declared but the facet is absent");
        };

        let repo = "conformance-credentials";
        let origin = "https://git.example.invalid/org/repo.git";
        let setup = sandbox
            .exec()
            .run(
                &ExecSpec::bash(
                    "rm -rf conformance-credentials && \
                     git init -q conformance-credentials && \
                     cd conformance-credentials && \
                     git remote add origin \"$CONFORMANCE_ORIGIN\"",
                )
                .env_var("CONFORMANCE_ORIGIN", origin)
                .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("credential fixture setup failed: {error}"))?;
        if !setup.success() {
            return fail(format!(
                "credential fixture setup exited {:?}: {}",
                setup.exit_code,
                setup.stderr_lossy()
            ));
        }

        let first = GitCredentials::new("x-access-token", "first-secret/1=");
        git.set_ambient_credentials(repo, Some(&first))
            .await
            .map_err(|error| format!("installing ambient credentials failed: {error}"))?;
        let filled = credential_fill(sandbox.exec(), repo).await?;
        if !filled.contains("username=x-access-token\n")
            || !filled.contains("password=first-secret/1=\n")
        {
            return fail(format!(
                "git did not pick up the ambient credentials: {filled:?}"
            ));
        }

        let remote = sandbox
            .exec()
            .run(
                &ExecSpec::new("git")
                    .args(["remote", "get-url", "origin"])
                    .working_dir(repo)
                    .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("remote get-url failed: {error}"))?;
        if remote.stdout_lossy().trim() != origin {
            return fail(format!(
                "the origin URL changed: {:?}",
                remote.stdout_lossy().trim()
            ));
        }

        let helpers = sandbox
            .exec()
            .run(
                &ExecSpec::new("git")
                    .args(["config", "--local", "--get-all", "credential.helper"])
                    .working_dir(repo)
                    .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("reading credential.helper failed: {error}"))?
            .stdout_lossy();
        let Some(store) = helpers
            .lines()
            .find_map(|line| line.strip_prefix("store --file="))
        else {
            return fail(format!("no store helper is configured: {helpers:?}"));
        };
        let store = store.trim().trim_matches('\'').to_owned();
        if let Some(runtime_directory) = sandbox.runtime_directory() {
            let prefix = format!("{}/", runtime_directory.trim_end_matches('/'));
            if !store.starts_with(&prefix) {
                return fail(format!(
                    "store {store:?} is not under the runtime directory {runtime_directory:?}"
                ));
            }
        }
        let metadata = sandbox
            .fs()
            .metadata(&store)
            .await
            .map_err(|error| format!("store metadata failed: {error}"))?;
        if metadata.mode.map(|mode| mode & 0o777) != Some(0o600) {
            return fail(format!("store mode is {:?}, expected 0600", metadata.mode));
        }

        let second = GitCredentials::new("x-access-token", "second-secret");
        git.set_ambient_credentials(repo, Some(&second))
            .await
            .map_err(|error| format!("rotating ambient credentials failed: {error}"))?;
        let filled = credential_fill(sandbox.exec(), repo).await?;
        if !filled.contains("password=second-secret\n") || filled.contains("first-secret") {
            return fail(format!("rotation did not replace the secret: {filled:?}"));
        }

        git.set_ambient_credentials(repo, None)
            .await
            .map_err(|error| format!("removing ambient credentials failed: {error}"))?;
        let filled = credential_fill(sandbox.exec(), repo).await?;
        if filled.contains("password=") {
            return fail(format!("removal left credentials behind: {filled:?}"));
        }
        let exists = sandbox
            .fs()
            .exists(&store)
            .await
            .map_err(|error| format!("store exists check failed: {error}"))?;
        if exists {
            return fail(format!("removal left the store file {store:?} behind"));
        }
        PASS
    })
    .await
}

/// The read and plumbing verbs report typed results that agree with git's
/// own answers: revisions, ancestry, the three diff views, the log, blob
/// sizes and contents, configuration, untracked paths, staging, and a
/// fetch, over a sandbox-local remote.
pub(super) async fn git_verbs_report_typed_results(ctx: &Conformance) -> CheckOutcome {
    ctx.with_ready(|sandbox| async move {
        require_on(sandbox.capabilities(), Capability::Git)?;
        let Some(git) = sandbox.git() else {
            return fail("git is declared but the facet is absent");
        };

        // Two commits on main: the first adds seed.txt, the second changes
        // it and adds added.txt. The fixture prints both commit ids and
        // clones the bare remote itself: a provider's native clone may not
        // reach a file transport, and clone has its own checks.
        let setup = sandbox
            .exec()
            .run(
                &ExecSpec::bash(
                    "rm -rf conformance-verbs && \
                     mkdir conformance-verbs && \
                     cd conformance-verbs && \
                     git init -q --bare remote.git && \
                     git init -q -b main seed && \
                     cd seed && \
                     printf 'seed\\n' > seed.txt && \
                     git add -- seed.txt && \
                     git -c user.name=Conformance \
                         -c user.email=conformance@example.com \
                         commit -q -m first && \
                     git rev-parse HEAD && \
                     printf 'seed\\nmore\\n' > seed.txt && \
                     printf 'added\\n' > added.txt && \
                     git add -- seed.txt added.txt && \
                     git -c user.name=Conformance \
                         -c user.email=conformance@example.com \
                         commit -q -m 'second\n\nbody' && \
                     git rev-parse HEAD && \
                     git remote add origin ../remote.git && \
                     git push -q origin refs/heads/main && \
                     git --git-dir=../remote.git symbolic-ref HEAD refs/heads/main && \
                     cd .. && \
                     git clone -q -b main remote.git clone",
                )
                .timeout(Duration::from_secs(60)),
            )
            .await
            .map_err(|error| format!("verbs fixture setup failed: {error}"))?;
        if !setup.success() {
            return fail(format!(
                "verbs fixture setup exited {:?}: {}",
                setup.exit_code,
                setup.stderr_lossy()
            ));
        }
        let stdout = setup.stdout_lossy();
        let mut ids = stdout.lines().map(str::trim);
        let (Some(base), Some(head)) = (ids.next(), ids.next()) else {
            return fail(format!("verbs fixture printed no commit ids: {stdout:?}"));
        };
        let (base, head) = (base.to_owned(), head.to_owned());

        let repo = "conformance-verbs/clone";

        let resolved = git
            .rev_parse(repo, "HEAD")
            .await
            .map_err(|error| format!("rev_parse failed: {error}"))?;
        if resolved != head {
            return fail(format!("rev_parse HEAD gave {resolved}, not {head}"));
        }
        let parent = git
            .rev_parse(repo, "HEAD~1")
            .await
            .map_err(|error| format!("rev_parse HEAD~1 failed: {error}"))?;
        if parent != base {
            return fail(format!("rev_parse HEAD~1 gave {parent}, not {base}"));
        }
        if git.rev_parse(repo, "no-such-revision").await.is_ok() {
            return fail("rev_parse of an unknown revision succeeded");
        }

        match (
            git.is_ancestor(repo, &base, &head).await,
            git.is_ancestor(repo, &head, &base).await,
        ) {
            (Ok(true), Ok(false)) => {}
            (forward, backward) => {
                return fail(format!("is_ancestor answered {forward:?} and {backward:?}"));
            }
        }

        let range = GitRevisionRange::new(base.clone()).to(head.clone());
        let options = GitDiffOptions::new(range.clone()).find_renames(50);
        let entries = git
            .diff_entries(repo, &options)
            .await
            .map_err(|error| format!("diff_entries failed: {error}"))?;
        let added = entries
            .iter()
            .find(|entry| entry.path == "added.txt")
            .ok_or_else(|| format!("diff_entries lacks added.txt: {entries:?}"))?;
        if added.change != GitChange::Added
            || added.old_blob.is_some()
            || added.new_blob.is_none()
            || added.new_mode.as_deref() != Some("100644")
        {
            return fail(format!("added.txt entry is wrong: {added:?}"));
        }
        let changed = entries
            .iter()
            .find(|entry| entry.path == "seed.txt")
            .ok_or_else(|| format!("diff_entries lacks seed.txt: {entries:?}"))?;
        if changed.change != GitChange::Modified || changed.old_blob == changed.new_blob {
            return fail(format!("seed.txt entry is wrong: {changed:?}"));
        }
        let added_blob = added.new_blob.clone().expect("checked above");

        let numstat = git
            .diff_numstat(repo, &options)
            .await
            .map_err(|error| format!("diff_numstat failed: {error}"))?;
        let added_stat = numstat
            .iter()
            .find(|entry| entry.path == "added.txt")
            .ok_or_else(|| format!("diff_numstat lacks added.txt: {numstat:?}"))?;
        if added_stat.additions != Some(1) || added_stat.deletions != Some(0) {
            return fail(format!("added.txt numstat is wrong: {added_stat:?}"));
        }

        let patch = git
            .diff_patch(repo, &options)
            .await
            .map_err(|error| format!("diff_patch failed: {error}"))?;
        if !patch.contains("diff --git a/added.txt b/added.txt") || !patch.contains("\n+added") {
            return fail(format!("diff_patch is wrong: {patch:?}"));
        }

        let commits = git
            .log(repo, &GitLogOptions::new(range.clone()).first_parent())
            .await
            .map_err(|error| format!("log failed: {error}"))?;
        let [commit] = commits.as_slice() else {
            return fail(format!("log of one commit gave {commits:?}"));
        };
        if commit.sha != head
            || commit.parents != [base.clone()]
            || commit.author.name != "Conformance"
            || commit.author.email != "conformance@example.com"
            || commit.message != "second\n\nbody"
            || !commit.author.date.starts_with("20")
        {
            return fail(format!("log commit is wrong: {commit:?}"));
        }

        let zero = "0".repeat(40);
        let sizes = git
            .blob_sizes(repo, &[added_blob.clone(), zero.clone()])
            .await
            .map_err(|error| format!("blob_sizes failed: {error}"))?;
        if sizes != [Some(6), None] {
            return fail(format!("blob_sizes gave {sizes:?}"));
        }
        let contents = git
            .blobs(repo, &[added_blob.clone(), zero.clone()], 1024)
            .await
            .map_err(|error| format!("blobs failed: {error}"))?;
        if contents != [Some(b"added\n".to_vec()), None] {
            return fail(format!("blobs gave {contents:?}"));
        }
        let only_added = [added_blob.clone()];
        let capped = git
            .blobs(repo, &only_added, 2)
            .await
            .map_err(|error| format!("capped blobs failed: {error}"))?;
        if capped != [None] {
            return fail(format!("a blob over the cap was returned: {capped:?}"));
        }

        git.config_set(repo, "user.name", "Verbs Conformance")
            .await
            .map_err(|error| format!("config_set failed: {error}"))?;
        let name = sandbox
            .exec()
            .run(
                &ExecSpec::new("git")
                    .args(["config", "--local", "--get", "user.name"])
                    .working_dir(repo)
                    .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("reading user.name failed: {error}"))?;
        if name.stdout_lossy().trim() != "Verbs Conformance" {
            return fail(format!(
                "config_set did not land: {:?}",
                name.stdout_lossy()
            ));
        }

        sandbox
            .fs()
            .write("conformance-verbs/clone/untracked.txt", b"new\n")
            .await
            .map_err(|error| format!("writing the untracked file failed: {error}"))?;
        let untracked = git
            .untracked_files(repo)
            .await
            .map_err(|error| format!("untracked_files failed: {error}"))?;
        if untracked != ["untracked.txt"] {
            return fail(format!("untracked_files gave {untracked:?}"));
        }
        git.add_all(repo, &[])
            .await
            .map_err(|error| format!("add_all failed: {error}"))?;
        let untracked = git
            .untracked_files(repo)
            .await
            .map_err(|error| format!("untracked_files after add failed: {error}"))?;
        if !untracked.is_empty() {
            return fail(format!("add_all left {untracked:?} untracked"));
        }
        let status = git
            .status(repo)
            .await
            .map_err(|error| format!("status after add failed: {error}"))?;
        if !status
            .dirty_paths
            .iter()
            .any(|path| path == "untracked.txt")
        {
            return fail(format!("add_all did not stage the file: {status:?}"));
        }

        let mut fetch = GitFetchOptions::default();
        fetch.refspecs = vec!["+refs/heads/main:refs/remotes/origin/verbs".to_owned()];
        git.fetch(repo, &fetch)
            .await
            .map_err(|error| format!("fetch failed: {error}"))?;
        let fetched = git
            .rev_parse(repo, "refs/remotes/origin/verbs")
            .await
            .map_err(|error| format!("rev_parse of the fetched ref failed: {error}"))?;
        if fetched != head {
            return fail(format!("fetch landed {fetched}, not {head}"));
        }
        PASS
    })
    .await
}

/// Git uses a sandbox-local bare remote so every operation can run without
/// external credentials or network access. Providers still choose their
/// native, derived, or hybrid implementation behind the normalized facet.
pub(super) async fn git_round_trip(ctx: &Conformance) -> CheckOutcome {
    ctx.with_ready(|sandbox| async move {
        require_on(sandbox.capabilities(), Capability::Git)?;
        let Some(git) = sandbox.git() else {
            return fail("git is declared but the facet is absent");
        };

        let setup = sandbox
            .exec()
            .run(
                &ExecSpec::bash(
                    "rm -rf conformance-git && \
                     mkdir conformance-git && \
                     cd conformance-git && \
                     git init -q --bare remote.git && \
                     git init -q -b main seed && \
                     cd seed && \
                     printf 'seed\\n' > seed.txt && \
                     git add -- seed.txt && \
                     git -c user.name=Conformance \
                         -c user.email=conformance@example.com \
                         commit -q -m seed && \
                     git remote add origin ../remote.git && \
                     git push -q origin main && \
                     git --git-dir=../remote.git symbolic-ref HEAD refs/heads/main",
                )
                .timeout(Duration::from_secs(60)),
            )
            .await
            .map_err(|error| format!("git fixture setup failed: {error}"))?;
        if !setup.success() {
            return fail(format!(
                "git fixture setup exited {:?}: {}",
                setup.exit_code,
                setup.stderr_lossy()
            ));
        }

        let root = sandbox.working_directory().trim_end_matches('/');
        let local_remote_path = format!("{root}/conformance-git/remote.git");
        let local_remote_url = format!("file://{local_remote_path}");
        let clone_url = ctx.specs.git_clone_url().unwrap_or(&local_remote_url);
        git.clone_repo(
            clone_url,
            "conformance-git/clone",
            &GitCloneOptions::default(),
        )
        .await
        .map_err(|error| format!("clone failed: {error}"))?;

        // A provider-specific clone fixture can have arbitrary content and a
        // different default branch. Normalize it onto the sandbox-local bare
        // remote before testing the rest of the Git contract.
        let origin = sandbox
            .exec()
            .run(
                &ExecSpec::bash(
                    "git remote set-url origin \"$CONFORMANCE_REMOTE\" && \
                     git fetch -q origin \
                         +refs/heads/main:refs/remotes/origin/main && \
                     git checkout -q -B main origin/main",
                )
                .env_var("CONFORMANCE_REMOTE", local_remote_path)
                .working_dir("conformance-git/clone")
                .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("local origin setup failed: {error}"))?;
        if !origin.success() {
            return fail(format!(
                "local origin setup exited {:?}: stdout={:?}, stderr={:?}",
                origin.exit_code,
                origin.stdout_lossy(),
                origin.stderr_lossy()
            ));
        }

        let repo = "conformance-git/clone";
        let status = git
            .status(repo)
            .await
            .map_err(|error| format!("initial status failed: {error}"))?;
        if status.current_branch.as_deref() != Some("main")
            || status.detached
            || !status.dirty_paths.is_empty()
        {
            return fail(format!("initial clone status is wrong: {status:?}"));
        }

        git.checkout(repo, &GitCheckoutOptions::new("feature").create())
            .await
            .map_err(|error| format!("create feature branch failed: {error}"))?;
        sandbox
            .fs()
            .write("conformance-git/clone/feature.txt", b"feature\n")
            .await
            .map_err(|error| format!("write feature file failed: {error}"))?;
        let status = git
            .status(repo)
            .await
            .map_err(|error| format!("dirty status failed: {error}"))?;
        if status.current_branch.as_deref() != Some("feature")
            || !status.dirty_paths.iter().any(|path| path == "feature.txt")
        {
            return fail(format!("dirty feature status is wrong: {status:?}"));
        }

        git.add(repo, &["feature.txt".to_owned()])
            .await
            .map_err(|error| format!("add failed: {error}"))?;
        let sha = git
            .commit(
                repo,
                &GitCommitOptions::new("feature commit", "Conformance", "conformance@example.com"),
            )
            .await
            .map_err(|error| format!("commit failed: {error}"))?;
        if sha.len() != 40 {
            return fail(format!("commit returned an invalid SHA: {sha:?}"));
        }
        let status = git
            .status(repo)
            .await
            .map_err(|error| format!("status after commit failed: {error}"))?;
        if status.head.as_deref() != Some(sha.as_str()) {
            return fail(format!(
                "status head {:?} does not name the commit {sha}",
                status.head
            ));
        }

        let branches = git
            .branches(repo)
            .await
            .map_err(|error| format!("branches failed: {error}"))?;
        if branches.current.as_deref() != Some("feature")
            || !branches.branches.iter().any(|branch| branch == "main")
            || !branches.branches.iter().any(|branch| branch == "feature")
        {
            return fail(format!("branch list is wrong: {branches:?}"));
        }

        let mut push = GitPushOptions::default();
        push.remote = Some("origin".to_owned());
        push.branch = Some("feature".to_owned());
        push.set_upstream = true;
        git.push(repo, &push)
            .await
            .map_err(|error| format!("push failed: {error}"))?;
        let remote_feature = sandbox
            .exec()
            .run(
                &ExecSpec::new("git")
                    .args(["--git-dir=remote.git", "rev-parse", "refs/heads/feature"])
                    .working_dir("conformance-git")
                    .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("remote feature check failed: {error}"))?;
        if !remote_feature.success() || remote_feature.stdout_lossy().trim() != sha {
            return fail(format!(
                "remote feature is wrong: stdout={:?}, stderr={:?}",
                remote_feature.stdout_lossy(),
                remote_feature.stderr_lossy()
            ));
        }

        // A refspec pushes the same commit under another remote name, and a
        // reset checkout starts a branch at a chosen revision.
        let mut by_refspec = GitPushOptions::default();
        by_refspec.remote = Some("origin".to_owned());
        by_refspec.refspec = Some("HEAD:refs/heads/from-refspec".to_owned());
        git.push(repo, &by_refspec)
            .await
            .map_err(|error| format!("refspec push failed: {error}"))?;
        let remote_refspec = sandbox
            .exec()
            .run(
                &ExecSpec::new("git")
                    .args([
                        "--git-dir=remote.git",
                        "rev-parse",
                        "refs/heads/from-refspec",
                    ])
                    .working_dir("conformance-git")
                    .timeout(Duration::from_secs(30)),
            )
            .await
            .map_err(|error| format!("remote refspec check failed: {error}"))?;
        if !remote_refspec.success() || remote_refspec.stdout_lossy().trim() != sha {
            return fail(format!(
                "remote from-refspec is wrong: stdout={:?}, stderr={:?}",
                remote_refspec.stdout_lossy(),
                remote_refspec.stderr_lossy()
            ));
        }
        git.checkout(
            repo,
            &GitCheckoutOptions::new("hotfix")
                .create_or_reset()
                .start_point("main"),
        )
        .await
        .map_err(|error| format!("checkout hotfix at main failed: {error}"))?;
        let hotfix = git
            .status(repo)
            .await
            .map_err(|error| format!("hotfix status failed: {error}"))?;
        if hotfix.current_branch.as_deref() != Some("hotfix")
            || hotfix.head.as_deref() == Some(sha.as_str())
        {
            return fail(format!("hotfix did not start at main: {hotfix:?}"));
        }

        git.checkout(repo, &GitCheckoutOptions::new("main"))
            .await
            .map_err(|error| format!("checkout main failed: {error}"))?;
        let upstream = sandbox
            .exec()
            .run(
                &ExecSpec::bash(
                    "printf 'upstream\\n' > upstream.txt && \
                     git add -- upstream.txt && \
                     git -c user.name=Conformance \
                         -c user.email=conformance@example.com \
                         commit -q -m upstream && \
                     git push -q origin main",
                )
                .working_dir("conformance-git/seed")
                .timeout(Duration::from_secs(60)),
            )
            .await
            .map_err(|error| format!("upstream update failed: {error}"))?;
        if !upstream.success() {
            return fail(format!(
                "upstream update exited {:?}: {}",
                upstream.exit_code,
                upstream.stderr_lossy()
            ));
        }
        git.pull(repo, None)
            .await
            .map_err(|error| format!("pull failed: {error}"))?;
        let pulled = sandbox
            .fs()
            .read("conformance-git/clone/upstream.txt")
            .await
            .map_err(|error| format!("read pulled file failed: {error}"))?;
        if pulled != b"upstream\n" {
            return fail(format!("pulled file has wrong content: {pulled:?}"));
        }
        let status = git
            .status(repo)
            .await
            .map_err(|error| format!("final status failed: {error}"))?;
        if status.current_branch.as_deref() != Some("main") || !status.dirty_paths.is_empty() {
            return fail(format!("final status is wrong: {status:?}"));
        }
        PASS
    })
    .await
}
