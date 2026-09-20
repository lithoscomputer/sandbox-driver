//! The Git facet over a sandbox-local bare remote: pinned clones,
//! ambient credentials, typed verbs, and the branch/commit/push/pull
//! round trip.

use std::time::Duration;

use sandbox_driver::{
    Capability, Error, ExecSpec, Git, GitChange, GitCheckoutOptions, GitCloneOptions,
    GitCommitOptions, GitCredentials, GitDiffOptions, GitFacet, GitFailureKind, GitFetchOptions,
    GitLogOptions, GitPushOptions, GitRevisionRange, Sandbox,
};

use crate::Conformance;
use crate::check::{COMMAND_TIMEOUT, CheckOutcome, PASS, Verdict, fail, phase, require_on, run_ok};

/// The committer every fixture commit uses.
const GIT_IDENTITY: &str = "-c user.name=Conformance -c user.email=conformance@example.com";

/// Fixture scripts run several git commands; they get more time than one.
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(60);

/// A Bash script that builds the suite's Git fixture under `dir`: a bare
/// `remote.git` whose HEAD names `main`, and a `seed` repository on
/// `main` with `origin` pointing at the remote. `steps` then run inside
/// `seed`.
fn seed_repository(dir: &str, steps: &str) -> String {
    format!(
        "rm -rf {dir} && \
         mkdir {dir} && \
         cd {dir} && \
         git init -q --bare remote.git && \
         git --git-dir=remote.git symbolic-ref HEAD refs/heads/main && \
         git init -q -b main seed && \
         cd seed && \
         git remote add origin ../remote.git && \
         {steps}"
    )
}

/// `git rev-parse <revision>` in `repo`, demanding success.
async fn rev_parse_via_exec(
    sandbox: &dyn Sandbox,
    label: &str,
    repo: &str,
    revision: &str,
) -> Result<String, Verdict> {
    let result = run_ok(
        sandbox,
        label,
        &ExecSpec::new("git")
            .args(["rev-parse", revision])
            .working_dir(repo)
            .timeout(COMMAND_TIMEOUT),
    )
    .await?;
    Ok(result.stdout_lossy().trim().to_owned())
}

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

        let steps = format!(
            "git {GIT_IDENTITY} commit -q --allow-empty -m tagged && \
             git {GIT_IDENTITY} tag -a -m release v1.0.0 && \
             git rev-parse 'HEAD^{{commit}}' && \
             git {GIT_IDENTITY} commit -q --allow-empty -m later && \
             git branch v1.0.0 HEAD && \
             git push -q origin refs/heads/main refs/heads/v1.0.0 refs/tags/v1.0.0"
        );
        let setup = run_ok(
            sandbox.as_ref(),
            "tag fixture setup",
            &ExecSpec::bash(seed_repository("conformance-tag", &steps)).timeout(FIXTURE_TIMEOUT),
        )
        .await?;
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
        let head =
            rev_parse_via_exec(sandbox.as_ref(), "tag clone rev-parse", repo, "HEAD").await?;
        if head != tagged {
            return fail(format!(
                "tag clone checked out {head:?}, not the tagged commit {tagged}"
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
                    .timeout(COMMAND_TIMEOUT),
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
            .timeout(COMMAND_TIMEOUT),
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
                .timeout(COMMAND_TIMEOUT),
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
                    .timeout(COMMAND_TIMEOUT),
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
                    .timeout(COMMAND_TIMEOUT),
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
        let steps = format!(
            "printf 'seed\\n' > seed.txt && \
             git add -- seed.txt && \
             git {GIT_IDENTITY} commit -q -m first && \
             git rev-parse HEAD && \
             printf 'seed\\nmore\\n' > seed.txt && \
             printf 'added\\n' > added.txt && \
             git add -- seed.txt added.txt && \
             git {GIT_IDENTITY} commit -q -m 'second\n\nbody' && \
             git rev-parse HEAD && \
             git push -q origin refs/heads/main && \
             cd .. && \
             git clone -q -b main remote.git clone"
        );
        let setup = run_ok(
            sandbox.as_ref(),
            "verbs fixture setup",
            &ExecSpec::bash(seed_repository("conformance-verbs", &steps)).timeout(FIXTURE_TIMEOUT),
        )
        .await?;
        let stdout = setup.stdout_lossy();
        let mut ids = stdout.lines().map(str::trim);
        let (Some(base), Some(head)) = (ids.next(), ids.next()) else {
            return fail(format!("verbs fixture printed no commit ids: {stdout:?}"));
        };
        let (base, head) = (base.to_owned(), head.to_owned());
        let repo = "conformance-verbs/clone";

        phase(
            "revisions and ancestry",
            check_revisions_and_ancestry(&git, repo, &base, &head),
        )
        .await?;
        let range = GitRevisionRange::new(base.clone()).to(head.clone());
        let options = GitDiffOptions::new(range.clone()).find_renames(50);
        let added_blob = phase("diff views", check_diff_views(&git, repo, &options)).await?;
        phase("log", check_log(&git, repo, &range, &base, &head)).await?;
        phase("blobs", check_blobs(&git, repo, &added_blob)).await?;
        phase(
            "config and staging",
            check_config_and_staging(sandbox.as_ref(), &git, repo),
        )
        .await?;
        phase("fetch", check_fetch(&git, repo, &head)).await
    })
    .await
}

/// `rev_parse` answers for HEAD and its parent and refuses an unknown
/// revision; `is_ancestor` orders the two commits one way only.
async fn check_revisions_and_ancestry(
    git: &GitFacet<'_>,
    repo: &str,
    base: &str,
    head: &str,
) -> CheckOutcome {
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
        git.is_ancestor(repo, base, head).await,
        git.is_ancestor(repo, head, base).await,
    ) {
        (Ok(true), Ok(false)) => PASS,
        (forward, backward) => fail(format!("is_ancestor answered {forward:?} and {backward:?}")),
    }
}

/// The three diff views agree on the second commit: entries with blobs
/// and modes, a numstat, and a patch. Returns the added file's blob id.
async fn check_diff_views(
    git: &GitFacet<'_>,
    repo: &str,
    options: &GitDiffOptions,
) -> Result<String, Verdict> {
    let entries = git
        .diff_entries(repo, options)
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
        .diff_numstat(repo, options)
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
        .diff_patch(repo, options)
        .await
        .map_err(|error| format!("diff_patch failed: {error}"))?;
    if !patch.contains("diff --git a/added.txt b/added.txt") || !patch.contains("\n+added") {
        return fail(format!("diff_patch is wrong: {patch:?}"));
    }
    Ok(added_blob)
}

/// A first-parent log of the range is the one commit, with every field
/// the fixture set.
async fn check_log(
    git: &GitFacet<'_>,
    repo: &str,
    range: &GitRevisionRange,
    base: &str,
    head: &str,
) -> CheckOutcome {
    let commits = git
        .log(repo, &GitLogOptions::new(range.clone()).first_parent())
        .await
        .map_err(|error| format!("log failed: {error}"))?;
    let [commit] = commits.as_slice() else {
        return fail(format!("log of one commit gave {commits:?}"));
    };
    if commit.sha != head {
        return fail(format!("log commit sha is {}, not {head}", commit.sha));
    }
    if commit.parents != [base.to_owned()] {
        return fail(format!(
            "log commit parents are {:?}, expected [{base}]",
            commit.parents
        ));
    }
    if commit.author.name != "Conformance" {
        return fail(format!(
            "log commit author name is {:?}, not \"Conformance\"",
            commit.author.name
        ));
    }
    if commit.author.email != "conformance@example.com" {
        return fail(format!(
            "log commit author email is {:?}, not \"conformance@example.com\"",
            commit.author.email
        ));
    }
    if commit.message != "second\n\nbody" {
        return fail(format!(
            "log commit message is {:?}, not the two-paragraph fixture message",
            commit.message
        ));
    }
    if !commit.author.date.starts_with("20") {
        return fail(format!(
            "log commit author date {:?} is not an ISO date",
            commit.author.date
        ));
    }
    PASS
}

/// Blob sizes and contents answer per id, `None` for an unknown id and
/// for a blob over the size cap.
async fn check_blobs(git: &GitFacet<'_>, repo: &str, added_blob: &str) -> CheckOutcome {
    let zero = "0".repeat(40);
    let sizes = git
        .blob_sizes(repo, &[added_blob.to_owned(), zero.clone()])
        .await
        .map_err(|error| format!("blob_sizes failed: {error}"))?;
    if sizes != [Some(6), None] {
        return fail(format!("blob_sizes gave {sizes:?}"));
    }
    let contents = git
        .blobs(repo, &[added_blob.to_owned(), zero], 1024)
        .await
        .map_err(|error| format!("blobs failed: {error}"))?;
    if contents != [Some(b"added\n".to_vec()), None] {
        return fail(format!("blobs gave {contents:?}"));
    }
    let only_added = [added_blob.to_owned()];
    let capped = git
        .blobs(repo, &only_added, 2)
        .await
        .map_err(|error| format!("capped blobs failed: {error}"))?;
    if capped != [None] {
        return fail(format!("a blob over the cap was returned: {capped:?}"));
    }
    PASS
}

/// `config_set` lands in the repository's own config; an untracked file
/// is reported until `add_all` stages it, after which status is dirty.
async fn check_config_and_staging(
    sandbox: &dyn Sandbox,
    git: &GitFacet<'_>,
    repo: &str,
) -> CheckOutcome {
    git.config_set(repo, "user.name", "Verbs Conformance")
        .await
        .map_err(|error| format!("config_set failed: {error}"))?;
    let name = sandbox
        .exec()
        .run(
            &ExecSpec::new("git")
                .args(["config", "--local", "--get", "user.name"])
                .working_dir(repo)
                .timeout(COMMAND_TIMEOUT),
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
    PASS
}

/// A fetch with an explicit refspec lands the remote's main under the
/// asked-for name.
async fn check_fetch(git: &GitFacet<'_>, repo: &str, head: &str) -> CheckOutcome {
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

        let steps = format!(
            "printf 'seed\\n' > seed.txt && \
             git add -- seed.txt && \
             git {GIT_IDENTITY} commit -q -m seed && \
             git push -q origin main"
        );
        run_ok(
            sandbox.as_ref(),
            "git fixture setup",
            &ExecSpec::bash(seed_repository("conformance-git", &steps)).timeout(FIXTURE_TIMEOUT),
        )
        .await?;
        let repo = "conformance-git/clone";

        phase(
            "clone and normalize",
            clone_and_normalize(ctx, sandbox.as_ref(), &git, repo),
        )
        .await?;
        let sha = phase(
            "branch, commit, and push",
            branch_commit_and_push(sandbox.as_ref(), &git, repo),
        )
        .await?;
        phase(
            "refspec and reset",
            refspec_and_reset(sandbox.as_ref(), &git, repo, &sha),
        )
        .await?;
        phase("pull", pull_upstream(sandbox.as_ref(), &git, repo)).await
    })
    .await
}

/// Clones the configured fixture into `repo` and points it at the
/// sandbox-local bare remote on `main`, clean.
async fn clone_and_normalize(
    ctx: &Conformance,
    sandbox: &dyn Sandbox,
    git: &GitFacet<'_>,
    repo: &str,
) -> CheckOutcome {
    let root = sandbox.working_directory().trim_end_matches('/');
    let local_remote_path = format!("{root}/conformance-git/remote.git");
    let local_remote_url = format!("file://{local_remote_path}");
    let clone_url = ctx.specs.git_clone_url().unwrap_or(&local_remote_url);
    git.clone_repo(clone_url, repo, &GitCloneOptions::default())
        .await
        .map_err(|error| format!("clone failed: {error}"))?;

    // A provider-specific clone fixture can have arbitrary content and a
    // different default branch. Normalize it onto the sandbox-local bare
    // remote before testing the rest of the Git contract.
    run_ok(
        sandbox,
        "local origin setup",
        &ExecSpec::bash(
            "git remote set-url origin \"$CONFORMANCE_REMOTE\" && \
             git fetch -q origin \
                 +refs/heads/main:refs/remotes/origin/main && \
             git checkout -q -B main origin/main",
        )
        .env_var("CONFORMANCE_REMOTE", local_remote_path)
        .working_dir(repo)
        .timeout(COMMAND_TIMEOUT),
    )
    .await?;

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
    PASS
}

/// A new branch, a dirty status, a commit whose sha status reports, a
/// branch list, and a push the bare remote confirms. Returns the sha.
async fn branch_commit_and_push(
    sandbox: &dyn Sandbox,
    git: &GitFacet<'_>,
    repo: &str,
) -> Result<String, Verdict> {
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
    let remote_feature = remote_ref(sandbox, "remote feature check", "refs/heads/feature").await?;
    if remote_feature != sha {
        return fail(format!(
            "remote feature is {remote_feature:?}, not the pushed commit {sha}"
        ));
    }
    Ok(sha)
}

/// A refspec pushes the same commit under another remote name, and a
/// reset checkout starts a branch at a chosen revision.
async fn refspec_and_reset(
    sandbox: &dyn Sandbox,
    git: &GitFacet<'_>,
    repo: &str,
    sha: &str,
) -> CheckOutcome {
    let mut by_refspec = GitPushOptions::default();
    by_refspec.remote = Some("origin".to_owned());
    by_refspec.refspec = Some("HEAD:refs/heads/from-refspec".to_owned());
    git.push(repo, &by_refspec)
        .await
        .map_err(|error| format!("refspec push failed: {error}"))?;
    let remote_refspec =
        remote_ref(sandbox, "remote refspec check", "refs/heads/from-refspec").await?;
    if remote_refspec != sha {
        return fail(format!(
            "remote from-refspec is {remote_refspec:?}, not the pushed commit {sha}"
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
    if hotfix.current_branch.as_deref() != Some("hotfix") || hotfix.head.as_deref() == Some(sha) {
        return fail(format!("hotfix did not start at main: {hotfix:?}"));
    }
    PASS
}

/// The seed repository advances the remote's main; `pull` on the clone's
/// main brings the new file down and leaves the tree clean.
async fn pull_upstream(sandbox: &dyn Sandbox, git: &GitFacet<'_>, repo: &str) -> CheckOutcome {
    git.checkout(repo, &GitCheckoutOptions::new("main"))
        .await
        .map_err(|error| format!("checkout main failed: {error}"))?;
    let steps = format!(
        "printf 'upstream\\n' > upstream.txt && \
         git add -- upstream.txt && \
         git {GIT_IDENTITY} commit -q -m upstream && \
         git push -q origin main"
    );
    run_ok(
        sandbox,
        "upstream update",
        &ExecSpec::bash(steps)
            .working_dir("conformance-git/seed")
            .timeout(FIXTURE_TIMEOUT),
    )
    .await?;
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
}

/// What the bare remote of the round-trip fixture has under `reference`.
async fn remote_ref(
    sandbox: &dyn Sandbox,
    label: &str,
    reference: &str,
) -> Result<String, Verdict> {
    let result = run_ok(
        sandbox,
        label,
        &ExecSpec::new("git")
            .args(["--git-dir=remote.git", "rev-parse", reference])
            .working_dir("conformance-git")
            .timeout(COMMAND_TIMEOUT),
    )
    .await?;
    Ok(result.stdout_lossy().trim().to_owned())
}
