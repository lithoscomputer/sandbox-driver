//! The hardened `git` invocation every derived verb runs as, and how a
//! failed one is reported.

use std::time::Duration;
use std::{fmt, io};

use crate::derived::shell_quote;
use crate::error::{Error, ExecFailure, GitFailure};
use crate::exec::{ExecResult, ExecSpec};

pub(super) const GIT_TIMEOUT: Duration = Duration::from_secs(60);
pub(super) const CLONE_TIMEOUT: Duration = Duration::from_secs(600);
pub(super) const NETWORK_TIMEOUT: Duration = Duration::from_secs(300);

/// Every derived git call runs hardened: no background maintenance, no
/// repository hooks, no fsmonitor daemon, paths unquoted, and no commit
/// or tag signing. The environment also disables terminal prompts
/// ([`GIT_ENV`]), and the diff verbs pass `--no-ext-diff` so a configured
/// external diff driver never runs.
pub(super) const GIT: &str = "git -c maintenance.auto=0 -c gc.auto=0 -c core.hooksPath=/dev/null \
                   -c core.fsmonitor=false -c core.quotePath=false -c commit.gpgsign=false \
                   -c tag.gpgsign=false";
/// Read verbs additionally refuse the file transport, so a diff or log
/// can never fetch through a local path.
pub(super) const GIT_READ: &str = "git -c maintenance.auto=0 -c gc.auto=0 -c core.hooksPath=/dev/null \
                        -c core.fsmonitor=false -c core.quotePath=false -c commit.gpgsign=false \
                        -c tag.gpgsign=false -c protocol.file.allow=never";
/// Environment every derived git call runs with: never a terminal prompt.
pub(super) const GIT_ENV: &[(&str, &str)] = &[("GIT_TERMINAL_PROMPT", "0")];

/// The shell command for `prefix` and quoted `args`.
pub(super) fn git_command(prefix: &str, args: &[String]) -> String {
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
pub(super) fn git_spec(
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
pub(super) fn git_failure(label: &str, result: ExecResult) -> Error {
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
pub(super) fn malformed(what: &str, detail: impl fmt::Display) -> Error {
    Error::io(
        format!("parsing {what}"),
        io::Error::other(detail.to_string()),
    )
}

pub(super) fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The `printf` that feeds object names to a batch command.
pub(super) fn feed_object_names(names: &[String]) -> String {
    let mut command = String::from("printf '%s\\n'");
    for name in names {
        command.push(' ');
        command.push_str(&shell_quote(name));
    }
    command
}
