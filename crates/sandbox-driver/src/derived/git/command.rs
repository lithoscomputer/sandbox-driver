//! The hardened `git` invocation every derived verb runs as, and how a
//! failed one is reported.

use std::fmt::Display;
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

/// One `git` invocation: the hardened prefix, per-call `-c` values, the
/// verb, and its quoted arguments, rendered as a shell command by
/// [`GitCommand::script`].
///
/// `label` names the operation in a classified failure (`"git push"`,
/// `"git diff --raw"`); `timeout` defaults to [`GIT_TIMEOUT`].
#[must_use]
pub(super) struct GitCommand {
    pub(super) label:   &'static str,
    pub(super) timeout: Duration,
    read_only:          bool,
    configs:            Vec<String>,
    verb:               &'static str,
    args:               Vec<String>,
}

impl GitCommand {
    pub(super) fn new(label: &'static str, verb: &'static str) -> Self {
        Self {
            label,
            timeout: GIT_TIMEOUT,
            read_only: false,
            configs: Vec::new(),
            verb,
            args: Vec::new(),
        }
    }

    /// A read verb: runs under [`GIT_READ`], which also refuses the file
    /// transport.
    pub(super) fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    /// A `-c key=value` for this call only, placed before the verb.
    pub(super) fn config(mut self, value: impl Into<String>) -> Self {
        self.configs.push(value.into());
        self
    }

    /// Every `-c key=value` in `values`, placed before the verb. An
    /// `Option` adds its value when present.
    pub(super) fn configs(mut self, values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.configs.extend(values.into_iter().map(Into::into));
        self
    }

    pub(super) fn arg(mut self, value: impl Into<String>) -> Self {
        self.args.push(value.into());
        self
    }

    /// Every argument in `values`, in order. An `Option` adds its value
    /// when present.
    pub(super) fn args(mut self, values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args.extend(values.into_iter().map(Into::into));
        self
    }

    /// `flag` when `condition` holds.
    pub(super) fn flag_if(self, condition: bool, flag: &str) -> Self {
        if condition { self.arg(flag) } else { self }
    }

    /// `flag` followed by `value`, when there is one.
    pub(super) fn option(self, flag: &str, value: Option<impl Display>) -> Self {
        match value {
            Some(value) => self.arg(flag).arg(value.to_string()),
            None => self,
        }
    }

    pub(super) fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The shell command: the prefix, then every `-c` value, the verb,
    /// and the arguments, each shell-quoted.
    pub(super) fn script(&self) -> String {
        let mut command = String::from(if self.read_only { GIT_READ } else { GIT });
        for config in &self.configs {
            push_quoted(&mut command, "-c");
            push_quoted(&mut command, config);
        }
        push_quoted(&mut command, self.verb);
        for arg in &self.args {
            push_quoted(&mut command, arg);
        }
        command
    }
}

fn push_quoted(command: &mut String, word: &str) {
    command.push(' ');
    command.push_str(&shell_quote(word));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_render_configs_before_the_verb_and_quote_every_word() {
        let command = GitCommand::new("git fetch", "fetch")
            .configs(Some("url.a.insteadOf=b"))
            .option("--depth", Some(1))
            .option("--filter", None::<&str>)
            .flag_if(true, "--no-tags")
            .flag_if(false, "--prune")
            .arg("origin")
            .args(["--", "it's"]);
        assert_eq!(
            command.script(),
            format!(
                "{GIT} '-c' 'url.a.insteadOf=b' 'fetch' '--depth' '1' '--no-tags' 'origin' '--' \
                 'it'\\''s'"
            )
        );
        assert_eq!(command.timeout, GIT_TIMEOUT);
        assert_eq!(command.label, "git fetch");
    }

    #[test]
    fn read_only_scripts_run_under_the_read_prefix() {
        let command = GitCommand::new("git log", "log")
            .read_only()
            .timeout(Duration::from_secs(7));
        assert_eq!(command.script(), format!("{GIT_READ} 'log'"));
        assert_eq!(command.timeout, Duration::from_secs(7));
    }
}
