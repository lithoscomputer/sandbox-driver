//! File operations the [`Files`](super::Files) capability leaves out, derived
//! over [`Sandbox::exec`]. They are library code, not a provider capability,
//! so they work unchanged on every provider and plugin whose workload has
//! Bash with `stat`, `mv`, `rm`, `rmdir` and `mkdir`: GNU, `BusyBox` or BSD.
//!
//! A relative path resolves against the directory a command starts in, which
//! is the sandbox's working directory.

use std::str;

use super::workload::validate_name;
use super::{
    Captured, CommandError, CommandFailure, Error, ExecSpec, FileKind, Sandbox, Termination,
    run_captured,
};

/// The budget of each command these helpers run.
const TIMEOUT_MS: u64 = 60_000;

/// What a script prints in place of its result when the path is not there.
const MISSING: &str = "sandbox-driver:missing";

/// What `stat` reports about a path. A symbolic link is described itself,
/// not the path it names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileStat {
    pub kind:           FileKind,
    /// The byte length of a file. Other kinds report what the workload's
    /// `stat` does.
    pub size:           u64,
    /// Permission bits, with the set-id and sticky bits, when the workload's
    /// `stat` printed them as octal.
    pub mode:           Option<u32>,
    /// Unix epoch milliseconds, at the one-second precision `stat` prints.
    pub modified_at_ms: Option<u64>,
}

/// Describes `path` without following a symbolic link.
///
/// # Errors
///
/// [`Error::NotFound`] inside [`CommandError::Sandbox`] when nothing is at
/// `path`, which includes a path the command's user cannot see.
pub async fn stat_path(sandbox: &dyn Sandbox, path: &str) -> Result<FileStat, CommandError> {
    let script = format!(
        "p={path}\n{missing}\nif stat -c %s -- / >/dev/null 2>&1; then stat -c '%F|%s|%a|%Y' -- \
         \"$p\"; else stat -f '%HT|%z|%Mp%Lp|%m' -- \"$p\"; fi",
        path = quoted("path", path)?,
        missing = if_missing("p"),
    );
    let captured = run(sandbox, script).await?;
    read_stat(path, captured)
}

/// Whether something is at `path`. A symbolic link is followed, so a link to
/// a path that is gone does not exist.
///
/// # Errors
///
/// [`CommandError::Failed`] when the check itself could not run to an
/// answer.
pub async fn path_exists(sandbox: &dyn Sandbox, path: &str) -> Result<bool, CommandError> {
    let script = format!("[ -e {} ]", quoted("path", path)?);
    let captured = run(sandbox, script).await?;
    read_exists(&captured)
}

/// Removes `path`. With `recursive`, a directory goes with everything in it;
/// without, a directory must be empty. A symbolic link is removed itself,
/// never the path it names. Removing a path that is not there succeeds.
///
/// # Errors
///
/// [`CommandError::Failed`] when the workload refused, for example for a
/// directory that is not empty.
pub async fn remove_path(
    sandbox: &dyn Sandbox,
    path: &str,
    recursive: bool,
) -> Result<(), CommandError> {
    let path = quoted("path", path)?;
    let script = if recursive {
        format!("rm -rf -- {path}")
    } else {
        format!(
            "p={path}\nif [ ! -e \"$p\" ] && [ ! -L \"$p\" ]; then exit 0; fi\nif [ -d \"$p\" ] && \
             [ ! -L \"$p\" ]; then rmdir -- \"$p\"; else rm -f -- \"$p\"; fi"
        )
    };
    succeeded("remove", &run(sandbox, script).await?)
}

/// Moves `from` to `to` as `mv` does: an existing file at `to` is replaced,
/// and an existing directory at `to` receives `from` inside it. The parent
/// of `to` must exist.
///
/// # Errors
///
/// [`Error::NotFound`] inside [`CommandError::Sandbox`] when nothing is at
/// `from`; nothing has moved.
pub async fn rename_path(sandbox: &dyn Sandbox, from: &str, to: &str) -> Result<(), CommandError> {
    let script = format!(
        "p={from}\n{missing}\nmv -- \"$p\" {to}",
        from = quoted("from", from)?,
        to = quoted("to", to)?,
        missing = if_missing("p"),
    );
    let captured = run(sandbox, script).await?;
    read_rename(from, captured)
}

/// Creates the directory `path` and any missing parents. A directory that is
/// already there is left as it is.
///
/// # Errors
///
/// [`CommandError::Failed`] when the workload refused, for example because a
/// file is in the way.
pub async fn create_dir_all(sandbox: &dyn Sandbox, path: &str) -> Result<(), CommandError> {
    let script = format!("mkdir -p -- {}", quoted("path", path)?);
    succeeded("create directory", &run(sandbox, script).await?)
}

async fn run(sandbox: &dyn Sandbox, script: String) -> Result<Captured, Error> {
    let mut spec = ExecSpec::bash(script);
    spec.timeout_ms = Some(TIMEOUT_MS);
    run_captured(sandbox, spec).await
}

/// `value`, once it is valid as one argument, quoted for Bash source.
fn quoted(field: &str, value: &str) -> Result<String, Error> {
    validate_name(field, value)?;
    Ok(shell_quote(value))
}

/// Quotes a string for safe interpolation into Bash source.
fn shell_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for c in value.chars() {
        if c == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(c);
        }
    }
    quoted.push('\'');
    quoted
}

/// Shell that prints [`MISSING`] and stops when nothing is at `$variable`,
/// not even a link to a path that is gone.
fn if_missing(variable: &str) -> String {
    format!(
        "if [ ! -e \"${variable}\" ] && [ ! -L \"${variable}\" ]; then echo '{MISSING}'; exit 0; \
         fi"
    )
}

fn succeeded(context: &str, captured: &Captured) -> Result<(), CommandError> {
    if captured.success() {
        Ok(())
    } else {
        Err(CommandFailure::new(context, captured).into())
    }
}

/// The capture of a command that succeeded with nothing lost.
fn complete(context: &str, captured: Captured) -> Result<Captured, CommandError> {
    succeeded(context, &captured)?;
    captured
        .into_complete()
        .map_err(|incomplete| unreadable(context, &incomplete.captured))
}

/// The script's stdout as text without its final newline.
fn answer<'a>(context: &str, captured: &'a Captured) -> Result<&'a str, CommandError> {
    let text = str::from_utf8(&captured.stdout.bytes).map_err(|_| unreadable(context, captured))?;
    Ok(text.strip_suffix('\n').unwrap_or(text))
}

fn unreadable(context: &str, captured: &Captured) -> CommandError {
    CommandError::UnexpectedOutput(Box::new(CommandFailure::new(context, captured)))
}

fn not_found(path: &str) -> CommandError {
    CommandError::Sandbox(Error::NotFound {
        resource: "file".to_owned(),
        id:       path.to_owned(),
    })
}

fn read_stat(path: &str, captured: Captured) -> Result<FileStat, CommandError> {
    let captured = &complete("stat", captured)?;
    let text = answer("stat", captured)?;
    if text == MISSING {
        return Err(not_found(path));
    }
    let fields: Vec<&str> = text.split('|').collect();
    let &[kind, size, mode, modified] = fields.as_slice() else {
        return Err(unreadable("stat", captured));
    };
    Ok(FileStat {
        kind:           parse_kind(kind),
        size:           size.parse().map_err(|_| unreadable("stat", captured))?,
        mode:           u32::from_str_radix(mode, 8).ok(),
        modified_at_ms: modified
            .parse::<u64>()
            .ok()
            .map(|seconds| seconds.saturating_mul(1000)),
    })
}

/// The kind a `stat` type string names. GNU and `BusyBox` print `regular
/// file` or `regular empty file`; BSD prints `Regular File`.
fn parse_kind(text: &str) -> FileKind {
    match text.to_ascii_lowercase().as_str() {
        "regular file" | "regular empty file" => FileKind::File,
        "directory" => FileKind::Directory,
        "symbolic link" => FileKind::Symlink,
        _ => FileKind::Other,
    }
}

fn read_exists(captured: &Captured) -> Result<bool, CommandError> {
    match (captured.outcome.termination, captured.outcome.exit_code) {
        (Termination::Exited, Some(0)) => Ok(true),
        (Termination::Exited, Some(1)) => Ok(false),
        _ => Err(CommandFailure::new("exists", captured).into()),
    }
}

fn read_rename(from: &str, captured: Captured) -> Result<(), CommandError> {
    let captured = &complete("rename", captured)?;
    match answer("rename", captured)? {
        "" => Ok(()),
        MISSING => Err(not_found(from)),
        _ => Err(unreadable("rename", captured)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exited(exit_code: i32, stdout: &str) -> Captured {
        ended(Termination::Exited, Some(exit_code), stdout)
    }

    fn ended(termination: Termination, exit_code: Option<i32>, stdout: &str) -> Captured {
        Captured::ended(termination, exit_code, stdout.as_bytes(), b"")
    }

    #[test]
    fn quotes_single_quotes_safely() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("a b;c$d"), "'a b;c$d'");
    }

    #[test]
    fn stat_reads_what_gnu_and_bsd_print() {
        // GNU and BusyBox: `%F|%s|%a|%Y`.
        assert_eq!(
            read_stat("f", exited(0, "regular file|42|644|1700000000\n")),
            Ok(FileStat {
                kind:           FileKind::File,
                size:           42,
                mode:           Some(0o644),
                modified_at_ms: Some(1_700_000_000_000),
            })
        );
        assert_eq!(
            read_stat("f", exited(0, "regular empty file|0|4755|1\n")).map(|stat| stat.mode),
            Ok(Some(0o4755))
        );
        // BSD: `%HT|%z|%Mp%Lp|%m`.
        assert_eq!(
            read_stat("d", exited(0, "Directory|96|1777|1700000000\n")),
            Ok(FileStat {
                kind:           FileKind::Directory,
                size:           96,
                mode:           Some(0o1777),
                modified_at_ms: Some(1_700_000_000_000),
            })
        );
        for (text, kind) in [
            ("symbolic link", FileKind::Symlink),
            ("Symbolic Link", FileKind::Symlink),
            ("fifo", FileKind::Other),
            ("socket", FileKind::Other),
            ("Character Device", FileKind::Other),
        ] {
            assert_eq!(
                read_stat("p", exited(0, &format!("{text}|0|644|1\n"))).map(|stat| stat.kind),
                Ok(kind),
                "{text}"
            );
        }
    }

    #[test]
    fn stat_tells_a_missing_path_from_a_failed_and_an_unreadable_command() {
        assert_eq!(
            read_stat("gone/file", exited(0, &format!("{MISSING}\n"))),
            Err(CommandError::Sandbox(Error::NotFound {
                resource: "file".into(),
                id:       "gone/file".into(),
            }))
        );
        assert!(matches!(
            read_stat("f", exited(1, "")),
            Err(CommandError::Failed(failure)) if failure.context == "stat"
        ));
        // Too few fields, a size that is not a number, and output a provider
        // reported losing part of.
        let mut lossy = exited(0, "regular file|42|644|1\n");
        lossy.stdout.omitted_bytes = 1;
        for captured in [
            exited(0, "regular file|42\n"),
            exited(0, "regular file|big|644|1\n"),
            lossy,
        ] {
            assert!(
                matches!(
                    read_stat("f", captured.clone()),
                    Err(CommandError::UnexpectedOutput(_))
                ),
                "{captured:?}"
            );
        }
    }

    #[test]
    fn only_a_clean_exit_with_one_means_the_path_is_absent() {
        assert_eq!(read_exists(&exited(0, "")), Ok(true));
        assert_eq!(read_exists(&exited(1, "")), Ok(false));
        // A shell that could not start, and a command stopped at its
        // deadline while reporting the shell's own code.
        for captured in [
            exited(127, ""),
            ended(Termination::TimedOut, Some(1), ""),
            ended(Termination::Lost, None, ""),
        ] {
            assert!(
                matches!(read_exists(&captured), Err(CommandError::Failed(_))),
                "{captured:?}"
            );
        }
    }

    #[test]
    fn rename_reports_a_missing_source_as_not_found() {
        assert_eq!(read_rename("a", exited(0, "")), Ok(()));
        assert_eq!(
            read_rename("a", exited(0, &format!("{MISSING}\n"))),
            Err(not_found("a"))
        );
        assert!(matches!(
            read_rename("a", exited(1, "")),
            Err(CommandError::Failed(failure)) if failure.context == "rename"
        ));
    }

    #[test]
    fn a_path_is_one_shell_word_whatever_it_contains() {
        assert_eq!(
            quoted("path", "it's -a $(dir)").as_deref(),
            Ok("'it'\\''s -a $(dir)'")
        );
        for path in ["", "a\0b"] {
            assert!(
                matches!(quoted("path", path), Err(Error::InvalidSpec { path, .. }) if path == "path"),
                "{path:?}"
            );
        }
    }
}
