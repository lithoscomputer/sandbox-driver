//! Content search and file walks inside a sandbox, derived over
//! [`Sandbox::exec`]. They are library code, not a provider capability, so
//! they work unchanged on every provider and plugin whose workload has Bash
//! and the tools each function names.
//!
//! A relative path resolves against the directory a command starts in, which
//! is the sandbox's working directory.

use std::fmt::Write as _;
use std::str;

use globset::GlobBuilder;
use serde::{Deserialize, Serialize};

use super::file_ops::{quoted, shell_quote, succeeded, unreadable};
use super::{
    Captured, CommandError, CommandFailure, Error, ExecSpec, Sandbox, Termination, run_captured,
};

/// The budget of each command these helpers run.
const TIMEOUT_MS: u64 = 30_000;

/// The exit code of a search that `head` cut short once it had every line it
/// needed: a successful run, truncated at the source.
const SIGPIPE_EXIT: i32 = 141;

/// Options for [`grep_files`].
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GrepOptions {
    pub case_insensitive: bool,
    /// The most matches to return, and the most taken from any one file.
    pub max_matches:      Option<usize>,
    /// Glob the searched files must match.
    pub include:          Option<String>,
}

/// One matching line.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GrepMatch {
    /// The file as the search tool printed it, which begins with the path
    /// that was searched.
    pub path:        String,
    pub line_number: u64,
    pub line:        String,
}

impl GrepMatch {
    pub fn new(path: impl Into<String>, line_number: u64, line: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            line_number,
            line: line.into(),
        }
    }
}

/// Options for [`walk_files`].
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WalkOptions {
    /// How many levels to descend; `1` is the files directly in the base.
    pub max_depth:    Option<usize>,
    /// Directory names pruned from the walk (e.g. `.git`, `node_modules`).
    pub exclude_dirs: Vec<String>,
}

/// One file from [`walk_files`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WalkedFile {
    /// Path relative to the walk base.
    pub path: String,
    /// `None` when the workload's `find` cannot report sizes (BSD and
    /// `BusyBox`).
    pub size: Option<u64>,
}

impl WalkedFile {
    pub fn new(path: impl Into<String>, size: Option<u64>) -> Self {
        Self {
            path: path.into(),
            size,
        }
    }
}

/// Searches the file `path`, or every file under the directory `path`, for
/// lines matching the regular expression `pattern`.
///
/// It runs ripgrep when the workload has `rg` on its `PATH`, and GNU or BSD
/// `grep -r` otherwise; `BusyBox` `grep` lacks the options this needs. The
/// two differ where the tools do: `pattern` is in the tool's own default
/// syntax, and ripgrep skips hidden and ignored files. Binary files are
/// skipped. With `max_matches` the workload also needs `head`.
///
/// # Errors
///
/// [`CommandError::Failed`] when the search could not run to an answer, for
/// example for a path that is not there; no match is an empty result.
/// [`CommandError::UnexpectedOutput`] when the matches outgrew what one
/// command's output keeps; set `max_matches` or narrow the search.
pub async fn grep_files(
    sandbox: &dyn Sandbox,
    pattern: &str,
    path: &str,
    options: &GrepOptions,
) -> Result<Vec<GrepMatch>, CommandError> {
    if options.max_matches == Some(0) {
        return Ok(Vec::new());
    }
    let captured = run(sandbox, grep_script(pattern, path, options)?).await?;
    read_grep(&captured, options.max_matches)
}

/// The files under `base` whose path relative to it matches the glob
/// `pattern`, in path order. `*` and `?` stop at a `/`; `**` crosses them.
///
/// # Errors
///
/// [`Error::InvalidSpec`] inside [`CommandError::Sandbox`] for a pattern
/// that is not a glob, and whatever [`walk_files`] fails with.
pub async fn glob_files(
    sandbox: &dyn Sandbox,
    pattern: &str,
    base: &str,
) -> Result<Vec<String>, CommandError> {
    let glob = GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .map_err(|error| Error::invalid_spec("pattern", error.to_string()))?
        .compile_matcher();
    let walked = walk_files(sandbox, base, &WalkOptions::default()).await?;
    Ok(walked
        .into_iter()
        .map(|file| file.path)
        .filter(|path| glob.is_match(path))
        .collect())
}

/// Every regular file under the directory `base`, in path order, over
/// `find`. A symbolic link is not followed, and a file named like an
/// excluded directory is still reported.
///
/// A base that is not there is an empty walk. So is a base that is a
/// symbolic link, or a relative base reached through one: a process in the
/// sandbox could otherwise point a walk that collects its output at another
/// tree. The directories above an absolute base are not checked.
///
/// # Errors
///
/// [`CommandError::Failed`] when the walk could not finish, for example at a
/// directory the command's user cannot read.
pub async fn walk_files(
    sandbox: &dyn Sandbox,
    base: &str,
    options: &WalkOptions,
) -> Result<Vec<WalkedFile>, CommandError> {
    let captured = run(sandbox, walk_script(base, options)?).await?;
    succeeded("walk", &captured)?;
    if !captured.is_complete() {
        return Err(unreadable("walk", &captured));
    }
    Ok(read_walk(&captured.stdout.bytes))
}

async fn run(sandbox: &dyn Sandbox, script: String) -> Result<Captured, Error> {
    let mut spec = ExecSpec::bash(script);
    spec.timeout_ms = Some(TIMEOUT_MS);
    run_captured(sandbox, spec).await
}

/// `value` as one single-quoted shell word; unlike a path it may be empty.
fn word(field: &str, value: &str) -> Result<String, Error> {
    if value.contains('\0') {
        return Err(Error::invalid_spec(field, "must be NUL-free"));
    }
    Ok(shell_quote(value))
}

fn grep_script(pattern: &str, path: &str, options: &GrepOptions) -> Result<String, Error> {
    let pattern = word("pattern", pattern)?;
    let path = quoted("path", path)?;
    let mut flags = String::new();
    if options.case_insensitive {
        flags.push_str(" -i");
    }
    if let Some(max) = options.max_matches {
        let _ = write!(flags, " -m {max}");
    }
    let (rg_include, grep_include) = match &options.include {
        Some(include) => {
            let include = word("include", include)?;
            (
                format!(" --glob {include}"),
                format!(" --include={include}"),
            )
        }
        None => (String::new(), String::new()),
    };
    // `--null` separates the path with NUL, so a `:` in a file name cannot
    // corrupt the parse (`-Z` would be zgrep mode to BSD grep). `-H` prints
    // the file name even when `path` is one file, which the parse needs.
    // `-I` keeps grep out of binary files, which ripgrep skips by itself.
    let search = format!(
        "if command -v rg >/dev/null 2>&1; then rg -H --line-number --no-heading --no-messages \
         --null{flags}{rg_include} -e {pattern} -- {path}; else grep -rnIH \
         --null{flags}{grep_include} -e {pattern} -- {path}; fi"
    );
    let Some(max) = options.max_matches else {
        return Ok(search);
    };
    // `-m` bounds the matches per file; `head` bounds the total at the
    // source, so a broad pattern stops early. That needs `pipefail`, or
    // `head` would hide a search that failed. A shell without it runs the
    // search to its end and the parse keeps the first `max` lines.
    Ok(format!(
        "search() {{ {search}; }}\nif (set -o pipefail) 2>/dev/null; then set -o pipefail; search \
         | head -n {max}; else search; fi"
    ))
}

fn read_grep(captured: &Captured, max: Option<usize>) -> Result<Vec<GrepMatch>, CommandError> {
    let exited = |code| {
        captured.outcome.termination == Termination::Exited
            && captured.outcome.exit_code == Some(code)
    };
    // Both tools exit with 1 when nothing matched.
    if exited(1) {
        return Ok(Vec::new());
    }
    if !exited(0) && !exited(SIGPIPE_EXIT) {
        return Err(CommandFailure::new("grep", captured).into());
    }
    if !captured.is_complete() {
        return Err(unreadable("grep", captured));
    }
    let text = String::from_utf8_lossy(&captured.stdout.bytes);
    let mut matches = Vec::new();
    for line in text.lines().take(max.unwrap_or(usize::MAX)) {
        let parsed = line.split_once('\0').and_then(|(path, rest)| {
            let (number, content) = rest.split_once(':')?;
            Some(GrepMatch::new(path, number.parse().ok()?, content))
        });
        // A line that does not parse means wrong results, not noise to skip.
        matches.push(parsed.ok_or_else(|| unreadable("grep", captured))?);
    }
    Ok(matches)
}

fn walk_script(base: &str, options: &WalkOptions) -> Result<String, Error> {
    let mut expression = String::new();
    if let Some(depth) = options.max_depth {
        let _ = write!(expression, " -maxdepth {depth}");
    }
    if options.exclude_dirs.is_empty() {
        expression.push_str(" -type f");
    } else {
        // `-type d` guards the prune, so a file named like an excluded
        // directory is still found.
        expression.push_str(" \\( -type d \\(");
        for (index, directory) in options.exclude_dirs.iter().enumerate() {
            if index > 0 {
                expression.push_str(" -o");
            }
            let _ = write!(expression, " -name {}", word("exclude_dirs", directory)?);
        }
        expression.push_str(" \\) -prune \\) -o -type f");
    }
    // Each file is printed as its size, a NUL, its path and a NUL. GNU find
    // prints both itself. Any other find hands the paths to `printf`, which
    // leaves the size empty.
    Ok(format!(
        "if [ -d {base} ]{guard}; then\nCDPATH= cd -- {base} || exit\nif find . -maxdepth 0 \
         -printf '' >/dev/null 2>&1; then find -H .{expression} -printf '%s\\0%P\\0'; else find \
         -H .{expression} -exec printf '\\0%s\\0' {{}} +; fi\nfi",
        base = quoted("base", base)?,
        guard = symlink_guard(base),
    ))
}

/// The ` && [ ! -L … ]` tests that refuse a symbolic link as the walk's
/// root. A relative base lives in the sandbox's working directory, so every
/// prefix of it is tested; a prefix ending in `.` or `..` passes, being a
/// directory. An absolute base is tested whole, because the directories
/// above it may be links the sandbox does not control (`/var` on macOS).
fn symlink_guard(base: &str) -> String {
    let mut guard = String::new();
    if base.starts_with('/') {
        let _ = write!(guard, " && [ ! -L {} ]", shell_quote(base));
        return guard;
    }
    let mut prefix = String::new();
    for segment in base.split('/').filter(|segment| !segment.is_empty()) {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(segment);
        let _ = write!(guard, " && [ ! -L {} ]", shell_quote(&prefix));
    }
    guard
}

fn read_walk(stdout: &[u8]) -> Vec<WalkedFile> {
    let mut files = Vec::new();
    let mut fields = stdout.split(|byte| *byte == 0);
    while let (Some(size), Some(path)) = (fields.next(), fields.next()) {
        let path = String::from_utf8_lossy(path);
        let path = path.strip_prefix("./").unwrap_or(&path);
        if !path.is_empty() {
            let size = str::from_utf8(size).ok().and_then(|size| size.parse().ok());
            files.push(WalkedFile::new(path, size));
        }
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ended(termination: Termination, exit_code: Option<i32>, stdout: &[u8]) -> Captured {
        Captured::ended(termination, exit_code, stdout, b"")
    }

    fn exited(exit_code: i32, stdout: &[u8]) -> Captured {
        ended(Termination::Exited, Some(exit_code), stdout)
    }

    #[test]
    fn grep_output_is_read_as_path_line_number_and_line() {
        // The NUL keeps a `:` in a file name, and one in the line, apart.
        let output = b"src/a.rs\x003:let x = 1;\nwith:colon.rs\x0010:a: b\n";
        assert_eq!(
            read_grep(&exited(0, output), None),
            Ok(vec![
                GrepMatch::new("src/a.rs", 3, "let x = 1;"),
                GrepMatch::new("with:colon.rs", 10, "a: b"),
            ])
        );
        // Output that `head` cut short is still an answer, and a shell
        // without `pipefail` printed more lines than were asked for.
        assert_eq!(
            read_grep(&exited(SIGPIPE_EXIT, output), Some(1)),
            Ok(vec![GrepMatch::new("src/a.rs", 3, "let x = 1;")])
        );
    }

    #[test]
    fn grep_tells_no_match_from_a_failed_and_an_unreadable_search() {
        assert_eq!(read_grep(&exited(1, b""), None), Ok(Vec::new()));
        for captured in [
            exited(2, b""),
            ended(Termination::TimedOut, None, b"a\x001:x\n"),
        ] {
            assert!(
                matches!(
                    read_grep(&captured, None),
                    Err(CommandError::Failed(failure)) if failure.context == "grep"
                ),
                "{captured:?}"
            );
        }
        // A line with no NUL, one with no line number, and output a
        // provider reported losing part of.
        let mut lossy = exited(0, b"a\x001:x\n");
        lossy.stdout.omitted_bytes = 1;
        for captured in [
            exited(0, b"Binary file blob matches\n"),
            exited(0, b"a\x00x:1\n"),
            lossy,
        ] {
            assert!(
                matches!(
                    read_grep(&captured, None),
                    Err(CommandError::UnexpectedOutput(_))
                ),
                "{captured:?}"
            );
        }
    }

    #[test]
    fn walk_output_is_read_with_and_without_sizes() {
        // GNU find: size, NUL, relative path, NUL.
        assert_eq!(
            read_walk(b"230\x00src/main.rs\x0014\x00README.md\x00"),
            vec![
                WalkedFile::new("README.md", Some(14)),
                WalkedFile::new("src/main.rs", Some(230)),
            ]
        );
        // Any other find: an empty size and a path that starts at `.`.
        assert_eq!(read_walk(b"\x00./src/main.rs\x00\x00./a b\nc\x00"), vec![
            WalkedFile::new("a b\nc", None),
            WalkedFile::new("src/main.rs", None),
        ]);
        assert!(read_walk(b"").is_empty());
    }

    #[test]
    fn every_prefix_of_a_relative_walk_root_is_refused_as_a_link() {
        assert_eq!(
            symlink_guard(".ai/it's"),
            r" && [ ! -L '.ai' ] && [ ! -L '.ai/it'\''s' ]"
        );
        assert_eq!(symlink_guard("/var/out"), " && [ ! -L '/var/out' ]");
    }

    #[test]
    fn a_value_with_a_nul_is_refused_before_any_command_runs() {
        let options = GrepOptions::default();
        for (pattern, path) in [("a\0b", "."), ("a", "x\0y"), ("a", "")] {
            assert!(
                matches!(
                    grep_script(pattern, path, &options),
                    Err(Error::InvalidSpec { .. })
                ),
                "{pattern:?} {path:?}"
            );
        }
        let exclude = WalkOptions {
            exclude_dirs: vec!["a\0b".to_owned()],
            ..WalkOptions::default()
        };
        assert!(matches!(
            walk_script(".", &exclude),
            Err(Error::InvalidSpec { .. })
        ));
    }
}
