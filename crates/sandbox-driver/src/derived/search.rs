use std::time::Duration;

use async_trait::async_trait;
use globset::GlobBuilder;
use tokio::sync::OnceCell;

use crate::derived::shell_quote;
use crate::error::{Error, ExecFailure, Result};
use crate::exec::{Exec, ExecResult, ExecSpec, Termination};
use crate::search::{GrepMatch, GrepOptions, Search, WalkOptions, WalkedFile};

const GREP_TIMEOUT: Duration = Duration::from_secs(30);
const WALK_TIMEOUT: Duration = Duration::from_secs(30);

/// Exec-derived [`Search`]: ripgrep with grep/find fallbacks.
///
/// Ripgrep availability is probed once per instance and cached. `walk`
/// first tries GNU find's `-printf` (sizes included) and falls back to
/// POSIX `find -print0` (sizes unknown) for BSD userlands.
pub struct DerivedSearch<'e> {
    exec:    &'e dyn Exec,
    ripgrep: OnceCell<bool>,
}

impl<'e> DerivedSearch<'e> {
    pub fn new(exec: &'e dyn Exec) -> Self {
        Self {
            exec,
            ripgrep: OnceCell::new(),
        }
    }

    async fn ripgrep_available(&self) -> bool {
        *self
            .ripgrep
            .get_or_init(|| async {
                let spec =
                    ExecSpec::new("command -v rg >/dev/null 2>&1").timeout(Duration::from_secs(10));
                match self.exec.run(&spec).await {
                    Ok(result) => result.success(),
                    Err(_) => false,
                }
            })
            .await
    }
}

/// Exit code when SIGPIPE ends the producer because `head` already has
/// everything it needs — a successful, truncated-at-the-source run.
const SIGPIPE_EXIT: i32 = 141;

/// Runs a command where exit code 1 means "no matches" rather than
/// failure, and 141 means the output cap cut the producer short.
async fn run_match_command(
    exec: &dyn Exec,
    label: &str,
    command: String,
    timeout: Duration,
) -> Result<Option<ExecResult>> {
    let spec = ExecSpec::new(command).timeout(timeout);
    let result = exec.run(&spec).await?;
    let truncated_at_source =
        result.termination == Termination::Exited && result.exit_code == Some(SIGPIPE_EXIT);
    if result.success() || truncated_at_source {
        return Ok(Some(result));
    }
    if result.exit_code == Some(1) {
        return Ok(None);
    }
    Err(Error::Exec(
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

#[async_trait]
impl Search for DerivedSearch<'_> {
    async fn grep(
        &self,
        pattern: &str,
        path: &str,
        options: &GrepOptions,
    ) -> Result<Vec<GrepMatch>> {
        // `--null` / `-Z` separate the path with NUL, so a `:` in a file
        // name cannot corrupt the parse; `-I` keeps binary notices out
        // of grep output (ripgrep skips binary files by default); `-H`
        // forces the file name even for a single-file path, which both
        // tools otherwise omit — and the parse requires.
        let mut command = if self.ripgrep_available().await {
            let mut cmd = String::from("rg -H --line-number --no-heading --no-messages --null");
            if options.case_insensitive {
                cmd.push_str(" -i");
            }
            if let Some(max) = options.max_matches {
                cmd.push_str(" -m ");
                cmd.push_str(&max.to_string());
            }
            if let Some(include) = &options.include {
                cmd.push_str(" --glob ");
                cmd.push_str(&shell_quote(include));
            }
            cmd.push_str(" -e ");
            cmd.push_str(&shell_quote(pattern));
            cmd.push_str(" -- ");
            cmd.push_str(&shell_quote(path));
            cmd
        } else {
            // `--null` (not `-Z`, which BSD grep reads as zgrep mode)
            // works on both GNU and BSD grep.
            let mut cmd = String::from("grep -rnIH --null");
            if options.case_insensitive {
                cmd.push_str(" -i");
            }
            if let Some(max) = options.max_matches {
                cmd.push_str(" -m ");
                cmd.push_str(&max.to_string());
            }
            if let Some(include) = &options.include {
                cmd.push_str(" --include=");
                cmd.push_str(&shell_quote(include));
            }
            cmd.push_str(" -e ");
            cmd.push_str(&shell_quote(pattern));
            cmd.push_str(" -- ");
            cmd.push_str(&shell_quote(path));
            cmd
        };
        // `-m` bounds matches per file; `head` bounds the total at the
        // source so a broad pattern cannot buffer unbounded output.
        // Under pipefail, `head` closing the pipe surfaces as 141.
        if let Some(max) = options.max_matches {
            command = format!("set -o pipefail\n{command} | head -n {max}");
        }

        let Some(result) = run_match_command(self.exec, "grep", command, GREP_TIMEOUT).await?
        else {
            return Ok(Vec::new());
        };

        let text = result.stdout_lossy();
        let mut matches = Vec::new();
        for line in text.lines() {
            let parsed = line.split_once('\0').and_then(|(file, rest)| {
                let (number, content) = rest.split_once(':')?;
                Some((file, number.parse::<u64>().ok()?, content))
            });
            // An unparseable line means wrong results, not skippable
            // noise — surface it instead of silently dropping matches.
            let Some((file, line_number, content)) = parsed else {
                return Err(Error::Exec(
                    ExecFailure::new(
                        "grep output parse",
                        result.termination,
                        result.exit_code,
                        result.stdout.clone(),
                        result.stderr.clone(),
                    )
                    .with_duration(result.duration),
                ));
            };
            matches.push(GrepMatch {
                path: file.to_owned(),
                line_number,
                line: content.to_owned(),
            });
            if let Some(max) = options.max_matches {
                if matches.len() >= max {
                    break;
                }
            }
        }
        Ok(matches)
    }

    async fn glob(&self, pattern: &str, base: &str) -> Result<Vec<String>> {
        let glob = GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .map_err(|error| Error::invalid_spec("pattern", error.to_string()))?
            .compile_matcher();
        let walked = self.walk(base, &WalkOptions::default()).await?;
        let mut paths: Vec<String> = walked
            .into_iter()
            .map(|file| file.path)
            .filter(|path| glob.is_match(path))
            .collect();
        paths.sort();
        Ok(paths)
    }

    /// Refuses to walk through a symlink in the sandbox-controlled part
    /// of the traversal root. A relative base resolves inside the
    /// sandbox working directory, so every accumulated prefix is
    /// checked; for an absolute base only the path itself is checked —
    /// its ancestors (macOS `/var` → `/private/var`, say) are
    /// legitimately symlinked and outside sandbox control.
    async fn walk(&self, base: &str, options: &WalkOptions) -> Result<Vec<WalkedFile>> {
        let mut expr = String::from("find -H .");
        if let Some(depth) = options.max_depth {
            expr.push_str(" -maxdepth ");
            expr.push_str(&depth.to_string());
        }
        if options.exclude_dirs.is_empty() {
            expr.push_str(" -type f");
        } else {
            // The prune is guarded by -type d so a regular *file* named
            // like an excluded directory still shows up in results.
            expr.push_str(" \\( -type d \\(");
            for (index, dir) in options.exclude_dirs.iter().enumerate() {
                if index > 0 {
                    expr.push_str(" -o");
                }
                expr.push_str(" -name ");
                expr.push_str(&shell_quote(dir));
            }
            expr.push_str(" \\) -prune \\) -o -type f");
        }

        // A missing root is an empty walk, not an error — callers glob
        // for directories that may not exist. The guard runs in the
        // command (not via working_dir) so a missing base cannot fail
        // the exec itself. The symlink checks refuse a symlinked
        // traversal root: a sandboxed process could otherwise redirect
        // an output-collection walk at an arbitrary tree.
        let symlink_guard = symlink_guard(base);
        let guarded = |find: &str| {
            format!(
                "if [ -d {base} ]{symlink_guard}; then cd {base} && {find}; fi",
                base = shell_quote(base)
            )
        };

        // GNU find first: sizes come along. `-printf` is missing from BSD
        // find, which fails and triggers the portable fallback.
        let gnu = guarded(&format!("{expr} -printf '%s\\0%P\\0'"));
        let spec = ExecSpec::new(gnu).timeout(WALK_TIMEOUT);
        let result = self.exec.run(&spec).await?;
        if result.success() {
            return Ok(parse_gnu_walk(&result.stdout));
        }

        let posix = guarded(&format!("{expr} -print0"));
        let spec = ExecSpec::new(posix).timeout(WALK_TIMEOUT);
        let result = self.exec.run(&spec).await?;
        if !result.success() {
            return Err(Error::Exec(
                ExecFailure::new(
                    "walk",
                    result.termination,
                    result.exit_code,
                    result.stdout,
                    result.stderr,
                )
                .with_duration(result.duration),
            ));
        }
        Ok(parse_posix_walk(&result.stdout))
    }
}

/// Builds the ` && [ ! -L … ]` checks that refuse a symlinked walk
/// root. Relative bases are checked per accumulated prefix (each lives
/// inside the sandbox working directory); absolute bases are checked
/// whole. A prefix ending in `.` or `..` passes trivially — those
/// resolve to directories, never symlinks — so segments accumulate
/// verbatim.
fn symlink_guard(base: &str) -> String {
    use std::fmt::Write;

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

fn parse_gnu_walk(stdout: &[u8]) -> Vec<WalkedFile> {
    let mut files = Vec::new();
    let mut fields = stdout.split(|&b| b == 0);
    while let (Some(size), Some(path)) = (fields.next(), fields.next()) {
        if path.is_empty() {
            continue;
        }
        let size = String::from_utf8_lossy(size).parse::<u64>().ok();
        files.push(WalkedFile {
            path: String::from_utf8_lossy(path).into_owned(),
            size,
        });
    }
    files
}

fn parse_posix_walk(stdout: &[u8]) -> Vec<WalkedFile> {
    stdout
        .split(|&b| b == 0)
        .filter(|path| !path.is_empty())
        .map(|path| {
            let text = String::from_utf8_lossy(path);
            let relative = text.strip_prefix("./").unwrap_or(&text);
            WalkedFile {
                path: relative.to_owned(),
                size: None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_exec::ScriptedExec;

    #[tokio::test]
    async fn grep_prefers_ripgrep_and_parses_matches() {
        let exec = ScriptedExec::new(vec![
            ScriptedExec::ok(""), // rg probe succeeds
            ScriptedExec::ok("src/a.rs\x003:let x = 1;\nwith:colon.rs\x0010:fn main() {}\n"),
        ]);
        let search = DerivedSearch::new(&exec);
        let matches = search
            .grep("x", ".", &GrepOptions::default())
            .await
            .expect("grep succeeds");
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].path, "src/a.rs");
        assert_eq!(matches[0].line_number, 3);
        // The NUL separator keeps a `:` in a file name unambiguous.
        assert_eq!(matches[1].path, "with:colon.rs");
        assert_eq!(matches[1].line_number, 10);
        let commands = exec.commands();
        assert!(commands[0].contains("command -v rg"));
        // Without `-H` both tools omit the path (and the NUL) when the
        // target is a single file, and the parse fails.
        assert!(commands[1].starts_with("rg -H --line-number --no-heading"));
        assert!(commands[1].contains("--null"));
        assert!(commands[1].contains("-e 'x' -- '.'"));
    }

    #[tokio::test]
    async fn grep_bounds_matches_at_the_source() {
        let exec = ScriptedExec::new(vec![
            ScriptedExec::ok(""), // rg probe succeeds
            ScriptedExec::ok("src/a.rs\x003:let x = 1;\n"),
        ]);
        let search = DerivedSearch::new(&exec);
        let options = GrepOptions {
            max_matches: Some(100),
            ..GrepOptions::default()
        };
        let matches = search.grep("x", ".", &options).await.expect("grep");
        assert_eq!(matches.len(), 1);
        let command = &exec.commands()[1];
        assert!(command.starts_with("set -o pipefail\n"), "cmd: {command}");
        assert!(command.contains(" -m 100"), "cmd: {command}");
        assert!(command.ends_with("| head -n 100"), "cmd: {command}");
    }

    #[tokio::test]
    async fn grep_surfaces_unparseable_output_instead_of_dropping_it() {
        let exec = ScriptedExec::new(vec![
            ScriptedExec::ok(""), // rg probe succeeds
            ScriptedExec::ok("Binary file blob matches\n"),
        ]);
        let search = DerivedSearch::new(&exec);
        let error = search
            .grep("x", ".", &GrepOptions::default())
            .await
            .expect_err("unparseable output is an error");
        assert!(error.to_string().contains("grep output parse"));
    }

    #[tokio::test]
    async fn grep_falls_back_to_grep_when_ripgrep_is_missing() {
        let exec = ScriptedExec::new(vec![
            ScriptedExec::failed(1), // rg probe fails
            ScriptedExec::failed(1), // grep: no matches
        ]);
        let search = DerivedSearch::new(&exec);
        let matches = search
            .grep("nothing", "/src", &GrepOptions::default())
            .await
            .expect("empty");
        assert!(matches.is_empty());
        assert!(exec.commands()[1].starts_with("grep -rnIH"));
    }

    #[tokio::test]
    async fn walk_refuses_symlinked_roots_per_component() {
        let exec = ScriptedExec::new(vec![ScriptedExec::ok("")]);
        let search = DerivedSearch::new(&exec);
        let files = search
            .walk(".ai/output", &WalkOptions::default())
            .await
            .expect("walk");
        assert!(files.is_empty());
        // Every sandbox-controlled prefix is refused as a symlink, so a
        // sandboxed process cannot redirect the walk at another tree.
        let command = &exec.commands()[0];
        assert!(
            command.starts_with(
                "if [ -d '.ai/output' ] && [ ! -L '.ai' ] && [ ! -L '.ai/output' ]; then "
            ),
            "command: {command}"
        );
    }

    #[tokio::test]
    async fn walk_parses_gnu_output_and_glob_filters() {
        let exec = ScriptedExec::new(vec![
            ScriptedExec::ok_bytes(b"14\x00src/main.rs\x00230\x00README.md\x00".to_vec()),
            ScriptedExec::ok_bytes(b"14\x00src/main.rs\x00230\x00README.md\x00".to_vec()),
        ]);
        let search = DerivedSearch::new(&exec);
        let files = search
            .walk("/repo", &WalkOptions::default())
            .await
            .expect("walk");
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "src/main.rs");
        assert_eq!(files[0].size, Some(14));

        let paths = search.glob("src/*.rs", "/repo").await.expect("glob");
        assert_eq!(paths, vec!["src/main.rs".to_owned()]);
    }

    #[tokio::test]
    async fn walk_falls_back_to_posix_find() {
        let exec = ScriptedExec::new(vec![
            ScriptedExec::failed(1), // GNU -printf rejected
            ScriptedExec::ok_bytes(b"./src/main.rs\x00./README.md\x00".to_vec()),
        ]);
        let search = DerivedSearch::new(&exec);
        let files = search
            .walk("/repo", &WalkOptions::default())
            .await
            .expect("walk");
        assert_eq!(files[0].path, "src/main.rs");
        assert_eq!(files[0].size, None);
        assert!(exec.commands()[1].contains("-print0"));
    }

    #[tokio::test]
    async fn walk_guards_the_root_and_prunes_only_directories() {
        let exec = ScriptedExec::new(vec![ScriptedExec::ok("")]);
        let search = DerivedSearch::new(&exec);
        let options = WalkOptions {
            exclude_dirs: vec!["node_modules".to_owned()],
            ..WalkOptions::default()
        };
        let files = search.walk("/missing", &options).await.expect("walk");
        assert!(files.is_empty());

        let command = &exec.commands()[0];
        assert!(
            command
                .starts_with("if [ -d '/missing' ] && [ ! -L '/missing' ]; then cd '/missing' && "),
            "command: {command}"
        );
        assert!(
            command.contains("\\( -type d \\( -name 'node_modules' \\) -prune \\) -o -type f"),
            "command: {command}"
        );
    }
}
