use std::time::Duration;

use async_trait::async_trait;
use globset::GlobBuilder;
use tokio::sync::OnceCell;

use crate::derived::shell_quote;
use crate::error::{Error, ExecFailure, Result};
use crate::exec::{Exec, ExecResult, ExecSpec};
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

/// Runs a command where exit code 1 means "no matches" rather than failure.
async fn run_match_command(
    exec: &dyn Exec,
    label: &str,
    command: String,
    timeout: Duration,
) -> Result<Option<ExecResult>> {
    let spec = ExecSpec::new(command).timeout(timeout);
    let result = exec.run(&spec).await?;
    if result.success() {
        return Ok(Some(result));
    }
    if result.exit_code == Some(1) {
        return Ok(None);
    }
    Err(Error::Exec(ExecFailure::new(
        label,
        result.termination,
        result.exit_code,
        result.stdout,
        result.stderr,
    )))
}

#[async_trait]
impl Search for DerivedSearch<'_> {
    async fn grep(
        &self,
        pattern: &str,
        path: &str,
        options: &GrepOptions,
    ) -> Result<Vec<GrepMatch>> {
        let command = if self.ripgrep_available().await {
            let mut cmd = String::from("rg --line-number --no-heading --no-messages");
            if options.case_insensitive {
                cmd.push_str(" -i");
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
            let mut cmd = String::from("grep -rn");
            if options.case_insensitive {
                cmd.push_str(" -i");
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

        let Some(result) = run_match_command(self.exec, "grep", command, GREP_TIMEOUT).await?
        else {
            return Ok(Vec::new());
        };

        let text = result.stdout_lossy();
        let mut matches = Vec::new();
        for line in text.lines() {
            let mut parts = line.splitn(3, ':');
            let (Some(file), Some(number), Some(content)) =
                (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let Ok(line_number) = number.parse::<u64>() else {
                continue;
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

    async fn walk(&self, base: &str, options: &WalkOptions) -> Result<Vec<WalkedFile>> {
        let mut expr = String::from("find -H .");
        if let Some(depth) = options.max_depth {
            expr.push_str(" -maxdepth ");
            expr.push_str(&depth.to_string());
        }
        if options.exclude_dirs.is_empty() {
            expr.push_str(" -type f");
        } else {
            expr.push_str(" \\(");
            for (index, dir) in options.exclude_dirs.iter().enumerate() {
                if index > 0 {
                    expr.push_str(" -o");
                }
                expr.push_str(" -name ");
                expr.push_str(&shell_quote(dir));
            }
            expr.push_str(" \\) -prune -o -type f");
        }

        // GNU find first: sizes come along. `-printf` is missing from BSD
        // find, which fails and triggers the portable fallback.
        let gnu = format!("{expr} -printf '%s\\0%P\\0'");
        let spec = ExecSpec::new(gnu)
            .timeout(WALK_TIMEOUT)
            .working_dir(base.to_owned());
        let result = self.exec.run(&spec).await?;
        if result.success() {
            return Ok(parse_gnu_walk(&result.stdout));
        }

        let posix = format!("{expr} -print0");
        let spec = ExecSpec::new(posix)
            .timeout(WALK_TIMEOUT)
            .working_dir(base.to_owned());
        let result = self.exec.run(&spec).await?;
        if !result.success() {
            return Err(Error::Exec(ExecFailure::new(
                "walk",
                result.termination,
                result.exit_code,
                result.stdout,
                result.stderr,
            )));
        }
        Ok(parse_posix_walk(&result.stdout))
    }
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
            ScriptedExec::ok("src/a.rs:3:let x = 1;\nsrc/b.rs:10:fn main() {}\n"),
        ]);
        let search = DerivedSearch::new(&exec);
        let matches = search
            .grep("x", ".", &GrepOptions::default())
            .await
            .expect("grep succeeds");
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].path, "src/a.rs");
        assert_eq!(matches[0].line_number, 3);
        let commands = exec.commands();
        assert!(commands[0].contains("command -v rg"));
        assert!(commands[1].starts_with("rg --line-number --no-heading"));
        assert!(commands[1].contains("-e 'x' -- '.'"));
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
        assert!(exec.commands()[1].starts_with("grep -rn"));
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
        assert!(exec.commands()[1].ends_with("-print0"));
    }
}
