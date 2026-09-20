//! Parsers for git's porcelain and plumbing output.

use super::command::{lossy, malformed};
use crate::error::Result;
use crate::git::{GitChange, GitCommit, GitDiffEntry, GitIdentity, GitNumstat, GitStatus};

/// Git's separator format for one commit of a log: unit separator between
/// fields, record separator between commits.
pub(super) const LOG_FORMAT: &str =
    "%H%x1f%T%x1f%P%x1f%an%x1f%ae%x1f%aI%x1f%cn%x1f%ce%x1f%cI%x1f%B%x1e";

/// A blob or mode git prints as all zeros is absent on that side.
fn present(value: &str) -> Option<String> {
    (!value.is_empty() && !value.bytes().all(|byte| byte == b'0')).then(|| value.to_owned())
}

/// Parses `git diff --raw -z` output: per entry a header
/// `:<old mode> <new mode> <old blob> <new blob> <status>` and one path, or
/// two for a rename or copy, each NUL-terminated.
pub(super) fn parse_raw_diff(output: &[u8]) -> Result<Vec<GitDiffEntry>> {
    let mut entries = Vec::new();
    let mut fields = output.split(|byte| *byte == 0).peekable();
    while let Some(header) = fields.next() {
        if header.is_empty() {
            continue;
        }
        let header = lossy(header);
        let Some(rest) = header.strip_prefix(':') else {
            return Err(malformed(
                "git diff --raw",
                format!("unexpected entry {header:?}"),
            ));
        };
        let parts: Vec<&str> = rest.split(' ').collect();
        let [old_mode, new_mode, old_blob, new_blob, status] = parts[..] else {
            return Err(malformed(
                "git diff --raw",
                format!("short header {header:?}"),
            ));
        };
        let mut letters = status.chars();
        let (change, similarity) = match letters.next() {
            Some('A') => (GitChange::Added, None),
            Some('C') => (GitChange::Copied, letters.as_str().parse().ok()),
            Some('D') => (GitChange::Deleted, None),
            Some('M') => (GitChange::Modified, None),
            Some('R') => (GitChange::Renamed, letters.as_str().parse().ok()),
            Some('T') => (GitChange::TypeChanged, None),
            Some('U') => (GitChange::Unmerged, None),
            _ => (GitChange::Unknown, None),
        };
        let first = fields
            .next()
            .ok_or_else(|| malformed("git diff --raw", "entry without a path"))?;
        let (old_path, path) = if matches!(change, GitChange::Renamed | GitChange::Copied) {
            let second = fields
                .next()
                .ok_or_else(|| malformed("git diff --raw", "rename without a new path"))?;
            (Some(lossy(first)), lossy(second))
        } else {
            (None, lossy(first))
        };
        entries.push(GitDiffEntry {
            change,
            path,
            old_path,
            old_mode: present(old_mode),
            new_mode: present(new_mode),
            old_blob: present(old_blob),
            new_blob: present(new_blob),
            similarity,
        });
    }
    Ok(entries)
}

/// Parses `git diff --numstat -z` output: `<added>\t<removed>\t<path>` per
/// entry, `-` for both counts on a binary path, and for a rename an empty
/// path followed by the old and new paths as their own fields.
pub(super) fn parse_numstat(output: &[u8]) -> Result<Vec<GitNumstat>> {
    let mut entries = Vec::new();
    let mut fields = output.split(|byte| *byte == 0);
    while let Some(entry) = fields.next() {
        if entry.is_empty() {
            continue;
        }
        let entry = lossy(entry);
        let mut parts = entry.splitn(3, '\t');
        let (Some(added), Some(removed), Some(path)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(malformed(
                "git diff --numstat",
                format!("short entry {entry:?}"),
            ));
        };
        let count = |text: &str| -> Result<Option<u64>> {
            if text == "-" {
                return Ok(None);
            }
            text.parse()
                .map(Some)
                .map_err(|_| malformed("git diff --numstat", format!("bad count {text:?}")))
        };
        let (old_path, path) = if path.is_empty() {
            let old = fields
                .next()
                .ok_or_else(|| malformed("git diff --numstat", "rename without an old path"))?;
            let new = fields
                .next()
                .ok_or_else(|| malformed("git diff --numstat", "rename without a new path"))?;
            (Some(lossy(old)), lossy(new))
        } else {
            (None, path.to_owned())
        };
        entries.push(GitNumstat {
            path,
            old_path,
            additions: count(added)?,
            deletions: count(removed)?,
        });
    }
    Ok(entries)
}

/// Parses a log in [`LOG_FORMAT`].
pub(super) fn parse_log(output: &str) -> Result<Vec<GitCommit>> {
    let mut commits = Vec::new();
    for record in output.split('\x1e') {
        let record = record.trim_start_matches('\n');
        if record.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = record.splitn(10, '\x1f').collect();
        let [
            sha,
            tree,
            parents,
            author_name,
            author_email,
            author_date,
            committer_name,
            committer_email,
            committer_date,
            message,
        ] = fields[..]
        else {
            return Err(malformed("git log", format!("short record {record:?}")));
        };
        commits.push(GitCommit {
            sha:       sha.to_owned(),
            tree:      tree.to_owned(),
            parents:   parents.split_whitespace().map(str::to_owned).collect(),
            author:    GitIdentity {
                name:  author_name.to_owned(),
                email: author_email.to_owned(),
                date:  author_date.to_owned(),
            },
            committer: GitIdentity {
                name:  committer_name.to_owned(),
                email: committer_email.to_owned(),
                date:  committer_date.to_owned(),
            },
            message:   message.trim_end_matches('\n').to_owned(),
        });
    }
    Ok(commits)
}

/// The header of one `cat-file --batch` or `--batch-check` entry: the
/// size when the object exists, `None` when git says `missing`.
pub(super) fn batch_header(line: &str) -> Result<Option<usize>> {
    let mut parts = line.split(' ');
    let _name = parts.next();
    match (parts.next(), parts.next()) {
        (Some("missing"), None) => Ok(None),
        (Some(_kind), Some(size)) => size
            .parse()
            .map(Some)
            .map_err(|_| malformed("git cat-file", format!("bad size in {line:?}"))),
        _ => Err(malformed("git cat-file", format!("bad header {line:?}"))),
    }
}

/// Parses `git cat-file --batch` output: a header line, the object's
/// bytes, and a newline, per requested object, in request order.
pub(super) fn parse_batch(
    output: &[u8],
    count: usize,
    max_bytes: u64,
) -> Result<Vec<Option<Vec<u8>>>> {
    let mut blobs = Vec::with_capacity(count);
    let mut position = 0;
    while position < output.len() && blobs.len() < count {
        let Some(newline) = output[position..].iter().position(|byte| *byte == b'\n') else {
            break;
        };
        let header = lossy(&output[position..position + newline]);
        position += newline + 1;
        let Some(size) = batch_header(&header)? else {
            blobs.push(None);
            continue;
        };
        let end = position + size;
        if end > output.len() {
            return Err(malformed(
                "git cat-file",
                format!(
                    "stream ends {} bytes into a {size} byte object",
                    output.len() - position
                ),
            ));
        }
        blobs.push(
            (u64::try_from(size).unwrap_or(u64::MAX) <= max_bytes)
                .then(|| output[position..end].to_vec()),
        );
        position = end;
        if output.get(position) == Some(&b'\n') {
            position += 1;
        }
    }
    if blobs.len() != count {
        return Err(malformed(
            "git cat-file",
            format!("{} objects answered for {count} requested", blobs.len()),
        ));
    }
    Ok(blobs)
}

/// Parses `git status --porcelain=v2 -z --branch` output: entries are
/// NUL-separated with verbatim paths, and a rename/copy entry is
/// followed by one extra NUL-separated field (the original path).
pub(super) fn parse_status_v2(output: &str) -> GitStatus {
    let mut status = GitStatus {
        current_branch: None,
        head:           None,
        detached:       false,
        ahead:          0,
        behind:         0,
        dirty_paths:    Vec::new(),
    };
    let mut entries = output.split('\0');
    while let Some(entry) = entries.next() {
        if let Some(oid) = entry.strip_prefix("# branch.oid ") {
            status.head = (oid != "(initial)").then(|| oid.to_owned());
        } else if let Some(head) = entry.strip_prefix("# branch.head ") {
            if head == "(detached)" {
                status.detached = true;
            } else {
                status.current_branch = Some(head.to_owned());
            }
        } else if let Some(ab) = entry.strip_prefix("# branch.ab ") {
            for part in ab.split_whitespace() {
                if let Some(ahead) = part.strip_prefix('+') {
                    status.ahead = ahead.parse().unwrap_or(0);
                } else if let Some(behind) = part.strip_prefix('-') {
                    status.behind = behind.parse().unwrap_or(0);
                }
            }
        } else if let Some(entry) = entry.strip_prefix("1 ") {
            // 8 fixed fields after the marker, then the path.
            if let Some(path) = entry.splitn(8, ' ').nth(7) {
                status.dirty_paths.push(path.to_owned());
            }
        } else if let Some(entry) = entry.strip_prefix("2 ") {
            // Rename/copy: 9 fields, the new path, then the original
            // path as its own NUL-separated field.
            if let Some(path) = entry.splitn(9, ' ').nth(8) {
                status.dirty_paths.push(path.to_owned());
            }
            let _original_path = entries.next();
        } else if let Some(entry) = entry.strip_prefix("u ") {
            // Unmerged (conflict): 10 fields, then the path. A repo
            // mid-merge must not pass a "workspace clean" check.
            if let Some(path) = entry.splitn(10, ' ').nth(9) {
                status.dirty_paths.push(path.to_owned());
            }
        } else if let Some(path) = entry.strip_prefix("? ") {
            status.dirty_paths.push(path.to_owned());
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_porcelain_v2_status() {
        // `-z` output, shapes verified against live git: a rename entry
        // is followed by the original path as its own NUL field, and
        // special-character paths arrive verbatim, not C-quoted.
        let status = parse_status_v2(concat!(
            "# branch.oid 1234\0",
            "# branch.head main\0",
            "# branch.upstream origin/main\0",
            "# branch.ab +2 -1\0",
            "1 .M N... 100644 100644 100644 aaaa bbbb src/lib.rs\0",
            "2 RM N... 100644 100644 100644 aaaa bbbb R100 new.txt\0old.txt\0",
            "u UU N... 100644 100644 100644 100644 aaaa bbbb cccc conflicted.rs\0",
            "? na\u{ef}ve notes.txt\0",
        ));
        assert_eq!(status.current_branch.as_deref(), Some("main"));
        assert_eq!(status.head.as_deref(), Some("1234"));
        assert!(!status.detached);
        assert_eq!(status.ahead, 2);
        assert_eq!(status.behind, 1);
        assert_eq!(status.dirty_paths, vec![
            "src/lib.rs".to_owned(),
            "new.txt".to_owned(),
            "conflicted.rs".to_owned(),
            "na\u{ef}ve notes.txt".to_owned(),
        ]);
    }

    #[test]
    fn an_unborn_branch_has_no_head() {
        let status = parse_status_v2("# branch.oid (initial)\0# branch.head main\0");
        assert_eq!(status.head, None);
        assert_eq!(status.current_branch.as_deref(), Some("main"));
    }

    #[test]
    fn raw_diff_entries_parse_every_status_and_zero_sides() {
        let output = concat!(
            ":000000 100644 0000000000000000000000000000000000000000 ",
            "1111111111111111111111111111111111111111 A\0added.txt\0",
            ":100644 100644 2222222222222222222222222222222222222222 ",
            "3333333333333333333333333333333333333333 M\0changed.txt\0",
            ":100644 100644 4444444444444444444444444444444444444444 ",
            "4444444444444444444444444444444444444444 R087\0old/name.rs\0new/name.rs\0",
            ":100644 000000 5555555555555555555555555555555555555555 ",
            "0000000000000000000000000000000000000000 D\0gone.txt\0",
        );
        let entries = parse_raw_diff(output.as_bytes()).expect("parses");
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].change, GitChange::Added);
        assert_eq!(entries[0].path, "added.txt");
        assert_eq!(entries[0].old_mode, None);
        assert_eq!(entries[0].new_mode.as_deref(), Some("100644"));
        assert_eq!(entries[0].old_blob, None);
        assert_eq!(entries[1].change, GitChange::Modified);
        assert_eq!(entries[2].change, GitChange::Renamed);
        assert_eq!(entries[2].old_path.as_deref(), Some("old/name.rs"));
        assert_eq!(entries[2].path, "new/name.rs");
        assert_eq!(entries[2].similarity, Some(87));
        assert_eq!(entries[3].change, GitChange::Deleted);
        assert_eq!(entries[3].new_blob, None);
        assert!(parse_raw_diff(b"garbage\0").is_err());
    }

    #[test]
    fn numstat_parses_counts_binaries_and_renames() {
        let output = "3\t1\tsrc/lib.rs\0-\t-\timage.png\x002\t0\t\0old.rs\0new.rs\0";
        let entries = parse_numstat(output.as_bytes()).expect("parses");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].additions, Some(3));
        assert_eq!(entries[0].deletions, Some(1));
        assert_eq!(entries[1].additions, None);
        assert_eq!(entries[1].deletions, None);
        assert_eq!(entries[2].old_path.as_deref(), Some("old.rs"));
        assert_eq!(entries[2].path, "new.rs");
    }

    #[test]
    fn logs_parse_separator_records_with_multiline_messages() {
        let output = concat!(
            "aaaa\x1ftttt\x1fpppp qqqq\x1fAda\x1fada@example.com\x1f2026-01-01T00:00:00+00:00",
            "\x1fBob\x1fbob@example.com\x1f2026-01-02T00:00:00+00:00\x1fsubject\n\nbody line\n\x1e\n",
            "bbbb\x1fuuuu\x1f\x1fAda\x1fada@example.com\x1f2026-01-03T00:00:00+00:00",
            "\x1fAda\x1fada@example.com\x1f2026-01-03T00:00:00+00:00\x1froot\n\x1e\n",
        );
        let commits = parse_log(output).expect("parses");
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].sha, "aaaa");
        assert_eq!(commits[0].parents, ["pppp", "qqqq"]);
        assert_eq!(commits[0].author.name, "Ada");
        assert_eq!(commits[0].committer.email, "bob@example.com");
        assert_eq!(commits[0].message, "subject\n\nbody line");
        assert!(commits[1].parents.is_empty());
        assert_eq!(commits[1].message, "root");
    }

    #[test]
    fn batch_output_yields_bytes_missing_and_capped_objects() {
        let output = b"1111111111111111111111111111111111111111 blob 6\nhello\n\n\
                       2222222222222222222222222222222222222222 missing\n\
                       3333333333333333333333333333333333333333 blob 3\nbig\n";
        let blobs = parse_batch(output, 3, 4).expect("parses");
        assert_eq!(blobs[0], None, "over the cap");
        assert_eq!(blobs[1], None, "missing");
        assert_eq!(blobs[2].as_deref(), Some(&b"big"[..]));
        let blobs = parse_batch(output, 3, 100).expect("parses");
        assert_eq!(blobs[0].as_deref(), Some(&b"hello\n"[..]));
        assert!(
            parse_batch(output, 4, 100).is_err(),
            "fewer answers than requests"
        );
        assert!(
            parse_batch(
                b"1111111111111111111111111111111111111111 blob 9\nshort\n",
                1,
                100
            )
            .is_err(),
            "a truncated stream is refused"
        );
    }
}
