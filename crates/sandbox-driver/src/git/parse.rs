//! Parsers for git's plumbing output. `None` means the output was not in
//! the form git prints, so nothing read from it can be trusted.

use super::model::{GitChange, GitCommit, GitDiffEntry, GitIdentity, GitNumstat};

/// Git's separator format for one commit of a log: unit separator between
/// fields, record separator between commits.
pub(super) const LOG_FORMAT: &str =
    "%H%x1f%T%x1f%P%x1f%an%x1f%ae%x1f%aI%x1f%cn%x1f%ce%x1f%cI%x1f%B%x1e";

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A blob or mode git prints as all zeros is absent on that side.
fn present(value: &str) -> Option<String> {
    (!value.is_empty() && !value.bytes().all(|byte| byte == b'0')).then(|| value.to_owned())
}

/// Parses `git diff --raw -z` output: per entry a header
/// `:<old mode> <new mode> <old blob> <new blob> <status>` and one path, or
/// two for a rename or copy, each NUL-terminated.
pub(super) fn parse_raw_diff(output: &[u8]) -> Option<Vec<GitDiffEntry>> {
    let mut entries = Vec::new();
    let mut fields = output.split(|byte| *byte == 0);
    while let Some(header) = fields.next() {
        if header.is_empty() {
            continue;
        }
        let header = lossy(header);
        let parts: Vec<&str> = header.strip_prefix(':')?.split(' ').collect();
        let &[old_mode, new_mode, old_blob, new_blob, status] = parts.as_slice() else {
            return None;
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
        // No path is empty, so an empty field is where the output stopped.
        let mut path = || fields.next().filter(|path| !path.is_empty()).map(lossy);
        let first = path()?;
        let (old_path, path) = if matches!(change, GitChange::Renamed | GitChange::Copied) {
            (Some(first), path()?)
        } else {
            (None, first)
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
    Some(entries)
}

/// Parses `git diff --numstat -z` output: `<added>\t<removed>\t<path>` per
/// entry, `-` for both counts on a binary path, and for a rename an empty
/// path followed by the old and new paths as their own fields.
pub(super) fn parse_numstat(output: &[u8]) -> Option<Vec<GitNumstat>> {
    let count = |text: &str| match text {
        "-" => Some(None),
        _ => text.parse().ok().map(Some),
    };
    let mut entries = Vec::new();
    let mut fields = output.split(|byte| *byte == 0);
    while let Some(entry) = fields.next() {
        if entry.is_empty() {
            continue;
        }
        let entry = lossy(entry);
        let mut parts = entry.splitn(3, '\t');
        let (added, removed, path) = (parts.next()?, parts.next()?, parts.next()?);
        let (old_path, path) = if path.is_empty() {
            (Some(lossy(fields.next()?)), lossy(fields.next()?))
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
    Some(entries)
}

/// Parses a log in [`LOG_FORMAT`].
pub(super) fn parse_log(output: &str) -> Option<Vec<GitCommit>> {
    let mut commits = Vec::new();
    for record in output.split('\x1e') {
        let record = record.trim_start_matches('\n');
        if record.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = record.splitn(10, '\x1f').collect();
        let &[
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
        ] = fields.as_slice()
        else {
            return None;
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
    Some(commits)
}

/// A header line that is not in the form `cat-file` prints.
struct Malformed;

/// The header of one `cat-file --batch` or `--batch-check` entry: the
/// size when the object exists, `None` when git says `missing`.
fn batch_header(line: &str) -> Result<Option<u64>, Malformed> {
    let mut parts = line.split(' ');
    let _name = parts.next();
    match (parts.next(), parts.next()) {
        (Some("missing"), None) => Ok(None),
        (Some(_kind), Some(size)) => size.parse().map(Some).map_err(|_| Malformed),
        _ => Err(Malformed),
    }
}

/// Parses `git cat-file --batch-check` output: one header line per
/// requested object, in request order.
pub(super) fn parse_batch_check(output: &str, count: usize) -> Option<Vec<Option<u64>>> {
    let sizes: Vec<Option<u64>> = output
        .lines()
        .map(batch_header)
        .collect::<Result<_, _>>()
        .ok()?;
    (sizes.len() == count).then_some(sizes)
}

/// Parses `git cat-file --batch` output: a header line, the object's
/// bytes, and a newline, per requested object, in request order. An object
/// larger than `max_bytes` is read past and reported as `None`.
pub(super) fn parse_batch(
    output: &[u8],
    count: usize,
    max_bytes: u64,
) -> Option<Vec<Option<Vec<u8>>>> {
    let mut blobs = Vec::with_capacity(count);
    let mut position = 0;
    while position < output.len() && blobs.len() < count {
        let newline = output[position..].iter().position(|byte| *byte == b'\n')?;
        let header = lossy(&output[position..position + newline]);
        position += newline + 1;
        let Some(size) = batch_header(&header).ok()? else {
            blobs.push(None);
            continue;
        };
        // A stream that ends inside an object was cut short.
        let end = position.checked_add(usize::try_from(size).ok()?)?;
        let bytes = output.get(position..end)?;
        blobs.push((size <= max_bytes).then(|| bytes.to_vec()));
        position = end;
        if output.get(position) == Some(&b'\n') {
            position += 1;
        }
    }
    (blobs.len() == count).then_some(blobs)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // No header, a short header, and a rename that lost its new path.
        for malformed in [
            &b"garbage\0"[..],
            b":100644 100644 M\0changed.txt\0",
            b":100644 100644 4444 4444 R100\0old\0",
        ] {
            assert_eq!(parse_raw_diff(malformed), None);
        }
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
        for malformed in [&b"3\tsrc/lib.rs\0"[..], b"three\t1\tsrc/lib.rs\0"] {
            assert_eq!(parse_numstat(malformed), None);
        }
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
        assert_eq!(parse_log("aaaa\x1ftttt\x1e"), None);
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
        assert_eq!(
            parse_batch(output, 4, 100),
            None,
            "fewer answers than requests"
        );
        assert_eq!(
            parse_batch(
                b"1111111111111111111111111111111111111111 blob 9\nshort\n",
                1,
                100
            ),
            None,
            "a stream cut short inside an object"
        );
    }

    #[test]
    fn batch_check_output_yields_one_size_per_request() {
        let output = "1111111111111111111111111111111111111111 blob 6\n\
                      2222222222222222222222222222222222222222 missing\n";
        assert_eq!(parse_batch_check(output, 2), Some(vec![Some(6), None]));
        assert_eq!(parse_batch_check(output, 3), None);
        assert_eq!(parse_batch_check("1111 blob six\n", 1), None);
    }
}
