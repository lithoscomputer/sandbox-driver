//! Filesystem and search: round trips, ranges and appends, missing
//! files, and grep over directories and single files.

use sandbox_driver::{Capability, Error, GrepOptions, Search};

use crate::Conformance;
use crate::check::{CheckOutcome, PASS, cleanup, fail};

pub(super) async fn fs_round_trips(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let fs = sandbox.fs();
        let payload = [0u8, 1, 2, 255, 254, 253];
        fs.write("conformance/dir/file.bin", &payload)
            .await
            .map_err(|error| format!("write failed: {error}"))?;
        let read = fs
            .read("conformance/dir/file.bin")
            .await
            .map_err(|error| format!("read failed: {error}"))?;
        if read != payload {
            return fail(format!("read returned different bytes: {read:?}"));
        }
        if !fs
            .exists("conformance/dir/file.bin")
            .await
            .map_err(|error| format!("exists failed: {error}"))?
        {
            return fail("exists returned false for a written file");
        }
        // A multi-hundred-KB write spans several chunks on exec-derived
        // filesystems and would overflow a single command argument if
        // sent whole (Linux caps one execve argument at 128KiB).
        let large: Vec<u8> = (0..300 * 1024)
            .map(|index: usize| u8::try_from(index % 251).expect("< 256"))
            .collect();
        fs.write("conformance/dir/large.bin", &large)
            .await
            .map_err(|error| format!("large write failed: {error}"))?;
        let read = fs
            .read("conformance/dir/large.bin")
            .await
            .map_err(|error| format!("large read failed: {error}"))?;
        if read != large {
            return fail(format!(
                "large write round trip returned {} bytes, expected {}",
                read.len(),
                large.len()
            ));
        }
        let metadata = fs
            .metadata("conformance/dir/file.bin")
            .await
            .map_err(|error| format!("metadata failed: {error}"))?;
        if metadata.size != payload.len() as u64 {
            return fail(format!(
                "metadata size {} != {}",
                metadata.size,
                payload.len()
            ));
        }
        let entries = fs
            .list_dir("conformance", 2)
            .await
            .map_err(|error| format!("list_dir failed: {error}"))?;
        if !entries.iter().any(|entry| entry.path.ends_with("file.bin")) {
            return fail("list_dir did not surface the written file");
        }
        fs.rename("conformance/dir/file.bin", "conformance/dir/renamed.bin")
            .await
            .map_err(|error| format!("rename failed: {error}"))?;
        if fs
            .exists("conformance/dir/file.bin")
            .await
            .map_err(|error| format!("exists failed: {error}"))?
        {
            return fail("source still exists after rename");
        }

        if ctx.caps().fs.permissions {
            fs.set_permissions("conformance/dir/renamed.bin", 0o600)
                .await
                .map_err(|error| format!("set_permissions failed: {error}"))?;
            let metadata = fs
                .metadata("conformance/dir/renamed.bin")
                .await
                .map_err(|error| format!("metadata failed: {error}"))?;
            if let Some(mode) = metadata.mode {
                if mode & 0o777 != 0o600 {
                    return fail(format!("mode {mode:o} after chmod 600"));
                }
            }
        }

        fs.delete("conformance", true)
            .await
            .map_err(|error| format!("recursive delete failed: {error}"))?;
        if fs
            .exists("conformance")
            .await
            .map_err(|error| format!("exists failed: {error}"))?
        {
            return fail("directory still exists after recursive delete");
        }
        // Delete is idempotent by contract: an already-deleted (or
        // never-existing) path succeeds.
        fs.delete("conformance", true)
            .await
            .map_err(|error| format!("repeated delete failed: {error}"))?;
        fs.delete("conformance-never-existed", false)
            .await
            .map_err(|error| format!("delete of a missing path failed: {error}"))?;
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

/// Grep must return matches whether the target is a directory or a
/// single file — tools like ripgrep omit the file name for a lone file
/// operand, and a provider (or the derived implementation) must not let
/// that change the result shape.
pub(super) async fn search_greps_directories_and_single_files(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        if !sandbox.capabilities().supports(Capability::Search) {
            return Ok(Some("capability search not declared".to_owned()));
        }
        sandbox
            .fs()
            .write(
                "conformance-grep/needle.txt",
                b"alpha needle beta\nplain line\n",
            )
            .await
            .map_err(|error| format!("write failed: {error}"))?;
        let Some(search) = sandbox.search() else {
            return fail("search is declared but the facet is absent");
        };
        for path in ["conformance-grep", "conformance-grep/needle.txt"] {
            let matches = search
                .grep("needle", path, &GrepOptions::default())
                .await
                .map_err(|error| format!("grep of {path} failed: {error}"))?;
            if matches.len() != 1 {
                return fail(format!(
                    "grep of {path} returned {} matches, expected 1",
                    matches.len()
                ));
            }
            if matches[0].line_number != 1 || !matches[0].line.contains("needle") {
                return fail(format!("grep of {path} returned {:?}", matches[0]));
            }
        }
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

pub(super) async fn fs_range_and_append_round_trip(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        let fs = sandbox.fs();
        fs.write("conformance-range/base.bin", b"0123456789")
            .await
            .map_err(|error| format!("write failed: {error}"))?;
        let middle = fs
            .read_range("conformance-range/base.bin", 2, Some(5))
            .await
            .map_err(|error| format!("read_range failed: {error}"))?;
        if middle != b"23456" {
            return fail(format!("read_range(2,5) returned {middle:?}"));
        }
        let tail = fs
            .read_range("conformance-range/base.bin", 7, None)
            .await
            .map_err(|error| format!("read_range to EOF failed: {error}"))?;
        if tail != b"789" {
            return fail(format!("read_range(7,None) returned {tail:?}"));
        }
        let past = fs
            .read_range("conformance-range/base.bin", 32, Some(4))
            .await
            .map_err(|error| format!("read_range past EOF failed: {error}"))?;
        if !past.is_empty() {
            return fail(format!("read past EOF returned {past:?}"));
        }

        // Append creates the file (and parents) and extends it.
        fs.write_append("conformance-range/appended.bin", b"first-")
            .await
            .map_err(|error| format!("first append failed: {error}"))?;
        fs.write_append("conformance-range/appended.bin", b"second")
            .await
            .map_err(|error| format!("second append failed: {error}"))?;
        let combined = fs
            .read("conformance-range/appended.bin")
            .await
            .map_err(|error| format!("read after append failed: {error}"))?;
        if combined != b"first-second" {
            return fail(format!(
                "append round trip returned {:?}",
                String::from_utf8_lossy(&combined)
            ));
        }
        fs.delete("conformance-range", true)
            .await
            .map_err(|error| format!("cleanup delete failed: {error}"))?;
        PASS
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}

/// Reading a file that does not exist is `NotFound`, so a caller can
/// treat absence as a value instead of parsing provider errors.
pub(super) async fn fs_missing_file_is_not_found(ctx: &Conformance) -> CheckOutcome {
    let sandbox = ctx.ready().await?;
    let outcome = async {
        match sandbox.fs().read("conformance-missing/nope.txt").await {
            Err(Error::NotFound { .. }) => {}
            Err(other) => return fail(format!("expected NotFound, got: {other}")),
            Ok(bytes) => return fail(format!("a missing file read {} bytes", bytes.len())),
        }
        match sandbox
            .fs()
            .read_range("conformance-missing/nope.txt", 0, Some(4))
            .await
        {
            Err(Error::NotFound { .. }) => PASS,
            Err(other) => fail(format!("expected NotFound from read_range, got: {other}")),
            Ok(bytes) => fail(format!("a missing file read_range {} bytes", bytes.len())),
        }
    }
    .await;
    cleanup(&sandbox).await;
    outcome
}
