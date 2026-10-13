//! Non-signalling process observation, ported from Petri's Host fence.
//!
//! macOS has no safe standard-library interface for its process table. The
//! isolated libproc calls below check buffer sizes and never send a signal.
#![allow(
    unsafe_code,
    reason = "libproc exposes process observation through a C API"
)]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "macos")]
use std::{mem, ptr};

#[cfg(target_os = "macos")]
use nix::libc;

/// Whether the group still has a live member, probed cheaply through the
/// sentinel first. `wait` runs this every poll tick for a step's whole natural
/// duration, and while the executor holds the sentinel unreaped its pid — the
/// pgid — cannot be recycled, so the probe is the sentinel itself: alive means
/// the group is alive without enumerating it. Only a dead or zombie sentinel —
/// our KILL, or a hostile workload's — makes the full listing necessary.
pub(super) fn group_is_live(pgid: i32) -> bool {
    sentinel_is_live(pgid) || has_live_group_members(pgid)
}

/// Observe a whole drain batch. Linux must enumerate `/proc` only once:
/// scanning it separately for every dead sentinel can exhaust the drain
/// deadline even when all of the groups have already exited.
#[cfg(target_os = "linux")]
pub(super) fn live_groups(pgids: &[i32]) -> HashSet<i32> {
    live_groups_in(Path::new("/proc"), pgids)
}

#[cfg(target_os = "linux")]
fn live_groups_in(procfs: &Path, pgids: &[i32]) -> HashSet<i32> {
    let requested: HashSet<_> = pgids.iter().copied().collect();
    let mut live = HashSet::new();
    if requested.is_empty() {
        return live;
    }
    let Ok(entries) = fs::read_dir(procfs) else {
        return live;
    };
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        if let Some(group) = live_group_from_stat(&stat).filter(|id| requested.contains(id)) {
            live.insert(group);
        }
    }
    live
}

/// libproc already lists members by group rather than scanning all processes.
#[cfg(target_os = "macos")]
pub(super) fn live_groups(pgids: &[i32]) -> HashSet<i32> {
    pgids
        .iter()
        .copied()
        .filter(|id| group_is_live(*id))
        .collect()
}

/// One `/proc/<pgid>/stat` read: the sentinel, live and still leading the
/// group.
#[cfg(target_os = "linux")]
fn sentinel_is_live(pgid: i32) -> bool {
    fs::read_to_string(format!("/proc/{pgid}/stat"))
        .is_ok_and(|stat| stat_is_live_in_group(&stat, pgid))
}

/// One libproc query: the sentinel, not yet a zombie.
#[cfg(target_os = "macos")]
fn sentinel_is_live(pgid: i32) -> bool {
    is_live(pgid)
}

/// Whether any live processes remain in the group. Non-signalling, and zombies
/// do not count: they cannot run, and the unreaped sentinel is deliberately
/// one.
#[cfg(target_os = "linux")]
fn has_live_group_members(pgid: i32) -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.bytes().all(|b| b.is_ascii_digit()))
        })
        .any(|entry| entry_is_live_member(&entry, pgid))
}

/// One `/proc/<pid>/stat` read for a numbered `/proc` entry: whether that
/// process is a live member of the group.
#[cfg(target_os = "linux")]
fn entry_is_live_member(entry: &fs::DirEntry, pgid: i32) -> bool {
    fs::read_to_string(entry.path().join("stat"))
        .is_ok_and(|stat| stat_is_live_in_group(&stat, pgid))
}

/// Parse one `/proc/<pid>/stat` line: `pid (comm) state ppid pgrp ...`. The
/// comm can hold spaces and parentheses, so the split is after the *last* `)`.
#[cfg(target_os = "linux")]
fn stat_is_live_in_group(stat: &str, pgid: i32) -> bool {
    live_group_from_stat(stat) == Some(pgid)
}

#[cfg(target_os = "linux")]
fn live_group_from_stat(stat: &str) -> Option<i32> {
    let (_, rest) = stat.rsplit_once(')')?;
    let mut fields = rest.split_whitespace();
    let state = fields.next()?;
    let group = fields.nth(1)?.parse::<i32>().ok()?;
    (state != "Z").then_some(group)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::env;

    use super::{HashSet, fs, live_groups_in};
    use crate::registry::fresh_id;

    #[test]
    fn a_batch_observes_descendants_and_ignores_zombies_and_unrelated_groups() {
        let procfs = env::temp_dir().join(fresh_id());
        fs::create_dir_all(&procfs).expect("fixture process table");
        for (pid, stat) in [
            ("100", "100 (sentinel) Z 1 100 100"),
            // The group remains live after its sentinel dies. The command
            // name can contain spaces and parentheses, including a ')'.
            ("101", "101 (child (with) spaces)) S 100 100 100"),
            ("200", "200 (sentinel) S 1 200 200"),
            ("201", "201 (second child) R 200 200 200"),
            ("300", "300 (zombie only) Z 1 300 300"),
            ("400", "400 (unrelated) S 1 400 400"),
            ("500", "500 (truncated) S 1"),
            ("600", "600 (bad group) S 1 invalid"),
            ("self", "100 (nonnumeric entry) S 1 700 700"),
        ] {
            let directory = procfs.join(pid);
            fs::create_dir(&directory).expect("fixture process");
            fs::write(directory.join("stat"), stat).expect("fixture stat");
        }
        // A process can disappear between enumeration and reading its stat.
        fs::create_dir(procfs.join("800")).expect("vanished process");
        let live = live_groups_in(&procfs, &[100, 100, 200, 300, 500, 600, 700, 800, 900]);
        let empty = live_groups_in(&procfs, &[]);
        fs::remove_dir_all(procfs).expect("fixture cleanup");
        assert_eq!(live, HashSet::from([100, 200]));
        assert!(empty.is_empty());
    }
}

/// libproc's process listing by group, each member checked for zombie state.
#[cfg(target_os = "macos")]
fn has_live_group_members(pgid: i32) -> bool {
    const PROC_PGRP_ONLY: u32 = 2;
    let group = u32::try_from(pgid).unwrap_or(0);

    // SAFETY: this is `proc_listpids`' documented size-query form. A null
    // buffer paired with a zero byte count asks only how many bytes a full
    // listing would need, so libproc writes nothing and there is no storage
    // whose validity, size, or lifetime could be violated. The reply is a byte
    // count, or a non-positive value the code below treats as an empty group.
    let sized = unsafe { libc::proc_listpids(PROC_PGRP_ONLY, group, ptr::null_mut(), 0) };
    if sized <= 0 {
        return false;
    }
    // Headroom above the reported size: the group can gain members between the
    // two calls, and a full buffer is indistinguishable from a truncated one.
    let capacity = usize::try_from(sized).unwrap_or(0) / size_of::<i32>() + 8;
    let mut pids = vec![0i32; capacity];
    let Ok(byte_capacity) = i32::try_from(capacity * size_of::<i32>()) else {
        return false;
    };

    // SAFETY: `pids.as_mut_ptr()` points to `capacity` initialized `i32`s in a
    // live allocation this thread borrows exclusively for the whole call, so
    // libproc's writes cannot race or dangle. `byte_capacity` is exactly that
    // allocation's size in bytes, so libproc cannot write past its end. Only
    // the returned byte count is used below, so no element libproc left
    // untouched is read as a pid.
    let filled = unsafe {
        libc::proc_listpids(
            PROC_PGRP_ONLY,
            group,
            pids.as_mut_ptr().cast(),
            byte_capacity,
        )
    };
    if filled <= 0 {
        return false;
    }

    pids.truncate(usize::try_from(filled).unwrap_or(0) / size_of::<i32>());
    pids.into_iter().any(|pid| pid > 0 && is_live(pid))
}

/// One libproc query: is this pid a process that still runs? A caller may pass
/// any `i32`, including a pid that has already gone, so this is a safe
/// function; the unsafe operations it needs are proved individually below.
#[cfg(target_os = "macos")]
fn is_live(pid: i32) -> bool {
    // sys/proc.h: SZOMB. libproc reports it through proc_bsdinfo.pbi_status.
    const SZOMB: u32 = 5;

    // SAFETY: `proc_bsdinfo` is a plain C output struct of integers and
    // fixed-size byte arrays, with no reference, `NonZero`, or enum field, so
    // every bit pattern — all zeros included — is a valid value of the type.
    // Zeroing therefore produces initialized storage the FFI call may
    // overwrite, and the zeros themselves are never trusted: nothing is read
    // out unless the call reports a complete structure.
    let mut info: libc::proc_bsdinfo = unsafe { mem::zeroed() };
    let Ok(size) = i32::try_from(size_of::<libc::proc_bsdinfo>()) else {
        return false;
    };

    // SAFETY: `&raw mut info` points at the initialized, writable
    // `proc_bsdinfo` above. It is a local this thread borrows exclusively, and
    // it outlives the call, so libproc's write can neither race nor dangle.
    // `size` is exactly that value's size in bytes, so libproc cannot write
    // past its end. `info` is read only where `got == size` proves libproc
    // filled the whole structure.
    let got =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };
    // A process that vanished between the listing and this query is not live.
    got == size && info.pbi_status != SZOMB
}
