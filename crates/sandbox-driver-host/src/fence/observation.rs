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
#[cfg(target_os = "macos")]
use rustix::io::Errno;
#[cfg(target_os = "macos")]
use rustix::process::{Pid, getpgid, getsid};

/// Live processes of the requested groups, from one observation.
///
/// A group's members are the processes in its process group and, when its
/// sentinel leads a session (a command run on a terminal), every process of
/// that session: an interactive shell moves itself and each job into a
/// process group of its own inside the session. The id is the sentinel's
/// pid, which is both the group id and the session id, and the unreaped
/// sentinel pins it, so membership by either is exact.
#[derive(Default)]
pub(super) struct Members {
    /// The requested ids with a live member.
    pub(super) live:       HashSet<i32>,
    /// `(id, pid)` for each live member that belongs to a requested id
    /// through its session only, in a process group of its own.
    pub(super) by_session: Vec<(i32, i32)>,
}

/// Whether the group still has a live member, probed cheaply through the
/// sentinel first. `wait` runs this every poll tick for a step's whole natural
/// duration, and while the executor holds the sentinel unreaped its pid — the
/// pgid — cannot be recycled, so the probe is the sentinel itself: alive means
/// the group is alive without enumerating it. Only a dead or zombie sentinel —
/// our KILL, or a hostile workload's — makes the full listing necessary.
pub(super) fn group_is_live(pgid: i32) -> bool {
    sentinel_is_live(pgid) || !members(&[pgid]).live.is_empty()
}

/// The requested ids with a live member.
pub(super) fn live_groups(pgids: &[i32]) -> HashSet<i32> {
    members(pgids).live
}

/// Observe a whole drain batch. Linux must enumerate `/proc` only once:
/// scanning it separately for every dead sentinel can exhaust the drain
/// deadline even when all of the groups have already exited.
#[cfg(target_os = "linux")]
pub(super) fn members(pgids: &[i32]) -> Members {
    members_in(Path::new("/proc"), pgids)
}

#[cfg(target_os = "linux")]
fn members_in(procfs: &Path, pgids: &[i32]) -> Members {
    let requested: HashSet<_> = pgids.iter().copied().collect();
    let mut members = Members::default();
    if requested.is_empty() {
        return members;
    }
    let Ok(entries) = fs::read_dir(procfs) else {
        return members;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .filter(|name| name.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(Process { group, session }) = live_process_from_stat(&stat) else {
            continue;
        };
        if requested.contains(&group) {
            members.live.insert(group);
        } else if requested.contains(&session) {
            members.live.insert(session);
            members.by_session.push((session, pid));
        }
    }
    members
}

/// One `/proc/<pgid>/stat` read: the sentinel, live and still leading the
/// group.
#[cfg(target_os = "linux")]
fn sentinel_is_live(pgid: i32) -> bool {
    fs::read_to_string(format!("/proc/{pgid}/stat"))
        .is_ok_and(|stat| live_process_from_stat(&stat).is_some_and(|p| p.group == pgid))
}

/// The process group and session of a live process.
#[cfg(target_os = "linux")]
struct Process {
    group:   i32,
    session: i32,
}

/// Parse one `/proc/<pid>/stat` line: `pid (comm) state ppid pgrp session
/// ...`. The comm can hold spaces and parentheses, so the split is after the
/// *last* `)`. Zombies are not live: they cannot run, and the unreaped
/// sentinel is deliberately one.
#[cfg(target_os = "linux")]
fn live_process_from_stat(stat: &str) -> Option<Process> {
    let (_, rest) = stat.rsplit_once(')')?;
    let mut fields = rest.split_whitespace();
    let state = fields.next()?;
    let group = fields.nth(1)?.parse::<i32>().ok()?;
    let session = fields.next()?.parse::<i32>().ok()?;
    (state != "Z").then_some(Process { group, session })
}

/// libproc lists members by group rather than scanning all processes; the
/// session members outside the group need the full listing.
#[cfg(target_os = "macos")]
pub(super) fn members(pgids: &[i32]) -> Members {
    const PROC_ALL_PIDS: u32 = 1;
    const PROC_PGRP_ONLY: u32 = 2;
    let mut members = Members::default();
    for &pgid in pgids {
        let group = u32::try_from(pgid).unwrap_or(0);
        if list_pids(PROC_PGRP_ONLY, group).into_iter().any(is_live) {
            members.live.insert(pgid);
        }
    }
    for pid in list_pids(PROC_ALL_PIDS, 0) {
        let Some(session) = id_of(getsid(Pid::from_raw(pid))) else {
            continue;
        };
        if pgids.contains(&session)
            && id_of(getpgid(Pid::from_raw(pid))) != Some(session)
            && is_live(pid)
        {
            members.live.insert(session);
            members.by_session.push((session, pid));
        }
    }
    members
}

/// The raw id from a process query; `None` when the process is gone.
#[cfg(target_os = "macos")]
fn id_of(id: Result<Pid, Errno>) -> Option<i32> {
    id.ok().map(Pid::as_raw_nonzero).map(i32::from)
}

/// One libproc query: the sentinel, not yet a zombie.
#[cfg(target_os = "macos")]
fn sentinel_is_live(pgid: i32) -> bool {
    is_live(pgid)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::env;

    use super::{HashSet, fs, members_in};
    use crate::registry::fresh_id;

    #[test]
    fn a_batch_observes_groups_and_sessions_and_ignores_zombies_and_unrelated_processes() {
        let procfs = env::temp_dir().join(fresh_id());
        fs::create_dir_all(&procfs).expect("fixture process table");
        // Fields: pid (comm) state ppid pgrp session.
        for (pid, stat) in [
            ("100", "100 (sentinel) Z 1 100 1"),
            // The group remains live after its sentinel dies. The command
            // name can contain spaces and parentheses, including a ')'.
            ("101", "101 (child (with) spaces)) S 100 100 1"),
            ("200", "200 (sentinel) S 1 200 1"),
            ("201", "201 (second child) R 200 200 1"),
            ("300", "300 (zombie only) Z 1 300 1"),
            ("400", "400 (unrelated) S 1 400 1"),
            ("500", "500 (truncated) S 1"),
            ("600", "600 (bad group) S 1 invalid"),
            ("self", "100 (nonnumeric entry) S 1 700 700"),
            // A terminal's sentinel leads a session; its shell and the
            // shell's job each lead a group of their own inside it.
            ("1000", "1000 (sentinel) Z 1 1000 1000"),
            ("1001", "1001 (shell) S 1000 1001 1000"),
            ("1002", "1002 (job) S 1001 1002 1000"),
            ("1003", "1003 (exited job) Z 1001 1003 1000"),
            ("1101", "1101 (other terminal) S 1 1101 1100"),
        ] {
            let directory = procfs.join(pid);
            fs::create_dir(&directory).expect("fixture process");
            fs::write(directory.join("stat"), stat).expect("fixture stat");
        }
        // A process can disappear between enumeration and reading its stat.
        fs::create_dir(procfs.join("800")).expect("vanished process");
        let mut members = members_in(&procfs, &[
            100, 100, 200, 300, 500, 600, 700, 800, 900, 1000,
        ]);
        let empty = members_in(&procfs, &[]);
        fs::remove_dir_all(procfs).expect("fixture cleanup");
        members.by_session.sort_unstable();
        assert_eq!(members.live, HashSet::from([100, 200, 1000]));
        assert_eq!(members.by_session, [(1000, 1001), (1000, 1002)]);
        assert!(empty.live.is_empty());
        assert!(empty.by_session.is_empty());
    }
}

/// libproc's process listing of one `kind` (all processes, or one group's).
#[cfg(target_os = "macos")]
fn list_pids(kind: u32, info: u32) -> Vec<i32> {
    // SAFETY: this is `proc_listpids`' documented size-query form. A null
    // buffer paired with a zero byte count asks only how many bytes a full
    // listing would need, so libproc writes nothing and there is no storage
    // whose validity, size, or lifetime could be violated. The reply is a byte
    // count, or a non-positive value the code below treats as an empty listing.
    let sized = unsafe { libc::proc_listpids(kind, info, ptr::null_mut(), 0) };
    if sized <= 0 {
        return Vec::new();
    }
    // Headroom above the reported size: the listing can gain members between the
    // two calls, and a full buffer is indistinguishable from a truncated one.
    let capacity = usize::try_from(sized).unwrap_or(0) / size_of::<i32>() + 8;
    let mut pids = vec![0i32; capacity];
    let Ok(byte_capacity) = i32::try_from(capacity * size_of::<i32>()) else {
        return Vec::new();
    };

    // SAFETY: `pids.as_mut_ptr()` points to `capacity` initialized `i32`s in a
    // live allocation this thread borrows exclusively for the whole call, so
    // libproc's writes cannot race or dangle. `byte_capacity` is exactly that
    // allocation's size in bytes, so libproc cannot write past its end. Only
    // the returned byte count is used below, so no element libproc left
    // untouched is read as a pid.
    let filled =
        unsafe { libc::proc_listpids(kind, info, pids.as_mut_ptr().cast(), byte_capacity) };
    if filled <= 0 {
        return Vec::new();
    }

    pids.truncate(usize::try_from(filled).unwrap_or(0) / size_of::<i32>());
    pids.retain(|pid| *pid > 0);
    pids
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
