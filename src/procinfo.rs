//! Maps a socket inode (from `proctcp.rs`) back to the process(es) that
//! hold it open, by walking `<proc_root>/<pid>/fd/*` symlinks looking
//! for `socket:[<inode>]` — genuinely how `lsof`/`fuser` do this on
//! Linux, no `lsof` binary dependency. `proc_root` is a parameter
//! throughout so all of this is testable against a fake tree instead of
//! the real `/proc`.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

/// One process found holding an fd for a matched socket inode.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: Option<String>,
    pub cmdline: Option<String>,
}

/// Result of scanning every `<proc_root>/*/fd` directory for one target
/// inode.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct InodeScan {
    /// Usually 0 or 1 PID. More than one is real and not a bug: a
    /// listening socket's fd is commonly inherited across `fork()`
    /// (e.g. a preforking server's worker processes all hold the same
    /// listen fd), so several PIDs can legitimately map to one inode.
    pub pids: Vec<u32>,
    /// Set when at least one `<pid>/fd` directory could not be read
    /// because it belongs to another user (`EACCES` — exactly the case
    /// real `lsof`/`fuser` need root to see into). This means the scan
    /// may be incomplete: some other, unreadable process could also (or
    /// instead) be the real owner. Kept separate from `pids` rather than
    /// folded into an error, since a *partial* result is still useful
    /// and should still be reported — not discarded just because it
    /// might not be the whole picture.
    pub permission_denied: bool,
}

/// Walks every PID directory under `proc_root` looking for an fd that
/// resolves to `socket:[<inode>]`. Directories that vanish mid-scan
/// (a process exiting concurrently) or that aren't even numeric PID
/// directories are silently skipped — normal, not an error condition.
pub fn find_pids_for_inode(proc_root: &Path, inode: u64) -> InodeScan {
    let mut scan = InodeScan::default();
    let target = format!("socket:[{inode}]");
    let Ok(entries) = fs::read_dir(proc_root) else {
        return scan;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let fds = match fs::read_dir(entry.path().join("fd")) {
            Ok(fds) => fds,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                scan.permission_denied = true;
                continue;
            }
            Err(_) => continue, // e.g. the process already exited
        };
        for fd in fds.flatten() {
            match fs::read_link(fd.path()) {
                Ok(link) if link.to_string_lossy() == target => {
                    scan.pids.push(pid);
                    break;
                }
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                    scan.permission_denied = true;
                }
                Err(_) => {}
            }
        }
    }
    scan
}

/// `/proc/<pid>/comm` — the short process name (e.g. `python3`).
pub fn process_name(proc_root: &Path, pid: u32) -> Option<String> {
    let comm = fs::read_to_string(proc_root.join(pid.to_string()).join("comm")).ok()?;
    let trimmed = comm.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// `/proc/<pid>/cmdline` is the process's argv, NUL-separated (not
/// space- or newline-separated) with no trailing newline — joined with
/// spaces here for display. Empty (a zombie, or some kernel threads)
/// yields `None` rather than an empty string.
pub fn process_cmdline(proc_root: &Path, pid: u32) -> Option<String> {
    let raw = fs::read(proc_root.join(pid.to_string()).join("cmdline")).ok()?;
    if raw.is_empty() {
        return None;
    }
    let joined = raw
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    if joined.is_empty() {
        None
    } else {
        Some(joined)
    }
}

/// Convenience wrapper: resolves every PID in `scan` into a full
/// `ProcessInfo` (name + cmdline best-effort, missing fields just become
/// `None` rather than failing the whole lookup).
pub fn resolve_processes(proc_root: &Path, pids: &[u32]) -> Vec<ProcessInfo> {
    pids.iter()
        .map(|&pid| ProcessInfo {
            pid,
            name: process_name(proc_root, pid),
            cmdline: process_cmdline(proc_root, pid),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fake_proc_root(name: &str) -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "whatport-test-{}-{}-{}",
            std::process::id(),
            name,
            n
        ))
    }

    #[test]
    fn finds_pid_for_a_matching_inode() {
        let root = fake_proc_root("match");
        let fd_dir = root.join("500/fd");
        fs::create_dir_all(&fd_dir).unwrap();
        symlink("socket:[777]", fd_dir.join("4")).unwrap();
        fs::write(root.join("500/comm"), "postgres\n").unwrap();
        fs::write(root.join("500/cmdline"), b"postgres\0-D\0/data\0").unwrap();

        let scan = find_pids_for_inode(&root, 777);
        assert_eq!(scan.pids, vec![500]);
        assert!(!scan.permission_denied);
        assert_eq!(process_name(&root, 500), Some("postgres".to_string()));
        assert_eq!(
            process_cmdline(&root, 500),
            Some("postgres -D /data".to_string())
        );

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn no_match_returns_empty_not_an_error() {
        let root = fake_proc_root("nomatch");
        fs::create_dir_all(&root).unwrap();
        let scan = find_pids_for_inode(&root, 999);
        assert!(scan.pids.is_empty());
        assert!(!scan.permission_denied);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn multiple_pids_can_share_one_inode_forked_listener_case() {
        // A preforking server: parent binds, forks workers, every
        // worker inherits the same listen fd -> same socket inode shows
        // up under several PIDs' fd directories.
        let root = fake_proc_root("forked");
        for pid in ["100", "101", "102"] {
            let fd_dir = root.join(pid).join("fd");
            fs::create_dir_all(&fd_dir).unwrap();
            symlink("socket:[888]", fd_dir.join("3")).unwrap();
        }
        let mut scan = find_pids_for_inode(&root, 888);
        scan.pids.sort();
        assert_eq!(scan.pids, vec![100, 101, 102]);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn permission_denied_on_one_pid_is_flagged_but_others_still_found() {
        let root = fake_proc_root("permdenied");
        let denied_fd = root.join("200/fd");
        fs::create_dir_all(&denied_fd).unwrap();
        symlink("socket:[999]", denied_fd.join("1")).unwrap();
        fs::set_permissions(&denied_fd, fs::Permissions::from_mode(0o000)).unwrap();

        let ok_fd = root.join("300/fd");
        fs::create_dir_all(&ok_fd).unwrap();
        symlink("socket:[321]", ok_fd.join("1")).unwrap();

        // Looking for the inode that's actually behind the readable fd
        // dir: found cleanly, and the permission-denied elsewhere is
        // still surfaced so the caller knows the picture might be
        // incomplete.
        let scan = find_pids_for_inode(&root, 321);
        assert_eq!(scan.pids, vec![300]);
        assert!(scan.permission_denied);

        // restore perms so the temp dir can be cleaned up
        fs::set_permissions(&denied_fd, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cmdline_with_no_content_is_none() {
        let root = fake_proc_root("emptycmdline");
        fs::create_dir_all(root.join("400")).unwrap();
        fs::write(root.join("400/cmdline"), b"").unwrap();
        assert_eq!(process_cmdline(&root, 400), None);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn missing_comm_file_is_none_not_a_panic() {
        let root = fake_proc_root("nocomm");
        fs::create_dir_all(&root).unwrap();
        assert_eq!(process_name(&root, 12345), None);
        fs::remove_dir_all(&root).ok();
    }
}
