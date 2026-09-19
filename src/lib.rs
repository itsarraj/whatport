pub mod procinfo;
pub mod proctcp;
pub mod signal;

use std::path::Path;

use serde::Serialize;

use procinfo::ProcessInfo;

#[derive(Debug, Clone, Serialize)]
pub struct ProcessMatch {
    pub pid: u32,
    pub name: Option<String>,
    pub cmdline: Option<String>,
}

impl From<&ProcessInfo> for ProcessMatch {
    fn from(p: &ProcessInfo) -> Self {
        ProcessMatch {
            pid: p.pid,
            name: p.name.clone(),
            cmdline: p.cmdline.clone(),
        }
    }
}

/// One `LISTEN` socket bound to the port that was asked about, plus
/// whatever process(es) — usually exactly one — hold it open.
#[derive(Debug, Clone, Serialize)]
pub struct PortMatch {
    /// `"tcp"` or `"tcp6"`.
    pub protocol: &'static str,
    pub local_addr: String,
    pub inode: u64,
    /// Normally one entry. Empty means a socket genuinely exists on
    /// this port but no owning process could be found among the PIDs we
    /// were able to read (see `permission_denied` on the containing
    /// `ScanOutcome`). More than one is real: `SO_REUSEPORT`, or a
    /// forked listener whose children all inherited the same fd.
    pub processes: Vec<ProcessMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanOutcome {
    pub matches: Vec<PortMatch>,
    /// True if scanning `/proc/*/fd` hit at least one directory we
    /// couldn't read (another user's process, and we're not root) —
    /// meaning the true owner of a socket with zero resolved processes
    /// might just be a process we couldn't see into, not that nothing
    /// owns it.
    pub permission_denied: bool,
}

/// The full pipeline for one port: read `net/tcp` + `net/tcp6` under
/// `proc_root`, keep only `LISTEN` rows bound to `port`, and resolve
/// each to its owning process(es) by inode.
pub fn find_port(proc_root: &Path, port: u16) -> ScanOutcome {
    let mut matches = Vec::new();
    let mut permission_denied = false;

    for (rel, protocol, ipv6) in [("net/tcp", "tcp", false), ("net/tcp6", "tcp6", true)] {
        let Ok(contents) = std::fs::read_to_string(proc_root.join(rel)) else {
            continue;
        };
        for socket in proctcp::parse_listen_sockets_for_port(&contents, port, ipv6) {
            let scan = procinfo::find_pids_for_inode(proc_root, socket.inode);
            if scan.permission_denied {
                permission_denied = true;
            }
            let processes: Vec<ProcessMatch> = procinfo::resolve_processes(proc_root, &scan.pids)
                .iter()
                .map(ProcessMatch::from)
                .collect();
            matches.push(PortMatch {
                protocol,
                local_addr: socket.local_addr,
                inode: socket.inode,
                processes,
            });
        }
    }

    ScanOutcome {
        matches,
        permission_denied,
    }
}

/// Every distinct PID across every match's process list, in first-seen
/// order — what `--kill` targets. Deduplicated because the same PID can
/// legitimately show up more than once (e.g. one process holding both
/// the `tcp` and `tcp6` listen sockets for a dual-stack bind).
pub fn distinct_pids(outcome: &ScanOutcome) -> Vec<u32> {
    let mut seen = std::collections::HashSet::new();
    let mut pids = Vec::new();
    for m in &outcome.matches {
        for p in &m.processes {
            if seen.insert(p.pid) {
                pids.push(p.pid);
            }
        }
    }
    pids
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    /// Builds a fake `/proc`-like tree with one TCP listen socket on
    /// `port`, owned by `pid`, and returns its root path.
    fn fake_proc_tree(tag: &str, port: u16, inode: u64, pid: u32) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("whatport-lib-test-{}-{}", std::process::id(), tag));
        fs::create_dir_all(root.join("net")).unwrap();
        let port_hex = format!("{port:04X}");
        fs::write(
            root.join("net/tcp"),
            format!(
                "header\n   0: 00000000:{port_hex} 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 {inode} 1 0 100 0 0 10 0\n"
            ),
        )
        .unwrap();
        fs::write(root.join("net/tcp6"), "header\n").unwrap();

        let fd_dir = root.join(pid.to_string()).join("fd");
        fs::create_dir_all(&fd_dir).unwrap();
        symlink(format!("socket:[{inode}]"), fd_dir.join("3")).unwrap();
        fs::write(root.join(pid.to_string()).join("comm"), "myserver\n").unwrap();
        fs::write(
            root.join(pid.to_string()).join("cmdline"),
            b"myserver\0--port\0",
        )
        .unwrap();

        root
    }

    #[test]
    fn end_to_end_finds_the_process_bound_to_the_port() {
        let root = fake_proc_tree("basic", 8080, 111, 500);
        let outcome = find_port(&root, 8080);
        assert_eq!(outcome.matches.len(), 1);
        assert_eq!(outcome.matches[0].protocol, "tcp");
        assert_eq!(outcome.matches[0].processes.len(), 1);
        assert_eq!(outcome.matches[0].processes[0].pid, 500);
        assert_eq!(
            outcome.matches[0].processes[0].name,
            Some("myserver".to_string())
        );
        assert!(!outcome.permission_denied);
        assert_eq!(distinct_pids(&outcome), vec![500]);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn port_not_in_use_returns_no_matches() {
        let root = fake_proc_tree("unused", 8080, 111, 500);
        let outcome = find_port(&root, 9999);
        assert!(outcome.matches.is_empty());
        assert!(distinct_pids(&outcome).is_empty());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn distinct_pids_dedupes_a_pid_seen_on_both_tcp_and_tcp6() {
        let root = std::env::temp_dir().join(format!(
            "whatport-lib-test-{}-dualstack",
            std::process::id()
        ));
        fs::create_dir_all(root.join("net")).unwrap();
        fs::write(
            root.join("net/tcp"),
            "header\n   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0 100 0 0 10 0\n",
        )
        .unwrap();
        fs::write(
            root.join("net/tcp6"),
            "header\n   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0 100 0 0 10 0\n",
        )
        .unwrap();
        let fd_dir = root.join("700/fd");
        fs::create_dir_all(&fd_dir).unwrap();
        symlink("socket:[111]", fd_dir.join("3")).unwrap();
        symlink("socket:[222]", fd_dir.join("4")).unwrap();

        let outcome = find_port(&root, 8080);
        assert_eq!(outcome.matches.len(), 2);
        assert_eq!(distinct_pids(&outcome), vec![700]);
        fs::remove_dir_all(&root).ok();
    }
}
