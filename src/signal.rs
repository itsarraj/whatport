//! Sending SIGTERM/SIGKILL to a PID, plus confirming the process is
//! actually gone afterward rather than just trusting that the signal
//! landed.

use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

/// How long to poll `/proc/<pid>` for after sending a signal before
/// giving up on confirming the process actually exited.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(3);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, PartialEq)]
pub enum KillOutcome {
    /// Signal sent, and the process was confirmed gone (its
    /// `/proc/<pid>` directory disappeared) within the timeout.
    ConfirmedDead,
    /// Signal sent successfully, but the process was still alive when
    /// the confirmation window ran out (common for a plain SIGTERM
    /// against a process that ignores or slow-handles it — `--force`
    /// for SIGKILL is the escalation).
    SentButStillRunning,
    /// The PID no longer existed even before we tried (`ESRCH`) — it
    /// exited on its own between detection and the kill attempt. Not a
    /// failure: the end state (process gone) is what was wanted anyway.
    AlreadyGone,
    /// We don't have permission to signal this PID (`EPERM`) — e.g. it's
    /// owned by another user and we're not root.
    PermissionDenied,
    /// Any other OS-level failure sending the signal.
    Error(String),
}

/// Checks whether `<proc_root>/<pid>` still exists — the cheapest live
/// liveness check available, and exactly what `kill -0` itself is
/// backed by on Linux.
pub fn is_running(proc_root: &Path, pid: u32) -> bool {
    proc_root.join(pid.to_string()).exists()
}

/// Sends SIGTERM (or SIGKILL if `force`) to `pid`, then polls
/// `<proc_root>/<pid>` for up to `CONFIRM_TIMEOUT` to report whether the
/// process is actually gone — not just "the syscall didn't error."
pub fn kill_and_confirm(proc_root: &Path, pid: u32, force: bool) -> KillOutcome {
    let signal = if force {
        Signal::SIGKILL
    } else {
        Signal::SIGTERM
    };
    match kill(Pid::from_raw(pid as i32), signal) {
        Ok(()) => {}
        Err(Errno::ESRCH) => return KillOutcome::AlreadyGone,
        Err(Errno::EPERM) => return KillOutcome::PermissionDenied,
        Err(e) => return KillOutcome::Error(e.to_string()),
    }

    let deadline = Instant::now() + CONFIRM_TIMEOUT;
    while Instant::now() < deadline {
        if !is_running(proc_root, pid) {
            return KillOutcome::ConfirmedDead;
        }
        sleep(POLL_INTERVAL);
    }
    if is_running(proc_root, pid) {
        KillOutcome::SentButStillRunning
    } else {
        KillOutcome::ConfirmedDead
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn is_running_reflects_whether_the_proc_dir_exists() {
        let root = std::env::temp_dir().join(format!("whatport-sig-test-{}", std::process::id()));
        fs::create_dir_all(root.join("42")).unwrap();
        assert!(is_running(&root, 42));
        assert!(!is_running(&root, 43));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn signaling_a_pid_that_does_not_exist_on_this_real_host_is_already_gone() {
        // A PID far beyond the default `pid_max` (2^22 on stock Linux)
        // but still safely within `i32`'s positive range (unlike, say,
        // 4 billion, which would wrap negative in `Pid::from_raw`'s
        // `as i32` cast and get reinterpreted as a process-*group* kill
        // — exactly the kind of thing this test wants to avoid poking
        // at a real host). Essentially guaranteed not to exist: exercises
        // the real `kill()` syscall's ESRCH path, not a fake proc tree.
        let outcome = kill_and_confirm(Path::new("/proc"), 999_999_999u32, false);
        assert_eq!(outcome, KillOutcome::AlreadyGone);
    }
}
