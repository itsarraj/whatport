//! Live end-to-end verification against a *real* spawned process on a
//! *real* port, on this real host — not mocked `/proc`. This is the bar
//! this whole workspace holds every tool to (see `tools/README.md`).
//!
//! Each test spawns a genuine `python3 -m http.server`, runs the actual
//! compiled `whatport` binary against the real port it's listening on,
//! and asserts against ground truth: the child's real PID (`child.id()`)
//! and, for the kill tests, the process's real absence afterward
//! (`/proc/<pid>` gone / `kill -0` failing).

use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `cargo test` runs every test in this binary concurrently by default.
/// Each test picks a "free" port by binding to port 0 and immediately
/// releasing it (see `free_port` below) — with several tests doing that
/// at the same instant, two can legitimately be handed the *same* just-
/// released port before either one's real `python3` server claims it,
/// so one server fails to bind and a later assertion sees "nothing is
/// listening" instead of a real race in the tool under test. Observed
/// live in this exact suite. Serializing everything in this file with
/// one lock removes that race entirely — real fix, not a retry/sleep
/// papering over it — while unit tests elsewhere still run in parallel
/// as normal (this only affects this binary's own tests).
static SERIAL: Mutex<()> = Mutex::new(());

fn serialize() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Asks the OS for a free port by binding to port 0 and immediately
/// releasing it, then hands that port number to a real `python3`
/// listener.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    listener.local_addr().unwrap().port()
}

fn spawn_http_server(port: u16) -> Child {
    Command::new("python3")
        .args([
            "-m",
            "http.server",
            "--bind",
            "127.0.0.1",
            &port.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn a real python3 http.server")
}

/// Polls until a TCP connection to `port` succeeds (the server is
/// genuinely accepting) or `timeout` elapses.
fn wait_until_listening(port: u16, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("python3 http.server never started listening on port {port}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn proc_dir_exists(pid: u32) -> bool {
    std::path::Path::new("/proc").join(pid.to_string()).exists()
}

/// Spawns the real http.server and immediately hands the `Child` off to
/// a background thread that just blocks on `wait()`. Necessary for the
/// kill tests specifically: this test process is the server's real
/// parent, so once `whatport --kill` (a separate, unrelated process)
/// signals it, the kernel can't fully reap it into "gone from /proc"
/// until *this* parent calls `wait()` on it — until then it's a zombie,
/// which still has a `/proc/<pid>` entry and would otherwise make
/// `whatport`'s own liveness poll (correctly) report "still running".
/// Reaping in the background the instant it happens is what a real
/// daemon's real init/supervisor does automatically; this reproduces
/// that instead of leaving a self-inflicted zombie artifact of the test
/// harness itself.
fn spawn_reaped_http_server(port: u16) -> u32 {
    let child = spawn_http_server(port);
    let pid = child.id();
    std::thread::spawn(move || {
        let mut child = child;
        let _ = child.wait();
    });
    pid
}

fn whatport_bin() -> &'static str {
    env!("CARGO_BIN_EXE_whatport")
}

fn run_whatport(args: &[&str]) -> (String, String, i32) {
    let output = Command::new(whatport_bin())
        .args(args)
        .output()
        .expect("run the compiled whatport binary");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code().unwrap_or(-1),
    )
}

#[test]
fn finds_the_real_pid_of_a_real_process_listening_on_a_real_port() {
    let _guard = serialize();
    let port = free_port();
    let mut child = spawn_http_server(port);
    wait_until_listening(port, Duration::from_secs(5));

    let real_pid = child.id();
    let (stdout, _stderr, code) = run_whatport(&[&port.to_string()]);

    // Clean up regardless of assertion outcome.
    let _ = child.kill();
    let _ = child.wait();

    assert_eq!(code, 0, "whatport should exit 0 when it finds a listener");
    assert!(
        stdout.contains(&real_pid.to_string()),
        "expected the real PID {real_pid} in whatport's output, got:\n{stdout}"
    );
    assert!(
        stdout.to_lowercase().contains("python"),
        "expected the real process name to mention python, got:\n{stdout}"
    );
}

#[test]
fn json_output_is_valid_and_contains_the_real_pid() {
    let _guard = serialize();
    let port = free_port();
    let mut child = spawn_http_server(port);
    wait_until_listening(port, Duration::from_secs(5));
    let real_pid = child.id();

    let (stdout, _stderr, code) = run_whatport(&[&port.to_string(), "--json"]);
    let _ = child.kill();
    let _ = child.wait();

    assert_eq!(code, 0);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    let text = parsed.to_string();
    assert!(
        text.contains(&real_pid.to_string()),
        "expected pid {real_pid} in JSON output: {text}"
    );
}

#[test]
fn reports_port_not_in_use_with_nonzero_exit() {
    let _guard = serialize();
    // Grab a free port and then release it, and don't listen on it —
    // whatever it is, it should be unbound at the moment whatport looks.
    let port = free_port();
    let (stdout, _stderr, code) = run_whatport(&[&port.to_string()]);
    assert_eq!(
        code, 1,
        "should be a nonzero exit when nothing is listening"
    );
    assert!(
        stdout.contains("nothing is listening"),
        "expected a clear not-in-use message, got:\n{stdout}"
    );
}

#[test]
fn kill_sends_sigterm_and_the_real_process_is_genuinely_dead_afterward() {
    let _guard = serialize();
    let port = free_port();
    let real_pid = spawn_reaped_http_server(port);
    wait_until_listening(port, Duration::from_secs(5));

    assert!(
        proc_dir_exists(real_pid),
        "sanity check: the real child process should exist in /proc before killing it"
    );

    let (stdout, _stderr, code) = run_whatport(&[&port.to_string(), "--kill"]);

    assert_eq!(
        code, 0,
        "kill should exit 0 on success, got stdout:\n{stdout}"
    );
    assert!(
        stdout.contains(&real_pid.to_string()),
        "kill report should mention the real pid {real_pid}, got:\n{stdout}"
    );
    assert!(
        stdout.contains("confirmed dead"),
        "expected an explicit dead-confirmation line, got:\n{stdout}"
    );

    // Ground truth, independent of whatport's own claim: the real PID's
    // /proc entry is genuinely gone.
    let deadline = Instant::now() + Duration::from_secs(2);
    while proc_dir_exists(real_pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !proc_dir_exists(real_pid),
        "pid {real_pid} should be genuinely gone from /proc after --kill"
    );
}

#[test]
fn kill_force_sends_sigkill_and_confirms_death() {
    let _guard = serialize();
    let port = free_port();
    let real_pid = spawn_reaped_http_server(port);
    wait_until_listening(port, Duration::from_secs(5));

    let (stdout, _stderr, code) = run_whatport(&[&port.to_string(), "--kill", "--force"]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("SIGKILL"), "stdout:\n{stdout}");
    assert!(stdout.contains("confirmed dead"), "stdout:\n{stdout}");

    let deadline = Instant::now() + Duration::from_secs(2);
    while proc_dir_exists(real_pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!proc_dir_exists(real_pid));
}

#[test]
fn kill_on_an_unused_port_fails_cleanly_without_a_pid_to_target() {
    let _guard = serialize();
    let port = free_port();
    let (stdout, _stderr, code) = run_whatport(&[&port.to_string(), "--kill"]);
    assert_eq!(code, 1);
    assert!(stdout.contains("nothing is listening"));
}
