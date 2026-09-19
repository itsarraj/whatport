use std::io::{self, ErrorKind, Write};
use std::path::Path;

use clap::Parser;
use whatport::signal::KillOutcome;
use whatport::{distinct_pids, find_port, PortMatch, ScanOutcome};

#[derive(Parser)]
#[command(
    name = "whatport",
    about = "Find (and optionally kill) whatever process is listening on a TCP port",
    version
)]
struct Cli {
    /// The port to look up.
    port: u16,

    /// Send SIGTERM to the process(es) found listening on this port.
    #[arg(long)]
    kill: bool,

    /// With --kill, send SIGKILL instead of SIGTERM.
    #[arg(long)]
    force: bool,

    /// Print machine-readable JSON instead of the human-readable table.
    #[arg(long)]
    json: bool,
}

/// Ignores a broken pipe rather than propagating it — the standard fix
/// in this workspace for a tool whose output will obviously get piped
/// into `head`/`less`/`grep` (see `netaudit`'s `main.rs` for the same
/// pattern and the live bug that motivated it).
fn ignore_broken_pipe(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(e) if e.kind() == ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

fn print_text(out: &mut impl Write, port: u16, outcome: &ScanOutcome) -> io::Result<()> {
    for m in &outcome.matches {
        if m.processes.is_empty() {
            writeln!(
                out,
                "{:<5} {:<24} owning process unknown",
                m.protocol, m.local_addr
            )?;
            if outcome.permission_denied {
                writeln!(
                    out,
                    "      (permission denied reading some /proc/<pid>/fd directories — the real owner may be one of those)"
                )?;
            }
            continue;
        }
        for p in &m.processes {
            let name = p.name.as_deref().unwrap_or("?");
            let cmd = p
                .cmdline
                .as_deref()
                .map(|c| format!("  {c}"))
                .unwrap_or_default();
            writeln!(
                out,
                "{:<5} {:<24} pid {:<8} {}{}",
                m.protocol, m.local_addr, p.pid, name, cmd
            )?;
        }
    }
    if outcome.matches.len() > 1 || distinct_pids(outcome).len() > 1 {
        writeln!(
            out,
            "note: more than one socket/process matched port {port} (SO_REUSEPORT or a forked listener) — all listed above"
        )?;
    }
    Ok(())
}

fn print_kill_report(
    out: &mut impl Write,
    pid: u32,
    outcome: KillOutcome,
    force: bool,
) -> io::Result<bool> {
    let verb = if force { "SIGKILL" } else { "SIGTERM" };
    match outcome {
        KillOutcome::ConfirmedDead => {
            writeln!(
                out,
                "sent {verb} to pid {pid} — confirmed dead (no longer in /proc)"
            )?;
            Ok(true)
        }
        KillOutcome::SentButStillRunning => {
            writeln!(
                out,
                "sent {verb} to pid {pid} — still running after 3s (try --force for SIGKILL)"
            )?;
            Ok(false)
        }
        KillOutcome::AlreadyGone => {
            writeln!(out, "pid {pid} was already gone before the signal was sent")?;
            Ok(true)
        }
        KillOutcome::PermissionDenied => {
            writeln!(
                out,
                "permission denied sending {verb} to pid {pid} (not our process, not root)"
            )?;
            Ok(false)
        }
        KillOutcome::Error(e) => {
            writeln!(out, "failed to signal pid {pid}: {e}")?;
            Ok(false)
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let proc_root = Path::new("/proc");

    let outcome = find_port(proc_root, cli.port);

    let stdout = io::stdout();
    let mut out = stdout.lock();

    if outcome.matches.is_empty() {
        ignore_broken_pipe(if cli.json {
            writeln!(
                out,
                "{}",
                serde_json::to_string_pretty(&Vec::<PortMatch>::new())?
            )
        } else {
            writeln!(out, "nothing is listening on port {}", cli.port)
        })?;
        std::process::exit(1);
    }

    ignore_broken_pipe(if cli.json {
        writeln!(out, "{}", serde_json::to_string_pretty(&outcome.matches)?)
    } else {
        print_text(&mut out, cli.port, &outcome)
    })?;

    if !cli.kill {
        return Ok(());
    }

    let pids = distinct_pids(&outcome);
    if pids.is_empty() {
        writeln!(
            out,
            "cannot kill: no owning process could be determined for port {}{}",
            cli.port,
            if outcome.permission_denied {
                " (permission denied reading some process directories)"
            } else {
                ""
            }
        )?;
        std::process::exit(1);
    }

    let mut all_ok = true;
    for pid in pids {
        let result = whatport::signal::kill_and_confirm(proc_root, pid, cli.force);
        let ok = print_kill_report(&mut out, pid, result, cli.force)?;
        all_ok &= ok;
    }

    if !all_ok {
        std::process::exit(1);
    }
    Ok(())
}
