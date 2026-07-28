//! Logging setup: everything is written to a timestamped run log file AND
//! surfaced to the terminal. The web UI later tails the same structured log so
//! the operator sees identical events in both places.
//!
//! The log directory is a stable per-user path ($XDG_STATE_HOME/opennetbench,
//! falling back to ~/.local/state/opennetbench), NOT the current directory.
//! That matters because a `sudo opennetbench` run and a plain one have
//! different HOMEs, so neither can leave a root-owned `logs/` dir sitting in
//! the working directory that the other can't write into. If the file log
//! can't be set up for any reason we warn and keep going with terminal-only
//! logging — the tool must always run, so logging never aborts it.

use std::path::PathBuf;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialize tracing. `log_dir` overrides the default per-user log directory.
///
/// Returns the log file path (when file logging is active) plus a guard that
/// must be held for the lifetime of the process to keep the non-blocking writer
/// alive. On any file-logging failure this falls back to terminal-only logging
/// and returns `(None, None)` — it never fails the process.
pub fn init(run_id: &str, log_dir: Option<PathBuf>) -> (Option<PathBuf>, Option<WorkerGuard>) {
    let filter = || {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,opennetbench=debug"))
    };

    match setup_file_appender(run_id, log_dir) {
        Ok((path, non_blocking, guard)) => {
            tracing_subscriber::registry()
                .with(filter())
                .with(fmt::layer().with_target(false)) // terminal
                .with(
                    fmt::layer()
                        .with_ansi(false)
                        .with_writer(non_blocking), // file
                )
                .init();
            (Some(path), Some(guard))
        }
        Err(err) => {
            // Terminal-only fallback. Warn on stderr since logging isn't up yet.
            eprintln!("warning: file logging disabled ({err}); logging to terminal only");
            tracing_subscriber::registry()
                .with(filter())
                .with(fmt::layer().with_target(false))
                .init();
            (None, None)
        }
    }
}

/// Resolve the log directory, ensure it exists and is writable, and build the
/// non-blocking file appender. Any failure short-circuits to `Err` so the
/// caller can fall back to terminal-only logging instead of panicking later.
fn setup_file_appender(
    run_id: &str,
    log_dir: Option<PathBuf>,
) -> std::io::Result<(PathBuf, tracing_appender::non_blocking::NonBlocking, WorkerGuard)> {
    let dir = match log_dir {
        Some(d) => d,
        None => default_log_dir().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no writable log directory (set HOME/XDG_STATE_HOME or pass --log-dir)",
            )
        })?,
    };
    std::fs::create_dir_all(&dir)?;

    let file_name = format!("onb-{run_id}.log");
    let path = dir.join(&file_name);

    // Probe writability up front. tracing-appender opens the file lazily on the
    // first write and PANICS inside its worker thread if that open fails, so we
    // verify here where the error is recoverable.
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    let file_appender = tracing_appender::rolling::never(&dir, &file_name);
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    Ok((path, non_blocking, guard))
}

/// Per-user log directory: `$XDG_STATE_HOME/opennetbench`, else
/// `$HOME/.local/state/opennetbench`. `None` if neither is set.
fn default_log_dir() -> Option<PathBuf> {
    if let Some(state) = std::env::var_os("XDG_STATE_HOME") {
        if !state.is_empty() {
            return Some(PathBuf::from(state).join("opennetbench"));
        }
    }
    let home = std::env::var_os("HOME")?;
    if home.is_empty() {
        return None;
    }
    Some(
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("opennetbench"),
    )
}
