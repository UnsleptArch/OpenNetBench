//! Logging setup: everything is written to a timestamped run log file AND
//! surfaced to the terminal. The web UI later tails the same structured log so
//! the operator sees identical events in both places.

use anyhow::Result;
use std::path::PathBuf;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialize tracing. Returns the log file path plus a guard that must be
/// held for the lifetime of the process to keep the non-blocking writer alive.
pub fn init(run_id: &str) -> Result<(PathBuf, WorkerGuard)> {
    let dir = PathBuf::from("logs");
    std::fs::create_dir_all(&dir)?;
    let file_name = format!("onb-{run_id}.log");
    let path = dir.join(&file_name);

    let file_appender = tracing_appender::rolling::never(&dir, &file_name);
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,opennetbench=debug"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false)) // terminal
        .with(
            fmt::layer()
                .with_ansi(false)
                .with_writer(non_blocking), // file
        )
        .init();

    Ok((path, guard))
}
