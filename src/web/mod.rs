//! Web UI backend (skeleton).
//!
//! Serves the local dashboard — the "Wireshark meets Prometheus" view: dense
//! log stream, live time-series graphs, and a History tab. Metrics stream over
//! a WebSocket; static assets (uPlot-based frontend) are embedded in the binary
//! so the tool ships as a single file. A PWA manifest lets the operator install
//! it as a standalone app.
//!
//! axum + WebSocket + rust-embed land in the web increment.

use anyhow::Result;

pub const DEFAULT_BIND: &str = "127.0.0.1:8787";

/// Start the dashboard server. Skeleton: not yet listening.
pub async fn serve(_bind: &str) -> Result<()> {
    // TODO(next): axum router, /ws metrics stream, embedded assets, PWA manifest.
    Ok(())
}
