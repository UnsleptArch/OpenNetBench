//! Metrics model.
//!
//! These are the numbers that make the tool worth more than a flood generator:
//! the collapse curve, time-to-degradation, and — the differentiator —
//! recovery time. The engine feeds samples in; the web UI streams snapshots out.

use serde::{Deserialize, Serialize};

/// A single point on the collapse curve: latency percentiles at a moment in
/// time, tagged with the concurrent load that produced them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencySample {
    /// Milliseconds since run start.
    pub t_ms: u64,
    /// Concurrent connections / in-flight requests at this instant.
    pub concurrency: u32,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    /// Fraction of requests in the window that errored or timed out (0.0–1.0).
    pub error_rate: f64,
}

/// Live snapshot the web UI renders. Cheap to clone and serialize.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub requests_sent: u64,
    pub responses_ok: u64,
    pub errors: u64,
    /// Connections currently held open (slowloris/RUDY/tcp_exhaust money shot).
    pub held_connections: u32,
    pub current_rps: f64,
    pub latest: Option<LatencySample>,
}

/// The distilled findings of a run — populated as evidence accumulates.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunOutcome {
    /// ms from run start to first sustained p99 breach of baseline.
    pub time_to_degradation_ms: Option<u64>,
    /// ms from load-stop to p99 returning to baseline. `None` = never recovered
    /// within the observation window. This is the blue-team gold metric.
    pub recovery_time_ms: Option<u64>,
    /// Baseline p99 measured before load (from recon timing).
    pub baseline_p99_ms: Option<f64>,
    /// The load level at which latency went non-linear (the knee), if found.
    pub knee_concurrency: Option<u32>,
}
