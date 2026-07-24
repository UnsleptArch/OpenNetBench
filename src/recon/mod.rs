//! Recon engine (skeleton).
//!
//! Crawls the target, fingerprints the server, and scores endpoints by
//! *asymmetry* — how much a single request costs the server vs. the client.
//! Output is a ranked list the operator reviews and approves. Recon NEVER
//! auto-queues a flood: human-in-the-loop is the safety and credibility line.

pub mod score;

use serde::{Deserialize, Serialize};

/// One discovered endpoint plus everything we learned about it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub url: String,
    pub method: String,
    /// Whether responses carry cache headers (uncached = higher flood value).
    pub cacheable: bool,
    /// Baseline server-side timing, averaged over samples (ms).
    pub baseline_ms: f64,
    /// Asymmetry score — see `score` module. Higher = more fragile.
    pub asymmetry: f64,
}

/// The full recon report presented to the operator for target approval.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReconReport {
    pub server_fingerprint: Option<String>,
    pub missing_security_headers: Vec<String>,
    /// Sensitive paths that responded (.env, actuator, graphql, …).
    pub exposed_paths: Vec<String>,
    /// HTTP methods the server accepted (TRACE, DELETE, CONNECT, …).
    pub allowed_methods: Vec<String>,
    /// Endpoints ranked by descending asymmetry.
    pub ranked_endpoints: Vec<Endpoint>,
}

// TODO(next): crawl.rs (async site crawl + form discovery),
// fingerprint.rs (server/header/method probing), and wire baseline timing.
