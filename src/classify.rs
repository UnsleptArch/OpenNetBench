//! Response classification.
//!
//! The intelligence of the tool: deciding whether the target dropping/blocking
//! us means the defense WORKED (mitigation win) or the service FAILED (finding).
//! Getting this wrong — calling a WAF save a "vuln" — would make every report a
//! lie, so verdicts always carry a confidence, never certainty.

use serde::{Deserialize, Serialize};

/// What the observed behavior most likely means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Traffic served normally; no stress observed.
    Healthy,
    /// 403/429 with a WAF/rate-limiter fingerprint — the defense is working.
    MitigationEngaged,
    /// Immediate clean RST on connect — edge firewall / connection drop.
    EdgeBlocked,
    /// Rising p99 → timeouts → refused, correlated with our load ramp. A real
    /// resource-exhaustion condition.
    Degrading,
    /// Service stopped responding entirely under load.
    Down,
    /// Not enough signal yet.
    Unknown,
}

impl Verdict {
    /// Is this a finding (something the target owner must fix) vs. a defense win?
    pub fn is_finding(self) -> bool {
        matches!(self, Verdict::Degrading | Verdict::Down)
    }
}

/// A classification with the evidence that produced it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Classification {
    pub verdict: Verdict,
    /// 0.0–1.0. Never 1.0 — we report likelihood, not proof.
    pub confidence: f64,
    /// Human-readable evidence trail (status codes, WAF fingerprint, timing).
    pub evidence: Vec<String>,
}
