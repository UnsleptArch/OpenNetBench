//! Persistence (skeleton).
//!
//! One local SQLite file backs two things:
//!   1. Run history (the UI's History tab) — every run's config + outcome.
//!   2. CVE correlation — a fingerprint → relevant-CVE lookup, populated by the
//!      installer from NVD feeds. This is correlation, NOT a full CVE scanner.
//!
//! rusqlite (bundled) gets wired in the persistence increment; the signatures
//! here fix the shape the rest of the code depends on.

use crate::recon::ReconReport;
use anyhow::Result;
use serde::{Deserialize, Serialize};

pub const DEFAULT_DB_PATH: &str = "opennetbench.db";

/// A CVE correlated to an observed server fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveMatch {
    pub id: String,
    pub summary: String,
    pub cvss: Option<f64>,
    /// Why we surfaced it (e.g. "HTTP/2 advertised → CVE-2023-44487 candidate").
    pub rationale: String,
}

/// Correlate a recon fingerprint against the local CVE DB.
///
/// Skeleton: returns an empty match set until the DB is wired.
pub fn correlate_cves(_report: &ReconReport, _db_path: &str) -> Result<Vec<CveMatch>> {
    Ok(Vec::new())
}
