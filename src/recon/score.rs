//! Asymmetry scoring.
//!
//! The core research idea: a single machine can't out-muscle a target, but it
//! can find the endpoint where one cheap request forces expensive server work.
//! We estimate that ratio from observable signals collected during recon.

/// Compute an asymmetry score from recon signals. Higher = the endpoint costs
/// the server far more than it costs us, and is a priority target.
///
/// Inputs are intentionally simple observables:
/// - `baseline_ms`: server-side latency for one request (proxy for CPU work).
/// - `request_bytes`: how little we spend to trigger it.
/// - `cacheable`: cached responses cost the origin ~nothing → deprioritize.
/// - `dynamic`: response varied with input (DB/compute in the path).
pub fn asymmetry(baseline_ms: f64, request_bytes: usize, cacheable: bool, dynamic: bool) -> f64 {
    // Cost to the server ~ time it spent. Cost to us ~ bytes we sent.
    let client_cost = (request_bytes.max(1) as f64).log2();
    let server_cost = baseline_ms.max(0.1);
    let mut score = server_cost / client_cost;
    if cacheable {
        score *= 0.15; // an edge cache absorbs the load; low value.
    }
    if dynamic {
        score *= 1.75; // compute/DB in the path amplifies the asymmetry.
    }
    score
}
