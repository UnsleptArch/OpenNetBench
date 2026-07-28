//! Asymmetry scoring.
//!
//! A single origin can't out-muscle a target; it wins by finding the endpoint
//! where one cheap request forces disproportionate server work. We measure that
//! along axes and combine them:
//!
//! - **Compute** — marginal server time a crafted input forces (from differential
//!   probing), amplified by how badly latency knees under a small concurrent
//!   burst, and **weighted by our confidence** in the timing estimate. A noisy
//!   300 ms delta must not outrank a rock-solid 80 ms one.
//! - **Bandwidth** — response bytes out per request byte in (amplification). A
//!   cacheable response is largely absorbed by an edge/CDN, so it's discounted.
//!   Bandwidth is a byte count, not a timing, so it needs no confidence weight.
//! - **GraphQL** — query-cost amplification (a strong, specific signal).
//!
//! Each axis is log-compressed so neither's raw magnitude (ms vs. a byte ratio
//! in the thousands) drowns the other. Weights are explicit. Classification is
//! done by comparing the axes' actual score *contributions*, not a hand-tuned
//! boundary in signal space.

/// Weight on the compute axis (forced server ms).
const COMPUTE_W: f64 = 1.0;
/// Weight on the bandwidth-amplification axis.
const BANDWIDTH_W: f64 = 0.7;
/// Weight on GraphQL query-cost amplification.
const GQL_W: f64 = 1.2;
/// Bandwidth discount when the response is cacheable (edge absorbs the load).
const CACHE_DISCOUNT: f64 = 0.15;

/// The measured signals for one endpoint.
#[derive(Debug, Clone, Copy)]
pub struct Signals {
    /// Marginal server ms a crafted input forces above baseline (median).
    pub compute_ms: f64,
    /// Confidence in `compute_ms`, 0..1 (from sample spread + count).
    pub confidence: f64,
    /// Latency knee under a bounded concurrent burst (>= 1.0; 1.0 = flat).
    pub degradation: f64,
    /// Response bytes out per request byte in.
    pub amplification: f64,
    /// GraphQL heavy/trivial query cost ratio (1.0 if not GraphQL).
    pub graphql_cost: f64,
    /// Whether responses are cacheable (bandwidth largely absorbed at the edge).
    pub cacheable: bool,
}

/// Per-axis score contributions — their sum is the asymmetry score, and their
/// relative sizes decide the weakness classification.
#[derive(Debug, Clone, Copy)]
pub struct Contributions {
    pub compute: f64,
    pub bandwidth: f64,
    pub graphql: f64,
}

/// Break the score into its per-axis contributions.
pub fn contributions(sig: &Signals) -> Contributions {
    let compute_pressure = sig.compute_ms.max(0.0) * sig.degradation.max(1.0);
    let cache_factor = if sig.cacheable { CACHE_DISCOUNT } else { 1.0 };
    Contributions {
        compute: COMPUTE_W * (1.0 + compute_pressure).ln() * sig.confidence.clamp(0.0, 1.0),
        bandwidth: BANDWIDTH_W * sig.amplification.max(1.0).ln() * cache_factor,
        graphql: GQL_W * sig.graphql_cost.max(1.0).ln(),
    }
}

/// Combined asymmetry rank key — higher = more fragile / higher leverage.
pub fn asymmetry(sig: &Signals) -> f64 {
    let c = contributions(sig);
    c.compute + c.bandwidth + c.graphql
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Signals {
        Signals {
            compute_ms: 0.0,
            confidence: 0.9,
            degradation: 1.0,
            amplification: 1.0,
            graphql_cost: 1.0,
            cacheable: false,
        }
    }

    #[test]
    fn a_static_cheap_endpoint_scores_near_zero() {
        assert!(asymmetry(&base()) < 0.01);
    }

    #[test]
    fn compute_cost_and_degradation_raise_the_score() {
        let mut s = base();
        s.compute_ms = 500.0;
        let flat = asymmetry(&s);
        s.degradation = 4.0;
        assert!(asymmetry(&s) > flat);
    }

    #[test]
    fn cacheable_bandwidth_is_discounted() {
        let mut hot = base();
        hot.amplification = 10_000.0;
        let mut cached = hot;
        cached.cacheable = true;
        assert!(asymmetry(&cached) < asymmetry(&hot));
    }

    #[test]
    fn graphql_cost_contributes() {
        let mut s = base();
        s.graphql_cost = 50.0;
        assert!(asymmetry(&s) > asymmetry(&base()));
    }

    #[test]
    fn confidence_weights_compute_a_solid_small_delta_beats_a_noisy_large_one() {
        // The reviewer's exact concern: a noisy 300 ms must not outrank a
        // rock-solid 80 ms.
        let mut noisy = base();
        noisy.compute_ms = 300.0;
        noisy.confidence = 0.2;

        let mut solid = base();
        solid.compute_ms = 80.0;
        solid.confidence = 0.9;

        assert!(asymmetry(&solid) > asymmetry(&noisy));
    }
}
