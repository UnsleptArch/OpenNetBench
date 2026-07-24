//! Load engine (skeleton).
//!
//! Owns the scheduler that paces vectors according to `RunMode`, the adaptive
//! self-throttle, and the per-vector worker pools. Each vector gets its own
//! submodule; this module dispatches to them and aggregates metrics.

use crate::config::{RunConfig, Vector};
use anyhow::Result;
use tracing::{info, warn};

/// Drive a full run to completion (or until the operator stops it).
///
/// Skeleton: validates the plan and logs intent. Vector workers, the scheduler,
/// and the adaptive throttle land in subsequent increments.
pub async fn run(cfg: &RunConfig) -> Result<()> {
    info!(target = %cfg.target, mode = ?cfg.mode, "engine: starting run");

    for plan in &cfg.vectors {
        if plan.vector.needs_root() && !is_root() {
            warn!(
                vector = plan.vector.slug(),
                "vector requires root (CAP_NET_RAW) — will be skipped"
            );
        }
        info!(
            vector = plan.vector.slug(),
            layer = plan.vector.layer(),
            concurrency = plan.tuning.concurrency,
            "engine: vector queued"
        );
    }

    // TODO(next): scheduler + ramp-up, per-vector workers, adaptive throttle,
    // metrics aggregation, cooperative shutdown on Ctrl-C.
    warn!("engine execution not yet implemented — this is the scaffold");
    Ok(())
}

/// Best-effort root check (Unix). Raw-socket vectors need it.
fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid is always safe to call and has no preconditions.
        unsafe { libc_geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(unix)]
extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

/// Convenience: which vectors are L7 vs L4, for scheduler grouping later.
pub fn is_l7(v: Vector) -> bool {
    v.layer() == "L7"
}
