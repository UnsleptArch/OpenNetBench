//! Interactive flow: walks the operator from consent to a fully-resolved
//! `RunConfig`. Ordering mirrors the documented UX — authorization, target,
//! proxy, mode, recon, per-vector tuning, timing, final summary.

use crate::config::{ProxyConfig, RunConfig, RunMode, Vector, VectorPlan, VectorTuning};
use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, MultiSelect, Select};
use std::time::Duration;

pub fn banner() {
    println!("OpenNetBench — single-origin resilience assessment");
    println!("GPLv3 · authorized testing only · all traffic leaves THIS host\n");
}

/// Build a run plan through interactive prompts.
pub fn interactive_flow() -> Result<RunConfig> {
    // Target ----------------------------------------------------------------
    let target: String = Input::new()
        .with_prompt("Target URL")
        .interact_text()?;
    let target = normalize_target(&target)?;

    // Proxy -----------------------------------------------------------------
    let proxy = if Confirm::new()
        .with_prompt("Route through a proxy (e.g. Tor SOCKS5 127.0.0.1:9050)?")
        .default(false)
        .interact()?
    {
        let url: String = Input::new()
            .with_prompt("Proxy URL")
            .default("socks5://127.0.0.1:9050".to_string())
            .interact_text()?;
        Some(ProxyConfig { url })
    } else {
        None
    };

    // Mode ------------------------------------------------------------------
    let modes = [RunMode::Adaptive, RunMode::Dumb];
    let mode_idx = Select::new()
        .with_prompt("Run mode")
        .items(&modes.iter().map(|m| m.label()).collect::<Vec<_>>())
        .default(0)
        .interact()?;
    let mode = modes[mode_idx];

    // Recon -----------------------------------------------------------------
    let run_recon = Confirm::new()
        .with_prompt("Run recon first (crawl + rank targets for your approval)?")
        .default(true)
        .interact()?;

    // Vector selection ------------------------------------------------------
    let labels: Vec<String> = Vector::ALL
        .iter()
        .map(|v| format!("{:<16} [{}] {}", v.slug(), v.layer(), v.description()))
        .collect();
    let picks = MultiSelect::new()
        .with_prompt("Select vectors (space to toggle, enter to confirm)")
        .items(&labels)
        .interact()?;
    anyhow::ensure!(!picks.is_empty(), "no vectors selected — nothing to run");

    // Per-vector tuning -----------------------------------------------------
    let mut vectors = Vec::with_capacity(picks.len());
    for idx in picks {
        let v = Vector::ALL[idx];
        let tuning = tune_vector(v)?;
        vectors.push(VectorPlan { vector: v, tuning });
    }

    // Timing ----------------------------------------------------------------
    let duration_s: u64 = Input::new()
        .with_prompt("Duration (seconds, 0 = until stopped)")
        .default(60)
        .interact_text()?;
    let rampup_s: u64 = Input::new()
        .with_prompt("Ramp-up (seconds)")
        .default(10)
        .interact_text()?;

    let cfg = RunConfig {
        target,
        proxy,
        mode,
        run_recon,
        vectors,
        duration: Duration::from_secs(duration_s),
        rampup: Duration::from_secs(rampup_s),
    };

    print_summary(&cfg);
    Ok(cfg)
}

/// Prompt for per-vector knobs, seeded from conservative defaults. This is the
/// "uber customizable" surface — each vector is tuned independently.
fn tune_vector(v: Vector) -> Result<VectorTuning> {
    let d = VectorTuning::defaults_for(v);
    println!("\n-- tuning {} [{}] --", v.slug(), v.layer());

    let concurrency: u32 = Input::new()
        .with_prompt("  concurrency (workers/connections)")
        .default(d.concurrency)
        .interact_text()?;
    let rate_per_worker: u32 = Input::new()
        .with_prompt("  requests/sec per worker (0 = unbounded)")
        .default(d.rate_per_worker)
        .interact_text()?;

    let mut tuning = VectorTuning {
        concurrency,
        rate_per_worker,
        ..d.clone()
    };

    // Only prompt for fields that mean something for this vector.
    match v {
        Vector::Slowloris | Vector::Rudy => {
            let secs: u64 = Input::new()
                .with_prompt("  trickle interval (seconds)")
                .default(d.trickle_interval.as_secs())
                .interact_text()?;
            tuning.trickle_interval = Duration::from_secs(secs);
        }
        Vector::UdpFlood => {
            tuning.payload_bytes = Input::new()
                .with_prompt("  UDP payload bytes")
                .default(d.payload_bytes)
                .interact_text()?;
        }
        _ => {}
    }
    Ok(tuning)
}

fn normalize_target(raw: &str) -> Result<String> {
    let candidate = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    url::Url::parse(&candidate).with_context(|| format!("invalid target URL: {raw}"))?;
    Ok(candidate)
}

fn print_summary(cfg: &RunConfig) {
    println!("\n===== run plan =====");
    println!("target   : {}", cfg.target);
    println!(
        "proxy    : {}",
        cfg.proxy.as_ref().map(|p| p.url.as_str()).unwrap_or("none")
    );
    println!("mode     : {}", cfg.mode.label());
    println!("recon    : {}", if cfg.run_recon { "yes" } else { "no" });
    println!("duration : {}s (ramp {}s)", cfg.duration.as_secs(), cfg.rampup.as_secs());
    println!("vectors  :");
    for p in &cfg.vectors {
        println!(
            "  - {:<16} conc={} rate={}/s",
            p.vector.slug(),
            p.tuning.concurrency,
            p.tuning.rate_per_worker
        );
    }
    println!("====================\n");
}
