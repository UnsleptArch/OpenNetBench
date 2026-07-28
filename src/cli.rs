//! Interactive flow: walks the operator from consent to a fully-resolved
//! `RunConfig`. Ordering mirrors the documented UX — authorization, target,
//! proxy, mode, recon, per-vector tuning, timing, final summary.

use crate::config::{ProxyConfig, RunConfig, RunMode, Vector, VectorPlan, VectorTuning};
use crate::recon::{ReconReport, Weakness};
use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, MultiSelect, Select};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Load a run plan from a JSON file (same shape as [`RunConfig`]). The consent
/// gate is still enforced separately in `main` — config never bypasses it.
pub fn load_config(path: &std::path::Path) -> Result<RunConfig> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("reading config {}", path.display()))?;
    let cfg: RunConfig = serde_json::from_str(&data).context("parsing config JSON")?;
    let cfg = RunConfig {
        target: normalize_target(&cfg.target)?,
        ..cfg
    };
    print_summary(&cfg);
    Ok(cfg)
}

/// Print the recon findings for the operator.
pub fn present_recon(report: &ReconReport) {
    println!("\n===== recon report =====");
    println!(
        "server       : {}",
        report.server_fingerprint.as_deref().unwrap_or("unknown")
    );
    if report.spa_catchall {
        println!("catch-all    : yes (SPA fallback) — exposure scan filtered against it");
    }
    if !report.allowed_methods.is_empty() {
        println!("methods      : {}", report.allowed_methods.join(", "));
    }
    if !report.missing_security_headers.is_empty() {
        println!("missing hdrs : {}", report.missing_security_headers.join(", "));
    }
    if !report.exposed_paths.is_empty() {
        println!("exposed      :");
        for p in &report.exposed_paths {
            println!("  ! {p}");
        }
    }
    println!("ranked endpoints (by asymmetry):");
    for (i, ep) in report.ranked_endpoints.iter().take(15).enumerate() {
        println!(
            "  {:>2}. [{:>5.1}] {:<4} {:<9} {}{}",
            i + 1,
            ep.asymmetry,
            ep.method,
            weakness_label(ep.weakness),
            ep.url,
            if ep.cacheable { " [cached]" } else { "" },
        );
        println!(
            "        {}  |  baseline {:.0}ms  conf {:.2}",
            ep.note, ep.baseline_ms, ep.confidence
        );
    }
    println!("========================\n");
}

/// Resolve the exposure-scan wordlist: the flag's file if given, otherwise ask
/// the operator (built-in default vs. a custom file). `None` means the built-in
/// list, which recon fills in.
pub fn choose_wordlist(flag: Option<&PathBuf>, interactive: bool) -> Result<Option<Vec<String>>> {
    if let Some(p) = flag {
        return Ok(Some(load_wordlist(p)?));
    }
    if !interactive {
        return Ok(None); // non-interactive: use the built-in default, no prompt
    }
    let choice = Select::new()
        .with_prompt("Wordlist for the path-exposure scan")
        .items(&["Built-in (~40 common paths)", "Custom file..."])
        .default(0)
        .interact()?;
    if choice == 0 {
        Ok(None)
    } else {
        let path: String = Input::new()
            .with_prompt("Wordlist file path (one path per line)")
            .interact_text()?;
        Ok(Some(load_wordlist(Path::new(&path))?))
    }
}

fn load_wordlist(path: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading wordlist {}", path.display()))?;
    let paths: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            if l.starts_with('/') {
                l.to_string()
            } else {
                format!("/{l}")
            }
        })
        .collect();
    anyhow::ensure!(
        !paths.is_empty(),
        "wordlist {} has no usable entries",
        path.display()
    );
    Ok(paths)
}

fn weakness_label(w: Weakness) -> &'static str {
    match w {
        Weakness::InputCompute => "compute",
        Weakness::Bandwidth => "bandwidth",
        Weakness::Degradation => "degrade",
        Weakness::GraphQL => "graphql",
        Weakness::Static => "static",
    }
}

/// Choose which endpoint becomes the flood target. In `auto` mode the highest-
/// asymmetry endpoint is selected without prompting (unattended runs); otherwise
/// the operator picks, or keeps the original target. Returns the chosen URL, or
/// `None` to keep the configured target.
pub fn select_target(report: &ReconReport, auto: bool) -> Option<String> {
    let top = report.ranked_endpoints.first()?;
    if auto {
        return Some(top.url.clone());
    }

    let mut items: Vec<String> = report
        .ranked_endpoints
        .iter()
        .take(15)
        .map(|ep| format!("{:>7.1}  {}  {}", ep.asymmetry, ep.method, ep.url))
        .collect();
    items.push("(keep original target)".to_string());

    let choice = Select::new()
        .with_prompt("Approve a flood target")
        .items(&items)
        .default(0)
        .interact()
        .ok()?;
    if choice == items.len() - 1 {
        None
    } else {
        Some(report.ranked_endpoints[choice].url.clone())
    }
}

pub fn banner() {
    println!("OpenNetBench — single-origin resilience assessment");
    println!("GPLv3 · authorized testing only · all traffic leaves THIS host\n");
}

/// The interactive plan plus the two run options that aren't part of the saved
/// config (they're flags for scripted runs, y/n prompts here).
pub struct InteractivePlan {
    pub cfg: RunConfig,
    pub auto_approve: bool,
    pub stop_on_detect: bool,
}

/// Build a run plan through interactive prompts.
pub fn interactive_flow() -> Result<InteractivePlan> {
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

    // Preset shortcut -------------------------------------------------------
    // Offer the curated combos before the full manual walkthrough. A preset
    // fixes the vector mix, mode, and recon choice; the operator still sets
    // timing and the stop/approval behavior.
    if Confirm::new()
        .with_prompt("Use a preset (curated vector combo for a kind of target)?")
        .default(false)
        .interact()?
    {
        return preset_flow(target, proxy);
    }

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

    // Auto-approve: only meaningful if recon runs and picks a target for you.
    let auto_approve = if run_recon {
        Confirm::new()
            .with_prompt("Auto-approve recon's top-ranked target (skip the pick prompt)?")
            .default(false)
            .interact()?
    } else {
        false
    };

    // Stop-on-detect: off = run the full duration; on = prompt to stop the
    // moment a finding is detected.
    let stop_on_detect = Confirm::new()
        .with_prompt("Stop and ask when a finding is detected? (No = run the full duration)")
        .default(false)
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
    Ok(InteractivePlan {
        cfg,
        auto_approve,
        stop_on_detect,
    })
}

/// Preset shortcut: pick a curated combo, then only prompt for the choices a
/// preset leaves open (timing, stop-on-detect, and recon auto-approve). The
/// preset fixes the vectors, run mode, and whether recon runs; every preset hits
/// at full pressure and can be edited afterward via `--save-config`.
fn preset_flow(target: String, proxy: Option<ProxyConfig>) -> Result<InteractivePlan> {
    use crate::presets;

    let labels: Vec<String> = presets::PRESETS
        .iter()
        .map(|p| {
            let sudo = if p.needs_root { " [sudo]" } else { "" };
            format!("{:<12} {}{}", p.name, p.description, sudo)
        })
        .collect();
    let idx = Select::new()
        .with_prompt("Preset")
        .items(&labels)
        .default(0)
        .interact()?;
    let preset = &presets::PRESETS[idx];

    if preset.needs_root {
        println!("note: '{}' uses raw-socket vectors — run under sudo or they are skipped.", preset.name);
    }

    let duration_s: u64 = Input::new()
        .with_prompt("Duration (seconds, 0 = until stopped)")
        .default(60)
        .interact_text()?;
    let rampup_s: u64 = Input::new()
        .with_prompt("Ramp-up (seconds)")
        .default(10)
        .interact_text()?;

    // Recon-driven presets can auto-approve their top-ranked target.
    let auto_approve = if preset.run_recon {
        Confirm::new()
            .with_prompt("Auto-approve recon's top-ranked target (skip the pick prompt)?")
            .default(false)
            .interact()?
    } else {
        false
    };

    let stop_on_detect = Confirm::new()
        .with_prompt("Stop and ask when a finding is detected? (No = run the full duration)")
        .default(false)
        .interact()?;

    let cfg = presets::build_config(
        preset,
        target,
        proxy,
        Duration::from_secs(duration_s),
        Duration::from_secs(rampup_s),
    );

    print_summary(&cfg);
    Ok(InteractivePlan {
        cfg,
        auto_approve,
        stop_on_detect,
    })
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

pub fn normalize_target(raw: &str) -> Result<String> {
    let candidate = if raw.contains("://") {
        raw.to_string()
    } else {
        // Bare IPs default to http (router/admin UIs are usually plaintext, and
        // L4 vectors just need address:port); hostnames default to https.
        let host_part = raw.split('/').next().unwrap_or(raw);
        let host_only = host_part.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_part);
        let is_ip = host_only.parse::<std::net::IpAddr>().is_ok();
        let scheme = if is_ip { "http" } else { "https" };
        format!("{scheme}://{raw}")
    };
    url::Url::parse(&candidate).with_context(|| format!("invalid target URL: {raw}"))?;
    Ok(candidate)
}

pub fn print_summary(cfg: &RunConfig) {
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
