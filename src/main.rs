//! OpenNetBench — single-origin adversarial-load / resilience assessment tool.
//!
//! Safety model (enforced by architecture, not just policy): all traffic
//! originates from this host, there is no IP spoofing, no amplification, and no
//! command-and-control. A mandatory consent gate blocks every run.

// Scaffold stage: several types/functions are forward-declared for modules that
// land in later increments (engine workers, web server, DB, CVE correlation).
#![allow(dead_code)]

mod auth;
mod auto;
mod classify;
mod cli;
mod config;
mod db;
mod engine;
mod logging;
mod metrics;
mod presets;
mod recon;
mod web;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use clap::Parser;
use config::Tier;
use std::path::PathBuf;
use tracing::info;

/// CLI entry. The tool is primarily interactive; flags exist for repeatable
/// runs and non-target operations. The consent gate always applies.
#[derive(Parser, Debug)]
#[command(name = "opennetbench", version, about)]
struct Args {
    /// Load the run plan from a JSON file instead of the interactive prompts.
    /// Consent is still required; only the plan questions are skipped.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Auto-engine: probe --target, characterize it, recommend a preset + tier,
    /// then run it (after the normal consent + confirm).
    #[arg(long)]
    auto: bool,

    /// Let recon auto-select the highest-asymmetry target (no approval prompt).
    #[arg(long)]
    auto_approve: bool,

    /// Watch the target during the run; when a finding is detected (target down
    /// or degrading), pause and ask whether to stop. Off by default: the run
    /// always goes the full duration unless you enable this.
    #[arg(long)]
    stop_on_detect: bool,

    /// Use a built-in preset combo (see --list-presets). Requires --target.
    #[arg(long, value_name = "NAME")]
    preset: Option<String>,

    /// Aggressiveness tier for a preset: recon|light|moderate|aggressive|brutal.
    #[arg(long, default_value = "moderate")]
    tier: String,

    /// Target URL or IP (bare IPs get http:// assumed for presets).
    #[arg(long)]
    target: Option<String>,

    /// Run duration in seconds (preset mode). 0 = until stopped.
    #[arg(long, default_value_t = 60)]
    duration: u64,

    /// Ramp-up in seconds (preset mode).
    #[arg(long, default_value_t = 10)]
    rampup: u64,

    /// List available presets and tiers, then exit.
    #[arg(long)]
    list_presets: bool,

    /// Write the resolved plan to a JSON file and exit (no consent, no run).
    /// Combine with --preset to generate an editable config.
    #[arg(long, value_name = "FILE")]
    save_config: Option<PathBuf>,

    /// Serve the dashboard UI over existing run history and exit (no run).
    #[arg(long)]
    ui_only: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let run_id = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let (log_path, _guard) = logging::init(&run_id)?;

    cli::banner();

    if args.list_presets {
        print_presets();
        return Ok(());
    }

    if args.ui_only {
        info!("serving dashboard only (no assessment run)");
        return web::serve(web::DEFAULT_BIND).await;
    }

    // Build the plan from a preset if requested (before consent, so --save-config
    // works as a non-running generator).
    let preset_cfg = match &args.preset {
        Some(name) => Some(build_preset_config(&args, name)?),
        None => None,
    };

    // --save-config: dump the resolved plan (preset or loaded config) and exit.
    if let Some(path) = &args.save_config {
        let cfg = match (preset_cfg, &args.config) {
            (Some(cfg), _) => cfg,
            (None, Some(cfgpath)) => cli::load_config(cfgpath)?,
            (None, None) => return Err(anyhow!("--save-config needs --preset or --config")),
        };
        std::fs::write(path, serde_json::to_string_pretty(&cfg)?)
            .with_context(|| format!("writing {}", path.display()))?;
        println!("Wrote plan to {} — edit and run with --config.", path.display());
        return Ok(());
    }

    // Legal notice + mandatory consent gate — always, before anything else.
    println!("{}\n", auth::LEGAL_NOTICE);
    auth::require_consent()?;

    // Base from flags; the interactive flow may override with y/n answers.
    let mut auto_approve = args.auto_approve;
    let mut stop_on_detect = args.stop_on_detect;

    let mut cfg = if args.auto {
        // Probe the target (traffic), so this happens after consent.
        let target = args
            .target
            .as_deref()
            .ok_or_else(|| anyhow!("--auto requires --target"))?;
        let target = cli::normalize_target(target)?;
        info!(target = %target, "auto-engine: probing target");
        let c = auto::characterize(&target).await;
        auto::print_characterization(&c);
        let rec = auto::recommend(&c, is_root());
        auto::print_recommendation(&rec);
        let preset = presets::find(rec.preset).expect("recommended preset must exist");
        let cfg = presets::build_config(
            preset,
            rec.tier,
            target,
            None,
            std::time::Duration::from_secs(args.duration),
            std::time::Duration::from_secs(args.rampup),
        );
        cli::print_summary(&cfg);
        cfg
    } else {
        match (preset_cfg, &args.config) {
            (Some(cfg), _) => {
                cli::print_summary(&cfg);
                cfg
            }
            (None, Some(path)) => cli::load_config(path)?,
            (None, None) => {
                let plan = cli::interactive_flow()?;
                auto_approve = plan.auto_approve;
                stop_on_detect = plan.stop_on_detect;
                plan.cfg
            }
        }
    };

    // Optional recon: crawl + rank endpoints, then (unless auto-approved) let the
    // operator pick which becomes the flood target. Recon also seeds the
    // classifier's baseline latency and WAF fingerprint.
    let mut ctx = classify::RunContext {
        stop_on_detect,
        ..Default::default()
    };
    if cfg.run_recon {
        info!(target = %cfg.target, "recon: starting");
        match recon::run_recon(&cfg.target).await {
            Ok(report) => {
                cli::present_recon(&report);
                ctx.waf_vendor = classify::detect_waf(report.server_fingerprint.as_deref());
                let chosen = match cli::select_target(&report, auto_approve) {
                    Some(url) => {
                        info!(target = %url, auto = auto_approve, "recon: target selected");
                        cfg.target = url.clone();
                        url
                    }
                    None => {
                        info!("recon: keeping original target");
                        cfg.target.clone()
                    }
                };
                ctx.baseline_ms = report
                    .ranked_endpoints
                    .iter()
                    .find(|e| e.url == chosen)
                    .map(|e| e.baseline_ms);
            }
            Err(e) => tracing::warn!(error = %e, "recon failed — continuing with original target"),
        }
    }

    // Final go/no-go before generating any traffic.
    if !dialoguer::Confirm::new()
        .with_prompt("Execute this plan now?")
        .default(false)
        .interact()?
    {
        info!("operator declined execution at final gate — exiting");
        println!("Aborted. No traffic sent.");
        return Ok(());
    }

    info!(run_id, log = %log_path.display(), "run authorized — handing to engine");
    engine::run(&cfg, ctx).await?;

    info!("run complete");
    Ok(())
}

/// Resolve --preset/--tier/--target into a runnable config.
fn build_preset_config(args: &Args, name: &str) -> Result<config::RunConfig> {
    let preset = presets::find(name)
        .ok_or_else(|| anyhow!("unknown preset '{name}' — see --list-presets"))?;
    let tier = Tier::parse(&args.tier)
        .ok_or_else(|| anyhow!("unknown tier '{}' — see --list-presets", args.tier))?;
    let target = args
        .target
        .as_deref()
        .ok_or_else(|| anyhow!("--preset requires --target"))?;
    let target = cli::normalize_target(target)?;
    if preset.needs_root {
        eprintln!("note: preset '{}' uses raw-socket vectors — run with sudo.", preset.name);
    }
    Ok(presets::build_config(
        preset,
        tier,
        target,
        None,
        std::time::Duration::from_secs(args.duration),
        std::time::Duration::from_secs(args.rampup),
    ))
}

fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(unix)]
extern "C" {
    fn geteuid() -> u32;
}

fn print_presets() {
    println!("Presets (use --preset <name> --target <url|ip> [--tier <tier>]):\n");
    for p in presets::PRESETS {
        let sudo = if p.needs_root { "  [sudo]" } else { "" };
        println!("  {:<12} {}{}", p.name, p.description, sudo);
    }
    println!("\nTiers (--tier):\n");
    for t in Tier::ALL {
        println!("  {:<12} {}", t.slug(), t.description());
    }
    println!("\nExample:");
    println!("  sudo ./opennetbench --preset router --tier aggressive --target 192.168.1.254 --duration 40");
    println!("  ./opennetbench --preset web --tier moderate --target https://example.com --save-config web.json");
}
