//! OpenNetBench — single-origin adversarial-load / resilience assessment tool.
//!
//! Safety model (enforced by architecture, not just policy): all traffic
//! originates from this host (an optional SOCKS5 proxy routes L7/TCP traffic;
//! raw L4/UDP vectors always leave from this host), there is no amplification
//! and no command-and-control. A consent gate — typed, or asserted explicitly
//! with --i-am-authorized for unattended runs — precedes every run.

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

    /// Auto-engine: probe --target, characterize it, recommend a preset,
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

    /// Target URL or IP (bare IPs get http:// assumed for presets).
    #[arg(long)]
    target: Option<String>,

    /// Run duration in seconds (preset mode). 0 = until stopped.
    #[arg(long, default_value_t = 60)]
    duration: u64,

    /// Ramp-up in seconds (preset mode).
    #[arg(long, default_value_t = 10)]
    rampup: u64,

    /// List available presets, then exit.
    #[arg(long)]
    list_presets: bool,

    /// Write the resolved plan to a JSON file and exit (no consent, no run).
    /// Combine with --preset to generate an editable config.
    #[arg(long, value_name = "FILE")]
    save_config: Option<PathBuf>,

    /// Serve the dashboard UI over existing run history and exit (no run).
    #[arg(long)]
    ui_only: bool,

    /// Directory for run log files. Default: $XDG_STATE_HOME/opennetbench
    /// (else ~/.local/state/opennetbench). If it can't be written, the run
    /// still proceeds with terminal-only logging.
    #[arg(long, value_name = "DIR")]
    log_dir: Option<PathBuf>,

    /// Run recon against this URL, print the ranked report, and exit. Sends only
    /// recon's own bounded probes — never a flood. Still requires consent, since
    /// active recon sends crafted requests and a small burst to the target.
    #[arg(long, value_name = "URL")]
    recon: Option<String>,

    /// Wordlist file for the path-exposure scan (one path per line, `#` comments).
    /// If omitted, recon prompts and offers a built-in default.
    #[arg(long, value_name = "FILE")]
    wordlist: Option<PathBuf>,

    /// Proxy URL for L7/TCP traffic (e.g. socks5://127.0.0.1:9050). Raw L4/UDP
    /// vectors always send from this host — a proxy does not anonymize them.
    #[arg(long, value_name = "URL")]
    proxy: Option<String>,

    /// Run mode for a flag-driven run: adaptive (self-throttling, default) or dumb.
    #[arg(long, value_name = "MODE")]
    mode: Option<String>,

    /// Comma-separated vector slugs for a fully flag-driven run (see
    /// --list-vectors). Requires --target; builds the plan without any prompts.
    #[arg(long, value_name = "SLUGS")]
    vectors: Option<String>,

    /// Enable recon in a flag-driven (--vectors) run.
    #[arg(long)]
    run_recon: bool,

    /// List the available vector slugs, then exit.
    #[arg(long)]
    list_vectors: bool,

    /// Assert authorization non-interactively: skip the typed consent phrase and
    /// the final confirmation so the tool can run unattended/scripted. By passing
    /// it you affirm you are authorized to test the target.
    #[arg(long)]
    i_am_authorized: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let run_id = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let (log_path, _guard) = logging::init(&run_id, args.log_dir.clone());

    cli::banner();

    if args.list_presets {
        print_presets();
        return Ok(());
    }

    if args.list_vectors {
        print_vectors();
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

    // Legal notice + consent gate. --i-am-authorized asserts authorization
    // non-interactively (for unattended/scripted runs); otherwise a human types
    // the phrase. Either way the legal notice is shown.
    println!("{}\n", auth::LEGAL_NOTICE);
    if args.i_am_authorized {
        info!("authorization asserted via --i-am-authorized (non-interactive run)");
    } else {
        auth::require_consent()?;
    }

    // --recon: recon-only. Run the recon suite against the URL, print the ranked
    // report, and exit. No flood is scheduled — only recon's bounded probes.
    if let Some(target) = &args.recon {
        let wordlist = cli::choose_wordlist(args.wordlist.as_ref(), !args.i_am_authorized)?;
        println!("Recon-only against {target} — no flood will be sent.\n");
        match recon::run_recon(target, flag_proxy(&args).as_ref(), wordlist.as_deref()).await {
            Ok(report) => cli::present_recon(&report),
            Err(e) => return Err(anyhow!("recon failed: {e}")),
        }
        return Ok(());
    }

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
            target,
            flag_proxy(&args),
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
            // Fully flag-driven run: --vectors builds a plan with no prompts.
            (None, None) if args.vectors.is_some() => {
                let cfg = build_flag_config(&args)?;
                cli::print_summary(&cfg);
                cfg
            }
            // Non-interactive with no plan source is an error, not a hang.
            (None, None) if args.i_am_authorized => {
                return Err(anyhow!(
                    "--i-am-authorized needs a plan: use --preset, --config, --auto, or --vectors"
                ));
            }
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
        let wordlist = cli::choose_wordlist(args.wordlist.as_ref(), !args.i_am_authorized)?;
        info!(target = %cfg.target, "recon: starting");
        match recon::run_recon(&cfg.target, cfg.proxy.as_ref(), wordlist.as_deref()).await {
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

    // Final go/no-go before generating any traffic. --i-am-authorized skips it
    // (the assertion already covered authorization for this unattended run).
    if !args.i_am_authorized
        && !dialoguer::Confirm::new()
            .with_prompt("Execute this plan now?")
            .default(false)
            .interact()?
    {
        info!("operator declined execution at final gate — exiting");
        println!("Aborted. No traffic sent.");
        return Ok(());
    }

    let log_display = log_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "terminal-only".to_string());
    info!(run_id, log = %log_display, "run authorized — handing to engine");
    engine::run(&cfg, ctx).await?;

    info!("run complete");
    Ok(())
}

/// Resolve --preset/--target into a runnable config.
fn build_preset_config(args: &Args, name: &str) -> Result<config::RunConfig> {
    let preset = presets::find(name)
        .ok_or_else(|| anyhow!("unknown preset '{name}' — see --list-presets"))?;
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
        target,
        flag_proxy(args),
        std::time::Duration::from_secs(args.duration),
        std::time::Duration::from_secs(args.rampup),
    ))
}

/// Build the ProxyConfig from --proxy, if given.
fn flag_proxy(args: &Args) -> Option<config::ProxyConfig> {
    args.proxy
        .as_ref()
        .map(|url| config::ProxyConfig { url: url.clone() })
}

/// Build a fully flag-driven run config from --vectors and friends (no prompts).
fn build_flag_config(args: &Args) -> Result<config::RunConfig> {
    let target = args
        .target
        .as_deref()
        .ok_or_else(|| anyhow!("--vectors requires --target"))?;
    let target = cli::normalize_target(target)?;

    let mut vectors = Vec::new();
    for slug in args
        .vectors
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let v = config::Vector::from_slug(slug)
            .ok_or_else(|| anyhow!("unknown vector '{slug}' — see --list-vectors"))?;
        vectors.push(config::VectorPlan {
            vector: v,
            tuning: config::VectorTuning::defaults_for(v),
        });
    }
    anyhow::ensure!(!vectors.is_empty(), "--vectors needs at least one vector slug");

    let mode = match args.mode.as_deref() {
        None | Some("adaptive") => config::RunMode::Adaptive,
        Some("dumb") => config::RunMode::Dumb,
        Some(other) => return Err(anyhow!("unknown mode '{other}' — use adaptive or dumb")),
    };

    if vectors.iter().any(|p| p.vector.needs_root()) && !is_root() {
        eprintln!("note: selected vectors include raw-socket vectors — run with sudo.");
    }

    Ok(config::RunConfig {
        target,
        proxy: flag_proxy(args),
        mode,
        run_recon: args.run_recon,
        vectors,
        duration: std::time::Duration::from_secs(args.duration),
        rampup: std::time::Duration::from_secs(args.rampup),
    })
}

/// Print the available vector slugs (for --vectors), then return.
fn print_vectors() {
    println!("Vectors (use --vectors slug,slug,... with --target):\n");
    for v in config::Vector::ALL {
        let root = if v.needs_root() { "  [root]" } else { "" };
        println!(
            "  {:<16} [{}] {}{}",
            v.slug(),
            v.layer(),
            v.description(),
            root
        );
    }
    println!("\nExample:\n  ./opennetbench --target https://example.com \\");
    println!("    --vectors http_flood,slowloris --duration 60 --i-am-authorized");
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
    println!("Presets (use --preset <name> --target <url|ip>):\n");
    for p in presets::PRESETS {
        let sudo = if p.needs_root { "  [sudo]" } else { "" };
        println!("  {:<12} {}{}", p.name, p.description, sudo);
    }
    println!(
        "\nAll presets hit at full pressure ({} workers/vector). Dump with --save-config",
        presets::PRESET_CONCURRENCY
    );
    println!("and edit the JSON to dial it back.\n");
    println!("Example:");
    println!("  sudo ./opennetbench --preset router --target 192.168.1.254 --duration 40");
    println!("  ./opennetbench --preset web --target https://example.com --save-config web.json");
}
