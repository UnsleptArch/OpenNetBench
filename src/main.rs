//! OpenNetBench — single-origin adversarial-load / resilience assessment tool.
//!
//! Safety model (enforced by architecture, not just policy): all traffic
//! originates from this host, there is no IP spoofing, no amplification, and no
//! command-and-control. A mandatory consent gate blocks every run.

// Scaffold stage: several types/functions are forward-declared for modules that
// land in later increments (engine workers, web server, DB, CVE correlation).
#![allow(dead_code)]

mod auth;
mod classify;
mod cli;
mod config;
mod db;
mod engine;
mod logging;
mod metrics;
mod recon;
mod web;

use anyhow::Result;
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

    if args.ui_only {
        info!("serving dashboard only (no assessment run)");
        return web::serve(web::DEFAULT_BIND).await;
    }

    // Legal notice + mandatory consent gate — always, before anything else.
    println!("{}\n", auth::LEGAL_NOTICE);
    auth::require_consent()?;

    let cfg = match &args.config {
        Some(path) => cli::load_config(path)?,
        None => cli::interactive_flow()?,
    };

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
    engine::run(&cfg).await?;

    info!("run complete");
    Ok(())
}
