//! Recon engine.
//!
//! Crawls the target, fingerprints the server, and scores endpoints by
//! *asymmetry* — how much a single request costs the server vs. the client.
//! Output is a ranked list the operator reviews and approves. Recon NEVER
//! auto-queues a flood unless the operator opted into `auto_approve_targets`;
//! human-in-the-loop is the default safety and credibility line.

mod crawl;
mod fingerprint;
pub mod score;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, Instant};

const MAX_CRAWL_PAGES: usize = 25;
const MAX_CRAWL_DEPTH: usize = 2;
const MAX_MEASURED_ENDPOINTS: usize = 25;
const TIMING_SAMPLES: usize = 3;

/// One discovered endpoint plus everything we learned about it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub url: String,
    pub method: String,
    /// Whether responses carry cache headers (uncached = higher flood value).
    pub cacheable: bool,
    /// Baseline server-side timing, averaged over samples (ms).
    pub baseline_ms: f64,
    /// Asymmetry score — see `score` module. Higher = more fragile.
    pub asymmetry: f64,
}

/// The full recon report presented to the operator for target approval.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReconReport {
    pub server_fingerprint: Option<String>,
    pub missing_security_headers: Vec<String>,
    /// Sensitive paths that responded (.env, actuator, graphql, …).
    pub exposed_paths: Vec<String>,
    /// HTTP methods the server accepted (TRACE, DELETE, CONNECT, …).
    pub allowed_methods: Vec<String>,
    /// Endpoints ranked by descending asymmetry.
    pub ranked_endpoints: Vec<Endpoint>,
}

fn build_client() -> Result<Client> {
    Client::builder()
        // Authorized testing routinely targets self-signed / internal certs.
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .user_agent("OpenNetBench-recon/0.1")
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .context("building recon HTTP client")
}

/// Run the full recon suite against `base` and return a ranked report.
pub async fn run_recon(base: &str) -> Result<ReconReport> {
    let client = build_client()?;

    let fp = fingerprint::fingerprint(&client, base).await;
    let crawl = crawl::crawl(&client, base, MAX_CRAWL_PAGES, MAX_CRAWL_DEPTH).await;

    // Assemble unique candidate endpoints: base + crawled links + form actions.
    let mut seen: HashSet<String> = HashSet::new();
    let mut candidates: Vec<(String, String, bool)> = Vec::new(); // url, method, dynamic_hint
    let push = |url: String, method: String, dynamic: bool, set: &mut HashSet<String>, out: &mut Vec<(String, String, bool)>| {
        if set.insert(url.clone()) {
            out.push((url, method, dynamic));
        }
    };
    push(base.to_string(), "GET".into(), false, &mut seen, &mut candidates);
    for u in crawl.urls {
        push(u, "GET".into(), false, &mut seen, &mut candidates);
    }
    for f in crawl.forms {
        let dynamic = f.method == "POST";
        push(f.action, f.method, dynamic, &mut seen, &mut candidates);
    }
    candidates.truncate(MAX_MEASURED_ENDPOINTS);

    // Measure each candidate and score its asymmetry.
    let mut endpoints = Vec::new();
    for (url, method, dynamic) in candidates {
        if let Some(ep) = measure_endpoint(&client, &url, &method, dynamic).await {
            endpoints.push(ep);
        }
    }
    endpoints.sort_by(|a, b| b.asymmetry.total_cmp(&a.asymmetry));

    Ok(ReconReport {
        server_fingerprint: fp.server,
        missing_security_headers: fp.missing_security_headers,
        exposed_paths: fp.exposed_paths,
        allowed_methods: fp.allowed_methods,
        ranked_endpoints: endpoints,
    })
}

/// Time an endpoint (averaged TTFB over samples) and score it.
async fn measure_endpoint(
    client: &Client,
    url: &str,
    method: &str,
    dynamic_hint: bool,
) -> Option<Endpoint> {
    let mut total_ms = 0.0;
    let mut n = 0u32;
    let mut cacheable = false;
    for i in 0..TIMING_SAMPLES {
        if let Some((ms, cache)) = timed_ttfb(client, url).await {
            total_ms += ms;
            n += 1;
            if i == 0 {
                cacheable = cache;
            }
        }
    }
    if n == 0 {
        return None;
    }
    let baseline_ms = total_ms / n as f64;
    let dynamic = dynamic_hint || url.contains('?');
    let request_bytes = url.len() + 128;
    let asymmetry = score::asymmetry(baseline_ms, request_bytes, cacheable, dynamic);
    Some(Endpoint {
        url: url.to_string(),
        method: method.to_string(),
        cacheable,
        baseline_ms,
        asymmetry,
    })
}

/// A single timed GET: returns (time-to-headers ms, cacheable).
async fn timed_ttfb(client: &Client, url: &str) -> Option<(f64, bool)> {
    let t0 = Instant::now();
    let resp = client.get(url).send().await.ok()?;
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    Some((ms, is_cacheable(resp.headers())))
}

fn is_cacheable(headers: &reqwest::header::HeaderMap) -> bool {
    if headers.contains_key("age") {
        return true;
    }
    if let Some(cc) = headers.get("cache-control").and_then(|v| v.to_str().ok()) {
        let cc = cc.to_ascii_lowercase();
        if cc.contains("no-store") || cc.contains("no-cache") || cc.contains("private") {
            return false;
        }
        if cc.contains("max-age") || cc.contains("public") {
            return true;
        }
    }
    false
}
