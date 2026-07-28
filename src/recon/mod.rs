//! Recon engine.
//!
//! Discovers a target's surface (HTML crawl + robots/sitemap/OpenAPI), then
//! hunts for *asymmetry* — endpoints where one cheap request forces expensive
//! server work — by actively probing them: differential cheap-vs-expensive
//! inputs, a small bounded concurrency burst to find the latency knee, and a
//! read-only GraphQL query-cost probe. Output is a ranked list the operator
//! reviews and approves; recon NEVER auto-queues a flood unless the operator
//! opted into `auto_approve_targets`. Human-in-the-loop is the safety line.
//!
//! Active probing sends crafted inputs and a bounded burst, so recon is no
//! longer strictly read-only. It stays behind the same consent gate as a run,
//! GraphQL probing uses only `query` operations (never mutations), and HTML form
//! POSTs are replayed only when they look like search/filter and NOT like an
//! auth/delete/payment action.

mod crawl;
mod discover;
mod fingerprint;
mod param;
mod probe;
pub mod score;

use anyhow::{Context, Result};
use param::{Param, ParamLoc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;
use url::Url;

const MAX_CRAWL_PAGES: usize = 25;
const MAX_CRAWL_DEPTH: usize = 2;
const MAX_MEASURED_ENDPOINTS: usize = 40;
/// How many top-ranked endpoints get the bounded degradation burst.
const DEGRADE_TOP_K: usize = 5;
/// Size of the single degradation burst — small on purpose (a probe, not a flood).
const DEGRADE_CONCURRENCY: usize = 20;
/// Compute delta (ms) above which an endpoint counts as input-compute-sensitive.
const COMPUTE_SIGNIFICANT_MS: f64 = 40.0;
/// Amplification ratio above which an endpoint counts as a bandwidth weapon.
const AMP_SIGNIFICANT: f64 = 50.0;
/// Latency knee above which an endpoint counts as fragile under load.
const KNEE_SIGNIFICANT: f64 = 2.0;
/// Minimum confidence for a compute delta to be trusted as a real weakness.
const MIN_COMPUTE_CONF: f64 = 0.35;
/// GraphQL cost ratio above which the endpoint counts as GraphQL-fragile.
const GQL_SIGNIFICANT: f64 = 2.0;

/// Why an endpoint is a weak point (the dominant signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Weakness {
    /// A crafted input forces disproportionate server compute.
    InputCompute,
    /// A small request draws a huge response (amplification).
    Bandwidth,
    /// Latency knees badly under a little concurrency.
    Degradation,
    /// GraphQL query-cost amplification.
    GraphQL,
    /// No notable asymmetry found.
    Static,
}

/// One discovered endpoint plus everything we learned about it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub url: String,
    pub method: String,
    /// Whether responses carry cache headers (cached = edge absorbs the load).
    pub cacheable: bool,
    /// Server latency at rest for this endpoint (ms).
    pub baseline_ms: f64,
    /// Combined asymmetry score — higher = more fragile / higher leverage.
    pub asymmetry: f64,
    /// Marginal server ms a crafted input forced above baseline (median).
    pub compute_ms: f64,
    /// Confidence in `compute_ms`, 0..1 (sample spread + count).
    pub confidence: f64,
    /// Response bytes out per request byte in.
    pub amplification: f64,
    /// Latency knee under the bounded burst (1.0 = not probed / flat).
    pub degradation: f64,
    /// GraphQL heavy/trivial cost ratio (1.0 if not GraphQL).
    pub graphql_cost: f64,
    /// The dominant weakness class.
    pub weakness: Weakness,
    /// Human-readable explanation of the finding (which param, how much).
    pub note: String,
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
    /// The server serves a non-404 catch-all for unknown paths (SPA fallback);
    /// the exposed-path list was filtered against it.
    pub spa_catchall: bool,
    /// Endpoints ranked by descending asymmetry.
    pub ranked_endpoints: Vec<Endpoint>,
}

/// How a candidate endpoint should be probed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Get,
    PostForm,
}

struct Candidate {
    url: Url,
    kind: Kind,
    params: Vec<Param>,
    /// Acquisition priority — higher-value sources survive truncation.
    priority: u8,
}

fn build_client(proxy: Option<&crate::config::ProxyConfig>) -> Result<Client> {
    let mut b = Client::builder()
        // Authorized testing routinely targets self-signed / internal certs.
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .user_agent("OpenNetBench-recon/0.1")
        .redirect(reqwest::redirect::Policy::limited(3));
    if let Some(p) = proxy {
        let px = reqwest::Proxy::all(&p.url).context("invalid recon proxy URL")?;
        b = b.proxy(px);
    }
    b.build().context("building recon HTTP client")
}

/// Run the full recon suite against `base` and return a ranked report. When
/// `proxy` is set, all recon requests route through it.
pub async fn run_recon(
    base: &str,
    proxy: Option<&crate::config::ProxyConfig>,
    wordlist: Option<&[String]>,
) -> Result<ReconReport> {
    let client = build_client(proxy)?;
    let paths = match wordlist {
        Some(w) => w.to_vec(),
        None => fingerprint::default_wordlist(),
    };
    let fp = fingerprint::fingerprint(&client, base, &paths).await;

    let base_url = match Url::parse(base) {
        Ok(u) => u,
        // Without a parseable base we can only report the fingerprint.
        Err(_) => {
            return Ok(ReconReport {
                server_fingerprint: fp.server,
                missing_security_headers: fp.missing_security_headers,
                exposed_paths: fp.exposed_paths,
                allowed_methods: fp.allowed_methods,
                spa_catchall: fp.spa_catchall,
                ranked_endpoints: Vec::new(),
            });
        }
    };

    let candidates = assemble_candidates(&client, &base_url).await;

    // Probe every candidate for asymmetry.
    let mut endpoints = Vec::new();
    let mut graphql_urls: HashSet<String> = HashSet::new();
    for c in candidates {
        if is_graphql_url(&c.url) {
            graphql_urls.insert(c.url.as_str().to_string());
            continue; // handled by the dedicated GraphQL probe below.
        }
        if let Some(ep) = probe_candidate(&client, &c).await {
            endpoints.push(ep);
        }
    }

    // GraphQL: probe any URL that looks like a GraphQL endpoint (from crawl,
    // discovery, or the sensitive-path scan).
    if fp.exposed_paths.iter().any(|p| p.contains("graphql")) {
        for path in ["/graphql", "/api/graphql", "/query"] {
            if let Ok(u) = base_url.join(path) {
                graphql_urls.insert(u.as_str().to_string());
            }
        }
    }
    for gurl in graphql_urls {
        if let Ok(u) = Url::parse(&gurl) {
            if let Some(ep) = probe_graphql(&client, &u).await {
                endpoints.push(ep);
            }
        }
    }

    // Rank, then spend the bounded degradation burst on the top few.
    endpoints.sort_by(|a, b| b.asymmetry.total_cmp(&a.asymmetry));

    // Control burst on the base URL under the same concurrency captures our own
    // client/pool/scheduling overhead, which we divide out of each candidate's
    // knee so we measure the *server* degrading, not our sender.
    let control_knee = match Url::parse(base) {
        Ok(u) => probe::degradation(&client, &u, DEGRADE_CONCURRENCY).await.knee,
        Err(_) => 1.0,
    };

    for ep in endpoints.iter_mut().take(DEGRADE_TOP_K) {
        if ep.weakness == Weakness::GraphQL {
            continue; // don't burst POST GraphQL — keep active load off mutating-ish paths.
        }
        let Ok(u) = Url::parse(&ep.url) else { continue };
        let d = probe::degradation(&client, &u, DEGRADE_CONCURRENCY).await;
        let normalized = (d.knee / control_knee.max(1.0)).max(1.0);
        ep.degradation = normalized;
        if normalized >= KNEE_SIGNIFICANT {
            ep.note = format!(
                "{}; latency {:.1}× under {} concurrent (client-normalized)",
                ep.note, normalized, DEGRADE_CONCURRENCY
            );
        }
        // Re-classify with the measured degradation, then re-score.
        ep.weakness = classify(&signals_of(ep), normalized);
        ep.asymmetry = score_of(ep);
    }

    // Re-rank after degradation rescoring.
    endpoints.sort_by(|a, b| b.asymmetry.total_cmp(&a.asymmetry));

    Ok(ReconReport {
        server_fingerprint: fp.server,
        missing_security_headers: fp.missing_security_headers,
        exposed_paths: fp.exposed_paths,
        allowed_methods: fp.allowed_methods,
        spa_catchall: fp.spa_catchall,
        ranked_endpoints: endpoints,
    })
}

/// Gather unique candidate endpoints from the base URL, the HTML crawl, and the
/// structured sources (robots/sitemap/OpenAPI).
async fn assemble_candidates(client: &Client, base_url: &Url) -> Vec<Candidate> {
    let crawl = crawl::crawl(client, base_url.as_str(), MAX_CRAWL_PAGES, MAX_CRAWL_DEPTH).await;
    let discovered = discover::discover(client, base_url).await;

    let mut seen: HashSet<(bool, String)> = HashSet::new();
    let mut out: Vec<Candidate> = Vec::new();

    let push = |url: Url, kind: Kind, params: Vec<Param>, priority: u8, out: &mut Vec<Candidate>, seen: &mut HashSet<(bool, String)>| {
        let key = (kind == Kind::PostForm, url.as_str().to_string());
        if seen.insert(key) {
            out.push(Candidate { url, kind, params, priority });
        }
    };

    // Push higher-value sources first so dedup keeps the richer version (e.g. an
    // OpenAPI entry with declared params beats the same URL from a bare crawl).
    push(base_url.clone(), Kind::Get, param::from_url(base_url), 85, &mut out, &mut seen);

    for d in discovered {
        if let Ok(url) = Url::parse(&d.url) {
            let priority = match d.source {
                discover::Source::OpenApi => 100,
                discover::Source::Robots => 80,
                discover::Source::Sitemap => 60,
            };
            push(url, Kind::Get, d.params, priority, &mut out, &mut seen);
        }
    }

    // API endpoints mined from JS bundles — the real surface on a SPA. High
    // priority: they beat static crawl assets for the probe budget.
    for u in crawl.api_urls {
        if let Ok(url) = Url::parse(&u) {
            let params = param::from_url(&url);
            push(url, Kind::Get, params, 78, &mut out, &mut seen);
        }
    }

    for f in crawl.forms {
        let Ok(url) = Url::parse(&f.action) else { continue };
        if f.method == "POST" {
            // Only replay POST forms that look like search/filter and NOT like a
            // state-changing action (auth/delete/payment/upload/etc).
            if looks_searchy(&f.action, &f.fields) && !looks_destructive(&f.action, &f.fields) {
                let params = fields_as(&f.fields, ParamLoc::Form);
                push(url, Kind::PostForm, params, 70, &mut out, &mut seen);
            }
        } else {
            // GET form: its fields plus any query already on the action.
            let mut params = fields_as(&f.fields, ParamLoc::Query);
            merge_params(&mut params, param::from_url(&url));
            push(url, Kind::Get, params, 75, &mut out, &mut seen);
        }
    }

    for u in crawl.urls {
        if let Ok(url) = Url::parse(&u) {
            let params = param::from_url(&url);
            push(url, Kind::Get, params, 40, &mut out, &mut seen);
        }
    }

    // Prioritize before truncating so structured, parameter-rich endpoints are
    // never evicted by arbitrary crawl order. Stable sort keeps insertion order
    // within a priority band.
    out.sort_by_key(|c| std::cmp::Reverse(c.priority));
    out.truncate(MAX_MEASURED_ENDPOINTS);
    out
}

/// Differentially probe one non-GraphQL candidate and build its Endpoint.
async fn probe_candidate(client: &Client, c: &Candidate) -> Option<Endpoint> {
    let diff = match c.kind {
        Kind::Get => probe::differential(client, &c.url, &c.params).await?,
        Kind::PostForm => probe::differential_form(client, &c.url, &c.params).await?,
    };

    let method = match c.kind {
        Kind::Get => "GET",
        Kind::PostForm => "POST",
    };

    let mut ep = Endpoint {
        url: c.url.as_str().to_string(),
        method: method.to_string(),
        cacheable: diff.cacheable,
        baseline_ms: diff.baseline_ms,
        asymmetry: 0.0,
        compute_ms: diff.compute_ms,
        confidence: diff.confidence,
        amplification: diff.amplification,
        degradation: 1.0,
        graphql_cost: 1.0,
        weakness: Weakness::Static,
        note: build_note(&diff, diff.amplification),
    };
    ep.weakness = classify(&signals_of(&ep), 1.0);
    ep.asymmetry = score_of(&ep);
    Some(ep)
}

/// Probe a GraphQL endpoint (read-only query cost) and build its Endpoint.
async fn probe_graphql(client: &Client, url: &Url) -> Option<Endpoint> {
    let g = probe::graphql(client, url).await?;
    let note = format!(
        "GraphQL query cost {:.1}×{}",
        g.cost_ratio,
        if g.introspection { ", introspection enabled" } else { "" }
    );
    let mut ep = Endpoint {
        url: url.as_str().to_string(),
        method: "POST".to_string(),
        cacheable: false,
        baseline_ms: g.baseline_ms,
        asymmetry: 0.0,
        compute_ms: 0.0,
        confidence: 0.5,
        amplification: 1.0,
        degradation: 1.0,
        graphql_cost: g.cost_ratio,
        weakness: Weakness::GraphQL,
        note,
    };
    ep.asymmetry = score_of(&ep);
    Some(ep)
}

/// Build the scoring signals for an endpoint from its stored raw measurements.
fn signals_of(ep: &Endpoint) -> score::Signals {
    score::Signals {
        compute_ms: ep.compute_ms,
        confidence: ep.confidence,
        degradation: ep.degradation,
        amplification: ep.amplification,
        graphql_cost: ep.graphql_cost,
        cacheable: ep.cacheable,
    }
}

fn score_of(ep: &Endpoint) -> f64 {
    score::asymmetry(&signals_of(ep))
}

/// Pick the dominant weakness class. An axis must clear a human-meaningful
/// significance threshold to be eligible (keeping the class consistent with the
/// note); when several are eligible, the one with the largest score
/// *contribution* wins — replacing the old arbitrary `log10(amp)*100` boundary.
/// Compute is additionally gated by confidence so a large-but-untrusted delta
/// isn't labeled fragile. `knee` is the (normalized) degradation factor.
fn classify(sig: &score::Signals, knee: f64) -> Weakness {
    let c = score::contributions(sig);
    let compute_sig = sig.compute_ms >= COMPUTE_SIGNIFICANT_MS && sig.confidence >= MIN_COMPUTE_CONF;
    let amp_sig = sig.amplification >= AMP_SIGNIFICANT;
    let gql_sig = sig.graphql_cost >= GQL_SIGNIFICANT;

    if knee >= KNEE_SIGNIFICANT && !compute_sig && !amp_sig && !gql_sig {
        return Weakness::Degradation;
    }

    // Among significant axes, the largest contribution wins.
    let mut best = (Weakness::Static, 0.0_f64);
    if gql_sig && c.graphql > best.1 {
        best = (Weakness::GraphQL, c.graphql);
    }
    if compute_sig && c.compute > best.1 {
        best = (Weakness::InputCompute, c.compute);
    }
    if amp_sig && c.bandwidth > best.1 {
        best = (Weakness::Bandwidth, c.bandwidth);
    }
    best.0
}

fn build_note(diff: &probe::Diff, amplification: f64) -> String {
    let mut parts = Vec::new();
    if diff.compute_ms >= COMPUTE_SIGNIFICANT_MS {
        let p = diff.worst_param.as_deref().unwrap_or("input");
        parts.push(format!(
            "{p} → {:.1}× latency (+{:.0}ms)",
            diff.worst_ratio, diff.compute_ms
        ));
    }
    if amplification >= AMP_SIGNIFICANT {
        parts.push(format!(
            "{:.0}× amplification ({} body)",
            amplification,
            human_bytes(diff.body_bytes)
        ));
    }
    if diff.noncomparable {
        // An expensive input took a different code path — usually a WAF block or
        // input validation. Worth surfacing even when no compute delta landed.
        parts.push("expensive input rejected (WAF/validation?)".to_string());
    }
    if parts.is_empty() {
        "no notable asymmetry".to_string()
    } else {
        parts.join(", ")
    }
}

fn human_bytes(n: usize) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n}B")
    } else {
        format!("{v:.1}{}", UNITS[i])
    }
}

fn is_graphql_url(u: &Url) -> bool {
    u.path().to_ascii_lowercase().contains("graphql")
}

fn fields_as(fields: &[String], loc: ParamLoc) -> Vec<Param> {
    fields
        .iter()
        .filter(|n| !n.is_empty())
        .map(|n| Param { name: n.clone(), loc })
        .collect()
}

/// Append params from `extra` that aren't already present by name.
fn merge_params(into: &mut Vec<Param>, extra: Vec<Param>) {
    for p in extra {
        if !into.iter().any(|q| q.name == p.name) {
            into.push(p);
        }
    }
}

const DESTRUCTIVE_HINTS: &[&str] = &[
    // Auth / account
    "login", "signin", "sign-in", "log-in", "register", "signup", "sign-up",
    "logout", "password", "passwd", "auth", "token", "otp", "confirm", "verify",
    "reset", "activate", "deactivate",
    // State-changing / financial
    "delete", "remove", "destroy", "pay", "payment", "checkout", "purchase",
    "order", "credit", "card", "transfer", "withdraw", "cancel", "refund",
    "upload", "book", "reserve", "enroll", "rsvp",
    // Communication / notification side effects (send mail, tickets, posts)
    "subscribe", "unsubscribe", "contact", "feedback", "notify", "invite",
    "message", "comment", "ticket", "mail", "email", "send", "share", "publish",
    "export", "generate",
];
const SEARCHY_HINTS: &[&str] = &[
    "search", "filter", "query", "find", "browse", "list", "q", "sort",
];

fn any_hit(action: &str, fields: &[String], needles: &[&str]) -> bool {
    let a = action.to_ascii_lowercase();
    needles.iter().any(|n| {
        a.contains(n) || fields.iter().any(|f| f.to_ascii_lowercase().contains(n))
    })
}

fn looks_destructive(action: &str, fields: &[String]) -> bool {
    any_hit(action, fields, DESTRUCTIVE_HINTS)
}
fn looks_searchy(action: &str, fields: &[String]) -> bool {
    any_hit(action, fields, SEARCHY_HINTS)
}

/// Cacheability heuristic shared with the probe module.
pub(super) fn is_cacheable(headers: &reqwest::header::HeaderMap) -> bool {
    // Strongest signal: an edge/CDN telling us this response was served from
    // cache. These override cache-control (a HIT is a HIT regardless).
    let hit = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_ascii_lowercase().contains("hit"))
            .unwrap_or(false)
    };
    if hit("x-cache") || hit("cf-cache-status") || hit("x-cache-status") {
        return true;
    }
    if let Some(cc) = headers.get("cache-control").and_then(|v| v.to_str().ok()) {
        let cc = cc.to_ascii_lowercase();
        // `private` can still carry an Age header on a shared cache, so honor an
        // explicit no-store/no-cache/private as authoritative "not shared".
        if cc.contains("no-store") || cc.contains("no-cache") || cc.contains("private") {
            return false;
        }
        if cc.contains("max-age") || cc.contains("public") {
            return true;
        }
    }
    // A bare Age header means some shared cache is in front of this response.
    headers.contains_key("age")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(compute_ms: f64, confidence: f64, amplification: f64, graphql_cost: f64) -> score::Signals {
        score::Signals {
            compute_ms,
            confidence,
            degradation: 1.0,
            amplification,
            graphql_cost,
            cacheable: false,
        }
    }

    #[test]
    fn classify_prefers_the_dominant_axis() {
        assert_eq!(classify(&sig(0.0, 0.9, 1.0, 1.0), 1.0), Weakness::Static);
        assert_eq!(classify(&sig(500.0, 0.9, 1.0, 1.0), 1.0), Weakness::InputCompute);
        assert_eq!(classify(&sig(0.0, 0.9, 10_000.0, 1.0), 1.0), Weakness::Bandwidth);
        assert_eq!(classify(&sig(0.0, 0.9, 1.0, 1.0), 4.0), Weakness::Degradation);
        // A large but low-confidence compute delta is not trusted as fragile.
        assert_eq!(classify(&sig(500.0, 0.1, 1.0, 1.0), 1.0), Weakness::Static);
    }

    #[test]
    fn destructive_forms_are_rejected_searchy_ones_pass() {
        assert!(looks_destructive("/account/delete", &[]));
        assert!(looks_destructive("/x", &["password".to_string()]));
        assert!(looks_destructive("/newsletter", &["email".to_string()])); // side-effect keyword
        assert!(looks_searchy("/products/search", &[]));
        assert!(!looks_destructive("/products/search", &["q".to_string()]));
        assert!(!looks_searchy("/lookup", &[])); // 'lookup' dropped from searchy
    }

    #[test]
    fn human_bytes_scales() {
        assert_eq!(human_bytes(512), "512B");
        assert_eq!(human_bytes(2048), "2.0KB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0MB");
    }

    // End-to-end: a minimal HTTP server with one input-sensitive endpoint
    // (latency scales with the query length) and one static cached page. Recon
    // should discover both and rank the asymmetric one first.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_test_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let line = req.lines().next().unwrap_or("");
                    let path = line.split_whitespace().nth(1).unwrap_or("/");

                    let (body, extra): (String, &str) = if path.starts_with("/slow") {
                        // Latency scales with the raw query length → the expensive
                        // (long) value forces far more server time than the cheap one.
                        let qlen = path.split('?').nth(1).map(|q| q.len()).unwrap_or(0);
                        let ms = (qlen as u64).min(400);
                        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                        ("ok".to_string(), "")
                    } else if path == "/static" {
                        ("cached".to_string(), "Cache-Control: max-age=600\r\n")
                    } else if path.starts_with("/waf") {
                        // Cheap query → 200; long (expensive) query → 403, and
                        // slow, mimicking a WAF inspecting a big payload. The
                        // comparability gate must NOT read this as compute.
                        let qlen = path.split('?').nth(1).map(|q| q.len()).unwrap_or(0);
                        if qlen > 50 {
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            let r = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
                            let _ = sock.write_all(r.as_bytes()).await;
                            return;
                        }
                        ("ok".to_string(), "")
                    } else if path.starts_with("/combo") {
                        // Fast unless BOTH params carry a long value — a pathological
                        // plan that only the interaction pass can surface.
                        let q = path.split('?').nth(1).unwrap_or("");
                        let long = q
                            .split('&')
                            .filter(|kv| kv.split('=').nth(1).map(|v| v.len() > 50).unwrap_or(false))
                            .count();
                        if long >= 2 {
                            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                        }
                        ("ok".to_string(), "")
                    } else if path == "/" {
                        (
                            "<a href=\"/slow?q=a\">s</a><a href=\"/static\">c</a><a href=\"/waf?q=a\">w</a><a href=\"/combo?search=a&filter=a\">x</a>".to_string(),
                            "Content-Type: text/html\r\n",
                        )
                    } else {
                        let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                        let _ = sock.write_all(resp.as_bytes()).await;
                        return;
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{}\r\n{}",
                        body.len(),
                        extra,
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn recon_ranks_input_sensitive_endpoint_first() {
        let port = spawn_test_server().await;
        let base = format!("http://127.0.0.1:{port}/");
        let report = run_recon(&base, None, None).await.unwrap();

        let top = report
            .ranked_endpoints
            .first()
            .expect("recon found no endpoints");
        assert!(
            top.url.contains("/slow"),
            "expected the input-sensitive endpoint on top, got {} ({})",
            top.url,
            top.note
        );
        assert_eq!(top.weakness, Weakness::InputCompute);
        assert!(top.compute_ms >= COMPUTE_SIGNIFICANT_MS);
        // Multi-sampling should yield real confidence in a deterministic signal.
        assert!(top.confidence > 0.5, "confidence too low: {}", top.confidence);

        // The static cached page must be present but out-ranked.
        let stat = report
            .ranked_endpoints
            .iter()
            .find(|e| e.url.contains("/static"))
            .expect("static page not discovered");
        assert!(top.asymmetry > stat.asymmetry);

        // The WAF-style endpoint (200→403 on the expensive input) must be
        // rejected by the comparability gate, not read as compute.
        let waf = report
            .ranked_endpoints
            .iter()
            .find(|e| e.url.contains("/waf"))
            .expect("waf endpoint not discovered");
        assert_eq!(waf.compute_ms, 0.0, "WAF status flip read as compute: {}", waf.note);
        assert_ne!(waf.weakness, Weakness::InputCompute);
        assert!(waf.note.contains("rejected"), "note should flag rejection: {}", waf.note);

        // The interaction endpoint (slow only when BOTH params are pushed) must
        // be caught by the 2-param pass, not by either single parameter.
        let combo = report
            .ranked_endpoints
            .iter()
            .find(|e| e.url.contains("/combo"))
            .expect("combo endpoint not discovered");
        assert!(
            combo.compute_ms >= COMPUTE_SIGNIFICANT_MS,
            "interaction not detected: {} ({}ms)",
            combo.note,
            combo.compute_ms
        );
        assert!(
            combo.note.contains('+'),
            "note should name the interacting pair: {}",
            combo.note
        );
    }

    // A SPA that serves index.html for every unknown path, with its API hidden
    // in a JS bundle — the exact shape that defeated recon on Juice Shop.
    async fn spawn_spa_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            const INDEX: &str = "<!doctype html><script src=\"/app.js\"></script>";
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .unwrap_or("")
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/");
                    let (ct, body): (&str, String) = if path == "/app.js" {
                        // The bundle references the real API endpoint.
                        ("application/javascript", "x=fetch(\"/rest/products/search?q=\"+q);".to_string())
                    } else if path.starts_with("/rest/products/search") {
                        let qlen = path.split("q=").nth(1).map(|q| q.len()).unwrap_or(0);
                        if qlen > 50 {
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        }
                        ("application/json", "{\"data\":[]}".to_string())
                    } else {
                        // "/" and every unknown path → the SPA catch-all.
                        ("text/html", INDEX.to_string())
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn recon_handles_spa_catchall_and_mines_js_endpoints() {
        let port = spawn_spa_server().await;
        let base = format!("http://127.0.0.1:{port}/");
        let report = run_recon(&base, None, None).await.unwrap();

        // The catch-all is detected and the exposure scan filtered against it —
        // no false-positive flood of "exposed" paths.
        assert!(report.spa_catchall, "SPA catch-all not detected");
        assert!(
            report.exposed_paths.is_empty(),
            "catch-all not filtered, false positives: {:?}",
            report.exposed_paths
        );

        // The API endpoint mined from the JS bundle is discovered, probed, and —
        // being input-sensitive — ranked above the static SPA shell.
        let top = report.ranked_endpoints.first().expect("no endpoints found");
        assert!(
            top.url.contains("/rest/products/search"),
            "JS-mined API not ranked top: {} ({})",
            top.url,
            top.note
        );
        assert_eq!(top.weakness, Weakness::InputCompute);
        assert!(top.compute_ms >= COMPUTE_SIGNIFICANT_MS);
    }
}
