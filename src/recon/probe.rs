//! Active asymmetry probes.
//!
//! - `differential`: send an endpoint a cheap vs. an expensive value for each
//!   parameter and measure the extra server work the expensive one forces. The
//!   shared network path cancels in the delta, so the residual is server cost.
//!   A comparability gate rejects expensive responses whose status class or
//!   content type differs from the baseline (WAF blocks, validation errors, fast
//!   500s) so we don't read transport/error latency as compute.
//! - `degradation`: fire a small, bounded concurrent burst and measure the
//!   latency knee — the strongest fragility signal, kept deliberately small.
//! - `graphql`: probe a GraphQL endpoint's query cost (read-only `query` ops
//!   only — introspection and nested selection, never a mutation). Detection is
//!   by GraphQL JSON response shape (`data`/`errors`), not HTTP status.

use super::param::{self, Param, ParamLoc};
use reqwest::Client;
use std::time::Instant;
use url::Url;

/// Cap on how many parameters we differentially probe per endpoint.
const MAX_PROBED_PARAMS: usize = 6;
/// Fixed per-request header overhead estimate (Host/UA/Accept/… bytes) used when
/// computing request size for the amplification ratio.
const REQ_HEADER_OVERHEAD: usize = 160;
/// Adaptive sampling: max cheap/expensive pairs per parameter.
const MAX_PAIRS: usize = 5;
/// Below this median delta, one pair is enough (nothing interesting here).
const LOW_MS: f64 = 15.0;
/// Below this median delta after 3 pairs, stop; above it, collect up to MAX_PAIRS.
const MID_MS: f64 = 60.0;
/// The joint (2-param) delta must beat the best single-param delta by this factor
/// to count as a real interaction effect.
const INTERACTION_MARGIN: f64 = 1.3;
/// Number of aliased fields in the GraphQL cost query (fan-out amplification).
const GQL_ALIAS_FANOUT: usize = 200;

/// One HTTP measurement.
pub struct Measure {
    /// Time to response headers (ms).
    pub ttfb_ms: f64,
    /// Time to the full body (ms).
    pub total_ms: f64,
    pub body_bytes: usize,
    pub status: u16,
    pub cacheable: bool,
    /// Coarse content type (before `;`, lowercased) for comparability checks.
    pub content_type: Option<String>,
}

/// Send a request, timing it and returning the measurement plus the body bytes.
async fn send_measured(builder: reqwest::RequestBuilder) -> Option<(Measure, Vec<u8>)> {
    let t0 = Instant::now();
    let resp = builder.send().await.ok()?;
    let ttfb_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let status = resp.status().as_u16();
    let cacheable = super::is_cacheable(resp.headers());
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(';').next().unwrap_or("").trim().to_ascii_lowercase());
    let bytes = resp.bytes().await.ok()?;
    let total_ms = t0.elapsed().as_secs_f64() * 1000.0;
    Some((
        Measure {
            ttfb_ms,
            total_ms,
            body_bytes: bytes.len(),
            status,
            cacheable,
            content_type,
        },
        bytes.to_vec(),
    ))
}

async fn measure_req(builder: reqwest::RequestBuilder) -> Option<Measure> {
    send_measured(builder).await.map(|(m, _)| m)
}

pub async fn measure_get(client: &Client, url: &Url) -> Option<Measure> {
    measure_req(client.get(url.clone())).await
}

/// Two responses are comparable if they're the same status class and content
/// type. If not, the expensive input took a different code path (block / error /
/// redirect) and its timing is not a compute measurement.
fn comparable(a: &Measure, b: &Measure) -> bool {
    a.status / 100 == b.status / 100 && a.content_type == b.content_type
}

/// Estimate transmitted request bytes for a GET (request line + fixed header
/// overhead + host), so amplification is response-out / request-in.
fn get_request_bytes(u: &Url) -> f64 {
    let line = 4 // "GET "
        + u.path().len()
        + u.query().map(|q| q.len() + 1).unwrap_or(0)
        + 11 // " HTTP/1.1\r\n"
        + u.host_str().map(|h| h.len()).unwrap_or(0);
    (line + REQ_HEADER_OVERHEAD) as f64
}

/// Result of differential probing one endpoint.
pub struct Diff {
    /// Cheap-input server latency at rest (median TTFB, ms).
    pub baseline_ms: f64,
    /// Marginal server ms the worst parameter forces above baseline (median).
    pub compute_ms: f64,
    /// Confidence in `compute_ms`, 0..1 (from the winning param's sample spread).
    pub confidence: f64,
    /// Largest comparable response body observed (bytes) — for the note.
    pub body_bytes: usize,
    /// Max response-out / request-in byte ratio observed.
    pub amplification: f64,
    pub cacheable: bool,
    /// The parameter that produced the most extra work, if any.
    pub worst_param: Option<String>,
    /// Expensive/cheap latency ratio for that worst parameter.
    pub worst_ratio: f64,
    /// True if at least one expensive probe was rejected as non-comparable
    /// (different status/content-type) — often a WAF or input validation.
    pub noncomparable: bool,
}

/// Per-parameter differential statistics from adaptive interleaved sampling.
struct ParamStat {
    /// Whether the cheap/expensive responses were comparable.
    comparable: bool,
    /// Median pairwise delta, floored at 0 (ms of forced server work).
    compute_ms: f64,
    /// Confidence 0..1 from sample spread + count.
    confidence: f64,
    /// Median expensive/cheap TTFB ratio.
    ratio: f64,
    body_bytes: usize,
    amplification: f64,
}

fn median_of(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let mut v = xs.to_vec();
    v.sort_by(f64::total_cmp);
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// Median absolute deviation about `center` — a robust spread measure.
fn mad_of(xs: &[f64], center: f64) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let dev: Vec<f64> = xs.iter().map(|x| (x - center).abs()).collect();
    median_of(&dev)
}

/// Confidence 0..1 in a delta estimate: rises with sample count, falls with
/// relative spread (MAD / |median|). A single sample is inherently weak.
fn confidence(deltas: &[f64]) -> f64 {
    let n = deltas.len();
    if n == 0 {
        return 0.0;
    }
    if n == 1 {
        return 0.3;
    }
    let med = median_of(deltas);
    let rel = mad_of(deltas, med) / (med.abs() + 5.0); // +5ms floor: don't over-punish tiny deltas
    let spread_score = (1.0 - rel).clamp(0.0, 1.0);
    let count_score = (n as f64 / MAX_PAIRS as f64).min(1.0);
    (spread_score * count_score).clamp(0.0, 0.95)
}

/// Adaptively sample interleaved cheap/expensive pairs for one parameter.
///
/// Interleaving (cheap, expensive, cheap, expensive, …) cancels slow drift; the
/// pairwise delta cancels the shared per-request transport floor. Sampling stops
/// early when the delta is clearly uninteresting, and escalates only when there
/// is evidence, so the request budget concentrates on promising parameters.
async fn adaptive_delta<FC, FE>(
    mk_cheap: FC,
    mk_exp: FE,
    exp_req_bytes: f64,
    cheap_ttfbs: &mut Vec<f64>,
) -> Option<ParamStat>
where
    FC: Fn() -> reqwest::RequestBuilder,
    FE: Fn() -> reqwest::RequestBuilder,
{
    let mut deltas = Vec::new();
    let mut cheaps = Vec::new();
    let mut exps = Vec::new();
    let mut body_bytes = 0usize;
    let mut amp = 0.0f64;

    for i in 0..MAX_PAIRS {
        let Some(c) = measure_req(mk_cheap()).await else { break };
        let Some(e) = measure_req(mk_exp()).await else { break };
        if !comparable(&c, &e) {
            return Some(ParamStat {
                comparable: false,
                compute_ms: 0.0,
                confidence: 0.0,
                ratio: 1.0,
                body_bytes: 0,
                amplification: 0.0,
            });
        }
        cheaps.push(c.ttfb_ms);
        exps.push(e.ttfb_ms);
        deltas.push(e.ttfb_ms - c.ttfb_ms);
        body_bytes = body_bytes.max(e.body_bytes);
        amp = amp.max(e.body_bytes as f64 / exp_req_bytes.max(1.0));

        // Adaptive stops.
        if i == 0 && deltas[0].abs() < LOW_MS {
            break;
        }
        if i == 2 && median_of(&deltas).abs() < MID_MS {
            break;
        }
    }

    if deltas.is_empty() {
        return None;
    }
    cheap_ttfbs.extend(&cheaps);
    let cheap_med = median_of(&cheaps);
    Some(ParamStat {
        comparable: true,
        compute_ms: median_of(&deltas).max(0.0),
        confidence: confidence(&deltas),
        ratio: if cheap_med > 0.1 {
            median_of(&exps) / cheap_med
        } else {
            1.0
        },
        body_bytes,
        amplification: amp,
    })
}

fn new_diff(base: &Measure, req_bytes: f64) -> Diff {
    Diff {
        baseline_ms: base.ttfb_ms,
        compute_ms: 0.0,
        confidence: 0.0,
        body_bytes: base.body_bytes,
        amplification: base.body_bytes as f64 / req_bytes.max(1.0),
        cacheable: base.cacheable,
        worst_param: None,
        worst_ratio: 1.0,
        noncomparable: false,
    }
}

/// Fold a comparable parameter's stats into the running Diff, keeping the worst.
fn fold(diff: &mut Diff, stat: &ParamStat, param: &str) {
    diff.body_bytes = diff.body_bytes.max(stat.body_bytes);
    diff.amplification = diff.amplification.max(stat.amplification);
    if stat.compute_ms > diff.compute_ms {
        diff.compute_ms = stat.compute_ms;
        diff.confidence = stat.confidence;
        diff.worst_param = Some(param.to_string());
        diff.worst_ratio = stat.ratio;
    }
}

/// Probe an endpoint with cheap vs. expensive values for each query parameter,
/// using adaptive interleaved sampling. A warm-up request first establishes the
/// connection and warms caches so the baseline isn't a cold-start outlier.
pub async fn differential(client: &Client, base: &Url, params: &[Param]) -> Option<Diff> {
    let cheap_url = param::url_cheap(base, params);
    let _ = measure_get(client, &cheap_url).await; // warm-up (discarded)
    let base_m = measure_get(client, &cheap_url).await?;
    let mut diff = new_diff(&base_m, get_request_bytes(&cheap_url));
    let mut cheap_ttfbs = vec![base_m.ttfb_ms];

    let mut single_deltas: Vec<(String, f64)> = Vec::new();
    for p in params
        .iter()
        .filter(|p| p.loc == ParamLoc::Query)
        .take(MAX_PROBED_PARAMS)
    {
        let exp = param::expensive_value(&p.name);
        let u = param::url_with(base, params, &p.name, &exp);
        let exp_req = get_request_bytes(&u);
        let stat = adaptive_delta(
            || client.get(cheap_url.clone()),
            || client.get(u.clone()),
            exp_req,
            &mut cheap_ttfbs,
        )
        .await;
        match stat {
            Some(s) if s.comparable => {
                single_deltas.push((p.name.clone(), s.compute_ms));
                fold(&mut diff, &s, &p.name);
            }
            Some(_) => diff.noncomparable = true,
            None => {}
        }
    }

    // Interaction pass: some pathological query plans only fire when two knobs
    // are pushed together (filter + sort, sort + limit, …). Probe the top-2
    // single-param offenders jointly and keep it only if it clearly beats them.
    if single_deltas.len() >= 2 {
        single_deltas.sort_by(|a, b| b.1.total_cmp(&a.1));
        let (n1, n2) = (single_deltas[0].0.clone(), single_deltas[1].0.clone());
        let (v1, v2) = (param::expensive_value(&n1), param::expensive_value(&n2));
        let u = param::url_with_pairs(base, params, &[(&n1, &v1), (&n2, &v2)]);
        let exp_req = get_request_bytes(&u);
        if let Some(s) = adaptive_delta(
            || client.get(cheap_url.clone()),
            || client.get(u.clone()),
            exp_req,
            &mut cheap_ttfbs,
        )
        .await
        {
            if s.comparable && s.compute_ms > diff.compute_ms * INTERACTION_MARGIN {
                diff.compute_ms = s.compute_ms;
                diff.confidence = s.confidence;
                diff.worst_param = Some(format!("{n1}+{n2}"));
                diff.worst_ratio = s.ratio;
                diff.body_bytes = diff.body_bytes.max(s.body_bytes);
                diff.amplification = diff.amplification.max(s.amplification);
            }
        }
    }

    diff.baseline_ms = median_of(&cheap_ttfbs);
    Some(diff)
}

/// Differential probe over a form POST body (cheap vs. expensive per field),
/// with the same adaptive interleaved sampling. Only call this for forms already
/// vetted as non-destructive by the caller.
pub async fn differential_form(client: &Client, url: &Url, params: &[Param]) -> Option<Diff> {
    let fields: Vec<&Param> = params.iter().filter(|p| p.loc == ParamLoc::Form).collect();
    if fields.is_empty() {
        return None;
    }
    let cheap_body: Vec<(String, String)> = fields
        .iter()
        .map(|p| (p.name.clone(), param::cheap_value(&p.name)))
        .collect();
    let cheap_len = form_body_len(&cheap_body);

    let _ = send_measured(client.post(url.clone()).form(&cheap_body)).await; // warm-up
    let (base_m, _) = send_measured(client.post(url.clone()).form(&cheap_body)).await?;
    let mut diff = new_diff(&base_m, get_request_bytes(url) + cheap_len);
    let mut cheap_ttfbs = vec![base_m.ttfb_ms];

    for p in fields.iter().take(MAX_PROBED_PARAMS) {
        let exp_body: Vec<(String, String)> = fields
            .iter()
            .map(|f| {
                let v = if f.name == p.name {
                    param::expensive_value(&f.name)
                } else {
                    param::cheap_value(&f.name)
                };
                (f.name.clone(), v)
            })
            .collect();
        let exp_req = get_request_bytes(url) + form_body_len(&exp_body);
        let stat = adaptive_delta(
            || client.post(url.clone()).form(&cheap_body),
            || client.post(url.clone()).form(&exp_body),
            exp_req,
            &mut cheap_ttfbs,
        )
        .await;
        match stat {
            Some(s) if s.comparable => fold(&mut diff, &s, &p.name),
            Some(_) => diff.noncomparable = true,
            None => {}
        }
    }

    diff.baseline_ms = median_of(&cheap_ttfbs);
    Some(diff)
}

fn form_body_len(body: &[(String, String)]) -> f64 {
    // name=value&name=value… — a close approximation of the encoded body length.
    body.iter()
        .map(|(k, v)| k.len() + v.len() + 2)
        .sum::<usize>() as f64
}

/// Latency knee and error onset under a small concurrent burst.
pub struct Degradation {
    /// p50 latency under load / single-request latency. 1.0 = flat (robust).
    pub knee: f64,
    /// Fraction of the burst that errored or timed out.
    pub error_rate: f64,
}

/// Fire one bounded burst of `concurrency` simultaneous requests and compare the
/// median latency to a single request. Deliberately a single small burst — this
/// is a fragility measurement, not a flood.
pub async fn degradation(client: &Client, url: &Url, concurrency: usize) -> Degradation {
    let single = match measure_get(client, url).await {
        Some(m) => m.total_ms.max(0.1),
        None => return Degradation { knee: 1.0, error_rate: 1.0 },
    };

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..concurrency {
        let c = client.clone();
        let u = url.clone();
        set.spawn(async move { measure_get(&c, &u).await.map(|m| m.total_ms) });
    }

    let mut lat = Vec::new();
    let mut errs = 0usize;
    while let Some(r) = set.join_next().await {
        match r {
            Ok(Some(ms)) => lat.push(ms),
            _ => errs += 1,
        }
    }

    let error_rate = errs as f64 / concurrency.max(1) as f64;
    lat.sort_by(f64::total_cmp);
    let p50 = if lat.is_empty() { single } else { lat[lat.len() / 2] };
    Degradation {
        knee: (p50 / single).max(1.0),
        error_rate,
    }
}

/// GraphQL cost probe result.
pub struct Gql {
    /// Trivial-query total time (ms) — the endpoint's floor.
    pub baseline_ms: f64,
    /// Heavy-query total time / trivial-query total time. >1 = the endpoint lets
    /// a single query cost far more than a minimal one.
    pub cost_ratio: f64,
    /// Whether schema introspection is enabled (leaks the full type graph and
    /// enables precise cost-amplification queries).
    pub introspection: bool,
}

/// Probe a suspected GraphQL endpoint. Uses only read-only `query` operations.
/// Confirms it's really GraphQL by the response JSON shape, not HTTP status
/// (GraphQL commonly returns 200 with an `errors` array, or 4xx with `data`).
pub async fn graphql(client: &Client, url: &Url) -> Option<Gql> {
    let (trivial, body) = post_query_full(client, url, "{__typename}").await?;
    if !is_graphql_body(&body) {
        return None;
    }

    let introspection = match post_query_full(client, url, "query{__schema{types{name}}}").await {
        Some((_, b)) => json_has_path(&b, &["data", "__schema"]),
        None => false,
    };

    // Alias fan-out: resolve the same field N times in one query. Cheap for us,
    // O(N) resolver work server-side, and — unlike deep introspection — it works
    // even when introspection is disabled (`__typename` is always available).
    // Read-only.
    let mut heavy = String::with_capacity(GQL_ALIAS_FANOUT * 16);
    heavy.push_str("query{");
    for i in 0..GQL_ALIAS_FANOUT {
        heavy.push_str(&format!("a{i}:__typename "));
    }
    heavy.push('}');
    let cost_ratio = match measure_req(gql_builder(client, url, &heavy)).await {
        Some(h) if trivial.total_ms > 0.1 => (h.total_ms / trivial.total_ms).max(1.0),
        _ => 1.0,
    };

    Some(Gql {
        baseline_ms: trivial.total_ms,
        cost_ratio,
        introspection,
    })
}

fn gql_builder(client: &Client, url: &Url, query: &str) -> reqwest::RequestBuilder {
    // Build the JSON body by hand so we don't need reqwest's `json` feature.
    let body = serde_json::json!({ "query": query }).to_string();
    client
        .post(url.clone())
        .header("content-type", "application/json")
        .body(body)
}

async fn post_query_full(client: &Client, url: &Url, query: &str) -> Option<(Measure, Vec<u8>)> {
    send_measured(gql_builder(client, url, query)).await
}

/// A GraphQL response is JSON with a top-level `data` or `errors` member.
fn is_graphql_body(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .map(|v| v.get("data").is_some() || v.get("errors").is_some())
        .unwrap_or(false)
}

fn json_has_path(body: &[u8], path: &[&str]) -> bool {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    let mut cur = &v;
    for key in path {
        match cur.get(key) {
            Some(next) => cur = next,
            None => return false,
        }
    }
    !cur.is_null()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graphql_body_detection() {
        assert!(is_graphql_body(br#"{"data":{"__typename":"Query"}}"#));
        assert!(is_graphql_body(br#"{"errors":[{"message":"nope"}]}"#));
        assert!(!is_graphql_body(br#"{"foo":1}"#));
        assert!(!is_graphql_body(b"<html>not json</html>"));
    }

    #[test]
    fn json_path_lookup() {
        let b = br#"{"data":{"__schema":{"types":[]}}}"#;
        assert!(json_has_path(b, &["data", "__schema"]));
        assert!(!json_has_path(b, &["data", "missing"]));
        assert!(!json_has_path(br#"{"data":null}"#, &["data", "__schema"]));
    }

    #[test]
    fn median_and_mad() {
        assert_eq!(median_of(&[3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median_of(&[1.0, 2.0, 3.0, 4.0]), 2.5);
        assert_eq!(mad_of(&[1.0, 2.0, 3.0], 2.0), 1.0);
    }

    #[test]
    fn confidence_rewards_tight_repeated_samples() {
        let noisy = confidence(&[10.0, 200.0, 5.0, 180.0]); // huge spread
        let tight = confidence(&[100.0, 102.0, 99.0, 101.0, 100.0]); // tight, n=5
        assert!(tight > noisy);
        assert!(confidence(&[50.0]) < tight); // a single sample is weak
        assert_eq!(confidence(&[]), 0.0);
    }
}
