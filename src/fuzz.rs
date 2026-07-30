//! Fuzzing surface (compiled only under `cfg(fuzzing)`).
//!
//! Each function is a thin, panic-transparent wrapper over an internal pure
//! function, so the out-of-tree fuzz crate (`dev/fuzz`) can drive the parsers and
//! encoders in-process without any of them becoming public API. The wrappers
//! deliberately swallow return values: the property under test is "arbitrary
//! input never panics / never loops forever", which libFuzzer detects directly.

use crate::engine::{dns_flood, histogram, http_flood, wire};
use crate::recon::{crawl, discover};

/// HTML link/form scanner — the most byte-index-heavy parser (adversarial markup,
/// multibyte UTF-8, unbalanced tags).
pub fn recon_extract_refs(html: &str) {
    let _ = crawl::extract_refs(html);
}

/// JS-bundle API-endpoint miner (quote scanning + path-template filling).
pub fn recon_extract_js(js: &str) {
    let _ = crawl::extract_js_endpoints(js);
}

/// robots.txt line parser.
pub fn recon_robots(text: &str) {
    let _ = discover::parse_robots(text);
}

/// sitemap.xml `<loc>` extractor (nested `find` windows over arbitrary XML).
pub fn recon_sitemap(xml: &str) {
    let _ = discover::parse_sitemap(xml);
}

/// OpenAPI/Swagger parser over already-parsed JSON (the JSON parse itself is
/// serde_json's problem, not ours; this fuzzes our traversal of arbitrary shapes).
pub fn recon_openapi(json: &str) {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(json) {
        let _ = discover::parse_openapi(&v);
    }
}

/// Cache-buster request-line splice over arbitrary template bytes.
pub fn cache_bust_into(template: &[u8], id: u64) {
    let mut out = Vec::new();
    http_flood::cache_bust_into(template, id, &mut out);
}

/// DNS A-query encoder. Uses a buffer sized to the worst-case output for the given
/// domain, so this fuzzes the wire-encoding logic itself. (Production uses a fixed
/// 512-byte buffer and relies on the URL-parsed host being length-bounded; that
/// bound is a caller invariant, not something this target should trip on.)
pub fn dns_encode_query(id: u16, rand: u64, domain: &str) {
    // 12 header + 1 label-len + 10 random label + (each domain byte can add its
    // own length prefix) + 1 root + 4 qtype/qclass, with slack.
    let cap = 64 + domain.len() * 2;
    let mut buf = vec![0u8; cap];
    let n = dns_flood::encode_query(&mut buf, id, rand, domain);
    assert!(n <= buf.len(), "encode_query wrote past its buffer");
}

/// Internet checksum over arbitrary bytes (fold + odd-tail handling).
pub fn wire_checksum(data: &[u8]) {
    let _ = wire::checksum(data);
}

/// Histogram bucket mapping stays in range and round-trips without panic.
pub fn histogram_bucket(us: u64) {
    let idx = histogram::bucket_of(us);
    assert!(idx < histogram::N, "bucket index out of range");
    let _ = histogram::us_of(idx);
}
