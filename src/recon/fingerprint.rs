//! Server fingerprinting, security-header audit, method enumeration, and
//! sensitive-path probing. All read-only GET/OPTIONS requests.

use reqwest::Client;

/// Security headers whose *absence* is worth reporting.
const SECURITY_HEADERS: &[&str] = &[
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
];

/// Common sensitive paths to probe (non-404 = exposed).
const SENSITIVE_PATHS: &[&str] = &[
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/api",
    "/api/graphql",
    "/graphql",
    "/graphiql",
    "/admin",
    "/administrator",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/server-status",
    "/server-info",
    "/metrics",
    "/debug",
    "/debug/pprof",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/openapi.json",
    "/.well-known/security.txt",
    "/config.json",
    "/config.yaml",
    "/backup",
    "/backup.zip",
    "/db.sql",
    "/dump.sql",
    "/.aws/credentials",
    "/.ssh/id_rsa",
    "/robots.txt",
    "/sitemap.xml",
    "/console",
    "/jenkins",
    "/.dockerenv",
    "/docker-compose.yml",
    "/status",
];

pub struct Fingerprint {
    pub server: Option<String>,
    pub missing_security_headers: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub exposed_paths: Vec<String>,
    /// The server returns a non-404 catch-all for unknown paths (typical of a
    /// SPA history fallback). The sensitive-path results were filtered against it.
    pub spa_catchall: bool,
}

/// The built-in sensitive-path wordlist, as owned strings (so a caller can swap
/// in a custom list of the same shape).
pub fn default_wordlist() -> Vec<String> {
    SENSITIVE_PATHS.iter().map(|s| s.to_string()).collect()
}

/// Run the read-only fingerprinting suite against `base`, probing `paths` for
/// exposure. Catch-all servers are detected first so the path scan doesn't
/// report the whole wordlist as "exposed".
pub async fn fingerprint(client: &Client, base: &str, paths: &[String]) -> Fingerprint {
    let mut server = None;
    let mut missing = Vec::new();

    if let Ok(resp) = client.get(base).send().await {
        let headers = resp.headers();
        server = headers
            .get("server")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        for h in SECURITY_HEADERS {
            if !headers.contains_key(*h) {
                missing.push((*h).to_string());
            }
        }
    }

    let base_url = url::Url::parse(base).ok();
    let catchall = match &base_url {
        Some(u) => detect_catchall(client, u).await,
        None => None,
    };
    let exposed = match &base_url {
        Some(u) => probe_sensitive(client, u, paths, catchall.as_ref()).await,
        None => Vec::new(),
    };

    Fingerprint {
        server,
        missing_security_headers: missing,
        allowed_methods: enumerate_methods(client, base).await,
        exposed_paths: exposed,
        spa_catchall: catchall.is_some(),
    }
}

/// The response signature of a server's catch-all handler.
struct CatchAll {
    status: u16,
    len: usize,
}

async fn fetch_status_len(client: &Client, url: url::Url) -> Option<(u16, usize)> {
    let resp = client.get(url).send().await.ok()?;
    let status = resp.status().as_u16();
    let bytes = resp.bytes().await.ok()?;
    Some((status, bytes.len()))
}

/// Two byte lengths are "the same page": within 64 bytes or 5%.
fn lens_similar(a: usize, b: usize) -> bool {
    let (hi, lo) = if a >= b { (a, b) } else { (b, a) };
    hi - lo <= 64 || (lo > 0 && (hi - lo) * 100 / lo <= 5)
}

/// Detect a catch-all by requesting two random paths that should 404. If both
/// return the same non-404 status with a near-identical body, the server serves
/// a fallback (SPA index) for everything.
async fn detect_catchall(client: &Client, base: &url::Url) -> Option<CatchAll> {
    let mut seen = Vec::new();
    for p in ["/onb-nope-7f3a9c2e", "/onb-absent-1b8d4e6f/sub"] {
        if let Ok(u) = base.join(p) {
            if let Some(sl) = fetch_status_len(client, u).await {
                seen.push(sl);
            }
        }
    }
    if let [(s1, l1), (s2, l2)] = seen[..] {
        if s1 != 404 && s1 == s2 && lens_similar(l1, l2) {
            return Some(CatchAll {
                status: s1,
                len: (l1 + l2) / 2,
            });
        }
    }
    None
}

/// Prefer the `Allow` header from OPTIONS; note TRACE if the server honors it.
async fn enumerate_methods(client: &Client, base: &str) -> Vec<String> {
    let mut methods = Vec::new();
    if let Ok(resp) = client.request(reqwest::Method::OPTIONS, base).send().await {
        if let Some(allow) = resp.headers().get("allow").and_then(|v| v.to_str().ok()) {
            methods.extend(allow.split(',').map(|m| m.trim().to_uppercase()).filter(|m| !m.is_empty()));
        }
    }
    if let Ok(resp) = client.request(reqwest::Method::TRACE, base).send().await {
        if resp.status().is_success() && !methods.iter().any(|m| m == "TRACE") {
            methods.push("TRACE".to_string());
        }
    }
    methods
}

/// Probe `paths` for exposure. A path counts as exposed only if it doesn't
/// 404/400 AND its response differs from the catch-all signature (if any) — so a
/// SPA that serves index.html for everything doesn't light up the whole list.
async fn probe_sensitive(
    client: &Client,
    base_url: &url::Url,
    paths: &[String],
    catchall: Option<&CatchAll>,
) -> Vec<String> {
    let mut exposed = Vec::new();
    for path in paths {
        let Ok(url) = base_url.join(path) else { continue };
        let Some((s, len)) = fetch_status_len(client, url).await else { continue };
        if s == 404 || s == 400 {
            continue;
        }
        if let Some(ca) = catchall {
            // Same response as the catch-all → not a real exposure.
            if s == ca.status && lens_similar(len, ca.len) {
                continue;
            }
        }
        exposed.push(format!("{path} [{s}]"));
    }
    exposed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_similar_within_tolerance() {
        assert!(lens_similar(1000, 1000));
        assert!(lens_similar(1000, 1030)); // within 64
        assert!(lens_similar(10_000, 10_400)); // within 5%
        assert!(!lens_similar(1000, 5000));
    }

    #[test]
    fn default_wordlist_is_nonempty_and_rooted() {
        let wl = default_wordlist();
        assert!(wl.len() > 20);
        assert!(wl.iter().all(|p| p.starts_with('/')));
    }
}
