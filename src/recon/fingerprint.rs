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
}

/// Run the read-only fingerprinting suite against `base`.
pub async fn fingerprint(client: &Client, base: &str) -> Fingerprint {
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

    Fingerprint {
        server,
        missing_security_headers: missing,
        allowed_methods: enumerate_methods(client, base).await,
        exposed_paths: probe_sensitive(client, base).await,
    }
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

/// Probe the sensitive-path list; report those that don't 404 / error.
async fn probe_sensitive(client: &Client, base: &str) -> Vec<String> {
    let base_url = match url::Url::parse(base) {
        Ok(u) => u,
        Err(_) => return Vec::new(),
    };
    let mut exposed = Vec::new();
    for path in SENSITIVE_PATHS {
        let Ok(url) = base_url.join(path) else { continue };
        if let Ok(resp) = client.get(url.clone()).send().await {
            let s = resp.status().as_u16();
            if s != 404 && s != 400 {
                exposed.push(format!("{path} [{s}]"));
            }
        }
    }
    exposed
}
