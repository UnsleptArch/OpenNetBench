//! Structured-source discovery: pull endpoints (and, where available, their
//! parameters) out of files the target hands us for free — `robots.txt`,
//! `sitemap.xml`, and OpenAPI/Swagger specs. This finds surface that an HTML
//! crawl misses, and the OpenAPI path gives real parameter names to probe.

use super::param::{Param, ParamLoc};
use reqwest::Client;
use url::Url;

/// Which structured source an endpoint came from (drives probe prioritization).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Robots,
    Sitemap,
    OpenApi,
}

/// An endpoint discovered from a structured source, with any parameters the
/// source declared.
pub struct Discovered {
    pub url: String,
    pub params: Vec<Param>,
    pub source: Source,
}

/// Run all structured-source probes against `base`. Best-effort: every source
/// that errors or is absent simply contributes nothing.
pub async fn discover(client: &Client, base: &Url) -> Vec<Discovered> {
    let mut out = Vec::new();

    // robots.txt: harvest Disallow/Allow paths (juicy — owner-marked) + sitemaps.
    if let Some(text) = fetch_text(client, base, "/robots.txt").await {
        let (paths, sitemaps) = parse_robots(&text);
        for p in paths {
            if let Ok(u) = base.join(&p) {
                out.push(Discovered {
                    url: u.to_string(),
                    params: super::param::from_url(&u),
                    source: Source::Robots,
                });
            }
        }
        for sm in sitemaps {
            if let Ok(u) = Url::parse(&sm) {
                harvest_sitemap(client, &u, &mut out).await;
            }
        }
    }

    // Default sitemap location if robots didn't point at one.
    if !out.iter().any(|d| d.url.contains("sitemap")) {
        if let Ok(u) = base.join("/sitemap.xml") {
            harvest_sitemap(client, &u, &mut out).await;
        }
    }

    // OpenAPI / Swagger: the richest source — endpoints AND parameter names.
    for spec_path in ["/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs"] {
        if let Some(text) = fetch_text(client, base, spec_path).await {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                let ops = parse_openapi(&v);
                if !ops.is_empty() {
                    for op in ops {
                        if let Ok(u) = base.join(&op.path) {
                            out.push(Discovered {
                                url: u.to_string(),
                                params: op.params,
                                source: Source::OpenApi,
                            });
                        }
                    }
                    break; // one valid spec is enough.
                }
            }
        }
    }

    out
}

async fn fetch_text(client: &Client, base: &Url, path: &str) -> Option<String> {
    let url = base.join(path).ok()?;
    let resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.text().await.ok()
}

async fn harvest_sitemap(client: &Client, url: &Url, out: &mut Vec<Discovered>) {
    if let Ok(resp) = client.get(url.clone()).send().await {
        if let Ok(body) = resp.text().await {
            for loc in parse_sitemap(&body) {
                if let Ok(u) = Url::parse(&loc) {
                    out.push(Discovered {
                        url: u.to_string(),
                        params: super::param::from_url(&u),
                        source: Source::Sitemap,
                    });
                }
            }
        }
    }
}

/// Parse robots.txt: returns (allow/disallow paths, sitemap URLs).
pub(crate) fn parse_robots(text: &str) -> (Vec<String>, Vec<String>) {
    let mut paths = Vec::new();
    let mut sitemaps = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((key, val)) = line.split_once(':') else { continue };
        let val = val.trim();
        if val.is_empty() {
            continue;
        }
        match key.trim().to_ascii_lowercase().as_str() {
            "disallow" | "allow" => {
                // Skip bare "/" and wildcard-only rules — no concrete endpoint.
                if val.starts_with('/') && val != "/" && !val.contains('*') {
                    paths.push(val.to_string());
                }
            }
            "sitemap" => sitemaps.push(val.to_string()),
            _ => {}
        }
    }
    paths.sort();
    paths.dedup();
    (paths, sitemaps)
}

/// Extract `<loc>` URLs from a sitemap (or sitemap index).
pub(crate) fn parse_sitemap(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(start) = xml[from..].find("<loc>") {
        let s = from + start + "<loc>".len();
        let Some(end) = xml[s..].find("</loc>") else { break };
        let url = xml[s..s + end].trim().to_string();
        if !url.is_empty() {
            out.push(url);
        }
        from = s + end;
    }
    out
}

pub(crate) struct OpenApiOp {
    path: String,
    params: Vec<Param>,
}

/// Parse an OpenAPI/Swagger document into GET-able operations with their query
/// parameters. Path templates like `/users/{id}` get a concrete placeholder.
pub(crate) fn parse_openapi(v: &serde_json::Value) -> Vec<OpenApiOp> {
    let mut out = Vec::new();
    let Some(paths) = v.get("paths").and_then(|p| p.as_object()) else {
        return out;
    };
    for (raw_path, item) in paths {
        let Some(get) = item.get("get") else { continue };
        // Collect query parameters (OpenAPI `in: query`).
        let mut params = Vec::new();
        if let Some(arr) = get.get("parameters").and_then(|p| p.as_array()) {
            for p in arr {
                let in_query = p.get("in").and_then(|i| i.as_str()) == Some("query");
                if let (true, Some(name)) = (in_query, p.get("name").and_then(|n| n.as_str())) {
                    params.push(Param { name: name.to_string(), loc: ParamLoc::Query });
                }
            }
        }
        // Fill path templates with a benign placeholder so the URL resolves.
        let path = fill_path_template(raw_path);
        out.push(OpenApiOp { path, params });
    }
    out
}

/// Replace `{param}` segments in an OpenAPI path with `1` so it's requestable.
fn fill_path_template(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut depth: u32 = 0;
    for c in path.chars() {
        match c {
            '{' => {
                depth += 1;
                if depth == 1 {
                    out.push('1');
                }
            }
            '}' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn robots_yields_paths_and_sitemaps() {
        let txt = "User-agent: *\nDisallow: /admin/\nDisallow: /\nAllow: /public/list?limit=10\nDisallow: /*.json\nSitemap: https://x/sitemap.xml\n";
        let (paths, sitemaps) = parse_robots(txt);
        assert!(paths.contains(&"/admin/".to_string()));
        assert!(paths.iter().any(|p| p.starts_with("/public/list")));
        assert!(!paths.contains(&"/".to_string())); // bare root skipped
        assert!(!paths.iter().any(|p| p.contains('*'))); // wildcard rule skipped
        assert_eq!(sitemaps, vec!["https://x/sitemap.xml".to_string()]);
    }

    #[test]
    fn sitemap_locs_extracted() {
        let xml = "<urlset><url><loc>https://x/a</loc></url><url><loc> https://x/b </loc></url></urlset>";
        assert_eq!(parse_sitemap(xml), vec!["https://x/a".to_string(), "https://x/b".to_string()]);
    }

    #[test]
    fn openapi_paths_and_query_params() {
        let spec = serde_json::json!({
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [
                            {"name": "id", "in": "path"},
                            {"name": "expand", "in": "query"},
                            {"name": "limit", "in": "query"}
                        ]
                    }
                },
                "/health": { "get": {} },
                "/create": { "post": {} }
            }
        });
        let ops = parse_openapi(&spec);
        let users = ops.iter().find(|o| o.path == "/users/1").expect("templated path");
        let names: Vec<&str> = users.params.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"expand") && names.contains(&"limit"));
        assert!(!names.contains(&"id")); // path param, not query
        assert!(ops.iter().any(|o| o.path == "/health"));
        assert!(!ops.iter().any(|o| o.path == "/create")); // POST-only skipped
    }

    #[test]
    fn path_template_filled() {
        assert_eq!(fill_path_template("/a/{id}/b/{sub}"), "/a/1/b/1");
        assert_eq!(fill_path_template("/plain"), "/plain");
    }
}
