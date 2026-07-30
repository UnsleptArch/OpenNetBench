//! Async same-host crawl with lightweight link and form discovery.
//!
//! Link extraction is a small byte scanner rather than a full HTML parser — good
//! enough to enumerate an attack surface without pulling in html5ever.

use reqwest::Client;
use std::collections::{HashSet, VecDeque};
use url::Url;

pub struct Form {
    pub action: String,
    pub method: String,
    /// Names of the form's input/select/textarea fields (probeable parameters).
    pub fields: Vec<String>,
}

pub struct CrawlResult {
    pub urls: Vec<String>,
    pub forms: Vec<Form>,
    /// API endpoint paths mined from JavaScript bundles (SPA route/API discovery).
    pub api_urls: Vec<String>,
}

/// Cap on API endpoints mined from JS, to bound the probe budget.
const MAX_API_URLS: usize = 50;

/// BFS from `base`, staying on the same host, bounded by `max_pages`/`max_depth`.
pub async fn crawl(client: &Client, base: &str, max_pages: usize, max_depth: usize) -> CrawlResult {
    let mut urls: Vec<String> = Vec::new();
    let mut forms: Vec<Form> = Vec::new();
    let mut api_urls: Vec<String> = Vec::new();
    let mut api_seen: HashSet<String> = HashSet::new();
    let Ok(base_url) = Url::parse(base) else {
        return CrawlResult { urls, forms, api_urls };
    };
    // Scope the crawl to the exact ORIGIN, not just the host: a different scheme
    // or port is a different service and must not be pulled in as a flood target.
    let origin = Origin::of(&base_url);

    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(Url, usize)> = VecDeque::new();
    queue.push_back((base_url.clone(), 0));
    seen.insert(base_url.as_str().to_string());

    while let Some((url, depth)) = queue.pop_front() {
        if urls.len() >= max_pages {
            break;
        }
        let Ok(resp) = client.get(url.clone()).send().await else {
            continue;
        };
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_html = ct.contains("text/html");
        let is_js =
            ct.contains("javascript") || ct.contains("ecmascript") || url.path().ends_with(".js");
        urls.push(url.as_str().to_string());

        // JavaScript bundle: mine it for API endpoint literals (SPA route/API
        // discovery). We don't crawl these — just record them as candidates.
        if is_js {
            if let Ok(body) = resp.text().await {
                for ep in extract_js_endpoints(&body) {
                    if api_urls.len() >= MAX_API_URLS {
                        break;
                    }
                    if let Ok(resolved) = url.join(&ep) {
                        if Origin::of(&resolved) == origin {
                            let key = resolved.as_str().to_string();
                            if api_seen.insert(key.clone()) {
                                api_urls.push(key);
                            }
                        }
                    }
                }
            }
            continue;
        }

        if !is_html || depth >= max_depth {
            continue;
        }
        let Ok(body) = resp.text().await else { continue };

        for (kind, raw) in extract_refs(&body) {
            let Ok(resolved) = url.join(&raw) else { continue };
            if Origin::of(&resolved) != origin {
                continue;
            }
            match kind {
                RefKind::Form(method, fields) => forms.push(Form {
                    action: resolved.as_str().to_string(),
                    method,
                    fields,
                }),
                RefKind::Link => {
                    let key = resolved.as_str().to_string();
                    if seen.insert(key) && queue.len() + urls.len() < max_pages * 4 {
                        queue.push_back((resolved, depth + 1));
                    }
                }
            }
        }
    }

    CrawlResult { urls, forms, api_urls }
}

const API_MARKERS: &[&str] = &["api", "rest", "graphql", "/v1", "/v2", "service", "search", "query"];
const ASSET_EXTS: &[&str] = &[
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
    ".map", ".html", ".webp", ".mp4", ".json.map",
];

/// Mine a JS bundle for API endpoint literals — quoted absolute paths that look
/// like API routes (contain an API marker, aren't static assets). Path templates
/// (`:id`, `{id}`) are filled with a placeholder so the URL resolves.
pub(crate) fn extract_js_endpoints(js: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for quote in ['"', '\''] {
        let mut from = 0;
        while let Some(pos) = js[from..].find(quote) {
            let start = from + pos + 1;
            let Some(end_rel) = js[start..].find(quote) else { break };
            let cand = &js[start..start + end_rel];
            from = start + end_rel + 1;
            if is_api_pathish(cand) {
                let filled = fill_templates(cand);
                if !out.contains(&filled) {
                    out.push(filled);
                }
            }
        }
    }
    out
}

fn is_api_pathish(s: &str) -> bool {
    if !s.starts_with('/') || s.len() < 2 || s.len() > 128 {
        return false;
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/_-.?=&:{}%".contains(&b))
    {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    let path_only = lower.split('?').next().unwrap_or(&lower);
    if ASSET_EXTS.iter().any(|e| path_only.ends_with(e)) {
        return false;
    }
    API_MARKERS.iter().any(|m| lower.contains(m))
}

/// Replace `{seg}` and `:seg` path templates with a benign placeholder.
fn fill_templates(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                out.push('1');
                while i < bytes.len() && bytes[i] != b'}' {
                    i += 1;
                }
                i += 1; // skip '}'
            }
            b':' => {
                out.push('1');
                i += 1;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
}

/// A same-origin key: scheme + host + effective port. Two URLs share an origin
/// only if all three match (https://x:8443 and http://x:80 do not).
#[derive(PartialEq, Eq)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
}
impl Origin {
    fn of(u: &Url) -> Origin {
        let scheme = u.scheme().to_string();
        let default_port = if scheme == "https" { 443 } else { 80 };
        Origin {
            scheme,
            host: u.host_str().unwrap_or("").to_string(),
            port: u.port().unwrap_or(default_port),
        }
    }
}

pub(crate) enum RefKind {
    Link,
    Form(String, Vec<String>), // method, field names
}

/// Scan HTML for `href`/`src` links and `<form ... action=... method=...>`.
pub(crate) fn extract_refs(html: &str) -> Vec<(RefKind, String)> {
    let mut out = Vec::new();
    let bytes = html.as_bytes();

    for attr in ["href=\"", "src=\""] {
        let mut from = 0;
        while let Some(pos) = html[from..].find(attr) {
            let start = from + pos + attr.len();
            if let Some(end) = html[start..].find('"') {
                let val = &html[start..start + end];
                if !val.is_empty() && !val.starts_with('#') && !val.starts_with("javascript:") {
                    out.push((RefKind::Link, val.to_string()));
                }
                from = start + end;
            } else {
                break;
            }
        }
    }

    // Forms: find each "<form", read action/method from the opening tag and the
    // field names from the form body (up to the matching </form>).
    let lower = html.to_ascii_lowercase();
    let mut from = 0;
    while let Some(pos) = lower[from..].find("<form") {
        let tag_start = from + pos;
        let tag_end = lower[tag_start..]
            .find('>')
            .map(|e| tag_start + e)
            .unwrap_or(bytes.len());
        let tag = &html[tag_start..tag_end];
        let action = attr_value(tag, "action").unwrap_or_default();
        let method = attr_value(tag, "method").unwrap_or_else(|| "GET".to_string());
        let region_end = lower[tag_end..]
            .find("</form>")
            .map(|e| tag_end + e)
            .unwrap_or(bytes.len());
        let fields = field_names(&lower[tag_end..region_end]);
        if !action.is_empty() {
            out.push((RefKind::Form(method.to_uppercase(), fields), action));
        }
        from = region_end;
    }

    out
}

/// Collect `name="..."` values from a form body (its input/select/textarea tags).
fn field_names(region_lower: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut from = 0;
    while let Some(pos) = region_lower[from..].find("name=") {
        let start = from + pos + "name=".len();
        let rest = &region_lower[start..];
        let name = match rest.chars().next() {
            Some(q @ ('"' | '\'')) => {
                let after = &rest[1..];
                after.find(q).map(|e| after[..e].to_string())
            }
            _ => {
                let end = rest.find([' ', '>', '\t', '\n', '/']).unwrap_or(rest.len());
                Some(rest[..end].to_string())
            }
        };
        if let Some(n) = name {
            if !n.is_empty() && !names.contains(&n) {
                names.push(n);
            }
        }
        from = start;
    }
    names
}

/// Read `name="value"` (or `name='value'`) from a single tag string.
fn attr_value(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let key = format!("{name}=");
    let idx = lower.find(&key)? + key.len();
    let rest = &tag[idx..];
    let quote = rest.chars().next()?;
    if quote == '"' || quote == '\'' {
        let after = &rest[1..];
        let end = after.find(quote)?;
        Some(after[..end].to_string())
    } else {
        // unquoted attribute value
        let end = rest.find([' ', '>', '\t', '\n']).unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_links_and_forms() {
        let html = r##"<a href="/about">A</a><img src="/img/logo.png">
            <a href="#skip">x</a><a href="javascript:void(0)">y</a>
            <form action="/search" method="get"><input name="q"></form>
            <FORM ACTION="/submit" METHOD="POST"></FORM>"##;
        let refs = extract_refs(html);

        let links: Vec<&String> = refs
            .iter()
            .filter_map(|(k, v)| matches!(k, RefKind::Link).then_some(v))
            .collect();
        assert!(links.iter().any(|l| l.as_str() == "/about"));
        assert!(links.iter().any(|l| l.as_str() == "/img/logo.png"));
        // Anchors and javascript: pseudo-links are skipped.
        assert!(!links.iter().any(|l| l.starts_with('#')));
        assert!(!links.iter().any(|l| l.starts_with("javascript:")));

        let forms: Vec<(&String, &Vec<String>, &String)> = refs
            .iter()
            .filter_map(|(k, v)| match k {
                RefKind::Form(m, f) => Some((m, f, v)),
                _ => None,
            })
            .collect();
        assert!(forms.iter().any(|(m, _, a)| m.as_str() == "GET" && a.as_str() == "/search"));
        assert!(forms.iter().any(|(m, _, a)| m.as_str() == "POST" && a.as_str() == "/submit"));
        // The GET search form's input name is captured as a probeable field.
        let search = forms.iter().find(|(_, _, a)| a.as_str() == "/search").unwrap();
        assert!(search.1.contains(&"q".to_string()));
    }

    #[test]
    fn mines_api_endpoints_from_js() {
        let js = r#"
            const base="/assets/logo.png"; // asset, skipped
            fetch("/rest/products/search?q="+term);
            this.http.get('/api/Products/'+id);
            const u="/rest/user/:id/reviews";
            const tpl="/api/orders/{orderId}";
            const noise="/home/about"; // no API marker, skipped
        "#;
        let eps = extract_js_endpoints(js);
        assert!(eps.iter().any(|e| e == "/rest/products/search?q="));
        assert!(eps.iter().any(|e| e == "/api/Products/"));
        assert!(eps.iter().any(|e| e == "/rest/user/1/reviews")); // :id filled
        assert!(eps.iter().any(|e| e == "/api/orders/1")); // {orderId} filled
        assert!(!eps.iter().any(|e| e.contains("logo.png")));
        assert!(!eps.iter().any(|e| e == "/home/about"));
    }
}
