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
}

pub struct CrawlResult {
    pub urls: Vec<String>,
    pub forms: Vec<Form>,
}

/// BFS from `base`, staying on the same host, bounded by `max_pages`/`max_depth`.
pub async fn crawl(client: &Client, base: &str, max_pages: usize, max_depth: usize) -> CrawlResult {
    let mut urls: Vec<String> = Vec::new();
    let mut forms: Vec<Form> = Vec::new();
    let Ok(base_url) = Url::parse(base) else {
        return CrawlResult { urls, forms };
    };
    let host = base_url.host_str().unwrap_or("").to_string();

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
        let is_html = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|c| c.contains("text/html"))
            .unwrap_or(false);
        urls.push(url.as_str().to_string());
        if !is_html || depth >= max_depth {
            continue;
        }
        let Ok(body) = resp.text().await else { continue };

        for (kind, raw) in extract_refs(&body) {
            let Ok(resolved) = url.join(&raw) else { continue };
            if resolved.host_str() != Some(host.as_str()) {
                continue;
            }
            match kind {
                RefKind::Form(method) => forms.push(Form {
                    action: resolved.as_str().to_string(),
                    method,
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

    CrawlResult { urls, forms }
}

enum RefKind {
    Link,
    Form(String), // method
}

/// Scan HTML for `href`/`src` links and `<form ... action=... method=...>`.
fn extract_refs(html: &str) -> Vec<(RefKind, String)> {
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

    // Forms: find each "<form", read its action/method from the opening tag.
    let lower = html.to_ascii_lowercase();
    let mut from = 0;
    while let Some(pos) = lower[from..].find("<form") {
        let tag_start = from + pos;
        let tag_end = lower[tag_start..]
            .find('>')
            .map(|e| tag_start + e)
            .unwrap_or(bytes.len());
        let tag = &html[tag_start..tag_end];
        let action = attr_value(tag, "action").unwrap_or_else(|| "".to_string());
        let method = attr_value(tag, "method").unwrap_or_else(|| "GET".to_string());
        if !action.is_empty() {
            out.push((RefKind::Form(method.to_uppercase()), action));
        }
        from = tag_end;
    }

    out
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

        let forms: Vec<(&String, &String)> = refs
            .iter()
            .filter_map(|(k, v)| match k {
                RefKind::Form(m) => Some((m, v)),
                _ => None,
            })
            .collect();
        assert!(forms.iter().any(|(m, a)| m.as_str() == "GET" && a.as_str() == "/search"));
        assert!(forms.iter().any(|(m, a)| m.as_str() == "POST" && a.as_str() == "/submit"));
    }
}
