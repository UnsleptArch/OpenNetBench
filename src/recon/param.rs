//! Request parameters and the cheap/expensive payloads used for differential
//! asymmetry probing.
//!
//! The idea: for a parameterized endpoint, send it once with a *cheap* value and
//! once with an *expensive* value crafted to maximize server work, then compare
//! latency and response size. Because both requests traverse the same network
//! path, the RTT floor cancels in the delta — what's left is server cost we can
//! force. Payloads are chosen from the parameter's name (its most likely role).

use url::Url;

/// Where a parameter lives in the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamLoc {
    Query,
    Form,
}

/// One tunable parameter on an endpoint.
#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub loc: ParamLoc,
}

/// The guessed role of a parameter, which decides its expensive payload. Each
/// role targets a different class of server-side complexity, not just size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Pagination / size knob — push it huge to force big allocations or scans.
    Numeric,
    /// Free-text search/filter — force a full-table / wildcard scan.
    Search,
    /// Sort/order key — force an expensive multi-key sort over many columns.
    Sort,
    /// A value the server likely compiles as a regex — catastrophic backtracking.
    Regex,
    /// Unknown — send an oversized value to stress parsing/validation.
    Generic,
}

const NUMERIC_HINTS: &[&str] = &[
    "limit", "size", "count", "page", "per_page", "perpage", "pagesize", "offset",
    "rows", "depth", "max", "top", "first", "last", "n", "num", "length", "take",
];
const SEARCH_HINTS: &[&str] = &[
    "q", "query", "search", "term", "keyword", "filter", "name", "title", "text",
    "s", "find", "lookup", "select", "where",
];
const SORT_HINTS: &[&str] = &["sort", "order", "orderby", "sortby", "sort_by", "order_by"];
const REGEX_HINTS: &[&str] = &["regex", "pattern", "expr", "expression", "match", "grep", "re"];

fn role_of(name: &str) -> Role {
    let n = name.to_ascii_lowercase();
    if NUMERIC_HINTS.iter().any(|h| n == *h || n.ends_with(&format!("_{h}"))) {
        Role::Numeric
    } else if REGEX_HINTS.iter().any(|h| n == *h) {
        Role::Regex
    } else if SORT_HINTS.iter().any(|h| n == *h) {
        Role::Sort
    } else if SEARCH_HINTS.iter().any(|h| n == *h) {
        Role::Search
    } else {
        Role::Generic
    }
}

/// A cheap, benign value for the baseline request.
pub fn cheap_value(name: &str) -> String {
    match role_of(name) {
        Role::Numeric | Role::Generic => "1".to_string(),
        Role::Search | Role::Regex => "a".to_string(),
        Role::Sort => "id".to_string(),
    }
}

/// An expensive value crafted to maximize server-side work for this parameter's
/// likely role — targeting algorithmic/planner complexity, not just parser cost.
/// Returned raw/unencoded; the caller lets the HTTP layer encode it.
pub fn expensive_value(name: &str) -> String {
    match role_of(name) {
        // Uncapped limit → the server fetches/serializes an enormous result set
        // (also feeds the bandwidth axis).
        Role::Numeric => "100000000".to_string(),
        // Leading-wildcard LIKE defeats indexes → full scan; padding makes each
        // per-row comparison do real work.
        Role::Search => format!("%{}%", "z".repeat(256)),
        // Many sort keys → an expensive multi-column sort (or a slow error path).
        Role::Sort => (0..64).map(|i| format!("f{i}")).collect::<Vec<_>>().join(","),
        // Catastrophic-backtracking pattern: if the server compiles this as a
        // regex, matching is exponential. Opportunistic — depends on the server
        // actually treating the value as a pattern.
        Role::Regex => "(a+)+$".to_string(),
        // Oversized opaque value: stresses parsing/validation/per-byte work.
        Role::Generic => "A".repeat(8192),
    }
}

/// Extract the query parameters already present on a URL as a probeable set.
pub fn from_url(url: &Url) -> Vec<Param> {
    let mut seen = std::collections::HashSet::new();
    url.query_pairs()
        .filter_map(|(k, _)| {
            let name = k.to_string();
            (!name.is_empty() && seen.insert(name.clone())).then_some(Param {
                name,
                loc: ParamLoc::Query,
            })
        })
        .collect()
}

/// Rebuild `url` with a specific value set on one query parameter, all other
/// known params set to their cheap value. Returns the concrete URL to send.
pub fn url_with(base: &Url, params: &[Param], target: &str, target_value: &str) -> Url {
    url_with_pairs(base, params, &[(target, target_value)])
}

/// Rebuild `url` with explicit values on several query parameters at once; every
/// other known query param is set to its cheap value. Used by the interaction
/// pass to push two parameters expensive together.
pub fn url_with_pairs(base: &Url, params: &[Param], overrides: &[(&str, &str)]) -> Url {
    let mut u = base.clone();
    // Rebuild the query from scratch so we control every value deterministically.
    u.query_pairs_mut().clear();
    for p in params {
        if p.loc != ParamLoc::Query {
            continue;
        }
        let v = overrides
            .iter()
            .find(|(n, _)| *n == p.name)
            .map(|(_, val)| val.to_string())
            .unwrap_or_else(|| cheap_value(&p.name));
        u.query_pairs_mut().append_pair(&p.name, &v);
    }
    u
}

/// Rebuild `url` with every query parameter set to its cheap value (baseline).
pub fn url_cheap(base: &Url, params: &[Param]) -> Url {
    let mut u = base.clone();
    u.query_pairs_mut().clear();
    for p in params {
        if p.loc == ParamLoc::Query {
            u.query_pairs_mut().append_pair(&p.name, &cheap_value(&p.name));
        }
    }
    u
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_are_guessed_from_names() {
        assert_eq!(role_of("limit"), Role::Numeric);
        assert_eq!(role_of("per_page"), Role::Numeric);
        assert_eq!(role_of("q"), Role::Search);
        assert_eq!(role_of("search"), Role::Search);
        assert_eq!(role_of("sort"), Role::Sort);
        assert_eq!(role_of("order_by"), Role::Sort);
        assert_eq!(role_of("pattern"), Role::Regex);
        assert_eq!(role_of("token"), Role::Generic);
    }

    #[test]
    fn expensive_values_match_role() {
        assert_eq!(expensive_value("limit"), "100000000");
        assert!(expensive_value("q").starts_with('%'));
        assert!(expensive_value("q").len() > 200);
        assert!(expensive_value("sort").contains(','));
        assert_eq!(expensive_value("pattern"), "(a+)+$");
        assert_eq!(expensive_value("blob").len(), 8192);
    }

    #[test]
    fn url_with_pairs_sets_multiple_targets() {
        let base = Url::parse("https://x/s?q=x&sort=id&limit=5").unwrap();
        let params = from_url(&base);
        let u = url_with_pairs(&base, &params, &[("q", "BIG"), ("sort", "MANY")]);
        let pairs: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
        assert_eq!(pairs.get("q").map(String::as_str), Some("BIG"));
        assert_eq!(pairs.get("sort").map(String::as_str), Some("MANY"));
        assert_eq!(pairs.get("limit").map(String::as_str), Some("1")); // cheapened
    }

    #[test]
    fn from_url_extracts_unique_query_params() {
        let u = Url::parse("https://x/search?q=hi&limit=10&q=dup").unwrap();
        let ps = from_url(&u);
        let names: Vec<&str> = ps.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"q"));
        assert!(names.contains(&"limit"));
        assert_eq!(names.iter().filter(|n| **n == "q").count(), 1);
    }

    #[test]
    fn url_with_sets_target_and_cheapens_the_rest() {
        let base = Url::parse("https://x/s?q=x&limit=5").unwrap();
        let params = from_url(&base);
        let u = url_with(&base, &params, "limit", "100000000");
        let pairs: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
        assert_eq!(pairs.get("limit").map(String::as_str), Some("100000000"));
        assert_eq!(pairs.get("q").map(String::as_str), Some("a")); // cheapened
    }
}
