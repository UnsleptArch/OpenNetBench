//! Auto-engine: probe a target, characterize what it is, and recommend a preset
//! with reasoning. Recommend-and-approve: it never fires on its own — it builds
//! the plan and hands it to the normal consent/confirm path, and the plan is
//! fully editable (dump with --save-config).

use crate::classify::detect_waf;
use reqwest::Client;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;

const PROBE_PORTS: &[u16] = &[80, 443, 8080, 8443, 53, 22];
const PORT_TIMEOUT: Duration = Duration::from_secs(2);

/// Embedded/IoT HTTP server signatures — a hint the target is router/appliance
/// infrastructure rather than an application, even if it serves a web UI.
const EMBEDDED_SERVERS: &[&str] =
    &["uhttpd", "lighttpd", "goahead", "rompager", "mini_httpd", "boa", "micro_httpd", "mongoose"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    RouterHost,
    Dns,
    Cdn,
    Api,
    Web,
    Unknown,
}

impl TargetKind {
    fn label(self) -> &'static str {
        match self {
            TargetKind::RouterHost => "router / embedded host",
            TargetKind::Dns => "DNS server",
            TargetKind::Cdn => "CDN / WAF-fronted",
            TargetKind::Api => "HTTP/2 API",
            TargetKind::Web => "web application",
            TargetKind::Unknown => "unknown",
        }
    }
}

pub struct Characterization {
    pub host: String,
    pub open_ports: Vec<u16>,
    pub is_http: bool,
    pub is_https: bool,
    pub http2: bool,
    pub html: bool,
    pub server: Option<String>,
    pub waf: Option<String>,
    pub private_ip: bool,
    pub kind: TargetKind,
}

pub struct Recommendation {
    pub preset: &'static str,
    pub reasoning: Vec<String>,
}

/// Extract a bare host (no scheme, path, or port) for port scanning.
fn host_of(target: &str) -> String {
    let s = target.split("://").last().unwrap_or(target);
    let s = s.split('/').next().unwrap_or(s);
    match s.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => h.to_string(),
        _ => s.to_string(),
    }
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

fn is_embedded(server: Option<&str>) -> bool {
    server
        .map(|s| {
            let s = s.to_ascii_lowercase();
            EMBEDDED_SERVERS.iter().any(|e| s.contains(e))
        })
        .unwrap_or(false)
}

/// Probe the target and classify it. All read-only checks.
pub async fn characterize(target: &str) -> Characterization {
    let host = host_of(target);
    let private_ip = host.parse::<IpAddr>().map(is_private).unwrap_or(false);

    let mut open_ports = Vec::new();
    for &p in PROBE_PORTS {
        let ok = tokio::time::timeout(PORT_TIMEOUT, TcpStream::connect((host.as_str(), p)))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);
        if ok {
            open_ports.push(p);
        }
    }

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .user_agent("OpenNetBench-auto/0.1")
        .build()
        .ok();

    let mut is_http = false;
    let mut is_https = false;
    let mut http2 = false;
    let mut html = false;
    let mut server: Option<String> = None;

    if let Some(client) = &client {
        if open_ports.iter().any(|p| matches!(p, 80 | 8080)) {
            if let Ok(resp) = client.get(format!("http://{host}/")).send().await {
                is_http = true;
                server = server.or_else(|| header_str(&resp, "server"));
                html |= is_html(&resp);
            }
        }
        if open_ports.iter().any(|p| matches!(p, 443 | 8443)) {
            if let Ok(resp) = client.get(format!("https://{host}/")).send().await {
                is_https = true;
                http2 = resp.version() == reqwest::Version::HTTP_2;
                server = server.or_else(|| header_str(&resp, "server"));
                html |= is_html(&resp);
            }
        }
    }

    let waf = detect_waf(server.as_deref());
    let web = is_http || is_https;
    let dns = open_ports.contains(&53);

    let kind = if private_ip || is_embedded(server.as_deref()) {
        TargetKind::RouterHost
    } else if dns && !web {
        TargetKind::Dns
    } else if waf.is_some() {
        TargetKind::Cdn
    } else if http2 && !html {
        TargetKind::Api
    } else if web {
        TargetKind::Web
    } else if !open_ports.is_empty() {
        TargetKind::RouterHost
    } else {
        TargetKind::Unknown
    };

    Characterization {
        host,
        open_ports,
        is_http,
        is_https,
        http2,
        html,
        server,
        waf,
        private_ip,
        kind,
    }
}

/// Recommend a preset from the characterization. `root` gates raw-socket
/// vectors (SYN/ACK) for router targets.
pub fn recommend(c: &Characterization, root: bool) -> Recommendation {
    let mut reasoning = Vec::new();
    let preset = match c.kind {
        TargetKind::RouterHost => {
            reasoning.push(format!(
                "{} looks like router/appliance infrastructure — attack the connection/state table, not bandwidth (one host can't out-bandwidth it, but state tables are small)",
                c.host
            ));
            if root {
                reasoning.push("running as root: SYN + ACK + connection-hold combo available".into());
                "router"
            } else {
                reasoning.push("not root: connection-table exhaustion only — run with sudo to add SYN/ACK".into());
                "router-lite"
            }
        }
        TargetKind::Dns => {
            reasoning.push("port 53 open — random-subdomain query flood defeats caching".into());
            "dns"
        }
        TargetKind::Cdn => {
            reasoning.push(format!(
                "WAF/CDN fingerprint ({}) — test whether the origin holds up behind the edge",
                c.waf.as_deref().unwrap_or("unknown")
            ));
            "cdn"
        }
        TargetKind::Api => {
            reasoning.push("HTTP/2 with a non-HTML root — looks like an API; multiplexed request + rapid-reset".into());
            "api"
        }
        TargetKind::Web => {
            reasoning.push("serves HTML over HTTP(S) — L7 volumetric + slow-connection mix, recon-driven".into());
            "web"
        }
        TargetKind::Unknown => {
            reasoning.push("couldn't characterize the target — start with the connection-hold combo".into());
            "router-lite"
        }
    };
    Recommendation { preset, reasoning }
}

pub fn print_characterization(c: &Characterization) {
    println!("\n===== target characterization =====");
    println!("host        : {}", c.host);
    println!(
        "open ports  : {}",
        c.open_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("http/https  : {}/{}  http2={}  html={}", c.is_http, c.is_https, c.http2, c.html);
    println!("server      : {}", c.server.as_deref().unwrap_or("unknown"));
    if let Some(w) = &c.waf {
        println!("waf/cdn     : {w}");
    }
    println!("looks like  : {}", c.kind.label());
    println!("===================================");
}

pub fn print_recommendation(r: &Recommendation) {
    println!("\n===== recommendation =====");
    println!("preset : {}", r.preset);
    println!("why    :");
    for line in &r.reasoning {
        println!("  - {line}");
    }
    println!("(edit anytime: re-run with --preset or --save-config to a file)");
    println!("==========================\n");
}

fn header_str(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
}

fn is_html(resp: &reqwest::Response) -> bool {
    resp.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|c| c.contains("text/html"))
        .unwrap_or(false)
}
