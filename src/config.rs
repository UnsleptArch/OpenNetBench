//! Run configuration model.
//!
//! Everything the operator can tune lives here. Per-vector tuning is a
//! first-class goal: two operators should be able to launch wildly different
//! profiles (a tiny 20-connection HTTP probe vs. a 5000-connection slowloris
//! hold) from the same binary without touching code.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// The adversarial-load vectors OpenNetBench can generate.
///
/// Every vector is single-origin: all traffic leaves the host NIC. There is no
/// spoofing, amplification, or reflection vector by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Vector {
    /// L7 — high-volume HTTP/1.1+2 with rotating browser fingerprints.
    HttpFlood,
    /// L7 — TLS-forced HTTPS flood.
    HttpsOnly,
    /// L7 — CVE-2023-44487 HTTP/2 stream RST loop.
    H2RapidReset,
    /// L7 — incomplete-header hold; drains the connection pool.
    Slowloris,
    /// L7 — slow POST body trickle; exhausts server worker threads.
    Rudy,
    /// L4/5 — repeated TLS handshakes; asymmetric CPU cost on the server.
    TlsExhaust,
    /// L4 — TCP SYN flood via raw socket (requires root).
    SynFlood,
    /// L4 — UDP flood with configurable port and payload.
    UdpFlood,
    /// L7 — random-subdomain DNS query flood.
    DnsFlood,
    /// L4 — connection-pool exhaustion; fills the accept() backlog.
    TcpExhaust,
    /// L7 — Slow Read: tiny receive window, drain the response byte-by-byte so
    /// the server holds its send buffer and connection open.
    SlowRead,
    /// L7 — CVE-2011-3192 Range header with many overlapping ranges; forces
    /// costly multipart response assembly.
    RangeFlood,
    /// L7 — full multiplexed HTTP/2 request flood (completed streams).
    H2Flood,
    /// L4 — TCP ACK flood via raw socket (requires root); stresses stateful
    /// firewall / conntrack state tables.
    AckFlood,
    /// L3 — ICMP echo flood via raw socket (requires root).
    IcmpFlood,
    /// L7 — CVE-2024-27316 HTTP/2 CONTINUATION flood: endless CONTINUATION
    /// frames without END_HEADERS force unbounded header-buffer growth.
    H2Continuation,
}

impl Vector {
    pub const ALL: [Vector; 16] = [
        Vector::HttpFlood,
        Vector::HttpsOnly,
        Vector::H2RapidReset,
        Vector::Slowloris,
        Vector::Rudy,
        Vector::TlsExhaust,
        Vector::SynFlood,
        Vector::UdpFlood,
        Vector::DnsFlood,
        Vector::TcpExhaust,
        Vector::SlowRead,
        Vector::RangeFlood,
        Vector::H2Flood,
        Vector::AckFlood,
        Vector::IcmpFlood,
        Vector::H2Continuation,
    ];

    pub fn slug(self) -> &'static str {
        match self {
            Vector::HttpFlood => "http_flood",
            Vector::HttpsOnly => "https_only",
            Vector::H2RapidReset => "h2_rapid_reset",
            Vector::Slowloris => "slowloris",
            Vector::Rudy => "rudy",
            Vector::TlsExhaust => "tls_exhaust",
            Vector::SynFlood => "syn_flood",
            Vector::UdpFlood => "udp_flood",
            Vector::DnsFlood => "dns_flood",
            Vector::TcpExhaust => "tcp_exhaust",
            Vector::SlowRead => "slow_read",
            Vector::RangeFlood => "range_flood",
            Vector::H2Flood => "h2_flood",
            Vector::AckFlood => "ack_flood",
            Vector::IcmpFlood => "icmp_flood",
            Vector::H2Continuation => "h2_continuation",
        }
    }

    pub fn layer(self) -> &'static str {
        match self {
            Vector::SynFlood
            | Vector::UdpFlood
            | Vector::TcpExhaust
            | Vector::TlsExhaust
            | Vector::AckFlood => "L4",
            Vector::IcmpFlood => "L3",
            _ => "L7",
        }
    }

    /// Whether the vector needs raw socket access (root/CAP_NET_RAW).
    pub fn needs_root(self) -> bool {
        matches!(
            self,
            Vector::SynFlood | Vector::AckFlood | Vector::IcmpFlood
        )
    }

    pub fn description(self) -> &'static str {
        match self {
            Vector::HttpFlood => "High-volume HTTP/1.1+2 with rotating browser fingerprints",
            Vector::HttpsOnly => "TLS-forced HTTPS flood",
            Vector::H2RapidReset => "CVE-2023-44487 HTTP/2 stream RST loop",
            Vector::Slowloris => "Incomplete header hold — drains connection pool",
            Vector::Rudy => "Slow POST body trickle — exhausts server threads",
            Vector::TlsExhaust => "Repeated handshakes — asymmetric CPU cost on server",
            Vector::SynFlood => "TCP SYN flood via raw socket (requires root)",
            Vector::UdpFlood => "UDP flood — configurable port and payload",
            Vector::DnsFlood => "Random-subdomain DNS query flood",
            Vector::TcpExhaust => "Connection pool exhaustion — fills accept() backlog",
            Vector::SlowRead => "Slow response drain — tiny window holds server send buffer",
            Vector::RangeFlood => "CVE-2011-3192 overlapping Range headers — costly assembly",
            Vector::H2Flood => "Multiplexed HTTP/2 request flood over one connection",
            Vector::AckFlood => "TCP ACK flood via raw socket — stresses firewall/conntrack",
            Vector::IcmpFlood => "ICMP echo flood via raw socket (requires root)",
            Vector::H2Continuation => "CVE-2024-27316 HTTP/2 CONTINUATION flood — unbounded header buffer",
        }
    }
}

/// How the scheduler paces load over the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    /// Backs off when connections go nowhere and ramps back up over minutes.
    /// Doubles as the recovery-time detector: the ramp cycle measures whether
    /// the target self-heals. This is the default, safer profile.
    Adaptive,
    /// Sustains maximum load until the operator stops. Used to probe dynamic
    /// WAFs that adapt to steady pressure. No self-throttling.
    Dumb,
}

impl RunMode {
    pub fn label(self) -> &'static str {
        match self {
            RunMode::Adaptive => "adaptive (self-throttling, measures recovery)",
            RunMode::Dumb => "dumb (max load until stopped, tests dynamic WAFs)",
        }
    }
}

/// Aggressiveness tier — scales how much load a preset generates. `Recon` runs
/// no flood at all (probe/recon only); the rest set a per-vector base
/// concurrency the preset applies to every vector it selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// No flood — recon + health probe only. Safe first pass.
    Recon,
    Light,
    Moderate,
    Aggressive,
    Brutal,
}

impl Tier {
    pub const ALL: [Tier; 5] = [
        Tier::Recon,
        Tier::Light,
        Tier::Moderate,
        Tier::Aggressive,
        Tier::Brutal,
    ];

    pub fn slug(self) -> &'static str {
        match self {
            Tier::Recon => "recon",
            Tier::Light => "light",
            Tier::Moderate => "moderate",
            Tier::Aggressive => "aggressive",
            Tier::Brutal => "brutal",
        }
    }

    pub fn parse(s: &str) -> Option<Tier> {
        Tier::ALL.into_iter().find(|t| t.slug() == s.to_ascii_lowercase())
    }

    /// Base per-vector concurrency this tier applies. `Recon` is 0 (no flood).
    pub fn concurrency(self) -> u32 {
        match self {
            Tier::Recon => 0,
            Tier::Light => 50,
            Tier::Moderate => 200,
            Tier::Aggressive => 800,
            Tier::Brutal => 3000,
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Tier::Recon => "no flood — recon + health probe only",
            Tier::Light => "gentle (50/vector) — smoke test",
            Tier::Moderate => "default (200/vector)",
            Tier::Aggressive => "heavy (800/vector)",
            Tier::Brutal => "max single-origin pressure (3000/vector)",
        }
    }
}

/// Per-vector tuning knobs. Not every field applies to every vector; the
/// engine reads only the fields relevant to the vector it's driving. Defaults
/// are deliberately conservative — the operator scales up explicitly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorTuning {
    /// Concurrent workers / open connections this vector maintains.
    pub concurrency: u32,
    /// Target requests-per-second per worker (0 = unbounded / as fast as possible).
    pub rate_per_worker: u32,
    /// Payload size in bytes where applicable (UDP payload, RUDY body length).
    pub payload_bytes: usize,
    /// Trickle interval for slow vectors (slowloris header cadence, RUDY byte cadence).
    #[serde(with = "duration_secs")]
    pub trickle_interval: Duration,
    /// Destination port override (0 = derive from URL scheme).
    pub port: u16,
}

impl VectorTuning {
    /// Sensible small-scale defaults for a given vector.
    pub fn defaults_for(v: Vector) -> Self {
        match v {
            Vector::Slowloris | Vector::SlowRead => VectorTuning {
                concurrency: 200,
                rate_per_worker: 0,
                payload_bytes: 0,
                trickle_interval: Duration::from_secs(10),
                port: 0,
            },
            Vector::Rudy => VectorTuning {
                concurrency: 100,
                rate_per_worker: 0,
                payload_bytes: 1_000_000,
                trickle_interval: Duration::from_secs(10),
                port: 0,
            },
            Vector::UdpFlood => VectorTuning {
                concurrency: 8,
                rate_per_worker: 0,
                payload_bytes: 1024,
                trickle_interval: Duration::from_millis(0),
                port: 0,
            },
            Vector::SynFlood
            | Vector::TcpExhaust
            | Vector::AckFlood
            | Vector::IcmpFlood => VectorTuning {
                concurrency: 500,
                rate_per_worker: 0,
                payload_bytes: 0,
                trickle_interval: Duration::from_millis(0),
                port: 0,
            },
            // HttpFlood, HttpsOnly, H2RapidReset, TlsExhaust, DnsFlood,
            // RangeFlood, H2Flood
            _ => VectorTuning {
                concurrency: 50,
                rate_per_worker: 0,
                payload_bytes: 0,
                trickle_interval: Duration::from_millis(0),
                port: 0,
            },
        }
    }
}

/// A single vector plus its tuning, as queued for a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorPlan {
    pub vector: Vector,
    pub tuning: VectorTuning,
}

/// Optional upstream proxy (supports Tor via SOCKS5 at 127.0.0.1:9050).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub url: String,
}

/// The fully-resolved plan for one assessment run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunConfig {
    pub target: String,
    pub proxy: Option<ProxyConfig>,
    pub mode: RunMode,
    pub run_recon: bool,
    /// Opt out of human target approval. When true, recon auto-selects the
    /// highest-asymmetry endpoint and the run proceeds unattended — intended for
    /// long (multi-day) authorized soak tests. Default false (human approves).
    #[serde(default)]
    pub auto_approve_targets: bool,
    pub vectors: Vec<VectorPlan>,
    #[serde(with = "duration_secs")]
    pub duration: Duration,
    #[serde(with = "duration_secs")]
    pub rampup: Duration,
}

/// Serde helper: (de)serialize a `Duration` as whole seconds.
mod duration_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        Ok(Duration::from_secs(u64::deserialize(d)?))
    }
}
