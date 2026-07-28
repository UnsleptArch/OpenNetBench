//! Pre-built target profiles.
//!
//! A preset is a curated vector combo for a kind of target. It builds a ready
//! `RunConfig` the operator can still edit (dump to JSON, tweak, re-run with
//! --config). There is a single, deliberately hard load level — presets always
//! hit at full pressure; dial it back by editing the saved config if needed.

use crate::config::{ProxyConfig, RunConfig, RunMode, Vector, VectorPlan, VectorTuning};
use std::time::Duration;

/// Per-vector worker concurrency every preset applies. Tuned down from a naive
/// 3000: past a few thousand held connections a single origin exhausts its own
/// ephemeral ports / conntrack before it stresses the target, which is exactly
/// what produced false "target down" reads. ~2700 keeps real pressure on the
/// target's state table while staying inside one box's local limits.
pub const PRESET_CONCURRENCY: u32 = 2700;

pub struct Preset {
    pub name: &'static str,
    pub description: &'static str,
    pub vectors: &'static [Vector],
    pub mode: RunMode,
    pub run_recon: bool,
    /// Whether the combo includes raw-socket vectors (needs sudo).
    pub needs_root: bool,
}

pub const PRESETS: &[Preset] = &[
    Preset {
        name: "router",
        description: "Home router/gateway — state-table exhaustion (needs sudo)",
        vectors: &[Vector::SynFlood, Vector::AckFlood, Vector::TcpExhaust],
        mode: RunMode::Dumb,
        run_recon: false,
        needs_root: true,
    },
    Preset {
        name: "router-lite",
        description: "Router without sudo — connection-table exhaustion only",
        vectors: &[Vector::TcpExhaust],
        mode: RunMode::Dumb,
        run_recon: false,
        needs_root: false,
    },
    Preset {
        name: "web",
        description: "Web app/site — L7 volumetric + slow-connection mix (recon-driven)",
        vectors: &[
            Vector::HttpFlood,
            Vector::Slowloris,
            Vector::Rudy,
            Vector::RangeFlood,
        ],
        mode: RunMode::Adaptive,
        run_recon: true,
        needs_root: false,
    },
    Preset {
        name: "api",
        description: "API/backend — HTTP/2 request + rapid-reset + slow POST",
        vectors: &[Vector::H2Flood, Vector::H2RapidReset, Vector::Rudy],
        mode: RunMode::Adaptive,
        run_recon: true,
        needs_root: false,
    },
    Preset {
        name: "cdn",
        description: "CDN/WAF-fronted — TLS handshake + rapid-reset + origin flood",
        vectors: &[
            Vector::TlsExhaust,
            Vector::H2RapidReset,
            Vector::HttpFlood,
        ],
        mode: RunMode::Dumb,
        run_recon: true,
        needs_root: false,
    },
    Preset {
        name: "dns",
        description: "DNS server — random-subdomain query flood + UDP",
        vectors: &[Vector::DnsFlood, Vector::UdpFlood],
        mode: RunMode::Dumb,
        run_recon: false,
        needs_root: false,
    },
];

pub fn find(name: &str) -> Option<&'static Preset> {
    let n = name.to_ascii_lowercase();
    PRESETS.iter().find(|p| p.name == n)
}

/// Build a runnable config from a preset + target. Every vector gets
/// [`PRESET_CONCURRENCY`]; the operator can still dump to JSON and edit.
pub fn build_config(
    preset: &Preset,
    target: String,
    proxy: Option<ProxyConfig>,
    duration: Duration,
    rampup: Duration,
) -> RunConfig {
    let vectors = preset
        .vectors
        .iter()
        .map(|&v| {
            let mut tuning = VectorTuning::defaults_for(v);
            tuning.concurrency = PRESET_CONCURRENCY;
            VectorPlan { vector: v, tuning }
        })
        .collect();

    RunConfig {
        target,
        proxy,
        mode: preset.mode,
        run_recon: preset.run_recon,
        vectors,
        duration,
        rampup,
    }
}
