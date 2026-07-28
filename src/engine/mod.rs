//! Load engine.
//!
//! Owns the shared metrics, the cooperative shutdown, the per-vector governor
//! (ramp-up + adaptive throttle), and the sampler that turns raw counters into
//! the collapse curve. Vector workers live in submodules; this module wires
//! them together and paces them.

mod ack_flood;
mod dns_flood;
mod h2_continuation;
mod h2_flood;
mod h2_rapid_reset;
mod histogram;
mod http_flood;
mod icmp_flood;
mod l2;
mod net;
mod packet_mmsg;
mod packet_tx;
mod raw;
mod rudy;
mod slow_read;
mod slowloris;
mod syn_flood;
mod tcp_exhaust;
mod tls_exhaust;
mod udp_flood;
mod wire;
#[cfg(feature = "xdp")]
mod xdp;

use crate::classify::{self, RunContext, Signals};
use crate::config::{RunConfig, RunMode, Vector};
use crate::metrics::{LatencySample, RunOutcome, Snapshot};
use anyhow::Result;
use histogram::Histogram;
use net::Target;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

const SAMPLE_INTERVAL: Duration = Duration::from_millis(250);
/// How long workers get to observe shutdown and exit before we force-abort them.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Lock-free run counters plus the latency histogram. Shared across all workers.
pub struct Metrics {
    pub requests_sent: AtomicU64,
    /// Completed round-trips: an actual response/handshake was received from the
    /// target. Connectionless floods must NOT touch this — see `packets_sent`.
    pub responses_ok: AtomicU64,
    /// Datagrams/packets handed to the local kernel by fire-and-forget vectors
    /// (UDP/DNS/ICMP/raw). This is egress send rate, NOT confirmed delivery, and
    /// is kept separate so it can never be reported as target throughput.
    pub packets_sent: AtomicU64,
    pub errors: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub held_connections: AtomicU32,
    // L7 status distribution (set by http/range/h2 workers) — the classifier's
    // primary application-layer signal.
    pub http_2xx: AtomicU64,
    pub http_3xx: AtomicU64,
    pub http_4xx: AtomicU64,
    pub http_403: AtomicU64,
    pub http_429: AtomicU64,
    pub http_5xx: AtomicU64,
    hist: Histogram,
}

impl Metrics {
    fn new() -> Self {
        Metrics {
            requests_sent: AtomicU64::new(0),
            responses_ok: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            held_connections: AtomicU32::new(0),
            http_2xx: AtomicU64::new(0),
            http_3xx: AtomicU64::new(0),
            http_4xx: AtomicU64::new(0),
            http_403: AtomicU64::new(0),
            http_429: AtomicU64::new(0),
            http_5xx: AtomicU64::new(0),
            hist: Histogram::new(),
        }
    }

    /// Record one request's latency (O(1), lock-free).
    #[inline]
    pub fn record_latency(&self, d: Duration) {
        self.hist.record_us(d.as_micros() as u64);
    }

    /// Record an observed HTTP status code into the class buckets.
    #[inline]
    pub fn record_status(&self, code: u16) {
        let c = match code {
            200..=299 => &self.http_2xx,
            300..=399 => &self.http_3xx,
            403 => &self.http_403,
            429 => &self.http_429,
            400..=499 => &self.http_4xx,
            500..=599 => &self.http_5xx,
            _ => return,
        };
        c.fetch_add(1, Relaxed);
    }
}

/// Sum a `u64` counter across every vector's metrics.
#[inline]
fn agg(metrics: &[Arc<Metrics>], f: impl Fn(&Metrics) -> u64) -> u64 {
    metrics.iter().map(|m| f(m)).sum()
}

/// Headroom of file descriptors to leave free for the runtime, probes, logs, etc.
const FD_HEADROOM: u64 = 128;

/// Right-size total concurrency to the machine's open-file limit. Nearly every
/// worker holds one socket (= one fd); asking for more than the process can open
/// just yields EMFILE storms that look like target failures but are ours. We
/// first try to raise the soft limit toward the hard cap, then return a scale
/// factor (≤ 1.0) to apply to every vector's concurrency if it still won't fit.
fn fd_scale(planned: u64) -> f64 {
    if planned == 0 {
        return 1.0;
    }
    let want = planned + FD_HEADROOM;
    let soft = rlimit::increase_nofile_limit(want).unwrap_or_else(|_| {
        rlimit::Resource::NOFILE.get().map(|(s, _)| s).unwrap_or(1024)
    });
    if want <= soft {
        return 1.0;
    }
    let usable = soft.saturating_sub(FD_HEADROOM).max(1);
    let scale = usable as f64 / planned as f64;
    warn!(
        planned,
        fd_soft_limit = soft,
        scaled_to = usable,
        "planned concurrency exceeds the open-file limit — scaling load down to fit \
         (raise it with `ulimit -n` for full pressure)"
    );
    scale
}

/// RAII counter for open connections: `held_connections` follows scope exactly,
/// so it stays correct even when a worker returns early on error.
pub struct HeldGuard<'a>(&'a AtomicU32);
impl<'a> HeldGuard<'a> {
    #[inline]
    pub fn new(c: &'a AtomicU32) -> Self {
        c.fetch_add(1, Relaxed);
        HeldGuard(c)
    }
}
impl Drop for HeldGuard<'_> {
    #[inline]
    fn drop(&mut self) {
        self.0.fetch_sub(1, Relaxed);
    }
}

/// Cooperative shutdown over a `watch` channel: cheap `is_down()` reads and
/// prompt wakeups with no lost-notification race.
pub struct Shutdown {
    tx: watch::Sender<bool>,
}
impl Shutdown {
    fn new() -> Arc<Self> {
        Arc::new(Shutdown {
            tx: watch::channel(false).0,
        })
    }
    fn trigger(&self) {
        let _ = self.tx.send(true);
    }
    #[inline]
    pub fn is_down(&self) -> bool {
        *self.tx.borrow()
    }
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }
}

/// Per-vector pacing. `target` is the number of workers currently allowed to
/// generate load; workers gate on a single relaxed load. Ramp-up grows it;
/// adaptive throttle shrinks it under distress.
pub struct Governor {
    target: AtomicU32,
    pub max: u32,
}
impl Governor {
    fn new(max: u32) -> Arc<Self> {
        Arc::new(Governor {
            target: AtomicU32::new(0),
            max,
        })
    }
    #[inline]
    pub fn active(&self, idx: u32) -> bool {
        idx < self.target.load(Relaxed)
    }
}

/// Drive a full run to completion (or until Ctrl-C). `ctx` carries recon-derived
/// baseline/WAF hints; pass `RunContext::default()` when recon didn't run.
pub async fn run(cfg: &RunConfig, ctx: RunContext) -> Result<()> {
    let target = Arc::new(Target::resolve(&cfg.target, cfg.proxy.as_ref()).await?);
    info!(addr = %target.addr, tls = target.tls, proxied = target.is_proxied(), "engine: target resolved");

    // SOCKS5 carries only TCP: raw L3/L4 and UDP vectors cannot be proxied and
    // will egress from this host's real address. Warn so the operator isn't
    // misled into thinking those are anonymized/routed.
    if target.is_proxied() {
        let bypass: Vec<&str> = cfg
            .vectors
            .iter()
            .filter(|p| {
                matches!(
                    p.vector,
                    Vector::SynFlood
                        | Vector::AckFlood
                        | Vector::IcmpFlood
                        | Vector::UdpFlood
                        | Vector::DnsFlood
                )
            })
            .map(|p| p.vector.slug())
            .collect();
        if !bypass.is_empty() {
            warn!(
                vectors = bypass.join(","),
                "proxy set but these vectors are raw/UDP — SOCKS5 can't carry them; \
                 they will send directly from this host"
            );
        }
    }

    let shutdown = Shutdown::new();
    // One Metrics per vector: each governor throttles on its OWN vector's signal
    // (no cross-vector contamination), and the sampler/summary aggregate across
    // them. Populated as vectors are spawned below.
    let mut vec_metrics: Vec<Arc<Metrics>> = Vec::new();
    // Ground-truth health probe: baseline the target's connect latency BEFORE
    // load starts, so we can tell whether the run actually affected it.
    let probe_baseline_ms = probe_baseline(target.addr).await;
    info!(baseline_ms = ?probe_baseline_ms, "health probe: baseline");

    // Independent application-layer probe: does the *service* answer real
    // requests? Only meaningful if it answered at baseline; a service down (or
    // not present) at rest disables the signal so it can't produce false
    // findings against pure-L4 targets.
    let service_client = build_service_client();
    let service_baseline_ok = match &service_client {
        Some(c) => service_baseline(c, &cfg.target).await,
        None => false,
    };
    info!(service_baseline_ok, "service probe: baseline");
    let service_points: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));

    let start = Instant::now();
    let samples: Arc<Mutex<Vec<LatencySample>>> = Arc::new(Mutex::new(Vec::with_capacity(1024)));
    let probe_points: Arc<Mutex<Vec<(u64, ProbeOutcome)>>> = Arc::new(Mutex::new(Vec::new()));

    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    // Preflight: size total concurrency to the fd limit (skipping vectors that
    // won't run for lack of root), so we stress the target — not our own sockets.
    let planned: u64 = cfg
        .vectors
        .iter()
        .filter(|p| !p.vector.needs_root() || is_root())
        .map(|p| p.tuning.concurrency as u64)
        .sum();
    let scale = fd_scale(planned);

    // Raw vectors that use the AF_XDP fast path share the NIC's TX queues, and
    // only one socket may own a given (ifindex, queue). Rank each running raw
    // vector so it takes a disjoint slice of the queues instead of colliding.
    let fast_vectors: Vec<Vector> = cfg
        .vectors
        .iter()
        .map(|p| p.vector)
        .filter(|v| matches!(v, Vector::SynFlood | Vector::AckFlood))
        .filter(|v| !v.needs_root() || is_root())
        .collect();
    let fast_groups = fast_vectors.len().max(1) as u32;
    let fast_rank = |v: Vector| fast_vectors.iter().position(|x| *x == v).unwrap_or(0) as u32;

    // Spawn each vector's governor + worker pool.
    for plan in &cfg.vectors {
        let v = plan.vector;
        if v.needs_root() && !is_root() {
            warn!(vector = v.slug(), "requires root — skipping");
            continue;
        }
        // Effective concurrency after fd-budget scaling (≥1 for any requested load).
        let concurrency = if scale >= 1.0 {
            plan.tuning.concurrency
        } else {
            ((plan.tuning.concurrency as f64 * scale) as u32).max(1)
        };
        // Per-vector metrics: shadows the module-level name so every worker spawn
        // below transparently uses this vector's own counters/histogram.
        let metrics = Arc::new(Metrics::new());
        vec_metrics.push(metrics.clone());
        let gov = Governor::new(concurrency);
        handles.push(tokio::spawn(govern(
            gov.clone(),
            metrics.clone(),
            shutdown.clone(),
            cfg.rampup,
            cfg.mode,
            v.has_load_feedback(),
        )));

        match v {
            Vector::HttpFlood | Vector::HttpsOnly => {
                let templates = net::build_get_templates(&target.host, &target.path);
                for idx in 0..concurrency {
                    handles.push(tokio::spawn(http_flood::worker(
                        idx,
                        target.clone(),
                        templates.clone(),
                        metrics.clone(),
                        gov.clone(),
                        shutdown.clone(),
                        plan.tuning.rate_per_worker,
                    )));
                }
            }
            Vector::Slowloris => {
                let head = net::build_slowloris_head(&target.host, &target.path);
                for idx in 0..concurrency {
                    handles.push(tokio::spawn(slowloris::worker(
                        idx,
                        target.clone(),
                        head.clone(),
                        metrics.clone(),
                        gov.clone(),
                        shutdown.clone(),
                        plan.tuning.trickle_interval,
                    )));
                }
            }
            Vector::Rudy => {
                let body_len = plan.tuning.payload_bytes.max(1);
                let head = net::build_rudy_head(&target.host, &target.path, body_len);
                for idx in 0..concurrency {
                    handles.push(tokio::spawn(rudy::worker(
                        idx,
                        target.clone(),
                        head.clone(),
                        metrics.clone(),
                        gov.clone(),
                        shutdown.clone(),
                        plan.tuning.trickle_interval,
                    )));
                }
            }
            Vector::TcpExhaust => {
                for idx in 0..concurrency {
                    handles.push(tokio::spawn(tcp_exhaust::worker(
                        idx,
                        target.clone(),
                        metrics.clone(),
                        gov.clone(),
                        shutdown.clone(),
                    )));
                }
            }
            Vector::TlsExhaust => {
                for idx in 0..concurrency {
                    handles.push(tokio::spawn(tls_exhaust::worker(
                        idx,
                        target.clone(),
                        metrics.clone(),
                        gov.clone(),
                        shutdown.clone(),
                    )));
                }
            }
            Vector::UdpFlood => {
                let port = if plan.tuning.port > 0 {
                    plan.tuning.port
                } else {
                    target.addr.port()
                };
                let dest = SocketAddr::new(target.addr.ip(), port);
                let payload: Arc<[u8]> = vec![0x41u8; plan.tuning.payload_bytes.max(1)].into();
                for idx in 0..concurrency {
                    handles.push(tokio::spawn(udp_flood::worker(
                        idx,
                        dest,
                        payload.clone(),
                        metrics.clone(),
                        gov.clone(),
                        shutdown.clone(),
                        plan.tuning.rate_per_worker,
                    )));
                }
            }
            Vector::DnsFlood => {
                let port = if plan.tuning.port > 0 {
                    plan.tuning.port
                } else {
                    53
                };
                let dest = SocketAddr::new(target.addr.ip(), port);
                let domain: Arc<str> = Arc::from(target.host.as_str());
                for idx in 0..concurrency {
                    handles.push(tokio::spawn(dns_flood::worker(
                        idx,
                        dest,
                        domain.clone(),
                        metrics.clone(),
                        gov.clone(),
                        shutdown.clone(),
                        plan.tuning.rate_per_worker,
                    )));
                }
            }
            Vector::H2RapidReset => {
                for idx in 0..concurrency {
                    handles.push(tokio::spawn(h2_rapid_reset::worker(
                        idx,
                        target.clone(),
                        metrics.clone(),
                        gov.clone(),
                        shutdown.clone(),
                    )));
                }
            }
            Vector::SynFlood => {
                let (rank, groups) = (fast_rank(Vector::SynFlood), fast_groups);
                for idx in 0..concurrency {
                    handles.push(tokio::spawn(syn_flood::worker(
                        idx,
                        target.clone(),
                        metrics.clone(),
                        gov.clone(),
                        shutdown.clone(),
                        rank,
                        groups,
                    )));
                }
            }
            // Range flood reuses the http_flood worker with a Range template.
            Vector::RangeFlood => {
                let templates = net::build_range_templates(&target.host, &target.path);
                for idx in 0..concurrency {
                    handles.push(tokio::spawn(http_flood::worker(
                        idx,
                        target.clone(),
                        templates.clone(),
                        metrics.clone(),
                        gov.clone(),
                        shutdown.clone(),
                        plan.tuning.rate_per_worker,
                    )));
                }
            }
            Vector::SlowRead => {
                let templates = net::build_get_templates(&target.host, &target.path);
                let request: Arc<[u8]> = Arc::from(templates[0].as_ref());
                for idx in 0..concurrency {
                    handles.push(tokio::spawn(slow_read::worker(
                        idx,
                        target.clone(),
                        request.clone(),
                        metrics.clone(),
                        gov.clone(),
                        shutdown.clone(),
                        plan.tuning.trickle_interval,
                    )));
                }
            }
            Vector::H2Flood => {
                for idx in 0..concurrency {
                    handles.push(tokio::spawn(h2_flood::worker(
                        idx,
                        target.clone(),
                        metrics.clone(),
                        gov.clone(),
                        shutdown.clone(),
                    )));
                }
            }
            Vector::AckFlood => {
                let (rank, groups) = (fast_rank(Vector::AckFlood), fast_groups);
                for idx in 0..concurrency {
                    handles.push(tokio::spawn(ack_flood::worker(
                        idx,
                        target.clone(),
                        metrics.clone(),
                        gov.clone(),
                        shutdown.clone(),
                        rank,
                        groups,
                    )));
                }
            }
            Vector::IcmpFlood => {
                for idx in 0..concurrency {
                    handles.push(tokio::spawn(icmp_flood::worker(
                        idx,
                        target.clone(),
                        metrics.clone(),
                        gov.clone(),
                        shutdown.clone(),
                    )));
                }
            }
            Vector::H2Continuation => {
                for idx in 0..concurrency {
                    handles.push(tokio::spawn(h2_continuation::worker(
                        idx,
                        target.clone(),
                        metrics.clone(),
                        gov.clone(),
                        shutdown.clone(),
                    )));
                }
            }
        }
    }

    if handles.is_empty() {
        warn!("no runnable vectors — nothing to do");
        return Ok(());
    }
    let metrics_all: Arc<[Arc<Metrics>]> = vec_metrics.into();
    // Abort handles captured up front: cooperative shutdown is the happy path,
    // but a worker wedged in a blocking network wait must never keep the process
    // (or its traffic) alive — so we force-abort any stragglers after a grace.
    let worker_aborts: Vec<tokio::task::AbortHandle> =
        handles.iter().map(|h| h.abort_handle()).collect();

    // Sampler: turns counters into the collapse curve, 4×/sec.
    let sampler = tokio::spawn(sample(
        metrics_all.clone(),
        shutdown.clone(),
        samples.clone(),
        start,
    ));
    // Independent health probe: checks the target's reachability during the run.
    let prober = tokio::spawn(health_probe(
        target.addr,
        shutdown.clone(),
        probe_points.clone(),
        start,
    ));
    // Independent service probe (only when the app answered at baseline): catches
    // "TCP still accepts but the service is unusable" — the slow-connection case.
    let service_prober = match (&service_client, service_baseline_ok) {
        (Some(c), true) => Some(tokio::spawn(service_probe(
            c.clone(),
            cfg.target.clone(),
            shutdown.clone(),
            service_points.clone(),
        ))),
        _ => None,
    };
    // Optional: watch the probe and prompt to stop the moment a finding appears.
    let monitor = if ctx.stop_on_detect {
        Some(tokio::spawn(detect_monitor(
            probe_points.clone(),
            probe_baseline_ms,
            shutdown.clone(),
        )))
    } else {
        None
    };

    info!("engine live — Ctrl-C to stop");
    wait_for_stop(cfg.duration, shutdown.clone()).await;
    shutdown.trigger();
    info!("stopping — draining workers");

    // Bounded drain: workers should observe shutdown and exit within the grace
    // window; if any are stuck in a blocking read, abort them so traffic stops.
    let drain = async {
        for h in handles {
            let _ = h.await;
        }
    };
    if tokio::time::timeout(SHUTDOWN_GRACE, drain).await.is_err() {
        warn!("workers did not drain within grace — aborting stragglers");
        for a in &worker_aborts {
            a.abort();
        }
    }
    let _ = sampler.await;
    let _ = prober.await;
    if let Some(sp) = service_prober {
        let _ = sp.await;
    }
    if let Some(m) = monitor {
        m.abort();
    }

    let samples = samples.lock().unwrap();
    let outcome = derive_outcome(&samples, ctx.baseline_ms);
    log_summary(&metrics_all, &outcome, start.elapsed());

    // Reduce the health-probe timeline to peak latency + failure counts. Local
    // exhaustion (our box, not the target) is tallied separately so it can never
    // masquerade as a target-down finding.
    let baseline_accepting = probe_baseline_ms.is_some();
    let pts = probe_points.lock().unwrap();
    let probe_total = pts.len() as u32;
    let probe_failures = pts
        .iter()
        .filter(|(_, o)| o.counts_as_failure(baseline_accepting))
        .count() as u32;
    let probe_local = pts.iter().filter(|(_, o)| o.is_local()).count() as u32;
    let probe_peak_ms = pts
        .iter()
        .filter_map(|(_, o)| o.latency_ms())
        .fold(None, |acc: Option<f64>, v| Some(acc.map_or(v, |a| a.max(v))));
    let peak_held = samples.iter().map(|s| s.concurrency).max().unwrap_or(0);

    // Service-probe results: how many independent GETs the app failed to answer.
    let svc = service_points.lock().unwrap();
    let service_checks = svc.len() as u32;
    let service_failures = svc.iter().filter(|ok| !**ok).count() as u32;

    info!(
        peak_held_connections = peak_held,
        bytes_sent = agg(&metrics_all, |m| m.bytes_sent.load(Relaxed)),
        packets_sent = agg(&metrics_all, |m| m.packets_sent.load(Relaxed)),
        probe_checks = probe_total,
        probe_failures,
        probe_local_exhaustion = probe_local,
        probe_peak_ms = ?probe_peak_ms,
        service_baseline_ok,
        service_checks,
        service_failures,
        "target-side"
    );

    // L7 status codes are only produced by vectors that complete a request and
    // read a response. Slow-hold and connectionless vectors never do, so the
    // classifier must lean on the health/service probe for them — not assume
    // "no HTTP signal" means the service is fine.
    let l7_active = cfg.vectors.iter().any(|p| {
        matches!(
            p.vector,
            Vector::HttpFlood
                | Vector::HttpsOnly
                | Vector::RangeFlood
                | Vector::H2Flood
        )
    });
    let signals = Signals {
        requests: agg(&metrics_all, |m| m.requests_sent.load(Relaxed)),
        errors: agg(&metrics_all, |m| m.errors.load(Relaxed)),
        http_2xx: agg(&metrics_all, |m| m.http_2xx.load(Relaxed)),
        http_3xx: agg(&metrics_all, |m| m.http_3xx.load(Relaxed)),
        http_4xx: agg(&metrics_all, |m| m.http_4xx.load(Relaxed)),
        http_403: agg(&metrics_all, |m| m.http_403.load(Relaxed)),
        http_429: agg(&metrics_all, |m| m.http_429.load(Relaxed)),
        http_5xx: agg(&metrics_all, |m| m.http_5xx.load(Relaxed)),
        baseline_ms: ctx.baseline_ms,
        waf_vendor: ctx.waf_vendor.clone(),
        l7_active,
        probe_baseline_ms,
        probe_peak_ms,
        probe_failures,
        probe_local_inconclusive: probe_local,
        probe_total,
        peak_held,
        service_baseline_ok,
        service_checks,
        service_failures,
    };
    let verdict = classify::classify(&signals, &samples);
    info!(
        verdict = verdict.verdict.label(),
        confidence = verdict.confidence,
        finding = verdict.verdict.is_finding(),
        "classification"
    );
    for e in &verdict.evidence {
        info!(evidence = %e);
    }
    Ok(())
}

const PROBE_INTERVAL: Duration = Duration::from_secs(1);
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

// Linux errno values we care about when a probe connect() fails. These let us
// tell a *target-side* failure apart from *our own* box running out of sockets —
// the difference between a real finding and a self-inflicted false positive.
/// Is this connect() errno one of *our* local-resource exhaustion errors (too
/// many fds / no ephemeral port / no buffer space) rather than a target fault?
/// Numbers are OS-specific, so gate them; `AddrNotAvailable` is handled portably
/// via `ErrorKind` in [`classify_connect_error`].
fn is_local_resource_errno(n: Option<i32>) -> bool {
    // EMFILE, ENFILE, ENOBUFS (+ EADDRNOTAVAIL as a fallback when ErrorKind
    // didn't already catch it). These differ between Linux and the BSDs/macOS.
    #[cfg(target_os = "linux")]
    const LOCAL: &[i32] = &[24, 23, 105, 99];
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    const LOCAL: &[i32] = &[24, 23, 55, 49];
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    )))]
    const LOCAL: &[i32] = &[];
    matches!(n, Some(x) if LOCAL.contains(&x))
}

/// Map a failed connect() to who is at fault, portably.
fn classify_connect_error(e: &std::io::Error) -> ProbeOutcome {
    use std::io::ErrorKind;
    match e.kind() {
        // Host answered with a RST — the service is refusing this connection.
        ErrorKind::ConnectionRefused => ProbeOutcome::Refused,
        // No local address/port available — our box, not the target.
        ErrorKind::AddrNotAvailable => ProbeOutcome::LocalExhausted,
        _ if is_local_resource_errno(e.raw_os_error()) => ProbeOutcome::LocalExhausted,
        // Unreachable / reset mid-handshake / anything else — treat as target-side.
        _ => ProbeOutcome::TargetFail,
    }
}

/// The result of one health-probe connect, classified by *who* is at fault.
#[derive(Clone, Copy)]
pub enum ProbeOutcome {
    /// Connected — the target is healthily accepting. Carries connect latency (ms).
    Ok(f64),
    /// Target sent a RST (ECONNREFUSED): reachable at the host level, but the
    /// *service* is refusing this connection. Whether that is a failure depends
    /// on the baseline — see [`ProbeOutcome::counts_as_failure`].
    Refused,
    /// No answer within the timeout, or the network is unreachable — a genuine
    /// target-side failure.
    TargetFail,
    /// Our own machine ran out of sockets/ports/fds. Says nothing about the
    /// target; must be excluded from any "target is down" conclusion.
    LocalExhausted,
}

impl ProbeOutcome {
    /// Connect latency in ms, if we actually connected.
    fn latency_ms(self) -> Option<f64> {
        match self {
            ProbeOutcome::Ok(ms) => Some(ms),
            _ => None,
        }
    }
    /// Does this probe count as a target-side failure? A timeout/unreachable
    /// always does. A RST counts **only if the service was accepting at
    /// baseline**: baseline-Accepting → load-Refused means load knocked the
    /// listener over (a real finding), whereas a target that refused even at
    /// rest was simply never offering the service. Local exhaustion never counts.
    fn counts_as_failure(self, baseline_accepting: bool) -> bool {
        match self {
            ProbeOutcome::TargetFail => true,
            ProbeOutcome::Refused => baseline_accepting,
            _ => false,
        }
    }
    /// Did this probe fail because *our* box ran out of local resources?
    fn is_local(self) -> bool {
        matches!(self, ProbeOutcome::LocalExhausted)
    }
}

/// One TCP connect to the target, classified into [`ProbeOutcome`]. This is the
/// independent, ground-truth measure of whether the target is still accepting
/// connections (and how fast) while under load — it works for every vector,
/// including L4/raw ones that produce no application-layer signal.
async fn probe_once(addr: SocketAddr) -> ProbeOutcome {
    let t0 = Instant::now();
    match tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => ProbeOutcome::Ok(t0.elapsed().as_secs_f64() * 1000.0),
        Ok(Err(e)) => classify_connect_error(&e),
        Err(_) => ProbeOutcome::TargetFail, // our timeout elapsed — target not answering
    }
}

/// Average connect latency over a few probes, measured before load starts. Only
/// successful connects contribute; a target that refuses even at rest has no
/// meaningful latency baseline.
async fn probe_baseline(addr: SocketAddr) -> Option<f64> {
    let mut total = 0.0;
    let mut n = 0u32;
    for _ in 0..3 {
        if let ProbeOutcome::Ok(ms) = probe_once(addr).await {
            total += ms;
            n += 1;
        }
    }
    (n > 0).then(|| total / n as f64)
}

/// Periodic health probe for the duration of the run.
async fn health_probe(
    addr: SocketAddr,
    shutdown: Arc<Shutdown>,
    out: Arc<Mutex<Vec<(u64, ProbeOutcome)>>>,
    start: Instant,
) {
    let mut down = shutdown.subscribe();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(PROBE_INTERVAL) => {}
            _ = down.changed() => return,
        }
        let outcome = probe_once(addr).await;
        out.lock().unwrap().push((start.elapsed().as_millis() as u64, outcome));
    }
}

const SERVICE_TIMEOUT: Duration = Duration::from_secs(4);

/// Independent application-layer health client. Verifies nothing about the
/// TLS cert (we only care whether the *app* answers) and never follows
/// redirects. It is a DIRECT control-plane observer — deliberately not routed
/// through the run's proxy — so it measures the target independently of the
/// path the load takes (and keeps working if the proxy itself is the bottleneck).
fn build_service_client() -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(SERVICE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("OpenNetBench-health/1.0")
        .no_proxy()
        .build()
        .ok()
}

/// One independent GET. `true` = the service answered (any status < 500) within
/// the timeout; `false` = timeout / connect failure / 5xx = the service is not
/// usably serving. This is the signal a TCP connect can't give: a server whose
/// worker pool is exhausted by slowloris still completes TCP handshakes while
/// answering no real requests.
async fn service_probe_once(client: &reqwest::Client, url: &str) -> bool {
    match client.get(url).send().await {
        Ok(resp) => resp.status().as_u16() < 500,
        Err(_) => false,
    }
}

/// Is the application serving normally before load starts? (2 of 3 GETs answer.)
async fn service_baseline(client: &reqwest::Client, url: &str) -> bool {
    let mut ok = 0u32;
    for _ in 0..3 {
        if service_probe_once(client, url).await {
            ok += 1;
        }
    }
    ok >= 2
}

/// Periodic application-layer health probe for the duration of the run.
async fn service_probe(
    client: reqwest::Client,
    url: String,
    shutdown: Arc<Shutdown>,
    out: Arc<Mutex<Vec<bool>>>,
) {
    let mut down = shutdown.subscribe();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(PROBE_INTERVAL) => {}
            _ = down.changed() => return,
        }
        let ok = service_probe_once(&client, &url).await;
        out.lock().unwrap().push(ok);
    }
}

/// `--stop-on-detect` mode: watch the health probe and, the first time it shows
/// a finding (the target stops answering after a healthy baseline, or its
/// connect latency blows up), pause and ask the operator whether to stop.
async fn detect_monitor(
    probe_points: Arc<Mutex<Vec<(u64, ProbeOutcome)>>>,
    baseline: Option<f64>,
    shutdown: Arc<Shutdown>,
) {
    let mut down = shutdown.subscribe();
    let mut asked = false;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            _ = down.changed() => return,
        }
        if asked {
            continue;
        }

        // Look at the last few probes for a sustained failure or latency blowout.
        let (failing, slow) = {
            let pts = probe_points.lock().unwrap();
            if pts.len() < 2 {
                (false, false)
            } else {
                let recent = &pts[pts.len().saturating_sub(3)..];
                // Genuine target-side failures count. A RST counts only if the
                // service was accepting at baseline; our own local socket
                // exhaustion never trips the stop prompt.
                let baseline_accepting = baseline.is_some();
                let failing = recent
                    .iter()
                    .filter(|(_, o)| o.counts_as_failure(baseline_accepting))
                    .count()
                    >= 2;
                let slow = baseline
                    .map(|b| {
                        recent
                            .iter()
                            .filter_map(|(_, o)| o.latency_ms())
                            .any(|ms| ms > b * 3.0 + classify::MIN_DEGRADE_DELTA_MS)
                    })
                    .unwrap_or(false);
                (failing, slow)
            }
        };

        if failing || slow {
            asked = true;
            let reason = if failing { "target stopped answering" } else { "target latency blew up" };
            let sd = shutdown.clone();
            // Prompt off-thread so we don't block the runtime; a non-TTY just
            // continues (returns false).
            let stop = tokio::task::spawn_blocking(move || {
                dialoguer::Confirm::new()
                    .with_prompt(format!("[stop-on-detect] {reason} — stop the run now?"))
                    .default(true)
                    .interact()
                    .unwrap_or(false)
            })
            .await
            .unwrap_or(false);
            if stop {
                info!("stop-on-detect: operator chose to stop");
                sd.trigger();
                return;
            }
            info!("stop-on-detect: operator chose to continue");
        }
    }
}

/// Resolve when either the duration elapses or Ctrl-C is received. A duration of
/// zero means "until stopped".
async fn wait_for_stop(duration: Duration, shutdown: Arc<Shutdown>) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let mut down = shutdown.subscribe();
    if duration.is_zero() {
        tokio::select! {
            _ = ctrl_c => {}
            _ = down.changed() => {}
        }
    } else {
        tokio::select! {
            _ = ctrl_c => {}
            _ = tokio::time::sleep(duration) => {}
            _ = down.changed() => {}
        }
    }
}

/// Governor loop: linear ramp to `max` over `rampup`; in adaptive mode, cut the
/// target hard when the recent error rate spikes and regrow gently — the
/// back-off/regrow cycle is what measures whether the target recovers.
async fn govern(
    gov: Arc<Governor>,
    metrics: Arc<Metrics>,
    shutdown: Arc<Shutdown>,
    rampup: Duration,
    mode: RunMode,
    has_feedback: bool,
) {
    let start = Instant::now();
    let step = (gov.max / 20).max(1);
    let mut last_ok = 0u64;
    let mut last_err = 0u64;
    let mut down = shutdown.subscribe();

    loop {
        if shutdown.is_down() {
            return;
        }
        let elapsed = start.elapsed();
        let ramp_ceiling = if rampup.is_zero() {
            gov.max
        } else {
            let frac = (elapsed.as_secs_f64() / rampup.as_secs_f64()).min(1.0);
            ((frac * gov.max as f64) as u32).max(1)
        };

        // Adaptive throttling needs a target-derived signal. Fire-and-forget
        // vectors (UDP/DNS/ICMP/raw) have none — a local send succeeding says
        // nothing about the target — so they just ramp, never pretend to adapt.
        let next = match mode {
            RunMode::Dumb => ramp_ceiling,
            RunMode::Adaptive if !has_feedback => ramp_ceiling,
            RunMode::Adaptive => {
                // Self-throttle on the honest error rate: completions vs failures,
                // not raw attempts. "Connections going nowhere" (all resets) reads
                // as ~100% error and backs the load off — the intended behavior.
                let ok = metrics.responses_ok.load(Relaxed);
                let err = metrics.errors.load(Relaxed);
                let d_ok = ok - last_ok;
                let d_err = err - last_err;
                last_ok = ok;
                last_err = err;
                let attempts = d_ok + d_err;
                let error_rate = if attempts > 0 {
                    d_err as f64 / attempts as f64
                } else {
                    0.0
                };
                let cur = gov.target.load(Relaxed);
                if error_rate > 0.5 && elapsed > rampup {
                    (cur / 2).max(1) // distress: back off, begin recovery probe
                } else {
                    (cur + step).min(ramp_ceiling)
                }
            }
        };
        gov.target.store(next, Relaxed);

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            _ = down.changed() => return,
        }
    }
}

/// Sampler: every 250 ms, snapshot the histogram, compute windowed p50/p95/p99,
/// derive RPS/error-rate deltas, and append one collapse-curve point.
async fn sample(
    metrics: Arc<[Arc<Metrics>]>,
    shutdown: Arc<Shutdown>,
    out: Arc<Mutex<Vec<LatencySample>>>,
    start: Instant,
) {
    let mut prev = [0u64; histogram::N];
    let mut cur = [0u64; histogram::N];
    let mut last_ok = 0u64;
    let mut last_err = 0u64;
    let mut last_at = Instant::now();
    let mut down = shutdown.subscribe();

    loop {
        tokio::select! {
            _ = tokio::time::sleep(SAMPLE_INTERVAL) => {}
            _ = down.changed() => return,
        }

        // Aggregate every vector's histogram into one collapse-curve window.
        cur.fill(0);
        let mut tmp = [0u64; histogram::N];
        for m in metrics.iter() {
            m.hist.snapshot_into(&mut tmp);
            for i in 0..histogram::N {
                cur[i] += tmp[i];
            }
        }
        let mut delta = [0u64; histogram::N];
        for i in 0..histogram::N {
            delta[i] = cur[i] - prev[i];
        }
        prev.copy_from_slice(&cur);

        let (p50, p95, p99) = histogram::quantiles_ms(&delta);

        // RPS is real throughput — completed responses/sec, NOT connect attempts
        // and NOT fire-and-forget sends. A target that accepts then resets us
        // produces zero completions, so RPS falls toward 0 rather than inflating.
        // Divide by the ACTUAL elapsed window, not a nominal 250 ms — a late
        // wakeup under load would otherwise distort the rate.
        let ok = agg(&metrics, |m| m.responses_ok.load(Relaxed));
        let err = agg(&metrics, |m| m.errors.load(Relaxed));
        let d_ok = ok - last_ok;
        let d_err = err - last_err;
        last_ok = ok;
        last_err = err;
        let now = Instant::now();
        let window_s = now.duration_since(last_at).as_secs_f64().max(1e-3);
        last_at = now;

        let rps = d_ok as f64 / window_s;
        let attempts = d_ok + d_err;
        let error_rate = if attempts > 0 {
            d_err as f64 / attempts as f64
        } else {
            0.0
        };
        let held = agg(&metrics, |m| m.held_connections.load(Relaxed) as u64) as u32;

        let snap = LatencySample {
            t_ms: start.elapsed().as_millis() as u64,
            concurrency: held,
            p50_ms: p50,
            p95_ms: p95,
            p99_ms: p99,
            error_rate,
        };

        info!(rps, p99_ms = p99, held, err_rate = error_rate, "sample");
        out.lock().unwrap().push(snap);
    }
}

/// Post-process the collapse curve into the headline metrics. Best-effort:
/// baseline is the earliest low-error latency; degradation is a sustained 3×
/// breach; recovery is p99 returning within 1.5× baseline afterwards.
fn derive_outcome(samples: &[LatencySample], recon_baseline: Option<f64>) -> RunOutcome {
    let mut o = RunOutcome::default();
    // Prefer the recon pre-load baseline; fall back to the earliest low-error
    // sample when recon didn't run.
    let baseline = recon_baseline.or_else(|| {
        samples
            .iter()
            .find(|s| s.error_rate < 0.1 && s.p99_ms > 0.0)
            .map(|s| s.p99_ms)
    });
    o.baseline_p99_ms = baseline;
    let Some(base) = baseline else { return o };

    // Degradation must be SUSTAINED: mark the knee only after a run of
    // consecutive breaching samples, and time-to-degradation at the run's start.
    // Recovery is symmetric — p99 back within 1.5× baseline for a full run.
    let mut over_run = 0usize;
    let mut over_start: Option<(u64, u32)> = None;
    let mut under_run = 0usize;
    let mut degraded_at: Option<u64> = None;
    for s in samples {
        let breached =
            s.p99_ms > base * 3.0 && s.p99_ms - base > classify::MIN_DEGRADE_DELTA_MS;
        match degraded_at {
            None => {
                if breached {
                    if over_run == 0 {
                        over_start = Some((s.t_ms, s.concurrency));
                    }
                    over_run += 1;
                    if over_run >= classify::DEGRADE_CONSECUTIVE {
                        let (t, knee) = over_start.unwrap_or((s.t_ms, s.concurrency));
                        degraded_at = Some(t);
                        o.time_to_degradation_ms = Some(t);
                        o.knee_concurrency = Some(knee);
                    }
                } else {
                    over_run = 0;
                    over_start = None;
                }
            }
            Some(deg_t) => {
                if s.p99_ms <= base * 1.5 {
                    under_run += 1;
                    if under_run >= classify::DEGRADE_CONSECUTIVE {
                        o.recovery_time_ms = Some(s.t_ms.saturating_sub(deg_t));
                        break;
                    }
                } else {
                    under_run = 0;
                }
            }
        }
    }
    o
}

fn log_summary(metrics: &[Arc<Metrics>], o: &RunOutcome, elapsed: Duration) {
    let sent = agg(metrics, |m| m.requests_sent.load(Relaxed));
    let ok = agg(metrics, |m| m.responses_ok.load(Relaxed));
    let packets = agg(metrics, |m| m.packets_sent.load(Relaxed));
    let errs = agg(metrics, |m| m.errors.load(Relaxed));
    info!("===== run summary =====");
    info!(
        elapsed_s = elapsed.as_secs_f64(),
        requests = sent,
        responses_ok = ok,
        packets_sent = packets,
        errors = errs,
        "totals"
    );
    info!(
        baseline_p99_ms = ?o.baseline_p99_ms,
        time_to_degradation_ms = ?o.time_to_degradation_ms,
        knee_concurrency = ?o.knee_concurrency,
        recovery_time_ms = ?o.recovery_time_ms,
        "findings"
    );
}

/// Snapshot for the (future) web UI. Cheap, lock-free.
pub fn snapshot(metrics: &Metrics) -> Snapshot {
    Snapshot {
        requests_sent: metrics.requests_sent.load(Relaxed),
        responses_ok: metrics.responses_ok.load(Relaxed),
        errors: metrics.errors.load(Relaxed),
        held_connections: metrics.held_connections.load(Relaxed),
        current_rps: 0.0,
        latest: None,
    }
}

/// Best-effort root check (Unix) for raw-socket vectors.
fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(unix)]
extern "C" {
    fn geteuid() -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RunConfig, RunMode, Vector, VectorPlan, VectorTuning};
    use std::sync::atomic::AtomicU64;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Minimal keep-alive HTTP/1.1 server that counts completed requests.
    async fn spawn_server(hits: Arc<AtomicU64>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let hits = hits.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                            hits.fetch_add(1, Relaxed);
                            if sock
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn http_flood_generates_and_measures_traffic() {
        let hits = Arc::new(AtomicU64::new(0));
        let port = spawn_server(hits.clone()).await;

        let cfg = RunConfig {
            target: format!("http://127.0.0.1:{port}/"),
            proxy: None,
            mode: RunMode::Dumb,
            run_recon: false,
            vectors: vec![VectorPlan {
                vector: Vector::HttpFlood,
                tuning: VectorTuning {
                    concurrency: 4,
                    rate_per_worker: 0,
                    payload_bytes: 0,
                    trickle_interval: Duration::from_secs(1),
                    port: 0,
                },
            }],
            duration: Duration::from_millis(700),
            rampup: Duration::from_millis(50),
        };

        run(&cfg, RunContext::default()).await.unwrap();
        assert!(
            hits.load(Relaxed) > 0,
            "server received no requests — engine produced no traffic"
        );
    }

    #[test]
    fn histogram_quantiles_are_monotonic() {
        let h = Histogram::new();
        for us in [500u64, 1_000, 2_000, 50_000, 500_000] {
            for _ in 0..100 {
                h.record_us(us);
            }
        }
        let mut snap = [0u64; histogram::N];
        h.snapshot_into(&mut snap);
        let (p50, p95, p99) = histogram::quantiles_ms(&snap);
        assert!(p50 > 0.0 && p50 <= p95 && p95 <= p99, "p50={p50} p95={p95} p99={p99}");
    }
}
