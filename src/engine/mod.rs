//! Load engine.
//!
//! Owns the shared metrics, the cooperative shutdown, the per-vector governor
//! (ramp-up + adaptive throttle), and the sampler that turns raw counters into
//! the collapse curve. Vector workers live in submodules; this module wires
//! them together and paces them.

mod histogram;
mod http_flood;
mod net;
mod slowloris;

use crate::config::{RunConfig, RunMode, Vector};
use crate::metrics::{LatencySample, RunOutcome, Snapshot};
use anyhow::Result;
use histogram::Histogram;
use net::Target;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

const SAMPLE_INTERVAL: Duration = Duration::from_millis(250);

/// Lock-free run counters plus the latency histogram. Shared across all workers.
pub struct Metrics {
    pub requests_sent: AtomicU64,
    pub responses_ok: AtomicU64,
    pub errors: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub held_connections: AtomicU32,
    hist: Histogram,
}

impl Metrics {
    fn new() -> Self {
        Metrics {
            requests_sent: AtomicU64::new(0),
            responses_ok: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            held_connections: AtomicU32::new(0),
            hist: Histogram::new(),
        }
    }

    /// Record one request's latency (O(1), lock-free).
    #[inline]
    pub fn record_latency(&self, d: Duration) {
        self.hist.record_us(d.as_micros() as u64);
    }
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

/// Drive a full run to completion (or until Ctrl-C).
pub async fn run(cfg: &RunConfig) -> Result<()> {
    let target = Arc::new(Target::resolve(&cfg.target).await?);
    info!(addr = %target.addr, tls = target.tls, "engine: target resolved");

    let metrics = Arc::new(Metrics::new());
    let shutdown = Shutdown::new();
    let start = Instant::now();
    let samples: Arc<Mutex<Vec<LatencySample>>> = Arc::new(Mutex::new(Vec::with_capacity(1024)));

    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    // Spawn each vector's governor + worker pool.
    for plan in &cfg.vectors {
        let v = plan.vector;
        if v.needs_root() && !is_root() {
            warn!(vector = v.slug(), "requires root — skipping");
            continue;
        }
        let gov = Governor::new(plan.tuning.concurrency);
        handles.push(tokio::spawn(govern(
            gov.clone(),
            metrics.clone(),
            shutdown.clone(),
            cfg.rampup,
            cfg.mode,
        )));

        match v {
            Vector::HttpFlood | Vector::HttpsOnly => {
                let templates = net::build_get_templates(&target.host, &target.path);
                for idx in 0..plan.tuning.concurrency {
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
                for idx in 0..plan.tuning.concurrency {
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
            other => warn!(vector = other.slug(), "vector not yet implemented — skipping"),
        }
    }

    if handles.is_empty() {
        warn!("no runnable vectors — nothing to do");
        return Ok(());
    }

    // Sampler: turns counters into the collapse curve, 4×/sec.
    let sampler = tokio::spawn(sample(
        metrics.clone(),
        shutdown.clone(),
        samples.clone(),
        start,
    ));

    info!("engine live — Ctrl-C to stop");
    wait_for_stop(cfg.duration, shutdown.clone()).await;
    shutdown.trigger();
    info!("stopping — draining workers");

    for h in handles {
        let _ = h.await;
    }
    let _ = sampler.await;

    let outcome = derive_outcome(&samples.lock().unwrap());
    log_summary(&metrics, &outcome, start.elapsed());
    Ok(())
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
) {
    let start = Instant::now();
    let step = (gov.max / 20).max(1);
    let mut last_sent = 0u64;
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

        let next = match mode {
            RunMode::Dumb => ramp_ceiling,
            RunMode::Adaptive => {
                let sent = metrics.requests_sent.load(Relaxed);
                let err = metrics.errors.load(Relaxed);
                let d_sent = sent - last_sent;
                let d_err = err - last_err;
                last_sent = sent;
                last_err = err;
                let error_rate = if d_sent > 0 {
                    d_err as f64 / d_sent as f64
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
    metrics: Arc<Metrics>,
    shutdown: Arc<Shutdown>,
    out: Arc<Mutex<Vec<LatencySample>>>,
    start: Instant,
) {
    let mut prev = [0u64; histogram::N];
    let mut cur = [0u64; histogram::N];
    let mut last_sent = 0u64;
    let mut last_err = 0u64;
    let mut down = shutdown.subscribe();

    loop {
        tokio::select! {
            _ = tokio::time::sleep(SAMPLE_INTERVAL) => {}
            _ = down.changed() => return,
        }

        metrics.hist.snapshot_into(&mut cur);
        let mut delta = [0u64; histogram::N];
        for i in 0..histogram::N {
            delta[i] = cur[i] - prev[i];
        }
        prev.copy_from_slice(&cur);

        let (p50, p95, p99) = histogram::quantiles_ms(&delta);

        let sent = metrics.requests_sent.load(Relaxed);
        let err = metrics.errors.load(Relaxed);
        let d_sent = sent - last_sent;
        let d_err = err - last_err;
        last_sent = sent;
        last_err = err;

        let rps = d_sent as f64 / SAMPLE_INTERVAL.as_secs_f64();
        let error_rate = if d_sent > 0 {
            d_err as f64 / d_sent as f64
        } else {
            0.0
        };
        let held = metrics.held_connections.load(Relaxed);

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
fn derive_outcome(samples: &[LatencySample]) -> RunOutcome {
    let mut o = RunOutcome::default();
    let baseline = samples
        .iter()
        .find(|s| s.error_rate < 0.1 && s.p99_ms > 0.0)
        .map(|s| s.p99_ms);
    o.baseline_p99_ms = baseline;
    let Some(base) = baseline else { return o };

    let mut degraded_at: Option<u64> = None;
    for s in samples {
        match degraded_at {
            None => {
                if s.p99_ms > base * 3.0 {
                    degraded_at = Some(s.t_ms);
                    o.time_to_degradation_ms = Some(s.t_ms);
                    o.knee_concurrency = Some(s.concurrency);
                }
            }
            Some(deg_t) => {
                if s.p99_ms <= base * 1.5 {
                    o.recovery_time_ms = Some(s.t_ms.saturating_sub(deg_t));
                    break;
                }
            }
        }
    }
    o
}

fn log_summary(metrics: &Metrics, o: &RunOutcome, elapsed: Duration) {
    let sent = metrics.requests_sent.load(Relaxed);
    let ok = metrics.responses_ok.load(Relaxed);
    let errs = metrics.errors.load(Relaxed);
    info!("===== run summary =====");
    info!(
        elapsed_s = elapsed.as_secs_f64(),
        requests = sent,
        ok,
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

        run(&cfg).await.unwrap();
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
