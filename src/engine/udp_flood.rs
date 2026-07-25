//! UDP flood worker (L4).
//!
//! Sends a pre-built datagram to the target as fast as the governor and
//! optional per-worker rate allow. The payload is built once and shared; the
//! socket is `connect`ed so each send is a single syscall with no per-packet
//! address handling. No spoofing — the source is this host's real address.

use super::{Governor, Metrics, Shutdown};
use std::net::SocketAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

pub async fn worker(
    idx: u32,
    dest: SocketAddr,
    payload: Arc<[u8]>,
    metrics: Arc<Metrics>,
    gov: Arc<Governor>,
    shutdown: Arc<Shutdown>,
    rate_per_worker: u32,
) {
    let mut down = shutdown.subscribe();
    let bind: SocketAddr = if dest.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = match UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(_) => {
            metrics.errors.fetch_add(1, Relaxed);
            return;
        }
    };
    sock.connect(dest).await.ok();

    let interval =
        (rate_per_worker > 0).then(|| Duration::from_secs_f64(1.0 / rate_per_worker as f64));
    let mut next_tick = tokio::time::Instant::now();

    loop {
        if *down.borrow() {
            return;
        }
        if !gov.active(idx) {
            tokio::select! {
                _ = down.changed() => {}
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
            continue;
        }
        if let Some(iv) = interval {
            tokio::select! {
                _ = tokio::time::sleep_until(next_tick) => {}
                _ = down.changed() => return,
            }
            next_tick += iv;
        }

        metrics.requests_sent.fetch_add(1, Relaxed);
        match sock.send(&payload).await {
            Ok(n) => {
                metrics.bytes_sent.fetch_add(n as u64, Relaxed);
                metrics.responses_ok.fetch_add(1, Relaxed);
            }
            Err(_) => {
                metrics.errors.fetch_add(1, Relaxed);
                // A closed/unreachable UDP port returns ECONNREFUSED instantly;
                // without a tiny backoff this spins millions of failing syscalls
                // per second, burning CPU for nothing.
                tokio::time::sleep(Duration::from_micros(200)).await;
            }
        }
    }
}
