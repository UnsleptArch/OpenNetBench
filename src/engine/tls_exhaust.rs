//! TLS handshake-exhaustion worker (L4/5).
//!
//! Completes a full TLS handshake then immediately drops it, over and over. The
//! asymmetry is the point: the handshake costs the server real asymmetric CPU
//! (key exchange, signature) for very little client effort. Latency here is the
//! handshake time, which is exactly the server cost we want to surface.

use super::net::Target;
use super::{Governor, Metrics, Shutdown};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub async fn worker(
    idx: u32,
    target: Arc<Target>,
    metrics: Arc<Metrics>,
    gov: Arc<Governor>,
    shutdown: Arc<Shutdown>,
) {
    let mut down = shutdown.subscribe();

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

        let t0 = Instant::now();
        metrics.requests_sent.fetch_add(1, Relaxed);

        // Both the TCP connect and the TLS handshake must race the stop signal —
        // against an overwhelmed target either can park for the full connect
        // timeout (or, for the handshake, forever), and an unraced worker won't
        // drain until the grace window force-aborts it (the run's overshoot).
        let tcp = tokio::select! {
            r = target.connect_tcp() => match r {
                Ok(s) => s,
                Err(_) => {
                    metrics.errors.fetch_add(1, Relaxed);
                    continue;
                }
            },
            _ = down.changed() => return,
        };

        let handshake = target.connector.connect(target.server_name.clone(), tcp);
        tokio::select! {
            r = tokio::time::timeout(super::net::CONNECT_TIMEOUT, handshake) => match r {
                Ok(Ok(stream)) => {
                    metrics.record_latency(t0.elapsed());
                    metrics.responses_ok.fetch_add(1, Relaxed);
                    drop(stream); // tear down immediately, force a fresh handshake next
                }
                _ => {
                    metrics.errors.fetch_add(1, Relaxed);
                }
            },
            _ = down.changed() => return,
        }
    }
}
