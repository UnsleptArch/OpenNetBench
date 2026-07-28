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

        let tcp = match target.connect_tcp().await {
            Ok(s) => s,
            Err(_) => {
                metrics.errors.fetch_add(1, Relaxed);
                continue;
            }
        };

        match target
            .connector
            .connect(target.server_name.clone(), tcp)
            .await
        {
            Ok(stream) => {
                metrics.record_latency(t0.elapsed());
                metrics.responses_ok.fetch_add(1, Relaxed);
                drop(stream); // tear down immediately, force a fresh handshake next
            }
            Err(_) => {
                metrics.errors.fetch_add(1, Relaxed);
            }
        }
    }
}
