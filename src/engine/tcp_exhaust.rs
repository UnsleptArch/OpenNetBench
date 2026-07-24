//! TCP connection-exhaustion worker (L4).
//!
//! Opens a bare TCP connection and holds it open, occupying an entry in the
//! server's accept backlog / connection table, then parks on a read so it stays
//! open until the server drops it (read returns 0) or shutdown fires. No bytes
//! are sent — this stresses connection *state*, not bandwidth.

use super::net::Target;
use super::{Governor, HeldGuard, Metrics, Shutdown};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

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

        let mut stream = match TcpStream::connect(target.addr).await {
            Ok(s) => s,
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

        // Hold until the peer closes (read yields 0) or we're told to stop.
        let mut scratch = [0u8; 64];
        tokio::select! {
            r = stream.read(&mut scratch) => {
                if matches!(r, Ok(0) | Err(_)) {
                    // peer dropped us; loop reconnects
                }
            }
            _ = down.changed() => return,
        }
    }
}
