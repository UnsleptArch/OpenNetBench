//! WebSocket exhaustion worker (L7).
//!
//! Completes a real RFC 6455 upgrade handshake, then holds the connection open
//! and trickles small masked frames to keep it alive. Every held socket occupies
//! a server-side WebSocket session (per-connection buffers, a task/goroutine,
//! connection-table state) that a plain HTTP request never ties up, so a pool of
//! these starves a server's WebSocket capacity the way slowloris starves its HTTP
//! worker pool. The keepalive frames also exercise the per-frame parse path.
//!
//! Hand-rolled: the handshake is one GET with the Upgrade headers (built in
//! `net`), and client frames are masked per the spec. The worker checks for
//! "101 Switching Protocols" and does not validate `Sec-WebSocket-Accept` — it is
//! generating load, not acting as a conformant client. Like every other L7
//! worker here, each connect/read/write races the stop signal so shutdown
//! cancels a parked worker instantly instead of the drain force-aborting it.

use super::net::Target;
use super::{Governor, HeldGuard, Metrics, Shutdown};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A minimal masked client ping with an empty payload: FIN|ping (0x89),
/// MASK|len0 (0x80), then the 4-byte masking key. The spec requires client frames
/// to be masked; it does not require the mask to be random (randomness is a
/// security property irrelevant to load generation), so a fixed key is fine.
const PING_FRAME: [u8; 6] = [0x89, 0x80, 0x37, 0xfa, 0x21, 0x3d];

/// Bound the handshake response read so a target that accepts the upgrade but
/// stalls can't pin a worker (shutdown-racing covers the stop case separately).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn worker(
    idx: u32,
    target: Arc<Target>,
    handshake: Arc<[u8]>,
    metrics: Arc<Metrics>,
    gov: Arc<Governor>,
    shutdown: Arc<Shutdown>,
    frame_interval: Duration,
) {
    let mut down = shutdown.subscribe();
    let mut scratch = [0u8; 512];

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

        // Connect — race the stop signal so shutdown cancels a pending connect.
        let mut conn = tokio::select! {
            r = target.connect() => match r {
                Ok(c) => c,
                Err(_) => {
                    metrics.errors.fetch_add(1, Relaxed);
                    tokio::select! {
                        _ = down.changed() => return,
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                    }
                    continue;
                }
            },
            _ = down.changed() => return,
        };

        metrics.requests_sent.fetch_add(1, Relaxed);
        let wrote = tokio::select! {
            r = conn.write_all(&handshake) => r.is_ok(),
            _ = down.changed() => return,
        };
        if !wrote {
            metrics.errors.fetch_add(1, Relaxed);
            continue;
        }
        metrics.bytes_sent.fetch_add(handshake.len() as u64, Relaxed);

        // Read the response and confirm the upgrade (101). Bounded + racing stop.
        let n = tokio::select! {
            r = tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.read(&mut scratch)) => match r {
                Ok(Ok(n)) => n,
                _ => {
                    metrics.errors.fetch_add(1, Relaxed);
                    continue;
                }
            },
            _ = down.changed() => return,
        };
        if !is_switching_protocols(&scratch[..n]) {
            // 4xx/5xx (not a WebSocket endpoint) or a closed connection.
            metrics.errors.fetch_add(1, Relaxed);
            continue;
        }
        metrics.responses_ok.fetch_add(1, Relaxed);

        // Upgraded. Hold the session open and trickle keepalive frames until the
        // server drops us or we're told to stop.
        let _held = HeldGuard::new(&metrics.held_connections);
        loop {
            tokio::select! {
                _ = tokio::time::sleep(frame_interval) => {}
                r = conn.read(&mut scratch) => match r {
                    Ok(0) | Err(_) => break,   // server closed → reconnect
                    Ok(_) => continue,         // server frame (pong/data); keep holding
                },
                _ = down.changed() => return,
            }
            let sent = tokio::select! {
                r = conn.write_all(&PING_FRAME) => r.is_ok(),
                _ = down.changed() => return,
            };
            if !sent {
                break;
            }
            metrics.requests_sent.fetch_add(1, Relaxed);
            metrics.bytes_sent.fetch_add(PING_FRAME.len() as u64, Relaxed);
        }
    }
}

/// True if the response begins with an HTTP 101 status line (any 1.x version).
fn is_switching_protocols(buf: &[u8]) -> bool {
    buf.starts_with(b"HTTP/1.1 101") || buf.starts_with(b"HTTP/1.0 101")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_101_upgrade() {
        assert!(is_switching_protocols(b"HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(is_switching_protocols(b"HTTP/1.0 101 Web Socket Protocol Handshake\r\n"));
        assert!(!is_switching_protocols(b"HTTP/1.1 404 Not Found\r\n"));
        assert!(!is_switching_protocols(b"HTTP/1.1 200 OK\r\n"));
        assert!(!is_switching_protocols(b""));
    }

    #[test]
    fn ping_frame_is_a_masked_empty_ping() {
        assert_eq!(PING_FRAME[0], 0x89, "FIN | ping opcode");
        assert_eq!(PING_FRAME[1], 0x80, "MASK bit set, zero-length payload");
        assert_eq!(PING_FRAME.len(), 6, "2-byte header + 4-byte mask, no payload");
    }
}
