//! Shared raw-socket helpers for the L3/L4 packet vectors.
//!
//! pnet's transport API is synchronous, so each vector runs its send loop on a
//! blocking thread and reads the shared atomics/watch directly. Source IPs are
//! always this host's real address — no spoofing.

use super::net::Target;
use super::{Governor, Metrics, Shutdown};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet_transport::TransportChannelType::Layer4;
use pnet_transport::TransportProtocol::Ipv4;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

/// Cheap, allocation-free PRNG for per-packet randomness.
pub struct XorShift(pub u64);
impl XorShift {
    pub fn seeded(idx: u32) -> Self {
        XorShift(0x9E3779B97F4A7C15 ^ ((idx as u64).wrapping_mul(0x2545F4914F6CDD1D) | 1))
    }
    #[inline]
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// The local IPv4 the kernel would use to reach `dst`, for checksum pseudo-headers.
pub fn local_src_ipv4(dst: SocketAddr) -> Option<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(dst).ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

/// Generic raw TCP flag flood (SYN, ACK, …). Runs the synchronous send loop on
/// a blocking thread. `flags` is a `TcpFlags` bitset.
pub async fn tcp_flag_flood(
    idx: u32,
    target: Arc<Target>,
    metrics: Arc<Metrics>,
    gov: Arc<Governor>,
    shutdown: Arc<Shutdown>,
    flags: u8,
    label: &'static str,
) {
    let _ = tokio::task::spawn_blocking(move || {
        tcp_flag_blocking(idx, target, metrics, gov, shutdown, flags, label)
    })
    .await;
}

fn tcp_flag_blocking(
    idx: u32,
    target: Arc<Target>,
    metrics: Arc<Metrics>,
    gov: Arc<Governor>,
    shutdown: Arc<Shutdown>,
    flags: u8,
    label: &'static str,
) {
    let dst = target.addr;
    let IpAddr::V4(dst_ip) = dst.ip() else {
        warn!("{label}: target is not IPv4 — skipping");
        return;
    };
    let Some(src_ip) = local_src_ipv4(dst) else {
        warn!("{label}: could not determine local IPv4 source — skipping");
        return;
    };
    let dst_port = dst.port();

    let proto = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    let (mut tx, _rx) = match pnet_transport::transport_channel(4096, proto) {
        Ok(ch) => ch,
        Err(e) => {
            warn!(error = %e, "{label}: cannot open raw socket (need root) — skipping");
            return;
        }
    };

    let mut rng = XorShift::seeded(idx);
    let mut buf = [0u8; 20]; // 20-byte TCP header, no options
    let want_ack = flags & TcpFlags::ACK != 0;

    loop {
        if shutdown.is_down() {
            return;
        }
        if !gov.active(idx) {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }

        let r = rng.next();
        let src_port = 1024 + (r % 64_000) as u16;
        let seq = (r >> 16) as u32;

        let mut pkt = MutableTcpPacket::new(&mut buf).expect("20-byte buffer fits a TCP header");
        pkt.set_source(src_port);
        pkt.set_destination(dst_port);
        pkt.set_sequence(seq);
        if want_ack {
            pkt.set_acknowledgement((r ^ 0x5DEECE66D) as u32);
        }
        pkt.set_data_offset(5);
        pkt.set_flags(flags);
        pkt.set_window(64_240);
        let checksum = ipv4_checksum(&pkt.to_immutable(), &src_ip, &dst_ip);
        pkt.set_checksum(checksum);

        metrics.requests_sent.fetch_add(1, Relaxed);
        match tx.send_to(pkt, IpAddr::V4(dst_ip)) {
            Ok(n) => {
                metrics.bytes_sent.fetch_add(n as u64, Relaxed);
                metrics.responses_ok.fetch_add(1, Relaxed);
            }
            Err(_) => {
                metrics.errors.fetch_add(1, Relaxed);
            }
        }
    }
}
