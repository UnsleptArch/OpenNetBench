//! ICMP echo flood worker (L3, raw socket, requires root/CAP_NET_RAW).
//!
//! Emits ICMP echo requests (pings) to the target from this host's real source
//! address. Synchronous pnet send loop on a blocking thread, like the TCP raw
//! vectors.

use super::net::Target;
use super::raw::XorShift;
use super::{Governor, Metrics, Shutdown};
use pnet_packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet_packet::icmp::{checksum, IcmpPacket, IcmpTypes};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_transport::TransportChannelType::Layer4;
use pnet_transport::TransportProtocol::Ipv4;
use std::net::IpAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

const PAYLOAD_LEN: usize = 56; // classic ping payload size
const PKT_LEN: usize = 8 + PAYLOAD_LEN;

pub async fn worker(
    idx: u32,
    target: Arc<Target>,
    metrics: Arc<Metrics>,
    gov: Arc<Governor>,
    shutdown: Arc<Shutdown>,
) {
    let _ = tokio::task::spawn_blocking(move || run_blocking(idx, target, metrics, gov, shutdown))
        .await;
}

fn run_blocking(
    idx: u32,
    target: Arc<Target>,
    metrics: Arc<Metrics>,
    gov: Arc<Governor>,
    shutdown: Arc<Shutdown>,
) {
    let IpAddr::V4(dst_ip) = target.addr.ip() else {
        warn!("icmp_flood: target is not IPv4 — skipping");
        return;
    };

    let proto = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, _rx) = match pnet_transport::transport_channel(4096, proto) {
        Ok(ch) => ch,
        Err(e) => {
            warn!(error = %e, "icmp_flood: cannot open raw socket (need root) — skipping");
            return;
        }
    };

    let mut rng = XorShift::seeded(idx);
    let mut buf = [0u8; PKT_LEN];

    loop {
        if shutdown.is_down() {
            return;
        }
        if !gov.active(idx) {
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
                metrics.responses_ok.fetch_add(1, Relaxed);
            }
            Err(_) => {
                metrics.errors.fetch_add(1, Relaxed);
            }
        }
    }
}
