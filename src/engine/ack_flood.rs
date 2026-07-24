//! TCP ACK flood worker (L4, raw socket, requires root/CAP_NET_RAW).
//!
//! Bare ACK segments with random sequence/ack numbers that match no existing
//! connection. Stateful firewalls and conntrack must look each one up, so the
//! pressure lands on connection-state tables rather than bandwidth — the
//! state-exhaustion angle single-origin testing is actually good at.

use super::net::Target;
use super::{Governor, Metrics, Shutdown};
use pnet_packet::tcp::TcpFlags;
use std::sync::Arc;

pub async fn worker(
    idx: u32,
    target: Arc<Target>,
    metrics: Arc<Metrics>,
    gov: Arc<Governor>,
    shutdown: Arc<Shutdown>,
) {
    super::raw::tcp_flag_flood(idx, target, metrics, gov, shutdown, TcpFlags::ACK, "ack_flood").await;
}
