//! TCP SYN flood worker (L4, raw socket, requires root/CAP_NET_RAW).
//!
//! Emits bare SYNs to the target port, bypassing the kernel's connection
//! tracking. The source IP is this host's REAL address — no spoofing (spoofing
//! is incompatible with the single-origin safety model and breaks the vector,
//! since the SYN-ACK would go elsewhere). Delegates to the shared raw sender.

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
    super::raw::tcp_flag_flood(idx, target, metrics, gov, shutdown, TcpFlags::SYN, "syn_flood").await;
}
