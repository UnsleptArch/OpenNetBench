//! Transmit backends for the stateless packet vectors.
//!
//! `PacketTx` is the seam between a vector's per-packet L4 bytes and the wire.
//! Today there are two backends; a batched AF_XDP backend will slot in as a
//! third without touching the vectors:
//!
//! - **`AfPacket`** — injects a full Ethernet frame via an `AF_PACKET` raw
//!   socket (`pnet_datalink`). Because it enters at the driver, it **bypasses
//!   the IP stack, netfilter OUTPUT, and local conntrack** — so a unique-flow
//!   flood no longer thrashes *our own* connection table (finding F2), which is
//!   what capped the earlier router run. Same syscall-per-packet cost as the
//!   legacy path; the win is removing the local state explosion.
//! - **legacy** — the vector keeps its existing `pnet_transport` Layer-4 send
//!   (the kernel builds IP + L2). Used as the fallback whenever full-frame
//!   injection can't be set up (no root, L2 unresolved, unknown interface).
//!
//! The vector picks a backend once at startup and logs which one it got.

use super::l2::L2Route;
use super::wire::{self, FramePrefix};
use anyhow::{anyhow, Result};
use pnet_datalink::{Channel, DataLinkSender};
use std::io;
use std::net::Ipv4Addr;

/// A backend that transmits one packet given its L4 header+payload bytes.
pub trait PacketTx: Send {
    /// Transmit one packet whose bytes-after-IP (the L4 header + payload) are
    /// `l4`. Backends that own the whole frame prepend their cached L2/L3 prefix.
    /// Returns `Ok(true)` when the frame was enqueued to the wire, `Ok(false)`
    /// when it was dropped for backpressure (TX ring / driver buffer full). The
    /// caller must NOT count a `false` as sent — that's what inflated the raw
    /// packet counts to fantasy rates.
    fn send_l4(&mut self, l4: &[u8]) -> io::Result<bool>;
    /// Human-readable backend name, for the run log.
    fn mode(&self) -> &'static str;
}

/// Full-frame injection over an `AF_PACKET` raw socket.
pub struct AfPacket {
    tx: Box<dyn DataLinkSender>,
    prefix: [u8; wire::FRAME_PREFIX_LEN],
    frame: Vec<u8>,
}

impl AfPacket {
    /// Build a full-frame sender for a fixed shape: fixed L4 length `l4_len`,
    /// IP protocol `proto`, toward `dst_ip` via the resolved L2 `route`.
    pub fn new(
        route: &L2Route,
        dst_ip: Ipv4Addr,
        proto: u8,
        l4_len: usize,
        ttl: u8,
    ) -> Result<Self> {
        let iface = pnet_datalink::interfaces()
            .into_iter()
            .find(|i| i.name == route.iface)
            .ok_or_else(|| anyhow!("interface {} not found", route.iface))?;
        let tx = match pnet_datalink::channel(&iface, Default::default()) {
            Ok(Channel::Ethernet(tx, _rx)) => tx,
            Ok(_) => return Err(anyhow!("unexpected datalink channel type")),
            Err(e) => return Err(anyhow!("opening AF_PACKET on {}: {e}", route.iface)),
        };
        let prefix = FramePrefix::new(
            route.next_hop_mac,
            route.src_mac,
            route.src_ip,
            dst_ip,
            proto,
            l4_len,
            ttl,
        );
        let mut prefix_bytes = [0u8; wire::FRAME_PREFIX_LEN];
        prefix_bytes.copy_from_slice(prefix.as_bytes());
        Ok(AfPacket {
            tx,
            prefix: prefix_bytes,
            frame: Vec::with_capacity(wire::FRAME_PREFIX_LEN + l4_len),
        })
    }
}

impl PacketTx for AfPacket {
    #[inline]
    fn send_l4(&mut self, l4: &[u8]) -> io::Result<bool> {
        self.frame.clear();
        self.frame.extend_from_slice(&self.prefix);
        self.frame.extend_from_slice(l4);
        match self.tx.send_to(&self.frame, None) {
            Some(res) => res.map(|()| true),
            None => Ok(false), // no packet queued (buffer full) — a drop, not a send
        }
    }
    fn mode(&self) -> &'static str {
        "af_packet (full-frame, bypasses conntrack)"
    }
}
