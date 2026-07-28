//! Transmit backend seam for the stateless packet vectors.
//!
//! `PacketTx` is the boundary between a vector's per-packet L4 bytes and the
//! wire. Two backends implement it, both entering at the driver so they bypass
//! the IP stack, netfilter OUTPUT, and local conntrack (so a unique-flow flood
//! doesn't thrash *our own* state table — finding F2):
//!
//! - [`AfPacketMmsg`](super::packet_mmsg::AfPacketMmsg) — batched AF_PACKET
//!   (`sendmmsg` + `PACKET_QDISC_BYPASS`); the "any NIC" fast path.
//! - [`XdpTx`](super::xdp::XdpTx) — AF_XDP TX ring (`--features xdp`); the
//!   line-rate path on XDP-capable NICs.
//!
//! A vector picks a backend once at startup and logs which one it got.

use std::io;

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
