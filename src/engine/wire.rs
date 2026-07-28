//! Full L2/L3 frame construction for the fast packet-transmit path.
//!
//! On the ordinary socket path the kernel builds the Ethernet + IPv4 headers for
//! us. The fast paths (AF_PACKET today, AF_XDP next) inject at the driver, so we
//! must build the whole frame ourselves. This module is that builder: pure,
//! allocation-free, and unit-tested against known-good bytes — so the
//! unsafe/hardware transmit backends can rely on the framing being correct.

use std::net::Ipv4Addr;

pub const ETH_HDR_LEN: usize = 14;
pub const IPV4_HDR_LEN: usize = 20;
pub const FRAME_PREFIX_LEN: usize = ETH_HDR_LEN + IPV4_HDR_LEN; // 34
pub const ETHERTYPE_IPV4: u16 = 0x0800;

/// One's-complement Internet checksum (RFC 1071) over `data`, folded to 16 bits.
/// A header that already carries its correct checksum sums to 0 by this function.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8; // odd byte is high-order
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a 14-byte Ethernet II header.
pub fn eth_header(dst_mac: [u8; 6], src_mac: [u8; 6], ethertype: u16) -> [u8; ETH_HDR_LEN] {
    let mut h = [0u8; ETH_HDR_LEN];
    h[0..6].copy_from_slice(&dst_mac);
    h[6..12].copy_from_slice(&src_mac);
    h[12..14].copy_from_slice(&ethertype.to_be_bytes());
    h
}

/// Build a 20-byte IPv4 header (no options) with a correct header checksum.
/// `l4_len` is the length of everything after the IP header (the L4 header +
/// payload); the IP checksum covers only the 20-byte IP header.
pub fn ipv4_header(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    l4_len: u16,
    id: u16,
    ttl: u8,
) -> [u8; IPV4_HDR_LEN] {
    let mut h = [0u8; IPV4_HDR_LEN];
    h[0] = 0x45; // IPv4, IHL = 5 (20 bytes, no options)
    h[1] = 0x00; // DSCP / ECN
    let total = IPV4_HDR_LEN as u16 + l4_len;
    h[2..4].copy_from_slice(&total.to_be_bytes());
    h[4..6].copy_from_slice(&id.to_be_bytes());
    h[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment, offset 0
    h[8] = ttl;
    h[9] = proto;
    // h[10..12] checksum stays 0 while we compute it
    h[12..16].copy_from_slice(&src.octets());
    h[16..20].copy_from_slice(&dst.octets());
    let ck = checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h
}

/// A precomputed Ethernet+IPv4 prefix for a fixed shape (addresses, protocol,
/// L4 length) — the constant 34 bytes prepended to every packet of a flood.
/// Built once; the hot path only concatenates it with the per-packet L4 bytes.
#[derive(Clone)]
pub struct FramePrefix {
    bytes: [u8; FRAME_PREFIX_LEN],
}

impl FramePrefix {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dst_mac: [u8; 6],
        src_mac: [u8; 6],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        proto: u8,
        l4_len: usize,
        ttl: u8,
    ) -> Self {
        let eth = eth_header(dst_mac, src_mac, ETHERTYPE_IPV4);
        let ip = ipv4_header(src_ip, dst_ip, proto, l4_len as u16, 0, ttl);
        let mut bytes = [0u8; FRAME_PREFIX_LEN];
        bytes[0..ETH_HDR_LEN].copy_from_slice(&eth);
        bytes[ETH_HDR_LEN..].copy_from_slice(&ip);
        FramePrefix { bytes }
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_known_ipv4_header() {
        // A concrete IPv4 header with the checksum field zeroed; the expected
        // value is hand-verified (and cross-checked by the self-checksum-to-zero
        // test: header + this checksum folds to 0).
        let hdr: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(checksum(&hdr), 0x9c5d);
        // And inserting it makes the whole header check to zero.
        let mut full = hdr;
        full[10..12].copy_from_slice(&0x9c5du16.to_be_bytes());
        assert_eq!(checksum(&full), 0);
    }

    #[test]
    fn built_ipv4_header_self_checksums_to_zero() {
        // A header carrying its own correct checksum sums to zero.
        let h = ipv4_header(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 254),
            6,
            20,
            0,
            64,
        );
        assert_eq!(checksum(&h), 0);
    }

    #[test]
    fn ipv4_total_length_and_proto() {
        let h = ipv4_header(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 17, 8, 0, 64);
        assert_eq!(u16::from_be_bytes([h[2], h[3]]), 20 + 8); // total length
        assert_eq!(h[9], 17); // proto = UDP
        assert_eq!(h[0], 0x45); // v4, IHL 5
    }

    #[test]
    fn checksum_handles_odd_length() {
        // Odd trailing byte must be treated as the high-order octet of a word.
        assert_eq!(checksum(&[0x00]), checksum(&[0x00, 0x00]));
        assert_ne!(checksum(&[0xff]), checksum(&[0x00, 0xff]));
    }

    #[test]
    fn frame_prefix_layout() {
        let p = FramePrefix::new(
            [0xaa; 6],
            [0xbb; 6],
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            6,
            20,
            64,
        );
        let b = p.as_bytes();
        assert_eq!(b.len(), FRAME_PREFIX_LEN);
        assert_eq!(&b[0..6], &[0xaa; 6]); // dst mac
        assert_eq!(&b[6..12], &[0xbb; 6]); // src mac
        assert_eq!(u16::from_be_bytes([b[12], b[13]]), ETHERTYPE_IPV4);
        assert_eq!(b[14], 0x45); // IP version/IHL
        // IP header (bytes 14..34) is self-consistent.
        assert_eq!(checksum(&b[14..34]), 0);
    }
}
