//! Layer-2 resolution for the fast transmit path.
//!
//! Injecting frames at the driver (AF_PACKET / AF_XDP) means we own the Ethernet
//! header, so we must know: which interface egresses toward the target, our
//! source MAC, and the **next-hop** MAC (the gateway's MAC for an off-subnet
//! target, or the target's own MAC when it's on-link). We read these from the
//! kernel's own tables via `/proc` and `/sys` — no netlink dependency — and fall
//! back cleanly (the caller keeps the kernel socket path) when anything is
//! missing. The line parsers are pure and unit-tested.

use anyhow::{anyhow, Context, Result};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Everything the frame builder needs to address the wire.
#[derive(Debug, Clone)]
pub struct L2Route {
    pub iface: String,
    pub src_ip: Ipv4Addr,
    pub src_mac: [u8; 6],
    pub next_hop_mac: [u8; 6],
}

/// Resolve the full L2 path to `dst`: egress interface, source IP/MAC, and the
/// next-hop MAC. Returns an error (caller falls back to the kernel path) if any
/// piece can't be determined.
pub fn resolve(dst: Ipv4Addr) -> Result<L2Route> {
    let src_ip = local_src_ip(dst).context("determining local source IP")?;
    let route = pick_route(dst, &read_proc("/proc/net/route")?)
        .ok_or_else(|| anyhow!("no route to {dst}"))?;
    let next_hop = route.gateway.unwrap_or(dst);
    let src_mac = read_iface_mac(&route.iface)
        .with_context(|| format!("reading MAC of {}", route.iface))?;
    let next_hop_mac = resolve_neighbor_mac(next_hop, &route.iface)
        .with_context(|| format!("resolving MAC of next hop {next_hop}"))?;
    Ok(L2Route {
        iface: route.iface,
        src_ip,
        src_mac,
        next_hop_mac,
    })
}

/// The source IPv4 the kernel would use to reach `dst` (connect a UDP socket and
/// read its local address — no packets are sent).
fn local_src_ip(dst: Ipv4Addr) -> Result<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(SocketAddr::from((dst, 9)))?;
    match sock.local_addr()?.ip() {
        std::net::IpAddr::V4(v4) => Ok(v4),
        std::net::IpAddr::V6(_) => Err(anyhow!("local source is IPv6")),
    }
}

struct RouteEntry {
    iface: String,
    gateway: Option<Ipv4Addr>, // None = on-link (next hop is the destination itself)
}

/// Pick the best-matching route for `dst` from the contents of `/proc/net/route`.
/// Longest-prefix wins; a zero gateway means the destination is on-link.
fn pick_route(dst: Ipv4Addr, proc_route: &str) -> Option<RouteEntry> {
    let dst_be = u32::from(dst);
    let mut best: Option<(u32, RouteEntry)> = None; // (mask, entry)
    for line in proc_route.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let (iface, dest_hex, gw_hex, mask_hex) = (f[0], f[1], f[2], f[7]);
        let (Ok(dest), Ok(mask), Ok(gw)) = (
            u32::from_str_radix(dest_hex, 16),
            u32::from_str_radix(mask_hex, 16),
            u32::from_str_radix(gw_hex, 16),
        ) else {
            continue;
        };
        // /proc/net/route prints each address as the CPU-endian hex of the raw
        // __be32; on a little-endian host that's byte-reversed from octet order,
        // so swap to the `u32::from(Ipv4Addr)` convention (first octet high byte).
        let dest_h = dest.swap_bytes();
        let mask_h = mask.swap_bytes();
        let gw_h = gw.swap_bytes();
        if dst_be & mask_h == dest_h {
            let better = best.as_ref().map(|(m, _)| mask_h > *m).unwrap_or(true);
            if better {
                let gateway = (gw_h != 0).then(|| Ipv4Addr::from(gw_h));
                best = Some((mask_h, RouteEntry {
                    iface: iface.to_string(),
                    gateway,
                }));
            }
        }
    }
    best.map(|(_, e)| e)
}

/// Number of hardware TX queues the interface exposes, from
/// `/sys/class/net/<iface>/queues/tx-*`. This is the ceiling on distinct AF_XDP
/// queue ids we can shard across (one xsk per `(ifindex, queue)`); returns at
/// least 1 so the fast path always has one shard.
pub fn tx_queue_count(iface: &str) -> usize {
    let names = std::fs::read_dir(format!("/sys/class/net/{iface}/queues"))
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    count_tx_queues(names.iter().map(String::as_str))
}

/// This raw vector's contiguous slice `[start, end)` of `nq` NIC TX queues when
/// the queues are split evenly across `groups` fast-path vectors (this one at
/// `rank`). Only one AF_XDP socket may own a given `(ifindex, queue)`, so vectors
/// sharing a NIC must take disjoint slices or they collide with EBUSY. The slice
/// is empty (`start == end`) when there are more vectors than queues — that
/// vector falls back to AF_PACKET.
pub fn queue_slice(nq: usize, rank: u32, groups: u32) -> (u32, u32) {
    let groups = groups.max(1);
    let nq = nq as u32;
    let start = rank.min(groups) * nq / groups;
    let end = (rank + 1).min(groups) * nq / groups;
    (start, end)
}

/// Count `tx-<n>` entries among a set of `queues/` directory names. Pure so it
/// can be tested without a real interface.
fn count_tx_queues<'a>(names: impl Iterator<Item = &'a str>) -> usize {
    names
        .filter(|n| n.strip_prefix("tx-").is_some_and(|d| d.bytes().all(|b| b.is_ascii_digit())))
        .count()
        .max(1)
}

/// Read an interface's MAC from `/sys/class/net/<iface>/address`.
fn read_iface_mac(iface: &str) -> Result<[u8; 6]> {
    let s = read_proc(&format!("/sys/class/net/{iface}/address"))?;
    parse_mac(s.trim()).ok_or_else(|| anyhow!("unparseable MAC '{}'", s.trim()))
}

/// Resolve `ip`'s MAC from the kernel ARP cache (`/proc/net/arp`), provoking an
/// ARP resolution with a throwaway UDP datagram if the entry isn't present yet.
fn resolve_neighbor_mac(ip: Ipv4Addr, iface: &str) -> Result<[u8; 6]> {
    if let Some(mac) = lookup_arp(ip, iface, &read_proc("/proc/net/arp")?) {
        return Ok(mac);
    }
    // Nudge the kernel to resolve it, then re-read.
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        let _ = sock.connect(SocketAddr::from((ip, 9)));
        let _ = sock.send(&[0u8; 0]);
    }
    std::thread::sleep(Duration::from_millis(200));
    lookup_arp(ip, iface, &read_proc("/proc/net/arp")?)
        .ok_or_else(|| anyhow!("no ARP entry for {ip} on {iface}"))
}

/// Find `ip`'s MAC in the contents of `/proc/net/arp` (optionally constrained to
/// `iface`). Skips incomplete entries (all-zero MAC).
fn lookup_arp(ip: Ipv4Addr, iface: &str, proc_arp: &str) -> Option<[u8; 6]> {
    for line in proc_arp.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 {
            continue;
        }
        let (arp_ip, mac_str, dev) = (f[0], f[3], f[5]);
        if arp_ip != ip.to_string() || dev != iface {
            continue;
        }
        if let Some(mac) = parse_mac(mac_str) {
            if mac != [0u8; 6] {
                return Some(mac);
            }
        }
    }
    None
}

/// Parse `aa:bb:cc:dd:ee:ff` into six bytes.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0;
    for part in s.split(':') {
        if n >= 6 {
            return None;
        }
        out[n] = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    (n == 6).then_some(out)
}

fn read_proc(path: &str) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_slice_partitions_without_overlap() {
        // 4 queues, 2 vectors → [0,2) and [2,4): disjoint, cover everything.
        assert_eq!(queue_slice(4, 0, 2), (0, 2));
        assert_eq!(queue_slice(4, 1, 2), (2, 4));
        // Uneven: 3 queues, 2 vectors → [0,1) and [1,3).
        assert_eq!(queue_slice(3, 0, 2), (0, 1));
        assert_eq!(queue_slice(3, 1, 2), (1, 3));
        // Over-subscribed: 1 queue, 2 vectors → one gets it, one gets empty.
        assert_eq!(queue_slice(1, 0, 2), (0, 0));
        assert_eq!(queue_slice(1, 1, 2), (0, 1));
        // Single group takes the whole NIC; groups=0 is treated as 1.
        assert_eq!(queue_slice(8, 0, 1), (0, 8));
        assert_eq!(queue_slice(8, 0, 0), (0, 8));
    }

    #[test]
    fn tx_queue_count_filters_and_floors() {
        // Real multi-queue NIC: tx-0..tx-3 plus rx dirs → 4.
        let names = ["rx-0", "tx-0", "tx-1", "tx-2", "tx-3", "rx-1"];
        assert_eq!(count_tx_queues(names.into_iter()), 4);
        // Non-numeric / bogus entries are ignored.
        assert_eq!(count_tx_queues(["tx-", "tx-x", "txn-0"].into_iter()), 1);
        // Empty (unreadable sysfs) still yields at least one shard.
        assert_eq!(count_tx_queues(std::iter::empty()), 1);
    }

    #[test]
    fn parse_mac_roundtrip() {
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff"), Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(parse_mac("00:00:00:00:00:00"), Some([0; 6]));
        assert_eq!(parse_mac("aa:bb:cc:dd:ee"), None); // too short
        assert_eq!(parse_mac("zz:bb:cc:dd:ee:ff"), None); // non-hex
    }

    // Realistic /proc/net/route: default via .1 on eth0, plus the on-link subnet.
    const ROUTE: &str = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0";

    #[test]
    fn route_offlink_uses_gateway() {
        // 8.8.8.8 is off-subnet → next hop is the default gateway 192.168.1.1.
        let r = pick_route(Ipv4Addr::new(8, 8, 8, 8), ROUTE).unwrap();
        assert_eq!(r.iface, "eth0");
        assert_eq!(r.gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn route_onlink_has_no_gateway() {
        // 192.168.1.254 matches the /24 on-link route (longest prefix) → on-link.
        let r = pick_route(Ipv4Addr::new(192, 168, 1, 254), ROUTE).unwrap();
        assert_eq!(r.iface, "eth0");
        assert_eq!(r.gateway, None);
    }

    const ARP: &str = "IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:11:22:33     *        eth0
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0";

    #[test]
    fn arp_lookup_finds_complete_entry() {
        assert_eq!(
            lookup_arp(Ipv4Addr::new(192, 168, 1, 1), "eth0", ARP),
            Some([0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33])
        );
    }

    #[test]
    fn arp_lookup_skips_incomplete_and_wrong_iface() {
        // Incomplete (all-zero) entry is not a valid resolution.
        assert_eq!(lookup_arp(Ipv4Addr::new(192, 168, 1, 9), "eth0", ARP), None);
        // Right IP, wrong interface.
        assert_eq!(lookup_arp(Ipv4Addr::new(192, 168, 1, 1), "wlan0", ARP), None);
    }
}
