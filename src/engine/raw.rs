//! Shared raw-socket helpers for the L3/L4 packet vectors.
//!
//! Each raw vector elects one **leader** (worker `idx 0`); the leader spawns a
//! pool of pinned OS threads — one per NIC TX queue (AF_XDP) or one per assigned
//! CPU (batched AF_PACKET) — and every other logical worker no-ops. That keeps a
//! multi-vector run off tokio's bounded blocking-thread pool, where a per-worker
//! send loop would let the first vector starve the rest. Source IPs are always
//! this host's real address — no spoofing.

use super::net::Target;
use super::packet_mmsg::AfPacketMmsg;
use super::packet_tx::PacketTx;
use super::{l2, wire, Governor, Metrics, Shutdown};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet_transport::TransportChannelType::Layer4;
use pnet_transport::TransportProtocol::Ipv4;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

const IPPROTO_TCP: u8 = 6;
const TCP_HDR_LEN: usize = 20; // bare TCP header, no options
const FLOOD_TTL: u8 = 64;

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
#[allow(clippy::too_many_arguments)]
pub async fn tcp_flag_flood(
    idx: u32,
    target: Arc<Target>,
    metrics: Arc<Metrics>,
    gov: Arc<Governor>,
    shutdown: Arc<Shutdown>,
    flags: u8,
    label: &'static str,
    queue_rank: u32,
    queue_groups: u32,
) {
    let _ = tokio::task::spawn_blocking(move || {
        tcp_flag_blocking(idx, target, metrics, gov, shutdown, flags, label, queue_rank, queue_groups)
    })
    .await;
}

/// Fill a 20-byte TCP header for one flood packet from fresh PRNG output `r`.
/// Shared by all transmit paths so the packet is identical either way.
#[inline]
fn fill_tcp(
    buf: &mut [u8; TCP_HDR_LEN],
    r: u64,
    dst_port: u16,
    flags: u8,
    want_ack: bool,
    src_ip: &Ipv4Addr,
    dst_ip: &Ipv4Addr,
) {
    let src_port = 1024 + (r % 64_000) as u16;
    let seq = (r >> 16) as u32;
    let mut pkt = MutableTcpPacket::new(buf).expect("20-byte buffer fits a TCP header");
    pkt.set_source(src_port);
    pkt.set_destination(dst_port);
    pkt.set_sequence(seq);
    if want_ack {
        pkt.set_acknowledgement((r ^ 0x5DEECE66D) as u32);
    }
    pkt.set_data_offset(5);
    pkt.set_flags(flags);
    pkt.set_window(64_240);
    let checksum = ipv4_checksum(&pkt.to_immutable(), src_ip, dst_ip);
    pkt.set_checksum(checksum);
}

fn fmt_mac(m: [u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
}

/// The fixed per-run inputs a shard needs to build every TCP packet. `Copy` so it
/// moves cheaply into each shard thread.
#[derive(Clone, Copy)]
struct TcpParams {
    dst_ip: Ipv4Addr,
    src_ip: Ipv4Addr,
    dst_port: u16,
    flags: u8,
    want_ack: bool,
}

/// One shard's send loop: fill a fresh TCP header and transmit until shutdown.
/// `gov_idx` indexes this vector's governor so ramp-up enables shards one at a
/// time; `seed` seeds the PRNG for distinct flows (spread across vectors so two
/// vectors' shards don't emit identical packets).
fn fast_send_loop(
    gov_idx: u32,
    seed: u32,
    tx: &mut dyn PacketTx,
    p: TcpParams,
    metrics: &Metrics,
    gov: &Governor,
    shutdown: &Shutdown,
) {
    const FRAME_BYTES: u64 = (wire::FRAME_PREFIX_LEN + TCP_HDR_LEN) as u64;
    let mut rng = XorShift::seeded(seed);
    let mut buf = [0u8; TCP_HDR_LEN];
    loop {
        if shutdown.is_down() {
            return;
        }
        if !gov.active(gov_idx) {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        fill_tcp(&mut buf, rng.next(), p.dst_port, p.flags, p.want_ack, &p.src_ip, &p.dst_ip);
        metrics.requests_sent.fetch_add(1, Relaxed);
        match tx.send_l4(&buf) {
            Ok(true) => {
                metrics.bytes_sent.fetch_add(FRAME_BYTES, Relaxed);
                // Enqueued to the wire — NOT a target response. See Metrics::packets_sent.
                metrics.packets_sent.fetch_add(1, Relaxed);
            }
            Ok(false) => {
                // Ring/buffer-full backpressure drop — attempted, not sent. The wire
                // can't take more right now (e.g. wlan0's airtime cap keeps the TX
                // ring full), so don't hot-spin this pinned core: yield it so the L7
                // vectors, health probes, and other shards get to run. When several
                // raw vectors run at once they'd otherwise pin and peg every core and
                // starve everything else. Costs nothing on a flowing NIC, where sends
                // return Ok(true) and never reach here.
                std::thread::yield_now();
            }
            Err(_) => {
                metrics.errors.fetch_add(1, Relaxed);
            }
        }
    }
}

/// One shard: the CPU core to pin its thread to, and the transmit backend.
type Shard = (usize, Box<dyn PacketTx>);

/// Pin the calling thread to a single CPU (best-effort). Keeping a hot send loop
/// on one core stops the scheduler migrating it — so the frame prefix, ring
/// indices, and (when pinned to the queue's own core) the DMA'd-back completion
/// descriptors stay in that core's cache instead of being reloaded after a bounce.
fn pin_current_thread_to(cpu: usize) {
    // SAFETY: cpu_set_t is a plain bitmask; CPU_SET/sched_setaffinity have no
    // preconditions beyond a zeroed set, and pid 0 targets the calling thread.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        let _ = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

/// Run one thread per shard (each already pinned to a core) and block until every
/// shard finishes. `PacketTx: Send`, so each `Box` moves into its thread; the
/// shared atomics/watch are `Arc`-cloned per shard.
fn run_shards(
    shards: Vec<Shard>,
    p: TcpParams,
    seed_base: u32,
    metrics: Arc<Metrics>,
    gov: Arc<Governor>,
    shutdown: Arc<Shutdown>,
) {
    let mut handles = Vec::with_capacity(shards.len());
    for (shard_id, (cpu, mut tx)) in shards.into_iter().enumerate() {
        let (m, g, s) = (metrics.clone(), gov.clone(), shutdown.clone());
        let gov_idx = shard_id as u32;
        let seed = seed_base.wrapping_add(shard_id as u32);
        handles.push(std::thread::spawn(move || {
            pin_current_thread_to(cpu);
            fast_send_loop(gov_idx, seed, tx.as_mut(), p, &m, &g, &s);
        }));
    }
    for h in handles {
        let _ = h.join();
    }
}

/// Build one AF_XDP sender per NIC TX queue id in `queues`, each shard pinned to
/// that queue's own core (`queue_id % ncpus`) for completion-cache locality.
/// Queues that won't bind (driver/kernel lacks the mode, or already owned) are
/// logged and skipped; the returned vector may be shorter than `queues` or empty.
#[cfg(feature = "xdp")]
fn build_xdp_backends(
    route: &l2::L2Route,
    p: &TcpParams,
    queues: &[u32],
    ncpus: usize,
    label: &str,
) -> Vec<Shard> {
    let mut shards: Vec<Shard> = Vec::with_capacity(queues.len());
    for &q in queues {
        match super::xdp::XdpTx::new(route, p.dst_ip, IPPROTO_TCP, TCP_HDR_LEN, FLOOD_TTL, q) {
            Ok(tx) => shards.push((q as usize % ncpus, Box::new(tx))),
            Err(e) => warn!(vector = label, queue = q, error = %e, "AF_XDP queue bind failed"),
        }
    }
    shards
}

/// Build one batched AF_PACKET (`sendmmsg`) sender per CPU in `cpus`, each shard
/// pinned to that core. Works on any NIC — no XDP driver support needed.
fn build_afpacket_backends(
    route: &l2::L2Route,
    p: &TcpParams,
    cpus: &[usize],
    label: &str,
) -> Vec<Shard> {
    let mut shards: Vec<Shard> = Vec::with_capacity(cpus.len());
    for &cpu in cpus {
        match AfPacketMmsg::new(route, p.dst_ip, IPPROTO_TCP, TCP_HDR_LEN, FLOOD_TTL) {
            Ok(tx) => shards.push((cpu, Box::new(tx))),
            Err(e) => warn!(vector = label, cpu, error = %e, "AF_PACKET shard open failed"),
        }
    }
    shards
}

#[allow(clippy::too_many_arguments)]
fn tcp_flag_blocking(
    idx: u32,
    target: Arc<Target>,
    metrics: Arc<Metrics>,
    gov: Arc<Governor>,
    shutdown: Arc<Shutdown>,
    flags: u8,
    label: &'static str,
    queue_rank: u32,
    queue_groups: u32,
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
    let p = TcpParams {
        dst_ip,
        src_ip,
        dst_port: dst.port(),
        flags,
        want_ack: flags & TcpFlags::ACK != 0,
    };

    // One leader per vector owns the shard pool; siblings no-op. Shards are their
    // own pinned OS threads, so a multi-vector run never starves the bounded
    // blocking-thread pool the way a per-worker send loop would.
    if idx != 0 {
        return;
    }
    let ncpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let seed_base = queue_rank.wrapping_mul(4096); // distinct flows per vector

    match l2::resolve(dst_ip) {
        Ok(route) => {
            // AF_XDP first (built + wired): one TX-ring socket per NIC queue in
            // this vector's disjoint queue slice (F3 line-rate path).
            #[cfg(feature = "xdp")]
            {
                let nq = l2::tx_queue_count(&route.iface).min(gov.max as usize).max(1);
                let (qstart, qend) = l2::queue_slice(nq, queue_rank, queue_groups);
                let queues: Vec<u32> = (qstart..qend).collect();
                if !queues.is_empty() {
                    let shards = build_xdp_backends(&route, &p, &queues, ncpus, label);
                    if !shards.is_empty() {
                        let cpus: Vec<usize> = shards.iter().map(|(c, _)| *c).collect();
                        info!(vector = label, iface = %route.iface, shards = shards.len(),
                            queues = format!("{qstart}..{qend}"), cpus = format!("{cpus:?}"),
                            mode = "af_xdp (sharded, one socket per NIC queue)", "fast path armed");
                        run_shards(shards, p, seed_base, metrics, gov, shutdown);
                        return;
                    }
                    warn!(vector = label, "AF_XDP bound no queue — falling back to AF_PACKET shards");
                }
            }

            // AF_PACKET batched shards (any NIC): partition the CPUs across the
            // raw vectors so syn/ack pin to disjoint cores instead of contending.
            let (c0, c1) = l2::queue_slice(ncpus, queue_rank, queue_groups);
            let cpus: Vec<usize> = if c0 == c1 {
                vec![0] // more vectors than cores — this one still gets a shard
            } else {
                (c0..c1).map(|c| c as usize).collect()
            };
            let shards = build_afpacket_backends(&route, &p, &cpus, label);
            if !shards.is_empty() {
                let pinned: Vec<usize> = shards.iter().map(|(c, _)| *c).collect();
                info!(vector = label, iface = %route.iface, shards = shards.len(),
                    cpus = format!("{pinned:?}"),
                    mode = "af_packet+sendmmsg (batched, qdisc-bypass, sharded)", "fast path armed");
                run_shards(shards, p, seed_base, metrics, gov, shutdown);
                return;
            }
            warn!(vector = label, "no fast backend available — using kernel transmit path");
        }
        Err(e) => {
            warn!(vector = label, error = %e, "L2 resolve failed — using kernel transmit path");
        }
    }

    // Last resort (L2 unresolved or no fast socket opened): kernel Layer-4 on the
    // single leader thread. Pays the full egress path incl. conntrack; rare.
    kernel_l4_loop(&p, &metrics, &gov, &shutdown, label);
}

/// Fallback path: pnet's synchronous Layer-4 channel (the kernel builds IP + L2).
/// One thread; used only when the frame-injection fast paths can't be set up.
fn kernel_l4_loop(
    p: &TcpParams,
    metrics: &Metrics,
    gov: &Governor,
    shutdown: &Shutdown,
    label: &str,
) {
    let proto = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    let (mut tx, _rx) = match pnet_transport::transport_channel(4096, proto) {
        Ok(ch) => ch,
        Err(e) => {
            warn!(error = %e, "{label}: cannot open raw socket (need root) — skipping");
            return;
        }
    };
    info!(vector = label, "using kernel Layer-4 transmit path");
    let mut rng = XorShift::seeded(0);
    let mut buf = [0u8; TCP_HDR_LEN];
    loop {
        if shutdown.is_down() {
            return;
        }
        if !gov.active(0) {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        fill_tcp(&mut buf, rng.next(), p.dst_port, p.flags, p.want_ack, &p.src_ip, &p.dst_ip);
        metrics.requests_sent.fetch_add(1, Relaxed);
        let pkt = MutableTcpPacket::new(&mut buf).expect("20-byte buffer fits a TCP header");
        match tx.send_to(pkt, IpAddr::V4(p.dst_ip)) {
            Ok(n) => {
                metrics.bytes_sent.fetch_add(n as u64, Relaxed);
                metrics.packets_sent.fetch_add(1, Relaxed);
            }
            Err(_) => {
                metrics.errors.fetch_add(1, Relaxed);
            }
        }
    }
}
