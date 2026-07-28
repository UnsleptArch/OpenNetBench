//! AF_XDP transmit backend — pure `libc`, TX-only, no libbpf/libxdp.
//!
//! This is the line-rate path: packets are written into a shared UMEM and handed
//! to the NIC through an `AF_XDP` TX ring, so the per-packet `sendto` of the
//! kernel/AF_PACKET paths collapses to **one wakeup syscall per batch** (finding
//! F1), and nothing traverses the IP stack, netfilter, or conntrack (F2).
//!
//! Scope: one socket bound to (ifindex, `queue_id`), best-effort zero-copy (the
//! kernel falls back to copy mode if the driver lacks ZC). The raw vector shards
//! one such socket per NIC TX queue onto its own thread for line rate (F3).
//! Frames are complete Ethernet+IPv4+L4, so this reuses the same [`FramePrefix`]
//! and L2 resolution as the AF_PACKET path.
//!
//! COMPILE-VERIFIED, NOT RUNTIME-VERIFIED HERE: the ring offsets, memory
//! barriers, and bind flags follow the kernel ABI, but this needs validation on
//! a real NIC (there's none in the build/test sandbox). The `PacketTx` seam and
//! the AF_PACKET fallback mean the tool is never blocked on it.
#![cfg(feature = "xdp")]

use super::l2::L2Route;
use super::packet_tx::PacketTx;
use super::wire::{self, FramePrefix};
use anyhow::{anyhow, bail, Result};
use std::ffi::CString;
use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicU32, Ordering};

const FRAME_SIZE: u32 = 2048;
const NUM_FRAMES: u32 = 4096;
const TX_RING_SIZE: u32 = 2048; // power of two
const COMP_RING_SIZE: u32 = 2048; // power of two
const FILL_RING_SIZE: u32 = 2048; // power of two; registered but unused (TX-only)
const KICK_BATCH: u32 = 64; // amortize the wakeup syscall across this many frames
const XDP_RING_NEED_WAKEUP: u32 = 1; // struct xdp_ring `flags` bit

/// A memory-mapped single-producer/single-consumer ring shared with the kernel.
/// We produce into TX / consume from COMPLETION; the kernel does the opposite.
struct Ring {
    producer: *mut u32,
    consumer: *mut u32,
    flags: *mut u32,
    desc: *mut u8,
    mask: u32,
    map: *mut c_void,
    map_len: usize,
}

impl Ring {
    #[inline]
    fn prod_acq(&self) -> u32 {
        unsafe { AtomicU32::from_ptr(self.producer).load(Ordering::Acquire) }
    }
    #[inline]
    fn cons_acq(&self) -> u32 {
        unsafe { AtomicU32::from_ptr(self.consumer).load(Ordering::Acquire) }
    }
    /// Publish the producer index. Release so the kernel (Acquire) only ever sees
    /// the advanced index *after* the descriptor bytes it points at are written —
    /// otherwise it could DMA a half-written / stale descriptor.
    #[inline]
    fn set_prod_rel(&self, v: u32) {
        unsafe { AtomicU32::from_ptr(self.producer).store(v, Ordering::Release) }
    }
    #[inline]
    fn set_cons_rel(&self, v: u32) {
        unsafe { AtomicU32::from_ptr(self.consumer).store(v, Ordering::Release) }
    }
    #[inline]
    fn needs_wakeup(&self) -> bool {
        unsafe { (self.flags.read_volatile() & XDP_RING_NEED_WAKEUP) != 0 }
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        if !self.map.is_null() {
            unsafe { libc::munmap(self.map, self.map_len) };
        }
    }
}

pub struct XdpTx {
    fd: i32,
    umem: *mut u8,
    umem_len: usize,
    tx: Ring,
    comp: Ring,
    prefix: [u8; wire::FRAME_PREFIX_LEN],
    free: Vec<u64>, // free UMEM frame offsets
    tx_prod: u32,   // our cached TX producer index
    comp_cons: u32, // our cached completion consumer index
    pending: u32,   // frames enqueued since the last wakeup
}

// The raw pointers are owned solely by the thread that holds this struct; the
// engine spawns one XdpTx per blocking worker thread, never shared.
unsafe impl Send for XdpTx {}

impl XdpTx {
    /// Set up an AF_XDP TX socket toward `dst_ip` for fixed-shape frames, bound to
    /// NIC TX `queue_id`. Sharding runs one socket per queue on its own thread;
    /// only one socket may bind a given `(ifindex, queue_id)`.
    pub fn new(
        route: &L2Route,
        dst_ip: Ipv4Addr,
        proto: u8,
        l4_len: usize,
        ttl: u8,
        queue_id: u32,
    ) -> Result<Self> {
        let ifindex = {
            let cname = CString::new(route.iface.as_str())?;
            let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
            if idx == 0 {
                bail!("if_nametoindex({}) failed", route.iface);
            }
            idx
        };

        let fd = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0) };
        if fd < 0 {
            bail!("socket(AF_XDP): {}", io::Error::last_os_error());
        }
        // Guard so the fd/umem are released on any early return below.
        let mut guard = FdGuard { fd, umem: std::ptr::null_mut(), umem_len: 0 };

        // UMEM: page-aligned anonymous mapping of NUM_FRAMES * FRAME_SIZE.
        let umem_len = (NUM_FRAMES * FRAME_SIZE) as usize;
        let umem = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                umem_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if umem == libc::MAP_FAILED {
            bail!("mmap(UMEM): {}", io::Error::last_os_error());
        }
        guard.umem = umem;
        guard.umem_len = umem_len;

        // Register the UMEM.
        let mut reg: libc::xdp_umem_reg = unsafe { mem::zeroed() };
        reg.addr = umem as u64;
        reg.len = umem_len as u64;
        reg.chunk_size = FRAME_SIZE;
        reg.headroom = 0;
        setsockopt(fd, libc::XDP_UMEM_REG, &reg)?;

        // A socket that owns its UMEM must register BOTH the fill and completion
        // rings before bind — even TX-only. The kernel's xsk_bind() rejects a
        // umem-owning socket whose fill ring (fq_tmp) is missing with EINVAL, so
        // skipping it (we never RX) is exactly what made bind fail on every
        // driver. We register the fill ring but never map or produce to it.
        setsockopt(fd, libc::XDP_UMEM_FILL_RING, &FILL_RING_SIZE)?;
        setsockopt(fd, libc::XDP_UMEM_COMPLETION_RING, &COMP_RING_SIZE)?;
        setsockopt(fd, libc::XDP_TX_RING, &TX_RING_SIZE)?;

        // Ring register offsets.
        let mut off: libc::xdp_mmap_offsets = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::xdp_mmap_offsets>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_XDP,
                libc::XDP_MMAP_OFFSETS,
                &mut off as *mut _ as *mut c_void,
                &mut len,
            )
        };
        if rc != 0 {
            bail!("getsockopt(XDP_MMAP_OFFSETS): {}", io::Error::last_os_error());
        }

        let tx = map_ring(
            fd,
            libc::XDP_PGOFF_TX_RING,
            &off.tx,
            TX_RING_SIZE,
            mem::size_of::<libc::xdp_desc>(),
        )?;
        let comp = map_ring(
            fd,
            libc::XDP_UMEM_PGOFF_COMPLETION_RING as libc::off_t,
            &off.cr,
            COMP_RING_SIZE,
            mem::size_of::<u64>(),
        )?;

        // Bind to (ifindex, queue_id). No forced mode → the kernel uses zero-copy
        // when the driver supports it and copy mode otherwise.
        let mut sxdp: libc::sockaddr_xdp = unsafe { mem::zeroed() };
        sxdp.sxdp_family = libc::AF_XDP as u16;
        sxdp.sxdp_flags = libc::XDP_USE_NEED_WAKEUP;
        sxdp.sxdp_ifindex = ifindex;
        sxdp.sxdp_queue_id = queue_id;
        let rc = unsafe {
            libc::bind(
                fd,
                &sxdp as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_xdp>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            bail!("bind(AF_XDP {}, q{queue_id}): {}", route.iface, io::Error::last_os_error());
        }

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

        // All frames start free.
        let free: Vec<u64> = (0..NUM_FRAMES as u64).map(|i| i * FRAME_SIZE as u64).collect();

        guard.disarm(); // success: XdpTx owns the fd/umem now
        Ok(XdpTx {
            fd,
            umem: umem as *mut u8,
            umem_len,
            tx,
            comp,
            prefix: prefix_bytes,
            free,
            tx_prod: 0,
            comp_cons: 0,
            pending: 0,
        })
    }

    /// Reclaim completed frames back onto the free list.
    fn reclaim(&mut self) {
        let prod = self.comp.prod_acq();
        let base = self.comp.desc as *const u64;
        while self.comp_cons != prod {
            let addr = unsafe { *base.add((self.comp_cons & self.comp.mask) as usize) };
            self.free.push(addr);
            self.comp_cons = self.comp_cons.wrapping_add(1);
        }
        self.comp.set_cons_rel(self.comp_cons);
    }

    /// Issue the TX wakeup syscall if the kernel asked for it (or in copy mode).
    fn kick(&mut self) {
        if self.pending == 0 {
            return;
        }
        if self.tx.needs_wakeup() {
            unsafe {
                libc::sendto(
                    self.fd,
                    std::ptr::null(),
                    0,
                    libc::MSG_DONTWAIT,
                    std::ptr::null(),
                    0,
                );
            }
        }
        self.pending = 0;
    }

    #[inline]
    fn tx_free_slots(&self) -> u32 {
        TX_RING_SIZE - (self.tx_prod.wrapping_sub(self.tx.cons_acq()))
    }
}

impl PacketTx for XdpTx {
    #[inline]
    fn send_l4(&mut self, l4: &[u8]) -> io::Result<bool> {
        let frame_len = self.prefix.len() + l4.len();
        debug_assert!(frame_len <= FRAME_SIZE as usize);

        if self.free.is_empty() || self.tx_free_slots() == 0 {
            self.kick();
            self.reclaim();
            if self.free.is_empty() || self.tx_free_slots() == 0 {
                // Ring saturated this instant — drop (backpressure), not a send.
                return Ok(false);
            }
        }

        let addr = self.free.pop().unwrap();
        // Copy the full frame (cached L2/L3 prefix + this packet's L4) into UMEM.
        unsafe {
            let dst = self.umem.add(addr as usize);
            std::ptr::copy_nonoverlapping(self.prefix.as_ptr(), dst, self.prefix.len());
            std::ptr::copy_nonoverlapping(l4.as_ptr(), dst.add(self.prefix.len()), l4.len());
        }

        // Publish one TX descriptor, then advance the producer with Release.
        let idx = (self.tx_prod & self.tx.mask) as usize;
        unsafe {
            let d = (self.tx.desc as *mut libc::xdp_desc).add(idx);
            (*d).addr = addr;
            (*d).len = frame_len as u32;
            (*d).options = 0;
        }
        self.tx_prod = self.tx_prod.wrapping_add(1);
        self.tx.set_prod_rel(self.tx_prod);

        self.pending += 1;
        if self.pending >= KICK_BATCH {
            self.kick();
        }
        Ok(true)
    }

    fn mode(&self) -> &'static str {
        "af_xdp (batched ring TX, bypasses kernel stack)"
    }
}

impl Drop for XdpTx {
    fn drop(&mut self) {
        // Flush any queued frames before tearing down.
        self.pending = self.pending.max(1);
        self.kick();
        unsafe {
            libc::munmap(self.umem as *mut c_void, self.umem_len);
            libc::close(self.fd);
        }
    }
}

/// Cleanup guard for the partial-construction path (before `XdpTx` owns things).
struct FdGuard {
    fd: i32,
    umem: *mut c_void,
    umem_len: usize,
}
impl FdGuard {
    fn disarm(&mut self) {
        self.fd = -1;
        self.umem = std::ptr::null_mut();
    }
}
impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.umem.is_null() {
                libc::munmap(self.umem, self.umem_len);
            }
            if self.fd >= 0 {
                libc::close(self.fd);
            }
        }
    }
}

fn setsockopt<T>(fd: i32, opt: i32, val: &T) -> Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_XDP,
            opt,
            val as *const T as *const c_void,
            mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(anyhow!("setsockopt({opt}): {}", io::Error::last_os_error()));
    }
    Ok(())
}

fn map_ring(
    fd: i32,
    pgoff: libc::off_t,
    off: &libc::xdp_ring_offset,
    size: u32,
    desc_size: usize,
) -> Result<Ring> {
    let map_len = off.desc as usize + size as usize * desc_size;
    let map = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            map_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            fd,
            pgoff,
        )
    };
    if map == libc::MAP_FAILED {
        return Err(anyhow!("mmap(ring @ {pgoff:#x}): {}", io::Error::last_os_error()));
    }
    let base = map as *mut u8;
    Ok(Ring {
        producer: unsafe { base.add(off.producer as usize) as *mut u32 },
        consumer: unsafe { base.add(off.consumer as usize) as *mut u32 },
        flags: unsafe { base.add(off.flags as usize) as *mut u32 },
        desc: unsafe { base.add(off.desc as usize) },
        mask: size - 1,
        map,
        map_len,
    })
}
