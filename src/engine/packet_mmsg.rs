//! Batched AF_PACKET transmit backend — the "any NIC" fast path.
//!
//! The plain AF_PACKET backend pays one `sendto` syscall per frame; that syscall
//! rate is the ceiling on the fallback path. This backend instead fills a buffer
//! of `BATCH` complete frames and flushes them with a single `sendmmsg()`, so the
//! syscall cost is amortized ~1000× — the same trick the fast flood tools use.
//! It also sets `PACKET_QDISC_BYPASS`, so TX skips the qdisc layer and doesn't
//! take the per-netdev qdisc spinlock (the multicore scaling wall).
//!
//! Requires no XDP driver support, so it runs on **any** NIC. Needs root /
//! CAP_NET_RAW for the `AF_PACKET` socket, like every raw vector. The frame shape
//! is fixed (constant L4 length), so the L2/L3 prefix is written into every slot
//! once and each packet only rewrites its L4 bytes.

use super::l2::L2Route;
use super::packet_tx::PacketTx;
use super::wire::{self, FramePrefix};
use anyhow::{bail, Result};
use std::ffi::CString;
use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::raw::c_void;

/// Frames per `sendmmsg()`. The kernel caps a single call at `UIO_MAXIOV` (1024)
/// messages, so this is the most we can flush per syscall.
const BATCH: usize = 1024;

pub struct AfPacketMmsg {
    fd: i32,
    frame_len: usize,
    prefix_len: usize,
    frames: Vec<u8>,             // BATCH * frame_len, prefix pre-filled per slot
    iovecs: Vec<libc::iovec>,    // one per slot, pointing into `frames`
    msgs: Vec<libc::mmsghdr>,    // one per slot, pointing into `iovecs`
    count: usize,                // frames buffered since the last flush
}

// The raw pointers in `iovecs`/`msgs` reference this struct's own heap buffers
// (`frames`, `iovecs`), which stay put across a move; the struct is owned by a
// single sender thread and never shared.
unsafe impl Send for AfPacketMmsg {}

impl AfPacketMmsg {
    /// Open a batched AF_PACKET sender for a fixed frame shape toward `dst_ip`.
    pub fn new(
        route: &L2Route,
        dst_ip: Ipv4Addr,
        proto: u8,
        l4_len: usize,
        ttl: u8,
    ) -> Result<Self> {
        let ifindex = {
            let cname = CString::new(route.iface.as_str())?;
            let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
            if idx == 0 {
                bail!("if_nametoindex({}) failed", route.iface);
            }
            idx as i32
        };

        // SOCK_RAW so we supply the whole Ethernet frame; protocol 0 = TX only.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
        if fd < 0 {
            bail!("socket(AF_PACKET): {}", io::Error::last_os_error());
        }
        let guard = FdGuard(fd);

        // Bind to the egress interface so a NULL msg_name sends out that NIC.
        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = 0;
        sll.sll_ifindex = ifindex;
        let rc = unsafe {
            libc::bind(
                fd,
                &sll as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            bail!("bind(AF_PACKET {}): {}", route.iface, io::Error::last_os_error());
        }

        // Skip the qdisc on TX (no qdisc spinlock). Best-effort: older kernels
        // may not have it, and losing it only costs some multicore scaling.
        let one: i32 = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_QDISC_BYPASS,
                &one as *const i32 as *const c_void,
                mem::size_of::<i32>() as libc::socklen_t,
            );
        }

        let frame_len = wire::FRAME_PREFIX_LEN + l4_len;
        let prefix = FramePrefix::new(
            route.next_hop_mac,
            route.src_mac,
            route.src_ip,
            dst_ip,
            proto,
            l4_len,
            ttl,
        );
        let mut frames = build_frame_buffer(prefix.as_bytes(), BATCH, frame_len);

        // Build the iovec + mmsghdr arrays once; every slot's length is fixed, so
        // after this only the frame bytes change between flushes.
        let frame_base = frames.as_mut_ptr();
        let mut iovecs: Vec<libc::iovec> = (0..BATCH)
            .map(|i| libc::iovec {
                iov_base: unsafe { frame_base.add(i * frame_len) } as *mut c_void,
                iov_len: frame_len,
            })
            .collect();
        let iov_base = iovecs.as_mut_ptr();
        let msgs: Vec<libc::mmsghdr> = (0..BATCH)
            .map(|i| {
                let mut m: libc::mmsghdr = unsafe { mem::zeroed() };
                m.msg_hdr.msg_iov = unsafe { iov_base.add(i) };
                m.msg_hdr.msg_iovlen = 1;
                m
            })
            .collect();

        guard.disarm();
        Ok(AfPacketMmsg {
            fd,
            frame_len,
            prefix_len: wire::FRAME_PREFIX_LEN,
            frames,
            iovecs,
            msgs,
            count: 0,
        })
    }

    /// Flush the buffered frames with one `sendmmsg()`.
    fn flush(&mut self) -> io::Result<()> {
        if self.count == 0 {
            return Ok(());
        }
        let n = unsafe { libc::sendmmsg(self.fd, self.msgs.as_mut_ptr(), self.count as u32, 0) };
        self.count = 0;
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl PacketTx for AfPacketMmsg {
    #[inline]
    fn send_l4(&mut self, l4: &[u8]) -> io::Result<bool> {
        debug_assert_eq!(self.prefix_len + l4.len(), self.frame_len);
        // Only the L4 bytes change; the prefix in this slot is already correct.
        let off = self.count * self.frame_len + self.prefix_len;
        self.frames[off..off + l4.len()].copy_from_slice(l4);
        self.count += 1;
        if self.count == BATCH {
            self.flush()?;
        }
        Ok(true)
    }

    fn mode(&self) -> &'static str {
        "af_packet+sendmmsg (batched, qdisc-bypass)"
    }
}

impl Drop for AfPacketMmsg {
    fn drop(&mut self) {
        let _ = self.flush();
        unsafe { libc::close(self.fd) };
    }
}

/// Close the fd if construction fails before `AfPacketMmsg` takes ownership.
struct FdGuard(i32);
impl FdGuard {
    fn disarm(self) {
        mem::forget(self);
    }
}
impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// Allocate `batch` frame slots of `frame_len` bytes with `prefix` written at the
/// start of each (the fixed L2/L3 header). Pure, so the layout is unit-testable.
fn build_frame_buffer(prefix: &[u8], batch: usize, frame_len: usize) -> Vec<u8> {
    let mut frames = vec![0u8; batch * frame_len];
    for slot in frames.chunks_mut(frame_len) {
        slot[..prefix.len()].copy_from_slice(prefix);
    }
    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_buffer_writes_prefix_into_every_slot() {
        let prefix = [0xAA, 0xBB, 0xCC];
        let frame_len = 5; // 3-byte prefix + 2-byte L4
        let frames = build_frame_buffer(&prefix, 4, frame_len);
        assert_eq!(frames.len(), 4 * frame_len);
        for i in 0..4 {
            let slot = &frames[i * frame_len..(i + 1) * frame_len];
            assert_eq!(&slot[..3], &prefix, "slot {i} prefix");
            assert_eq!(&slot[3..], &[0, 0], "slot {i} L4 starts zeroed");
        }
    }
}
