# Performance

The send path, the numbers, and how they were actually measured. No vibes, every figure here came off a NIC counter or a generation counter that was cross-checked against one.

## The bar

The whole fast path was built against one acceptance test: crash a real home router in under thirty seconds. If it could not do that it was not good enough for the kind of adversarial testing the tool is meant to stand next to. It clears the bar. On a live run against a gateway the target went from answering to fully down in about six seconds, verdict Down at 0.90 confidence, off connection and state exhaustion, running on wifi, nowhere near the code's actual ceiling.

## The headline number

**25.6 million packets per second** of 54-byte frames, single desktop, Ryzen 7800X3D (8 cores, 16 threads), 16 pinned shards, AF_PACKET plus batched sendmmsg with the qdisc bypassed.

Some context for that:

- It is about 1.7x over 10GbE line rate at 64 bytes (14.88 Mpps).
- It is roughly 17x over 1GbE line rate.
- It is about 11 Gbps of tiny frames.

The practical conclusion is simple. For any target up to and including 10 gig, this tool is bound by the wire and not by the code. The speed race is effectively over for realistic targets. Going faster than this only matters against 25/40/100GbE gear.

## Why it is fast

Generating packets fast is not an algorithm problem, the send loop is O(P) with a fixed cost per packet, there is no asymptotic win hiding anywhere. It is a constant-factor problem, and the constant is dominated by four things. The fast path kills all four.

1. **Syscall per packet.** The naive path does one `sendto` per frame. The batched backend buffers up to 1024 frames and ships them with a single `sendmmsg`, and the XDP backend collapses a whole batch into one wakeup. This is the single biggest win.
2. **The qdisc spinlock.** Per-netdev, it caps multicore scaling hard, every core contends on it. `PACKET_QDISC_BYPASS` skips it entirely on the AF_PACKET path, and AF_XDP never touches it.
3. **Netfilter and local conntrack.** The kernel path runs the OUTPUT chain and creates conntrack state for every packet, which means a unique-flow flood exhausts your own box before the target. Injecting full frames at the driver bypasses both. This is the thing that killed an early router run, our machine died first.
4. **One core per shard.** Each shard thread is pinned with `sched_setaffinity`, so the frame prefix, the ring indices and the DMA'd-back completion descriptors all stay warm in one core's cache with no migration bounce.

Frame prefixes are precomputed once per shard and only the L4 bytes get rewritten per packet, so there is no per-frame formatting either.

## How it was measured, and every ceiling on the way

The important discipline here is that every "slow" number turned out to be the medium, never the code. The send side kept being faster than whatever could carry the packets away. Here is the ladder, because the story is in the gap between the numbers.

| Harness | What it measures | Result | What it actually told us |
|---|---|---|---|
| wlan0 (wifi) | live router kill | ~60K pps at the wire | 802.11 airtime wall. Generation hit 759K but the wire stuck at 60K. Wifi can never show the win |
| veth pair | RX-side delivery | ~3.4M pps | The veth single-pair delivery path caps here regardless of how many senders you throw at it |
| dummy0 | pure send side | **25.6M pps** | The real send ceiling. dummy0 discards TX with no RX softirq, so nothing downstream can bottleneck it |
| virtio VM | AF_XDP validation | armed and correct | Confirmed the XDP ring, bind and barriers work on a known-good driver |

The key read is that the wifi 60K and the veth 3.4M were both delivery walls. When we finally put the send path against a sink that could not bottleneck it, `dummy0`, it did 25.6M, which is 7.5x the veth number. Every low number before that was the medium, and the send path always had headroom.

The trust rule for all of this: the wire truth is the NIC's `tx_packets` counter, not what the tool thinks it generated. On veth and dummy0 the generated count matched the counter closely, so no silent drops. On wifi they diverged wildly (759K generated, 60K on the wire), which is exactly how you spot a medium wall.

## AF_XDP versus AF_PACKET, which to use

The batched AF_PACKET path already beats 10GbE line rate, so for almost every real target it is enough and it needs no special driver. Build it and forget it.

AF_XDP (`--features xdp`) is the headroom play for 25GbE and up, where bypassing the qdisc lock and the skb allocation entirely starts to matter. It needs a capable NIC. Zero-copy wants Intel igc/ice/i40e/ixgbe or mlx5 and similar. A Realtek NIC drops to generic copy mode, which is a few times faster than the kernel path but not line rate, and if your test box is Realtek that is the NIC capping you and not the code. Check with `ethtool -i <iface>`. AF_XDP is Linux only and needs root or the right capabilities, and it falls back cleanly to AF_PACKET when it cannot bind, so it always runs.

One historical note since it burned a lot of time. AF_XDP would not arm on any driver for a while, and it turned out to be a one-line bug, the socket owned its UMEM but never registered a fill ring, and the kernel rejects that with EINVAL before it ever consults the driver. Every "this NIC cannot do XDP" conclusion before that fix was wrong, it was our code. After registering the fill ring, XDP armed on virtio and on veth. If you are hacking on the XDP path, that class of bug hides as a driver limitation and it is not one.

## What is left

The pps race is basically won below 25GbE, so the remaining work is not about going faster.

- NIC-counter wire truth printed in the run summary, so the tool tells you generated versus wire pps automatically instead of you reading it off `/proc`. This is the honesty capstone.
- PACKET_MMAP TX ring, zero per-frame skb allocation. Optional, only matters at 25GbE and up.
- AF_XDP RX to count SYN-ACK, RST and ICMP replies, which turns the raw L4 vectors from send-only into measured, and feeds the classifier real reply data.
- A head-to-head against blitzping on this exact box against the same dummy0 sink. We do every trick it does (raw AF_PACKET, sendmmsg batching, thread per core, precomputed headers) plus the qdisc bypass, so on equal hardware we should be at least even and probably ahead, but the only fair verdict is running both on one machine against one sink. Until then, no crown.
