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

## Formal methodology: isolating the send-side throughput ceiling

The narrative above is the short version. This section states the same result in the register a reviewer would expect, because the figure is only as credible as the method that produced it.

### Problem statement and design rationale

Reported packet-generation figures are routinely confounded by the transport medium and by the instrumentation used to obtain them. A generator that emits frames faster than the attached link, the receiving host, or the local kernel can absorb will report an egress rate that reflects the narrowest downstream stage rather than the transmit code itself. To characterise the send path in isolation, its throughput ceiling must be decoupled from every downstream constraint: the physical medium, the receiver's softirq and delivery path, and the queueing-discipline and connection-tracking machinery of the local kernel.

The measurement strategy treats each candidate bottleneck as a controlled variable and removes it in turn, observing the resulting egress rate at each step. The design follows the logic of successive substitution: if eliminating a suspected constraint raises the observed rate, that constraint was binding; if it does not, the ceiling lies elsewhere.

### Apparatus

All measurements were taken on a single host (AMD Ryzen 7800X3D, 8 physical cores and 16 hardware threads, 62 GiB RAM, Linux 7.1.4). The generator was configured with sixteen transmit shards, one pinned to each hardware thread via `sched_setaffinity`, each emitting 54-byte Ethernet frames through an AF_PACKET socket with `PACKET_QDISC_BYPASS` enabled and frames aggregated into batches of up to 1024 per `sendmmsg` call. Frame prefixes were precomputed once per shard, with only the layer-4 header rewritten per packet, so per-frame formatting cost is excluded from the measured path by construction.

### Instrumentation and ground truth

Two counters were recorded per run. The first is the generator's own accepted-frame count, that is, frames the kernel accepted from `sendmmsg`. The second, treated as authoritative, is the interface `tx_packets` delta read from `/sys/class/net/<iface>/statistics/tx_packets` across the run window. The two are expected to agree only when no stage downstream of the socket silently discards frames. Because `PACKET_QDISC_BYPASS` removes the backpressure that would otherwise throttle the sender to the link rate, divergence between the two counters is itself the diagnostic signal for a medium-imposed wall. All rates reported below are computed from the authoritative counter over the measured wall-clock interval.

### Procedure and results

Four transmit targets were used, each removing one more downstream constraint than the last:

1. A physical 802.11 interface. Egress at the wire settled at approximately 60 Kpps while the generator accepted approximately 759 Kpps. The order-of-magnitude divergence localises the constraint to 802.11 airtime arbitration, a property of the half-duplex medium rather than of the generator.
2. A virtual Ethernet (veth) pair terminated in a separate network namespace. Egress settled at approximately 3.4 Mpps and, decisively, was invariant to sender parallelism: sixteen pinned shards and five hundred unpinned workers produced the same ceiling. This localises the constraint to the single-pair delivery and receive-softirq path, not to the sender.
3. A discard interface (dummy0) with a statically configured neighbour entry. This interface accepts and immediately discards transmitted frames, incrementing `tx_packets` without any receive-side processing or physical medium. Egress reached 25,640,853 pps (approximately 25.6 Mpps; 384.6 million frames over 15.03 seconds), with the accepted-frame count matching the interface counter to within measurement noise, indicating no silent loss.
4. A virtio-net interface inside a hardware-virtualised guest, used to validate the AF_XDP transmit path against a known-good driver rather than to establish a throughput figure.

### Interpretation and threats to validity

The monotonic progression across successively less constrained targets (roughly 60 Kpps, then 3.4 Mpps, then 25.6 Mpps), together with the invariance of the veth result to sender parallelism, supports the conclusion that every figure below 25.6 Mpps was imposed by the delivery medium and not by the transmit code. The dummy0 result, obtained once every downstream constraint had been removed, is therefore taken as the send-side ceiling of the generator on this hardware: approximately 25.6 million packets per second, or about 1.7 times the theoretical 10GbE line rate for minimum-size frames (14.88 Mpps).

Several limitations bound this claim. First, dummy0 exercises the driver transmit routine and interface accounting but not a physical PHY or DMA to real hardware, so the figure is an upper bound on generation capacity rather than a demonstrated wire rate; establishing the latter requires a wired, XDP-capable interface not present on the test host. Second, the result is specific to this processor, frame size, and shard count, and does not generalise to arbitrary hardware. Third, `tx_packets` attests driver acceptance rather than successful delivery, which is immaterial for a discard interface but would require external corroboration on a physical link. Within these bounds, the operationally relevant conclusion is unchanged: for any target at or below 10GbE the system is constrained by the network, not by the generator.

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
