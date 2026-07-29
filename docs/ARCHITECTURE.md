# Architecture

How the thing is actually built, module by module, with the reasoning. If you want to use it, read [USAGE.md](USAGE.md) instead. This is for reading the code or auditing it.

## One paragraph

OpenNetBench is a single-origin adversarial-load tool. It generates the traffic real attackers use, L3 up to L7, nineteen vectors, from one host, measures how the target behaves under that load with two independent probes, and classifies the outcome with a confidence and an evidence trail. No amplification and no command and control, all by construction, with an optional SOCKS5 proxy for the L7 path. The NIC is the hard ceiling.

## Safety model, enforced by the code

These are not policy promises, they fall out of how the tree is built. Full version in [SAFETY.md](SAFETY.md).

| Property | How it is guaranteed |
|---|---|
| Single origin | All traffic leaves this host. There is no agent protocol, no peer discovery, no coordination code anywhere |
| No spoofing | Raw vectors compute checksums from the host's real source IP (`local_src_ipv4`). Spoofing is not implemented, and it would break the TCP vectors anyway since the SYN-ACK would go somewhere else |
| No amplification | No reflection vectors exist. Every byte is generated locally |
| No C2 | No remote-control surface. The only egress is the attack traffic and the probes, both to the target you named |
| Mandatory consent | `auth.rs` blocks every run until you type an exact phrase at a TTY. A flag or a file cannot satisfy it |

## Top-level flow (`main.rs`)

```
parse CLI
  --list-presets   print and exit
  --save-config    build plan, write JSON, exit   (no consent, nothing fires)
  --ui-only        serve dashboard, exit
  run path:
     legal notice + consent gate (auth::require_consent)   always
     resolve the plan:
       --auto     characterize, recommend, build_config
       --preset   build_config(preset, target)
       --config   load_config(json)
       none       interactive_flow
     if run_recon   run_recon, present, select or auto-approve target
     final "execute this plan?" confirm
     engine::run(cfg, ctx)
```

## Config model (`config.rs`)

`Vector` is the nineteen vectors as an enum, each with `slug()`, `layer()`, `needs_root()`, `description()`. `Vector::ALL` is the canonical list. `RunMode` is Adaptive or Dumb. `VectorTuning` is the per-vector knobs with `defaults_for(vector)`. `RunConfig` is the fully resolved serializable plan, which is what `--save-config` writes and `--config` reads.

## Presets (`presets.rs`)

A `Preset` is a curated vector combo for a target class. `build_config` stamps `PRESET_CONCURRENCY` (2700) on every vector and hands back a normal `RunConfig` you can dump and edit. No aggressiveness ladder, presets run at full pressure, tuned down from a naive 3000 so a single origin exhausts the target's state before its own local socket limits.

## Auto-engine (`auto.rs`)

`--auto` is recommend-and-approve, it never fires on its own. `characterize(target)` does a TCP-connect port scan plus an HTTP/HTTPS fingerprint plus WAF and embedded-server detection, classifies into a `TargetKind`, and `recommend` maps that to a preset with human-readable reasoning before dropping into the normal consent and confirm path. Private IPs and embedded servers like uhttpd or RomPager get called routers even when they serve a web UI, because a router admin page is not a web app.

## Recon (`recon/`)

`fingerprint.rs` reads the Server header, missing security headers, does OPTIONS/TRACE method enumeration, and probes around forty sensitive paths. `crawl.rs` is an async same-host BFS with a byte-scanner for links and form actions, no html5ever. `score.rs` is the research idea, asymmetry equals server cost over client cost, it ranks endpoints by how much a single request costs the server versus us. `run_recon` assembles candidates, times each one with a three-sample TTFB average, detects cacheability, scores asymmetry, and returns a ranked report. Recon never auto-fires, you or `--auto-approve` pick the target off the ranked list.

## The engine (`engine/`)

The performance-critical core. Lock-free hot path, zero per-request allocation, O(1) recording, prompt cooperative shutdown.

### Shared state (`engine/mod.rs`)

`Metrics` is all `AtomicU64/U32` with Relaxed ordering, no mutex per request, one instance per vector. The sampler and summary aggregate across them but each governor sees only its own vector so a distressed vector never throttles a healthy one. `responses_ok` means a real round trip, connectionless floods increment `packets_sent` instead, which is local egress and not confirmed delivery, so their send rate never gets reported as target throughput.

`Shutdown` is a `tokio::sync::watch<bool>`. Cheap `is_down()` reads and a `subscribe()` receiver each worker races in `select!` so there is no lost-notification window. Unbounded reads race it too, and `run()` force-aborts any straggler after a five-second drain grace, so stopping the process always stops the traffic.

`Governor` per vector is an `AtomicU32 target_concurrency` that workers gate on with one relaxed load. `govern()` ramps it zero to max over the ramp-up, and in Adaptive mode halves under distress and re-grows, which is the cycle that measures recovery. Fire-and-forget vectors just ramp, they never fake an adaptive decision off a local send count.

Before spawning, `fd_scale()` reads `RLIMIT_NOFILE`, raises the soft limit toward the hard cap, and scales concurrency down to fit if it still will not, so you do not get an EMFILE storm that reads as target failure but is really your own socket table.

### Latency histogram (`engine/histogram.rs`)

HdrHistogram-style, 512 buckets, a constant 4KB. Recording is O(1), one `leading_zeros` and one atomic add, safe to hammer concurrently. Quantiles are computed only in the sampler, four times a second, on windowed deltas, so the collapse curve reflects latency at the current load and not cumulative.

### Sampler and outcome

`sample()` runs every 250ms, aggregates every vector's histogram, computes windowed p50/p95/p99, and derives RPS and error rate. RPS is completed responses over the actual elapsed window, not a nominal 250ms, because a late wakeup under load would otherwise distort it. Error rate is errors over completions plus errors. After the run `derive_outcome()` pulls baseline p99 (from recon if it ran), time-to-degradation, the knee, and recovery time. Degradation needs a 3x ratio and an absolute delta over 25ms and both holding for three consecutive samples, so a lone spike never registers.

### The two probes, ground truth

Two independent direct observers run alongside the load, never proxied.

`health_probe()` TCP-connects once a second plus a pre-load baseline. Each connect is classified by whose fault it is, a success, a RST (Refused), a timeout or unreachable (TargetFail), or our own socket exhaustion (LocalExhausted, which is excluded from any "target down" call). A RST counts as failure only if the service was accepting at baseline, so baseline-accepting into load-refused means the load knocked the listener over. This is the only signal that works for the raw L4 vectors.

`service_probe()` fires a real independent GET once a second when the app answered at baseline. It catches what a TCP connect cannot, a server whose worker pool is starved by slowloris still completes handshakes while answering no real requests. Baseline-healthy GETs failing under load is a finding even when the connect probe looks fine.

### Connection layer (`engine/net.rs`)

`Conn` is plain-or-TLS behind one enum, both variants Unpin so the I/O path has no box and no vtable. `Target::resolve` does DNS once up front and shares the `SocketAddr`. Request templates (rotating browser fingerprints, the slowloris head, the RUDY POST head, the CVE-2011-3192 Range request) are all serialized once so workers never format strings in the loop. SOCKS5 proxying, when configured, routes every TCP connection through the proxy, TCP only, the raw and UDP vectors egress direct and the tool warns.

### The vectors

Each vector is its own module following the gate and shutdown pattern. Full catalog with mechanisms is in [VECTORS.md](VECTORS.md). The L7 vectors are async tokio tasks over `net::Conn`. The raw vectors run a synchronous send loop on dedicated threads and read the shared atomics and watch directly.

### Transmit backends (`packet_tx.rs`, `packet_mmsg.rs`, `wire.rs`, `l2.rs`, `xdp.rs`)

This is where the big numbers come from, and it changed a lot. The raw SYN/ACK path picks the fastest transmitter available at startup behind the `PacketTx` trait and falls back cleanly so it always runs.

The unit of parallelism is the shard, not the logical worker. Worker index zero is the shard leader, it resolves Layer 2 once, then spawns one pinned thread per shard. CPUs are partitioned across the running raw vectors with `l2::queue_slice`, so on a router run syn takes the low half of the cores and ack takes the high half, each shard pinned to its core with `sched_setaffinity` to keep the frame prefix, ring indices and completion descriptors warm on one core. This is the shard-collapse model and it is the default path now, it fixed a nasty starvation bug where the old per-worker model saturated the tokio blocking pool with the first vector and the second vector never ran.

Backends, fastest first:

1. **AF_XDP** (`xdp.rs`, only with `--features xdp`). Pure libc, TX-only. Frames go into a shared UMEM and out an AF_XDP TX ring, so the per-packet `sendto` collapses to one wakeup syscall per 64-frame batch and nothing touches the IP stack, netfilter or conntrack. One socket per NIC TX queue, queues partitioned across vectors so two vectors on one NIC do not fight over queue zero. No libbpf or libxdp, the default build pulls no C toolchain. Producer stores are Release, completion reads are Acquire.

2. **AF_PACKET plus sendmmsg** (`packet_mmsg.rs`). A raw `SOCK_RAW` socket bound to the egress ifindex, buffering up to 1024 full frames and flushing them with a single `sendmmsg`, with `PACKET_QDISC_BYPASS` set so it skips the qdisc spinlock that otherwise caps multicore scaling. Works on any NIC, no XDP driver needed. This is the backend that carries the tool past 10GbE, and it is what runs when XDP is not built or the NIC will not do it.

3. **Kernel Layer-4** (`pnet_transport`). The original path, kernel builds IP and L2. The always-available last resort when we are not root or Layer 2 will not resolve.

`wire.rs` builds the Ethernet plus IPv4 prefix with checksums, all unit-tested byte-exact. `l2.rs` resolves the egress interface, source MAC and next-hop MAC out of `/proc/net/route`, `/proc/net/arp` and `/sys`, with an ARP nudge, since injecting frames means we own Layer 2. Source IP and MAC are hard-bound to this host, the full-frame path exposes no spoofing knob.

`send_l4` returns whether the frame was actually enqueued, so a TX-ring-full backpressure drop is counted as attempted-not-sent and never inflates the sent counter, which is a mistake an earlier version made and it made the pps numbers lie.

## Classifier (`classify.rs`)

`classify(Signals, samples)` returns a verdict, a confidence, and evidence. Checked in order: the health probe first (ground truth, local exhaustion excluded, and if it dominates the probe is declared unreliable and we fall through rather than blame the target), then the service probe, then an L4-only fallback (stable probe means Healthy, no probe signal at all means Unknown), then the rate limiter (429s), then the WAF (403s plus a vendor fingerprint), then latency exhaustion (p99 over 3x baseline and over 25ms sustained for three samples), and finally Healthy for a clean 2xx run. Confidence is capped at 0.9, it reports likelihood and never proof, so it will not call a working WAF a vuln.

## Cross-cutting

`logging.rs` sends tracing to a timestamped `onb-<runid>.log` under `$XDG_STATE_HOME/opennetbench` (or `~/.local/state/opennetbench`, override with `--log-dir`) and the terminal. If that directory can't be written it warns and keeps going terminal-only. `metrics.rs` holds the serializable shapes a report or the future dashboard will consume. `db.rs` and `web/` are stubs for the planned SQLite history and dashboard.

## Extending it

New vector: add a `Vector` variant with its metadata, write an `engine/<name>.rs` worker following the gate and shutdown pattern, add a dispatch arm in `engine::run`, reuse `net::Conn` for TCP or `raw.rs` for raw sockets. New preset: one entry in `presets::PRESETS`. New classifier signal: a field on `Signals`, populate it in `engine::run`, add a branch in `classify` and keep the confidence honest.

## Build and test

```bash
cargo build --release          # optimized binary
cargo build --release --features xdp   # with the AF_XDP backend
cargo test                     # unit and in-process integration tests
./install.sh                   # build and put opennetbench on PATH
```

Tests cover the byte-level encoders (DNS wire format, HTTP/2 framing, Ethernet/IP frame build and checksums), the L2 parsers, the queue-slice partition, the HTML scanner, the latency histogram, an in-process traffic smoke test, and the classifier verdict matrix.
