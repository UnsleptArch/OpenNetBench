# Architecture

*How the system is built, module by module, with the reasoning behind each structural choice.
This document is for reading and auditing the code; to operate the tool, read
[USAGE.md](USAGE.md), and for function-level internals — memory ordering, the control loops, the
numerical methods — read [INTERNALS.md](INTERNALS.md), of which this is the architectural
companion.*

---

## Table of Contents

1. [One Paragraph](#1-one-paragraph)
2. [Design Principles](#2-design-principles)
3. [Safety Model, Enforced by Structure](#3-safety-model-enforced-by-structure)
4. [The Run Lifecycle](#4-the-run-lifecycle)
5. [The Configuration Model](#5-the-configuration-model)
6. [Presets and the Auto-Engine](#6-presets-and-the-auto-engine)
7. [Reconnaissance](#7-reconnaissance)
8. [The Load Engine](#8-the-load-engine)
9. [The Two Ground-Truth Probes](#9-the-two-ground-truth-probes)
10. [The Transmit Backends](#10-the-transmit-backends)
11. [The Classifier](#11-the-classifier)
12. [Cross-Cutting Modules](#12-cross-cutting-modules)
13. [Extending the System](#13-extending-the-system)
14. [Build and Test](#14-build-and-test)

---

## 1. One Paragraph

OpenNetBench is a single-origin adversarial-load tool. It generates the traffic real attackers
use, from L3 to L7, across twenty vectors, from one host; it measures how the target behaves under
that load with two independent probes; and it classifies the outcome with a confidence and an
evidence trail. There is no amplification and no command-and-control, both by construction, with
an optional SOCKS5 proxy for the L7 path. On realistic targets the NIC is the hard ceiling, not
the code.

---

## 2. Design Principles

Five principles recur throughout the codebase and explain most of its non-obvious structure.
Naming them once here makes the later sections shorter.

1. **Honesty over firepower.** The tool's value is the *verdict*, and a verdict is worthless if it
   can be fooled by the tool's own limitations. A large fraction of the engineering budget goes not
   to generating load but to *not lying about it*: separating egress from confirmed delivery,
   detecting local resource exhaustion, refusing to adapt on a signal that does not exist, and
   capping confidence below certainty. Where firepower and honesty conflict, honesty wins.
2. **Structural safety.** Safety properties are enforced by the shape of the tree — absent
   capabilities and mandatory gates — not by runtime policy (see §3 and [SAFETY.md](SAFETY.md)).
3. **Lock-free hot path, zero per-operation allocation.** The load engine sustains thousands of
   concurrent workers, so the per-operation cost must be O(1) and allocation-free; templates and
   frame prefixes are built once and shared.
4. **Pure seams for testing and fuzzing.** The parsers and the classifier are pure functions of
   their inputs, which is what makes them unit-testable and fuzzable (see [FUZZING.md](FUZZING.md));
   the library/binary split exists to make those seams linkable.
5. **Explicit over clever.** Named constants over magic numbers, stated memory ordering over
   implicit assumptions, and design decisions recorded in comments where the rejected alternative
   matters.

---

## 3. Safety Model, Enforced by Structure

These are not policy promises; they fall out of how the tree is built. The full treatment is in
[SAFETY.md](SAFETY.md); the summary:

| Property | How it is guaranteed |
|---|---|
| Single origin | All traffic leaves this host. There is no agent protocol, no peer discovery, no coordination code anywhere. |
| No spoofing | Raw vectors compute checksums from the host's real source IP (`local_src_ipv4`); spoofing is not implemented, and would break the stateful TCP vectors anyway (the SYN-ACK would go elsewhere). |
| No amplification | No reflection vectors exist. Every byte is generated locally. |
| No C2 | No remote-control surface. The only egress is attack traffic and the probes, both to the named target. |
| Mandatory consent | `auth.rs` blocks every interactive run until an exact phrase is typed at a TTY; a flag or a file cannot satisfy it. |

---

## 4. The Run Lifecycle

The binary (`main.rs`) is a thin shim over the library crate (`lib.rs`); its whole job is to route
a parsed CLI to one of a few resolution paths and then hand a `RunConfig` to `engine::run`. The
top-level flow:

```
parse CLI
  --list-presets / --list-vectors   print and exit
  --save-config                     build plan, write JSON, exit  (no consent, nothing fires)
  --ui-only                         serve dashboard, exit  (stub)
  run path:
     legal notice + consent gate    (auth::require_consent, or --i-am-authorized asserts it)
     --recon URL                    run_recon, print the ranked report, exit  (no flood)
     resolve the plan:
        --auto      characterize, recommend, build_config
        --preset    build_config(preset, target)
        --config    load_config(json)
        --vectors   build_flag_config   (fully scripted, no prompts)
        none        interactive_flow
     if run_recon   run_recon, present, select or auto-approve the target
     final "execute this plan?" confirm   (skipped by --i-am-authorized)
     engine::run(cfg, ctx)
```

Two properties of this flow are worth drawing out. First, the *only* paths that reach
`engine::run` — the point at which traffic is generated — pass through the consent gate or the
explicit `--i-am-authorized` assertion; there is no back door. Second, the plan-building paths
(`--save-config`) deliberately terminate *before* consent, because writing a plan is not running
one, and requiring consent to serialise a JSON file would be theatre.

The library crate exists so the parsers and the classifier can be linked in-process by the
out-of-tree fuzz harnesses; a libFuzzer harness is a function, not a subprocess, so it needs a
`lib` target (see [INTERNALS.md](INTERNALS.md) §2 and [FUZZING.md](FUZZING.md)).

---

## 5. The Configuration Model

`config.rs` is the single source of truth for *what a run is*.

- **`Vector`** is the twenty vectors as an enum. Each variant carries its metadata through
  methods: `slug()` (stable public identifier), `layer()`, `needs_root()`, `has_load_feedback()`,
  `records_http_status()`, and `description()`. `Vector::ALL` is the canonical ordering.
- **`RunMode`** is `Adaptive` or `Dumb` (§8, [USAGE.md](USAGE.md) §8).
- **`VectorTuning`** holds the per-vector knobs (`concurrency`, `rate_per_worker`, `payload_bytes`,
  `trickle_interval`, `port`), with `defaults_for(vector)` supplying conservative small-scale
  defaults.
- **`RunConfig`** is the fully-resolved, serialisable plan: target, proxy, mode, recon flag, the
  vector list with tuning, duration, and ramp. It is exactly what `--save-config` writes and
  `--config` reads.

Two of the metadata predicates carry real correctness weight and are deliberately kept beside the
vector list rather than scattered across the engine:

- `records_http_status()` marks the six vectors whose workers report HTTP status codes. The
  classifier keys its L7 signal on exactly this set; keeping the predicate co-located with the
  vector definition stops the classifier's gate from silently drifting out of sync when a new HTTP
  vector is added (an omission there would make the classifier discard that vector's status codes).
- `has_load_feedback()` partitions the vectors into feedback and fire-and-forget. This single
  predicate governs whether a vector may be adaptively throttled and whether its send count counts
  as egress or delivery — see [INTERNALS.md](INTERNALS.md) §6 and [VECTORS.md](VECTORS.md) §2.

---

## 6. Presets and the Auto-Engine

**Presets (`presets.rs`).** A `Preset` is a curated vector combination for a target class.
`build_config` stamps `PRESET_CONCURRENCY` (2700) on every vector and returns an ordinary
`RunConfig` that can still be dumped and edited. There is no aggressiveness ladder on purpose;
presets run at one fixed pressure, tuned down from a naïve 3000 so that a single origin exhausts
the target's state before its own local socket limits (see [USAGE.md](USAGE.md) §4).

**Auto-engine (`auto.rs`).** `--auto` is recommend-and-approve; it never fires on its own.
`characterize(target)` performs a TCP-connect port scan plus an HTTP/HTTPS fingerprint plus WAF and
embedded-server detection, classifies the result into a `TargetKind`, and `recommend` maps that to
a preset with human-readable reasoning before dropping into the normal consent-and-confirm path.
Private IPs and embedded servers (uhttpd, RomPager) are classified as routers even when they serve
a web UI, because a router admin page is not a web application and the right vectors differ.

---

## 7. Reconnaissance

The `recon/` module finds *where to aim* before any flood, on the thesis that a single origin wins
by asymmetry, not brute force.

- **`fingerprint.rs`** reads the `Server` header, notes missing security headers, enumerates methods
  via OPTIONS/TRACE, and probes around forty sensitive paths.
- **`crawl.rs`** is an async same-host breadth-first crawl with a byte-scanner for links and form
  actions — no `html5ever` dependency; the scanner walks bytes directly.
- **`discover.rs`** reads the structured sources (`robots.txt`, sitemap, OpenAPI/Swagger) and mines
  JavaScript bundles for API routes, so a single-page app reveals its real API surface.
- **`param.rs` / `probe.rs`** perform the differential probing: for each candidate parameter, a
  cheap value and an expensive one, sampled in interleaved pairs, measuring the marginal server time
  the expensive input forces and attaching a confidence from the spread.
- **`score.rs`** is the asymmetry model — server cost over client cost, log-compressed per axis,
  confidence-weighted on compute, cache-discounted on bandwidth (see [INTERNALS.md](INTERNALS.md)
  §13).

`run_recon` assembles the candidates, times each with a small-sample TTFB average, detects
cacheability, scores asymmetry, and returns a ranked report. Recon never auto-fires; the operator
(or `--auto-approve`) selects the target from the ranked list. The parsers here are the primary
fuzzing surface ([FUZZING.md](FUZZING.md)).

---

## 8. The Load Engine

`engine/` is the performance-critical core: lock-free hot path, zero per-request allocation, O(1)
recording, prompt cooperative shutdown. The function-level treatment is in
[INTERNALS.md](INTERNALS.md) §3–§9; the architecture:

### 8.1 Shared state (`engine/mod.rs`)

`Metrics` is all `AtomicU64`/`AtomicU32` with `Relaxed` ordering — no per-request mutex — and there
is **one instance per vector**. The sampler and summary aggregate across them, but each governor
sees only its own vector's metrics, so a distressed vector never throttles a healthy one.
`responses_ok` means a real round-trip; connectionless floods increment `packets_sent` instead,
which is local egress and not confirmed delivery, so their send rate is never reported as target
throughput. The `Relaxed` ordering is correct because counter increments commute and no counter
publishes other memory (see [INTERNALS.md](INTERNALS.md) §3).

`Shutdown` wraps a `tokio::sync::watch<bool>`: a cheap `is_down()` read plus a `subscribe()`
receiver that each worker races in `select!`, so there is no lost-notification window. `run()`
force-aborts any straggler after a five-second drain grace, so stopping the process always stops
the traffic.

`Governor` per vector is an `AtomicU32` target that workers gate on with one relaxed load.
`govern()` ramps it from zero to max over the ramp-up and, in adaptive mode with a feedback signal,
halves it under distress and re-grows — the AIMD cycle that measures recovery. Fire-and-forget
vectors just ramp; they never fake an adaptive decision off a local send count.

Before spawning, `fd_scale()` reads `RLIMIT_NOFILE`, raises the soft limit toward the hard cap, and
scales concurrency down to fit if it still will not, so the run does not produce an `EMFILE` storm
that reads as target failure but is really the generator's own socket table.

### 8.2 Latency histogram (`engine/histogram.rs`)

HdrHistogram-style, 512 buckets, a constant ~4 KB. Recording is O(1) — one `leading_zeros` and one
atomic add — and safe to hammer concurrently. Quantiles are computed only in the sampler, four
times a second, over *windowed* deltas, so the collapse curve reflects latency at the current load
rather than a cumulative average that would smear the signal.

### 8.3 Sampler and outcome

`sample()` runs every 250 ms, aggregates every vector's histogram, computes windowed p50/p95/p99,
and derives RPS and error rate. RPS is completed responses over the *actual* elapsed window, not a
nominal 250 ms, because a late wakeup under load would otherwise distort it. Error rate is errors
over completions-plus-errors. After the run, `derive_outcome()` pulls the baseline p99 (from recon
if it ran), the time-to-degradation, the knee, and the recovery time. Degradation requires a 3×
ratio, an absolute delta over 25 ms, and both holding for three consecutive samples, so a lone
spike never registers.

### 8.4 Connection layer (`engine/net.rs`)

`Conn` is plain-or-TLS behind one enum, both variants `Unpin`, so the I/O path carries no box and no
vtable dispatch. `Target::resolve` does DNS once up front and shares the `SocketAddr`. Request
templates — rotating browser fingerprints, the slowloris head, the RUDY POST head, the CVE-2011-3192
Range request — are serialised once, so workers never format strings in the loop. When a SOCKS5
proxy is configured, every TCP connection routes through it (TCP only); the raw and UDP vectors
egress directly and the tool warns.

### 8.5 The vectors

Each vector is its own module following the shared gate-and-shutdown contract ([VECTORS.md](VECTORS.md)
§2). The L7 vectors are async Tokio tasks over `net::Conn`; the raw vectors run a synchronous send
loop on dedicated, CPU-pinned threads that read the shared atomics and the shutdown flag directly.

---

## 9. The Two Ground-Truth Probes

Two independent direct observers run alongside the load, never proxied, because the whole point is
an *independent* measurement of the target rather than an inference from the attack traffic.

**`health_probe()`** TCP-connects once a second, with a pre-load baseline. Each connect is
classified by *whose fault* a failure is: a success, a RST (Refused), a timeout or unreachable
(TargetFail), or our own socket exhaustion (LocalExhausted, which is excluded from any "target
down" call). A RST counts as failure only if the service was accepting at baseline, so
baseline-accepting-into-load-refused means the load knocked the listener over. This is the only
signal that works for the raw L4 vectors.

**`service_probe()`** fires a real independent GET once a second when the app answered at baseline.
It catches what a TCP connect cannot: a server whose worker pool is starved by slowloris still
completes TCP handshakes while answering no real requests. Baseline-healthy GETs failing under load
is a finding even when the connect probe looks fine.

The separation of these two probes, and the local-exhaustion classification within the first, is
the operational core of the honesty principle (§2.1): it is how the tool distinguishes the target
dying from the generator running out of sockets, and the application dying from the connection layer
surviving.

---

## 10. The Transmit Backends

`packet_tx.rs`, `packet_mmsg.rs`, `wire.rs`, `l2.rs`, `xdp.rs` — where the large packet-rate numbers
come from. The raw SYN/ACK path selects the fastest transmitter available at startup behind the
`PacketTx` trait and falls back cleanly, so it always runs. The performance analysis is in
[PERFORMANCE.md](PERFORMANCE.md); the datapath internals in [INTERNALS.md](INTERNALS.md) §8.

The unit of parallelism is the **shard**, not the logical worker. Worker index 0 is the shard
leader: it resolves Layer 2 once, then spawns one pinned thread per shard. CPUs are partitioned
across the running raw vectors with `l2::queue_slice`, so on a router run `syn` takes the low half of
the cores and `ack` the high half, each shard pinned to its core with `sched_setaffinity` to keep the
frame prefix, the ring indices, and the completion descriptors warm on one core. This shard-collapse
model is the default path; it fixed a starvation bug in which the old per-worker model saturated
Tokio's blocking pool with the first vector and never ran the second.

Backends, fastest first:

1. **AF_XDP** (`xdp.rs`, only with `--features xdp`). Pure libc, TX-only. Frames go into a shared
   UMEM and out an AF_XDP TX ring, so the per-packet `sendto` collapses to one wakeup syscall per
   batch and nothing touches the IP stack, netfilter, or conntrack. One socket per NIC TX queue,
   queues partitioned across vectors. No libbpf or libxdp — the default build pulls no C toolchain.
   Producer stores are `Release`, completion reads `Acquire` (the one place the ordering genuinely
   matters; see [INTERNALS.md](INTERNALS.md) §8.3).
2. **AF_PACKET + `sendmmsg`** (`packet_mmsg.rs`). A `SOCK_RAW` socket bound to the egress ifindex,
   buffering up to 1024 full frames and flushing them with one `sendmmsg`, with `PACKET_QDISC_BYPASS`
   set so it skips the qdisc spinlock that otherwise caps multicore scaling. Works on any NIC. This is
   the backend that carries the tool past 10 GbE when XDP is not built or the NIC will not do it.
3. **Kernel Layer-4** (`pnet_transport`). The original path; the kernel builds IP and L2. The
   always-available last resort when not root or when Layer 2 will not resolve.

`wire.rs` builds the Ethernet + IPv4 prefix with correct checksums, unit-tested byte-exact and fuzzed
([INTERNALS.md](INTERNALS.md) §9). `l2.rs` resolves the egress interface, source MAC, and next-hop MAC
from `/proc/net/route`, `/proc/net/arp`, and `/sys`, with an ARP nudge, because injecting frames means
owning Layer 2. Source IP and MAC are hard-bound to this host; the full-frame path exposes no spoofing
knob. `send_l4` returns whether a frame was actually enqueued, so a TX-ring-full backpressure drop is
counted as attempted-not-sent and never inflates the sent counter — a mistake an earlier version made
that made the pps numbers lie.

---

## 11. The Classifier

`classify(Signals, samples)` returns a verdict, a confidence, and an evidence trail. The full
decision cascade, the robust statistics, and the confidence calibration are in
[INTERNALS.md](INTERNALS.md) §10–§12; the architecture is a priority-ordered cascade where the first
section with sufficient evidence returns:

1. the health probe (ground truth, local exhaustion excluded; if local failures dominate the probe is
   declared unreliable and the cascade falls through rather than blaming the target),
2. the service probe (worker-pool exhaustion a TCP connect cannot see),
3. an L4-only fallback (a stable probe means Healthy; no probe signal at all means Unknown),
4. the rate limiter (429s → MitigationEngaged),
5. the WAF (403s plus a vendor fingerprint → MitigationEngaged),
6. latency exhaustion (the collapse-curve analysis → Degrading/Down),
7. Healthy for a clean 2xx run.

The p99 breach threshold is the strongest of three floors — a 3× ratio, a 25 ms absolute delta, and a
noise-relative bar (the median plus five MADs of the run's own quiet prefix) — held for three
consecutive samples. The noise term stops a jittery target crying wolf on ordinary variance while
still letting a rock-stable one register a real 40 ms stall. A server failing fast behind a proxy
(instant 5xx or 408 under load) is caught by a separate server-error branch even when latency never
moves. Confidence is capped at 0.9 — likelihood, never proof — so a working WAF is never called a
vulnerability.

---

## 12. Cross-Cutting Modules

- **`logging.rs`** sends `tracing` output to a timestamped `onb-<runid>.log` under
  `$XDG_STATE_HOME/opennetbench` (or `~/.local/state/opennetbench`, override with `--log-dir`) and to
  the terminal; an unwritable directory degrades to terminal-only with a warning rather than failing.
- **`metrics.rs`** holds the serialisable shapes (`LatencySample`, `Snapshot`, `RunOutcome`) that a
  report or the planned dashboard consumes — the wire types shared between engine and classifier.
- **`auth.rs`** is the consent gate (§3, [SAFETY.md](SAFETY.md) §7).
- **`db.rs`** and **`web/`** are scaffolded stubs for the planned SQLite history and dashboard; their
  forward-declared types are why `lib.rs` carries a scoped `#![allow(dead_code)]`.

---

## 13. Extending the System

The extension points are deliberately narrow:

- **New vector:** add a `Vector` variant with its metadata (remember `needs_root`,
  `has_load_feedback`, and `records_http_status` — the last is what keeps the classifier's L7 gate in
  sync); write an `engine/<name>.rs` worker following the gate-and-shutdown contract; add a dispatch
  arm in `engine::run`; reuse `net::Conn` for TCP or `raw.rs` for raw sockets.
- **New preset:** one entry in `presets::PRESETS`.
- **New classifier signal:** a field on `Signals`, populated in `engine::run`, plus a branch in
  `classify` — and keep the confidence honest (cap it, corroborate it; see
  [INTERNALS.md](INTERNALS.md) §12).

---

## 14. Build and Test

```bash
cargo build --release                    # optimised binary
cargo build --release --features xdp     # with the AF_XDP backend
cargo test                               # unit and in-process integration tests
./install.sh                             # build and put opennetbench on PATH
```

The unit suite covers the byte-level encoders (DNS wire format, HTTP/2 framing, Ethernet/IP frame
build and checksums), the L2 parsers, the queue-slice partition, the HTML and JS scanners, the recon
differential and scoring, the latency histogram, in-process traffic and recon smoke tests against
hand-rolled servers, and the classifier verdict matrix. On top of it, the pure parsers and the
classifier are fuzzed with `cargo-fuzz` via the `cfg(fuzzing)`-gated surface, a campaign that already
found and fixed a real integer overflow in the classifier. The harnesses and methodology are in
[FUZZING.md](FUZZING.md); the function-level internals in [INTERNALS.md](INTERNALS.md).
