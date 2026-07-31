# OpenNetBench — Code Internals Reference

*A module-level and function-level treatment of the implementation, intended for
contributors, auditors, and reviewers. Where the prose describes an invariant, that
invariant is enforced in the code cited alongside it; where it describes a design
tradeoff, the rejected alternative is named so the decision can be re-examined rather
than merely inherited.*

---

## Table of Contents

1. [Scope and Reading Order](#1-scope-and-reading-order)
2. [Crate Topology and the Library/Binary Split](#2-crate-topology-and-the-librarybinary-split)
3. [Concurrency Model and Memory Ordering](#3-concurrency-model-and-memory-ordering)
4. [The Metrics Substrate](#4-the-metrics-substrate)
5. [Admission Control: The File-Descriptor Budget](#5-admission-control-the-file-descriptor-budget)
6. [The Governor: Ramp-Up and Adaptive Throttling](#6-the-governor-ramp-up-and-adaptive-throttling)
7. [Cooperative Shutdown](#7-cooperative-shutdown)
8. [The Transmit Datapath](#8-the-transmit-datapath)
9. [Frame Construction and the Internet Checksum](#9-frame-construction-and-the-internet-checksum)
10. [The Classifier: From Counters to a Verdict](#10-the-classifier-from-counters-to-a-verdict)
11. [Robust Degradation Detection](#11-robust-degradation-detection)
12. [Confidence Calibration](#12-confidence-calibration)
13. [Reconnaissance and the Asymmetry Model](#13-reconnaissance-and-the-asymmetry-model)
14. [The Fuzzing Surface](#14-the-fuzzing-surface)
15. [Invariants Catalogue](#15-invariants-catalogue)
16. [Glossary](#16-glossary)

---

## 1. Scope and Reading Order

This document describes *how the code is built*, not *how to operate it* (see
[USAGE.md](USAGE.md)) nor *why the vectors hurt* (see [VECTORS.md](VECTORS.md)). It
is complementary to [ARCHITECTURE.md](ARCHITECTURE.md): the architecture document
gives the bird's-eye module map, whereas this document descends to the level of
individual data structures, the memory-ordering discipline that keeps them correct
under concurrency, and the numerical methods that turn raw observations into a
defensible verdict.

A productive reading order for a first-time contributor is: §2 to situate the crate
layout, §3 to internalise the concurrency contract that every subsequent section
assumes, then §4–§7 for the load engine, §8–§9 for the raw datapath, §10–§12 for the
decision engine, and §13 for reconnaissance. Sections §14–§16 are reference material.

Throughout, a claim of the form *"the code guarantees X"* should be read as a
falsifiable assertion: if the cited function does not in fact guarantee X, that is a
bug in the code or in this document, and either way it should be reported.

---

## 2. Crate Topology and the Library/Binary Split

The project is a single Cargo package that compiles to two targets: a library crate
(`src/lib.rs`) and a thin binary (`src/main.rs`). The binary is deliberately anaemic —
it parses arguments, constructs a `RunConfig`, and hands control to the library. All
substantive logic lives in the library so that it can be linked by a *third* consumer:
the out-of-tree fuzzing crate under `dev/fuzz`.

This split is not stylistic. A libFuzzer harness is fundamentally a function —
`fuzz_target!(|data: &[u8]| { … })` — that the fuzzing runtime calls in-process,
millions of times, inside a single long-lived address space. It is emphatically *not*
a subprocess driven by a forkserver. Consequently a harness can only exercise code it
can *link against*, which requires that code to live behind a `lib` target with a
reachable symbol. Had the parsers and the classifier been buried in a binary-only
module tree, they would be unreachable from the fuzzer without duplication. The public
module declarations in `lib.rs` are what make the pure decision functions addressable:

```rust
pub mod auth;      pub mod auto;     pub mod classify;  pub mod cli;
pub mod config;    pub mod db;       pub mod engine;    pub mod logging;
pub mod metrics;   pub mod presets;  pub mod recon;     pub mod web;
```

The module responsibilities partition cleanly:

| Module | Responsibility |
|---|---|
| `config` | The declarative `RunConfig` and its constituent enums (`Vector`, `RunMode`, `VectorTuning`, `VectorPlan`). The single source of truth for *what* a run is. |
| `cli` | Argument parsing and the interactive prompt flow; produces a `RunConfig`. |
| `auth` | The consent gate — the typed-phrase interlock and the `--i-am-authorized` assertion. |
| `presets` | Named bundles of vectors and tuning (`web`, `api`, `router`, …). |
| `auto` | Target characterisation that recommends a vector combination. |
| `recon` | Active reconnaissance: crawl, discovery, differential probing, and asymmetry scoring. |
| `engine` | The load engine proper: metrics, governor, sampler, and the per-vector workers. |
| `classify` | The verdict engine: robust statistics over the sampled collapse curve. |
| `metrics` | The wire types shared between engine and classifier (`LatencySample`, `Snapshot`, `RunOutcome`). |
| `logging`, `db`, `web` | Structured logging, per-host persistence, and the (scaffolded) web surface. |

### 2.1 The `dead_code` allowance

`lib.rs` carries `#![allow(dead_code)]` with an explicit rationale in its header
comment: several types are forward-declared for modules that land in later increments
(the web server, the persistence layer, CVE correlation). This is a conscious
suspension of a normally-valuable lint, scoped to the crate root, and it is the kind
of thing an auditor should note and periodically challenge — a forward declaration
that never acquires a caller is indistinguishable from genuinely dead code.

### 2.2 The `cfg(fuzzing)` surface

The fuzzing entry points are gated behind `#[cfg(fuzzing)]`:

```rust
#[cfg(fuzzing)]
pub mod fuzz;
```

`cargo-fuzz` sets the `fuzzing` cfg for the entire build, so this module — a set of
thin `pub` wrappers over otherwise `pub(crate)` pure functions — exists *only* inside
a fuzzing build. An ordinary `cargo build` compiles as though the module were absent,
so the public API of the library is unchanged by the presence of the fuzz surface.
This is the mechanism by which internal functions are made fuzzable without widening
their visibility in production. See §14.

---

## 3. Concurrency Model and Memory Ordering

The engine is a Tokio multi-threaded runtime hosting three populations of tasks:

1. **Workers** — one Tokio task per unit of concurrency per vector. A worker is the
   thing that actually generates load: it opens a socket, sends, and (for
   connection-oriented vectors) reads.
2. **Governors** — one per vector. A governor does no I/O; it periodically adjusts how
   many of its vector's workers are permitted to generate load.
3. **The sampler** — one per run. It wakes on a fixed cadence, reads the shared
   counters, and appends a `LatencySample` to the collapse curve.

All three populations communicate through shared `Arc<Metrics>` and a small number of
atomics. There is deliberately no lock on the hot path. The correctness of a lock-free
design rests entirely on choosing the right memory ordering for each atomic operation,
so the reasoning is made explicit here rather than left implicit in `Relaxed`
sprinkled through the code.

### 3.1 Why counters use `Relaxed`

Every metric counter (`requests_sent`, `responses_ok`, `packets_sent`, `errors`,
`bytes_sent`, the HTTP status buckets) is incremented with
`fetch_add(1, Ordering::Relaxed)`. This is correct because:

- **Increments commute.** The final value of a monotone counter does not depend on the
  order in which concurrent `fetch_add`s are applied; addition is associative and
  commutative, and `fetch_add` is atomic, so no update is lost regardless of ordering.
- **No counter *publishes* another memory location.** `Relaxed` provides atomicity but
  no happens-before edge to surrounding non-atomic memory. That is acceptable *only*
  because a counter increment is never used as a signal that some other,
  non-atomically-written datum is now visible. Each counter is self-contained.
- **The reader tolerates skew.** The sampler reads counters that other threads are
  concurrently mutating. It may observe a value that is momentarily behind the true
  aggregate. This is not a correctness defect: a load-generation rate is a statistical
  quantity sampled over a window, and a few-microsecond skew between sibling counters
  is far below the noise floor of the measurement.

Were any counter used to gate visibility of *other* memory — a classic "set the data,
then set the ready flag" pattern — `Relaxed` would be wrong and an `Acquire`/`Release`
pair would be required. No such pattern exists on the counter path. Where such a
pattern *does* exist — the AF_XDP producer/consumer rings — the code correctly uses
`Release` on the producer store and `Acquire` on the consumer load (§8.3).

### 3.2 Why the governor target uses `Relaxed`

The `Governor::target` atomic is written by exactly one governor and read by many
workers of the same vector via `active(idx)`:

```rust
pub fn active(&self, idx: u32) -> bool {
    idx < self.target.load(Relaxed)
}
```

A worker whose index momentarily exceeds a freshly-lowered target simply completes its
current in-flight operation and re-checks on its next loop iteration; a worker whose
index is newly below a freshly-raised target begins generating load one iteration
later than it strictly could. Both outcomes are benign: the target is a *rate control
hint*, not a hard barrier, and the system is self-correcting on a 500 ms cadence.
Paying for `SeqCst` ordering here would buy nothing but a memory fence on the busiest
read in the program.

### 3.3 Ordering on the shutdown path

The one place where cross-thread *ordering* genuinely matters — a worker must reliably
observe that the run is over — is handled not by a bare atomic but by a Tokio `watch`
channel (§7). The channel provides the happens-before relationship and, crucially, the
*wakeup*: a worker parked in `tokio::select!` is woken promptly rather than polling. A
naked `AtomicBool` would provide the flag but not the wakeup, forcing a busy-poll.

---

## 4. The Metrics Substrate

`engine::Metrics` is the shared, lock-free record of everything a run produces. Its
fields fall into three groups.

### 4.1 Send-side counters, and the delivery/egress distinction

The single most important semantic distinction in the entire metrics design is between
two superficially-similar counters:

```rust
/// Completed round-trips: an actual response/handshake was received from the target.
pub responses_ok: AtomicU64,
/// Datagrams/packets handed to the local kernel by fire-and-forget vectors.
pub packets_sent: AtomicU64,
```

`responses_ok` counts *confirmed delivery* — a byte came back from the target, so we
know the target received something and answered. `packets_sent` counts *local egress*
— we handed a datagram to our own kernel and it accepted it for transmission. For a
connectionless flood (UDP, DNS, ICMP, raw SYN/ACK) there is no return traffic by
construction, so `responses_ok` must remain zero and only `packets_sent` advances.

The invariant, stated in the source, is that **a connectionless vector must never touch
`responses_ok`**. The reason is not tidiness: if egress were reported as throughput,
the tool would claim the *target* absorbed traffic that in reality never left the local
NIC's ring buffer, or that a firewall silently dropped. Conflating the two is precisely
the failure mode that makes naïve flooders lie about their effect. Keeping them in
separate counters means the summary can report "we emitted N packets" without ever
implying "the target processed N packets."

### 4.2 The HTTP status distribution

Seven counters bucket application-layer responses: `http_2xx`, `http_3xx`, `http_4xx`,
`http_403`, `http_408`, `http_429`, `http_5xx`. Two of these are pulled out of their
natural range on purpose:

- **`http_403`** is separated from the general `4xx` bucket because a 403 is a WAF/CDN
  fingerprint, not an ordinary client error — it is evidence of *mitigation*, which
  the classifier must treat categorically differently from a 404.
- **`http_408`** (Request Timeout) is separated because it is a *server-stress* signal:
  the server gave up reading our request under load. It belongs with the 5xx family in
  the classifier's "server distress" computation, not with the benign 4xx client
  errors.

The bucketing is performed once, at the point of observation, by `record_status`:

```rust
pub fn record_status(&self, code: u16) {
    let c = match code {
        200..=299 => &self.http_2xx,
        300..=399 => &self.http_3xx,
        403       => &self.http_403,
        408       => &self.http_408,
        429       => &self.http_429,
        400..=499 => &self.http_4xx,
        500..=599 => &self.http_5xx,
        _         => return,
    };
    c.fetch_add(1, Relaxed);
}
```

Note the ordering of the match arms: the specific codes (403, 408, 429) precede the
broad ranges (`400..=499`), so they win. A status outside 200–599 is silently ignored
rather than mis-bucketed — a defensible choice given that such codes are not part of
any signal the classifier consumes.

### 4.3 One `Metrics` per vector

The engine allocates a *separate* `Metrics` per vector rather than one shared instance:

```rust
// One Metrics per vector: each governor throttles on its OWN vector's signal
// (no cross-vector contamination), and the sampler/summary aggregate across them.
```

This is a correctness requirement for adaptive throttling. If an HTTP flood and a
Slowloris shared a counter, the Slowloris governor would throttle on the HTTP flood's
error rate and vice versa — a vector could back off because a *sibling* vector was in
distress. Per-vector isolation guarantees each governor's control loop closes over its
own signal. Aggregation for reporting is a separate, read-only concern, handled by:

```rust
fn agg(metrics: &[Arc<Metrics>], f: impl Fn(&Metrics) -> u64) -> u64 {
    metrics.iter().map(|m| f(m)).sum()
}
```

### 4.4 Held-connection accounting via RAII

Connection-holding vectors (Slowloris, RUDY, slow-read, TCP-exhaust) track live
connections in `held_connections: AtomicU32`. The count is maintained not by manual
increment/decrement pairs — which leak on every early `return` in an error path — but
by an RAII guard:

```rust
pub struct HeldGuard<'a>(&'a AtomicU32);
impl<'a> HeldGuard<'a> {
    pub fn new(c: &'a AtomicU32) -> Self { c.fetch_add(1, Relaxed); HeldGuard(c) }
}
impl Drop for HeldGuard<'_> {
    fn drop(&mut self) { self.0.fetch_sub(1, Relaxed); }
}
```

Because `Drop` runs on every scope exit — normal completion, `?` propagation, panic
unwinding — the counter tracks lexical scope *exactly*. There is no code path on which
a connection is opened, the guard constructed, and the decrement skipped. This turns a
notoriously leak-prone counter into one that is correct by construction.

---

## 5. Admission Control: The File-Descriptor Budget

Nearly every worker holds one socket, and a socket is a file descriptor. If the sum of
all vectors' requested concurrency exceeds the process's open-file limit, the kernel
returns `EMFILE` on socket creation — and those failures manifest as connection errors
that *look like the target refusing us* but are in fact self-inflicted. Left
unmanaged, this would poison every downstream signal.

`fd_scale` is the admission controller that prevents it:

```rust
const FD_HEADROOM: u64 = 128;

fn fd_scale(planned: u64) -> f64 {
    if planned == 0 { return 1.0; }
    let want = planned + FD_HEADROOM;
    let soft = rlimit::increase_nofile_limit(want).unwrap_or_else(|_| {
        rlimit::Resource::NOFILE.get().map(|(s, _)| s).unwrap_or(1024)
    });
    if want <= soft { return 1.0; }
    let usable = soft.saturating_sub(FD_HEADROOM).max(1);
    usable as f64 / planned as f64
}
```

The logic proceeds in three steps. First, it computes the total demand plus a headroom
reserve of 128 descriptors set aside for the runtime, the health probes, log files,
and DNS. Second, it *attempts to raise the soft limit* toward the hard cap — on most
systems the soft `NOFILE` limit is a conservative default well below the hard ceiling,
and simply asking for more is often granted. Third, if demand still cannot fit, it
returns a scale factor in `(0, 1]` that the caller multiplies into every vector's
concurrency, shrinking the whole run proportionally so that it fits within the
descriptors actually available.

Two details reward attention. The `saturating_sub` guards against the degenerate case
where the soft limit is itself below the headroom — subtraction cannot wrap to a huge
number. The `.max(1)` on the usable count guarantees the scale factor is never zero, so
a requested run always makes *some* progress rather than silently generating no load.
The preflight also excludes vectors that will be skipped for lack of root, so the
budget is computed against the run that will actually execute.

The engineering thesis here is that **a load generator must never mistake its own
resource exhaustion for the target's**. §10 shows the *other half* of that thesis — the
classifier's local-exhaustion detection — but admission control is the first line of
defence: don't ask for descriptors you cannot get.

---

## 6. The Governor: Ramp-Up and Adaptive Throttling

Each vector's `govern` task is a discrete control loop running on a 500 ms cadence. It
computes, each tick, how many workers should be permitted to generate load, and stores
that number in `Governor::target`. Its structure is a linear ramp bounded above,
optionally reduced by an error-rate feedback term.

### 6.1 The ramp ceiling

```rust
let ramp_ceiling = if rampup.is_zero() {
    gov.max
} else {
    let frac = (elapsed.as_secs_f64() / rampup.as_secs_f64()).min(1.0);
    ((frac * gov.max as f64) as u32).max(1)
};
```

The ceiling grows linearly from (near) zero to `gov.max` over the configured ramp-up
duration, then saturates. A gradual ramp serves two purposes: it lets the sampler
observe the *knee* of the collapse curve — the load at which latency begins to diverge
— rather than slamming straight to maximum and seeing only the endpoint; and it avoids
a thundering-herd connection storm that would trip the local fd budget before the
target is even engaged. A zero ramp-up (`--rampup 0`) degenerates to immediate maximum,
which is the correct behaviour for testing a WAF that reacts to *rate of change*.

### 6.2 The feedback term

Whether the ceiling is the final target depends on the run mode and whether the vector
even *has* a target-derived signal to feed back on:

```rust
let next = match mode {
    RunMode::Dumb => ramp_ceiling,
    RunMode::Adaptive if !has_feedback => ramp_ceiling,
    RunMode::Adaptive => { /* error-rate feedback */ }
};
```

- **`RunMode::Dumb`** ignores feedback entirely: ramp to max and stay there. This is
  the mode for exercising a *dynamic* mitigation — you want to hold maximum pressure to
  see whether the defence engages, not politely back off the moment it does.
- **`RunMode::Adaptive` on a vector without load feedback** (UDP, DNS, ICMP, raw
  SYN/ACK) also just ramps. This is a deliberate honesty constraint: a fire-and-forget
  vector's local send succeeding tells you *nothing* about the target, so there is no
  legitimate signal to adapt on, and the governor refuses to *pretend* it is adapting.
- **`RunMode::Adaptive` with feedback** runs the closed loop below.

### 6.3 The closed loop

```rust
let d_ok  = ok  - last_ok;
let d_err = err - last_err;
let attempts = d_ok + d_err;
let error_rate = if attempts > 0 { d_err as f64 / attempts as f64 } else { 0.0 };
let cur = gov.target.load(Relaxed);
if error_rate > 0.5 && elapsed > rampup {
    (cur / 2).max(1)            // distress: halve and begin a recovery probe
} else {
    (cur + step).min(ramp_ceiling)  // healthy: additive increase toward the ceiling
}
```

This is a variant of **AIMD** (additive-increase / multiplicative-decrease), the same
family of control law that governs TCP congestion avoidance. When the *windowed* error
rate — computed over the deltas since the previous tick, not cumulative totals —
exceeds one half, the governor halves the active worker count and lets the system probe
its way back up; otherwise it grows the target by a fixed `step = max/20`, i.e. it takes
roughly twenty ticks to traverse the full range.

Three properties are worth stating precisely:

1. **The error rate is measured over completions, not attempts.** `d_ok` and `d_err`
   are both *outcomes*; a connection that goes nowhere and resets counts as an error.
   The consequence is exactly the desired one: if the target starts refusing, the error
   rate climbs toward 1.0 and the loop backs off — the tool declines to keep hammering a
   target it has already knocked over, and instead measures whether it *recovers*.
2. **Multiplicative decrease is gated on `elapsed > rampup`.** During the initial ramp,
   transient errors are expected and must not trigger a spurious back-off; the decrease
   term only arms after the ramp completes.
3. **Both branches are clamped.** The decrease cannot fall below 1 (`.max(1)`), so a
   vector never fully stalls, and the increase cannot exceed the ramp ceiling, so
   feedback can never push load *above* the schedule.

The loop then sleeps 500 ms or wakes early on shutdown, via `tokio::select!` over the
sleep and the shutdown channel — so a governor cancels within milliseconds of Ctrl-C
rather than lingering for up to a full tick.

---

## 7. Cooperative Shutdown

Shutdown is cooperative and race-free, built on a Tokio `watch` channel wrapping a
single `bool`:

```rust
pub struct Shutdown { tx: watch::Sender<bool> }
impl Shutdown {
    fn trigger(&self)  { let _ = self.tx.send(true); }
    pub fn is_down(&self) -> bool { *self.tx.borrow() }
    pub fn subscribe(&self) -> watch::Receiver<bool> { self.tx.subscribe() }
}
```

The `watch` channel is chosen over a bare `AtomicBool` for one decisive reason: it
delivers a *wakeup*, not merely a *value*. A worker or governor parked in
`tokio::select!` on `receiver.changed()` is scheduled immediately when `trigger` fires;
there is no lost-notification window, because the channel remembers the latest value
and `changed()` observes any transition. The cheap, synchronous `is_down()` read
(`*self.tx.borrow()`) is available for hot-loop polling where a task is not otherwise
awaiting.

The run's top-level control installs a bounded grace period — `SHUTDOWN_GRACE`, five
seconds — after which any worker that has not observed shutdown and exited on its own is
force-aborted. In the common case every task observes the channel and exits within a
tick; the grace timer exists only to bound the pathological case where a worker is
wedged in a syscall, guaranteeing the process terminates.

---

## 8. The Transmit Datapath

For the raw L3/L4 vectors the tool offers a tiered transmit datapath. The tiers trade
portability for throughput; all three build the entire frame in userspace (§9) because
they inject below the point where the kernel would otherwise construct headers.

### 8.1 Tier 0 — per-frame `sendto`

The baseline raw path issues one `sendto` syscall per frame. Its ceiling is the syscall
rate, which on commodity hardware is on the order of a few hundred thousand to a couple
of million frames per second — the syscall *entry/exit* cost dominates, not the wire.
This tier is the correctness reference: simplest, most portable, and the shape the other
tiers must match byte-for-byte.

### 8.2 Tier 1 — batched `sendmmsg` with qdisc bypass (the default fast path)

`packet_mmsg::AfPacketMmsg` is the default high-rate backend and runs on **any** NIC.
Two mechanisms account for its throughput:

```rust
/// Frames per sendmmsg(). The kernel caps a single call at UIO_MAXIOV (1024).
const BATCH: usize = 1024;
```

- **Syscall amortisation.** Rather than one syscall per frame, it fills a contiguous
  buffer of up to `BATCH` complete frames — described by parallel `iovec` and `mmsghdr`
  arrays — and flushes them all with a single `sendmmsg()`. The per-frame syscall cost
  is thereby divided by up to ~1000. `BATCH` is 1024 because that is `UIO_MAXIOV`, the
  kernel's hard ceiling on messages per `sendmmsg` call; asking for more would be
  silently truncated.
- **Qdisc bypass.** The socket sets `PACKET_QDISC_BYPASS`, so transmitted frames skip
  the queueing-discipline layer entirely. This matters at multicore scale because the
  qdisc enqueue path takes a per-net-device spinlock; under many sending threads that
  lock becomes the scaling wall, and bypassing it is what lets throughput scale with
  cores rather than plateauing on lock contention.

The frame shape is fixed for the lifetime of the sender (constant L4 length), which
permits an important optimisation: the L2/L3 prefix is written into every buffer slot
*once* at construction, and each subsequent packet rewrites only its mutable L4 bytes.
The `unsafe impl Send` is sound because the raw pointers inside the `iovec`/`mmsghdr`
arrays reference the struct's own heap buffers, which do not move when the struct moves,
and the struct is owned by a single sender thread and never shared — the two conditions
that make the raw aliasing safe.

This tier requires `CAP_NET_RAW` (hence root) for its `AF_PACKET` `SOCK_RAW` socket,
like every raw vector.

### 8.3 Tier 2 — AF_XDP kernel bypass (feature-gated)

Behind the `xdp` Cargo feature, `engine::xdp` provides a pure-libc AF_XDP backend that
delivers frames straight into a shared UMEM and out the driver's TX ring, one socket
per hardware queue. On this path the send touches neither the IP stack, nor netfilter,
nor conntrack — it is genuine kernel bypass, the headroom tier for targets that can keep
up above 10 GbE. It is intentionally free of `libbpf` and any C toolchain in the default
build.

This is the one datapath where cross-thread *ordering* is load-bearing, and it is
handled correctly: the ring is a single-producer/single-consumer queue in which the
producer publishes descriptors with a **`Release`** store and the consumer observes them
with an **`Acquire`** load. That pairing establishes the happens-before edge guaranteeing
that when the consumer sees an updated producer index, the frame bytes the index refers
to are fully visible. This is the textbook case where `Relaxed` would be a real bug —
and, in contrast to the commutative counters of §3.1, the code uses the stronger ordering
precisely because a store here *publishes* other memory.

Because a given `(ifindex, queue)` may be owned by only one socket, when multiple raw
vectors run concurrently the engine ranks them and assigns each a disjoint slice of the
NIC's queues (`fast_groups` / `fast_rank`), so two vectors never collide on the same
hardware queue.

---

## 9. Frame Construction and the Internet Checksum

`engine::wire` is the pure, allocation-free frame builder shared by every fast transmit
tier. Because the fast paths inject at the driver, the kernel does not build headers for
them; this module is that builder, and its correctness is load-bearing for every unsafe
transmit backend that trusts it. It is unit-tested against known-good byte sequences and
fuzzed (§14), for the obvious reason that a framing bug is invisible until a packet
capture reveals malformed frames on the wire.

### 9.1 The one's-complement checksum (RFC 1071)

```rust
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;   // odd trailing byte is the high-order octet
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
```

This is the standard Internet checksum: a 16-bit one's-complement sum of the data,
folded and inverted. Three subtleties are handled explicitly:

1. **Accumulation in `u32`.** The running sum uses a 32-bit accumulator so that the
   carries produced by summing many 16-bit words are captured rather than lost; they are
   folded back in at the end. Summing directly in `u16` would discard carry and produce a
   wrong checksum.
2. **The odd trailing byte.** When the data length is odd, the final byte is treated as
   the *high-order* octet of a notional 16-bit word (`<< 8`), per the specification. Off-
   by-one handling here is a classic checksum bug; the `chunks_exact` + `remainder`
   idiom makes the two cases syntactically distinct and impossible to conflate.
3. **The fold loop.** `while (sum >> 16) != 0` folds carries repeatedly, because a single
   fold can itself generate a carry. A single non-looping fold is a subtle and common
   error that this loop avoids.

A useful self-checking property, noted in the source: a header that already carries its
correct checksum sums to zero under this function. That identity is what the
`wire_checksum` fuzz target and the unit tests exploit to validate round-trips.

### 9.2 Header builders

`eth_header` and `ipv4_header` construct the 14-byte Ethernet II and 20-byte IPv4
headers respectively, returning fixed-size arrays with no heap allocation. The IPv4
builder computes its header checksum over exactly the 20 header bytes — *not* the payload
— which is correct: the IPv4 checksum is a header-only checksum, and the L4 checksum
(TCP/UDP) is a separate computation over the L4 segment plus a pseudo-header. The
constants (`ETH_HDR_LEN = 14`, `IPV4_HDR_LEN = 20`, `FRAME_PREFIX_LEN = 34`,
`ETHERTYPE_IPV4 = 0x0800`) are named rather than magic, so the arithmetic that slices
buffers into header regions reads self-evidently.

---

## 10. The Classifier: From Counters to a Verdict

`classify::classify` is the decision engine. It consumes a `Signals` snapshot (the
aggregated counters plus the probe results and recon hints) and the `[LatencySample]`
collapse curve, and returns a `Classification { verdict, confidence, evidence }`. It is a
pure function of its inputs — no I/O, no clock, no globals — which is exactly what makes
it unit-testable (its test module is extensive) and fuzzable (§14).

### 10.1 The verdict lattice

```rust
pub enum Verdict { MitigationEngaged, Degrading, Down, EdgeBlocked, Healthy, Unknown }
```

The verdicts are not a linear severity scale; they encode *distinct explanations* for
what was observed:

- **`MitigationEngaged`** — a rate limiter (429) or WAF/CDN (403 with a recognised
  fingerprint) is actively absorbing the traffic. The defence is working. This is *not*
  a finding, and reporting it as one would be the tool crying wolf.
- **`Degrading` / `Down`** — a genuine resource-exhaustion finding: latency has diverged
  from baseline, or the target has stopped answering. `Down` is the more severe of the
  two, gated on stronger evidence.
- **`EdgeBlocked`** — fast refusals with no application response; something in front of
  the target is dropping us before the origin is reached.
- **`Healthy`** — the target absorbed the load and kept serving.
- **`Unknown`** — there was no signal capable of supporting *any* conclusion, most often
  a pure-L4 run with no health-probe data. Reporting `Unknown` honestly is strictly
  better than manufacturing a false `Healthy` or `Down`.

### 10.2 The decision cascade

The function is a priority-ordered cascade; the first section with sufficient evidence
returns, so more authoritative signals pre-empt weaker ones. The order is:

1. **Ground-truth health probe (§10.3)** — the only signal that works for L4/raw
   targets, and it *overrides* the rest when it shows real impact.
2. **Service-level probe** — detects worker/connection-pool exhaustion that a bare TCP
   connect cannot see (a Slowloris'd server still completes handshakes while answering
   no real requests).
3. **Rate limiter** — 429s are an unambiguous mitigation signal.
4. **WAF** — 403s carrying a vendor fingerprint.
5. **Degradation** — the collapse-curve analysis of §11.
6. **Absorption / Unknown** — the terminal fall-throughs.

### 10.3 Local-exhaustion detection — not blaming the target for our own limits

The health-probe section embodies the second half of the honesty thesis introduced in
§5. Some probe failures are the *target's* fault; others are ours, when the probe itself
cannot get a local socket because *we* exhausted them. The classifier separates these:

```rust
let probe_conclusive = sig.probe_total.saturating_sub(sig.probe_local_inconclusive);
let probe_reliable   = sig.probe_local_inconclusive <= sig.probe_total / 2;
```

`probe_local_inconclusive` counts probe attempts that failed on *local* socket/port
exhaustion — failures that say nothing whatsoever about the target. If those dominate
(more than half of all probes), `probe_reliable` is false and the probe is *disqualified
from deciding anything* this run; the classifier records an explanatory evidence line
advising the operator to reduce per-vector concurrency, and falls through to other
signals rather than misattributing local failure to the target.

The expression for `probe_reliable` is written as `x <= total / 2` rather than the
algebraically-equivalent `2*x <= total`, and the source comment states why: the doubled
form can overflow `u32` for a pathological probe count, and in release builds overflow
wraps silently — which would *flip the verdict*. This exact hazard was found by fuzzing
(§14): the `extreme_probe_counts_do_not_overflow` regression test pins the fix. It is a
small line with a large lesson: in a decision function, an arithmetic overflow is not a
crash, it is a *silently wrong answer*, which is worse.

When the probe *is* reliable and conclusive probes fail, the severity is graded by the
failure fraction: above 70 % returns `Down`, above 30 % returns `Degrading`. A separate
branch catches the case where the target still *connects* but its connect latency has
risen more than threefold above baseline (and by more than a floor delta, to reject
trivial absolute rises) — reported as `Degrading`.

### 10.4 Corroboration inputs

Before the cascade, the function computes a small integer `stress` — the count of
*independent* indicators that agree the target was impacted (probe failures, service
failures, detected degradation, elevated server-error fraction). This count is not itself
a verdict; it is fed to the confidence calibration (§12) so that a verdict several
independent signals concur on is reported with more confidence than one resting on a
single measurement.

---

## 11. Robust Degradation Detection

The collapse-curve analysis must distinguish a *real* latency regression from a target's
own baseline jitter. Using the mean and standard deviation for this would be a mistake:
both are unbounded-influence statistics, so a single pathological p99 spike — exactly the
kind of transient a noisy network produces — would drag them and manufacture a false
finding. The classifier therefore uses **robust** statistics.

### 11.1 Median and MAD

```rust
fn median(xs: &[f64]) -> Option<f64> { /* sort, take middle (or mean of two middles) */ }
fn mad(xs: &[f64])    -> Option<f64> { /* median of |x - median(x)| */ }
```

The median has a breakdown point of 50 % — up to half the samples can be arbitrarily
corrupted before it moves — and the **median absolute deviation** (MAD) is the
correspondingly robust measure of spread. Together they characterise a target's normal
operating band without being hijacked by outliers.

### 11.2 The breach threshold

`breach_threshold` derives, from the samples and the baseline, the p99 level above which
a sample counts as a genuine breach rather than noise. `detect_degradation` then walks
the collapse curve looking for a *sustained* excursion above that threshold — a single
sample over the line is not enough; the excursion must persist, which is what
distinguishes degradation from a blip. When degradation is detected it also reports the
*knee*: the concurrency level at which latency began to diverge, which is the
operationally useful number ("it held until N concurrent, then fell over").

The test suite pins both directions of this discrimination explicitly:
`single_p99_spike_is_not_a_finding` and
`jitter_within_a_targets_own_noise_band_is_not_degradation` guard against false
positives, while `p99_blowout_is_degrading_finding` and
`degradation_tracking_the_load_ramp_is_more_confident_and_reports_the_knee` guard the
true positives — and `recovery_after_load_eases_is_detected` confirms the analysis is not
one-directional.

---

## 12. Confidence Calibration

Every verdict carries a confidence in `[0, 1]`, and the design principle is that the tool
reports *likelihood, never proof*. Two functions govern it.

```rust
fn conf(fraction: f64, max: f64) -> f64 { /* scales a signal fraction, capped at max */ }
fn corroborate(base: f64, agreeing_signals: u32) -> f64 { /* raises base per agreeing signal */ }
```

- **`conf`** maps a raw signal fraction to a confidence, capped by a per-signal maximum.
  No single signal is ever permitted to assert certainty.
- **`corroborate`** takes a base confidence and the `stress` count from §10.4 and raises
  it as independent signals agree — the formal expression of "multiple corroborating
  observations warrant more confidence than one."

The global cap is **0.9**: the classifier never emits 1.0. This is an epistemic stance
rather than a numerical accident — a black-box active measurement of someone else's
service cannot, in principle, yield certainty, and a tool that claimed it would be
lying. The `extreme_probe_counts_do_not_overflow` test (§10.3) also transitively guards
the confidence path, since the overflow it pins fed a confidence computation.

---

## 13. Reconnaissance and the Asymmetry Model

A single origin cannot out-muscle a well-provisioned target by brute force; its leverage
comes from *asymmetry* — finding the one endpoint where a cheap request forces
disproportionate server work. The `recon` module hunts for that asymmetry and ranks
candidates, and `recon::score` is the model that does the ranking.

### 13.1 The signal vector

```rust
pub struct Signals {
    pub compute_ms: f64,     // marginal server ms a crafted input forces above baseline
    pub confidence: f64,     // 0..1, from sample spread + count
    pub degradation: f64,    // latency knee under a bounded concurrent burst (>= 1.0)
    pub amplification: f64,  // response bytes out per request byte in
    pub graphql_cost: f64,   // heavy/trivial GraphQL query-cost ratio
    pub cacheable: bool,     // whether the edge/CDN absorbs the response
}
```

These are gathered by differential probing: for each candidate parameter the recon engine
sends a *cheap* value and an *expensive* value (a large limit, a leading-wildcard search
that defeats an index, a catastrophic-backtracking pattern) in interleaved pairs, and
measures the marginal server time the expensive one forces. Interleaving controls for
drift; sampling in pairs yields the spread that becomes `confidence`.

### 13.2 The scoring function

```rust
pub fn contributions(sig: &Signals) -> Contributions {
    let compute_pressure = sig.compute_ms.max(0.0) * sig.degradation.max(1.0);
    let cache_factor = if sig.cacheable { CACHE_DISCOUNT } else { 1.0 };
    Contributions {
        compute:   COMPUTE_W  * (1.0 + compute_pressure).ln() * sig.confidence.clamp(0.0, 1.0),
        bandwidth: BANDWIDTH_W * sig.amplification.max(1.0).ln() * cache_factor,
        graphql:   GQL_W      * sig.graphql_cost.max(1.0).ln(),
    }
}
pub fn asymmetry(sig: &Signals) -> f64 {
    let c = contributions(sig);
    c.compute + c.bandwidth + c.graphql
}
```

Four modelling decisions are encoded here, each defensible:

1. **Log compression.** Every axis is passed through `ln`. Without it, a bandwidth
   amplification in the thousands would numerically dwarf a compute delta in the
   hundreds of milliseconds, and the ranking would collapse to "whichever axis has the
   larger natural units." Log-compressing puts the axes on comparable footing so their
   *weights* — not their raw magnitudes — decide their relative influence.
2. **Confidence weighting of the compute axis.** The compute contribution is multiplied
   by `confidence`. This directly answers a reviewer's concern preserved in the test
   `confidence_weights_compute_a_solid_small_delta_beats_a_noisy_large_one`: a noisy
   300 ms measurement must not outrank a rock-solid 80 ms one. Bandwidth is a byte count,
   not a timing, so it needs no such weight and gets none.
3. **Cache discounting.** A cacheable response is largely absorbed by an edge/CDN and
   never reaches the origin, so its bandwidth contribution is discounted by
   `CACHE_DISCOUNT = 0.15`. Failing to discount it would rank a CDN-cached asset as a
   prime target when in fact it is the opposite.
4. **Classification by contribution, not by boundary.** The weakness *type* is decided by
   comparing the axes' actual score contributions against one another, rather than by a
   hand-tuned threshold in raw signal space — so the classification moves coherently with
   the score instead of being a separate, drift-prone heuristic.

The weights (`COMPUTE_W = 1.0`, `BANDWIDTH_W = 0.7`, `GQL_W = 1.2`) are explicit named
constants precisely so this model can be *criticised and tuned* rather than reverse-
engineered from behaviour. The GraphQL axis carries the highest weight because a
query-cost amplification is a strong, specific, hard-to-fake signal.

---

## 14. The Fuzzing Surface

The verdict is only worth something if the code beneath it is honest under adversarial
input, so the components that turn *untrusted bytes* into a *decision* are fuzzed under
`cargo-fuzz`. The harnesses live in `dev/fuzz` and drive the `#[cfg(fuzzing)]` wrappers of
§2.2. Ten targets are maintained:

| Target | Exercises |
|---|---|
| `classify` | The full verdict cascade of §10, on arbitrary signal/sample inputs. |
| `recon_robots` | The `robots.txt` parser. |
| `recon_sitemap` | The sitemap XML parser. |
| `recon_openapi` | The OpenAPI/Swagger spec parser (deepest surface: cov ≈ 1000). |
| `recon_extract_refs` | Reference extraction from crawled HTML. |
| `recon_extract_js` | API-route mining from JavaScript bundles. |
| `dns_encode_query` | DNS query wire-encoding. |
| `wire_checksum` | The RFC 1071 checksum and framing of §9. |
| `cache_bust_into` | Cache-busting query synthesis. |
| `histogram_bucket` | Latency-histogram bucketing. |

The selection is principled: it targets exactly the parsers that chew on a target-
controlled or otherwise externally-supplied byte stream, plus the pure decision function.
The *send-side* vectors are largely absent by design — their response parsing is delegated
to vetted, upstream-fuzzed crates (`httparse`, `h2`, `rustls`, `quinn`), and their
outbound construction is config-driven rather than adversarial. The one hand-rolled
response-parse that is not yet isolated for fuzzing (the `Content-Length`-driven drain in
`http_flood`) is the identified next candidate.

The programme has already paid for itself: the first sweep found a real integer overflow
in the verdict engine — the `probe_reliable` computation of §10.3 — that would have
silently flipped a call under a pathological probe count. It is fixed, pinned by the
`extreme_probe_counts_do_not_overflow` regression test, and seeded into the corpus. See
[FUZZING.md](FUZZING.md) for the harness catalogue and the orchestrator's operation.

---

## 15. Invariants Catalogue

A consolidated list of the load-bearing invariants asserted throughout this document.
Each is enforced at the cited site; a change that violates one is a regression even if
the tests pass.

1. **Egress ≠ delivery.** A connectionless vector advances `packets_sent` and never
   `responses_ok`. *(§4.1, `engine::Metrics`.)*
2. **Per-vector metric isolation.** Each vector owns a distinct `Metrics`, so a governor
   throttles only on its own vector's signal. *(§4.3.)*
3. **Held-connection accounting is RAII.** `held_connections` follows lexical scope
   exactly via `HeldGuard::drop`. *(§4.4.)*
4. **Never mistake local exhaustion for the target's.** Admission control (`fd_scale`)
   sizes the run to the fd budget; the classifier disqualifies a probe dominated by local
   failures. *(§5, §10.3.)*
5. **No pretend-adaptation.** A fire-and-forget vector, having no target-derived signal,
   ramps but never claims to self-throttle. *(§6.2.)*
6. **Feedback cannot exceed the schedule.** Adaptive increase is clamped to the ramp
   ceiling; decrease is clamped to ≥ 1. *(§6.3.)*
7. **Shutdown is race-free and wakes tasks.** A `watch` channel provides both the flag
   and the notification; a grace timer bounds the pathological case. *(§7.)*
8. **Publishing memory uses Acquire/Release; commutative counters use Relaxed.** The XDP
   ring pairs Release/Acquire; metric counters are Relaxed. *(§3, §8.3.)*
9. **Checksum arithmetic is carry-correct and endian-correct.** 32-bit accumulation,
   looped fold, odd byte as high-order octet. *(§9.1.)*
10. **Decision arithmetic must not overflow.** `probe_reliable` is written to be
    overflow-safe; a silent wrap would flip a verdict. *(§10.3.)*
11. **Confidence is capped below certainty (≤ 0.9).** The tool reports likelihood, never
    proof. *(§12.)*
12. **Recon ranking is confidence-weighted and cache-discounted.** A noisy large delta
    does not outrank a solid small one; a cached asset is not ranked as a prime target.
    *(§13.2.)*

---

## 16. Glossary

- **AIMD** — Additive-Increase / Multiplicative-Decrease; the control law the adaptive
  governor shares with TCP congestion avoidance. *(§6.3.)*
- **Asymmetry** — the ratio of server work forced to client work spent; the quantity
  reconnaissance maximises. *(§13.)*
- **Collapse curve** — the time series of windowed latency percentiles against offered
  load, from which degradation and the knee are read. *(§11.)*
- **Knee** — the load level at which latency begins to diverge from baseline. *(§6.1,
  §11.2.)*
- **MAD** — Median Absolute Deviation; a breakdown-robust measure of spread. *(§11.1.)*
- **Qdisc bypass** — `PACKET_QDISC_BYPASS`, which skips the kernel queueing layer and its
  per-net-device spinlock. *(§8.2.)*
- **UMEM** — the shared user-memory region an AF_XDP socket uses for zero-copy frame
  buffers. *(§8.3.)*
- **`UIO_MAXIOV`** — the kernel's ceiling (1024) on messages per `sendmmsg` call, and
  therefore the value of `BATCH`. *(§8.2.)*
- **Verdict** — the classifier's categorical conclusion about a run's effect on the
  target. *(§10.1.)*

---

*This document tracks the code as of the current tree. When a cited function changes,
update the corresponding section, or the reference becomes a liability rather than an
asset.*
