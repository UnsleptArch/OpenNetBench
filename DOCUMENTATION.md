# OpenNetBench — Architecture & Internals

> Deep technical documentation for contributors and auditors. For usage, see the
> [README](README.md). This document describes the code as it exists, module by
> module, with the reasoning behind each design decision.

---

## 1. What it is, in one paragraph

OpenNetBench is a **single-origin** adversarial-load / resilience-assessment
tool. It generates the traffic patterns real attackers use — L3→L7, sixteen
vectors — from **one host**, measures the target's behaviour under that load
with an independent health probe, and **classifies** the outcome (did the
defence hold, or did the service break?) with a confidence and an evidence
trail. There is no spoofing, no amplification, and no command-and-control by
design; the machine's NIC is the hard ceiling, and every byte is attributable.

---

## 2. Safety model (architectural, not cosmetic)

These properties are enforced by *how the code is built*, not by policy text:

| Property | How it's guaranteed |
|---|---|
| **Single origin** | All traffic leaves this host. There is no agent protocol, peer discovery, or coordination code anywhere in the tree. |
| **No spoofing** | Raw vectors (`raw.rs`, `syn_flood`, `icmp_flood`) compute checksums from the host's **real** source IP (`local_src_ipv4`). Spoofing is not implemented — and would break TCP vectors anyway (the SYN-ACK would go elsewhere). |
| **No amplification** | No DNS/NTP/memcached reflection vectors exist. Every byte sent is generated locally. |
| **No C2** | There is no remote-control surface. The only network egress is the attack traffic and the health probe, both to the operator-specified target. |
| **Mandatory consent** | `auth.rs` blocks every run until the operator types an exact phrase at a TTY. It cannot be satisfied by a flag or file. |

The design deliberately trades "maximum firepower" for "fully attributable and
containable" — stop the process, stop the traffic.

---

## 3. Top-level flow (`main.rs`)

```
parse CLI (clap Args)
  ├─ --list-presets      → print presets, exit
  ├─ --save-config       → build plan (preset/config), write JSON, exit   [no consent]
  ├─ --ui-only           → serve dashboard, exit
  └─ run path:
       legal notice + consent gate (auth::require_consent)   ← always
       resolve plan:
         --auto     → auto::characterize → auto::recommend → presets::build_config
         --preset   → presets::build_config(preset, target)
         --config   → cli::load_config(json)
         (none)     → cli::interactive_flow  (also prompts auto_approve, stop_on_detect)
       if run_recon → recon::run_recon → present → select/auto-approve target
                      (seeds classifier baseline + WAF vendor into RunContext)
       final "Execute this plan?" confirm
       engine::run(cfg, ctx)
```

`auto_approve` and `stop_on_detect` are **not** part of the saved config — they
are CLI flags for scripted runs, or interactive y/n prompts otherwise, resolved
in `main` before the engine starts.

---

## 4. Configuration model (`config.rs`)

- **`Vector`** — the 16 vectors as a `#[repr]`-free enum, each carrying `slug()`,
  `layer()` (L3/L4/L7), `needs_root()`, and `description()`. `Vector::ALL` is the
  canonical ordered list.
- **`RunMode`** — `Adaptive` (self-throttles under distress, measures recovery)
  or `Dumb` (sustained max load; use this to pressure something that shrugs off
  adaptive back-off).
- **`VectorTuning`** — per-vector knobs (concurrency, rate/worker, payload bytes,
  trickle interval, port). `defaults_for(vector)` gives conservative starting
  points; a preset overrides `concurrency` with `PRESET_CONCURRENCY` (2700).
- **`RunConfig`** — the fully-resolved, serializable plan (target, proxy, mode,
  recon flag, vectors, duration, ramp-up). This is what `--save-config` writes
  and `--config` reads.

---

## 5. Presets (`presets.rs`)

A `Preset` is a curated vector combo for a target class:

| Preset | Vectors | Notes |
|---|---|---|
| `router` | syn + ack + tcp_exhaust | state-table exhaustion; needs sudo |
| `router-lite` | tcp_exhaust | same idea, no sudo |
| `web` | http_flood + slowloris + rudy + range_flood | recon-driven |
| `api` | h2_flood + h2_rapid_reset + rudy | |
| `cdn` | tls_exhaust + h2_rapid_reset + http_flood | origin-behind-edge |
| `dns` | dns_flood + udp_flood | |

`build_config(preset, target, …)` stamps `PRESET_CONCURRENCY` (2700) onto every
vector and returns a normal `RunConfig` — which you can dump, hand-edit, and
re-run. Presets are a starting point, never a black box. There is no
aggressiveness ladder: presets always run at full pressure, tuned down from a
naive 3000 so one origin exhausts the target's state table before its own local
socket limits.

---

## 6. Auto-engine (`auto.rs`)

`--auto` implements **recommend-and-approve**: it never fires on its own.

1. **`characterize(target)`** — TCP-connect port scan of `{80,443,8080,8443,53,22}`;
   HTTP/HTTPS fingerprint via `reqwest` (Server header, HTML content-type,
   HTTP/2 via ALPN in the response version); WAF/CDN detection; private-IP and
   embedded-server (`uhttpd`/`lighttpd`/`GoAhead`/`RomPager`/…) signatures.
2. Classifies into `TargetKind`: `RouterHost | Dns | Cdn | Api | Web | Unknown`.
   Private/loopback IPs and embedded servers → `RouterHost` even if they serve a
   web UI (a home router's admin page is not a "web app").
3. **`recommend(char, root)`** — maps the kind to a preset with human-readable
   reasoning, then hands the built plan to the normal consent/confirm path.

---

## 7. Recon (`recon/`)

- **`fingerprint.rs`** — Server header, missing security headers, `OPTIONS`/`TRACE`
  method enumeration, and ~40 sensitive-path probes (`.env`, `.git`, `actuator`,
  `graphql`, …).
- **`crawl.rs`** — async same-host BFS (bounded pages/depth) with a lightweight
  byte-scanner for `href`/`src` links **and** `<form>` actions/methods — no
  html5ever dependency.
- **`score.rs`** — the core research idea: **asymmetry** = server cost / client
  cost. `asymmetry(baseline_ms, request_bytes, cacheable, dynamic)` ranks
  endpoints by how much a single request costs the server versus us; cached
  endpoints are deprioritised, dynamic/compute-bearing ones amplified.
- **`mod.rs::run_recon`** — assembles candidate endpoints, times each (3-sample
  TTFB average), detects cacheability, scores asymmetry, and returns a
  descending-ranked `ReconReport`. Recon **never auto-fires**; the operator (or
  `--auto-approve`) selects the flood target from the ranked list.

---

## 8. The engine (`engine/`)

The performance-critical core. Design goals: lock-free hot path, zero per-request
allocation, O(1) recording, prompt cooperative shutdown.

### 8.1 Shared state (`engine/mod.rs`)

- **`Metrics`** — all counters are `AtomicU64/U32` with `Relaxed` ordering
  (`requests_sent`, `responses_ok`, `packets_sent`, `errors`, `bytes_sent`,
  `held_connections`, and per-class HTTP status counters
  `http_2xx/3xx/4xx/403/429/5xx`) plus a latency `Histogram`. No mutex is touched
  per request. **One `Metrics` instance per vector** — the sampler and summary
  aggregate across them, but each governor sees only its own vector's counters,
  so a distressed vector never throttles a healthy one. `responses_ok` means a
  real round-trip/handshake; connectionless floods (UDP/DNS/ICMP/raw) increment
  `packets_sent` (local egress, *not* confirmed delivery) so their send rate is
  never reported as target throughput.
- **`Shutdown`** — a `tokio::sync::watch<bool>`. Cheap `is_down()` reads, and
  `subscribe()` gives each worker a receiver it races in `select!` — no
  lost-notification window. Unbounded reads (HTTP/2 response, HTTP header read)
  race it too, and `run()` force-aborts any straggler after a 5 s drain grace, so
  stopping the process always stops the traffic.
- **`Governor`** (per vector) — an `AtomicU32 target_concurrency` that workers
  gate on with a single relaxed load (`idx < target`). `govern()` ramps it 0→max
  over the ramp-up; in `Adaptive` mode it halves under distress (error rate
  > 0.5) and re-grows — that back-off/re-grow cycle is what measures recovery.
  Fire-and-forget vectors (no target feedback) just ramp; they never fake an
  adaptive decision off a local send count.
- **fd preflight** — before spawning, `fd_scale()` reads `RLIMIT_NOFILE`, tries to
  raise the soft limit toward the hard cap, and scales total concurrency down to
  fit if it still won't (with a warning). Prevents EMFILE storms that would read
  as target failures but are really our own socket table.
- **`HeldGuard`** — RAII inc/dec of `held_connections`, so the count follows
  connection lifetime exactly even on early return.

### 8.2 Latency histogram (`engine/histogram.rs`)

HdrHistogram-style: 512 buckets (each power-of-two magnitude split into 8 linear
sub-buckets), a constant **4 KB**. Recording is O(1) — one `leading_zeros` and one
atomic add — safe to hammer concurrently. Quantiles are O(512), computed only in
the sampler (4×/s) on **windowed deltas** so the collapse curve reflects latency
*at the current load*, not cumulative.

### 8.3 Sampler & outcome

`sample()` runs every 250 ms: aggregates every vector's histogram, computes
windowed p50/p95/p99, and derives RPS + error rate. **RPS is completed responses
divided by the *actual* elapsed window** (not a nominal 250 ms — a late wakeup
under load would otherwise distort it); error rate is `errors / (completions +
errors)`. After the run, `derive_outcome()` extracts baseline p99 (from recon if
available), **time-to-degradation**, the knee, and **recovery time**. Degradation
requires a 3× ratio, an absolute delta > 25 ms (`MIN_DEGRADE_DELTA_MS`), **and**
that both persist for `DEGRADE_CONSECUTIVE` (3) consecutive samples — a lone
transient spike never registers, and recovery is symmetric.

### 8.4 Health probe & service probe — ground truth

Two independent, DIRECT (never proxied) control-plane observers run alongside the
load:

- **`health_probe()`** TCP-connects to the target once per second (plus a pre-load
  baseline). Each connect is classified by *who is at fault*: a success, a RST
  (`Refused`), a timeout/unreachable (`TargetFail`), or our own socket/port
  exhaustion (`LocalExhausted`, excluded from any "target down" conclusion). A RST
  counts as a failure **only if the service was accepting at baseline** —
  baseline-accepting → load-refused means load knocked the listener over. This is
  the only signal that works for L4/raw vectors.
- **`service_probe()`** issues a real independent `GET` once per second (reqwest,
  cert-agnostic, no redirects) when the app answered at baseline. It catches what
  a TCP connect cannot: a server whose worker/connection pool is exhausted by
  slowloris still completes TCP handshakes while answering no real requests. If
  baseline-healthy service GETs start failing under load, that's a finding even
  with a stable connect probe.

### 8.5 `--stop-on-detect` monitor

When enabled, `detect_monitor()` watches the probe timeline; the first time it
sees a sustained failure or latency blow-up, it prompts (off the runtime, via
`spawn_blocking`) whether to stop. Off by default → runs the full duration.

### 8.6 Connection layer (`engine/net.rs`)

- **`Conn`** — a plain-or-TLS `TcpStream` behind one enum (both variants `Unpin`,
  so `AsyncRead`/`AsyncWrite` delegate with no pin projection, no box, no vtable
  in the I/O path).
- **`Target::resolve`** — DNS once, up front; the `SocketAddr` is shared so the
  hot path never resolves. Holds two shared `rustls` connectors (default and
  ALPN-`h2`) built on the ring provider.
- **SOCKS5 proxy** — when configured, every TCP connection this target makes
  routes through the proxy (`tcp_stream()` via `tokio-socks`, host sent to the
  proxy as a name so it resolves — no local DNS leak). Covers all L7 TCP vectors,
  TLS-exhaust, and TCP-exhaust. **SOCKS5 is TCP-only**: raw L3/L4 and UDP/DNS
  vectors can't be carried and egress from the host's real address (the engine
  warns). The health/service probes stay direct by design. Only `socks5://` /
  `socks5h://` are accepted.
- Pre-built request templates: rotating browser fingerprints (`build_get_templates`),
  the slowloris partial head, the RUDY POST head, and the CVE-2011-3192 Range
  request — all serialized **once**, so workers never format strings in the loop.
- `connect_small_window` sets a tiny `SO_RCVBUF` for the Slow Read vector (falls
  back to an ordinary held connection when proxied — SOCKS5 can't set it).

### 8.7 The 16 vectors

| File | Vector(s) | Mechanism |
|---|---|---|
| `http_flood.rs` | http_flood, https_only, range_flood | keep-alive GET loop, zero-alloc, httparse, bounded body drain, honours response keep-alive |
| `slowloris.rs` | slowloris | partial headers held open, trickle |
| `rudy.rs` | rudy | complete POST header, body trickled forever |
| `slow_read.rs` | slow_read | tiny recv window, drain response one byte/tick |
| `tls_exhaust.rs` | tls_exhaust | repeated full TLS handshakes (latency = handshake cost) |
| `h2_flood.rs` | h2_flood | multiplexed HTTP/2 requests, completed + drained |
| `h2_rapid_reset.rs` | h2_rapid_reset | **CVE-2023-44487** — open stream, immediate RST |
| `h2_continuation.rs` | h2_continuation | **CVE-2024-27316** — raw HTTP/2 framing, endless CONTINUATION without END_HEADERS |
| `tcp_exhaust.rs` | tcp_exhaust | bare TCP connections held open (accept backlog / conn table) |
| `udp_flood.rs` | udp_flood | connected UDP send loop, shared payload |
| `dns_flood.rs` | dns_flood | random-subdomain A queries, hand-encoded on the wire |
| `raw.rs` + `syn_flood.rs` / `ack_flood.rs` | syn_flood, ack_flood | raw TCP SYN/ACK via pnet (root), real source IP |
| `icmp_flood.rs` | icmp_flood | ICMP echo flood via pnet (root) |

Raw vectors run their synchronous send loop on a `spawn_blocking` thread and read
the shared atomics/watch directly.

### 8.8 Transmit backends (`packet_tx.rs`, `wire.rs`, `l2.rs`, `xdp.rs`)

The stateless SYN/ACK path picks the fastest available transmitter at startup
behind the `PacketTx` seam, and falls back cleanly so it always runs:

1. **AF_XDP** (`xdp.rs`, only when built `--features xdp`) — pure-`libc`, TX-only:
   packets go into a shared UMEM and out through an AF_XDP TX ring, so the
   per-packet `sendto` collapses to **one wakeup syscall per 64-frame batch**
   (finding F1) and nothing touches the IP stack, netfilter, or conntrack (F2).
   Best-effort zero-copy; single queue for now (multi-queue sharding = F3, TODO).
   No libbpf/libxdp — the default build pulls no C toolchain. *Compile-verified;
   ring offsets/barriers need on-NIC validation.*
2. **AF_PACKET** (`packet_tx.rs`) — full Ethernet-frame injection via
   `pnet_datalink`. Same syscall-per-packet cost as the kernel path, but injecting
   at the driver **bypasses netfilter OUTPUT and local conntrack** (F2) — so a
   unique-flow flood exhausts the *target's* state table, not our own (which is
   what capped the earlier router run).
3. **Kernel Layer-4** (`pnet_transport`) — the original path, kernel builds IP+L2.
   The always-available fallback when we're not root or L2 can't be resolved.

`wire.rs` builds the Ethernet+IPv4 prefix (checksums included, unit-tested);
`l2.rs` resolves the egress interface, source MAC, and next-hop MAC from
`/proc/net/route`, `/proc/net/arp`, and `/sys` (with an ARP nudge), since injecting
frames means we own Layer 2. The source IP/MAC are hard-bound to this host — the
full-frame path exposes no spoofing knob.

---

## 9. Classifier (`classify.rs`)

`classify(Signals, samples) → Classification { verdict, confidence, evidence }`.
Verdicts, in the order they're checked:

1. **Health probe (ground truth)** — failures counted over *conclusive* checks
   only (local socket exhaustion excluded; if it dominates, the probe is declared
   unreliable and we fall through). >30% conclusive failures → `Down`/`Degrading`;
   probe latency > 3× baseline and > 25 ms → `Degrading`.
2. **Service probe** — baseline-healthy app now failing > 25% of independent GETs
   while TCP still accepts → `Degrading`/`Down`. This catches slow-connection
   exhaustion that a TCP probe alone reads as healthy.
3. **L4-only fallback** — no L7 signal but a stable probe → `Healthy` (absorbed);
   no probe signal at all → `Unknown`.
4. **Rate limiter** — ≥20% 429s → `MitigationEngaged`.
5. **WAF** — ≥20% 403s → `MitigationEngaged`, confidence boosted by a matched
   `detect_waf` vendor.
6. **Latency exhaustion** — p99 > 3× baseline & > 25 ms **sustained for 3+
   consecutive samples** → `Degrading`, or `Down` if the tail is near-total
   failure.
7. **Healthy** — ≥80% 2xx, stable latency.

Confidence is always capped at 0.9 — the tool reports likelihood, never proof, so
it never calls a WAF save a "vuln."

---

## 10. Cross-cutting

- **`logging.rs`** — `tracing` to a timestamped `logs/onb-<runid>.log` **and** the
  terminal; the (future) dashboard tails the same structured stream.
- **`metrics.rs`** — the serializable shapes (`LatencySample`, `Snapshot`,
  `RunOutcome`) the UI/report will consume.
- **`db.rs`, `web/`** — stubs for the SQLite history/CVE store and the dashboard.

---

## 11. Extending it

- **New vector** → add a `Vector` variant (+ `slug`/`layer`/`needs_root`/
  `description`/`defaults_for`), a `engine/<name>.rs` worker following the
  gate/shutdown pattern, and a dispatch arm in `engine::run`. Reuse `net::Conn`
  for TCP/TLS or `raw.rs` for raw sockets.
- **New preset** → one entry in `presets::PRESETS`.
- **New classifier signal** → add a field to `Signals`, populate it in
  `engine::run`, and add a branch in `classify` (keep the confidence honest).

---

## 12. Build & test

```
cargo build --release      # optimized binary
cargo test                 # unit + in-process integration tests
./install.sh               # build + put `opennetbench` on PATH
```

Tests cover the byte-level encoders (DNS wire format, HTTP/2 framing), the HTML
scanner, the latency histogram, an in-process traffic/measurement smoke test, and
the classifier verdict matrix.
