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
  ├─ --list-presets      → print presets/tiers, exit
  ├─ --save-config       → build plan (preset/config), write JSON, exit   [no consent]
  ├─ --ui-only           → serve dashboard, exit
  └─ run path:
       legal notice + consent gate (auth::require_consent)   ← always
       resolve plan:
         --auto     → auto::characterize → auto::recommend → presets::build_config
         --preset   → presets::build_config(preset, tier, target)
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
- **`Tier`** — aggressiveness: `Recon` (probe-only, concurrency 0), `Light` (50),
  `Moderate` (200), `Aggressive` (800), `Brutal` (3000) per-vector concurrency.
- **`VectorTuning`** — per-vector knobs (concurrency, rate/worker, payload bytes,
  trickle interval, port). `defaults_for(vector)` gives conservative starting
  points; a preset overrides `concurrency` with the tier's value.
- **`RunConfig`** — the fully-resolved, serializable plan (target, proxy, mode,
  recon flag, vectors, duration, ramp-up). This is what `--save-config` writes
  and `--config` reads.

---

## 5. Presets & tiers (`presets.rs`)

A `Preset` is a curated vector combo for a target class:

| Preset | Vectors | Notes |
|---|---|---|
| `router` | syn + ack + tcp_exhaust | state-table exhaustion; needs sudo |
| `router-lite` | tcp_exhaust | same idea, no sudo |
| `web` | http_flood + slowloris + rudy + range_flood | recon-driven |
| `api` | h2_flood + h2_rapid_reset + rudy | |
| `cdn` | tls_exhaust + h2_rapid_reset + http_flood | origin-behind-edge |
| `dns` | dns_flood + udp_flood | |

`build_config(preset, tier, target, …)` stamps the tier's concurrency onto every
vector and returns a normal `RunConfig` — which you can dump, hand-edit, and
re-run. Presets are a starting point, never a black box.

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
3. **`recommend(char, root)`** — maps the kind to a preset + tier with
   human-readable reasoning, then hands the built plan to the normal
   consent/confirm path.

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
  (`requests_sent`, `responses_ok`, `errors`, `bytes_sent`, `held_connections`,
  and per-class HTTP status counters `http_2xx/3xx/4xx/403/429/5xx`) plus a
  latency `Histogram`. No mutex is touched per request.
- **`Shutdown`** — a `tokio::sync::watch<bool>`. Cheap `is_down()` reads, and
  `subscribe()` gives each worker a receiver it races in `select!` — no
  lost-notification window.
- **`Governor`** (per vector) — an `AtomicU32 target_concurrency` that workers
  gate on with a single relaxed load (`idx < target`). `govern()` ramps it 0→max
  over the ramp-up; in `Adaptive` mode it halves under distress (error rate
  > 0.5) and re-grows — that back-off/re-grow cycle is what measures recovery.
- **`HeldGuard`** — RAII inc/dec of `held_connections`, so the count follows
  connection lifetime exactly even on early return.

### 8.2 Latency histogram (`engine/histogram.rs`)

HdrHistogram-style: 512 buckets (each power-of-two magnitude split into 8 linear
sub-buckets), a constant **4 KB**. Recording is O(1) — one `leading_zeros` and one
atomic add — safe to hammer concurrently. Quantiles are O(512), computed only in
the sampler (4×/s) on **windowed deltas** so the collapse curve reflects latency
*at the current load*, not cumulative.

### 8.3 Sampler & outcome

`sample()` runs every 250 ms: snapshots the histogram, computes windowed
p50/p95/p99, RPS and error-rate deltas, and appends a `LatencySample` to the
collapse curve. After the run, `derive_outcome()` extracts baseline p99 (from
recon if available), **time-to-degradation**, the knee, and **recovery time** —
degradation requires both a 3× ratio **and** an absolute delta > 25 ms
(`MIN_DEGRADE_DELTA_MS`), so sub-millisecond jitter never registers as a finding.

### 8.4 Health probe — ground truth

`health_probe()` TCP-connects to the target once per second (plus a pre-load
baseline), independent of the attack traffic. This is the **only** signal that
works for L4/raw vectors (which produce no application-layer response), and it is
the classifier's strongest input: if the target stops accepting connections or
its connect latency blows up *while we're loading it*, that's ground truth that
we affected it.

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
- Pre-built request templates: rotating browser fingerprints (`build_get_templates`),
  the slowloris partial head, the RUDY POST head, and the CVE-2011-3192 Range
  request — all serialized **once**, so workers never format strings in the loop.
- `connect_small_window` sets a tiny `SO_RCVBUF` for the Slow Read vector.

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

Raw vectors run their synchronous pnet send loop on a `spawn_blocking` thread and
read the shared atomics/watch directly.

---

## 9. Classifier (`classify.rs`)

`classify(Signals, samples) → Classification { verdict, confidence, evidence }`.
Verdicts, in the order they're checked:

1. **Health probe (ground truth)** — >30% probe failures → `Down`/`Degrading`;
   probe latency > 3× baseline and > 25 ms → `Degrading`. This runs first and
   overrides everything, and it's what makes L4 runs classifiable.
2. **L4-only fallback** — no L7 signal but a stable probe → `Healthy` (absorbed);
   no probe signal at all → `Unknown`.
3. **Rate limiter** — ≥20% 429s → `MitigationEngaged`.
4. **WAF** — ≥20% 403s → `MitigationEngaged`, confidence boosted by a matched
   `detect_waf` vendor.
5. **Latency exhaustion** — peak p99 > 3× baseline & > 25 ms → `Degrading`, or
   `Down` if the tail is near-total failure.
6. **Healthy** — ≥80% 2xx, stable latency.

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
