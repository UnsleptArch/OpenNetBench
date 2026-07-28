# OpenNetBench — reviewer briefing & feedback request

You are reviewing **OpenNetBench**, a Rust network-resilience / adversarial-load
testing tool. This document gives you enough context to review it well. Read it,
then read the source (`src/`, `Cargo.toml`, `DOCUMENTATION.md`), then give
**direct, critical feedback** using the prompt at the end. Do not be a
cheerleader — the author wants the flaws.

---

## 1. What it is and who it's for

A single-operator CLI that stress-tests a network target the operator is
**authorized** to assess, then classifies what happened: did the target absorb
the load, did a defense (WAF / rate limiter) engage, or did the service actually
degrade or fail? It is built as a portfolio piece for a **cybersecurity** résumé,
so the intelligence of the *verdict* matters as much as the raw load generation.

It is explicitly **not** a botnet, not a C2 framework, and not a bandwidth DDoS
cannon. It runs from one origin.

## 2. Non-negotiable safety model

- **Single origin only.** No IP spoofing (except the raw L3/L4 vectors, which use
  the host's *real* source IP), no amplification, no reflection, no distributed
  control.
- **Consent gate.** On every run the operator must type `I HAVE AUTHORIZATION`
  verbatim. It is TTY-only and cannot be piped. No flag path (`--config`,
  `--preset`, `--auto`) bypasses it.
- **Human-in-the-loop targeting.** Recon ranks candidate endpoints; a human
  approves the flood target. An opt-in `--auto-approve` exists for unattended
  soak runs, but approval-on is the default.
- **Recommend, never auto-fire.** The auto-engine characterizes a target and
  *recommends* a preset; it still routes through consent + confirmation.

If a review finds any way these can be violated, that is the highest-severity
possible finding.

## 3. Architecture

Rust + tokio. Modules (`src/`):

| module         | role |
|----------------|------|
| `main.rs`      | CLI parse, consent, orchestration, preset/auto/config resolution |
| `auth.rs`      | the consent gate |
| `cli.rs`       | interactive flow (target → proxy → preset? → mode → recon → vectors → tuning → timing) |
| `config.rs`    | `Vector` enum, `RunMode`, `VectorTuning`, `RunConfig`, serde |
| `presets.rs`   | curated vector combos per target kind; fixed load level |
| `auto.rs`      | probe + fingerprint → characterize → recommend a preset |
| `recon/`       | crawl + fingerprint + sensitive-path probe → asymmetry-ranked endpoints |
| `engine/`      | the load engine: workers per vector, governor, sampler, health probe |
| `classify.rs`  | turns run signals + collapse curve into a `Verdict` + confidence + evidence |
| `metrics.rs`   | `LatencySample`, `RunOutcome` types |
| `logging.rs`   | tracing to a timestamped run log + terminal |
| `db.rs`        | **stub** — SQLite CVE correlation, not built yet |
| `web/`         | **stub** — axum dashboard, not built yet |

Key deps: `tokio`, `httparse`, `tokio-rustls` (ring), `h2`, `pnet_packet` /
`pnet_transport` (raw sockets), `reqwest` (recon only), `dialoguer` (prompts),
`tracing`.

### Engine internals (`engine/mod.rs` + per-vector files)

- **Metrics**: lock-free atomic counters + a 512-bucket HdrHistogram-style
  latency histogram (`histogram.rs`, O(1) record). Counters:
  `requests_sent` (attempts), `responses_ok` (completed), `errors`,
  `bytes_sent`, `held_connections`, and HTTP status-class buckets.
- **Governor** (per vector): an atomic `target` concurrency. Ramp-up grows it
  linearly; in `Adaptive` mode it halves on distress and regrows (the back-off /
  regrow cycle doubles as a recovery-time detector). `Dumb` mode ignores
  feedback and holds max.
- **Sampler**: every 250 ms, snapshots the histogram delta → windowed
  p50/p95/p99, RPS, and error rate → one collapse-curve point.
- **Health probe**: an independent once-per-second TCP connect to the target,
  plus a pre-load baseline. This is the *only* availability signal that works for
  raw L4 vectors, and it is ground truth for "is the target still accepting
  connections."
- **Shutdown**: a `watch` channel; Ctrl-C or duration triggers a cooperative
  drain.

### Vectors (16 + recon)

L7: `http_flood`, `https_only`, `slowloris`, `rudy`, `slow_read`, `range_flood`
(CVE-2011-3192), `tls_exhaust`, `h2_flood`, `h2_rapid_reset` (CVE-2023-44487),
`h2_continuation` (CVE-2024-27316, hand-rolled framing).
L4/L3 (raw sockets, need root, real source IP): `syn_flood`, `ack_flood`,
`tcp_exhaust`, `udp_flood`, `dns_flood`, `icmp_flood`.

### Classifier (`classify.rs`)

Verdicts: `Healthy`, `MitigationEngaged` (defense working — **not** a finding),
`EdgeBlocked`, `Degrading` (finding), `Down` (finding), `Unknown`. Every verdict
carries a confidence (capped at 0.9 — never certainty) and an evidence trail.
Decision order: health probe → 429 (rate-limit) → 403 (+WAF fingerprint) → p99
blowout vs baseline → no-responses edge/down → mostly-2xx healthy. Two guards
against false findings: a **3× ratio AND a ≥25 ms absolute** p99 delta (kills
sub-ms localhost noise), and probe results split target-failure vs
local-exhaustion.

## 4. Recent fixes you should scrutinize (this is where bugs hide)

A live router test exposed three real bugs; they were just fixed. **Verify the
fixes are correct and complete:**

1. **Fantasy RPS.** The RPS counter tallied `requests_sent` (incremented the
   instant a connection existed), so a target that accepted-then-reset produced
   *millions* of "requests/sec" that were really failed reconnect churn. Fix:
   RPS and error-rate are now computed from `responses_ok` (completions) and
   `errors`; `error_rate = errors / (completions + errors)`. **Question for you:**
   is deriving RPS from completions the right call, or does it now under-report
   legitimate load in some vector? Does any consumer of the old semantics break?

2. **Unthrottled reconnect loop.** The HTTP worker hot-looped on transport reset
   with no backoff, spinning the CPU and exhausting local sockets. Fix: a 50 ms
   backoff on the `Err` path (a *clean* keep-alive close is a separate `Ok(false)`
   path and is **not** throttled). **Question:** is 50 ms right? Does it throttle
   legitimate high-throughput runs against healthy servers?

3. **Self-inflicted false DOWN.** The health probe did its own `connect()` from
   the same host; with the socket table exhausted, the probe failed and the tool
   declared the *target* DOWN. Fix: `probe_once` classifies the connect error —
   `ECONNREFUSED` = target up & refusing (not a failure), timeout/unreachable =
   real target failure, `EADDRNOTAVAIL`/`EMFILE`/`ENFILE`/`ENOBUFS` = *our* box
   (inconclusive). The classifier excludes local-exhaustion from the failure
   denominator and refuses a DOWN verdict when local errors dominate. **Question:**
   are the errno mappings correct and complete? Is treating `ECONNREFUSED` as
   "up" defensible for a health probe against a web port (accept-queue-full often
   presents as a dropped SYN → timeout, but tcp_abort_on_overflow can RST)?

Also changed: the tiered aggressiveness ladder (recon/light/moderate/aggressive/
brutal) was removed. Presets now always run at a single fixed concurrency
(`PRESET_CONCURRENCY = 2700` workers/vector), tuned down from a naive 3000 so a
single origin exhausts the target's state table *before* its own local limits.
**Question:** is a hardcoded 2700 defensible, or should it adapt to observed
local limits (ulimit -n, ephemeral port range, conntrack max)?

## 5. Known gaps / not-yet-built

- Web dashboard (`web/`) and SQLite CVE correlation (`db.rs`) are stubs.
- `derive_outcome` prefers the recon baseline but the wiring is partial.
- No integration/E2E test harness yet (see `dev/tests/`).
- Single-origin fundamentally cannot bandwidth-saturate a real target; the whole
  thesis is **state-table / connection-table exhaustion** and asymmetry, not
  volume. Judge the design against *that* goal, not against a DDoS cannon.

---

## 6. Your review task

Give the author specific, prioritized, critical feedback. Concretely:

1. **Correctness first.** Audit the three recent fixes above and the classifier.
   Find cases where the verdict would be wrong (false finding *or* missed
   finding). Trace at least one concrete failure scenario end to end.
2. **Safety.** Try to find any path that bypasses the consent gate or the
   single-origin invariant. Assume an adversarial operator reading the code.
3. **Metric honesty.** Is the collapse curve / RPS / error-rate now trustworthy
   under: healthy server, resetting target, rate-limited target, closed port,
   raw-L4-only run? Name any remaining way the numbers can lie.
4. **Rust quality.** Concurrency correctness (atomics ordering, the watch-channel
   shutdown, histogram snapshot races), error handling, and anything `unsafe`.
5. **Design / résumé value.** Is the state-table-exhaustion framing convincing?
   What one change would most raise the credibility of this as a security tool?

For each finding: state the file/line, the concrete failure, the severity, and
the smallest correct fix. Rank them. If something is *good*, say so briefly, then
move on — the value here is the critique.
