# External LLM feedback

Reviews of OpenNetBench solicited via `dev/LLM_REVIEW.md`. Each file is the
reviewer's output, lightly formatted, otherwise verbatim.

| File | Reviewer | Ran code? |
|------|----------|-----------|
| `2026-07-25-chatgpt.md` | ChatGPT | no (no cargo in env) |
| `2026-07-25-claude.md`  | Claude  | partial — verified consent gate vs dialoguer source |
| `2026-07-25-gemini.md`  | Gemini  | no |

## Consensus map — where reviewers agree (triage by this)

Findings raised by **2+ reviewers** are the highest-signal; a single-reviewer
finding may still be real but got less corroboration.

### Tier A — multiple reviewers, high severity

1. **Metrics are dishonest for non-HTTP vectors.** `responses_ok` = a local
   `send()` syscall for udp/dns/icmp/syn/ack (no read-back), so RPS = egress
   packet rate and error_rate ≈ 0% even against a black-holed target. Slow
   vectors (slowloris/rudy/tcp_exhaust) never complete a request, so they report
   **0 RPS / 0 error**. The completion-based fix only truly landed for HTTP.
   — *ChatGPT P1, Claude #1, Gemini #2.* **The dominant theme.**

2. **ECONNREFUSED-as-"up" is wrong for service health.** After a successful
   baseline, if load crashes the service (or fills the accept queue) and the OS
   RSTs subsequent probes, `probe_failures == 0` and the run can read **Healthy /
   MitigationEngaged — a false negative on a real DoS.** Needs a baseline-state
   transition: baseline-Accepting → later-Refused = service failure.
   — *ChatGPT P1, Claude #4, Gemini #1 (Critical).*

3. **Hardcoded 2700 → EMFILE / false-Unknown on normal machines.** No
   `RLIMIT_NOFILE` check; multi-vector presets want 8k–10k sockets vs a 1024/256
   default ulimit. Read the fd limit at startup and cap/warn.
   — *ChatGPT P1, Claude #6, Gemini #3.*

4. **Per-vector governor reads run-global counters.** One `Metrics` for the whole
   run, so in a mixed preset a distressed vector throttles healthy ones (and a
   healthy vector masks a distressed one). Per-vector metrics needed.
   — *ChatGPT P1, Claude #2.*

5. **Slow-L7 vectors treated as L4-only.** `l7_active` only matches
   http/https/range/h2_flood, so a Slowloris run that exhausts the target's
   worker pool but leaves TCP answering reads **Healthy**. Widen the capability
   signal. — *ChatGPT P1; overlaps Claude #1, Gemini #2.*

6. **50 ms backoff needs jitter / exponential.** Flat 50 ms synchronizes
   thousands of workers into a thundering herd on mass reset. Add jitter + capped
   exponential backoff. — *ChatGPT P2, Gemini #4.*

7. **errno constants are Linux-only.** Hardcoded Linux numbers with no
   `cfg(target_os)`; on macOS/BSD every local-exhaustion error falls through to
   `TargetFail` → the false-DOWN bug returns off-Linux. Prefer `io::ErrorKind`.
   — *ChatGPT P2, Claude #4.*

### Tier B — single reviewer, worth verifying

- **Shutdown not guaranteed** — a worker blocked in `read_buf().await` (target
  holds the socket open, never replies) doesn't race the shutdown channel, so
  Ctrl-C may not stop traffic promptly. Wrap unbounded I/O in
  `select!{ … , _ = shutdown.changed() => }` + a bounded drain-then-abort. Only
  ChatGPT raised it, but it's a plausible **safety** issue. *(needs a repro.)*
- **"Sustained" degradation triggers on one 250 ms sample** — a single p99 spike
  → Degrading. Needs N-consecutive / hysteresis. *(ChatGPT — verify against
  derive_outcome.)*
- **stop_on_detect compares HTTP-TTFB baseline to TCP-connect latency** — wrong
  threshold. Use `probe_baseline_ms` for probe decisions. *(ChatGPT.)*
- **Recon "same host" ≠ "same origin"** (ignores scheme+port); **POST forms are
  timed with GET** and method isn't carried into execution — undercuts the
  asymmetry thesis. *(ChatGPT.)*
- **Recon baseline silently lost** when operator keeps the original (un-crawled)
  target — falls back to sample-derived baseline with no log. *(Claude #5.)*
- **Proxy field is dead but shipped** — a Tor/SOCKS5 prompt exists, is stored and
  printed, but never used. ChatGPT: fail loud until supported. Claude escalates
  it to a **safety landmine**: a Tor-shaped prompt one `connect()` from
  invalidating the single-origin/attributability invariant. *(ChatGPT P1 +
  Claude #3.)*
- **Histogram snapshot tearing** — Gemini flags possible torn p99 reads across a
  sequential snapshot; Claude separately judged the histogram math correct and
  panic-free but didn't address per-window tearing. *(needs measurement.)*
- **Consent gate — conflict to resolve:** ChatGPT (P0) claims no explicit
  `IsTerminal` check and that `entered.trim()` accepts whitespace-padded phrases
  (not "verbatim"). Claude **empirically verified** dialoguer returns
  `Err(NotConnected)` on non-TTY stdin, so pipe-bypass does *not* work. Both note
  a pty/expect wrapper defeats any TTY gate (by design — it's friction, not a
  control). **Action: confirm the `trim()` detail in auth.rs and decide on an
  explicit `is_terminal()` guard + exact compare.**

### Cross-cutting design suggestion (ChatGPT + Gemini)

Both independently name the same #1 credibility upgrade: **an independent
control-plane / observer** — a separate, separately-resourced (ideally
externally-hosted) client issuing real application-level health checks, so the
report can prove "target degraded" vs "the load generator exhausted itself."
Gemini's variant: emit **receipts** (PCAP / TCP-state timeline) behind each
verdict. This is the strongest single move for the résumé thesis.

## Notes on scope / disagreements

- The reviewers largely **validate the recent fixes' direction** (completion RPS,
  local-vs-target probe split, Ok(false)/Err backoff split) while showing each
  was **incomplete** — mostly because the fixes were applied to the HTTP path
  only and not generalized across the 16 vectors.
- Nothing here has been acted on yet. This folder is the raw input to the next
  planning pass.
