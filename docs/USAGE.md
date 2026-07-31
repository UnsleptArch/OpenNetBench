# Usage — Complete Operator Reference

*Every entry point, every flag, every preset, the full per-vector tuning schema, and the
config-file format. The organising promise of the interface: every interactive choice has a
flag behind it, so the entire tool drives headless with no prompts at all. This document is
the authoritative reference for that surface.*

---

## Table of Contents

1. [Installation](#1-installation)
2. [The Four Entry Points](#2-the-four-entry-points)
3. [Complete Flag Reference](#3-complete-flag-reference)
4. [Presets](#4-presets)
5. [Target Syntax and Scheme Inference](#5-target-syntax-and-scheme-inference)
6. [The Config File Format](#6-the-config-file-format)
7. [Per-Vector Tuning Schema](#7-per-vector-tuning-schema)
8. [Run Modes](#8-run-modes)
9. [Reconnaissance](#9-reconnaissance)
10. [The Proxy](#10-the-proxy)
11. [Logging](#11-logging)
12. [Worked Examples](#12-worked-examples)
13. [Exit Behaviour and Signals](#13-exit-behaviour-and-signals)

---

## 1. Installation

```bash
git clone https://github.com/UnsleptArch/OpenNetBench.git
cd OpenNetBench
./install.sh
```

`install.sh` builds the release binary and places `opennetbench` on the `PATH`, adding
`~/.local/bin` to the shell profile if it is not already present so a fresh shell finds it.
Variants:

```bash
./install.sh --system     # machine-wide install to /usr/local/bin (uses sudo)
./install.sh --xdp        # also build the AF_XDP backend (needs a capable NIC)
./install.sh --uninstall  # remove the installed binary
```

The Rust toolchain (https://rustup.rs) is a prerequisite. The raw-socket vectors
(`syn_flood`, `ack_flood`, `icmp_flood`) require `sudo` at run time regardless of how the
binary was installed. To build without touching the `PATH`:

```bash
cargo build --release                    # ./target/release/opennetbench
cargo build --release --features xdp     # with the AF_XDP transmit backend
```

---

## 2. The Four Entry Points

There are four ways to drive the tool, spanning fully interactive to fully headless.

### 2.1 Interactive

Run `opennetbench` with no arguments. It walks through target, optional proxy, mode, recon,
vector selection, per-vector tuning, timing, and a final confirmation. This is the mode for
exploring an unfamiliar target when the desired configuration is not yet known.

### 2.2 Preset

```bash
opennetbench --preset <name> --target <thing>
```

Fires a curated vector combination at full pressure. The fast path for a known target class.
The presets are enumerated in §4.

### 2.3 Config file

```bash
opennetbench --config plan.json
```

Runs a previously-saved plan. Build one with `--save-config`, edit the JSON freely, run it as
many times as desired. The format is documented in §6.

### 2.4 Fully scripted

```bash
opennetbench --vectors <slugs> --target <thing> --i-am-authorized
```

Builds a plan from flags and runs it with zero prompts — no typed consent phrase, no final
confirmation. This is the CI / automation / unattended path. `--i-am-authorized` is the switch
that makes the run non-interactive: by passing it the operator asserts they are cleared to test
the target, and it stands in for both the consent gate and the final go/no-go (see
[SAFETY.md](SAFETY.md) §7).

```bash
# nothing interactive; drops straight into the engine
opennetbench --target https://example.com \
  --vectors http_flood,slowloris,h2_rapid_reset \
  --mode adaptive --duration 120 --rampup 15 --run-recon --i-am-authorized
```

---

## 3. Complete Flag Reference

Defaults are shown in parentheses.

### 3.1 Target and plan selection

| Flag | Effect |
|---|---|
| `--target <url\|ip>` | The target: a URL or a bare IP. Required by `--vectors`, `--preset`, `--auto`. |
| `--vectors <slugs>` | Comma-separated vector slugs; builds a plan with no prompts (needs `--target`). See `--list-vectors`. |
| `--preset <name>` | Run a built-in combination (§4); needs `--target`. |
| `--auto` | Probe the target, characterise it, recommend a preset, then run it through the normal consent and confirmation path. Never fires on its own. |
| `--config <file>` | Load and run a saved JSON plan. |
| `--save-config <file>` | Resolve the plan to JSON and exit **without running anything or asking for consent**. |

### 3.2 Timing and mode

| Flag | Effect |
|---|---|
| `--mode <adaptive\|dumb>` | Run mode for a flag-driven run (`adaptive`). See §8. |
| `--duration <s>` | Run length; `0` means run until stopped (`60`). |
| `--rampup <s>` | Seconds to ramp concurrency from zero to full (`10`). See §8. |

### 3.3 Reconnaissance and run-time behaviour

| Flag | Effect |
|---|---|
| `--recon <url>` | Recon **only**: crawl, probe, rank the weak endpoints, print the report, send no flood. |
| `--run-recon` | Enable the recon pass within a `--vectors` run. |
| `--auto-approve` | During recon, auto-select the top-ranked endpoint instead of prompting. |
| `--stop-on-detect` | Pause and ask whether to stop the moment a finding appears (off by default, so a run completes its full duration). |
| `--wordlist <file>` | Path-exposure wordlist for recon: one path per line, `#` for comments. |

`--auto-approve` and `--stop-on-detect` are run-time behaviour, not part of a saved plan; they
live only as flags or interactive prompts and are never baked into the JSON (§6).

### 3.4 Network, authorisation, and output

| Flag | Effect |
|---|---|
| `--proxy <url>` | Route the L7/TCP path through a SOCKS5 proxy (`socks5://` or `socks5h://`). See §10. |
| `--i-am-authorized` | Assert authorisation: skip the typed consent phrase and the final confirmation for unattended runs. |
| `--log-dir <dir>` | Where run logs go (`$XDG_STATE_HOME/opennetbench`, else `~/.local/state/opennetbench`). See §11. |

### 3.5 Informational (print and exit)

| Flag | Effect |
|---|---|
| `--list-vectors` | Print the vector slugs and descriptions, then exit. |
| `--list-presets` | Print the presets, then exit. |
| `--ui-only` | Serve the dashboard only, no run (a stub at present). |

---

## 4. Presets

A preset is a curated vector combination for a class of target, defined in `presets.rs`. Each
preset runs at a single fixed pressure — there is no aggressiveness ladder, by design.

| Preset | Vectors | Mode | Recon | Root | Notes |
|---|---|---|:---:|:---:|---|
| `router` | `syn_flood` + `ack_flood` + `tcp_exhaust` | dumb | no | ✓ | Gateway state-table exhaustion. |
| `router-lite` | `tcp_exhaust` | dumb | no | — | Same idea without root. |
| `web` | `http_flood` + `slowloris` + `rudy` + `range_flood` | adaptive | yes | — | L7 volumetric plus a slow-connection mix. |
| `api` | `h2_flood` + `h2_rapid_reset` + `rudy` | adaptive | yes | — | HTTP/2-heavy backend. |
| `cdn` | `tls_exhaust` + `h2_rapid_reset` + `http_flood` | dumb | yes | — | Origins behind an edge. |
| `dns` | `dns_flood` + `udp_flood` | dumb | no | — | DNS server. |

### 4.1 The fixed pressure, and why 2700

Every preset applies `PRESET_CONCURRENCY` = **2700** workers per vector. The number is not
arbitrary. Past a few thousand held connections, a single origin begins to exhaust its *own*
ephemeral ports and connection-tracking state before it stresses the target — which produces
false "target down" reads that are really the generator failing. 2700 is tuned down from a
naïve 3000 to keep real weight on the target's state table while staying inside one box's local
limits. If less pressure is wanted, dump the plan with `--save-config` and edit the
concurrency; if the host's file-descriptor limit is lower than the run demands, the engine's
preflight scales the whole run down proportionally to fit (see [INTERNALS.md](INTERNALS.md) §5).

To choose among presets by target class, see [VECTORS.md](VECTORS.md) §10; to have the tool
choose, use `--auto`.

---

## 5. Target Syntax and Scheme Inference

A target is a URL or a bare IP. When the scheme is omitted, it is inferred:

- A **bare IP** like `192.168.1.254` defaults to `http://`. Router and admin panels are usually
  plaintext, and the L4 vectors only need `address:port` regardless of scheme.
- A **hostname** like `example.com` defaults to `https://`.
- A **full URL** is always honoured as written; be explicit to override the inference.

DNS resolution happens once, up front, and the resolved `SocketAddr` is shared across all
workers (see [INTERNALS.md](INTERNALS.md) — `Target::resolve`), so a run does not re-resolve per
connection and cannot be skewed mid-run by a changing DNS answer.

---

## 6. The Config File Format

`--save-config <file>` writes the fully-resolved plan as JSON, intended to be read and edited.
It resolves and exits: nothing runs, and no consent is requested, because writing a plan is not
running one.

```bash
opennetbench --preset api --target https://api.example.com --save-config api.json
# edit api.json — dial concurrency down, change the duration, whatever
opennetbench --config api.json
```

The plan holds exactly the *durable* configuration:

- `target` — the target URL or IP.
- `proxy` — the optional SOCKS5 proxy configuration.
- `mode` — `adaptive` or `dumb`.
- `run_recon` — whether recon runs before the flood.
- `vectors` — the list of `{ vector, tuning }` entries (§7).
- `duration` and `rampup` — the timing, serialised as seconds.

It deliberately does **not** hold `--auto-approve` or `--stop-on-detect`: those are run-time
decisions, made at the moment of running, not properties of a plan. This separation keeps a
saved plan a description of *what traffic to generate*, distinct from *how to react while
generating it*.

---

## 7. Per-Vector Tuning Schema

Each vector in a plan carries its own `VectorTuning` block, so a single run can mix, for
instance, a 20-connection HTTP probe with a 5000-connection slowloris hold. The engine reads
only the fields relevant to the vector it is driving; irrelevant fields are ignored rather than
rejected.

| Field | Meaning | Applies to |
|---|---|---|
| `concurrency` | Workers / held connections this vector maintains. | all |
| `rate_per_worker` | Target requests/sec per worker; `0` = unbounded. | rate-limited floods (UDP, HTTP) |
| `payload_bytes` | Payload size in bytes. | `udp_flood` (datagram), `rudy` (advertised body length) |
| `trickle_interval` | Cadence for slow vectors. | `slowloris` (header pacing), `rudy` (byte pacing), `slow_read` (drain), `websocket` (keepalive) |
| `port` | Destination-port override; `0` derives it from the target scheme. | all |

### 7.1 Defaults per vector

`VectorTuning::defaults_for` sets conservative small-scale defaults; the operator scales up
explicitly, and presets override `concurrency` to 2700.

| Vector(s) | concurrency | payload_bytes | trickle_interval |
|---|---:|---:|---:|
| `slowloris`, `slow_read`, `websocket` | 200 | 0 | 10 s |
| `rudy` | 100 | 1,000,000 | 10 s |
| `syn_flood`, `ack_flood`, `icmp_flood`, `tcp_exhaust` | 500 | 0 | 0 |
| `udp_flood` | 8 | 1,024 | 0 |
| all others (HTTP family, `tls_exhaust`, `dns_flood`, `h2_*`, `range_flood`) | 50 | 0 | 0 |

The asymmetric defaults reflect the vectors' mechanisms: the slow-connection vectors need only
a couple hundred connections to starve a pool, RUDY advertises a megabyte body it will never
finish sending, and `udp_flood` needs only a handful of workers because each saturates a send
loop. See [VECTORS.md](VECTORS.md) for why each vector's effective pressure differs from its raw
worker count.

---

## 8. Run Modes

Two modes govern how the scheduler paces load. Both ramp concurrency from zero to full over
`--rampup` seconds; they differ in what happens after.

- **Adaptive** (default) self-throttles when the target shows distress on its own error signal,
  then re-grows. It is a closed control loop — additive increase while healthy, multiplicative
  decrease under distress (see [INTERNALS.md](INTERNALS.md) §6). That back-off-and-recovery cycle
  is *also* the mechanism by which the tool measures **recovery time**, the blue-team metric
  nothing else reports. Adaptive is the safer default profile.
- **Dumb** holds maximum load until stopped, with no self-throttling. Use it against a target
  that shrugs off adaptive back-off, or when the goal is specifically sustained maximum pressure —
  notably to probe a *dynamic* WAF that reacts to steady load, where backing off would hide the
  behaviour under test.

Fire-and-forget vectors (UDP, DNS, ICMP, raw SYN/ACK) have no target-derived signal, so even in
adaptive mode they only ramp — they never fake an adaptive decision off a local send count (see
[VECTORS.md](VECTORS.md) §2). Presets pick a sensible mode; override with `--mode`, interactively,
or in the JSON.

The `--rampup` value shapes what the collapse curve can show: a gradual ramp lets the sampler
observe the *knee* — the load at which latency begins to diverge — rather than slamming to
maximum and seeing only the endpoint. A ramp of `0` degenerates to immediate maximum, which is
correct when testing a defence that reacts to rate-of-change.

---

## 9. Reconnaissance

`--recon <url>` runs the full reconnaissance suite and prints a ranked report **without sending
a single flood packet**:

- **Crawl** — an async, same-host breadth-first crawl with a byte-scanner for links and form
  actions.
- **Structured-source discovery** — reads `robots.txt`, the sitemap, and any OpenAPI/Swagger
  spec, and mines JavaScript bundles for API routes, so a single-page app reveals its real API
  surface instead of a pile of static assets.
- **Differential asymmetry probing** — for each candidate parameter, sends a cheap value and an
  expensive one (a large limit, a leading-wildcard search that defeats an index, a
  catastrophic-backtracking pattern) in interleaved pairs and measures the marginal server time
  the expensive one forces, attaching a confidence from the sample spread.
- **Bounded degradation burst** — one small, bounded concurrent burst to find where latency knees
  under load, normalised against a control.
- **GraphQL query-cost** — a read-only fan-out to measure query-cost amplification.

The output is a list of endpoints ranked by measured asymmetry (server cost over client cost;
see [INTERNALS.md](INTERNALS.md) §13), each tagged with the parameter that hurt and by how much,
for the operator to approve before anything is flooded.

Recon still passes the consent gate, because active recon sends crafted inputs and a small burst
— it is not passive. Point it only at authorised targets. Bring a custom path wordlist with
`--wordlist`. Within a flood run, enable the same pass with `--run-recon`, and use
`--auto-approve` to take the top-ranked endpoint automatically instead of being prompted.

---

## 10. The Proxy

The TCP load path and recon can be routed through a SOCKS5 proxy (Tor included), via the
interactive prompt, `--proxy`, or a config file. Only `socks5://` and `socks5h://` are accepted,
and the hostname is handed to the proxy to resolve so DNS is not leaked locally.

**SOCKS5 is TCP only.** The raw L3/L4 vectors and UDP/DNS cannot be carried through it and egress
from the host's real address; the tool warns when a proxied run includes such vectors. The health
and service probes stay direct on purpose — a proxied probe would measure the proxy, not the
target. The proxy is a routing convenience for testing from a chosen vantage point, **not** an
anonymity tool; see [SAFETY.md](SAFETY.md) §6, §8 for the limits.

---

## 11. Logging

Every run writes a structured log via `tracing` to a timestamped file
(`onb-<runid>.log`) under `$XDG_STATE_HOME/opennetbench` (or `~/.local/state/opennetbench`),
overridable with `--log-dir`, in addition to the terminal. If the log directory cannot be
written, the run proceeds terminal-only with a warning rather than failing — a permissions
problem never costs a run. The log captures target resolution, per-vector spawn decisions
(including which vectors were skipped for lack of root and any fd-budget scaling), the sampled
collapse curve, the probe baselines and outcomes, and the final classification with its evidence
trail.

---

## 12. Worked Examples

```bash
# Interactive: walks through target, vectors, tuning, timing
opennetbench

# See what ships
opennetbench --list-presets
opennetbench --list-vectors

# Let it probe, characterise, recommend a combo, then run (through consent)
opennetbench --auto --target example.com --duration 60

# One preset, one shot
opennetbench --preset web --target https://example.com --duration 60

# Home router / gateway state exhaustion — raw sockets, so sudo
sudo opennetbench --preset router --target 192.168.1.254 --duration 40

# Build an editable plan without firing it, run it later
opennetbench --preset api --target https://api.example.com --save-config api.json
opennetbench --config api.json

# Recon only — find and rank weak endpoints, send no flood
opennetbench --recon https://example.com --wordlist paths.txt

# Fully scripted, no prompts (asserts authorisation)
opennetbench --target https://example.com --vectors http_flood,slowloris \
  --duration 60 --i-am-authorized

# Scripted mixed run with recon and a proxy, adaptive with a 15s ramp
opennetbench --target https://example.com \
  --vectors h2_flood,h2_rapid_reset,rudy \
  --mode adaptive --duration 120 --rampup 15 \
  --run-recon --auto-approve --proxy socks5h://127.0.0.1:9050 \
  --i-am-authorized
```

---

## 13. Exit Behaviour and Signals

A run terminates on any of: the configured `--duration` elapsing (unless `0`, which runs until
stopped), an operator interrupt (Ctrl-C), or `--stop-on-detect` firing and the operator choosing
to stop. In every case, termination is *cooperative and complete*: a shutdown signal propagates to
every worker over a `watch` channel, workers race it on every await and exit within the drain
grace, and any straggler wedged in a syscall is force-aborted after five seconds (see
[INTERNALS.md](INTERNALS.md) §7). Stopping the process stops the traffic — there is no residual
component and nothing to clean up. After the run, the tool prints the final classification: the
verdict, its confidence (capped at 0.9 — likelihood, never proof), and the evidence trail that
supports it.
