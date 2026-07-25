# OpenNetBench

**Single-origin network resilience assessment for authorized testing.**
`beta v1` · Rust · GPLv3

OpenNetBench generates the adversarial load patterns real threat actors use —
not benign synthetic traffic — so you can find your infrastructure's actual
breaking point before an attacker does. It runs sixteen vectors from L3 to L7,
measures the target with an independent health probe, and **classifies the
outcome**: did the defence hold, or did the service break?

Most load testers (JMeter, wrk, Locust) model legitimate users. They tell you how
you handle 10,000 shoppers. They don't tell you how you handle a slowloris hold,
an HTTP/2 rapid-reset campaign, or a connection-table exhaustion attempt.
OpenNetBench fills that gap — scoped to systems you own or are authorized to test.

---

## Highlights

- **16 vectors, L3→L7** — volumetric, slow-connection, state-exhaustion, protocol
  abuse. Three named CVEs (2023-44487, 2024-27316, 2011-3192).
- **Auto-engine** — probe a target, characterize it, and get a recommended
  attack combo + aggressiveness tier with reasoning (`--auto`).
- **Presets & tiers** — one-command profiles (`router`, `web`, `api`, `cdn`,
  `dns`, …) across five aggressiveness tiers (`recon`→`brutal`).
- **Ground-truth classification** — an independent health probe watches the
  target and the classifier reports `Healthy` / `MitigationEngaged` /
  `EdgeBlocked` / `Degrading` / `Down` with a confidence and evidence.
- **Real measurement** — the collapse curve (windowed p50/p95/p99 vs load),
  time-to-degradation, the knee, and **recovery time** — the metric almost
  nobody measures, and gold for blue teams.
- **Fast and lean** — lock-free atomics, a fixed 4 KB latency histogram, zero
  per-request allocation, prompt cooperative shutdown.

---

## Install

```bash
git clone <your-repo-url> && cd OpenNetBench
./install.sh            # builds release, installs `opennetbench` to ~/.local/bin
# or: ./install.sh --system   (machine-wide, /usr/local/bin)
```

Requires the Rust toolchain (<https://rustup.rs>). Raw-socket vectors
(`syn_flood`, `ack_flood`, `icmp_flood`) need `sudo` at run time.

Prefer to build only:

```bash
cargo build --release   # ./target/release/opennetbench
```

---

## Quick start

```bash
# Interactive — walks you through target, vectors, tuning, timing
opennetbench

# See what's available
opennetbench --list-presets

# Auto: probe the target, recommend a combo + tier, then run it
opennetbench --auto --target example.com --duration 60

# Preset + tier, one shot
opennetbench --preset web --tier moderate --target https://example.com --duration 60

# Router / gateway state-exhaustion (raw sockets → sudo)
sudo opennetbench --preset router --tier aggressive --target 192.168.1.254 --duration 40

# Generate an editable plan without running it
opennetbench --preset api --tier aggressive --target https://api.example.com --save-config api.json
opennetbench --config api.json     # run it later (edit the JSON freely)
```

**Targets:** a URL or a bare IP. Bare IPs default to `http://` (router/admin UIs
are usually plaintext, and L4 vectors just need `address:port`); hostnames
default to `https://`.

### Useful flags

| Flag | Effect |
|---|---|
| `--auto` | probe → characterize → recommend → run |
| `--preset <name> --tier <tier>` | run a built-in combo |
| `--target <url\|ip>` | the target |
| `--duration <s>` / `--rampup <s>` | run length / ramp (0 duration = until stopped) |
| `--auto-approve` | let recon auto-pick the top target (no prompt) |
| `--stop-on-detect` | pause and ask to stop the moment a finding appears (off = full duration) |
| `--save-config <file>` | write the resolved plan to JSON and exit |
| `--list-presets` | list presets and tiers |

---

## Vectors

| Vector | Layer | Description |
|---|---|---|
| `http_flood` / `https_only` | L7 | HTTP/1.1+2 flood, rotating browser fingerprints |
| `range_flood` | L7 | CVE-2011-3192 overlapping `Range` headers |
| `slowloris` | L7 | incomplete-header hold — drains the connection pool |
| `rudy` | L7 | slow POST body trickle — ties up worker threads |
| `slow_read` | L7 | tiny receive window — holds the server's send buffer |
| `h2_flood` | L7 | multiplexed HTTP/2 request flood |
| `h2_rapid_reset` | L7 | CVE-2023-44487 — stream open + immediate RST |
| `h2_continuation` | L7 | CVE-2024-27316 — endless CONTINUATION frames |
| `tls_exhaust` | L4/5 | repeated TLS handshakes — asymmetric server CPU |
| `tcp_exhaust` | L4 | connection-table / accept-backlog exhaustion |
| `syn_flood` | L4 | raw TCP SYN flood (root) |
| `ack_flood` | L4 | raw ACK flood — stresses stateful firewall/conntrack (root) |
| `udp_flood` | L4 | UDP flood, configurable payload |
| `dns_flood` | L7 | random-subdomain query flood |
| `icmp_flood` | L3 | ICMP echo flood (root) |

**Tiers:** `recon` (probe only) · `light` (50/vector) · `moderate` (200) ·
`aggressive` (800) · `brutal` (3000).

---

## How it decides "it broke"

An independent health probe connects to the target once a second throughout the
run (with a pre-load baseline). The classifier reads that ground truth plus the
collapse curve and HTTP status mix:

- **MitigationEngaged** — 429s (rate limiter) or 403s + a WAF/CDN fingerprint.
  The defence is working; not a finding.
- **Degrading / Down** — p99 blows past baseline, or the probe stops answering
  under load. A real resource-exhaustion finding.
- **EdgeBlocked** — fast connection refusals with no application response.
- **Healthy** — the target absorbed it.

Confidence is capped at 0.9 — it reports likelihood, never proof.

---

## Design notes

Single origin, by design: all traffic leaves this host. There is **no IP
spoofing, no amplification, and no command-and-control** — this is a resilience
tester, not a botnet or a C2 framework. A single, real source IP means every run
is fully attributable and instantly containable: stop the process, stop the
traffic. See [DOCUMENTATION.md](DOCUMENTATION.md) for the full architecture.

---

## Authorized use only

OpenNetBench generates real denial-of-service load. Point it **only** at
infrastructure you own or have explicit written authorization to test. Running it
against systems you don't control is illegal under the Computer Fraud and Abuse
Act (US), the Computer Misuse Act (UK), EU Directive 2013/40/EU, and equivalent
laws elsewhere. A consent gate requires you to attest authorization at the start
of every run — it's not decorative.

Good-faith, authorized security research only: your own systems, lab
environments, CTFs, or client infrastructure you're engaged to assess.

---

## Status

**Beta v1.** The engine, vectors, recon, auto-engine, presets/tiers, health
probe, and classifier are complete and tested. On the roadmap: the live
dashboard (animated collapse curve + findings), SQLite run history, and CVE
correlation.

## License

GPLv3. See [LICENSE](LICENSE).
