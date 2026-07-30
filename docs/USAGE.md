# Usage

Every flag, every preset, and how the config files work. The short version: every
interactive choice has a flag behind it, so the entire tool drives headless with
no prompts at all.

## The four ways in

**Interactive.** Run `opennetbench` with no arguments and it walks you through
target, optional proxy, mode, recon, which vectors, per-vector tuning, timing, and
a final confirm. Good when you are poking at something new and do not know what you
want yet.

**Preset.** `--preset <name> --target <thing>` fires a curated combo at full
pressure. The fast path for a known target class.

**Config file.** `--config plan.json` runs a plan you saved earlier. Build one with
`--save-config`, edit the JSON however you like, run it as many times as you want.

**Fully scripted.** `--vectors <slugs> --target <thing> --i-am-authorized` builds a
plan from flags and runs it with zero prompts, no typed consent phrase, no final
confirm. This is the CI / automation / unattended path. `--i-am-authorized` is the
switch that makes it non-interactive: by passing it you assert you are cleared to
test the target, and it stands in for both the consent gate and the go/no-go.

```bash
# nothing interactive about this, drops straight into the engine
opennetbench --target https://example.com \
  --vectors http_flood,slowloris,h2_rapid_reset \
  --mode adaptive --duration 120 --rampup 15 --run-recon --i-am-authorized
```

## Flags

Every flag. Defaults in parentheses.

| Flag | Effect |
|---|---|
| `--target <url\|ip>` | the target, a URL or a bare IP |
| `--vectors <slugs>` | comma-separated vector slugs, builds a plan with no prompts (needs `--target`). See `--list-vectors` |
| `--preset <name>` | run a built-in combo (see below), needs `--target` |
| `--auto` | probe the target, characterize it, recommend a preset, then run it through the normal consent and confirm |
| `--config <file>` | load and run a saved JSON plan |
| `--save-config <file>` | resolve the plan to JSON and exit without running anything or asking for consent |
| `--recon <url>` | recon only: crawl, probe, rank the weak endpoints, print the report, send no flood |
| `--mode <adaptive\|dumb>` | run mode for a flag-driven run (`adaptive`) |
| `--duration <s>` | how long to run, `0` means until you stop it (`60`) |
| `--rampup <s>` | seconds to ramp concurrency from zero to full (`10`) |
| `--run-recon` | enable the recon pass in a `--vectors` run |
| `--auto-approve` | during recon, auto-pick the top-ranked endpoint instead of asking |
| `--stop-on-detect` | pause and ask to stop the moment a finding shows up, off by default so it runs the whole duration |
| `--proxy <url>` | route the L7/TCP path through a SOCKS5 proxy (`socks5://` or `socks5h://`) |
| `--wordlist <file>` | path-exposure wordlist for recon, one path per line, `#` for comments |
| `--i-am-authorized` | assert authorization: skip the typed consent phrase and the final confirm for unattended runs |
| `--log-dir <dir>` | where run logs go (`$XDG_STATE_HOME/opennetbench`, else `~/.local/state/opennetbench`) |
| `--list-vectors` | print the vector slugs and exit |
| `--list-presets` | print the presets and exit |
| `--ui-only` | serve the dashboard only, no run (stub for now) |

`--auto-approve` and `--stop-on-detect` are run-time behavior, not part of a saved
plan, so they live as flags or interactive prompts and never get baked into the
JSON.

## Presets

Every preset applies to a class of target and runs at one fixed pressure.

| Preset | Vectors | Mode | Recon | Notes |
|---|---|---|---|---|
| `router` | `syn_flood` + `ack_flood` + `tcp_exhaust` | dumb | no | gateway state-table exhaustion, needs sudo |
| `router-lite` | `tcp_exhaust` | dumb | no | same idea without root |
| `web` | `http_flood` + `slowloris` + `rudy` + `range_flood` | adaptive | yes | L7 volumetric plus a slow-connection mix |
| `api` | `h2_flood` + `h2_rapid_reset` + `rudy` | adaptive | yes | HTTP/2 heavy backend |
| `cdn` | `tls_exhaust` + `h2_rapid_reset` + `http_flood` | dumb | yes | origins sitting behind an edge |
| `dns` | `dns_flood` + `udp_flood` | dumb | no | DNS server |

Every preset runs at one fixed pressure, 2700 workers per vector, and there is no
aggressiveness ladder on purpose. If you want less, dump the plan with
`--save-config` and edit it. The 2700 is not arbitrary either: past a few thousand
held connections a single origin starts exhausting its own ephemeral ports and
conntrack before it touches the target, which produces fake "target down" reads.
2700 keeps real weight on the target while staying inside one box's limits, and the
preflight scales it down further if your file-descriptor limit is lower.

## Targets

A URL or a bare IP.

- Bare IP like `192.168.1.254` defaults to `http://`. Router and admin panels are
  usually plaintext and the L4 vectors only need `address:port` anyway.
- A hostname like `example.com` defaults to `https://`.
- You can always be explicit and pass the full URL.

## Config files

`--save-config` writes the fully resolved plan as JSON. It is meant to be read and
edited. Every vector, its concurrency, rate, payload size, trickle interval and port
are all in there.

```bash
opennetbench --preset api --target https://api.example.com --save-config api.json
# open api.json, dial concurrency down, change the duration, whatever
opennetbench --config api.json
```

The plan holds the target, the proxy, the mode, the recon flag, the vector list with
tuning, the duration and the ramp. It does not hold `--auto-approve` or
`--stop-on-detect`, those are decisions you make at run time.

## Per-vector tuning

Each vector in a saved plan carries its own tuning block, so one run can mix a tiny
20-connection HTTP probe with a 5000-connection slowloris hold:

- `concurrency` — workers / held connections this vector maintains.
- `rate_per_worker` — target requests per second per worker, `0` is unbounded.
- `payload_bytes` — payload size where it applies (UDP payload, RUDY body length).
- `trickle_interval` — cadence for the slow vectors (slowloris header pacing, RUDY
  byte pacing, slow-read drain, WebSocket keepalive).
- `port` — destination port override, `0` derives it from the target.

The engine only reads the fields that matter for the vector it is driving.

## Proxy

You can route the TCP load path and recon through a SOCKS5 proxy, Tor included,
either from the interactive prompt, `--proxy`, or a config file. Only `socks5://`
and `socks5h://` are accepted and the hostname is handed to the proxy to resolve so
you do not leak DNS locally.

SOCKS5 is TCP only. The raw L3/L4 vectors and UDP/DNS cannot be carried through it
and they egress from the host's real address; the tool warns you when that happens.
The health and service probes stay direct on purpose, otherwise you would be
measuring the proxy instead of the target.

## Modes

Two run modes.

- **Adaptive** self-throttles when the target shows distress on its own error
  signal, then re-grows. That back-off and recovery cycle is how it measures
  recovery time, the blue-team metric nothing else reports.
- **Dumb** just holds maximum load. Use it against something that shrugs off the
  adaptive back-off, or when you specifically want sustained pressure with no mercy.

Presets pick a sensible mode for you. Override it with `--mode`, interactively, or in
the JSON.

## Recon only

`--recon <url>` runs the full recon suite (crawl, structured-source discovery,
differential asymmetry probing, a bounded degradation burst, GraphQL cost) and prints
the ranked report without sending a single flood packet. It still passes the consent
gate, because active recon sends crafted inputs and a small burst, so point it only
at authorized targets. Bring your own path wordlist with `--wordlist`.

## Logs

Every run writes a structured log to `$XDG_STATE_HOME/opennetbench` (or
`~/.local/state/opennetbench`), overridable with `--log-dir`. If the directory can
not be written the run still proceeds with terminal-only logging rather than dying,
so a permissions problem never costs you a run.
