# Usage

Everything you can pass it, what the presets are, and how the config files work.

## Running it

Three ways in.

**Interactive.** Just run `opennetbench` with no arguments and it walks you through target, optional proxy, mode, recon, which vectors, per-vector tuning, timing, and a final confirm. Good when you are poking at something new and do not know what you want yet.

**Preset.** `--preset <name> --target <thing>` fires a curated combo. This is the fast path for a known target class.

**Config file.** `--config plan.json` runs a plan you saved earlier. Build one with `--save-config`, edit the JSON however you like, run it as many times as you want. The consent gate still applies, a config file does not buy you out of that.

## Flags

| Flag | Effect |
|---|---|
| `--auto` | probe the target, characterize it, recommend a combo, then run it through the normal consent and confirm path |
| `--preset <name>` | run a built-in combo (see below) |
| `--target <url\|ip>` | the target, a URL or a bare IP |
| `--duration <s>` | how long to run. `0` means run until you stop it |
| `--rampup <s>` | seconds to ramp concurrency from zero to full |
| `--auto-approve` | during recon, auto-pick the top-ranked endpoint instead of asking |
| `--stop-on-detect` | pause and ask to stop the moment a finding shows up. off by default, which means it runs the whole duration |
| `--save-config <file>` | resolve the plan to JSON and exit without running anything |
| `--config <file>` | load and run a saved JSON plan |
| `--list-presets` | print the presets and exit |
| `--ui-only` | serve the dashboard only (stub for now) |

`--auto-approve` and `--stop-on-detect` are run-time behavior, not part of a saved plan, so they live as flags or interactive prompts and never get baked into the JSON.

## Presets

| Preset | Vectors | Notes |
|---|---|---|
| `router` | syn + ack + tcp_exhaust | state-table exhaustion. needs sudo |
| `router-lite` | tcp_exhaust | same idea without root |
| `web` | http_flood + slowloris + rudy + range_flood | recon-driven, adaptive |
| `api` | h2_flood + h2_rapid_reset + rudy | HTTP/2 heavy |
| `cdn` | tls_exhaust + h2_rapid_reset + http_flood | for origins sitting behind an edge |
| `dns` | dns_flood + udp_flood | DNS server |

Every preset runs at one fixed pressure, 2700 workers per vector. There is no aggressiveness ladder on purpose. If you want less, dump the plan and edit it. The 2700 number is not arbitrary either, past a few thousand held connections a single origin starts exhausting its own ephemeral ports and conntrack before it touches the target, and that produces fake "target down" reads. 2700 keeps real weight on the target while staying inside one box's limits.

## Targets

A URL or a bare IP.

- Bare IP like `192.168.1.254` defaults to `http://`. Router and admin panels are usually plaintext and the L4 vectors only need `address:port` anyway.
- A hostname like `example.com` defaults to `https://`.
- You can always be explicit and pass the full URL.

## Config files

`--save-config` writes the fully resolved plan as JSON. It is meant to be read and edited. Every vector, its concurrency, rate, payload size, trickle interval and port are all in there.

```bash
opennetbench --preset api --target https://api.example.com --save-config api.json
# open api.json, dial concurrency down, change the duration, whatever
opennetbench --config api.json
```

The plan holds the target, the proxy, the mode, the recon flag, the vector list with tuning, the duration and the ramp. It does not hold `--auto-approve` or `--stop-on-detect`, those are decisions you make at run time.

## Proxy

You can route the TCP load path and recon through a SOCKS5 proxy, Tor included, either from the interactive prompt or a config file. Only `socks5://` and `socks5h://` are accepted and the hostname is handed to the proxy to resolve so you do not leak DNS locally.

SOCKS5 is TCP only. The raw L3/L4 vectors and UDP/DNS cannot be carried through it and they egress from the host's real address, the tool warns you when that happens. The health and service probes stay direct on purpose, otherwise you would be measuring the proxy instead of the target.

## Modes

Two run modes.

- **Adaptive** self-throttles when the target shows distress, then re-grows. That back-off and recovery cycle is how it measures recovery time.
- **Dumb** just holds maximum load. Use it against something that shrugs off the adaptive back-off, or when you specifically want sustained pressure with no mercy.

Presets pick a sensible mode for you. You can override it interactively or in the JSON.
