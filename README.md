# OpenNetBench

**Single-origin adversarial load generator for authorized resilience testing.**
Rust. GPLv3. Linux.

**Note some of this was written by AI, as always I have tested the code and fuzzed the code (methodology will come in docs soon) however there may still be some LLM driven problems in the code for professional traffic generation I would watch its log very carefully if you feel somethings off -unslept**


Most load testers ask "how do you handle 10,000 happy shoppers that are always on the home page!!!!!11!" That is a useful question and it is not the one that takes your service down. OpenNetBench asks the other one. It throws the traffic real attackers throw. Slowloris holds, HTTP/2 rapid reset, connection-table exhaustion, raw SYN and ACK floods at line rate, and then it watches the target with an independent probe and tells you flat out whether the thing broke or held.

It runs twenty vectors from L3 to L7 off a single box. No amplification, no botnet, no C2. There is an optional SOCKS5 proxy for the L7 traffic if you want it, and the raw L4 stuff still goes out this host's own address, so it is not an anonymity tool and never pretends to be one. That lean design is deliberate and the reasoning is in [docs/SAFETY.md](docs/SAFETY.md). You many ask why, and the reason is because i was too lazy to implement all of that and it would look unprofessional on my CV or whatnot.

This is not TRex. TRex hands you line-rate numbers and walks away. OpenNetBench hands you a verdict. (no hate to TRex very good DPDK implementation)

---

## Why it exists

wrk, JMeter, Locust and friends model legitimate users. They tell you your throughput ceiling under polite traffic. None of them will hold ten thousand half-open connections until your worker pool starves, or open a stream and reset it before the server can breathe, or fill a home router's conntrack table in under a second. Those are the patterns that actually cause outages and those are the patterns this tool speaks.

The other half of the tool is the part nobody else bothers with. Generating load is easy. Knowing whether the target actually degraded, versus your own box running out of sockets, versus a WAF quietly eating the traffic, that is the hard part. OpenNetBench runs two independent observers against the target the whole time and classifies the outcome with a confidence and an evidence trail. It will not call a working rate limiter a "vuln" and it will not blame the target for your local port exhaustion.

---

## Finding the weak point

Firepower is half of it. The other half is knowing where to aim. Before it floods anything, OpenNetBench runs an active recon pass that hunts for asymmetry, the one endpoint where a cheap request costs the server a fortune.

It crawls the target, reads its `robots.txt`, sitemap and OpenAPI/Swagger spec for free, and mines the JavaScript bundles for API routes, so on a single-page app it finds the real surface instead of a pile of static assets. Then it actively probes each candidate. It sends a cheap value and an expensive one for every parameter, a huge limit, a leading-wildcard search that defeats the index, a catastrophic-backtracking pattern, and measures the extra server time the expensive one forces. It samples in interleaved pairs and attaches a confidence, so a noisy 300ms spike does not outrank a rock solid 80ms one. It pushes the top two parameters together to catch interaction effects. It fires one small bounded burst to find where latency knees under load, normalized against a control so it is measuring the server and not your own client. It probes GraphQL query cost with a read-only fan-out. It notices when a server hands back a catch-all page for every path so it does not report your whole wordlist as "exposed."

Out comes a ranked list of endpoints by measured asymmetry, each tagged with the parameter that hurt and by how much, for you to approve before anything gets flooded. Point it at a target and just look, no flood, with `--recon`. Bring your own path wordlist with `--wordlist`.

---

## What it can actually push

The send path was measured at **25.6 million packets per second** of 54-byte frames on a single desktop (Ryzen 7800X3D, 16 pinned shards, AF_PACKET plus batched `sendmmsg` with the qdisc bypassed). That is past 10GbE line rate. For anything up to and including a 10-gig target the tool is bound by the wire, not by the code.

That number matters because of the acceptance bar this was built against: crash general networking appliances fast in under thirty seconds fast. It does. On a live run the gateway (NETGEAR Nighthawk RS700S and also tested on an ASUS RT-BE96U and a Ubiquiti Cloud Gateway Max) went from answering to fully down in about six seconds, off state exhaustion, on wifi, nowhere near the code's ceiling.

How the number was reached, in short. The send path was isolated from everything downstream that could lie about it. On wifi the wire capped at 60K while the generator was doing 759K, and on a veth pair it capped at 3.4M no matter how many threads pushed, so both of those were the delivery medium, not the sender. Only when the frames went at a discard interface that nothing downstream could bottleneck did the real ceiling show up at 25.6M, and every figure was read off the NIC's own `tx_packets` counter rather than what the tool believed it sent. That divergence between generated and wire counts is exactly how a medium wall gives itself away. The formal writeup, with the controls, the instrumentation, and the threats to validity, is in [docs/PERFORMANCE.md](docs/PERFORMANCE.md), alongside the full harness breakdown and every ceiling on the way.

---

## Install

```bash
git clone https://github.com/UnsleptArch/OpenNetBench.git
cd OpenNetBench
./install.sh
```

That builds the release binary and puts `opennetbench` on your PATH. It will also add `~/.local/bin` to your shell profile if it is not already there, so a fresh shell just works.

```bash
./install.sh --system    # machine-wide, /usr/local/bin, uses sudo
./install.sh --xdp       # build the AF_XDP backend too (needs a capable NIC)
./install.sh --uninstall # remove it
```

You need the Rust toolchain (https://rustup.rs). Raw-socket vectors (`syn_flood`, `ack_flood`, `icmp_flood`) need `sudo` at run time.

Just want the binary, no PATH surgery:

```bash
cargo build --release   # ./target/release/opennetbench
```

---

## Quick start

```bash
# interactive, walks you through target, vectors, tuning, timing
opennetbench

# see what ships
opennetbench --list-presets

# let it probe the target, characterize it, recommend a combo, then run
opennetbench --auto --target example.com --duration 60

# one preset, one shot
opennetbench --preset web --target https://example.com --duration 60

# home router / gateway state exhaustion, raw sockets so sudo
sudo opennetbench --preset router --target 192.168.1.254 --duration 40

# build an editable plan without firing it, run it later
opennetbench --preset api --target https://api.example.com --save-config api.json
opennetbench --config api.json

# recon only, find and rank the weak endpoints, send no flood
opennetbench --recon https://example.com

# fully scripted, no prompts at all (--i-am-authorized asserts you are cleared to test it)
opennetbench --target https://example.com --vectors http_flood,slowloris \
  --duration 60 --i-am-authorized

# route the L7 traffic through a proxy (raw L4/UDP still leaves this host)
opennetbench --preset web --target https://example.com --proxy socks5://127.0.0.1:9050
```

Every interactive choice has a flag, so the whole thing scripts cleanly. `--list-vectors` prints the slugs, `--i-am-authorized` skips the typed consent phrase for unattended runs.

Targets are a URL or a bare IP. Bare IPs default to `http://` because router and admin UIs are usually plaintext and the L4 vectors just want `address:port`. Hostnames default to `https://`.

Full flag and preset reference lives in [docs/USAGE.md](docs/USAGE.md).

---

## The vectors

| Vector | Layer | What it does |
|---|---|---|
| `http_flood` / `https_only` | L7 | keep-alive HTTP/1.1 flood, rotating browser fingerprints |
| `range_flood` | L7 | CVE-2011-3192, a pile of overlapping `Range` headers |
| `slowloris` | L7 | incomplete headers held open, drains the connection pool |
| `rudy` | L7 | slow POST body, one byte at a time, ties up workers |
| `slow_read` | L7 | tiny receive window, pins the server's send buffer |
| `h2_flood` | L7 | multiplexed HTTP/2 request flood |
| `h2_rapid_reset` | L7 | CVE-2023-44487, open a stream and immediately reset it |
| `h2_continuation` | L7 | CVE-2024-27316, endless CONTINUATION frames with no end |
| `tls_exhaust` | L4/5 | repeat full TLS handshakes, cheap for you and expensive for them |
| `tcp_exhaust` | L4 | hold bare connections, exhaust the accept backlog / conn table |
| `syn_flood` | L4 | raw TCP SYN flood, real source IP (root) |
| `ack_flood` | L4 | raw ACK flood, beats on stateful firewalls and conntrack (root) |
| `udp_flood` | L4 | UDP flood, payload you pick |
| `dns_flood` | L7 | random-subdomain query flood |
| `icmp_flood` | L3 | ICMP echo flood (root) |
| `cache_bust` | L7 | HTTP flood with a unique query per request, skips the CDN and hits the origin |
| `header_flood` | L7 | huge, numerous request headers, cheap to send and costly to parse |
| `websocket` | L7 | real WebSocket handshakes held open, saturates the server's session capacity |
| `quic_flood` | L4/5 | churns QUIC/HTTP-3 handshakes over UDP, asymmetric TLS 1.3 crypto on the server |

Deeper notes on each one, and why it hurts, are in [docs/VECTORS.md](docs/VECTORS.md).

---

## How it decides "it broke"

An independent health probe TCP-connects to the target once a second the whole run, with a baseline taken before load starts. A second probe fires a real HTTP GET once a second when the app answered at baseline. The classifier reads both, plus the collapse curve (windowed p50/p95/p99 against load) and the HTTP status mix, and returns one of:

- **MitigationEngaged** — 429s from a rate limiter, or 403s with a WAF/CDN fingerprint. The defense is doing its job. Not a finding.
- **Degrading / Down** — p99 blows past baseline, or the probe stops answering. A real resource-exhaustion finding.
- **EdgeBlocked** — fast refusals, no application response.
- **Healthy** — the target ate it and kept going.

Confidence is capped at 0.9. It reports likelihood, never proof. It also knows the difference between the target dying and your own box running out of sockets, which is the mistake that makes most homegrown flooders lie to you.

---

## Safety model

Everything leaves one host, or a proxy if you point one at it. The optional SOCKS5 proxy routes the L7 and TCP vectors; the raw L4 and UDP vectors always send from this machine's real address, so a proxy is not a cloak and the tool does not pretend otherwise. There is no agent protocol, no peer discovery, no remote control anywhere in the tree. Every interactive run starts with a consent gate you type an exact phrase into at a real terminal; unattended runs assert authorization explicitly with `--i-am-authorized`, which is a choice you are making on the command line, not a silent default. Stop the process, stop the traffic. The full threat model is in [docs/SAFETY.md](docs/SAFETY.md).

---

## Authorized use only

This generates real denial-of-service load. Point it only at infrastructure you own or have written authorization to test. Doing otherwise is a crime under the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), EU Directive 2013/40/EU, and the equivalent law wherever you are. The consent gate is not decoration and it is not legal cover either, that part is on you.

Good-faith authorized testing only. Your own systems, your lab, a CTF, or a client that hired you to hit them. Blah blah blah 

---

## Docs

- [docs/USAGE.md](docs/USAGE.md) — every flag, preset, and config knob
- [docs/VECTORS.md](docs/VECTORS.md) — the twenty vectors in detail
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the engine is built, module by module
- [docs/PERFORMANCE.md](docs/PERFORMANCE.md) — the fast path, the numbers, the benchmarking method
- [docs/SAFETY.md](docs/SAFETY.md) — the threat model, what it deliberately is not, and why

## License

GPLv3. See [LICENSE](LICENSE).
