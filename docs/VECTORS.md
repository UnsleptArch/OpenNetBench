# Vectors — A Technical Catalogue

*The twenty attack vectors, treated one at a time: the mechanism each exploits, the
cost asymmetry that makes it effective from a single origin, its implementation in this
codebase, the target signal it produces, and the defence that neutralises it. This is
the reference an operator consults to choose a vector deliberately, and the reference an
auditor consults to confirm each vector does exactly what it claims and nothing more.*

---

## Table of Contents

1. [Framing: Why These Twenty](#1-framing-why-these-twenty)
2. [The Shared Worker Contract](#2-the-shared-worker-contract)
3. [Taxonomy](#3-taxonomy)
4. [Volumetric Application-Layer Vectors](#4-volumetric-application-layer-vectors)
5. [Slow-Connection Vectors](#5-slow-connection-vectors)
6. [Protocol-Abuse Vectors](#6-protocol-abuse-vectors)
7. [Handshake- and State-Exhaustion Vectors](#7-handshake--and-state-exhaustion-vectors)
8. [Raw L3/L4 Vectors](#8-raw-l3l4-vectors)
9. [The Asymmetry Principle, Quantified](#9-the-asymmetry-principle-quantified)
10. [Selection Guidance](#10-selection-guidance)
11. [Defence and Detection Appendix](#11-defence-and-detection-appendix)

---

## 1. Framing: Why These Twenty

A resilience test is only as honest as its traffic. The conventional load generators —
wrk, JMeter, Locust — model *legitimate* users: they answer the question "what is my
throughput ceiling under polite traffic?" That is a real and useful question, but it is
not the question that takes a service down. Outages are caused by traffic that is
*adversarial by construction*: connections held half-open until a worker pool starves,
streams opened and reset before the server can answer, connection-tracking tables filled
faster than they drain. Every vector in this catalogue models one such pattern, drawn
from a documented denial-of-service technique or a named CVE. None is synthetic filler.

The selection spans the stack from L3 (raw ICMP) to L7 (HTTP semantics), because a
target's weakest layer is not known in advance — a gateway falls to state exhaustion at
L4 while a web application falls to worker starvation at L7, and the same box may present
both surfaces. The catalogue is organised in this document by *what each vector attacks*
rather than by protocol layer, because that is how an operator actually reasons about a
target: "I need to exhaust connection state" is a more useful starting point than "I need
an L4 vector."

Two capabilities are deliberately **absent** from every vector, and their absence is a
design invariant rather than an unfinished feature (see [SAFETY.md](SAFETY.md)):

- **No amplification.** There is no reflection primitive anywhere — no DNS, NTP, or
  memcached reflector. Every byte that reaches the target was generated locally. Outbound
  equals impact, one to one.
- **No spoofing.** Every raw vector sources from this host's real address. There is no
  source-address parameter, and for the stateful TCP vectors spoofing would be
  self-defeating anyway, since the return segment would be delivered to the forged
  address rather than to the generator.

---

## 2. The Shared Worker Contract

Before the individual vectors, the contract they all honour. Every vector is implemented
as a worker (an `async` Tokio task for the L7/L5 vectors; a pinned OS thread for the raw
vectors) that obeys three invariants enforced by the engine, described in full in
[INTERNALS.md](INTERNALS.md) §3–§7:

1. **It gates on its own governor.** A worker generates load only while
   `governor.active(idx)` holds, so per-vector ramp-up and adaptive throttling apply
   independently. A worker whose index rises above the current target parks until it is
   admitted again.
2. **It races the shutdown signal.** Every blocking await — connect, read, write, sleep —
   is wrapped in a `tokio::select!` against the shutdown `watch` channel (or, for raw
   threads, a direct read of the shared flag), so stopping the process stops the traffic
   within the drain grace rather than after a full loop iteration.
3. **It records into its own lock-free `Metrics`.** A distressed vector throttles only on
   its own signal; it can never cause a sibling vector to back off. Recording is O(1) and
   allocation-free on the hot path.

A second cross-cutting property is **zero per-operation heap allocation on the hot path**.
Request templates, partial heads, payloads, and frame prefixes are all serialised *once*
before the loop and shared behind an `Arc<[u8]>`; the loop body formats only into
fixed-size stack buffers where it must mutate at all. This is what lets a single box
sustain thousands of concurrent workers without the allocator becoming the bottleneck.

The distinction between two families of vector recurs throughout and is worth stating
once precisely, because the engine and classifier both depend on it:

- **Feedback vectors** receive a target-derived signal — a completed response, a
  handshake, or a connect success/failure. They can be throttled adaptively and their
  outcomes feed the verdict. This is every vector *except* the connectionless floods.
- **Fire-and-forget vectors** (`udp_flood`, `dns_flood`, `icmp_flood`, `syn_flood`,
  `ack_flood`) receive nothing back by construction. A local `send()` succeeding says
  nothing about the target. They therefore ramp but never *adapt* (adapting on a local
  send count would be a lie), and their send count is recorded as `packets_sent` —
  egress, explicitly not confirmed delivery — and is never reported as target throughput.
  The predicate `Vector::has_load_feedback()` is the single source of truth for this
  partition.

---

## 3. Taxonomy

| # | Vector | Slug | Layer | Root | Feedback | HTTP status | CVE / technique |
|---|---|---|---|:---:|:---:|:---:|---|
| 1 | HTTP flood | `http_flood` | L7 | — | ✓ | ✓ | keep-alive request flood |
| 2 | HTTPS-only | `https_only` | L7 | — | ✓ | ✓ | TLS-forced request flood |
| 3 | Range flood | `range_flood` | L7 | — | ✓ | ✓ | CVE-2011-3192 |
| 4 | Cache-bust | `cache_bust` | L7 | — | ✓ | ✓ | cache-key defeat |
| 5 | Header flood | `header_flood` | L7 | — | ✓ | ✓ | parser-CPU amplification |
| 6 | HTTP/2 flood | `h2_flood` | L7 | — | ✓ | ✓ | multiplexed request flood |
| 7 | DNS flood | `dns_flood` | L7/UDP | — | — | — | random-subdomain query flood |
| 8 | Slowloris | `slowloris` | L7 | — | ✓ | — | incomplete-header hold |
| 9 | RUDY | `rudy` | L7 | — | ✓ | — | slow POST body |
| 10 | Slow read | `slow_read` | L7 | — | ✓ | — | tiny receive window |
| 11 | WebSocket | `websocket` | L7 | — | ✓ | — | RFC 6455 session hold |
| 12 | HTTP/2 rapid reset | `h2_rapid_reset` | L7 | — | ✓ | — | CVE-2023-44487 |
| 13 | HTTP/2 continuation | `h2_continuation` | L7 | — | ✓ | — | CVE-2024-27316 |
| 14 | TLS exhaust | `tls_exhaust` | L4/5 | — | ✓ | — | handshake CPU asymmetry |
| 15 | QUIC flood | `quic_flood` | L4/5 | — | ✓ | — | HTTP/3 handshake asymmetry |
| 16 | TCP exhaust | `tcp_exhaust` | L4 | — | ✓ | — | connection-table exhaustion |
| 17 | SYN flood | `syn_flood` | L4 | ✓ | — | — | half-open exhaustion |
| 18 | ACK flood | `ack_flood` | L4 | ✓ | — | — | conntrack/firewall state |
| 19 | ICMP flood | `icmp_flood` | L3 | ✓ | — | — | echo-request volumetric |
| 20 | UDP flood | `udp_flood` | L4 | — | — | — | datagram volumetric |

`Vector::ALL` is the canonical ordering; the slugs are stable public identifiers accepted
by `--vectors` and printed by `--list-vectors`. The "HTTP status" column marks the six
vectors whose workers call `Metrics::record_status` and thereby produce the
application-layer signal the classifier keys on (`records_http_status()`); keeping that
predicate beside the vector list is what stops the classifier's gate from silently
drifting out of sync when a new HTTP vector is added.

---

## 4. Volumetric Application-Layer Vectors

These generate genuine application-layer requests at volume. Their common worker is
`http_flood::worker`; five of the six vectors in this group are that worker driven with a
different request template, which is why they share the `records_http_status` property and
the httparse-based response handling described in [INTERNALS.md](INTERNALS.md) §14.

### 4.1 `http_flood` / `https_only` — the request flood

**Mechanism.** A keep-alive HTTP/1.1 GET loop over a persistent connection. Each response
is parsed with `httparse` (structural parse delegated to a vetted, upstream-fuzzed crate),
the status code is bucketed via `record_status`, and the body is drained but *bounded* —
the worker reads up to the advertised `Content-Length` and no further, so a server that
returns a large body cannot turn the generator's own read into the bottleneck.

**Implementation notes.** The worker honours the response's keep-alive disposition: a
clean server-side `Connection: close` is treated as a clean reconnect, *not* as an error.
This matters against servers such as Python's `http.server` that close every response by
default — without this, every request would register as a spurious failure and poison both
the error rate and the adaptive governor. Requests rotate through several realistic browser
fingerprints (User-Agent and header ordering), serialised once as templates in `net.rs` so
the loop never formats a string. `https_only` is the identical worker constrained to TLS,
for targets or test scenarios where the plaintext path must not be exercised.

**Target signal.** Latency to response completion (feeds the collapse curve) and the full
HTTP status distribution. This is the bread-and-butter vector and the one whose signal the
classifier can reason about most richly.

**Default scale.** 50 concurrent workers (`VectorTuning::defaults_for`); presets raise this
to `PRESET_CONCURRENCY` = 2700.

### 4.2 `range_flood` — CVE-2011-3192

**Mechanism.** The classic Apache byte-range amplification. A single request carries a
`Range` header enumerating a large pile of *overlapping* byte ranges. A naïve server
attempts to assemble a multipart response holding every requested segment simultaneously,
and because the ranges overlap, the memory it commits is wildly disproportionate to the
request size — the asymmetry the CVE weaponises.

**Implementation notes.** Reuses `http_flood::worker` with a purpose-built request
template; no separate worker is needed because the only difference from a plain flood is
the request bytes.

**Target signal.** HTTP status distribution and latency; a server buckling under range
assembly typically manifests as rising latency then 5xx.

### 4.3 `cache_bust` — origin isolation

**Mechanism.** An endpoint fronted by a CDN or reverse-proxy cache answers a plain flood
"for free" out of cache; the origin never feels the load, and a naïve flood would measure
*cache* performance rather than *origin* resilience. `cache_bust` splices a unique
`?_cb=<id>` query parameter into every request, so each request presents a distinct cache
key, misses the cache, and lands on the origin.

**Implementation notes.** The splice touches only the request line and allocates nothing in
the loop; the splicing function (`cache_bust_into`) is one of the fuzzed pure functions
(see [FUZZING.md](FUZZING.md)), because it slices arbitrary template bytes and a bounds
error there would be a crash on a hot path.

**Target signal.** HTTP status and latency, but interpreted as *origin* behaviour. The
operational purpose is precisely to make the origin, not the edge, the thing under test.

### 4.4 `header_flood` — parser-CPU amplification

**Mechanism.** The same GET, but carrying pathologically large and numerous request
headers: a large `Cookie`, a stack of duplicate `X-Forwarded-For`, an exploded
`Accept-Language`, and a wall of custom headers. This is cheap for the client to emit but
forces the server to parse, allocate for, and often validate a large header set on *every*
request. The pressure lands on parser CPU — a different resource axis than body size or
connection count.

**Implementation notes.** The header set is deliberately sized to stay *under* the usual
8–16 KB header limit, so a normal server parses it rather than fast-rejecting with a 431
Request Header Fields Too Large. A vector that trips the fast-reject path would measure the
limit, not the parser; staying under it is what keeps the amplification real.

**Target signal.** HTTP status and latency, with the expectation that CPU-bound servers
show latency degradation before any status change.

### 4.5 `h2_flood` — the HTTP/2 request flood

**Mechanism.** The modern equivalent of the plain request flood, for HTTP/2 servers. Many
streams are opened on a single multiplexed h2 connection; each request is *completed* —
the response headers awaited, the body drained — and its latency recorded. It stresses the
full request path (routing, handlers) over HTTP/2's cheap stream multiplexing, so a single
connection can carry far more concurrent request pressure than HTTP/1.1.

**Implementation notes.** Built on the `h2` crate; requires TLS with ALPN `h2`. Because it
completes streams (unlike `h2_rapid_reset`, §6.1), it produces genuine latency-to-headers
samples for the collapse curve and reports real status codes.

**Target signal.** Latency to response headers and the HTTP status distribution.

### 4.6 `dns_flood` — random-subdomain query flood

**Mechanism.** A flood of A-record queries for *random* subdomains of the target domain.
Random labels defeat resolver and cache deduplication, so every query is forced down the
full recursive or authoritative resolution path rather than being answered from cache. It
is classed L7 because it is application-layer DNS, though it rides UDP.

**Implementation notes.** Queries are wire-encoded by hand into a reused stack buffer (no
heap in the loop); the random labels come from a per-worker `xorshift` PRNG (allocation-free
and fast). The wire encoder (`dns_encode_query`) is fuzzed. Because it is UDP and
connectionless, `dns_flood` is a **fire-and-forget** vector: it advances `packets_sent`,
not `responses_ok`, and does not adapt.

**Target signal.** None direct — the health probe (a TCP connect to the resolver, if it
listens on TCP) is the only availability signal for a pure DNS run.

---

## 5. Slow-Connection Vectors

These do not need volume; they need *patience*. A handful of connections held wrong will
starve a worker or connection pool that would laugh at a request flood. Their shared signal
is `held_connections` (maintained by the RAII `HeldGuard`, see [INTERNALS.md](INTERNALS.md)
§4.4) and the connect-failure rate — **not** latency, because a starved server does not
answer slowly, it does not answer at all. Their default scale is small on purpose (200
connections, 100 for RUDY): the whole point is that a small hold does outsized damage.

### 5.1 `slowloris` — incomplete-header hold

**Mechanism.** Open a connection, send a partial HTTP request that is *never terminated*
(no blank line ending the header block), then trickle one additional header line every
`trickle_interval` to keep the server's parser waiting and the connection slot occupied.
Every held connection is one the server cannot give to a legitimate user. This is the
canonical worker-pool starvation attack.

**Implementation notes.** The partial head is pre-built and shared as `Arc<[u8]>` (no
per-connection allocation); each trickle line is formatted into a 64-byte stack buffer
(`LINE_CAP = 64`), so the trickle loop never touches the heap. The default trickle interval
is 10 s — slow enough to minimise the generator's own effort, fast enough to stay inside
typical server idle timeouts.

**Target signal.** `held_connections` and connect-failure rate. A server whose pool is
exhausted still completes TCP handshakes at baseline but stops accepting *new* application
connections — which is exactly the condition the independent service probe (§ below and
[INTERNALS.md](INTERNALS.md) §10) is designed to catch, since a bare TCP connect probe
alone would read the server as healthy.

### 5.2 `rudy` — R-U-Dead-Yet, the slow POST

**Mechanism.** Send a *complete, legitimate* POST header advertising a large
`Content-Length`, then trickle the request body one byte at a time and never finish it. The
server holds a worker or thread blocked, waiting for a body that never fully arrives. Where
slowloris withholds the end of the *headers*, RUDY withholds the end of the *body* — same
starvation, a different phase of the request.

**Implementation notes.** The POST head is pre-built and shared; the advertised body length
is `payload_bytes`, default 1,000,000. Default concurrency is 100 (lower than slowloris,
because each RUDY connection is even cheaper to hold and more reliably pins a worker). The
trickle cadence is the same `trickle_interval` knob.

**Target signal.** `held_connections` and connect-failure rate, identical in shape to
slowloris.

### 5.3 `slow_read` — the tiny receive window

**Mechanism.** The mirror image of slowloris. Send a *normal, complete* request, but read
the response one byte at a time from a socket configured with a deliberately tiny OS receive
buffer. The client's advertised TCP window stays near zero, so the server cannot flush its
response and is forced to hold the response — and the connection — in its own send buffer.
The server's memory and connection slot are pinned by the client's refusal to *read*, not
its refusal to *send*.

**Implementation notes.** The receive buffer is set to `RCVBUF = 256` bytes via
`setsockopt(SO_RCVBUF)`. The kernel doubles this for bookkeeping, but it remains small
enough that the TCP window advertised back to the server stays tiny, which is the mechanism.
The response is drained at `trickle_interval` cadence.

**Target signal.** `held_connections`. Particularly effective against servers that buffer
whole responses in memory before streaming.

### 5.4 `websocket` — RFC 6455 session hold

**Mechanism.** Complete a *real* WebSocket upgrade handshake, then hold the session open and
trickle small masked keepalive frames to keep it alive. A live WebSocket session is heavier
than a bare TCP connection: the server keeps a session object, per-connection read and write
buffers, and usually a dedicated task or goroutine per socket. Those pools are frequently
smaller and less defended than the HTTP connection pool, so a few hundred held sessions
saturate WebSocket capacity the way slowloris starves an HTTP worker pool. The keepalive
frames additionally exercise the server's per-frame parse path.

**Implementation notes.** Hand-rolled, no library. The handshake is a single GET carrying
the Upgrade headers (built in `net.rs`); the worker checks for `101 Switching Protocols` and
deliberately does **not** validate `Sec-WebSocket-Accept` — it is generating load, not acting
as a conformant client. Client frames are masked per the spec (the spec requires masking; it
does not require the mask to be unpredictable, so a fixed mask is used). The keepalive frame
is a minimal masked ping: `0x89` (FIN | ping), `0x80` (MASK | length 0), then a 4-byte
masking key. Point it at the WebSocket path (`ws` over `http://`, `wss` over `https://`).

**Target signal.** `held_connections`, interpreted as WebSocket session occupancy.

---

## 6. Protocol-Abuse Vectors

The named HTTP/2 CVEs. These are cheap for the client and brutal for the server *by design*
— the asymmetry is the entire mechanism, not a side effect of volume.

### 6.1 `h2_rapid_reset` — CVE-2023-44487

**Mechanism.** Over a single h2 connection, open a stream (send HEADERS), then immediately
reset it (send RST_STREAM), as fast as the peer will grant stream capacity. The server
performs the full setup work for a request — stream allocation, header decode, often routing
and handler dispatch — for a request it never gets to answer, then tears it all down. The
client's cost is a few frames; the server's cost is a whole request lifecycle. This is the
vector that knocked over a large fraction of the internet in 2023.

**Implementation notes.** Built on the `h2` crate, which exposes stream open and reset as
first-class operations; requires TLS with ALPN `h2`. It does not complete requests, so —
unlike `h2_flood` — it produces no latency-to-headers samples and reports no status codes;
its signal is the connect/stream success rate and the health/service probes.

**Target signal.** Stream-grant success rate and the independent probes. A patched server
caps the rate of resets per connection (the mitigation the CVE prompted) and this vector
will read as mitigated against it.

### 6.2 `h2_continuation` — CVE-2024-27316

**Mechanism.** Open a stream with a HEADERS frame that *omits* the END_HEADERS flag, then
send an endless run of CONTINUATION frames, each also without END_HEADERS. The header block
never terminates, so a vulnerable server appends to its per-request header buffer without
bound — memory and CPU exhaustion — and frequently the incomplete stream never counts against
the server's concurrent-stream limit, so the usual concurrency defence does not engage.

**Implementation notes.** This vector *cannot* be built on the `h2` crate — a conformant h2
client API will not emit a never-ending, never-terminated header block — so it speaks HTTP/2
on the wire directly. The frame builder `put_frame` writes the 9-byte HTTP/2 frame header
(24-bit length, 8-bit type, 8-bit flags, 32-bit stream id) followed by the payload; the
frame-type constants are `FT_SETTINGS = 0x4`, `FT_HEADERS = 0x1`, `FT_CONTINUATION = 0x9`.
The worker performs the connection preface and SETTINGS exchange, then the malformed HEADERS
and the unbounded CONTINUATION stream.

**Target signal.** The independent probes; a server whose header buffer is growing without
bound degrades globally, which the health and service probes observe.

---

## 7. Handshake- and State-Exhaustion Vectors

These attack the machinery that *fronts* the application — the TLS and QUIC handshake, the
TCP connection table — rather than the application logic itself. Their common theme is that
establishing state is cheap for the client and expensive for the server.

### 7.1 `tls_exhaust` — handshake CPU asymmetry

**Mechanism.** Complete a full TLS handshake, then immediately drop it, repeatedly. A TLS
handshake costs the server real asymmetric-cryptography CPU (key exchange, certificate
signature) for very little client effort — the client picks parameters and verifies almost
nothing; the server does the expensive private-key operation. The measured latency here *is*
the handshake time, which is exactly the server cost the vector exists to surface.

**Implementation notes.** Built on `tokio-rustls`. Each iteration establishes a fresh
connection and handshake (no session resumption, which would defeat the purpose by letting
the server skip the expensive path) and records the handshake duration as the latency sample.

**Target signal.** Handshake latency (feeds the collapse curve) and connect success rate.

### 7.2 `quic_flood` — HTTP/3 handshake asymmetry

**Mechanism.** The same handshake-exhaustion idea moved onto QUIC. It churns full QUIC
connections over UDP — open, complete the TLS 1.3 handshake, close, repeat — so the server
keeps paying the asymmetric crypto plus the per-attempt connection state that fronts every
HTTP/3 stack. It is the UDP-path analogue of `tls_exhaust`.

**Implementation notes.** Built on `quinn`; there is no sane way to hand-roll QUIC's
Initial-packet crypto and header protection correctly, so a library is mandatory here in a
way it is not for the hand-rolled vectors. ALPN is `h3`, targeting HTTP/3 endpoints. The
server certificate is deliberately **not** validated (a permissive verifier lets the
handshake complete against any certificate) because the vector generates load against an
authorised target rather than authenticating a peer.

**Caveat.** This vector only bites if the target actually speaks QUIC on the UDP port
(usually 443/udp). Many origins expose HTTP/3 only at the CDN edge, so aim it where h3 is
genuinely terminated, or it will simply fail to establish and read as the target refusing.

**Target signal.** Handshake completion rate and the health probe.

### 7.3 `tcp_exhaust` — connection-table exhaustion

**Mechanism.** Open a bare TCP connection and hold it open, occupying an entry in the
server's accept backlog and connection table, then park on a read so the connection stays
open until the server drops it (read returns 0) or shutdown fires. No application bytes are
ever sent — this stresses connection *state*, not bandwidth.

**Implementation notes.** The simplest of the hold vectors: connect, `HeldGuard`, park on a
read that races the shutdown signal. Crucially it needs **no root** — it is the no-privilege
way to exhaust state, and it is the vector that reliably kills home routers even without raw
sockets, because a consumer gateway's connection table is small and undefended.

**Target signal.** `held_connections` and connect-failure rate. When the table fills, new
connects begin to fail — including, tellingly, the health probe's own connects, which is how
a pure `tcp_exhaust` run produces a `Down` verdict.

---

## 8. Raw L3/L4 Vectors

These build their own frames and transmit through a raw socket, so they require root
(`CAP_NET_RAW`). Source IP and MAC are the host's real ones; there is no spoofing knob. Three
of the four (`syn_flood`, `ack_flood`, `icmp_flood`) require root; `udp_flood` uses an
ordinary datagram socket and does not. The transmit path for the SYN/ACK vectors selects the
fastest available backend at startup — AF_XDP, then batched AF_PACKET, then a kernel L4
fallback — described in full in [PERFORMANCE.md](PERFORMANCE.md) and
[INTERNALS.md](INTERNALS.md) §8. All four are **fire-and-forget**: they advance
`packets_sent`, not `responses_ok`, and never adapt.

### 8.1 `syn_flood` — half-open exhaustion

**Mechanism.** Emit bare TCP SYN segments to the target port, bypassing the kernel's own
connection tracking, so each SYN forces the target to allocate half-open connection state
(a SYN-ACK sent, a slot in the SYN backlog awaiting the final ACK that never comes). Enough
SYNs faster than the backlog drains and the listener stops accepting legitimate connections.

**Implementation notes.** Delegates to the shared raw sender `raw::tcp_flag_flood` with
`TcpFlags::SYN`. The source IP is this host's *real* address — no spoofing, which is both a
safety-model invariant and a functional requirement (a spoofed SYN's SYN-ACK would go to the
forged address, so the vector would generate no useful state pressure on a target that
validates). It carries a `queue_rank` / `queue_groups` pair so that when it runs alongside
`ack_flood`, the two take disjoint slices of the NIC's transmit queues rather than colliding.

**Target signal.** The health probe only (connectionless). A gateway or host whose SYN
backlog is exhausted refuses the probe's connects.

### 8.2 `ack_flood` — conntrack and firewall state

**Mechanism.** Emit bare ACK segments with random sequence and acknowledgement numbers that
match no existing connection. A stateful firewall or a Linux `conntrack` table must look up
each ACK to decide what to do with a segment for a connection it has no record of, so the
pressure lands on connection-state tables and per-packet lookup CPU rather than on bandwidth.
This is precisely the state-exhaustion angle at which single-origin testing is genuinely
effective — it does not take a botnet's bandwidth to overflow a consumer firewall's state
table.

**Implementation notes.** Delegates to `raw::tcp_flag_flood` with `TcpFlags::ACK` and random
sequence/ack numbers. Same real-source-address and queue-partitioning properties as
`syn_flood`.

**Target signal.** The health probe. A firewall whose state table is saturated begins
dropping or delaying legitimate traffic, which the probe observes as connect failure or
latency rise.

### 8.3 `icmp_flood` — L3 volumetric

**Mechanism.** Emit ICMP echo requests (pings) to the target from this host's real source
address — the simplest volumetric L3 primitive, useful for raw bandwidth saturation against
a target that answers or processes ICMP.

**Implementation notes.** This vector illustrates the *leader/thread-pool* pattern that the
raw vectors use to avoid a subtle starvation bug. Worker index 0 is the **leader** and owns
the entire send path; every other logical worker no-ops. The leader spawns a small pool of
plain OS threads (one per CPU), each with its own raw channel. The reason is that a large
`concurrency` mapped one-worker-per-blocking-thread would pin Tokio's bounded blocking-thread
pool (default ~512), starving every other `spawn_blocking` user — the other raw leaders, the
stop-on-detect prompt — and silently dropping any workers past the cap. The payload is the
classic 56-byte ping payload (`PAYLOAD_LEN = 56`). The ICMP checksum is computed per packet.

**Target signal.** The health probe.

### 8.4 `udp_flood` — datagram volumetric

**Mechanism.** Send a pre-built UDP datagram to the target as fast as the governor and the
optional per-worker rate allow. General-purpose volumetric pressure with an operator-chosen
payload.

**Implementation notes.** No root required — it uses an ordinary `UdpSocket`. The payload is
built once and shared; the socket is `connect()`-ed to the destination so each send is a
single syscall with no per-packet address handling. The source is this host's real address —
no spoofing. Default concurrency is 8 with a 1024-byte payload; the payload size is the
`payload_bytes` knob, and `rate_per_worker` bounds each worker's send rate if set.

**Target signal.** None direct (fire-and-forget); the health probe is the only availability
signal.

---

## 9. The Asymmetry Principle, Quantified

Every vector in this catalogue is an instance of a single strategic principle: a single
origin cannot win a resource race against a well-provisioned target by *symmetric* effort,
so it must find or manufacture an *asymmetry* — a place where one unit of client work forces
many units of server work. The vectors realise this asymmetry along different axes:

| Axis | Client cost | Server cost | Vectors |
|---|---|---|---|
| **Compute** | craft one request | expensive computation | `tls_exhaust`, `quic_flood`, `range_flood`, `header_flood`, `h2_rapid_reset` |
| **Memory** | trickle bytes | pinned buffers | `slowloris`, `rudy`, `slow_read`, `h2_continuation`, `range_flood` |
| **Connection state** | hold a socket | table entry + task | `tcp_exhaust`, `websocket`, `syn_flood` |
| **Lookup state** | send a segment | conntrack/firewall entry | `ack_flood` |
| **Resolution work** | one query | full recursive walk | `dns_flood` |
| **Bandwidth** | send bytes | receive bytes | `udp_flood`, `icmp_flood` |

The compute, memory, and state axes are the ones where a single box is *genuinely*
dangerous, because the server's cost exceeds the client's by orders of magnitude. The pure
bandwidth axis (`udp_flood`, `icmp_flood`) is the one where a single origin is *weakest*,
because the ratio is roughly one-to-one and the generator's uplink is the ceiling — those
vectors are included for completeness and for targets whose bandwidth budget is genuinely
smaller than the generator's, not because a single box out-floods a datacentre.

This is the same asymmetry the reconnaissance engine hunts for at L7 before any flood is
launched: `recon::score` ranks endpoints precisely by measured server-cost-over-client-cost
(see [INTERNALS.md](INTERNALS.md) §13). The vectors *exploit* asymmetry; recon *finds* it.

---

## 10. Selection Guidance

The presets encode the common cases; each is a curated combination validated against a
target class (see [USAGE.md](USAGE.md) for the full preset table).

- **Home router or gateway** → `router` (`syn_flood` + `ack_flood` + `tcp_exhaust`). State
  and connection-table exhaustion kill consumer gateways in seconds. Use `router-lite`
  (`tcp_exhaust` alone) when running without root.
- **Web application** → `web` (`http_flood` + `slowloris` + `rudy` + `range_flood`). Mixes a
  request flood with slow-connection holds; most application servers fall to one or the
  other, so running both finds whichever is weaker.
- **HTTP/2 API** → `api` (`h2_flood` + `h2_rapid_reset` + `rudy`). Rapid-reset is devastating
  against an unpatched h2 stack; the flood and slow POST cover the patched case.
- **Behind a CDN or WAF** → `cdn` (`tls_exhaust` + `h2_rapid_reset` + `http_flood`). Handshake
  exhaustion and rapid-reset can reach the origin even when volumetric traffic is absorbed at
  the edge; `cache_bust` is the manual addition when the origin must be isolated behind a
  cache.
- **DNS server** → `dns` (`dns_flood` + `udp_flood`).

When the target class is unknown, `--auto --target <thing>` fingerprints the target (TCP
port scan, HTTP/HTTPS fingerprint, WAF and embedded-server detection), classifies it, and
recommends a preset with human-readable reasoning before dropping into the normal consent
and confirmation path. It never fires on its own.

A note on mixing: because each vector has its own governor and its own metrics, a mixed run
is genuinely concurrent and independently paced — a slowloris hold and an HTTP flood in the
same run do not interfere with each other's throttling, and the classifier sees the union of
their signals. The only cross-vector coordination is the fd budget (§[INTERNALS.md] §5) and
the NIC transmit-queue partition for the raw vectors.

---

## 11. Defence and Detection Appendix

For each vector, the defence that neutralises it — useful both to the blue-team reader
interpreting a finding and to confirm that a "mitigated" verdict corresponds to a real,
nameable control.

| Vector | Primary mitigation | How a run reads when mitigated |
|---|---|---|
| `http_flood` / `https_only` | rate limiting (429), request-rate WAF rules | `MitigationEngaged` on 429s |
| `range_flood` | patched range handling; range-count caps | stable latency, 4xx on the malformed range |
| `cache_bust` | origin rate limiting; per-IP query-string caps | `MitigationEngaged` or stable origin |
| `header_flood` | header-size and header-count limits (431) | fast 431s, stable latency |
| `h2_flood` | h2 concurrency limits, per-connection request caps | stable latency under load |
| `dns_flood` | response-rate limiting, cache tuning, anycast | stable resolution latency |
| `slowloris` | request-header timeout, min-data-rate (e.g. `mod_reqtimeout`) | connects keep succeeding |
| `rudy` | request-body timeout, min-data-rate | connects keep succeeding |
| `slow_read` | response send timeout, min-read-rate | server closes slow readers |
| `websocket` | per-IP session caps, idle timeouts | new upgrades refused, existing dropped |
| `h2_rapid_reset` | reset-rate accounting per connection (the CVE patch) | stream grants throttled |
| `h2_continuation` | CONTINUATION-frame count/size limit (the CVE patch) | connection closed on the malformed block |
| `tls_exhaust` | handshake rate limiting, TLS offload, session resumption caps | handshake latency stable |
| `quic_flood` | QUIC retry / address validation, handshake rate limits | handshakes throttled |
| `tcp_exhaust` | connection limits per IP, larger tables, SYN cookies | connects keep succeeding |
| `syn_flood` | SYN cookies, backlog tuning | probe connects keep succeeding |
| `ack_flood` | conntrack sizing, stateless ACK handling at the edge | probe latency stable |
| `icmp_flood` | ICMP rate limiting, edge filtering | probe unaffected |
| `udp_flood` | ingress rate limiting, unused-port drop | probe unaffected |

The classifier's job is to distinguish the middle column from a genuine finding — to report
`MitigationEngaged` when a defence is doing exactly what it should, and `Degrading`/`Down`
only when a resource is genuinely exhausted. That distinction, and the confidence attached to
it, is documented in [INTERNALS.md](INTERNALS.md) §10–§12. A vector catalogue is only half of
an honest tool; the other half is refusing to call a working rate limiter a vulnerability.
