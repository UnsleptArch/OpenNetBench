# Vectors

Twenty of them, L3 up to L7. Each one models a real denial-of-service pattern, not synthetic filler. Grouped here by what they attack rather than by layer, because that is how you actually pick them.

Every vector shares the same skeleton. It gates on its own governor so ramp-up and adaptive throttle work per vector, it races a shutdown watch so stopping the process stops the traffic within the drain grace, and it records into its own lock-free metrics so one distressed vector never throttles a healthy one.

## Volumetric, L7

**http_flood** and **https_only.** Keep-alive HTTP/1.1 GET loop, zero allocation in the hot path, parsed with httparse, body drained but bounded. It honors the response keep-alive so a clean server-side close is a clean reconnect and not a fake error, which matters against things like Python's `http.server` that close every response. This is the bread-and-butter request flood.

**range_flood.** CVE-2011-3192, the old Apache byte-range trick. Sends a request carrying a big pile of overlapping `Range` headers so the server tries to buffer a huge number of overlapping segments and blows up its own memory. Reuses the http_flood worker with a different request template.

**cache_bust.** The http_flood worker with a unique `?_cb=<id>` query spliced into every request. A cached endpoint behind a CDN or reverse proxy answers a plain flood for free out of cache and the origin never feels it. A distinct URL per request misses the cache key every time, so the load actually lands on the origin. This is how you measure origin resilience instead of cache performance. The splice touches only the request line and allocates nothing in the loop.

**header_flood.** Same GET, pathological headers. A big Cookie, a stack of duplicate `X-Forwarded-For`, an exploded `Accept-Language`, and a wall of custom headers. Cheap for us to send, but the server has to parse, allocate and often validate a large header set on every single request. That is parser CPU, a different axis than body or connection floods. Sized to stay under the usual 8 to 16KB header limits so a normal server parses it instead of fast-rejecting with a 431.

**h2_flood.** Full multiplexed HTTP/2. Real requests over a real h2 connection, completed and drained, latency recorded. This is the modern equivalent of the plain request flood for HTTP/2 servers.

**dns_flood.** Random-subdomain A queries, hand-encoded straight onto the wire. Random subdomains defeat caching so every query walks the full resolver path. Listed as L7 because it is application-layer DNS, it just rides UDP.

## Slow connection, L7

These do not need volume. They need patience. A handful of connections held wrong will starve a worker pool that laughs at a request flood.

**slowloris.** Opens connections, sends partial headers, never finishes them, trickles just enough to keep them alive. Every held connection is one the server cannot give to a real user. Classic pool starvation.

**rudy.** R-U-Dead-Yet. Sends a complete, legitimate POST header advertising a content length, then trickles the body one tiny piece at a time forever. The server holds a worker waiting for a body that never fully arrives.

**slow_read.** The mirror image of slowloris. Sends a normal request but advertises a tiny receive window and drains the response a byte per tick, so the server's send buffer stays pinned and it cannot free the connection.

**websocket.** Completes a real RFC 6455 upgrade handshake, then holds the session open and trickles small masked keepalive frames. A live WebSocket is heavier than a bare TCP connection: the server keeps a session object, per-connection read and write buffers, and usually a dedicated task or goroutine per socket, and those pools are often smaller and less defended than the HTTP one. A few hundred held sessions saturate WS capacity the way slowloris starves an HTTP worker pool. Hand-rolled, no library: it sends the Upgrade GET, checks for a 101, and does not bother validating the accept because it is generating load, not acting as a client. Point it at the WebSocket path (`ws` over `http://`, `wss` over `https://`).

## Protocol abuse, L7

The named-CVE HTTP/2 attacks. These are cheap for the client and brutal for the server by design, that asymmetry is the whole point.

**h2_rapid_reset.** CVE-2023-44487, the one that knocked over a chunk of the internet in 2023. Open a stream, send the request, immediately send RST_STREAM. The server does all the setup work for a request it never gets to answer, and you can do it as fast as you can write frames.

**h2_continuation.** CVE-2024-27316. Sends a HEADERS frame without END_HEADERS and then an endless run of CONTINUATION frames, so the server keeps buffering header data waiting for an end that never comes. This one is raw HTTP/2 framing by hand because the `h2` crate will not let you build a headerless CONTINUATION stream.

## State and handshake exhaustion, L4/5

**tls_exhaust.** Repeated full TLS handshakes. A handshake is cheap for you to start and expensive for the server to complete, all that asymmetric crypto is on their side. Latency here is literally the server's handshake cost.

**quic_flood.** The same handshake-exhaustion idea, moved onto QUIC. It churns full QUIC connections over UDP: open, complete the TLS 1.3 handshake, drop, repeat, so the server keeps paying the asymmetric crypto and per-attempt connection state that fronts every HTTP/3 stack. Built on quinn because QUIC's Initial-packet crypto and header protection are not something you hand-roll correctly. ALPN is `h3` so it targets HTTP/3 endpoints, and it does not validate the server cert because it is generating load, not authenticating. One caveat worth knowing: it only bites if the target actually speaks QUIC on the UDP port, and a lot of origins only expose HTTP/3 at the CDN edge, so aim it where h3 is really terminated.

**tcp_exhaust.** Holds bare TCP connections open, no application traffic, just occupancy. Fills the accept backlog and the connection table. This is the no-root way to exhaust state, and it is what kills home routers even without raw sockets.

## Raw, L3/L4, root only

These build frames themselves and go out through a raw socket, so they need `sudo`. Source IP and MAC are the host's real ones, there is no spoofing knob, and the transmit path picks the fastest backend available at startup (see [PERFORMANCE.md](PERFORMANCE.md)).

**syn_flood.** Raw TCP SYN flood. Classic half-open exhaustion, real source address.

**ack_flood.** Raw ACK flood. Aimed at stateful firewalls and conntrack tables, a flood of ACKs for connections that do not exist makes the firewall burn state deciding what to do with each one.

**icmp_flood.** ICMP echo flood. The simplest volumetric L3 primitive, useful for raw bandwidth saturation against a target that answers ping.

## Which to reach for

- Home router or gateway: `router` preset, so syn + ack + tcp_exhaust. State exhaustion kills these fast.
- Web app: `web` preset. Mix a request flood with slow-connection holds, most app servers fall to one or the other.
- HTTP/2 API: `api` preset. Rapid reset and continuation are devastating against unpatched h2 stacks.
- Behind a CDN or WAF: `cdn` preset. Handshake exhaustion and rapid reset can reach the origin even when volumetric traffic gets absorbed at the edge.
- DNS server: `dns` preset.

Or just run `--auto --target <thing>` and let it fingerprint the target and pick for you.
