# benchmarking

Harnesses for checking the engine's **throughput** and — just as important — the
**honesty** of the numbers it reports. The engine's job is to produce a
trustworthy collapse curve and verdict; a fast-but-lying engine is worse than a
slow one.

## Why this exists

A real router run once reported **4–16 million "requests/sec" with an 80% error
rate and a DOWN verdict** while the router was fine. The RPS counter was tallying
failed connection churn, and the health probe was failing on *our own* exhausted
sockets, not the target. The fixes:

- RPS is now derived from **completed responses**, not connect attempts.
- Error rate is `errors / (completions + errors)`, not `errors / attempts`.
- The HTTP worker **backs off** after a transport reset instead of hot-looping.
- The health probe distinguishes a **target failure** (timeout/unreachable) from
  **local socket exhaustion** (EADDRNOTAVAIL / EMFILE / …), and the classifier
  refuses to call a run DOWN when the probe was drowned in local-resource errors.

Benchmarks here should defend those properties, not just measure speed.

## Loopback sanity (manual)

The consent gate is TTY-only and cannot be piped, so automated runs need a pty
driver (a short Python `pty.spawn` wrapper works). Rough procedure:

1. Start a local target: `python3 -m http.server 8080`.
2. Run a short flood at it: `http_flood`, ~10s, moderate concurrency, against
   `http://127.0.0.1:8080`.
3. Assert on the run log (`logs/onb-*.log`):
   - `rps` is **plausible** for the machine (thousands–tens of thousands), never
     millions.
   - `err_rate` stays low against a healthy server (keep-alive closes must not
     count as errors).
   - final verdict is `HEALTHY`, not a false finding.
4. Repeat against a **closed** port and confirm the worker does not spin
   (backoff engaged) and the verdict is `EDGE BLOCKED`/`DOWN` with honest,
   non-inflated counters.

## TODO

- Add a `criterion` micro-benchmark for the hot path (`one_request`, histogram
  record) once the API stabilizes.
- Scripted pty harness that runs the two scenarios above and diffs the summary
  line against expected bounds.
