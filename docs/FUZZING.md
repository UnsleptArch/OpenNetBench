# Fuzzing

*The white-box, coverage-guided fuzzing programme: what is fuzzed, why those seams and not others,
the property each harness asserts, the bug the campaign has already caught, and how to run both a
quick check and a long plateau-driven campaign. The governing principle is that the tool's value is
a verdict, and a verdict engine that can be made to panic or — worse — to silently return a wrong
answer under adversarial input is not trustworthy. So the seams that turn untrusted bytes into a
decision are fuzzed.*

---

## Table of Contents

1. [Why Fuzz, and Where](#why-fuzz)
2. [The Approach](#the-approach)
3. [The Targets](#the-targets)
4. [Property-Based Harnesses](#property-based-harnesses)
5. [What It Found](#what-it-found)
6. [Running It](#running-it)
7. [Long Campaigns](#long-campaigns)
8. [Distributing It](#distributing-it)
9. [Roadmap](#roadmap)

---

## Why fuzz

A load generator eats a lot of untrusted bytes. Before it floods anything it
crawls the target and parses whatever the target hands back: `robots.txt`, a
sitemap, an OpenAPI spec, JavaScript bundles, HTTP response headers. Then the
verdict engine takes a pile of arbitrary latency and error numbers and turns them
into a call about whether the target broke. A panic in a parser aborts a run. A
silent wrong answer in the classifier is worse, because the whole point of the
tool is to not lie to you about what happened. So the pure seams get fuzzed.

The selection is principled rather than exhaustive. The right things to fuzz are the functions where
externally-controlled bytes cross into parsing or decision logic that the project *wrote itself*.
That is exactly the recon parsers and the classifier. It is *not* the send-side vectors, whose
response parsing is delegated to vetted, upstream-fuzzed crates (`httparse`, `h2`, `rustls`, `quinn`)
and whose outbound construction is config-driven rather than adversarial — fuzzing those would mostly
re-fuzz other people's already-fuzzed code through an async socket that would have to be mocked. The
one hand-rolled response-parse not yet isolated for fuzzing (the `Content-Length`-driven drain in
`http_flood`) is named in the roadmap as the next candidate.

## The approach

White-box, in-process, coverage-guided (libFuzzer via `cargo-fuzz`). Unlike AFL++
wrapping a binary behind a forkserver, a libFuzzer harness is a function linked
against the code it exercises, so the crate is split into a library
(`src/lib.rs`) that the fuzz crate depends on and a thin binary (`src/main.rs`)
that consumes it.

The functions worth fuzzing are internal (the parsers, the encoders, the
classifier), and they stay internal. A `#[cfg(fuzzing)]` module (`src/fuzz.rs`)
exposes a curated set of thin wrappers over them. `cargo-fuzz` sets `--cfg
fuzzing` for the whole build, so that surface exists only during a fuzz build and
never widens the public API. An ordinary `cargo build` does not compile any of
it.

## The targets

Each is a separate libFuzzer binary that can be driven on its own.

| target | exercises | why |
|---|---|---|
| `classify` | the verdict engine over arbitrary signals + collapse curve | biggest input space, most consequential output |
| `recon_extract_refs` | the HTML link/form scanner | byte-index heavy, adversarial markup |
| `recon_extract_js` | the JS API-endpoint miner | quote scanning, path-template filling |
| `recon_openapi` | the OpenAPI/Swagger traversal | walks arbitrary JSON shapes |
| `recon_robots` | the `robots.txt` parser | line parsing over arbitrary text |
| `recon_sitemap` | the sitemap `<loc>` extractor | nested `find` windows over arbitrary XML |
| `cache_bust_into` | the cache-buster request-line splice | slices arbitrary template bytes |
| `dns_encode_query` | the DNS A-query wire encoder | fixed-buffer wire encoding |
| `wire_checksum` | the Internet checksum | fold plus odd-tail handling |
| `histogram_bucket` | the latency bucket mapping | range invariants, round-trip |

## Property-based harnesses

The harnesses fall into two classes by the strength of the property they assert.

The **parsers** assert the plain robustness property: for *any* input bytes, the function does not
panic and always terminates. This is the minimum a parser fed attacker-controlled data must
guarantee — a panic aborts the run, and a non-terminating parse hangs it. Coverage-guided fuzzing is
well-suited to this because it drives the input toward new branches, exercising the malformed,
truncated, and pathological shapes that a fixed corpus of well-formed samples never reaches.

The **`classify`** target is a genuine *property* harness, asserting a semantic invariant rather than
mere non-crashing: for any signals and any collapse curve, the verdict comes back with a *finite*
confidence in `[0, 1]` and never panics. That is precisely the invariant class ordinary unit tests do
not sweep — NaN and infinite latencies, degenerate count ratios (all-zero, all-error), empty and huge
sample sets, extreme probe counts. A unit test asserts behaviour on the inputs the author *thought
of*; a property harness asserts an invariant across the inputs they did not, which is where the
overflow of §"What it found" was hiding.

## What it found

The `classify` harness earned its keep on the first sweep. `classify.rs` computed
the probe-reliability gate as `probe_local_inconclusive * 2 <= probe_total`. For a
pathological count that `* 2` overflows a `u32`. Under overflow checks it panics.
In a release build it silently wraps, which flips the gate and can flip the
verdict. It is unreachable with real counts, which are bounded by how many
one-per-second probes fit in a run, so no unit test was ever going to hit it, but
it is wrong. Rewritten as `probe_local_inconclusive <= probe_total / 2`, which is
overflow-safe and arithmetically identical for integers. The crashing input is
kept in the corpus as a regression seed and there is a unit test
(`extreme_probe_counts_do_not_overflow`) pinning it.

The other nine targets ran millions of executions each with no crashes. These are
small pure functions, so their coverage saturates in minutes, not days.

## Running it

You need the nightly toolchain and `cargo-fuzz`:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

Then, from the repo root:

```bash
cargo +nightly fuzz list                          # the targets above
cargo +nightly fuzz run classify -- -max_total_time=60
cargo +nightly fuzz run classify <crash-file>     # replay a crash
cargo +nightly fuzz tmin classify <crash-file>    # shrink a crash
```

The harness crate lives at `fuzz/`. If it is kept out of tree instead (under
`dev/fuzz`), add `--fuzz-dir dev/fuzz` to each command.

## Long campaigns

For anything past a quick check there is a local driver, `dev/fuzz.py`. It is
local only by design, no network and no coordination, in keeping with the rest of
the tool. It fuzzes a target until its coverage plateaus (no new coverage for a
configurable window), runs libFuzzer in `-fork` mode so it uses every core and
keeps going past a crash, and records everything to a per-host SQLite database and
a JSON export. It is resumable: the corpus on disk is the durable state and the
database tracks per-target time and plateau status, so a killed run resumes where
it stopped.

```bash
dev/fuzz.py install                 # nightly + cargo-fuzz
dev/fuzz.py campaign                # every target, each until it plateaus
dev/fuzz.py run classify            # one target until it plateaus
dev/fuzz.py status                  # per-target time / coverage / plateau / crashes
dev/fuzz.py crashes                 # recorded crashes, deduplicated by stack hash
dev/fuzz.py export                  # write this host's JSON exports
```

Across several machines the model stays offline. Each box fuzzes its own targets
(one or two per box is a natural split), writes its own `<host>.db` and JSON
exports, and you collect those files and stitch them with `dev/fuzz-merge.py`,
which joins them into a fleet view: per-target coverage high-water, total
CPU-time, and every unique crash deduplicated across the whole fleet. No agent
ever talks to another.

```bash
dev/fuzz-merge.py results/          # combine every <host>.db / *.json in a dir
```

Useful libFuzzer flags after the `--`: `-max_total_time=<s>` bounds the run,
`-timeout=<s>` catches an input that hangs, `-rss_limit_mb=<n>` catches a runaway
allocation, `-fork=<n>` runs N worker processes sharing one corpus and keeps
going past a crash (with `-ignore_crashes=1`) instead of dying.

The corpus under `fuzz/corpus/<target>/` is the durable state. It is coverage,
not scratch: every interesting input libFuzzer finds is written there, so killing
a run and restarting it against the same corpus resumes from the same frontier.
Crash inputs land under `fuzz/artifacts/<target>/` and are portable, so a crash
found on one machine reproduces on any other with `cargo +nightly fuzz run
<target> <file>`.

## Distributing it

libFuzzer distributes through the corpus, not a coordinator. Every machine fuzzes
against its own local corpus and the fleet shares findings by merging corpora:
coverage discovered on one box propagates to the others when they ingest it, and
each then explores further from the combined frontier. Crash artifacts are just
files, so they collect the same way. There is no agent protocol and no shared
mutable state, which fits the rest of the project.

## Roadmap

Built and in use today: the ten harnesses above, the resumable plateau-driven
campaign runner (`dev/fuzz.py`), and the offline fleet merge (`dev/fuzz-merge.py`).

Not built yet:

- More targets on the stateful seams: the `httparse`-driven response reader, the
  raw HTTP/2 frame path, and the recon differential sampler.
- Coverage-report rendering wired into the campaign runner (`cargo fuzz coverage`
  works today, it is just not summarised automatically).
