# tests (integration / end-to-end)

Out-of-band tests that exercise the built binary as a whole, beyond the in-crate
`#[cfg(test)]` unit tests (run those with `cargo test`).

Candidates to live here:

- **pty-driven E2E**: drive the interactive flow through a pseudo-terminal
  (consent phrase → target → preset/vectors → confirm), run against a local
  server, and assert on the run log + verdict.
- **preset resolution**: `--save-config` for each preset → assert the emitted
  JSON has the expected vectors, mode, and per-vector concurrency.
- **classifier fixtures**: replay recorded `Signals` + collapse curves and assert
  the verdict, so regressions in `classify()` are caught without live traffic.
- **safety invariants**: assert the consent gate cannot be bypassed by any flag
  path (`--config`, `--preset`, `--auto`).

Keep anything that sends real traffic pointed at **localhost or an explicitly
owned lab target** only.
