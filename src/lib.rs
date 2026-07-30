//! OpenNetBench library crate.
//!
//! The binary (`main.rs`) is a thin CLI shim over this library. Splitting the
//! modules out here is what lets the out-of-tree fuzz crate (`dev/fuzz`) drive
//! the pure parsers and the classifier in-process: a libFuzzer harness is a
//! function, not a process wrapped by a forkserver, so it needs a `lib` target
//! to link against.

// Scaffold stage: several types/functions are forward-declared for modules that
// land in later increments (web server, DB, CVE correlation).
#![allow(dead_code)]

pub mod auth;
pub mod auto;
pub mod classify;
pub mod cli;
pub mod config;
pub mod db;
pub mod engine;
pub mod logging;
pub mod metrics;
pub mod presets;
pub mod recon;
pub mod web;

/// Fuzzing surface: thin `pub` wrappers over the internal, `pub(crate)` pure
/// functions the fuzz harnesses drive. Gated on `cfg(fuzzing)`, which cargo-fuzz
/// sets for the whole build, so none of this exists in an ordinary build and the
/// public API stays unchanged.
#[cfg(fuzzing)]
pub mod fuzz;
