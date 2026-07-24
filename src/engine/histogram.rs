//! Fixed-memory, lock-free latency histogram.
//!
//! HdrHistogram-style: each power-of-two magnitude is split into 8 linear
//! sub-buckets, giving ~12% relative resolution across the whole range
//! (~1µs to ~2.9 hours) in a constant 512 × 8 bytes = 4 KB. Recording is O(1):
//! one `leading_zeros` and one relaxed atomic add — no allocation, no locks,
//! safe to hammer from every worker concurrently. Quantiles are O(N=512) and
//! run only in the sampler (4×/sec), on windowed deltas.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

pub const N: usize = 512;
const SUB_BITS: u32 = 3; // 8 sub-buckets per magnitude
const SUB_COUNT: u64 = 1 << SUB_BITS;

/// Map a latency in microseconds to a bucket index. O(1).
#[inline]
fn bucket_of(us: u64) -> usize {
    let us = us.max(1);
    // Values below one full magnitude of sub-buckets are stored linearly.
    if us < SUB_COUNT {
        return us as usize;
    }
    let mag = 63 - us.leading_zeros(); // floor(log2(us)), 3..=63
    let sub = (us >> (mag - SUB_BITS)) & (SUB_COUNT - 1);
    let idx = (mag as usize) * (SUB_COUNT as usize) + sub as usize;
    idx.min(N - 1)
}

/// Approximate microsecond value at the *midpoint* of a bucket. Inverse of
/// `bucket_of`, used to turn a bucket index back into a latency for reporting.
fn us_of(idx: usize) -> f64 {
    if idx < SUB_COUNT as usize {
        return idx as f64;
    }
    let mag = (idx / SUB_COUNT as usize) as u32;
    let sub = (idx % SUB_COUNT as usize) as u64;
    let base = 1u64 << mag;
    let step = base >> SUB_BITS;
    (base + sub * step + step / 2) as f64
}

pub struct Histogram {
    buckets: [AtomicU64; N],
}

impl Histogram {
    pub fn new() -> Self {
        Histogram {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// Record one latency observation. O(1), lock-free.
    #[inline]
    pub fn record_us(&self, us: u64) {
        self.buckets[bucket_of(us)].fetch_add(1, Relaxed);
    }

    /// Copy the current cumulative counts into `out`. O(N).
    pub fn snapshot_into(&self, out: &mut [u64; N]) {
        for (o, b) in out.iter_mut().zip(self.buckets.iter()) {
            *o = b.load(Relaxed);
        }
    }
}

/// Compute p50/p95/p99 (in milliseconds) from a windowed count array — the
/// per-bucket delta between two cumulative snapshots. Returns zeros if empty.
pub fn quantiles_ms(delta: &[u64; N]) -> (f64, f64, f64) {
    let total: u64 = delta.iter().sum();
    if total == 0 {
        return (0.0, 0.0, 0.0);
    }
    let pick = |p: f64| -> f64 {
        let threshold = (p * total as f64).ceil() as u64;
        let mut cum = 0u64;
        for (i, &c) in delta.iter().enumerate() {
            cum += c;
            if cum >= threshold {
                return us_of(i) / 1000.0;
            }
        }
        us_of(N - 1) / 1000.0
    };
    (pick(0.50), pick(0.95), pick(0.99))
}
