//! Response classification.
//!
//! The intelligence of the tool: deciding whether the target dropping/blocking
//! us means the defense WORKED (mitigation win) or the service FAILED (finding).
//! Getting this wrong — calling a WAF save a "vuln" — would make every report a
//! lie, so verdicts always carry a confidence, never certainty.

use crate::metrics::LatencySample;
use serde::{Deserialize, Serialize};

/// Minimum absolute p99 increase over baseline (ms) before latency growth counts
/// as degradation. A 3× ratio alone is noise when both numbers are sub-ms (e.g.
/// localhost 0.2ms→1.7ms); real exhaustion moves p99 by tens of ms or more.
pub const MIN_DEGRADE_DELTA_MS: f64 = 25.0;

/// How many consecutive samples (at 250 ms each) must breach the degradation
/// threshold before it counts. Filters transient spikes (a scheduler pause, one
/// GC) from genuine sustained exhaustion. 3 samples ≈ 0.75 s.
pub const DEGRADE_CONSECUTIVE: usize = 3;

/// Baseline-ratio floor: p99 must reach at least this multiple of baseline.
const DEGRADE_RATIO: f64 = 3.0;

/// How many MADs above the quiet-baseline median counts as "clearly above noise".
/// ~5·MAD ≈ 3.4·σ, so a stable target almost never trips it by chance while a
/// jittery one is required to move further before we call it degraded.
const NOISE_K: f64 = 5.0;

/// The p99 a sample must exceed to count as a degradation breach.
///
/// A flat `base × 3` multiplier treats a rock-stable 2 ms target and a jittery
/// 200 ms one identically — the first can't register a real 40 ms stall, the
/// second cries wolf on ordinary variance. So the threshold is the strongest of
/// three floors: the ratio (`base × 3`), an absolute delta (`base + 25 ms`, kills
/// sub-ms noise), and a noise-relative bar (`median + 5·MAD` of the run's own
/// quiet prefix). The noise term binds in the middle — moderate baseline, high
/// jitter — exactly where the flat ratio misjudges.
pub fn breach_threshold(samples: &[LatencySample], base: f64) -> f64 {
    let mut floor = (base * DEGRADE_RATIO).max(base + MIN_DEGRADE_DELTA_MS);
    // The quiet prefix: leading low-error samples that aren't already breaching
    // the ratio floor, so the degradation itself can't poison the baseline.
    let quiet: Vec<f64> = samples
        .iter()
        .take_while(|s| s.error_rate < 0.1 && s.p99_ms <= base * DEGRADE_RATIO)
        .map(|s| s.p99_ms)
        .take(8)
        .collect();
    if let (Some(med), Some(mad)) = (median(&quiet), mad(&quiet)) {
        floor = floor.max(med + NOISE_K * mad);
    }
    floor
}

/// A sustained degradation found in the collapse curve, with where it started and
/// whether the target recovered once load let up.
#[derive(Debug, Clone, Copy)]
pub struct Degradation {
    /// Worst p99 observed from the knee onward.
    pub peak_p99: f64,
    /// Time (ms into the run) the sustained breach began.
    pub knee_t_ms: u64,
    /// Concurrent load in flight when it began — the "it broke at N" number.
    pub knee_concurrency: u32,
    /// Time from knee to a sustained return under `base × 1.5`, if it recovered
    /// within the run. `Some` is strong evidence the load caused it.
    pub recovery_ms: Option<u64>,
}

/// Find the first *sustained* degradation (≥ [`DEGRADE_CONSECUTIVE`] consecutive
/// samples over `threshold`) and describe it. `None` means only transient spikes,
/// which are not a finding. Shared by the classifier and the outcome summary so
/// the verdict and the reported knee can never disagree.
pub fn detect_degradation(
    samples: &[LatencySample],
    base: f64,
    threshold: f64,
) -> Option<Degradation> {
    if base <= 0.0 {
        return None;
    }
    // Locate the knee: the start of the first run of breaching samples that
    // reaches DEGRADE_CONSECUTIVE.
    let mut run = 0usize;
    let mut run_start: Option<(u64, u32)> = None;
    let mut knee_idx = None;
    for (i, s) in samples.iter().enumerate() {
        if s.p99_ms > threshold {
            if run == 0 {
                run_start = Some((s.t_ms, s.concurrency));
            }
            run += 1;
            if run >= DEGRADE_CONSECUTIVE {
                knee_idx = Some(i + 1 - DEGRADE_CONSECUTIVE);
                break;
            }
        } else {
            run = 0;
            run_start = None;
        }
    }
    let (knee_idx, (knee_t_ms, knee_concurrency)) = (knee_idx?, run_start?);

    let peak_p99 = samples[knee_idx..]
        .iter()
        .map(|s| s.p99_ms)
        .fold(threshold, f64::max);

    // Recovery: a sustained run back under base × 1.5 after the knee.
    let recovery_line = base * 1.5;
    let mut under = 0usize;
    let mut recovery_ms = None;
    for s in &samples[knee_idx..] {
        if s.p99_ms <= recovery_line {
            under += 1;
            if under >= DEGRADE_CONSECUTIVE {
                recovery_ms = Some(s.t_ms.saturating_sub(knee_t_ms));
                break;
            }
        } else {
            under = 0;
        }
    }

    Some(Degradation { peak_p99, knee_t_ms, knee_concurrency, recovery_ms })
}

/// Median of a slice (sorted copy); `None` if empty.
fn median(xs: &[f64]) -> Option<f64> {
    if xs.is_empty() {
        return None;
    }
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    Some(if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 })
}

/// Median absolute deviation — robust spread that ignores the outliers a mean
/// would chase. `None` if empty.
fn mad(xs: &[f64]) -> Option<f64> {
    let m = median(xs)?;
    let devs: Vec<f64> = xs.iter().map(|x| (x - m).abs()).collect();
    median(&devs)
}

/// What the observed behavior most likely means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Traffic served normally; no stress observed.
    Healthy,
    /// 403/429 with a WAF/rate-limiter fingerprint — the defense is working.
    MitigationEngaged,
    /// Connections refused/reset fast with no application response — edge block.
    EdgeBlocked,
    /// Rising p99 → timeouts, correlated with our load ramp. Real exhaustion.
    Degrading,
    /// Service stopped responding entirely under load.
    Down,
    /// Not enough signal to decide (e.g. L4/raw-only run).
    Unknown,
}

impl Verdict {
    /// Is this a finding (something the target owner must fix) vs. a defense win?
    pub fn is_finding(self) -> bool {
        matches!(self, Verdict::Degrading | Verdict::Down)
    }

    pub fn label(self) -> &'static str {
        match self {
            Verdict::Healthy => "HEALTHY (absorbed the load)",
            Verdict::MitigationEngaged => "MITIGATION ENGAGED (defense working)",
            Verdict::EdgeBlocked => "EDGE BLOCKED (dropped at the edge)",
            Verdict::Degrading => "DEGRADING (resource exhaustion — FINDING)",
            Verdict::Down => "DOWN (service failed under load — FINDING)",
            Verdict::Unknown => "UNKNOWN (insufficient signal)",
        }
    }
}

/// A classification with the evidence that produced it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Classification {
    pub verdict: Verdict,
    /// 0.0–1.0. Never 1.0 — we report likelihood, not proof.
    pub confidence: f64,
    /// Human-readable evidence trail (status codes, WAF fingerprint, timing).
    pub evidence: Vec<String>,
}

/// Context carried from recon into the run for use by the classifier and the
/// outcome derivation.
#[derive(Debug, Clone, Default)]
pub struct RunContext {
    /// Pre-load baseline latency (ms) from recon, if recon ran.
    pub baseline_ms: Option<f64>,
    /// WAF/CDN vendor inferred from the server fingerprint, if any.
    pub waf_vendor: Option<String>,
    /// When set, the engine watches the health probe and prompts to stop the
    /// moment it detects a finding (target down/degrading).
    pub stop_on_detect: bool,
}

/// The observable signals the classifier reasons over.
#[derive(Clone)]
pub struct Signals {
    pub requests: u64,
    pub errors: u64,
    pub http_2xx: u64,
    pub http_3xx: u64,
    pub http_4xx: u64,
    pub http_403: u64,
    /// 408 Request Timeout — server-stress signal, tracked apart from other 4xx.
    pub http_408: u64,
    pub http_429: u64,
    pub http_5xx: u64,
    pub baseline_ms: Option<f64>,
    pub waf_vendor: Option<String>,
    /// Whether any L7 vector that yields HTTP status codes actually ran.
    pub l7_active: bool,
    // Independent health-probe signal (works for any vector, incl. L4/raw).
    /// Connect latency (ms) before load started.
    pub probe_baseline_ms: Option<f64>,
    /// Worst connect latency (ms) observed during the run.
    pub probe_peak_ms: Option<f64>,
    /// Number of health probes that failed target-side (timeout/unreachable).
    pub probe_failures: u32,
    /// Health probes that failed on *our* local socket/port exhaustion — these say
    /// nothing about the target and must not drive a "down" verdict.
    pub probe_local_inconclusive: u32,
    /// Total health probes attempted.
    pub probe_total: u32,
    /// Peak concurrent held connections observed.
    pub peak_held: u32,
    // Independent application-layer probe (real GETs from a separate client).
    /// Whether the service answered normally BEFORE load started. When false the
    /// service signal is unusable and must be ignored.
    pub service_baseline_ok: bool,
    /// Independent service GETs that got no usable answer (timeout / connect
    /// failure / 5xx) during the run.
    pub service_failures: u32,
    /// Total independent service GETs attempted during the run.
    pub service_checks: u32,
}

/// Known WAF/CDN vendor substrings to look for in a `Server` header.
const WAF_VENDORS: &[(&str, &str)] = &[
    ("cloudflare", "Cloudflare"),
    ("akamai", "Akamai"),
    ("sucuri", "Sucuri"),
    ("incapsula", "Imperva Incapsula"),
    ("imperva", "Imperva"),
    ("fastly", "Fastly"),
    ("cloudfront", "AWS CloudFront"),
    ("barracuda", "Barracuda"),
    ("big-ip", "F5 BIG-IP"),
    ("mod_security", "ModSecurity"),
    ("awselb", "AWS ELB"),
];

/// Infer a WAF/CDN vendor from a `Server` header value.
pub fn detect_waf(server: Option<&str>) -> Option<String> {
    let s = server?.to_ascii_lowercase();
    WAF_VENDORS
        .iter()
        .find(|(needle, _)| s.contains(needle))
        .map(|(_, name)| name.to_string())
}

/// Classify a run from its aggregate signals and collapse curve.
pub fn classify(sig: &Signals, samples: &[LatencySample]) -> Classification {
    let mut ev = Vec::new();

    // --- Derived metrics, computed once so every section can corroborate. ---
    let responses = sig.http_2xx
        + sig.http_3xx
        + sig.http_4xx
        + sig.http_403
        + sig.http_408
        + sig.http_429
        + sig.http_5xx;
    let peak_p99 = samples.iter().map(|s| s.p99_ms).fold(0.0_f64, f64::max);
    let base = sig.baseline_ms.or_else(|| {
        samples
            .iter()
            .find(|s| s.error_rate < 0.1 && s.p99_ms > 0.0)
            .map(|s| s.p99_ms)
    });
    let tail_err = tail_error_rate(samples);
    let degradation =
        base.and_then(|b| detect_degradation(samples, b, breach_threshold(samples, b)));
    let server_err_frac = if responses > 0 {
        (sig.http_5xx + sig.http_408) as f64 / responses as f64
    } else {
        0.0
    };

    // Independent indicators that the *target* (not our own box) was impacted.
    // A verdict several of these agree on is reported with higher confidence than
    // one resting on a single measurement — see `corroborate`.
    let probe_conclusive = sig.probe_total.saturating_sub(sig.probe_local_inconclusive);
    let probe_reliable = sig.probe_local_inconclusive * 2 <= sig.probe_total;
    let probe_fail_frac = if probe_reliable && probe_conclusive > 0 {
        sig.probe_failures as f64 / probe_conclusive as f64
    } else {
        0.0
    };
    let service_fail_frac = if sig.service_baseline_ok && sig.service_checks > 0 {
        sig.service_failures as f64 / sig.service_checks as f64
    } else {
        0.0
    };
    let stress = (probe_fail_frac > 0.3) as u32
        + (service_fail_frac > 0.25) as u32
        + degradation.is_some() as u32
        + (server_err_frac > 0.3) as u32;

    // 0. Health probe — independent ground truth about the target's availability.
    // This is the only signal that works for L4/raw vectors, and it overrides the
    // rest when it shows real impact.
    if sig.probe_total > 0 {
        if let Some(pbase) = sig.probe_baseline_ms {
            let local = sig.probe_local_inconclusive;
            // Probes that failed because *we* ran out of local sockets/ports say
            // nothing about the target. If they dominate, the probe is unreliable
            // this run — don't let it decide anything; note it and fall through.
            if !probe_reliable {
                ev.push(format!(
                    "health probe unreliable: {}/{} checks failed on LOCAL socket exhaustion \
                     (our machine, not the target) — reduce per-vector concurrency for a clean read",
                    local, sig.probe_total
                ));
            } else if probe_conclusive > 0 {
                let peak = sig.probe_peak_ms.unwrap_or(pbase);
                if probe_fail_frac > 0.3 {
                    ev.push(format!(
                        "health probe: {:.0}% of conclusive connection checks to the target \
                         FAILED under load",
                        probe_fail_frac * 100.0
                    ));
                    if local > 0 {
                        ev.push(format!("({local} further checks were inconclusive — local limits)"));
                    }
                    let verdict =
                        if probe_fail_frac > 0.7 { Verdict::Down } else { Verdict::Degrading };
                    return Classification {
                        verdict,
                        confidence: corroborate(0.6 + probe_fail_frac * 0.3, stress),
                        evidence: ev,
                    };
                }
                if pbase > 0.0 && peak > pbase * 3.0 && peak - pbase > MIN_DEGRADE_DELTA_MS {
                    ev.push(format!(
                        "health probe connect latency rose {pbase:.1}ms → {peak:.1}ms under load ({:.1}x)",
                        peak / pbase
                    ));
                    return Classification {
                        verdict: Verdict::Degrading,
                        confidence: corroborate(0.8, stress),
                        evidence: ev,
                    };
                }
                ev.push(format!(
                    "health probe stable ({pbase:.1}ms baseline, {}/{} conclusive checks ok)",
                    probe_conclusive - sig.probe_failures,
                    probe_conclusive
                ));
            }
        }
    }

    // 0b. Service-level health — the signal a TCP connect cannot give. A server
    // whose worker/connection pool is exhausted (slowloris, rudy, slow read)
    // still completes TCP handshakes while answering no real requests, so a
    // stable connect probe alone would read "healthy". This runs only when the
    // app answered at baseline, and only reaches here when the TCP probe didn't
    // already return a verdict — i.e. TCP looked fine.
    if sig.service_baseline_ok && sig.service_checks > 0 {
        if service_fail_frac > 0.25 {
            ev.push(format!(
                "service probe: {:.0}% of independent requests got no usable answer under load, \
                 while the target still accepted TCP connections",
                service_fail_frac * 100.0
            ));
            let verdict =
                if service_fail_frac > 0.6 { Verdict::Down } else { Verdict::Degrading };
            return Classification {
                verdict,
                confidence: corroborate(0.6 + service_fail_frac * 0.3, stress),
                evidence: ev,
            };
        }
        ev.push(format!(
            "service probe healthy ({}/{} independent requests answered)",
            sig.service_checks - sig.service_failures,
            sig.service_checks
        ));
    }

    if !sig.l7_active {
        // No application-layer signal — lean on the health probe. A stable probe
        // means the target absorbed the load; no probe at all means we can't tell.
        if sig.probe_total > 0 && sig.probe_baseline_ms.is_some() {
            ev.push(format!(
                "target kept accepting connections (peak {} concurrent held) — absorbed",
                sig.peak_held
            ));
            return Classification { verdict: Verdict::Healthy, confidence: 0.6, evidence: ev };
        }
        ev.push("L4/raw vectors only and no health-probe signal — can't assess".into());
        return Classification { verdict: Verdict::Unknown, confidence: 0.0, evidence: ev };
    }

    // 1. Rate limiter — 429s are an unambiguous mitigation signal.
    if responses > 0 {
        let frac_429 = sig.http_429 as f64 / responses as f64;
        if frac_429 > 0.2 {
            ev.push(format!("{:.0}% of responses were 429 (rate limiting)", frac_429 * 100.0));
            return Classification {
                verdict: Verdict::MitigationEngaged,
                confidence: conf(frac_429, 0.9),
                evidence: ev,
            };
        }
        // 2. WAF block — 403s, strengthened by a known vendor fingerprint.
        let frac_403 = sig.http_403 as f64 / responses as f64;
        if frac_403 > 0.2 {
            ev.push(format!("{:.0}% of responses were 403 (blocked)", frac_403 * 100.0));
            let mut c = conf(frac_403, 0.75);
            if let Some(v) = &sig.waf_vendor {
                ev.push(format!("WAF/CDN fingerprint: {v}"));
                c = (c + 0.15).min(0.9);
            }
            return Classification {
                verdict: Verdict::MitigationEngaged,
                confidence: c,
                evidence: ev,
            };
        }
    }

    // 3. Resource exhaustion — a SUSTAINED p99 breach over the noise-relative
    // threshold. Beyond detecting it, we test whether *we* caused it: did the
    // breach track the rising load (knee concurrency above the quiet baseline),
    // and did p99 recover once load eased? Both are what separates "we broke it"
    // from "something else hiccuped", and both raise confidence.
    if let (Some(b), Some(d)) = (base, degradation) {
        ev.push(format!(
            "p99 held at {:.1}ms vs {:.1}ms baseline ({:.1}x); knee at ~{} concurrent, {:.1}s in",
            d.peak_p99,
            b,
            d.peak_p99 / b,
            d.knee_concurrency,
            d.knee_t_ms as f64 / 1000.0
        ));
        let baseline_conc = samples.first().map(|s| s.concurrency).unwrap_or(0);
        let mut caus = 0u32;
        if d.knee_concurrency > baseline_conc {
            ev.push(format!(
                "degradation tracked the load ramp (rose to {} concurrent) — consistent with us causing it",
                d.knee_concurrency
            ));
            caus += 1;
        }
        if let Some(rec) = d.recovery_ms {
            ev.push(format!(
                "p99 recovered ~{:.1}s after load eased — load-induced, not a pre-existing fault",
                rec as f64 / 1000.0
            ));
            caus += 1;
        }
        if caus == 0 {
            ev.push("load-correlation unclear (flat concurrency, no recovery window seen)".into());
        }
        // Down if the tail shows near-total failure; else degrading.
        if tail_err > 0.8 || (responses > 0 && sig.http_5xx as f64 / responses as f64 > 0.5) {
            ev.push(format!("tail error rate {:.0}%", tail_err * 100.0));
            return Classification {
                verdict: Verdict::Down,
                confidence: (corroborate(0.75, stress) + 0.05 * caus as f64).min(0.9),
                evidence: ev,
            };
        }
        return Classification {
            verdict: Verdict::Degrading,
            confidence: (corroborate(0.65, stress) + 0.05 * caus as f64).min(0.9),
            evidence: ev,
        };
    }

    // 3b. Server erroring under load without a latency blowup — an app that fails
    // fast behind a proxy answers instantly with 5xx/408, so the latency rule
    // above never fires. High server-error rate is a finding on its own.
    if responses > 0 && server_err_frac > 0.2 {
        let frac_5xx = sig.http_5xx as f64 / responses as f64;
        let frac_408 = sig.http_408 as f64 / responses as f64;
        ev.push(format!(
            "{:.0}% of responses were server errors under load ({:.0}% 5xx, {:.0}% 408 timeout)",
            server_err_frac * 100.0,
            frac_5xx * 100.0,
            frac_408 * 100.0
        ));
        let verdict = if server_err_frac > 0.5 { Verdict::Down } else { Verdict::Degrading };
        return Classification {
            verdict,
            confidence: corroborate(0.6 + server_err_frac * 0.3, stress),
            evidence: ev,
        };
    }

    // 4. No application responses at all despite L7 attempts → edge/down.
    if responses == 0 {
        if sig.errors == 0 {
            return Classification {
                verdict: Verdict::Unknown,
                confidence: 0.0,
                evidence: vec!["no responses and no errors recorded".into()],
            };
        }
        // Fast failures with no latency signal look like an edge drop.
        let fast = base.map(|b| peak_p99 < b * 2.0).unwrap_or(peak_p99 < 5.0);
        ev.push(format!("no HTTP responses; {} transport failures", sig.errors));
        return if fast {
            if let Some(v) = &sig.waf_vendor {
                ev.push(format!("edge fingerprint: {v}"));
            }
            Classification { verdict: Verdict::EdgeBlocked, confidence: 0.6, evidence: ev }
        } else {
            Classification { verdict: Verdict::Down, confidence: 0.6, evidence: ev }
        };
    }

    // 5. Mostly-2xx with stable latency → the target absorbed it.
    let frac_2xx = sig.http_2xx as f64 / responses as f64;
    if frac_2xx > 0.8 {
        ev.push(format!("{:.0}% 2xx, latency stable under load", frac_2xx * 100.0));
        return Classification {
            verdict: Verdict::Healthy,
            confidence: conf(frac_2xx, 0.85),
            evidence: ev,
        };
    }

    ev.push("mixed signals — no dominant pattern".into());
    Classification { verdict: Verdict::Unknown, confidence: 0.3, evidence: ev }
}

/// Average error rate over the last few samples (the run's tail).
fn tail_error_rate(samples: &[LatencySample]) -> f64 {
    let n = samples.len().min(4);
    if n == 0 {
        return 0.0;
    }
    let sum: f64 = samples[samples.len() - n..].iter().map(|s| s.error_rate).sum();
    sum / n as f64
}

/// Scale a dominance fraction (0..1) into a confidence capped at `max`.
fn conf(fraction: f64, max: f64) -> f64 {
    (0.4 + fraction * 0.6).min(max)
}

/// Raise a base confidence by how many *independent* signals agree with the
/// verdict beyond the one that triggered it. One signal is the base; each extra
/// corroborating signal adds a little. Capped at 0.9 — we report likelihood.
fn corroborate(base: f64, agreeing_signals: u32) -> f64 {
    (base + 0.05 * agreeing_signals.saturating_sub(1) as f64).min(0.9)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(p99: f64, err: f64) -> LatencySample {
        sample_at(0, 10, p99, err)
    }

    fn sample_at(t_ms: u64, concurrency: u32, p99: f64, err: f64) -> LatencySample {
        LatencySample {
            t_ms,
            concurrency,
            p50_ms: p99 / 2.0,
            p95_ms: p99 * 0.9,
            p99_ms: p99,
            error_rate: err,
        }
    }

    fn base_signals() -> Signals {
        Signals {
            requests: 1000,
            errors: 0,
            http_2xx: 0,
            http_3xx: 0,
            http_4xx: 0,
            http_403: 0,
            http_408: 0,
            http_429: 0,
            http_5xx: 0,
            baseline_ms: Some(10.0),
            waf_vendor: None,
            l7_active: true,
            probe_baseline_ms: None,
            probe_peak_ms: None,
            probe_failures: 0,
            probe_local_inconclusive: 0,
            probe_total: 0,
            peak_held: 0,
            service_baseline_ok: false,
            service_failures: 0,
            service_checks: 0,
        }
    }

    #[test]
    fn l4_only_is_unknown() {
        let mut s = base_signals();
        s.l7_active = false;
        assert_eq!(classify(&s, &[]).verdict, Verdict::Unknown);
    }

    #[test]
    fn rate_limiting_is_mitigation() {
        let mut s = base_signals();
        s.http_2xx = 500;
        s.http_429 = 500;
        assert_eq!(classify(&s, &[]).verdict, Verdict::MitigationEngaged);
    }

    #[test]
    fn waf_403_raises_confidence() {
        let mut s = base_signals();
        s.http_2xx = 300;
        s.http_403 = 700;
        let without = classify(&s, &[]).confidence;
        s.waf_vendor = Some("Cloudflare".into());
        let with = classify(&s, &[]);
        assert_eq!(with.verdict, Verdict::MitigationEngaged);
        assert!(with.confidence > without, "WAF fingerprint should raise confidence");
    }

    #[test]
    fn p99_blowout_is_degrading_finding() {
        let mut s = base_signals();
        s.http_2xx = 1000;
        // Sustained 12× breach (3+ consecutive samples), not a single spike.
        let samples = [
            sample(10.0, 0.0),
            sample(120.0, 0.1),
            sample(120.0, 0.1),
            sample(120.0, 0.1),
        ];
        let c = classify(&s, &samples);
        assert_eq!(c.verdict, Verdict::Degrading);
        assert!(c.verdict.is_finding());
    }

    #[test]
    fn single_p99_spike_is_not_a_finding() {
        let mut s = base_signals();
        s.http_2xx = 1000;
        // One transient spike surrounded by healthy samples must NOT be Degrading.
        let samples = [
            sample(10.0, 0.0),
            sample(200.0, 0.0), // lone spike
            sample(11.0, 0.0),
            sample(12.0, 0.0),
        ];
        let c = classify(&s, &samples);
        assert_ne!(c.verdict, Verdict::Degrading);
        assert_ne!(c.verdict, Verdict::Down);
    }

    #[test]
    fn total_tail_failure_is_down() {
        let mut s = base_signals();
        s.http_2xx = 1000;
        // A real outage: healthy start, then a sustained failing tail.
        let samples = [
            sample(10.0, 0.0),
            sample(200.0, 0.9),
            sample(200.0, 0.95),
            sample(200.0, 0.98),
            sample(200.0, 0.99),
        ];
        assert_eq!(classify(&s, &samples).verdict, Verdict::Down);
    }

    #[test]
    fn mostly_2xx_stable_is_healthy() {
        let mut s = base_signals();
        s.http_2xx = 990;
        s.http_5xx = 10;
        let samples = [sample(10.0, 0.0), sample(12.0, 0.0)];
        assert_eq!(classify(&s, &samples).verdict, Verdict::Healthy);
    }

    #[test]
    fn probe_failures_mean_down_even_for_l4() {
        let mut s = base_signals();
        s.l7_active = false; // e.g. a tcp_exhaust / syn_flood run
        s.probe_baseline_ms = Some(5.0);
        s.probe_total = 10;
        s.probe_failures = 9;
        assert_eq!(classify(&s, &[]).verdict, Verdict::Down);
    }

    #[test]
    fn service_dead_while_tcp_accepts_is_a_finding() {
        // Slowloris case: TCP connect stays healthy, but the app answers no
        // independent requests. The service probe must catch this, not report
        // Healthy just because the port still accepts.
        let mut s = base_signals();
        s.l7_active = false; // slowloris produces no HTTP status codes itself
        s.probe_baseline_ms = Some(5.0);
        s.probe_total = 30;
        s.probe_failures = 0; // TCP still accepting
        s.service_baseline_ok = true;
        s.service_checks = 20;
        s.service_failures = 18; // 90% of real requests unanswered
        let c = classify(&s, &[]);
        assert_eq!(c.verdict, Verdict::Down);
        assert!(c.verdict.is_finding());
    }

    #[test]
    fn service_probe_ignored_when_baseline_down() {
        // If the service never answered at baseline, its failures say nothing —
        // must not fabricate a finding on a pure-L4 target.
        let mut s = base_signals();
        s.l7_active = false;
        s.probe_baseline_ms = Some(5.0);
        s.probe_total = 10;
        s.probe_failures = 0;
        s.peak_held = 500;
        s.service_baseline_ok = false;
        s.service_checks = 10;
        s.service_failures = 10;
        let c = classify(&s, &[]);
        assert_ne!(c.verdict, Verdict::Down);
        assert_ne!(c.verdict, Verdict::Degrading);
    }

    #[test]
    fn local_socket_exhaustion_does_not_read_as_target_down() {
        // The router false-positive: our own box ran out of ephemeral ports, so
        // most probes failed locally. That must NOT be reported as the target
        // going down — it should fall through, not return Down/Degrading.
        let mut s = base_signals();
        s.l7_active = false; // L4-style run, probe is the only signal
        s.probe_baseline_ms = Some(9.6);
        s.probe_total = 30;
        s.probe_local_inconclusive = 28; // 28/30 failed on our sockets
        s.probe_failures = 2; // only 2 genuine target-side failures
        let c = classify(&s, &[]);
        assert_ne!(c.verdict, Verdict::Down);
        assert_ne!(c.verdict, Verdict::Degrading);
    }

    #[test]
    fn l4_absorbed_is_healthy_not_unknown() {
        let mut s = base_signals();
        s.l7_active = false;
        s.probe_baseline_ms = Some(5.0);
        s.probe_peak_ms = Some(6.0);
        s.probe_total = 10;
        s.probe_failures = 0;
        s.peak_held = 500;
        let c = classify(&s, &[]);
        assert_eq!(c.verdict, Verdict::Healthy);
    }

    #[test]
    fn l4_without_probe_is_unknown() {
        let mut s = base_signals();
        s.l7_active = false;
        assert_eq!(classify(&s, &[]).verdict, Verdict::Unknown);
    }

    #[test]
    fn probe_latency_blowout_is_degrading() {
        let mut s = base_signals();
        s.l7_active = false;
        s.probe_baseline_ms = Some(5.0);
        s.probe_peak_ms = Some(200.0); // 40x, +195ms
        s.probe_total = 10;
        assert_eq!(classify(&s, &[]).verdict, Verdict::Degrading);
    }

    #[test]
    fn detect_waf_matches_vendor() {
        assert_eq!(detect_waf(Some("cloudflare")).as_deref(), Some("Cloudflare"));
        assert_eq!(detect_waf(Some("nginx/1.25")), None);
        assert_eq!(detect_waf(None), None);
    }

    // --- W1: causation (load correlation + recovery + knee) ---

    #[test]
    fn degradation_tracking_the_load_ramp_is_more_confident_and_reports_the_knee() {
        let mut s = base_signals();
        s.http_2xx = 1000;
        // p99 blows up as concurrency climbs — a curve we plausibly caused.
        let rising = [
            sample_at(0, 5, 10.0, 0.0),
            sample_at(250, 10, 10.0, 0.0),
            sample_at(500, 100, 120.0, 0.05),
            sample_at(750, 150, 120.0, 0.05),
            sample_at(1000, 200, 120.0, 0.05),
        ];
        // Same p99 curve, but concurrency never moved — correlation is unclear.
        let flat = [
            sample_at(0, 10, 10.0, 0.0),
            sample_at(250, 10, 10.0, 0.0),
            sample_at(500, 10, 120.0, 0.05),
            sample_at(750, 10, 120.0, 0.05),
            sample_at(1000, 10, 120.0, 0.05),
        ];
        let a = classify(&s, &rising);
        let b = classify(&s, &flat);
        assert_eq!(a.verdict, Verdict::Degrading);
        assert_eq!(b.verdict, Verdict::Degrading);
        assert!(a.confidence > b.confidence, "load-correlated degradation should be more certain");
        assert!(
            a.evidence.iter().any(|e| e.contains("tracked the load ramp")),
            "should credit the load correlation"
        );
        assert!(
            a.evidence.iter().any(|e| e.contains("knee at ~100 concurrent")),
            "should report the concurrency at the knee"
        );
    }

    #[test]
    fn recovery_after_load_eases_is_detected() {
        let base = 10.0;
        let samples = [
            sample_at(0, 5, 10.0, 0.0),
            sample_at(250, 50, 120.0, 0.05),
            sample_at(500, 100, 120.0, 0.05),
            sample_at(750, 150, 120.0, 0.05),
            sample_at(1000, 20, 12.0, 0.0),
            sample_at(1250, 10, 11.0, 0.0),
            sample_at(1500, 5, 10.0, 0.0),
        ];
        let d = detect_degradation(&samples, base, breach_threshold(&samples, base))
            .expect("sustained breach");
        assert_eq!(d.knee_concurrency, 50);
        assert_eq!(d.recovery_ms, Some(1250));
    }

    // --- W3: noise-relative threshold ---

    #[test]
    fn jitter_within_a_targets_own_noise_band_is_not_degradation() {
        // A moderate-latency target whose p99 normally swings 40–140 ms. A flat 3×
        // rule (150 ms) would fire on the 200 ms samples; the noise-relative bar
        // (median + 5·MAD of the jittery baseline) must not.
        let mut s = base_signals();
        s.baseline_ms = Some(50.0);
        s.http_2xx = 1000;
        let samples = [
            sample_at(0, 10, 40.0, 0.0),
            sample_at(250, 20, 130.0, 0.0),
            sample_at(500, 30, 50.0, 0.0),
            sample_at(750, 40, 140.0, 0.0),
            sample_at(1000, 50, 45.0, 0.0),
            sample_at(1250, 60, 135.0, 0.0),
            sample_at(1500, 70, 200.0, 0.0),
            sample_at(1750, 80, 205.0, 0.0),
            sample_at(2000, 90, 210.0, 0.0),
        ];
        let c = classify(&s, &samples);
        assert_ne!(c.verdict, Verdict::Degrading, "ordinary jitter must not read as a finding");
        assert_ne!(c.verdict, Verdict::Down);
    }

    // --- W4: 5xx / 408 blind spots ---

    #[test]
    fn fast_5xx_without_latency_blowup_is_down() {
        let mut s = base_signals();
        s.http_2xx = 100;
        s.http_5xx = 900; // app fails fast behind a proxy — instant 502s
        let samples = [sample(10.0, 0.0), sample(11.0, 0.0)]; // no latency signal
        let c = classify(&s, &samples);
        assert_eq!(c.verdict, Verdict::Down);
        assert!(c.verdict.is_finding());
        assert!(c.evidence.iter().any(|e| e.contains("server errors")));
    }

    #[test]
    fn request_timeouts_408_count_as_server_stress() {
        let mut s = base_signals();
        s.http_2xx = 600;
        s.http_408 = 400; // server timing out reading our requests under load
        let samples = [sample(10.0, 0.0), sample(11.0, 0.0)];
        let c = classify(&s, &samples);
        assert_eq!(c.verdict, Verdict::Degrading);
        assert!(c.evidence.iter().any(|e| e.contains("408")));
    }

    // --- W2/W5: multi-signal corroboration ---

    #[test]
    fn corroborating_signals_raise_confidence() {
        // Lone probe failure vs. the same probe failure with the service probe,
        // the latency curve, and the 5xx rate all agreeing.
        let mut lone = base_signals();
        lone.probe_baseline_ms = Some(5.0);
        lone.probe_total = 10;
        lone.probe_failures = 4; // 40% — Degrading

        let mut corr = lone.clone();
        corr.service_baseline_ok = true;
        corr.service_checks = 10;
        corr.service_failures = 3; // 30% service failure
        corr.http_2xx = 600;
        corr.http_5xx = 400; // 40% server errors
        let samples = [
            sample(10.0, 0.0),
            sample(120.0, 0.05),
            sample(120.0, 0.05),
            sample(120.0, 0.05),
        ];

        let a = classify(&lone, &[]);
        let b = classify(&corr, &samples);
        assert_eq!(a.verdict, Verdict::Degrading);
        assert_eq!(b.verdict, Verdict::Degrading);
        assert!(b.confidence > a.confidence, "agreement across signals should raise confidence");
    }
}
