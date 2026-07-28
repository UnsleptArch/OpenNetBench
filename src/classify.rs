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

/// The peak p99 within any run of at least [`DEGRADE_CONSECUTIVE`] consecutive
/// samples that breached both the 3× ratio and the absolute delta over baseline.
/// `None` if no such sustained run exists (i.e. only transient spikes).
pub fn sustained_high_p99(samples: &[LatencySample], base: f64) -> Option<f64> {
    if base <= 0.0 {
        return None;
    }
    let mut run = 0usize;
    let mut run_peak = 0.0f64;
    let mut best: Option<f64> = None;
    for s in samples {
        let breached = s.p99_ms > base * 3.0 && s.p99_ms - base > MIN_DEGRADE_DELTA_MS;
        if breached {
            run += 1;
            run_peak = run_peak.max(s.p99_ms);
            if run >= DEGRADE_CONSECUTIVE {
                best = Some(best.map_or(run_peak, |b| b.max(run_peak)));
            }
        } else {
            run = 0;
            run_peak = 0.0;
        }
    }
    best
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
pub struct Signals {
    pub requests: u64,
    pub errors: u64,
    pub http_2xx: u64,
    pub http_3xx: u64,
    pub http_4xx: u64,
    pub http_403: u64,
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

    // 0. Health probe — independent ground truth about the target's availability.
    // This is the only signal that works for L4/raw vectors, and it overrides the
    // rest when it shows real impact.
    if sig.probe_total > 0 {
        if let Some(base) = sig.probe_baseline_ms {
            // Probes that failed because *we* ran out of local sockets/ports say
            // nothing about the target. If they dominate, the probe is unreliable
            // this run — don't let it decide anything; note it and fall through.
            let local = sig.probe_local_inconclusive;
            let conclusive = sig.probe_total.saturating_sub(local);
            if local * 2 > sig.probe_total {
                ev.push(format!(
                    "health probe unreliable: {}/{} checks failed on LOCAL socket exhaustion \
                     (our machine, not the target) — reduce per-vector concurrency for a clean read",
                    local, sig.probe_total
                ));
            } else if conclusive > 0 {
                let fail_frac = sig.probe_failures as f64 / conclusive as f64;
                let peak = sig.probe_peak_ms.unwrap_or(base);
                if fail_frac > 0.3 {
                    ev.push(format!(
                        "health probe: {:.0}% of conclusive connection checks to the target \
                         FAILED under load",
                        fail_frac * 100.0
                    ));
                    if local > 0 {
                        ev.push(format!("({local} further checks were inconclusive — local limits)"));
                    }
                    let verdict = if fail_frac > 0.7 { Verdict::Down } else { Verdict::Degrading };
                    return Classification {
                        verdict,
                        confidence: (0.6 + fail_frac * 0.3).min(0.9),
                        evidence: ev,
                    };
                }
                if base > 0.0 && peak > base * 3.0 && peak - base > MIN_DEGRADE_DELTA_MS {
                    ev.push(format!(
                        "health probe connect latency rose {base:.1}ms → {peak:.1}ms under load ({:.1}x)",
                        peak / base
                    ));
                    return Classification {
                        verdict: Verdict::Degrading,
                        confidence: 0.8,
                        evidence: ev,
                    };
                }
                ev.push(format!(
                    "health probe stable ({base:.1}ms baseline, {}/{} conclusive checks ok)",
                    conclusive - sig.probe_failures,
                    conclusive
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
        let sfail = sig.service_failures as f64 / sig.service_checks as f64;
        if sfail > 0.25 {
            ev.push(format!(
                "service probe: {:.0}% of independent requests got no usable answer under load, \
                 while the target still accepted TCP connections",
                sfail * 100.0
            ));
            let verdict = if sfail > 0.6 { Verdict::Down } else { Verdict::Degrading };
            return Classification {
                verdict,
                confidence: (0.6 + sfail * 0.3).min(0.9),
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

    let responses =
        sig.http_2xx + sig.http_3xx + sig.http_4xx + sig.http_403 + sig.http_429 + sig.http_5xx;

    let peak_p99 = samples.iter().map(|s| s.p99_ms).fold(0.0_f64, f64::max);
    let base = sig.baseline_ms.or_else(|| {
        samples
            .iter()
            .find(|s| s.error_rate < 0.1 && s.p99_ms > 0.0)
            .map(|s| s.p99_ms)
    });
    let tail_err = tail_error_rate(samples);

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

    // 3. Resource exhaustion — p99 blew past baseline under load, by both a
    // meaningful ratio AND a meaningful absolute amount (filters sub-ms noise),
    // AND for a SUSTAINED window (a single transient spike is not degradation).
    if let Some(base) = base {
        if let Some(sustained_p99) = sustained_high_p99(samples, base) {
            ev.push(format!(
                "p99 held at {:.1}ms vs {:.1}ms baseline ({:.1}x) for {}+ consecutive samples",
                sustained_p99,
                base,
                sustained_p99 / base,
                DEGRADE_CONSECUTIVE
            ));
            // Down if the tail shows near-total failure; else degrading.
            if tail_err > 0.8 || (responses > 0 && sig.http_5xx as f64 / responses as f64 > 0.5) {
                ev.push(format!("tail error rate {:.0}%", tail_err * 100.0));
                return Classification {
                    verdict: Verdict::Down,
                    confidence: 0.8,
                    evidence: ev,
                };
            }
            return Classification {
                verdict: Verdict::Degrading,
                confidence: 0.7,
                evidence: ev,
            };
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(p99: f64, err: f64) -> LatencySample {
        LatencySample {
            t_ms: 0,
            concurrency: 10,
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
}
