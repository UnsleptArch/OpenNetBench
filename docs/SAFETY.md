# Safety Model and Threat Analysis

*A formal statement of what this tool is, what it deliberately is not, and — for each
safety property it claims — the structural feature of the codebase that enforces it. The
governing principle is that a safety property asserted only in prose is a promise, whereas a
safety property that falls out of the shape of the source is a guarantee. This document
concerns itself only with the latter, and names the enforcing code for each.*

---

## Table of Contents

1. [Purpose and Posture](#1-purpose-and-posture)
2. [Definitions: Tool vs. Platform](#2-definitions-tool-vs-platform)
3. [The Trust Boundary](#3-the-trust-boundary)
4. [The Five Structural Guarantees](#4-the-five-structural-guarantees)
5. [Threat Model](#5-threat-model)
6. [Why Single-Origin Is a Feature, Not a Limitation](#6-why-single-origin-is-a-feature-not-a-limitation)
7. [The Consent Mechanism](#7-the-consent-mechanism)
8. [Residual Risks and Honest Limitations](#8-residual-risks-and-honest-limitations)
9. [Legal Framework and Operator Responsibility](#9-legal-framework-and-operator-responsibility)
10. [Auditor's Checklist](#10-auditors-checklist)

---

## 1. Purpose and Posture

OpenNetBench generates real denial-of-service load in order to answer a single question:
*when subjected to the traffic real attackers use, does this target hold or break?* It is an
instrument of **defensive** security — resilience testing, capacity validation, incident
rehearsal — and its entire design is organised around drawing a hard, enforced line between
an adversarial *testing tool* and an *attack platform*.

That line is not maintained by policy, documentation, or operator good intentions. It is
maintained by the *absence* of certain code and the *presence* of certain gates, both of
which an auditor can verify directly against the source tree. The sections below state each
property and cite the enforcement. Where a capability that a weaponised tool would have is
missing, that absence is deliberate and load-bearing — it is the design, not a gap someone
forgot to fill.

---

## 2. Definitions: Tool vs. Platform

It is worth being precise about the categories, because the whole safety argument rests on
the tool sitting firmly on one side of the divide.

An **attack platform** is characterised by capabilities that multiply or conceal force:
distribution across many origins (botnet, stresser fleet), reflection and amplification
(borrowing a third party's bandwidth), source concealment (spoofing, anonymising relays as a
core feature), and remote command-and-control (a coordinator directing distributed agents).
These are the capabilities that turn a testing technique into a weapon usable at scale
against unconsenting third parties.

An **adversarial testing tool** reproduces the *traffic patterns* of an attack from a single,
attributable origin, under explicit authorisation, so that a defender can measure resilience.
It has the attacker's *techniques* without the attacker's *reach*.

OpenNetBench is deliberately and structurally the latter. It is not a botnet, not a
command-and-control framework, not a stresser service, and not "hping3 with a spoofing dial."
Each of those characterisations corresponds to a capability that is absent from the tree by
construction, as §4 details.

---

## 3. The Trust Boundary

The tool's trust boundary is the single host it runs on. Everything inside that boundary —
the load engine, the classifier, the reconnaissance module, the probes — is code the operator
controls and can inspect. Everything that crosses the boundary is one of exactly two things:

1. **Attack traffic**, directed at the target the operator named, optionally routed through a
   SOCKS5 proxy the operator configured (for the L7 and TCP vectors only).
2. **Probe traffic**, directed at the same target — the health probe (TCP connect) and the
   service probe (HTTP GET) — always sent *directly*, never through the proxy, because a
   proxied probe would measure the proxy rather than the target.

There is no third category. Nothing listens for inbound control. Nothing phones home. Nothing
coordinates with another machine. The complete egress of a run is attack traffic plus probes,
all to the named target; the complete ingress is the target's responses to that traffic. This
minimal, auditable boundary is the foundation on which the five guarantees rest.

---

## 4. The Five Structural Guarantees

None of these is a property you must trust. Each is a consequence of how the tree is built,
and each cites the mechanism.

### 4.1 Single Origin

**Claim.** Every packet leaves this one host (or the SOCKS5 proxy configured for the L7/TCP
path). The tool cannot be pointed at a fleet.

**Enforcement.** There is no agent protocol, no peer-discovery mechanism, and no coordination
or control channel anywhere in the source. The capability to direct traffic from multiple
origins simply does not exist as code — there is no fleet-pointing function to invoke. This is
verifiable by inspection: a grep of the tree for coordination primitives (listeners, agent
handshakes, remote dispatch) returns nothing, because nothing is there. The single-origin
property is the *default and only* mode because no other mode was implemented.

### 4.2 No Spoofing

**Claim.** The raw vectors source from the machine's real address. There is no
source-address parameter.

**Enforcement.** The raw vectors compute their IP and TCP checksums from the host's real
source address (`local_src_ipv4`), and the full-frame transmit path uses the host's real
source MAC, resolved from the system's own routing and ARP state (see
[INTERNALS.md](INTERNALS.md) §8–§9). There is no code path that accepts a forged source
address, because none was written. Beyond the safety rationale, spoofing would be functionally
self-defeating for the stateful TCP vectors: a spoofed SYN's SYN-ACK would be delivered to the
forged address, so the vector would generate no useful pressure on a target that validates the
handshake. The absence of spoofing is thus both a safety invariant and a correctness one.

### 4.3 No Amplification

**Claim.** Every byte that reaches the target was generated locally. Outbound equals impact,
one to one.

**Enforcement.** There are no reflection vectors in the catalogue — no DNS, NTP, memcached, or
any other reflect-and-amplify primitive. The twenty vectors are enumerated in
[VECTORS.md](VECTORS.md); every one of them generates its traffic directly on the host and
sends it directly to the target. The tool cannot borrow a third party's bandwidth because it
has no reflector to borrow through. The operator's own uplink is therefore a hard ceiling on
impact — which is a safety property, not merely a performance one.

### 4.4 No Command and Control

**Claim.** There is no remote-control surface. Nothing listens; nothing phones home.

**Enforcement.** The only network egress is the attack traffic and the two probes, all to the
named target (§3). No socket is opened in listen mode for control purposes; there is no
second-stage payload, no beacon, no callback. Terminating the process terminates the traffic
instantly and completely — there is no residual component running on another machine to keep
it alive. This is reinforced by the cooperative-shutdown design ([INTERNALS.md] §7): stopping
the process propagates a shutdown signal that every worker observes, with a bounded grace
period after which any straggler is force-aborted. Stop the process, stop the traffic, with no
exceptions and nowhere for the traffic to hide.

### 4.5 Consent on Every Run

**Claim.** Every interactive run is gated behind an explicit, human, terminal-bound consent
step that a script cannot forge.

**Enforcement.** The gate lives in `auth.rs`. An interactive run halts until the operator
types an exact phrase at a real terminal. The gate checks for a TTY and compares the typed
phrase exactly, so a piped `yes`, a redirected file, or an environment variable will not
satisfy it, and a saved configuration does not buy past it. Unattended and scripted runs do
not bypass consent silently — they must assert authorisation explicitly with the
`--i-am-authorized` flag, which stands in for both the typed consent phrase and the final
go/no-go confirmation. That flag is a deliberate act on the command line, not a default, so
whether interactive or scripted, the operator steps over the line on purpose rather than
tripping over it by accident. See §7 for the full mechanism.

---

## 5. Threat Model

A safety document should state the adversary it is reasoning about and what is in and out of
scope.

### 5.1 What the tool defends against

The tool is designed so that its *own structure* prevents it from being trivially repurposed
as a weapon at scale. The specific misuse-escalation paths it structurally forecloses are:

- **Escalation to distributed attack.** Foreclosed by §4.1 — there is no coordination code, so
  the tool cannot become the controller of a distributed attack without being rewritten.
- **Escalation to amplified attack.** Foreclosed by §4.3 — no reflector exists, so impact
  cannot exceed the operator's own bandwidth.
- **Escalation to untraceable attack.** Substantially foreclosed by §4.2 and the direct-egress
  design — the raw and UDP vectors always carry the operator's real address, so those vectors
  are inherently attributable. (The SOCKS5 proxy for the L7/TCP path is an intentional
  exception with stated limits; see §6 and §8.)
- **Accidental firing.** Foreclosed by §4.5 — no run reaches the engine without an explicit,
  non-forgeable authorisation step.

### 5.2 What the tool does not and cannot defend against

Honesty requires stating the boundary of the safety argument. The tool cannot enforce:

- **Authorisation itself.** The consent gate proves *intent*, not *entitlement*. The tool has
  no way to verify that the operator is in fact authorised to test the named target; that
  verification is external and human. This is the single most important limitation and it is
  addressed directly in §9.
- **Misuse by a determined operator with source access.** A safety model built on the absence
  of code is a safety model against *casual* misuse and against the tool being *shipped* as a
  weapon. It is not a cryptographic control. A sufficiently determined operator can modify open
  source. The claim is not "this cannot be weaponised by anyone ever," which no open-source
  tool can make; the claim is "as distributed, this tool lacks the capabilities that
  distinguish a weapon from a testing instrument, and adding them is a visible, deliberate act."
- **The consequences of pointing it at the wrong target.** The tool generates real load. Aimed
  at infrastructure the operator does not control, it will cause a real outage and constitute a
  real crime (§9). The gate is a speed bump against accident, not a shield against intent.

---

## 6. Why Single-Origin Is a Feature, Not a Limitation

It is tempting to read "single origin, no amplification, no spoofing" as a list of things the
tool *cannot* do, i.e. as weakness. The design thesis is the opposite: for a *legitimate*
resilience tool, containment is worth more than raw reach.

With no proxy in play, every run originates from one attributable address. The operator's own
logs and the target's logs both show it; the traffic is instantly containable and instantly
stoppable; there is no scattered infrastructure to clean up and no second stage on another
machine. That containment is precisely the property a defender wants from a tool they are
running against their own production infrastructure — the last thing a blue team wants is a
test tool whose traffic they cannot cleanly identify, attribute, and halt.

And the containment costs nothing in relevant capability, because a single box is already more
than enough for realistic targets. The send path exceeds 10 GbE line rate from one desktop
(see [PERFORMANCE.md](PERFORMANCE.md)); for any target at or below 10 GbE the tool is bound by
the wire, not by its single-origin design. The firepower a botnet would add is irrelevant to
the targets this tool is built to test. Reach was not sacrificed for safety; it was never
needed.

The one deliberate exception is the optional SOCKS5 proxy for the L7 and TCP vectors, provided
so an operator can test from a specific network vantage point. Its limits are stated plainly
and enforced: it carries TCP only, so the raw L3/L4 vectors and UDP/DNS still egress from the
host's real address, and the tool *warns* when a proxied run includes such vectors. It is a
routing convenience, not a cloak, and the tool never presents it as anonymity (§8).

---

## 7. The Consent Mechanism

The consent gate deserves a precise description because it is the one active safety control
(as opposed to the passive controls of absent capability).

**Interactive path.** Before any traffic is generated, `auth.rs` presents a legal notice and
requires the operator to type an exact phrase. The implementation:

- **Requires a TTY.** The gate checks that it is attached to a real terminal. This defeats the
  most common accidental-automation vector — piping input into the process — because a pipe is
  not a TTY.
- **Compares the phrase exactly.** A partial match, a different phrase, or an environment
  variable does not satisfy it. There is no "assume yes" flag that also works interactively;
  the interactive path *always* requires the human keystroke.
- **Cannot be satisfied by configuration.** Loading a saved plan with `--config` does not carry
  a stored consent; the gate is re-presented. Consent is per-run and per-human, not a property
  that can be serialised.

**Scripted path.** Genuine automation (CI, unattended runs) needs a non-interactive route, and
pretending otherwise would simply push operators toward hacks that defeat the gate's intent.
The sanctioned route is the explicit `--i-am-authorized` flag, which asserts authorisation and
stands in for both the typed phrase and the final confirmation. The design point is that this
is a *visible, auditable, deliberate* token on the command line — it appears in shell history,
in CI configuration, in process listings — not a silent default. An operator using it is on
record as having asserted authorisation.

**What consent is not.** The gate establishes that the operator *intended* to run this load
against this target and *asserted* they were cleared to. It is a design feature that forces
deliberateness. It is emphatically **not** legal cover, and it does not make lawful anything
that was not already lawful. That is the subject of §9.

---

## 8. Residual Risks and Honest Limitations

A safety model that lists only its strengths is marketing. The genuine residual risks:

- **The proxy is not anonymity.** The SOCKS5 proxy routes only the L7 and TCP vectors. The raw
  L4 vectors and UDP/DNS always leave from the host's real address. An operator who mentally
  models the proxy as a cloak will be wrong about attribution for a significant fraction of the
  vectors. The tool warns at runtime when a proxied run includes vectors the proxy cannot
  carry, but the conceptual error is the operator's to avoid. The tool is not, and does not
  claim to be, an anonymity tool.
- **The tool cannot verify authorisation.** Restated from §5.2 because it is the central
  limitation: consent proves intent, not entitlement.
- **Real load has real consequences.** A misconfigured target, a shared-tenancy environment, or
  an unexpectedly fragile intermediary (a NAT, a stateful firewall between the operator and the
  target) can be affected by a run aimed at something else on the same path. The state-exhaustion
  vectors in particular pressure *intermediary* state, not just the endpoint's.
- **Local self-impact.** The tool works hard *not* to mistake its own resource exhaustion for
  the target's (fd budgeting and local-exhaustion detection; see [INTERNALS.md] §5, §10), but a
  sufficiently aggressive run can still degrade the operator's own host or local network segment
  before it degrades a well-provisioned target.

These are stated so that an operator plans around them rather than discovering them mid-run.

---

## 9. Legal Framework and Operator Responsibility

The tool generates genuine denial-of-service load. Directed at systems the operator does not
own or lack written authorisation to test, that is a crime — under the Computer Fraud and Abuse
Act (United States), the Computer Misuse Act (United Kingdom), EU Directive 2013/40/EU, and the
equivalent statute in essentially every jurisdiction. Authorisation is the one control the tool
cannot enforce for the operator, and it is therefore entirely the operator's responsibility.

Legitimate use looks like exactly one of the following:

- Infrastructure the operator **owns**.
- A client's infrastructure the operator has been **hired to test, in writing**.
- A **laboratory** the operator built.
- A **CTF** or intentionally-vulnerable environment.

Anything else is out of scope for this tool's intended purpose, and the consent gate's
existence does not change that. The gate is a design feature that enforces deliberateness; it
is not, and was never intended to be, legal cover.

This project's stance aligns with the U.S. Department of Justice's articulation of *good-faith
security research*: testing conducted to improve the security of the class of systems tested,
carried out in a manner designed to avoid harm, on systems the researcher is authorised to
assess. The tool is built to make good-faith use easy and casual misuse structurally awkward;
the good faith itself must be supplied by the operator.

---

## 10. Auditor's Checklist

For a reviewer verifying the safety claims against the source, the specific things to confirm:

1. **No coordination code.** Confirm there is no agent protocol, listener-for-control,
   peer-discovery, or remote-dispatch anywhere in the tree. (§4.1)
2. **No source-address parameter.** Confirm the raw vectors derive source IP/MAC from host
   state (`local_src_ipv4`, ARP/route resolution) and expose no forge knob. (§4.2,
   [INTERNALS.md] §8–§9)
3. **No reflection vector.** Confirm the vector catalogue contains no reflect-and-amplify
   primitive; every vector generates locally. (§4.3, [VECTORS.md])
4. **No inbound control surface.** Confirm the only egress is attack + probe traffic to the
   named target and nothing listens for control. (§4.4)
5. **Consent gate integrity.** Confirm `auth.rs` requires a TTY, compares the phrase exactly,
   is not satisfiable by config/env/pipe, and that the only non-interactive route is the
   explicit `--i-am-authorized` flag. (§4.5, §7)
6. **Shutdown completeness.** Confirm that process termination stops all traffic, with the
   grace-bounded force-abort of stragglers and no residual second stage. (§4.4, [INTERNALS.md]
   §7)
7. **Proxy honesty.** Confirm the proxy carries TCP only and that the tool warns when a proxied
   run includes raw/UDP vectors it cannot route. (§6, §8)

Each item is verifiable by reading the cited code, which is the point: the safety model is a
property of the source, and this checklist is how a skeptic confirms it rather than takes it on
faith. **I usually hate safety notes like this as they just feel undermining and very "legal" and while I know that this note probably won't stop anyone with bad intentions I much more felt a reason to include one in this project because of how easy and disruptive it is to use. Please please please don't get yourself in trouble while using projects like this, there can be some really big consequences.** 
