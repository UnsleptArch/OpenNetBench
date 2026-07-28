# Safety model

This tool generates real denial-of-service load. The design draws a hard line between "adversarial testing tool" and "attack platform," and the line is enforced by how the code is built, not by a paragraph of good intentions. Here is exactly where it sits and why.

## What it is

A single-origin resilience tester. It hits infrastructure you own or are authorized to test, from one box, with traffic patterns real attackers use, and it tells you whether the target held. That is the entire job.

## What it deliberately is not

It is not a botnet, not a C2 framework, not a stresser service, and not a fancy hping3 with a spoofing dial. Those capabilities were left out on purpose, and leaving them out is the whole point of the design, not a gap someone forgot to fill.

## The five guarantees, and how the code enforces each one

None of these is a promise you have to trust. Each one falls out of the structure of the tree.

**Single origin.** Every packet leaves this one host, or the SOCKS5 proxy you point it at for the L7 and TCP vectors. There is no agent protocol, no peer discovery, no coordination or control channel anywhere in the source. You cannot point it at a fleet because there is no fleet-pointing code to invoke. Grep the tree, there is nothing to find.

**No spoofing.** The raw vectors compute their IP and TCP checksums from the machine's real source address (`local_src_ipv4`) and the full-frame path uses the real source MAC. There is no source-address parameter to set. It is not that spoofing is discouraged, it is that it is not wired up, and it would break the stateful TCP vectors anyway since the SYN-ACK would come back to whatever address you faked.

**No amplification.** There are no reflection vectors. No DNS, NTP, memcached or any other reflect-and-amplify primitive exists in the tool. Every byte that hits the target was generated locally on your box, so your outbound is your impact, one to one. You cannot borrow someone else's bandwidth with this.

**No command and control.** The only network egress is the attack traffic and the two probes, and all of it goes to the target you named. There is no remote-control surface, nothing listens, nothing phones home. Kill the process and the traffic stops instantly and completely, there is no second stage sitting on another machine.

**Consent on every run.** Every interactive run stops at a gate in `auth.rs` that makes you type an exact phrase at a real terminal. It checks for a TTY and compares the phrase exactly, so a piped `yes` or an environment variable will not satisfy it, and a saved config does not buy you out of it. Unattended and scripted runs assert authorization instead with the explicit `--i-am-authorized` flag. That is a deliberate thing you put on the command line, not a silent default, so either way you are stepping over the line on purpose rather than tripping over it by accident.

## Why single origin is a feature

With no proxy in play, every run is instantly containable and comes from one address: your logs show it, the target's logs show it. Point a proxy at it and the L7 and TCP traffic routes through that instead, but the raw L4 and UDP vectors still leave from your real address, so this is not an anonymity tool and you should not treat it as one. Either way there is no scattered infrastructure and no second stage sitting on another machine. Stop the process, stop the traffic, done. That containment is worth more for a legitimate testing tool than raw firepower is, and the tool already pushes past 10GbE from one box anyway (see [PERFORMANCE.md](PERFORMANCE.md)).

## Your responsibility

The consent gate is a design feature. It is not legal cover and it does not make anything legal that was not already.

Point this only at infrastructure you own or have explicit written authorization to test. Running it against systems you do not control is a crime under the Computer Fraud and Abuse Act in the US, the Computer Misuse Act in the UK, EU Directive 2013/40/EU, and the equivalent law wherever you happen to be. Authorization is the one thing the tool cannot enforce for you, so that part is entirely on you.

Legitimate use looks like your own systems, a lab you built, a CTF, or a client that hired you to hit them and put it in writing.
