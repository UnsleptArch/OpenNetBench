//! Authorization consent gate.
//!
//! This is a deliberate friction point, not a security control. The operator
//! must type the exact phrase to proceed. It cannot be satisfied by a flag or
//! config value — the intent is that a human affirmatively attests to
//! authorization every time the tool runs against a target.

use anyhow::{bail, Result};
use dialoguer::Input;
use std::io::IsTerminal;

const CONSENT_PHRASE: &str = "I HAVE AUTHORIZATION";

pub const LEGAL_NOTICE: &str = "\
OpenNetBench generates adversarial network load. Running it against systems you
do not own or lack explicit written authorization to test is illegal under the
Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), EU Directive
2013/40/EU, and equivalent legislation in most jurisdictions.

All traffic originates from THIS machine only. There is no spoofing, no
amplification, and no command-and-control. The single source IP means every
byte is attributable to you.";

/// Block until the operator types the exact consent phrase. Returns an error
/// (aborting the run) on any mismatch. Never auto-passes.
pub fn require_consent() -> Result<()> {
    // Enforce the TTY requirement ourselves rather than relying on the prompt
    // library's behavior: a piped/redirected stdin can never satisfy consent.
    if !std::io::stdin().is_terminal() {
        bail!("authorization requires an interactive terminal — refusing piped/non-TTY input");
    }

    let entered: String = Input::new()
        .with_prompt(format!("Type exactly '{CONSENT_PHRASE}' to proceed"))
        .allow_empty(true)
        .interact_text()?;

    // Exact match — no trimming. "Type exactly" means exactly; a padded phrase
    // is not the phrase.
    if entered != CONSENT_PHRASE {
        bail!("authorization phrase not confirmed — aborting");
    }
    Ok(())
}
