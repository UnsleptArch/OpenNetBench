//! Authorization consent gate.
//!
//! This is a deliberate friction point, not a security control. Interactively,
//! the operator must type the exact phrase to proceed. Unattended/scripted runs
//! assert authorization instead with the explicit --i-am-authorized flag (see
//! main.rs); either way the operator is affirming they are authorized.

use anyhow::{bail, Result};
use dialoguer::Input;
use std::io::IsTerminal;

const CONSENT_PHRASE: &str = "I HAVE AUTHORIZATION";

pub const LEGAL_NOTICE: &str = "\
OpenNetBench generates adversarial network load. Running it against systems you
do not own or lack explicit written authorization to test is illegal under the
Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), EU Directive
2013/40/EU, and equivalent legislation in most jurisdictions.

Traffic originates from this machine. An optional SOCKS5 proxy routes L7/TCP
vectors; raw L4/UDP vectors always send from this host, so a proxy does not make
this an anonymity tool. There is no amplification and no command-and-control.
Run it only where you are authorized.";

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
