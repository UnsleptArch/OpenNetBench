#!/usr/bin/env bash
#
# OpenNetBench installer.
#
# Builds the release binary and installs it onto your PATH so `opennetbench`
# runs from anywhere. No root required for the default (per-user) install; use
# --system for a machine-wide install, and remember raw-socket vectors
# (syn/ack/icmp) still need `sudo opennetbench ...` at run time.
#
# Usage:
#   ./install.sh              # per-user install to ~/.local/bin
#   ./install.sh --system     # machine-wide install to /usr/local/bin (uses sudo)
#   ./install.sh --uninstall  # remove the installed binary
#
set -euo pipefail

BIN="opennetbench"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_BIN="${HOME}/.local/bin"
SYS_BIN="/usr/local/bin"

info()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()   { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

MODE="user"
[ "${1:-}" = "--system" ]    && MODE="system"
[ "${1:-}" = "--uninstall" ] && MODE="uninstall"

target_dir() { [ "$MODE" = "system" ] && echo "$SYS_BIN" || echo "$USER_BIN"; }

do_uninstall() {
  local removed=0
  for d in "$USER_BIN" "$SYS_BIN"; do
    if [ -e "$d/$BIN" ]; then
      info "Removing $d/$BIN"
      if [ -w "$d" ]; then rm -f "$d/$BIN"; else sudo rm -f "$d/$BIN"; fi
      removed=1
    fi
  done
  [ "$removed" = 1 ] && ok "Uninstalled." || warn "Nothing to uninstall."
  exit 0
}

[ "$MODE" = "uninstall" ] && do_uninstall

# 1. Toolchain check.
command -v cargo >/dev/null 2>&1 || die "cargo/Rust not found. Install from https://rustup.rs and re-run."
info "Using $(cargo --version)"

# 2. Build release.
info "Building release binary (this can take a minute)…"
( cd "$REPO_DIR" && cargo build --release )
SRC="$REPO_DIR/target/release/$BIN"
[ -x "$SRC" ] || die "Build succeeded but $SRC is missing."
ok "Built $SRC"

# 3. Install onto PATH.
DEST_DIR="$(target_dir)"
info "Installing to $DEST_DIR"
if [ "$MODE" = "system" ]; then
  sudo install -Dm755 "$SRC" "$DEST_DIR/$BIN"
else
  mkdir -p "$DEST_DIR"
  install -m755 "$SRC" "$DEST_DIR/$BIN"
fi
ok "Installed $DEST_DIR/$BIN"

# 4. PATH check for per-user installs.
if [ "$MODE" = "user" ] && ! printf '%s' ":$PATH:" | grep -q ":$USER_BIN:"; then
  warn "$USER_BIN is not on your PATH. Add this to your shell profile:"
  printf '\n    export PATH="%s:$PATH"\n\n' "$USER_BIN"
fi

# 5. Verify.
if command -v "$BIN" >/dev/null 2>&1; then
  ok "Ready. Try:  $BIN --list-presets"
else
  ok "Ready. Try:  $DEST_DIR/$BIN --list-presets"
fi
cat <<'EOF'

Quick start:
  opennetbench                                   # interactive
  opennetbench --list-presets                    # presets & tiers
  opennetbench --auto --target example.com       # probe → recommend → run
  sudo opennetbench --preset router --tier aggressive --target 192.168.1.254 --duration 40

Raw-socket vectors (syn/ack/icmp) require sudo. Authorized targets only.
EOF
