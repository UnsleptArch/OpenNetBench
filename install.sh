#!/usr/bin/env bash
#
# OpenNetBench installer.
#
# Builds the release binary and drops `opennetbench` on your PATH so it runs
# from anywhere. Per-user install needs no root. Machine-wide install (--system)
# uses sudo for the copy into /usr/local/bin. Either way the raw-socket vectors
# (syn/ack/icmp) still want `sudo opennetbench ...` when you actually run them,
# because raw sockets need the capability and that is not something the installer
# can hand you.
#
# Usage:
#   ./install.sh              per-user install to ~/.local/bin (default)
#   ./install.sh --system     machine-wide install to /usr/local/bin
#   ./install.sh --xdp        build with the AF_XDP line-rate backend enabled
#   ./install.sh --uninstall  rip it back out
#
# Flags stack, so `./install.sh --system --xdp` does what it looks like.

set -euo pipefail

BIN="opennetbench"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_BIN="${HOME}/.local/bin"
SYS_BIN="/usr/local/bin"

# tiny bit of colour so you can actually read the output
info()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()   { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

MODE="user"
FEATURES=""
for arg in "$@"; do
  case "$arg" in
    --system)    MODE="system" ;;
    --uninstall) MODE="uninstall" ;;
    --xdp)       FEATURES="--features xdp" ;;
    *)           die "unknown flag: $arg (try --system, --xdp, --uninstall)" ;;
  esac
done

target_dir() { [ "$MODE" = "system" ] && echo "$SYS_BIN" || echo "$USER_BIN"; }

# Uninstall walks both locations so it does not matter how you installed it.
do_uninstall() {
  local removed=0
  for d in "$USER_BIN" "$SYS_BIN"; do
    if [ -e "$d/$BIN" ]; then
      info "removing $d/$BIN"
      if [ -w "$d" ]; then rm -f "$d/$BIN"; else sudo rm -f "$d/$BIN"; fi
      removed=1
    fi
  done
  [ "$removed" = 1 ] && ok "gone." || warn "nothing to uninstall."
  exit 0
}
[ "$MODE" = "uninstall" ] && do_uninstall

# 1. toolchain
command -v cargo >/dev/null 2>&1 || die "no cargo on PATH. grab Rust from https://rustup.rs and run this again."
info "using $(cargo --version)"

# 2. build
info "building release${FEATURES:+ (with xdp)}, this takes a minute the first time..."
( cd "$REPO_DIR" && cargo build --release $FEATURES )
SRC="$REPO_DIR/target/release/$BIN"
[ -x "$SRC" ] || die "build finished but $SRC is not there. something is off."
ok "built $SRC"

# 3. drop it on PATH
DEST_DIR="$(target_dir)"
info "installing to $DEST_DIR"
if [ "$MODE" = "system" ]; then
  sudo install -Dm755 "$SRC" "$DEST_DIR/$BIN"
else
  mkdir -p "$DEST_DIR"
  install -m755 "$SRC" "$DEST_DIR/$BIN"
fi
ok "installed $DEST_DIR/$BIN"

# 4. make sure the per-user bin dir is actually on PATH, and keep it that way
#    across new shells. system installs land in /usr/local/bin which is already
#    on everyones PATH so we skip this there.
if [ "$MODE" = "user" ] && ! printf '%s' ":$PATH:" | grep -q ":$USER_BIN:"; then
  # pick the rc file for whatever shell youre running
  case "$(basename "${SHELL:-bash}")" in
    zsh)  RC="${HOME}/.zshrc" ;;
    fish) RC="${HOME}/.config/fish/config.fish" ;;
    *)    RC="${HOME}/.bashrc" ;;
  esac
  LINE="export PATH=\"$USER_BIN:\$PATH\""
  [ "$(basename "${SHELL:-bash}")" = "fish" ] && LINE="set -gx PATH $USER_BIN \$PATH"

  if [ -f "$RC" ] && grep -qF "$USER_BIN" "$RC"; then
    warn "$USER_BIN not on PATH this session but its already in $RC. open a new shell."
  else
    printf '\n# added by OpenNetBench installer\n%s\n' "$LINE" >> "$RC"
    ok "added $USER_BIN to your PATH in $RC"
    warn "run 'source $RC' or open a new shell to pick it up now."
  fi
fi

# 5. done
echo
ok "ready."
cat <<'EOF'

quick start:
  opennetbench                                   interactive walkthrough
  opennetbench --list-presets                    what combos ship in the box
  opennetbench --auto --target example.com       probe it, get a recommendation, run
  sudo opennetbench --preset router --target 192.168.1.254 --duration 40

raw vectors (syn/ack/icmp) need sudo. point it only at stuff you own or are
cleared to hit. the consent gate will make you say so before anything fires.
EOF
