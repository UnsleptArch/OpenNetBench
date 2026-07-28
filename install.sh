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

# colour palette. respect NO_COLOR and non-tty output (pipes, CI) by blanking it.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'
  C_CYAN=$'\033[1;36m'; C_MAGENTA=$'\033[1;35m'; C_GREEN=$'\033[1;32m'
  C_YELLOW=$'\033[1;33m'; C_RED=$'\033[1;31m'; C_BLUE=$'\033[1;34m'
else
  C_RESET=''; C_DIM=''; C_BOLD=''; C_CYAN=''; C_MAGENTA=''; C_GREEN=''
  C_YELLOW=''; C_RED=''; C_BLUE=''
fi

info()  { printf '%s[*]%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die()   { printf '%s[x]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

rule() { printf '%s  ────────────────────────────────────────────────────────%s\n' "$C_DIM" "$C_RESET"; }

banner() {
  printf '\n'
  rule
  printf '%s   ▚▚▚  %sOpenNetBench%s  %s▚▚▚%s\n' "$C_CYAN" "$C_BOLD$C_MAGENTA" "$C_RESET" "$C_CYAN" "$C_RESET"
  printf '%s   single-origin adversarial load generator%s\n' "$C_DIM" "$C_RESET"
  rule
  printf '\n'
}

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

banner

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

# 0. don't run the whole thing as root. sudo is used only for the copy step.
#    building as root makes target/ root-owned, which then breaks later user
#    builds and can leave the installer copying a stale binary.
if [ "$(id -u)" -eq 0 ]; then
  die "don't run this whole script as root. use './install.sh --system' (it sudo's only the copy). running 'sudo ./install.sh' builds as root and poisons target/."
fi

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

# verify the copy actually took and matches what we just built — otherwise a
# stale/root-owned target or a silent copy failure looks like "success".
if ! cmp -s "$SRC" "$DEST_DIR/$BIN"; then
  die "install did not take: $DEST_DIR/$BIN does not match the built binary (permissions, or a stale root-owned target/?)"
fi
ok "verified it matches the fresh build"

# a stale system copy will shadow a user install under sudo (sudo's secure_path
# has /usr/local/bin but not ~/.local/bin), so flag it.
if [ "$MODE" = "user" ] && [ -e "$SYS_BIN/$BIN" ] && ! cmp -s "$SRC" "$SYS_BIN/$BIN"; then
  warn "$SYS_BIN/$BIN also exists and differs — 'sudo opennetbench' will run THAT older copy."
  warn "run './install.sh --system' to refresh it, or 'sudo rm $SYS_BIN/$BIN'."
fi

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
echo
printf '%squick start%s\n' "$C_BOLD$C_CYAN" "$C_RESET"
qs() { printf '  %s%-46s%s %s%s%s\n' "$C_GREEN" "$1" "$C_RESET" "$C_DIM" "$2" "$C_RESET"; }
qs "opennetbench"                                "interactive walkthrough"
qs "opennetbench --recon https://example.com"    "find + rank weak endpoints, no flood"
qs "opennetbench --list-presets"                 "what combos ship in the box"
qs "opennetbench --auto --target example.com"    "probe it, get a recommendation, run"
qs "sudo opennetbench --preset router --target 192.168.1.254 --duration 40" ""
echo
printf '%sraw vectors (syn/ack/icmp) need sudo. point it only at stuff you own or are%s\n' "$C_YELLOW" "$C_RESET"
printf '%scleared to hit. the consent gate will make you say so before anything fires.%s\n' "$C_YELLOW" "$C_RESET"
