#!/usr/bin/env bash
set -uo pipefail

# ============================================================================
# test.sh <dir> — enforcement tests for sandfence.
#
# What matters is whether the policy actually allows/denies the right things,
# so these probes run real commands INSIDE the sandbox and assert each outcome.
#
#   ./test.sh ~/sandfence-tests   # a REAL path — NOT /tmp or /var/folders
#
# It refuses a temp dir on purpose: /tmp and /var/folders are granted
# read-write, which would mask the file-isolation tests in later steps.
#
# NOTE: sandbox-exec cannot nest. Run this in a plain shell on macOS, NOT from
# inside an agent session that is itself sandboxed.
# ============================================================================

here="$(cd "$(dirname "$0")" && pwd)"
SF="$here/sandfence.sh"

# --- arg: a real working directory (reject temp) ---------------------------
root="${1:-}"
[ -n "$root" ] || { echo "usage: $0 <dir>   (a real path, not /tmp or /var/folders)" >&2; exit 2; }
mkdir -p "$root" || exit 2
root="$(cd "$root" && pwd -P)"
case "$root" in
  /tmp/*|/private/tmp/*|/var/folders/*|/private/var/folders/*|/tmp|/var/folders)
    echo "test.sh: refusing a temp dir ($root) — it's granted rw and masks isolation tests" >&2
    exit 2 ;;
esac

# $HOME must be a real, writable dir — the HOME probes below create/read files
# there, and a broken $HOME would make them fail for the wrong reason (a missing
# file reads as a "denial", a false PASS).
[ -d "$HOME" ] && [ -w "$HOME" ] || {
  echo "test.sh: \$HOME ($HOME) must be an existing writable directory" >&2; exit 2; }

# --- tiny assert framework --------------------------------------------------
pass=0; fail=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=$((fail+1)); }
skip() { printf '  \033[33mSKIP\033[0m  %s\n' "$1"; }

# assert_allow "desc" <cmd...>   — expect the sandboxed command to SUCCEED (exit 0)
assert_allow() {
  local desc="$1"; shift
  if "$SF" "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc (expected success, got failure)"; fi
}
# assert_deny  "desc" <cmd...>   — expect the sandboxed command to FAIL (non-zero)
assert_deny() {
  local desc="$1"; shift
  if "$SF" "$@" >/dev/null 2>&1; then bad "$desc (expected failure, but it succeeded)"; else ok "$desc"; fi
}

echo "sandfence enforcement tests"
echo "  script:  $SF"
echo "  workdir: $root"
echo

# --- default-deny baseline --------------------------------------------------
echo "[baseline]"

# A passthrough command runs at all (exec + dyld work under the baseline).
assert_allow "a passthrough command runs"           /usr/bin/true
assert_allow "shell + coreutils run"                 /bin/sh -c 'exit 0'

# $HOME is not writable: a redirect into it must fail, and leave no file.
home_probe="$HOME/.sandfence_write_probe.$$"
rm -f "$home_probe"
assert_deny  "write into \$HOME is denied"           /bin/sh -c "echo x > '$home_probe'"
if [ -e "$home_probe" ]; then bad "no file left in \$HOME after denied write"; rm -f "$home_probe";
else ok "no file left in \$HOME after denied write"; fi

# A secret in $HOME is not readable. Create it OUTSIDE the sandbox and confirm
# it IS readable there — so the in-sandbox denial below is provably the sandbox's
# doing, not a missing/unreadable file (which would be a false PASS).
read_probe="$HOME/.sandfence_read_probe.$$"
printf 'TOPSECRET\n' > "$read_probe" || { echo "setup: cannot create read probe" >&2; exit 2; }
/bin/cat "$read_probe" >/dev/null 2>&1 || { echo "setup: read probe not readable unsandboxed" >&2; rm -f "$read_probe"; exit 2; }
assert_deny  "reading a file under \$HOME is denied"  /bin/cat "$read_probe"
rm -f "$read_probe"

# ~/.ssh specifically is denied. Read-only probe: only run it if ~/.ssh already
# exists — never create or remove it, so the test can't touch the user's files.
if [ -d "$HOME/.ssh" ]; then
  assert_deny "listing ~/.ssh is denied"             /bin/ls "$HOME/.ssh"
else
  skip "listing ~/.ssh is denied (~/.ssh does not exist)"
fi

echo
echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ]
