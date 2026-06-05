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

# Same, but run sandfence with its cwd set to <dir> — so the granted working
# copy is <dir> (sandfence grants the directory it's launched from).
sf_in() { local d="$1"; shift; ( cd "$d" && "$SF" "$@" ); }
assert_allow_in() {
  local d="$1" desc="$2"; shift 2
  if sf_in "$d" "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc (expected success, got failure)"; fi
}
assert_deny_in() {
  local d="$1" desc="$2"; shift 2
  if sf_in "$d" "$@" >/dev/null 2>&1; then bad "$desc (expected failure, but it succeeded)"; else ok "$desc"; fi
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
echo "[launch guard]"
# Launching with the working copy = $HOME (or /) is refused outright — it would
# grant the whole home tree read-write. The wrapper refuses before sandboxing.
assert_deny_in "$HOME" "launching from \$HOME is refused"          /usr/bin/true

echo
echo "[working copy]"

# A real git repo under the (non-temp) test root. Setup runs UNsandboxed and
# must fully succeed (set -e), else the probes below would test nothing.
wc="$root/wc"
rm -rf "$wc"; mkdir -p "$wc"
(
  set -e
  export GIT_CONFIG_GLOBAL=/dev/null   # hermetic: ignore the user's global signing/hooks/templates
  cd "$wc"
  git init -q
  git config user.email sandfence@test.local
  git config user.name  "sandfence test"
  printf 'hello\n' > tracked.txt
  git add -f tracked.txt               # -f: ignore any global excludes (~/.config/git/ignore)
  git commit -qm init
) >/dev/null 2>&1
head_before="$(git -C "$wc" rev-parse HEAD 2>/dev/null || true)"
if [ -z "$head_before" ]; then
  bad "setup: test git repo has no initial commit (setup failed — probes skipped)"
else
  # The working copy is read-write…
  assert_allow_in "$wc" "edit a tracked file in the working copy" /bin/sh -c 'echo more >> tracked.txt'
  assert_allow_in "$wc" "create a new file in the working copy"    /bin/sh -c 'echo x > newfile.txt'
  # …but its own .git is not writable, so history can't be rewritten.
  assert_deny_in  "$wc" "writing inside .git is denied"            /bin/sh -c 'echo x > .git/sandfence_intrusion'
  # git init in a scratch SUBDIR works (the deny is only the top-level .git), which
  # also proves git genuinely runs in the sandbox — so a commit failure below is the
  # sandbox denying the .git write, not git being broken.
  assert_allow_in "$wc" "git init in a scratch subdir is allowed"  /bin/sh -c 'rm -rf scratch && mkdir scratch && cd scratch && git init -q'
  # The commit must be denied AND must not have moved HEAD. Disable hooks/signing
  # so the attempt reaches the actual .git write rather than failing earlier.
  assert_deny_in  "$wc" "git commit is denied"                     git -c core.hooksPath=/dev/null -c commit.gpgsign=false commit --allow-empty -m probe
  head_after="$(git -C "$wc" rev-parse HEAD 2>/dev/null || true)"
  if [ "$head_after" = "$head_before" ]; then ok "git commit left HEAD unchanged";
  else bad "git commit moved HEAD ($head_before -> $head_after)"; fi
fi

echo
echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ]
