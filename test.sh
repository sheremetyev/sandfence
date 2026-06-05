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
  # git runs without warning about the ungranted global excludes file.
  giterr="$(sf_in "$wc" git status 2>&1 >/dev/null)"
  if printf '%s' "$giterr" | grep -q 'Operation not permitted'; then
    bad "git status emits no 'Operation not permitted' warning (got: $giterr)"
  else ok "git status emits no 'Operation not permitted' warning"; fi
fi

echo
echo "[-r / -w]"
ro="$root/extra-ro"; rw="$root/extra-rw"
rm -rf "$ro" "$rw"; mkdir -p "$ro" "$rw"
printf 'readme\n' > "$ro/file.txt"
( cd "$rw" && git init -q ) >/dev/null 2>&1     # give the -w dir a .git to test the carve-out
assert_deny_in  "$wc" "a dir is NOT readable without -r"      /bin/cat "$ro/file.txt"
assert_allow_in "$wc" "-r dir: file is readable"              -r "$ro" /bin/cat "$ro/file.txt"
assert_deny_in  "$wc" "-r dir: not writable"                  -r "$ro" /bin/sh -c "echo x > '$ro/new.txt'"
assert_allow_in "$wc" "-r file: a single file is readable"    -r "$ro/file.txt" /bin/cat "$ro/file.txt"
assert_allow_in "$wc" "-w dir: writable"                      -w "$rw" /bin/sh -c "echo x > '$rw/new.txt'"
if [ -d "$rw/.git" ]; then
  assert_deny_in "$wc" "-w dir: its own .git is write-denied"  -w "$rw" /bin/sh -c "echo x > '$rw/.git/intrusion'"
else
  bad "setup: could not git-init the -w test dir (.git probe skipped)"
fi

echo
echo "[agents]"
# The claude / codex bundles (--claude / --codex, or the agent as the tool) grant each agent's
# own binary + state dir — auth lives in a file there (~/.claude/.credentials.json, ~/.codex/
# auth.json), never the Keychain — while write-denying the persistence files (settings.json /
# config.toml) that would otherwise fire hooks on a later UNsandboxed run. We drive the bundle
# with the FLAGS (they apply a bundle regardless of the command actually run) plus a harmless
# probe, with HOME redirected to an isolated fake home so nothing touches your real ~/.claude /
# ~/.codex (same trick as the jj XDG test). The bundle reads $HOME from the env, so a redirected
# HOME relocates every agent grant under the test root.
fakehome="$root/fakehome"
rm -rf "$fakehome"
mkdir -p "$fakehome/.claude" "$fakehome/.codex" "$fakehome/.ssh" "$fakehome/Library/Keychains"
# Allow-probe targets must be readable UNsandboxed first, so an in-sandbox denial is provably the
# sandbox's doing and not a missing file (a false PASS) — same discipline as the baseline probes.
printf '{"claudeAiOauth":{}}\n'  > "$fakehome/.claude/.credentials.json"
printf '{"ORIG":true}\n'         > "$fakehome/.claude/settings.json"
printf 'ORIG\n'                  > "$fakehome/.codex/auth.json"
printf 'model = "orig"\n'        > "$fakehome/.codex/config.toml"
printf 'KEYCHAINSECRET\n'        > "$fakehome/Library/Keychains/login.keychain-db"

sf_home() { ( cd "$wc" && HOME="$fakehome" "$SF" "$@" ); }   # sandfence from the workspace, fake HOME
assert_allow_home() { local d="$1"; shift; if sf_home "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d (expected success, got failure)"; fi; }
assert_deny_home()  { local d="$1"; shift; if sf_home "$@" >/dev/null 2>&1; then bad "$d (expected failure, but it succeeded)"; else ok "$d"; fi; }

# claude: own state reachable (incl. the file-based credential), so the agent can authenticate.
assert_allow_home "claude: own ~/.claude/.credentials.json is readable"  --claude /bin/cat "$fakehome/.claude/.credentials.json"
assert_allow_home "claude: own ~/.claude state dir is writable"          --claude /bin/sh -c "echo x > '$fakehome/.claude/state_probe'"
# …but settings.json is write-denied (it carries hooks/statusLine/apiKeyHelper that would run on a
# later UNsandboxed claude). Check the file CONTENT, not just exit code: it must be byte-unchanged.
sf_home --claude /bin/sh -c "echo CLOBBER > '$fakehome/.claude/settings.json'" >/dev/null 2>&1
if grep -q CLOBBER "$fakehome/.claude/settings.json" 2>/dev/null; then
  bad "claude: settings.json write is denied (persistence guard)"
else ok "claude: settings.json write is denied (persistence guard)"; fi
# The login Keychain is never granted, even with the claude bundle active.
assert_deny_home "claude: login Keychain is denied"                      --claude /bin/cat "$fakehome/Library/Keychains/login.keychain-db"

# codex: own state incl. auth.json writable (it stores + refreshes its token there)…
assert_allow_home "codex: own ~/.codex/auth.json is writable"            --codex /bin/sh -c "echo x >> '$fakehome/.codex/auth.json'"
# …but config.toml (MCP servers / notify hooks → run on a later UNsandboxed codex) is write-denied.
sf_home --codex /bin/sh -c "echo CLOBBER > '$fakehome/.codex/config.toml'" >/dev/null 2>&1
if grep -q CLOBBER "$fakehome/.codex/config.toml" 2>/dev/null; then
  bad "codex: config.toml write is denied (persistence guard)"
else ok "codex: config.toml write is denied (persistence guard)"; fi

# codex node-runtime grant is restricted to the canonical nvm layout (~/.nvm/versions/node/<v>),
# matched positively. A real nvm-style version dir is granted read-only…
nvmdir="$fakehome/.nvm/versions/node/v99"; mkdir -p "$nvmdir/bin" "$nvmdir/lib"
: > "$nvmdir/bin/node"
printf '#!/bin/sh\nexit 0\n' > "$nvmdir/bin/codex"; chmod +x "$nvmdir/bin/codex"
printf 'NODELIB\n' > "$nvmdir/lib/marker"
if ( cd "$wc" && HOME="$fakehome" PATH="$nvmdir/bin:$PATH" "$SF" --codex /bin/cat "$nvmdir/lib/marker" ) >/dev/null 2>&1; then
  ok "codex: an nvm node version dir is granted read-only"
else bad "codex: an nvm node version dir is granted read-only (expected readable)"; fi
# …but a NON-nvm codex (e.g. ~/.local/bin/codex) must NOT auto-grant its prefix — that would
# read-expose all of ~/.local. A secret under ~/.local/share stays unreadable.
mkdir -p "$fakehome/.local/bin" "$fakehome/.local/share"
: > "$fakehome/.local/bin/node"
printf '#!/bin/sh\nexit 0\n' > "$fakehome/.local/bin/codex"; chmod +x "$fakehome/.local/bin/codex"
printf 'LOCALSECRET\n' > "$fakehome/.local/share/secret"
if ( cd "$wc" && HOME="$fakehome" PATH="$fakehome/.local/bin:$PATH" "$SF" --codex /bin/cat "$fakehome/.local/share/secret" ) >/dev/null 2>&1; then
  bad "codex: a non-nvm prefix (~/.local/bin) does NOT grant ~/.local"
else ok "codex: a non-nvm prefix (~/.local/bin) does NOT grant ~/.local"; fi

echo
echo "[environment]"
# Ambient env vars are NOT inherited — only an operational allowlist passes through — so
# secrets in the caller's shell can't leak to the sandboxed command or its children. Probe
# with /usr/bin/env (prints the REAL environment; /bin/sh would synthesize a default PATH and
# mask a regression), and treat a failed run as a failure rather than a silent pass.
if envdump="$( export SANDFENCE_FAKE_SECRET=leaked; sf_in "$root" /usr/bin/env 2>/dev/null )"; then
  if printf '%s\n' "$envdump" | grep -q '^SANDFENCE_FAKE_SECRET='; then
    bad "an ambient env var leaked into the sandbox"
  else ok "an ambient env var is dropped inside the sandbox"; fi
  if printf '%s\n' "$envdump" | grep -q '^PATH='; then
    ok "operational basics (PATH) are preserved inside the sandbox"
  else bad "PATH missing inside the sandbox"; fi
else
  bad "environment probe failed to run (sandfence did not execute)"
fi

if command -v jj >/dev/null 2>&1; then
  echo
  echo "[jj working copy]"
  # jj is available even outside a jj repo (the binary grant is not gated on .jj).
  # $root is a plain dir (not a jj repo), so this exercises the ungated grant.
  assert_allow_in "$root" "jj runs outside a jj repo"    jj --version
  # Isolate jj's config under the test root (XDG_CONFIG_HOME) so the suite doesn't
  # register test repos in the real ~/.config/jj. sandfence's jj-config grant follows
  # XDG_CONFIG_HOME, so the sandboxed jj reads this same isolated dir.
  jjwc="$root/jjwc"; jjxdg="$root/jjxdg"
  rm -rf "$jjwc" "$jjxdg"; mkdir -p "$jjwc"
  (
    set -e
    export XDG_CONFIG_HOME="$jjxdg" GIT_CONFIG_GLOBAL=/dev/null
    unset JJ_CONFIG                 # don't let a dev's JJ_CONFIG override the isolated dir
    cd "$jjwc"
    jj git init
    printf 'hello\n' > tracked.txt
    jj --ignore-working-copy status   # populates any per-repo secure-config metadata
  ) >/dev/null 2>&1
  if [ ! -d "$jjwc/.jj" ]; then
    bad "setup: could not create test jj repo under $jjwc"
  else
    export XDG_CONFIG_HOME="$jjxdg"; unset JJ_CONFIG
    assert_allow_in "$jjwc" "jj status (read-only) runs"   jj --ignore-working-copy status
    assert_deny_in  "$jjwc" "writing inside .jj is denied"  /bin/sh -c 'echo x > .jj/sandfence_intrusion'
    unset XDG_CONFIG_HOME
  fi
fi

echo
echo "[worktree / workspace]"
# A git worktree's .git is a FILE pointing into the MAIN repo's store elsewhere; a secondary jj
# workspace's .jj/repo is a FILE pointing at the main .jj/repo store. sandfence should grant
# READ-ONLY access to that main STORE (so history/log work) but NEVER the main repo's working copy
# (it may hold its own secrets), and only when the main repo is a direct SIBLING of the workspace —
# so a workspace-controlled (forged) pointer can't reach $HOME / an arbitrary store.

# --- git worktree (git is always present via the Xcode baseline) ---
mw="$root/mainrepo"; wt="$root/mainrepo.wt"
rm -rf "$mw" "$wt"; mkdir -p "$mw"
(
  set -e
  export GIT_CONFIG_GLOBAL=/dev/null
  cd "$mw"
  git init -q
  git config user.email sandfence@test.local; git config user.name "sandfence test"
  printf 'MAINWCSECRET\n' > main_wc_secret.txt
  git add -f main_wc_secret.txt
  git commit -qm init
  git worktree add -q "$wt"
) >/dev/null 2>&1
if [ ! -f "$wt/.git" ] || [ ! -r "$mw/main_wc_secret.txt" ]; then
  bad "setup: git worktree not created (worktree probes skipped)"
else
  # The main repo's store is readable from the worktree…
  assert_allow_in "$wt" "git worktree: main repo .git store is readable"       /bin/cat "$mw/.git/HEAD"
  # …but the main repo's WORKING COPY (its own files) is not.
  assert_deny_in  "$wt" "git worktree: main repo working copy is NOT readable"  /bin/cat "$mw/main_wc_secret.txt"
  # A main repo one level deeper (NOT a sibling of the worktree) is not auto-granted.
  nsmain="$root/deeper/nsmain"; nswt="$root/nsmain.wt"
  rm -rf "$root/deeper" "$nswt"; mkdir -p "$nsmain"
  (
    set -e
    export GIT_CONFIG_GLOBAL=/dev/null
    cd "$nsmain"
    git init -q
    git config user.email sandfence@test.local; git config user.name "sandfence test"
    printf 'x\n' > f.txt; git add -f f.txt; git commit -qm init
    git worktree add -q "$nswt"
  ) >/dev/null 2>&1
  if [ -f "$nswt/.git" ]; then
    assert_deny_in "$nswt" "git worktree: a NON-sibling main store is NOT auto-granted" /bin/cat "$nsmain/.git/HEAD"
  else
    bad "setup: non-sibling worktree not created (probe skipped)"
  fi
fi

# --- jj workspace (only if jj is installed) ---
if command -v jj >/dev/null 2>&1; then
  jjmain="$root/jjmain"; jjws="$root/jjmain.ws"; jjxdg2="$root/jjxdg2"
  rm -rf "$jjmain" "$jjws" "$jjxdg2"; mkdir -p "$jjmain"
  (
    set -e
    export XDG_CONFIG_HOME="$jjxdg2" GIT_CONFIG_GLOBAL=/dev/null
    unset JJ_CONFIG
    cd "$jjmain"
    jj git init
    printf 'JJMAINWCSECRET\n' > main_wc_secret.txt
    jj workspace add "$jjws"            # secondary workspace → its .jj/repo is a file pointing here
  ) >/dev/null 2>&1
  export XDG_CONFIG_HOME="$jjxdg2"; unset JJ_CONFIG
  if [ ! -f "$jjws/.jj/repo" ] || [ ! -r "$jjmain/main_wc_secret.txt" ]; then
    bad "setup: jj workspace not created (jj workspace probes skipped)"
  else
    assert_allow_in "$jjws" "jj workspace: main .jj/repo store is readable"       /bin/ls "$jjmain/.jj/repo"
    assert_deny_in  "$jjws" "jj workspace: main repo working copy is NOT readable" /bin/cat "$jjmain/main_wc_secret.txt"
  fi
  # A forged .jj/repo FILE claiming the store lives at $HOME must NOT grant $HOME.
  forge="$root/forged.ws"; rm -rf "$forge"; mkdir -p "$forge/.jj"
  printf '%s' "$HOME" > "$forge/.jj/repo"
  hprobe="$HOME/.sandfence_wt_probe.$$"
  printf 'HOMEWCSECRET\n' > "$hprobe" 2>/dev/null
  if [ -r "$hprobe" ]; then
    assert_deny_in "$forge" "jj workspace: a forged .jj/repo pointing at \$HOME is NOT granted" /bin/cat "$hprobe"
    rm -f "$hprobe"
  else
    skip "jj workspace: forged-pointer probe (could not create \$HOME probe)"
  fi
  # A forged workspace whose sibling main .git is a SYMLINK (not a real in-place store) must NOT get
  # a backend grant — the resolver canonicalizes + validates it. The OS also blocks the symlink at
  # access time, so the observable property here is the emitted profile: assert via --print that no
  # backend grant is produced for the symlinked .git.
  bmain="$root/bmain"; bws="$root/bws"; rm -rf "$bmain" "$bws"
  mkdir -p "$bmain/.jj/repo/store" "$bws/.jj"
  ln -s "$HOME" "$bmain/.git"                       # forged backend → $HOME (not a real .git store)
  printf '%s/.jj/repo' "$bmain" > "$bws/.jj/repo"
  if ( cd "$bws" && "$SF" --print ) 2>/dev/null | grep -q 'git backend'; then
    bad "jj workspace: a symlinked (non-store) main .git backend is NOT granted"
  else ok "jj workspace: a symlinked (non-store) main .git backend is NOT granted"; fi
  rm -f "$bmain/.git"
  unset XDG_CONFIG_HOME
fi

echo
echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ]
