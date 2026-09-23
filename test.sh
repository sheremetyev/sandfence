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

# POSIX semaphores: a real Pool exercises the parent's create and each child's re-open.
assert_allow "POSIX semaphores: a multiprocessing Pool round-trips" \
  /usr/bin/python3 -c 'import multiprocessing as m
p = m.Pool(2)
assert p.map(abs, [-1, -2]) == [1, 2]
p.close(); p.join()'

# FSEvents: a sandboxed watcher on / sees a change in the working copy, but not one in $HOME.
fswd="$root/fsevents"; rm -rf "$fswd"; mkdir -p "$fswd"
cat > "$fswd/fsw.c" <<'EOF'
#include <CoreServices/CoreServices.h>
static void cb(ConstFSEventStreamRef s, void *i, size_t n, void *p,
               const FSEventStreamEventFlags f[], const FSEventStreamEventId id[]) {
  for (size_t k = 0; k < n; k++) printf("%s\n", ((char **)p)[k]);
  fflush(stdout);
}
int main(void) {
  CFArrayRef root = CFArrayCreate(NULL, (const void *[]){CFSTR("/")}, 1, NULL);
  FSEventStreamRef s = FSEventStreamCreate(NULL, cb, NULL, root, kFSEventStreamEventIdSinceNow, 0.1,
      kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer);
  FSEventStreamSetDispatchQueue(s, dispatch_get_main_queue());
  FSEventStreamStart(s);
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{ exit(0); });
  dispatch_main();
}
EOF
if /usr/bin/clang -framework CoreServices -o "$fswd/fsw" "$fswd/fsw.c" >/dev/null 2>&1; then
  inside="$fswd/changed"; outside="$HOME/.sandfence-fsevents-probe.$$"
  ( cd "$fswd" && "$SF" ./fsw > out 2>/dev/null ) & sleep 1
  : > "$inside"; : > "$outside"; wait "$!"; rm -f "$inside" "$outside"
  if grep -qxF "$inside"  "$fswd/out"; then ok "FSEvents: watching sees working-copy changes"
  else bad "FSEvents: watching sees working-copy changes"; fi
  # match the unique name, not the full path — events may spell $HOME differently (symlink, firmlink)
  if grep -qF "${outside##*/}" "$fswd/out"; then bad "FSEvents: changes in \$HOME are NOT reported"
  else ok "FSEvents: changes in \$HOME are NOT reported"; fi
else
  skip "FSEvents probe (clang unavailable)"
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
  # Its agent config is write-denied too. Pre-created unsandboxed so each probe reaches the deny, not a
  # missing parent, and the CONTENT is checked: an exit code can't tell a denied write from another failure.
  for p in .claude/settings.json .codex/config.toml .cursor/hooks.json .mcp.json; do
    case "$p" in */*) mkdir -p "$wc/${p%/*}" ;; esac
    printf 'ORIG\n' > "$wc/$p"
    sf_in "$wc" /bin/sh -c "echo CLOBBER > '$p'" >/dev/null 2>&1
    if grep -q CLOBBER "$wc/$p" 2>/dev/null; then bad "repo agent config: overwriting $p is denied"
    else ok "repo agent config: overwriting $p is denied"; fi
  done
  # Whole dirs, entry included: no new file inside, no renaming the dir away, no renaming one in.
  assert_deny_in  "$wc" "repo agent config: adding a file to .claude/ is denied"   /bin/sh -c 'echo x > .claude/new.json'
  assert_deny_in  "$wc" "repo agent config: renaming .claude/ away is denied"      /bin/mv .claude .claude.bak
  assert_deny_in  "$wc" "repo agent config: renaming a dir into .grok is denied" \
    /bin/sh -c 'rm -rf staged && mkdir staged && echo x > staged/config.toml && mv staged .grok'
  assert_allow_in "$wc" "repo agent config: a nested .claude (not top level) is writable" \
    /bin/sh -c 'mkdir -p sub/.claude && echo x > sub/.claude/settings.json'
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
  assert_deny_in "$wc" "-w dir: its own .mcp.json is write-denied" -w "$rw" /bin/sh -c "echo x > '$rw/.mcp.json'"
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

# ~/.grok is read-only (it holds code a later UNsandboxed grok runs), with runtime state opened by
# name: listed state is writable, everything else — new files included — is not.
mkdir -p "$fakehome/.grok/bin" "$fakehome/.grok/vendor" "$fakehome/.grok/sessions/proj"
printf '#!/bin/sh\necho ORIG\n' > "$fakehome/.grok/bin/grok"; chmod +x "$fakehome/.grok/bin/grok"
printf '#!/bin/sh\necho ORIG\n' > "$fakehome/.grok/vendor/rg-15.0.0-override"
for f in auth.json config.toml trusted_folders.toml hooks-paths requirements.toml lsp.json \
         disabled-hooks settings_cache.json models_cache.json sessions/proj/permission.toml; do
  printf 'ORIG\n' > "$fakehome/.grok/$f"
done
assert_allow_home "grok: own ~/.grok/auth.json is writable"              --grok /bin/sh -c "echo x >> '$fakehome/.grok/auth.json'"
assert_allow_home "grok: its sessions/ dir is writable"                  --grok /bin/sh -c "echo x > '$fakehome/.grok/sessions/proj/resources_state.json'"
assert_allow_home "grok: an atomic-write temp file is writable"          --grok /bin/sh -c "echo x > '$fakehome/.grok/.tmpAbC123'"
assert_deny_home  "grok: an unlisted NEW file under ~/.grok is denied"   --grok /bin/sh -c "echo x > '$fakehome/.grok/future-hooks.json'"
assert_deny_home  "grok: a permission.toml built deeper can't be staged" --grok /bin/sh -c "mkdir -p '$fakehome/.grok/sessions/stage/p2' && echo x > '$fakehome/.grok/sessions/stage/p2/permission.toml'"
assert_deny_home  "grok: its bin/ can't be swapped out by rename"        --grok /bin/mv "$fakehome/.grok/bin" "$fakehome/.grok/bin.old"
# Each of these is code or config a later grok loads; check the CONTENT, not just the exit code.
for f in config.toml trusted_folders.toml bin/grok vendor/rg-15.0.0-override hooks-paths requirements.toml \
         lsp.json disabled-hooks settings_cache.json models_cache.json sessions/proj/permission.toml; do
  sf_home --grok /bin/sh -c "echo CLOBBER > '$fakehome/.grok/$f'" >/dev/null 2>&1
  if grep -q CLOBBER "$fakehome/.grok/$f" 2>/dev/null; then
    bad "grok: ~/.grok/$f write is denied (persistence guard)"
  else ok "grok: ~/.grok/$f write is denied (persistence guard)"; fi
done
# No unix sockets under ~/.grok: never join an UNsandboxed grok's leader, nor bind one it would join.
# The bind probe uses a writable path (sessions/), so only the network rule can be what denies it.
sock="$fakehome/.grok/leader.sock"; bsock="$fakehome/.grok/sessions/leader.sock"
if [ "${#bsock}" -lt 100 ]; then
  sockpy='import socket,sys; s=socket.socket(socket.AF_UNIX); getattr(s,sys.argv[1])(sys.argv[2])'
  assert_deny_home "grok: can't bind a unix socket under ~/.grok, even where files are writable" \
    --grok /usr/bin/python3 -c "$sockpy" bind "$bsock"
  rm -f "$bsock" "$sock"
  /usr/bin/python3 -c 'import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(1); time.sleep(10)' "$sock" &
  lpid=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S "$sock" ] && break; /bin/sleep 0.2; done
  if [ -S "$sock" ]; then   # the listener must exist, else "connect" fails for the wrong reason
    assert_deny_home "grok: can't connect to an unsandboxed leader socket"  --grok /usr/bin/python3 -c "$sockpy" connect "$sock"
  else bad "setup: unsandboxed leader socket never appeared (connect probe skipped)"; fi
  kill "$lpid" 2>/dev/null; wait "$lpid" 2>/dev/null; rm -f "$sock"
else
  skip "grok: socket probes (test root path too long for a unix socket)"
fi

echo
echo "[toolchains]"
# Presets are named -r/-w bundles: toolchain caches writable, but registry TOKENS and PATH-plant
# vectors (bin dirs) stay denied. Probed via the FLAGS with the isolated fake HOME from [agents] (so
# nothing touches your real ~/.cargo / ~/.nvm). We test the security carve-outs, not a real build
# (that's a manual smoke test). sf_home / assert_*_home are defined in [agents] above.

# --- rust ---
mkdir -p "$fakehome/.rustup" "$fakehome/.cargo/bin" "$fakehome/.cargo/registry"
printf 'TOOLCHAIN\n' > "$fakehome/.rustup/marker"
printf 'token\n'     > "$fakehome/.cargo/credentials.toml"
assert_allow_home "rust: ~/.cargo cache is writable"            --rust /bin/sh -c "echo x > '$fakehome/.cargo/registry/probe'"
assert_allow_home "rust: ~/.rustup toolchains are readable"     --rust /bin/cat "$fakehome/.rustup/marker"
# ~/.cargo/bin is read-only (no PATH-plant). Content check: the file must not appear.
sf_home --rust /bin/sh -c "echo EVIL > '$fakehome/.cargo/bin/planted'" >/dev/null 2>&1
if [ -e "$fakehome/.cargo/bin/planted" ]; then bad "rust: ~/.cargo/bin is NOT writable (no PATH-plant)"; rm -f "$fakehome/.cargo/bin/planted"
else ok "rust: ~/.cargo/bin is NOT writable (no PATH-plant)"; fi
assert_deny_home  "rust: crates.io credentials are NOT readable" --rust /bin/cat "$fakehome/.cargo/credentials.toml"
# config.toml can hold a registry.token → not readable; ~/.cargo/env is shell-sourced → not writable.
printf '[registry]\ntoken="SECRET"\n' > "$fakehome/.cargo/config.toml"
assert_deny_home "rust: ~/.cargo/config.toml is NOT readable (may hold a registry token)" --rust /bin/cat "$fakehome/.cargo/config.toml"
# …but an explicit -r overrides the preset deny (it's emitted last) — the documented opt-back-in.
assert_allow_home "rust: an explicit -r re-opens a preset-denied path" --rust -r "$fakehome/.cargo/config.toml" /bin/cat "$fakehome/.cargo/config.toml"
printf 'ORIG\n' > "$fakehome/.cargo/env"
sf_home --rust /bin/sh -c "echo CLOBBER >> '$fakehome/.cargo/env'" >/dev/null 2>&1
if grep -q CLOBBER "$fakehome/.cargo/env" 2>/dev/null; then bad "rust: ~/.cargo/env is NOT writable (persistence)"
else ok "rust: ~/.cargo/env is NOT writable (persistence)"; fi

# --- node ---
mkdir -p "$fakehome/.npm" "$fakehome/.nvm/versions/node/v99"
printf 'NODELIB\n'            > "$fakehome/.nvm/versions/node/v99/marker"
printf 'token\n'              > "$fakehome/.npmrc"
assert_allow_home "node: a PM cache (~/.npm) is writable"          --node /bin/sh -c "echo x > '$fakehome/.npm/probe'"
assert_allow_home "node: ~/.nvm toolchains are readable"           --node /bin/cat "$fakehome/.nvm/versions/node/v99/marker"
assert_deny_home  "node: ~/.npmrc (registry token) is NOT readable" --node /bin/cat "$fakehome/.npmrc"
# the per-version global npmrc under ~/.nvm can also hold a registry token → not readable.
mkdir -p "$fakehome/.nvm/versions/node/v99/etc"
printf '//registry.npmjs.org/:_authToken=SECRET\n' > "$fakehome/.nvm/versions/node/v99/etc/npmrc"
assert_deny_home "node: nvm global npmrc is NOT readable (registry token)" --node /bin/cat "$fakehome/.nvm/versions/node/v99/etc/npmrc"
# npm logs may hold old tokens → not readable (writes still allowed).
mkdir -p "$fakehome/.npm/_logs"
printf '//registry.npmjs.org/:_authToken=SECRET\n' > "$fakehome/.npm/_logs/leak.log"
assert_deny_home "node: ~/.npm/_logs is NOT readable (old tokens)" --node /bin/cat "$fakehome/.npm/_logs/leak.log"

# --- node: fnm ---
# The data dir (auto-detected at ~/.local/share/fnm) is read-only with its per-version npmrc denied; the
# multishell link `fnm env` puts on PATH resolves through read-only, only when the env names it.
unset FNM_DIR FNM_MULTISHELL_PATH
fnmdir="$fakehome/.local/share/fnm"; fnminst="$fnmdir/node-versions/v99.0.0/installation"
fnmlink="$fakehome/.local/state/fnm_multishells/1_2"
mkdir -p "$fnminst/bin" "$fnminst/etc" "${fnmlink%/*}"
printf 'FNMLIB\n' > "$fnminst/marker"
printf '//registry.npmjs.org/:_authToken=SECRET\n' > "$fnminst/etc/npmrc"
ln -sfn "$fnminst" "$fnmlink"
assert_allow_home "node: fnm data dir (~/.local/share/fnm) is readable"                  --node /bin/cat "$fnminst/marker"
assert_deny_home  "node: fnm per-version global npmrc is NOT readable (registry token)"  --node /bin/cat "$fnminst/etc/npmrc"
sf_home --node /bin/sh -c "echo EVIL > '$fnminst/bin/planted'" >/dev/null 2>&1
if [ -e "$fnminst/bin/planted" ]; then bad "node: fnm data dir is NOT writable (no fnm install / -g plant)"; rm -f "$fnminst/bin/planted"
else ok "node: fnm data dir is NOT writable (no fnm install / -g plant)"; fi
assert_deny_home  "node: fnm multishell link is NOT reachable unless FNM_MULTISHELL_PATH names it" --node /bin/cat "$fnmlink/marker"
FNM_MULTISHELL_PATH="$fnmlink" assert_allow_home "node: fnm multishell link (FNM_MULTISHELL_PATH) resolves read-only" --node /bin/cat "$fnmlink/marker"
FNM_MULTISHELL_PATH="$fnmlink" sf_home --node /bin/ln -sfn "$fakehome/.npm" "$fnmlink" >/dev/null 2>&1
if [ "$(readlink "$fnmlink")" = "$fnminst" ]; then ok "node: fnm multishell link is NOT re-pointable from inside (no fnm use)"
else bad "node: fnm multishell link is NOT re-pointable from inside (no fnm use)"; ln -sfn "$fnminst" "$fnmlink"; fi
# …even when the link sits in a writable tree named through a symlinked parent (older fnm uses $TMPDIR,
# i.e. /var → /private/var; here ~/.npm behind an alias stands in for it). The rules must land on the
# resolved dir, so probe via the real path — the alias itself is ungranted here (/var is, in the baseline).
fnmlink2="$fakehome/.npm/fnm_multishells/3_4"; mkdir -p "${fnmlink2%/*}"; ln -sfn "$fnminst" "$fnmlink2"
ln -sfn "$fakehome/.npm" "$fakehome/npm-alias"; fnmlink2_alias="$fakehome/npm-alias/fnm_multishells/3_4"
FNM_MULTISHELL_PATH="$fnmlink2_alias" assert_allow_home "node: fnm multishell link in a writable tree still resolves" --node /bin/cat "$fnmlink2/marker"
FNM_MULTISHELL_PATH="$fnmlink2_alias" sf_home --node /bin/sh -c "ln -sfn '$fakehome/.npm' '$fnmlink2' || { rm -rf '${fnmlink2%/*}' && ln -sfn '$fakehome/.npm' '$fnmlink2'; }" >/dev/null 2>&1
if [ "$(readlink "$fnmlink2")" = "$fnminst" ]; then ok "node: fnm multishell link in a writable tree is NOT re-pointable from inside"
else bad "node: fnm multishell link in a writable tree is NOT re-pointable from inside"; fi
# FNM_DIR from the env wins over the defaults
fnmalt="$fakehome/fnm-alt"; mkdir -p "$fnmalt/node-versions"; printf 'ALT\n' > "$fnmalt/marker"
FNM_DIR="$fnmalt" assert_allow_home "node: FNM_DIR from the env is granted read-only" --node /bin/cat "$fnmalt/marker"
FNM_DIR="$fnmalt" assert_deny_home  "node: with FNM_DIR set, the default fnm dir is NOT granted" --node /bin/cat "$fnminst/marker"
unset FNM_DIR FNM_MULTISHELL_PATH

# --- node: corepack ---
# Its home (~/.cache/node/corepack) is read-only: cached package managers run, but a fetched (or
# planted) one — exec'd by a later UNsandboxed shim — can't land. Pinned in the env; COREPACK_HOME wins.
unset COREPACK_HOME
cph="$fakehome/.cache/node/corepack"; mkdir -p "$cph/v1/pnpm/9"; printf 'PM\n' > "$cph/v1/pnpm/9/marker"
assert_allow_home "node: corepack home (~/.cache/node/corepack) is readable"     --node /bin/cat "$cph/v1/pnpm/9/marker"
assert_allow_home "node: COREPACK_HOME is pinned to the granted home inside"     --node /bin/sh -c "[ \"\$COREPACK_HOME\" = '$cph' ]"
sf_home --node /bin/sh -c "echo EVIL > '$cph/v1/pnpm/9/planted'" >/dev/null 2>&1
if [ -e "$cph/v1/pnpm/9/planted" ]; then bad "node: corepack home is NOT writable (no fetched/planted package manager)"; rm -f "$cph/v1/pnpm/9/planted"
else ok "node: corepack home is NOT writable (no fetched/planted package manager)"; fi
cpalt="$fakehome/corepack-alt"; mkdir -p "$cpalt"; printf 'ALT\n' > "$cpalt/marker"
COREPACK_HOME="$cpalt" assert_allow_home "node: COREPACK_HOME from the env is granted read-only"       --node /bin/cat "$cpalt/marker"
COREPACK_HOME="$cpalt" assert_deny_home  "node: with COREPACK_HOME set, the default home is NOT granted" --node /bin/cat "$cph/v1/pnpm/9/marker"
unset COREPACK_HOME

# --- node: pnpm ---
# Home (~/Library/pnpm) is read-only — bin/, global/ and self-fetched versions can't be planted — while
# the store inside it and the cache are created + writable, minus the dlx cache; global config denied.
unset PNPM_HOME
ph="$fakehome/Library/pnpm"; pc="$fakehome/Library/Caches/pnpm"; rm -rf "$ph" "$pc"
mkdir -p "$ph/bin" "$fakehome/Library/Preferences/pnpm"
printf '#!/bin/sh\nexit 0\n' > "$ph/pnpm"; chmod +x "$ph/pnpm"
printf '//registry.npmjs.org/:_authToken=SECRET\n' > "$fakehome/Library/Preferences/pnpm/rc"
assert_allow_home "node: pnpm store (~/Library/pnpm/store) is created + writable"   --node /bin/sh -c "echo x > '$ph/store/probe'"
assert_allow_home "node: pnpm cache (~/Library/Caches/pnpm) is created + writable"  --node /bin/sh -c "echo x > '$pc/probe'"
assert_allow_home "node: the standalone pnpm binary is readable"                   --node /bin/cat "$ph/pnpm"
assert_allow_home "node: PNPM_HOME is pinned to the granted home inside"           --node /bin/sh -c "[ \"\$PNPM_HOME\" = '$ph' ]"
assert_allow_home "node: pnpm store dir is pinned inside (env for pnpm >=11, npm user config for <=10)" --node /bin/sh -c "[ \"\$pnpm_config_store_dir\" = '$ph/store' ] && grep -qx 'store-dir=$ph/store' \"\$NPM_CONFIG_USERCONFIG\""
sf_home --node /bin/sh -c "echo EVIL > '$ph/bin/planted'" >/dev/null 2>&1
if [ -e "$ph/bin/planted" ]; then bad "node: pnpm bin dir is NOT writable (no PATH-plant)"; rm -f "$ph/bin/planted"
else ok "node: pnpm bin dir is NOT writable (no PATH-plant)"; fi
sf_home --node /bin/sh -c "mkdir -p '$pc/dlx/h' && echo EVIL > '$pc/dlx/h/planted'" >/dev/null 2>&1
if [ -e "$pc/dlx" ]; then bad "node: pnpm dlx cache is NOT writable (a later unsandboxed dlx execs it)"; rm -rf "$pc/dlx"
else ok "node: pnpm dlx cache is NOT writable (a later unsandboxed dlx execs it)"; fi
assert_deny_home  "node: pnpm global config (registry token) is NOT readable"      --node /bin/cat "$fakehome/Library/Preferences/pnpm/rc"
phalt="$fakehome/pnpm-alt"; mkdir -p "$phalt"
PNPM_HOME="$phalt" assert_allow_home "node: PNPM_HOME from the env: its store is created + writable" --node /bin/sh -c "echo x > '$phalt/store/probe'"
PNPM_HOME="$phalt" assert_deny_home  "node: with PNPM_HOME set, the default home is NOT granted"    --node /bin/cat "$ph/pnpm"
unset PNPM_HOME

# --- python ---
mkdir -p "$fakehome/Library/Caches/pip"
assert_allow_home "python: pip cache (~/Library/Caches/pip) is writable" --python /bin/sh -c "echo x > '$fakehome/Library/Caches/pip/probe'"

# --- go ---
# Default layout under the fake HOME (the caller's GOPATH/GOMODCACHE/GOCACHE must not leak in). The
# caches are NOT pre-created: sandfence must make them at launch (go aborts when it can't).
unset GOPATH GOMODCACHE GOCACHE
goenv="$fakehome/Library/Application Support/go/env"
rm -rf "$fakehome/go" "$fakehome/Library/Caches/go-build" "${goenv%/env}"
mkdir -p "$fakehome/go/bin" "${goenv%/env}"
printf '#!/bin/sh\nexit 0\n' > "$fakehome/go/bin/tool"; chmod +x "$fakehome/go/bin/tool"
printf 'GOPROXY=https://user:SECRET@proxy.example\n' > "$goenv"
assert_deny_home  "go: ~/go is NOT readable without --go"                          /bin/ls "$fakehome/go/bin"
assert_allow_home "go: module cache (~/go/pkg/mod) is created + writable"          --go /bin/sh -c "echo x > '$fakehome/go/pkg/mod/probe'"
assert_allow_home "go: checksum-db state (~/go/pkg/sumdb) is created + writable"   --go /bin/sh -c "echo x > '$fakehome/go/pkg/sumdb/probe'"
assert_allow_home "go: build cache (~/Library/Caches/go-build) is created + writable" --go /bin/sh -c "echo x > '$fakehome/Library/Caches/go-build/probe'"
assert_allow_home "go: a tool in ~/go/bin runs"                                    --go "$fakehome/go/bin/tool"
# Not writable (content-checked): ~/go/bin (PATH-plant), a downloaded toolchain + its zip and a vcs clone's
# config in the module cache (a later UNsandboxed go runs them), the `go env -w` store (GOFLAGS/CC are commands).
tc="$fakehome/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.99.darwin-arm64/bin"; vcs="$fakehome/go/pkg/mod/cache/vcs/abc"
tczip="$fakehome/go/pkg/mod/cache/download/golang.org/toolchain/@v"
mkdir -p "$tc" "$vcs" "$tczip"; printf 'ORIG\n' > "$tc/go"; printf 'ORIG\n' > "$vcs/config"; printf 'ORIG\n' > "$tczip/v0.0.1-go1.99.darwin-arm64.zip"
for f in "$fakehome/go/bin/tool" "$tc/go" "$tczip/v0.0.1-go1.99.darwin-arm64.zip" "$vcs/config" "$goenv"; do
  sf_home --go /bin/sh -c "echo CLOBBER > '$f'" >/dev/null 2>&1
  if grep -q CLOBBER "$f" 2>/dev/null; then bad "go: NOT writable: ${f#"$fakehome"/}"
  else ok "go: NOT writable: ${f#"$fakehome"/}"; fi
done
assert_deny_home  "go: the go env store is NOT readable (GOPROXY token)"           --go /bin/cat "$goenv"
assert_deny_home  "go: a vcs clone's config is NOT readable (URL-embedded token)"  --go /bin/cat "$vcs/config"
# A symlinked GOMODCACHE: the denies must hold on the resolved path (Seatbelt checks resolved paths).
ln -sfn "$fakehome/go/pkg/mod" "$fakehome/modlink"
if ( cd "$wc" && HOME="$fakehome" GOMODCACHE="$fakehome/modlink" "$SF" --go /bin/sh -c "echo CLOBBER > '$tc/go'" ) >/dev/null 2>&1 \
   || grep -q CLOBBER "$tc/go"; then
  bad "go: a symlinked GOMODCACHE keeps the toolchain write-deny"
else ok "go: a symlinked GOMODCACHE keeps the toolchain write-deny"; fi
# A GOMODCACHE in the launcher's env relocates the grant (and reaches go inside); the default is then ungranted.
if ( cd "$wc" && HOME="$fakehome" GOMODCACHE="$fakehome/altmod" "$SF" --go /bin/sh -c 'echo x > "$GOMODCACHE/probe"' ) >/dev/null 2>&1 \
   && [ -e "$fakehome/altmod/probe" ]; then
  ok "go: GOMODCACHE from the env relocates the module cache grant (and is passed through)"
else bad "go: GOMODCACHE from the env relocates the module cache grant (and is passed through)"; fi
if ( cd "$wc" && HOME="$fakehome" GOMODCACHE="$fakehome/altmod" "$SF" --go /bin/sh -c "echo CLOBBER > '$fakehome/go/pkg/mod/probe'" ) >/dev/null 2>&1 \
   || grep -q CLOBBER "$fakehome/go/pkg/mod/probe"; then
  bad "go: a relocated GOMODCACHE leaves the default ~/go/pkg/mod ungranted"
else ok "go: a relocated GOMODCACHE leaves the default ~/go/pkg/mod ungranted"; fi
# A real go, if reachable: a stdlib-only build under the fake HOME (fresh caches, denied env/telemetry
# store — not yours). Proves GOCACHE works and the denials are silent; module downloads need network.
case "$(command -v go 2>/dev/null || true)" in
  /usr/local/go/*)                          goflag="" ;;        # go.dev installer: under the baseline /usr grant
  "${HOMEBREW_PREFIX:-/opt/homebrew}"/*)    goflag="--brew" ;;  # brew's go (bin/go symlinks within the prefix)
  *)                                        goflag="skip" ;;    # absent, or a layout (~/sdk, mise) that needs -r
esac
if [ "$goflag" != skip ]; then
  mkdir -p "$wc/gohello"; printf 'package main\nimport "fmt"\nfunc main() { fmt.Println("hi") }\n' > "$wc/gohello/hello.go"
  goout="$(sf_home $goflag --go go run gohello/hello.go 2>&1)"
  if [ "$goout" = "hi" ]; then ok "go: a real \`go run\` builds (caches usable; env/telemetry denial is silent)"
  else bad "go: a real \`go run\` builds (got: $goout)"; fi
else
  skip "go: a real \`go run\` builds (no go on PATH under /usr/local/go or the brew prefix)"
fi

# --- brew ---
# A FAKE prefix under the test root, selected via HOMEBREW_PREFIX: outside the working copy (so only
# --brew can reach it) and nothing here touches the real /opt/homebrew. bin/ symlinks into Cellar/.
fakebrew="$root/fakebrew"
rm -rf "$fakebrew"
mkdir -p "$fakebrew/bin" "$fakebrew/Cellar/tool/1.0/bin" "$fakebrew/etc/homebrew" "$fakebrew/var/postgres"
printf '#!/bin/sh\nexit 0\n' > "$fakebrew/bin/brew"; chmod +x "$fakebrew/bin/brew"   # what marks a REAL prefix
printf '#!/bin/sh\nexit 0\n' > "$fakebrew/Cellar/tool/1.0/bin/tool"; chmod +x "$fakebrew/Cellar/tool/1.0/bin/tool"
ln -s ../Cellar/tool/1.0/bin/tool "$fakebrew/bin/tool"
printf '//registry.npmjs.org/:_authToken=SECRET\n' > "$fakebrew/etc/npmrc"
printf 'HOMEBREW_GITHUB_API_TOKEN=SECRET\n' > "$fakebrew/etc/homebrew/brew.env"
printf 'DBSECRET\n' > "$fakebrew/var/postgres/data"
export HOMEBREW_PREFIX="$fakebrew"   # sf_home / assert_*_home (from [agents]) pass the env through

# Ungranted without the flag; with it, a formula runs through the bin/ symlink into Cellar/.
assert_deny_home  "brew: prefix is NOT readable without --brew"           /bin/cat "$fakebrew/bin/brew"
assert_allow_home "brew: a formula runs via its bin/ symlink"              --brew "$fakebrew/bin/tool"
# The read carve-outs: var/ (service data), etc/homebrew/ (brew.env token), etc/npmrc (registry token).
assert_deny_home  "brew: var/ (service data) is NOT readable"              --brew /bin/cat "$fakebrew/var/postgres/data"
assert_deny_home  "brew: etc/homebrew/brew.env (GitHub token) is NOT readable" --brew /bin/cat "$fakebrew/etc/homebrew/brew.env"
assert_deny_home  "brew: etc/npmrc (registry token) is NOT readable"       --brew /bin/cat "$fakebrew/etc/npmrc"
# Not writable: bin/ is on PATH (PATH-plant). Content check: the planted file must not appear.
sf_home --brew /bin/sh -c "echo EVIL > '$fakebrew/bin/planted'" >/dev/null 2>&1
if [ -e "$fakebrew/bin/planted" ]; then bad "brew: bin/ is NOT writable (no PATH-plant / brew install)"; rm -f "$fakebrew/bin/planted"
else ok "brew: bin/ is NOT writable (no PATH-plant / brew install)"; fi
# A HOMEBREW_PREFIX with no bin/brew (here, the fake HOME) must refuse to launch, not grant that tree.
if ( cd "$wc" && HOME="$fakehome" HOMEBREW_PREFIX="$fakehome" "$SF" --brew /usr/bin/true ) >/dev/null 2>&1; then
  bad "brew: a HOMEBREW_PREFIX that is not a Homebrew prefix is refused"
else ok "brew: a HOMEBREW_PREFIX that is not a Homebrew prefix is refused"; fi
unset HOMEBREW_PREFIX
# The real default prefix, if present (exercises /opt traversal; bin/brew is a plain script).
if [ -r /opt/homebrew/bin/brew ]; then
  assert_allow_in "$wc" "brew: real /opt/homebrew is readable with --brew" --brew /bin/cat /opt/homebrew/bin/brew
else
  skip "brew: real /opt/homebrew is readable with --brew (no /opt/homebrew/bin/brew)"
fi

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
