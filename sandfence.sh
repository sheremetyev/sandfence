#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# sandfence.sh — run a command under a default-deny macOS sandbox-exec profile.
#
# Grants: system runtime, temp, devices, process + network, the working copy
# (read-write, its own .git/.jj + agent config read-only), and a few read-only tool configs.
# Denied by default: the rest of $HOME — ~/.ssh, ~/.aws, the login Keychain,
# ~/.gitconfig credentials. See DESIGN.md for how it works and why each grant exists.
#
# Usage:  sandfence.sh [-r PATH]... [-w PATH]... [--brew|--rust|--node|--python|--go]
#                      [--claude|--codex|--grok] [--print] <tool> [args...]
# ============================================================================

usage() {
  printf '%s\n' \
    'Usage: sandfence.sh [-r PATH]... [-w PATH]... [--print] <tool> [args...]' \
    '  -r PATH    read-only access to a dir or file   (repeatable)' \
    '  -w PATH    read-write access to a dir or file  (repeatable; a dir keeps its .git/.jj + agent config read-only)' \
    '  --claude   also grant the claude agent bundle (binary + ~/.claude state; auth via file, not Keychain)' \
    '  --codex    also grant the codex agent bundle  (binary + node runtime + ~/.codex state)' \
    '  --grok     also grant the grok agent bundle   (binary + ~/.grok read-only; only its runtime state writable)' \
    '  --rust/--node/--python/--go  toolchain preset: caches writable, registry tokens + PATH-plant denied' \
    '  --brew     Homebrew prefix read-only ($HOMEBREW_PREFIX, default /opt/homebrew); var/ + brew/npm config denied' \
    '  --print    print the composed SBPL profile and exit (also -p)' \
    '  <tool>     any command on PATH (resolved by sandbox-exec)'
  exit "${1:-1}"
}

# ---------------------------------------------------------------------------
# Path helpers. Profile rules accumulate in $dynamic; per-repo write-denies in
# $repo_deny, which is emitted LAST so last-match-wins beats the read-write grant.
# ---------------------------------------------------------------------------
validate_path() {             # <path> <label> — require an absolute, SBPL-safe path
  local p="$1" label="$2"
  case "$p" in /*) ;; *) echo "sandfence.sh: $label is not an absolute path: $p" >&2; exit 1 ;; esac
  if [[ "$p" == *'"'* || "$p" == *'\'* || "$p" =~ [[:cntrl:]] ]]; then
    echo "sandfence.sh: $label has unsafe characters (quote, backslash, control): $p" >&2; exit 1
  fi
}
resolve_dir() { cd "$1" 2>/dev/null && pwd -P; }   # canonicalize a dir (resolve symlinks)
canon_dir()   { [ -n "$1" ] && resolve_dir "$1" || printf '%s' "${1%/}"; }   # …if it exists, else as given; never cd "" (= cwd)

# A (subpath ...) grant does NOT confer the right to traverse the path's parents,
# so each granted root needs lookup-only (metadata) literals up its chain — enough
# to walk in, not to list. ("/" itself is granted in the baseline.)
emit_ancestors() {            # <abs-path> — emit metadata-only traversal for each parent
  local p="$1"
  case "$p" in /*) ;; *) return 0 ;; esac
  while p="${p%/*}"; [ -n "$p" ]; do
    dynamic+="(allow file-read-metadata (literal \"$p\"))"$'\n'
  done
}
grant_rw()      { validate_path "$1" grant; emit_ancestors "$1"; dynamic+="(allow file-read* file-write* (subpath \"$1\"))"$'\n'; }   # read-write dir
grant_ro()      { validate_path "$1" grant; emit_ancestors "$1"; dynamic+="(allow file-read* (subpath \"$1\"))"$'\n'; }               # read-only dir
grant_file()    { validate_path "$1" grant; emit_ancestors "$1"; dynamic+="(allow file-read* (literal \"$1\"))"$'\n'; }               # read one file
grant_file_rw() { validate_path "$1" grant; emit_ancestors "$1"; dynamic+="(allow file-read* file-write* (literal \"$1\"))"$'\n'; }   # read-write one file
sect()          { dynamic+=";; --- $1 ---"$'\n'; }                                                                                    # labeled comment in the profile

resolve_file() {              # canonicalize a file path (resolve symlinks in its parent dir)
  local dir="${1%/*}" base="${1##*/}"
  [ "$dir" = "$1" ] && dir="."   # no slash → relative to cwd
  [ -z "$dir" ] && dir="/"        # file directly under the root, e.g. /foo
  dir="$(cd "$dir" 2>/dev/null && pwd -P)" || return 1
  printf '%s/%s\n' "${dir%/}" "$base"   # %/ strips a trailing slash so root yields /foo, not //foo
}
abspath() {                   # <path> <base> — resolve to a canonical abs dir (path may be relative to
  [ -n "$1" ] || return 0     # base, or empty); prints nothing if unresolvable. Follows a VCS pointer to its store.
  case "$1" in
    /*) ( cd "$1"    2>/dev/null && pwd -P ) ;;
    *)  ( cd "$2/$1" 2>/dev/null && pwd -P ) ;;
  esac || true
}
is_git_store() {              # <dir> — a REAL git store: basename .git, with HEAD + objects/
  [ "${1##*/}" = .git ] && [ -e "$1/HEAD" ] && [ -d "$1/objects" ]
}
deny_repo_meta() {            # <abs-dir> — write-deny its own top-level .git/.jj + agent config
  # Agent config (hooks, MCP servers, permissions) runs in a later UNsandboxed session here. Whole
  # dirs, entry included: a per-file deny is bypassed by renaming a prepared .cursor2/ into place.
  local n rule="(deny file-write*"
  for n in .git .jj .claude .grok .codex .cursor .mcp.json; do rule+=" (subpath \"$1/$n\") (literal \"$1/$n\")"; done
  repo_deny+="$rule)"$'\n'
}

# ---------------------------------------------------------------------------
# Parse args: flags, then the tool + its args.
# ---------------------------------------------------------------------------
reads=(); writes=(); agents=(); presets=(); print_only=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -r)  [[ $# -ge 2 ]] || { echo "sandfence.sh: -r needs a path" >&2; exit 1; }; reads+=("$2"); shift 2 ;;
    -r*) reads+=("${1#-r}"); shift ;;
    -w)  [[ $# -ge 2 ]] || { echo "sandfence.sh: -w needs a path" >&2; exit 1; }; writes+=("$2"); shift 2 ;;
    -w*) writes+=("${1#-w}"); shift ;;
    --claude|--codex|--grok) agents+=("${1#--}"); shift ;;
    --brew|--rust|--node|--python|--go) presets+=("${1#--}"); shift ;;
    -p|--print) print_only=1; shift ;;
    -h|--help)  usage 0 ;;
    --)         shift; break ;;
    -*)         echo "sandfence.sh: unknown flag: $1" >&2; usage 1 ;;
    *)          break ;;
  esac
done
if [[ $# -ge 1 ]]; then
  tool="$1"; shift
  case "$tool" in
    claude) cmd=("$(command -v claude || true)" --dangerously-skip-permissions) ;;
    codex)  cmd=("$(command -v codex || true)" --dangerously-bypass-approvals-and-sandbox) ;;
    # A private leader socket: grok spawns its leader INSIDE the box instead of joining an unsandboxed one.
    grok)   cmd=("$(command -v grok || true)" --always-approve \
                 --leader-socket "${TMPDIR:-/tmp}/sandfence-grok-$$.sock") ;;
    *)      cmd=("$tool") ;;
  esac
elif [[ -n "$print_only" ]]; then
  tool=""; cmd=()                 # --print with no tool: show the baseline profile
else
  usage 1
fi
# The tool's own bundle auto-applies; --claude/--codex/--grok add the OTHER agent's bundle too
# (e.g. `--codex claude` lets a claude session also read/run codex). See DESIGN.md ("Agent bundles").
case "$tool" in claude|codex|grok) agents+=("$tool") ;; esac

# ---------------------------------------------------------------------------
# Static baseline: read-only, secret-free. NOTE: never grant (subpath "/System")
# for reads — that string also matches the firmlink at /System/Volumes/Data/...
# (your whole home). Grant specific system subpaths + metadata-only traversal,
# the way Apple's own profiles do.
# ---------------------------------------------------------------------------
IFS= read -r -d '' static_body <<'SBPL' || true
(define (home-literal rel) (literal (string-append HOME_DIR rel)))

(deny default)

;; --- System runtime: let any binary exec + load dyld/libs/frameworks -------
(allow file-read*
    (subpath "/usr")                          ;; system binaries, dylibs, /usr/share
    (subpath "/bin") (subpath "/sbin")
    (subpath "/System/Library")               ;; system frameworks + resources
    (subpath "/System/Cryptexes")             ;; dyld shared cache (cryptex split)
    (subpath "/System/Volumes/Preboot")       ;; some dyld/framework lookups resolve through here
    (subpath "/Library/Apple")                ;; Apple-provided system frameworks
    (subpath "/Library/Developer")            ;; Xcode CLT: SDK, headers, clang/ld
    (subpath "/Applications/Xcode.app"))      ;; git + python3 live here on some machines
(allow file-read-metadata                     ;; traversal only (stat), no data reads
    (subpath "/System")                       ;; reach /System/Library without exposing the data firmlink
    (literal "/Library") (literal "/Applications")
    (literal "/private") (literal "/private/var") (literal "/private/etc"))

;; Volume root: keep file-read* — it's the traversal grant nothing else backstops
;; (metadata-only "/" breaks all exec); listing it reveals only standard dirs.
(allow file-read* (literal "/"))

;; --- Resolver / locale / TLS trust store (files) ---------------------------
(allow file-read*
    (literal "/private/etc/hosts")
    (literal "/private/etc/resolv.conf")
    (literal "/private/etc/services")
    (literal "/private/etc/protocols")
    (literal "/private/etc/localtime")
    (subpath "/private/etc/ssl")              ;; CA bundle for HTTPS
    (subpath "/private/var/db/timezone")      ;; date/time formatting
    (literal "/Library/Preferences/.GlobalPreferences.plist")        ;; locale/region defaults
    (home-literal "/Library/Preferences/.GlobalPreferences.plist")
    (literal "/etc") (literal "/var"))         ;; compat symlinks tools hardcode

;; --- Apple toolchain resolver (read-only) ----------------------------------
;; git/cc/python3 stubs find the real binary via these selectors; the Xcode
;; license plist is their license check (a denial fails every git op). We do NOT
;; grant ~/.gitconfig / XDG git config — they can carry credentials; git uses an
;; empty global config instead (GIT_CONFIG_GLOBAL below), and commits are denied.
(allow file-read* (subpath "/private/var/select"))
(allow file-read* (literal "/Library/Preferences/com.apple.dt.Xcode.plist"))

;; --- Temp (read-write) -----------------------------------------------------
(allow file-read* file-write*
    (subpath "/tmp") (subpath "/private/tmp")
    (subpath "/var/folders") (subpath "/private/var/folders"))

;; --- Devices ---------------------------------------------------------------
(allow file-read* file-write*
    (literal "/dev/null") (literal "/dev/zero")
    (literal "/dev/stdin") (literal "/dev/stdout") (literal "/dev/stderr")
    (subpath "/dev/fd")
    (literal "/dev/tty") (literal "/dev/ptmx")
    (regex #"^/dev/ttys") (regex #"^/dev/pty"))
(allow file-read* (literal "/dev/random") (literal "/dev/urandom") (literal "/dev/dtracehelper"))
(allow file-ioctl (literal "/dev/tty") (literal "/dev/ptmx") (regex #"^/dev/ttys"))

;; --- Process control -------------------------------------------------------
(allow process-exec)                          ;; global; exec is bounded by traversal, not read
(allow process-fork)
(allow sysctl-read)                           ;; system info (hw.ncpu, kern.osversion, …)
(deny sysctl-read                             ;; …but NOT other processes' argv/env via KERN_PROCARGS2
    (sysctl-name "kern.procargs") (sysctl-name "kern.procargs2"))
(allow pseudo-tty)
(allow process-info* (target same-sandbox))
(allow signal (target same-sandbox))
(allow mach-priv-task-port (target same-sandbox))

;; --- Network: open by design — egress + local binds (dev servers) ----------
(allow network*)
(allow system-socket)
(allow mach-lookup
    (global-name "com.apple.system.notification_center")
    (global-name "com.apple.system.opendirectoryd.libinfo")           ;; getpwuid / id
    (global-name "com.apple.system.opendirectoryd.membership")
    (global-name "com.apple.cfprefsd.agent")                          ;; CFPreferences
    (global-name "com.apple.cfprefsd.daemon")
    (global-name "com.apple.logd")
    (global-name "com.apple.diagnosticd")
    (global-name "com.apple.trustd")                                  ;; TLS cert validation
    (global-name "com.apple.trustd.agent")
    (global-name "com.apple.SystemConfiguration.configd")
    (global-name "com.apple.SystemConfiguration.DNSConfiguration")
    (global-name "com.apple.dnssd.service")                           ;; DNS resolution
    (global-name "com.apple.networkd")
    (global-name "com.apple.nehelper")
    (global-name "com.apple.nesessionmanager"))
(allow ipc-posix-shm-read*
    (ipc-posix-name "apple.shm.notification_center")
    (ipc-posix-name-prefix "apple.cfprefs."))

;; --- FSEvents: directory watchers (fs.watch, dev servers); filtered to our sandbox
(allow mach-lookup (global-name "com.apple.FSEvents"))

;; --- POSIX semaphores ------------------------------------------------------
;; Python multiprocessing locks a Pool with one, and each child re-opens it by name —
;; create and open are separate ops, hence the whole family.
(allow ipc-posix-sem* (semaphore-owner same-sandbox))

;; NOT granted, on purpose (default-deny covers them): your home directory at
;; large, the login Keychain, ~/.ssh, ~/.aws, gh/glab tokens, Docker sockets.
SBPL

# ---------------------------------------------------------------------------
# Working copy: the current dir, read-write (reaching it needs ancestor
# traversal). Its own top-level .git/.jj is write-denied via $repo_deny (emitted
# last) so the agent can edit code but can't commit, amend, or rewrite history —
# and so is its agent config (.claude, .grok, .codex, .cursor, .mcp.json), which a
# later UNsandboxed agent would execute.
# HOME is interpolated into (literal ...); validate it before composing.
# ---------------------------------------------------------------------------
validate_path "$HOME" "HOME"
workdir="$(resolve_dir "$PWD")" || { echo "sandfence.sh: cannot resolve working directory ($PWD)" >&2; exit 1; }

# Refuse / or $HOME (or a parent of $HOME) as the working copy — that would expose
# every secret under your home. Run from a project subdirectory instead. (The
# launcher is trusted, so a plain path check is enough.)
home_real="$(resolve_dir "$HOME")" || home_real="$HOME"
if [ "$workdir" = "/" ] || [ "$workdir" = "$home_real" ]; then
  echo "sandfence.sh: refusing to grant '$workdir' read-write — run from a project subdirectory, not / or \$HOME" >&2; exit 1
fi
case "$home_real/" in
  "$workdir"/*) echo "sandfence.sh: refusing to grant '$workdir' read-write — it contains your home directory" >&2; exit 1 ;;
esac

dynamic=";; --- working copy (read-write) ---"$'\n'
repo_deny=";; --- repo history + agent config: working copy's own .git/.jj/.claude/.grok/… write-denied (last) ---"$'\n'
grant_rw "$workdir"
deny_repo_meta "$workdir"

# Worktree / workspace: if the working copy's VCS metadata points at a MAIN repo
# elsewhere, grant READ-ONLY access to that repo's STORE only — never its working
# copy (which may hold its own secrets). The pointer is repo-controlled, so we
# require a REAL VCS store that is a direct SIBLING of the workspace; other layouts,
# pass the store with -r (e.g. -r ../main/.git). See DESIGN.md ("Worktrees").
# Resolution runs unsandboxed; /usr/bin/git is absolute so a hostile PATH can't hijack it.
if [ -x /usr/bin/git ] && [ -f "$workdir/.git" ]; then               # git worktree: .git is a FILE
  gitcommon="$(abspath "$(cd "$workdir" && /usr/bin/git rev-parse --git-common-dir 2>/dev/null || true)" "$workdir")"
  mainroot="${gitcommon%/*}"                                         # common dir is <mainroot>/.git
  if [ -n "$gitcommon" ] && is_git_store "$gitcommon" \
     && [ -n "${mainroot%/*}" ] && [ "${mainroot%/*}" = "${workdir%/*}" ]; then   # real store + non-root sibling
    sect "main repo .git store (sibling worktree, read-only)"; grant_ro "$gitcommon"
  fi
fi
if [ -f "$workdir/.jj/repo" ]; then                                  # secondary jj workspace: .jj/repo is a FILE
  jjrepo="$(abspath "$(<"$workdir/.jj/repo")" "$workdir/.jj")"   # → the main .jj/repo store (read via builtin)
  mainroot="${jjrepo%/.jj/repo}"                                     # store is <mainroot>/.jj/repo
  if [ -n "$jjrepo" ] && [ "${jjrepo##*/.jj/}" = repo ] && [ -d "$jjrepo/store" ] \
     && [ -n "${mainroot%/*}" ] && [ "${mainroot%/*}" = "${workdir%/*}" ]; then   # real store + non-root sibling
    sect "main repo .jj store (sibling workspace, read-only)"; grant_ro "$jjrepo"
    # jj uses a git backend: a colocated main repo keeps its commits in <mainroot>/.git.
    # Validate it like the worktree store so a forged/symlinked .git can't redirect the grant.
    gitbackend="$(abspath "$mainroot/.git" "$mainroot")"
    if [ -n "$gitbackend" ] && is_git_store "$gitbackend" && [ "${gitbackend%/*}" = "$mainroot" ]; then
      sect "main repo git backend (.git, read-only)"; grant_ro "$gitbackend"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Agent bundles (--claude/--codex/--grok, or the agent as the tool): grant each
# agent's own binary + state dir. Auth is a file there (~/.claude/.credentials.json,
# ~/.codex/auth.json, ~/.grok/auth.json), never the Keychain. settings.json / config.toml are
# write-denied — they carry hooks / MCP / notify commands that would fire on a
# later UNsandboxed run (the deny follows the rw grant, so last-match-wins blocks
# the write while reads still work). See DESIGN.md ("Agent bundles").
# ---------------------------------------------------------------------------
for a in "${agents[@]+"${agents[@]}"}"; do
  case "$a" in
    claude)
      sect "claude: binary (ro) + own state (rw); settings.json write-denied"
      claude_bin="$(command -v claude || true)"
      case "$claude_bin" in /*) grant_file "$claude_bin" ;; esac   # absolute only
      grant_ro "$HOME/.local/share/claude"
      grant_rw "$HOME/.claude"
      dynamic+="(deny file-write* (literal \"$HOME/.claude/settings.json\") (literal \"$HOME/.claude/settings.local.json\"))"$'\n'
      grant_rw "$HOME/.cache/claude"
      grant_rw "$HOME/.local/state/claude"
      dynamic+="(allow file-read* file-write* (prefix \"$HOME/.claude.json\"))"$'\n'   # ~/.claude.json[.backup]: session/project state
      dynamic+="(allow file-read* file-write* (literal \"$HOME/.claude.lock\"))"$'\n'
      ;;
    codex)
      sect "codex: node runtime (ro) + own state incl. auth.json (rw); config.toml write-denied"
      grant_rw "$HOME/.codex"
      dynamic+="(deny file-write* (literal \"$HOME/.codex/config.toml\"))"$'\n'
      codex_bin="$(command -v codex || true)"
      case "$codex_bin" in /*) ;; *) codex_bin="" ;; esac   # ignore a relative hit (PATH has '.') — untrusted + would hang emit_ancestors
      if [[ -n "$codex_bin" ]]; then
        grant_file "$codex_bin"                               # the codex executable (exec'd only in-sandbox)
        # codex needs its node runtime readable. Auto-grant ONLY the canonical nvm
        # layout, matched positively (a blocklist of shared prefixes is never complete).
        # Other node managers: brew → --brew; fnm → --node; volta → grant the version dir with -r.
        noderoot="${codex_bin%/bin/codex}"                    # …/<v>/bin/codex → the node version dir
        case "$noderoot" in
          "$HOME"/.nvm/versions/node/*)
            grant_ro "$noderoot"
            dynamic+="(deny file-read* (literal \"$noderoot/etc/npmrc\"))"$'\n' ;;   # …minus its global npmrc (may hold a registry token)
        esac
      fi
      ;;
    grok)
      sect "grok: ~/.grok read-only, its runtime state (rw) allowlisted; leader sockets denied"
      grok_bin="$(command -v grok || true)"
      case "$grok_bin" in /*) grant_file "$grok_bin" ;; esac   # absolute only (~/.local/bin/grok → a symlink into ~/.grok)
      # ~/.grok mixes state with code a later UNsandboxed grok runs (its binary, a ripgrep, hooks,
      # lsp.json, folder trust). So: read-only, then its runtime state opened by name; new names stay denied.
      grant_ro "$HOME/.grok"
      # A (prefix) also covers .lock/-wal/.tmp siblings and a dir's contents. Deliberately absent though
      # rewritten at launch (grok refetches them): settings_cache.json, models_cache.json, version.json, docs/.
      for f in auth.json active_sessions agent_id mcp_credentials.json tip_cursor.json slash-mru.json \
               last-copy.txt worktrees.db CHANGELOG managed_config.lock trusted_folders.toml.lock \
               .config-init.lock .metadata_version .tmp sessions logs memory memtrace grove; do
        dynamic+="(allow file-write* (prefix \"$HOME/.grok/$f\"))"$'\n'
      done
      # …except a project's remembered grants (sessions/<project>/permission*.toml), at any depth.
      dynamic+="(deny file-write* (require-all (subpath \"$HOME/.grok/sessions\") (regex #\"/permission[^/]*\\.toml\$\")))"$'\n'
      # No unix sockets under ~/.grok: never join (or squat on) an UNsandboxed grok's leader.
      dynamic+="(deny network-outbound network-bind (subpath \"$HOME/.grok\"))"$'\n'
      # Without the WindowServer, grok's TUI deadlocks on Backspace/Esc. See DESIGN.md for the cost.
      dynamic+="(allow mach-lookup (global-name \"com.apple.windowserver.active\"))"$'\n'
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Toolchain presets (--brew/--rust/--node/--python/--go): named bundles of -r/-w grants.
# Caches writable, but registry/publish TOKENS and PATH-plant vectors (bin dirs,
# build-command config) stay denied. Anything here is also doable by hand with
# -r/-w. Assumes Homebrew, rustup/cargo, nvm/fnm, Apple-python, default-go layouts; for pyenv/etc. use -r.
# ---------------------------------------------------------------------------
for p in "${presets[@]+"${presets[@]}"}"; do
  case "$p" in
    brew)
      # Prefix from the launcher's env (brew shellenv sets it), else the Apple Silicon default. It must
      # hold a real Homebrew (bin/brew) so a stale value fails loudly instead of granting another tree.
      brew_prefix="${HOMEBREW_PREFIX:-/opt/homebrew}"; brew_prefix="${brew_prefix%/}"
      validate_path "$brew_prefix" "HOMEBREW_PREFIX"
      [ -x "$brew_prefix/bin/brew" ] || { echo "sandfence.sh: --brew: no Homebrew at $brew_prefix (set HOMEBREW_PREFIX)" >&2; exit 1; }
      sect "preset: homebrew (prefix ro; var/, etc/homebrew/, etc/npmrc denied)"
      grant_ro "$brew_prefix"                 # every formula readable + runnable; nothing writable (no brew/pip/npm -g installs)
      # Read-denied after the grant (-r re-opens): var/ is service data + logs (postgres, mysql, redis);
      # etc/homebrew/ is brew's own config (brew.env: HOMEBREW_GITHUB_API_TOKEN); etc/npmrc is brew-node's
      # global npm config (registry token), like the nvm one under --node.
      dynamic+="(deny file-read* (subpath \"$brew_prefix/var\") (subpath \"$brew_prefix/etc/homebrew\") (literal \"$brew_prefix/etc/npmrc\"))"$'\n'
      ;;
    rust)
      sect "preset: rust (toolchains ro; cargo caches rw; bin ro; env/config/token denied)"
      grant_ro "$HOME/.rustup"                # toolchains: rustc, std
      grant_rw "$HOME/.cargo"                 # registry/git caches (also provides jj)
      # ~/.cargo/bin (on PATH) and ~/.cargo/env (shell-sourced) are write-denied so a run
      # can't plant a PATH binary or shell hook — blocks `cargo install`, not `cargo build`.
      # config[.toml] (build hooks / registry.token) and credentials are read+write denied.
      # cargo treats a denied config as absent; re-open a custom one with -r ~/.cargo/config.toml.
      # All after the rw grant (last-match-wins).
      dynamic+="(deny file-write* (subpath \"$HOME/.cargo/bin\") (literal \"$HOME/.cargo/env\"))"$'\n'
      dynamic+="(deny file-read* file-write* (literal \"$HOME/.cargo/config\") (literal \"$HOME/.cargo/config.toml\") (literal \"$HOME/.cargo/credentials.toml\") (literal \"$HOME/.cargo/credentials\"))"$'\n'
      ;;
    node)
      sect "preset: node/npm (nvm + fnm + corepack + pnpm home ro; npm/pnpm caches rw; config + registry token denied)"
      grant_ro "$HOME/.nvm"                   # nvm: node versions + nvm itself
      grant_rw "$HOME/.npm"                   # npm cache
      dynamic+="(deny file-read* (subpath \"$HOME/.npm/_logs\"))"$'\n'   # logs can hold old tokens; writes still allowed
      for nr in "$HOME"/.nvm/versions/node/*/etc/npmrc; do   # each version's global npmrc can hold a registry token
        [ -e "$nr" ] && { validate_path "$nr" grant; dynamic+="(deny file-read* (literal \"$nr\"))"$'\n'; }
      done
      # fnm: FNM_DIR from the env (`fnm env` exports it), else fnm's default locations. Read-only like
      # ~/.nvm (fnm install / npm -g would plant a binary a later UNsandboxed shell execs); pinned in
      # the env so fnm inside uses the granted tree.
      fnm_dir="$(canon_dir "${FNM_DIR:-}")"
      [ -n "$fnm_dir" ] || for d in "$HOME/.local/share/fnm" "$HOME/.fnm" "$HOME/Library/Application Support/fnm"; do
        [ -d "$d" ] && { fnm_dir="$(canon_dir "$d")"; break; }
      done
      if [[ -n "$fnm_dir" ]]; then
        export FNM_DIR="$fnm_dir"
        grant_ro "$fnm_dir"
        for nr in "$fnm_dir"/node-versions/*/installation/etc/npmrc; do   # per-version global npmrc: registry token
          [ -e "$nr" ] && { validate_path "$nr" grant; dynamic+="(deny file-read* (literal \"$nr\"))"$'\n'; }
        done
        # `fnm env` puts $FNM_MULTISHELL_PATH/bin on PATH: a per-shell symlink to one version. Readable, so
        # node resolves through it; its dir is write-denied (older fnm keeps it under $TMPDIR, granted rw)
        # so `fnm use` can't re-point the LAUNCHING shell's node at a planted binary. Parent canonicalized
        # (Seatbelt matches resolved paths; $TMPDIR goes through /var → /private/var), the link itself kept.
        ms=""; case "${FNM_MULTISHELL_PATH:-}" in /*) ms="$(resolve_file "$FNM_MULTISHELL_PATH" || true)" ;; esac
        if [[ "$ms" == /*/* ]]; then
          grant_file "$ms"
          dynamic+="(deny file-write* (subpath \"${ms%/*}\") (literal \"${ms%/*}\"))"$'\n'
        fi
      fi
      # corepack (node's pnpm/yarn shims): its home read-only, pinned in the env. Cached package managers
      # run; fetching one fails (a planted one would be exec'd by a later UNsandboxed shim) — run
      # `corepack prepare <pm>@<ver> --activate` (or a first `pnpm --version`) outside once.
      corepack_home="$(canon_dir "${COREPACK_HOME:-$HOME/.cache/node/corepack}")"
      export COREPACK_HOME="$corepack_home"
      grant_ro "$corepack_home"
      # pnpm: home read-only (bin/ + global/ are on PATH; self-fetched pnpm/node versions there run
      # later UNsandboxed), pinned in the env; the store inside it + the cache read-write (created at
      # launch, below), minus the dlx cache (a later UNsandboxed `pnpm dlx` execs it — so dlx can't
      # fetch inside; use installed deps). The store is pinned too: without an explicit store-dir pnpm
      # probes hard-linking into its read-only home and silently falls back to a shadow store inside
      # the project. pnpm ≥11 reads pnpm_config_*; ≤10 reads npm's user config (written at launch,
      # below — npm ≥11 warns about unknown npm_config_* env vars on every command).
      # Global config (~/Library/Preferences/pnpm: registry token, npmPath/scriptShell) stays denied.
      pnpm_home="$(canon_dir "${PNPM_HOME:-$HOME/Library/pnpm}")"
      export PNPM_HOME="$pnpm_home"
      pnpm_store="$(canon_dir "$pnpm_home/store")"; pnpm_cache="$HOME/Library/Caches/pnpm"
      export pnpm_config_store_dir="$pnpm_store"
      grant_ro "$pnpm_home"
      grant_rw "$pnpm_store"
      grant_rw "$pnpm_cache"
      dynamic+="(deny file-write* (subpath \"$pnpm_cache/dlx\"))"$'\n'
      # NOT granted (default-deny): ~/.npmrc + the global config/bin homes — they hold the
      # registry token and -g install bins. Point npm's USER config at a launch-written file holding
      # only pnpm's store-dir, so it neither reads your token nor EPERM-crashes. yarn: grant its cache
      # with -w. Private registry / other node managers (volta, brew → --brew): -r <path> (and set
      # NPM_CONFIG_USERCONFIG to it, adding store-dir=<PNPM_HOME>/store for pnpm ≤10). See DESIGN.md.
      export NPM_CONFIG_USERCONFIG="${NPM_CONFIG_USERCONFIG:-$pnpm_cache/npmrc}"
      ;;
    python)
      sect "preset: python (pip cache rw)"
      grant_rw "$HOME/Library/Caches/pip"     # pip download cache (macOS)
      # The interpreter is whatever python3 is on PATH: Apple's /usr/bin/python3 is in the baseline,
      # a brew one needs --brew, pyenv needs -r ~/.pyenv. An ungranted one fails to exec, loudly.
      ;;
    go)
      # Caches: the launcher's env (first GOPATH entry) or go's macOS defaults, canonicalized when they exist
      # (the denies below check resolved paths) and exported so go inside uses what's granted. Toolchain:
      # whatever go is on PATH (/usr/local/go is in the baseline; brew's → --brew).
      gopath="${GOPATH:-$HOME/go}"; gopath="$(canon_dir "${gopath%%:*}")"; gopath="${gopath:-$HOME/go}"
      gomodcache="$(canon_dir "${GOMODCACHE:-$gopath/pkg/mod}")"
      gocache="$(canon_dir "${GOCACHE:-$HOME/Library/Caches/go-build}")"
      export GOPATH="$gopath" GOMODCACHE="$gomodcache" GOCACHE="$gocache"
      sect "preset: go (caches rw; GOPATH/bin ro; downloaded toolchains write-denied; vcs clones denied)"
      grant_rw "$gomodcache"                  # modules
      grant_rw "$gopath/pkg/sumdb"            # checksum-db state
      grant_rw "$gocache"                     # build cache (go aborts without it; all three created after --print)
      grant_ro "$gopath/bin"                  # tools run; `go install` into it (a PATH dir) fails
      # Carved out of the module cache: auto-downloaded toolchains are write-denied (a later UNsandboxed go
      # execs them); cache/vcs/ clones are denied outright (git config there can name a command or hold a
      # URL-embedded token). So fetch a newer Go / GOPROXY=direct outside.
      dynamic+="(deny file-write* (prefix \"$gomodcache/golang.org/toolchain@\") (subpath \"$gomodcache/cache/download/golang.org/toolchain\"))"$'\n'
      dynamic+="(deny file-read* file-write* (subpath \"$gomodcache/cache/vcs\"))"$'\n'
      # NOT granted: the `go env -w` store, ~/Library/Application Support/go/env (GOPROXY can embed a token;
      # GOFLAGS/CC are commands). go treats it as absent; -r it to keep yours. Telemetry dir: skipped silently.
      ;;
  esac
done

# TLS roots: with the Keychain denied, Rust/OpenSSL tools fail ("no native root CA
# certificates found"). Point them at the public CA bundle (already a granted read;
# no Keychain/securityd access). SSL_CERT_FILE is on the env allowlist below.
if [[ -z "${SSL_CERT_FILE:-}" ]]; then
  for ca in /private/etc/ssl/cert.pem /etc/ssl/cert.pem; do
    [[ -r "$ca" ]] && { export SSL_CERT_FILE="$ca"; break; }
  done
fi

# git/jj read their global config under $XDG_CONFIG_HOME (default ~/.config). Fall
# back to ~/.config if it's relative (git/jj ignore a relative XDG too) or SBPL-unsafe.
xdg_config="${XDG_CONFIG_HOME:-$HOME/.config}"
case "$xdg_config" in /*) ;; *) xdg_config="$HOME/.config" ;; esac
if [[ "$xdg_config" == *'"'* || "$xdg_config" == *'\'* || "$xdg_config" =~ [[:cntrl:]] ]]; then
  xdg_config="$HOME/.config"
fi

# Global git ignore/attributes: grant just those two files + dir lookup (not listing),
# so git honors them without exposing the token-bearing config or credential store alongside.
xdg_git="$xdg_config/git"
sect "global git ignore/attributes (read-only)"
emit_ancestors "$xdg_git"
dynamic+="(allow file-read-metadata (literal \"$xdg_git\"))"$'\n'
dynamic+="(allow file-read* (literal \"$xdg_git/ignore\") (literal \"$xdg_git/attributes\"))"$'\n'

# jj: grant its binary + read-only user config whenever jj is installed (so jj is
# available like git, not only inside a jj repo). Read-only config stops a run planting
# config that fires on a later UNsandboxed jj; .jj in the working copy is write-denied,
# so read-only jj needs `--ignore-working-copy`. A symlinked/shim install whose target
# is in an ungranted tree isn't auto-resolved (brew → --brew, else -r); cargo/direct installs work.
jj_bin="$(command -v jj 2>/dev/null || true)"
if [[ "$jj_bin" == /* ]]; then                          # jj is installed at an absolute path
  sect "jj: binary (ro) + user config (ro)"
  grant_file "$jj_bin"
  grant_ro "$xdg_config/jj"
fi

# -r / -w: extra read-only / read-write access to a dir or single file (repeatable).
# Emitted LAST so an explicit grant WINS over a preset/agent deny (e.g. -r ~/.cargo/config.toml
# re-opens what --rust denied). A -w dir keeps its own .git/.jj + agent config read-only; -r is read-only
# wholesale. Explicit opt-ins, so (unlike the working copy) not home-guarded. (The .git/.jj
# history + agent-config denies still come after, in $repo_deny, so those stay non-overridable.)
if [[ ${#writes[@]} -gt 0 || ${#reads[@]} -gt 0 ]]; then
  sect "extra access (-r / -w; wins over presets/agents)"
fi
for p in "${writes[@]+"${writes[@]}"}"; do
  if   [ -d "$p" ]; then rp="$(resolve_dir  "$p")" || { echo "sandfence.sh: -w: cannot resolve: $p" >&2; exit 1; }; grant_rw "$rp"; deny_repo_meta "$rp"
  elif [ -e "$p" ]; then rp="$(resolve_file "$p")" || { echo "sandfence.sh: -w: cannot resolve: $p" >&2; exit 1; }; grant_file_rw "$rp"
  else echo "sandfence.sh: -w: no such file or directory: $p" >&2; exit 1; fi
done
for p in "${reads[@]+"${reads[@]}"}"; do
  if   [ -d "$p" ]; then rp="$(resolve_dir  "$p")" || { echo "sandfence.sh: -r: cannot resolve: $p" >&2; exit 1; }; grant_ro "$rp"
  elif [ -e "$p" ]; then rp="$(resolve_file "$p")" || { echo "sandfence.sh: -r: cannot resolve: $p" >&2; exit 1; }; grant_file "$rp"
  else echo "sandfence.sh: -r: no such file or directory: $p" >&2; exit 1; fi
done

# Point git at an empty global config (we don't grant ~/.gitconfig — it can carry
# credentials), so git neither reads it nor warns on the denied path; commits are denied
# anyway. Soft default so a caller-set GIT_CONFIG_GLOBAL (to a granted file) still wins.
# Global excludes/attributes are honored via read grants above, not this override.
export GIT_CONFIG_GLOBAL="${GIT_CONFIG_GLOBAL:-/dev/null}"

profile="(version 1)
(define HOME_DIR \"$HOME\")
$static_body
$dynamic
$repo_deny"

[[ -n "$print_only" ]] && { printf '%s\n' "$profile"; exit 0; }

# Ensure each active agent's config dir exists: once boxed the agent can't create it
# ($HOME isn't writable inside), so a fresh user's first in-sandbox /login could not
# save its credentials. After --print so printing has no side effects.
for a in "${agents[@]+"${agents[@]}"}"; do
  case "$a" in
    claude) mkdir -p "$HOME/.claude" 2>/dev/null || true ;;
    codex)  mkdir -p "$HOME/.codex"  2>/dev/null || true ;;
    grok)   mkdir -p "$HOME/.grok"   2>/dev/null || true ;;
  esac
done
# --go caches: go aborts if it can't create them, and their parents aren't writable inside.
[ -n "${gocache:-}" ] && { mkdir -p "$gopath/pkg/sumdb" "$gomodcache" "$gocache" 2>/dev/null || true; }
# --node: pnpm's store + cache — their parents aren't writable inside (a corepack-only user has no ~/Library/pnpm) —
# and npm's user config carrying the store-dir for pnpm ≤10 (see the preset).
[ -n "${pnpm_store:-}" ] && { mkdir -p "$pnpm_store" "$pnpm_cache" 2>/dev/null || true; }
[ "${NPM_CONFIG_USERCONFIG:-}" = "${pnpm_cache:-}/npmrc" ] && { printf 'store-dir=%s\n' "$pnpm_store" > "$NPM_CONFIG_USERCONFIG" 2>/dev/null || true; }

# Run with an ALLOWLISTED environment, not the caller's full env: env vars are inherited
# regardless of the profile, so ambient secrets (AWS_*, GITHUB_TOKEN, OPENAI_API_KEY,
# SSH_AUTH_SOCK, …) would otherwise reach the command and every child. Pass only operational
# basics (+ the redirects/paths computed above); add a non-secret name below if a task needs it.
clean_env=()
for name in PATH HOME USER LOGNAME SHELL TERM TMPDIR PWD \
            LANG LC_ALL LC_CTYPE TERM_PROGRAM COLORTERM __CF_USER_TEXT_ENCODING \
            XDG_CONFIG_HOME SSL_CERT_FILE GIT_CONFIG_GLOBAL NPM_CONFIG_USERCONFIG \
            HOMEBREW_PREFIX GOPATH GOMODCACHE GOCACHE \
            FNM_DIR FNM_MULTISHELL_PATH FNM_VERSION_FILE_STRATEGY FNM_RESOLVE_ENGINES \
            FNM_COREPACK_ENABLED FNM_ARCH FNM_LOGLEVEL COREPACK_HOME PNPM_HOME \
            pnpm_config_store_dir; do                       # brew shellenv's prefix; --go caches;
                                                            # --node's fnm dir + `fnm env` settings (not the dist mirror: a URL
                                                            # can embed a token) + corepack/pnpm homes + pnpm's store
  [ -n "${!name:-}" ] && clean_env+=("$name=${!name}")   # include only vars that are actually set
done

# Pin absolute paths: the wrapper runs UNsandboxed, so a hostile PATH could otherwise
# hijack env / sandbox-exec.
exec /usr/bin/env -i "${clean_env[@]+"${clean_env[@]}"}" \
  /usr/bin/sandbox-exec -p "$profile" "${cmd[@]}" "$@"
