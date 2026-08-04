#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# sandfence.sh — run a command under a default-deny macOS sandbox-exec profile.
#
# Grants: system runtime, temp, devices, process + network, the working copy
# (read-write, its own .git/.jj read-only), and a few read-only tool configs.
# Denied by default: the rest of $HOME — ~/.ssh, ~/.aws, the login Keychain,
# ~/.gitconfig credentials. See DESIGN.md for how it works and why each grant exists.
#
# Usage:  sandfence.sh [-r PATH]... [-w PATH]... [--rust|--node|--python]
#                      [--claude|--codex] [--print] <tool> [args...]
# ============================================================================

usage() {
  printf '%s\n' \
    'Usage: sandfence.sh [-r PATH]... [-w PATH]... [--print] <tool> [args...]' \
    '  -r PATH    read-only access to a dir or file   (repeatable)' \
    '  -w PATH    read-write access to a dir or file  (repeatable; a dir keeps its .git/.jj read-only)' \
    '  --claude   also grant the claude agent bundle (binary + ~/.claude state; auth via file, not Keychain)' \
    '  --codex    also grant the codex agent bundle  (binary + node runtime + ~/.codex state)' \
    '  --rust/--node/--python  toolchain preset: caches writable, registry tokens + PATH-plant denied' \
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
deny_repo_meta() {            # <abs-dir> — write-deny its own top-level .git/.jj
  repo_deny+="(deny file-write* (subpath \"$1/.git\") (literal \"$1/.git\") (subpath \"$1/.jj\") (literal \"$1/.jj\"))"$'\n'
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
    --claude|--codex) agents+=("${1#--}"); shift ;;
    --rust|--node|--python) presets+=("${1#--}"); shift ;;
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
    *)      cmd=("$tool") ;;
  esac
elif [[ -n "$print_only" ]]; then
  tool=""; cmd=()                 # --print with no tool: show the baseline profile
else
  usage 1
fi
# The tool's own bundle auto-applies; --claude/--codex add the OTHER agent's bundle too
# (e.g. `--codex claude` lets a claude session also read/run codex). See DESIGN.md ("Agent bundles").
case "$tool" in claude|codex) agents+=("$tool") ;; esac

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
# last) so the agent can edit code but can't commit, amend, or rewrite history.
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
repo_deny=";; --- repo history: working copy's own .git/.jj write-denied (last) ---"$'\n'
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
# Agent bundles (--claude/--codex, or claude/codex as the tool): grant each
# agent's own binary + state dir. Auth is a file there (~/.claude/.credentials.json,
# ~/.codex/auth.json), never the Keychain. settings.json / config.toml are
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
        # Other node managers (brew, fnm, volta): grant the version dir with -r.
        noderoot="${codex_bin%/bin/codex}"                    # …/<v>/bin/codex → the node version dir
        case "$noderoot" in
          "$HOME"/.nvm/versions/node/*)
            grant_ro "$noderoot"
            dynamic+="(deny file-read* (literal \"$noderoot/etc/npmrc\"))"$'\n' ;;   # …minus its global npmrc (may hold a registry token)
        esac
      fi
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Toolchain presets (--rust/--node/--python): named bundles of -r/-w grants.
# Caches writable, but registry/publish TOKENS and PATH-plant vectors (bin dirs,
# build-command config) stay denied. Anything here is also doable by hand with
# -r/-w. Assumes rustup/cargo, nvm, Apple-python layouts; for brew/pyenv/etc. use -r.
# ---------------------------------------------------------------------------
for p in "${presets[@]+"${presets[@]}"}"; do
  case "$p" in
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
      sect "preset: node/npm (nvm ro; npm cache rw; config + registry token denied)"
      grant_ro "$HOME/.nvm"                   # node versions + nvm
      grant_rw "$HOME/.npm"                   # npm cache
      dynamic+="(deny file-read* (subpath \"$HOME/.npm/_logs\"))"$'\n'   # logs can hold old tokens; writes still allowed
      for nr in "$HOME"/.nvm/versions/node/*/etc/npmrc; do   # each version's global npmrc can hold a registry token
        [ -e "$nr" ] && dynamic+="(deny file-read* (literal \"$nr\"))"$'\n'
      done
      # NOT granted (default-deny): ~/.npmrc + the global config/bin homes — they hold the
      # registry token and -g install bins. Point npm's USER config at an empty file so it
      # neither reads your token nor EPERM-crashes. Stock npm only; for pnpm/yarn grant their
      # store with -w. Private registry / non-nvm node: -r <path> (and set NPM_CONFIG_USERCONFIG
      # to it). See DESIGN.md ("Toolchain presets").
      export NPM_CONFIG_USERCONFIG="${NPM_CONFIG_USERCONFIG:-/dev/null}"
      ;;
    python)
      sect "preset: python (pip cache rw; Apple /usr/bin/python3)"
      grant_rw "$HOME/Library/Caches/pip"     # pip download cache (macOS)
      # Apple's /usr/bin/python3 (already in the baseline). Prepend /usr/bin so `python3`
      # resolves to it, not an ungranted brew/pyenv python. For those, grant the prefix with -r.
      export PATH="/usr/bin:${PATH:-}"
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
# is in an ungranted tree isn't auto-resolved (use -r); cargo/direct installs work.
jj_bin="$(command -v jj 2>/dev/null || true)"
if [[ "$jj_bin" == /* ]]; then                          # jj is installed at an absolute path
  sect "jj: binary (ro) + user config (ro)"
  grant_file "$jj_bin"
  grant_ro "$xdg_config/jj"
fi

# -r / -w: extra read-only / read-write access to a dir or single file (repeatable).
# Emitted LAST so an explicit grant WINS over a preset/agent deny (e.g. -r ~/.cargo/config.toml
# re-opens what --rust denied). A -w dir keeps its own .git/.jj read-only; -r is read-only
# wholesale. Explicit opt-ins, so (unlike the working copy) not home-guarded. (The .git/.jj
# history denies still come after, in $repo_deny, so those stay non-overridable.)
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
  esac
done

# Run with an ALLOWLISTED environment, not the caller's full env: env vars are inherited
# regardless of the profile, so ambient secrets (AWS_*, GITHUB_TOKEN, OPENAI_API_KEY,
# SSH_AUTH_SOCK, …) would otherwise reach the command and every child. Pass only operational
# basics (+ the redirects/paths computed above); add a non-secret name below if a task needs it.
clean_env=()
for name in PATH HOME USER LOGNAME SHELL TERM TMPDIR PWD \
            LANG LC_ALL LC_CTYPE TERM_PROGRAM COLORTERM __CF_USER_TEXT_ENCODING \
            XDG_CONFIG_HOME SSL_CERT_FILE GIT_CONFIG_GLOBAL NPM_CONFIG_USERCONFIG; do
  [ -n "${!name:-}" ] && clean_env+=("$name=${!name}")   # include only vars that are actually set
done

# Pin absolute paths: the wrapper runs UNsandboxed, so a hostile PATH could otherwise
# hijack env / sandbox-exec.
exec /usr/bin/env -i "${clean_env[@]+"${clean_env[@]}"}" \
  /usr/bin/sandbox-exec -p "$profile" "${cmd[@]}" "$@"
