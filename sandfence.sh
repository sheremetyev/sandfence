#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# sandfence.sh — run a command under a default-deny macOS sandbox-exec profile.
#
# Grants the secret-free system baseline plus the working copy: the current
# directory is read-write, with its own .git/.jj write-denied so the agent can
# edit code but not rewrite history. Nothing else under $HOME is granted —
# ~/.ssh, ~/.aws, the login Keychain, ~/.gitconfig credentials stay denied.
#
# Usage:  sandfence.sh [--print] <tool> [args...]
# ============================================================================

usage() {
  printf '%s\n' \
    'Usage: sandfence.sh [--print] <tool> [args...]' \
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
sect()          { dynamic+=";; --- $1 ---"$'\n'; }                                                                                    # labeled comment in the profile
deny_repo_meta() {            # <abs-dir> — write-deny its own top-level .git/.jj
  repo_deny+="(deny file-write* (subpath \"$1/.git\") (literal \"$1/.git\") (subpath \"$1/.jj\") (literal \"$1/.jj\"))"$'\n'
}

# ---------------------------------------------------------------------------
# Parse args: --print, then the tool + its args.
# ---------------------------------------------------------------------------
print_only=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--print) print_only=1; shift ;;
    -h|--help)  usage 0 ;;
    --)         shift; break ;;
    -*)         echo "sandfence.sh: unknown flag: $1" >&2; usage 1 ;;
    *)          break ;;
  esac
done
if [[ $# -ge 1 ]]; then
  tool="$1"; shift; cmd=("$tool")
elif [[ -n "$print_only" ]]; then
  tool=""; cmd=()                 # --print with no tool: show the baseline profile
else
  usage 1
fi

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

# Point git at an empty global config (we don't grant ~/.gitconfig — it can carry
# credentials), so git neither reads it nor warns on the denied path; commits are
# denied anyway. Soft default so a caller-set GIT_CONFIG_GLOBAL (granted) still wins.
export GIT_CONFIG_GLOBAL="${GIT_CONFIG_GLOBAL:-/dev/null}"

profile="(version 1)
(define HOME_DIR \"$HOME\")
$static_body
$dynamic
$repo_deny"

[[ -n "$print_only" ]] && { printf '%s\n' "$profile"; exit 0; }

# Pin absolute paths: the wrapper runs UNsandboxed, so a hostile PATH could
# otherwise hijack sandbox-exec.
exec /usr/bin/sandbox-exec -p "$profile" "${cmd[@]}" "$@"
