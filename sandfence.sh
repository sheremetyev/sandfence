#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# sandfence.sh — run a command under a default-deny macOS sandbox-exec profile.
#
# The baseline grants only the boring, secret-free necessities — system runtime,
# temp, devices, process, and network — so a program can exec and run. Nothing
# under $HOME is granted, so secrets (~/.ssh, ~/.aws, the login Keychain) stay denied.
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

profile="(version 1)
(define HOME_DIR \"$HOME\")
$static_body"

[[ -n "$print_only" ]] && { printf '%s\n' "$profile"; exit 0; }

# Pin absolute paths: the wrapper runs UNsandboxed, so a hostile PATH could
# otherwise hijack sandbox-exec.
exec /usr/bin/sandbox-exec -p "$profile" "${cmd[@]}" "$@"
