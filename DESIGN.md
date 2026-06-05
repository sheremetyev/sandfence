# How sandfence works

This explains the design behind `sandfence.sh` — enough to understand, audit, and
extend it. The [README](README.md) covers what it's for and the threat model; this
covers the mechanism and the non-obvious decisions. If you only read one other thing,
read the script: it's the whole tool, and `--print` shows you exactly what any
invocation grants.

## The idea

A coding agent run with `--dangerously-skip-permissions` will do whatever its model
decides — including the occasional wrong `rm -rf`, `git reset --hard`, or
`pip install` into your system. sandfence puts the **OS kernel** between the agent and
your machine: the agent runs normally, but every file open is checked against a
profile the kernel enforces. The agent can't talk its way past it, because it isn't
the agent's decision.

The tool is one wrapper script. It composes a sandbox profile, then `exec`s your
command under `sandbox-exec` with that profile and a scrubbed environment. Nothing
runs as a daemon; there's no VM, no image, no state.

## sandbox-exec / Seatbelt in 60 seconds

macOS has a kernel sandbox (Seatbelt). `/usr/bin/sandbox-exec -p <profile> <cmd>`
applies a profile to a process and everything it spawns. Profiles are written in
**SBPL** — TinyScheme S-expressions beginning with `(version 1)`. A profile is a list
of rules:

```scheme
(deny default)                                  ; deny everything…
(allow file-read* (subpath "/usr"))             ; …then re-allow specific things
(allow file-read* file-write* (subpath "/tmp"))
```

Four path filters do most of the work: `(literal "/x")` (exactly that path),
`(subpath "/x")` (that path and everything under it), `(prefix "/x")` (string prefix),
and `(regex #"…")`. Operations include `file-read*`, `file-write*`,
`file-read-metadata`, `process-exec`, `network*`, `mach-lookup`, and more.

Three facts about Seatbelt shape the whole design:

- **Last match wins.** Rules are evaluated top to bottom and the *last* one that
  matches a request decides it. The widespread claim that "deny always beats allow" is
  false — Apple's own profiles re-`allow` paths they denied earlier. sandfence relies
  on this: it grants the working copy read-write, then emits a `(deny file-write* …)`
  for that copy's `.git`/`.jj` **after**, so the deny wins.
- **It checks the resolved path.** Symlinks are followed before the check, so a symlink
  in your repo pointing at `~/.ssh` is denied — you can't escape a confinement by
  pointing out of it.
- **Children inherit the sandbox.** Tests, dev servers, `npm install`, a `build.rs` —
  everything the agent spawns is confined by the same profile, automatically. This is
  what makes the guarantee hold for a coding agent, which mostly works by running other
  programs.

Two limitations worth knowing up front: `sandbox-exec` is **deprecated** (2017) but
still fully functional — macOS itself runs on the same engine — and it **can't nest**,
so you can't apply a profile from inside an already-sandboxed process (this is why the
test suite must run in a plain shell).

## How the profile is composed

`sandfence.sh` builds one big profile string in three parts, concatenated in this
order (so last-match-wins lands the way we want):

1. **Static baseline** (`$static_body`, a heredoc) — the read-only, secret-free
   necessities: system runtime, temp, devices, process control, network. Identical for
   every run.
2. **Dynamic grants** (`$dynamic`) — built up by the helper functions for this specific
   run: the working copy, any worktree/workspace store, agent bundles, toolchain
   presets, `-r`/`-w`, the jj binary, global git ignore.
3. **Repo-history denies** (`$repo_deny`) — the `.git`/`.jj` write-denies for every
   writable directory, emitted **dead last** so nothing can override them.

Run `sandfence.sh --print [flags] [tool]` to see the exact composed profile for any
invocation. To check that an edit still produces valid SBPL, compile it without
applying it:

```sh
sandfence.sh --print claude > /tmp/p.sb
sandbox-exec -f /tmp/p.sb /usr/bin/true; echo $?
#   exit 65  → SBPL syntax error (read the backtrace)
#   exit 71  → compiled fine, apply was blocked (you're inside a sandbox) — also a pass
#   exit 0   → compiled, applied, and ran
```

## The non-obvious bits

These are the things that aren't obvious from reading SBPL and cost real time to
discover. They're the reason several rules look the way they do.

**Traversal is separate from reading.** Being allowed to read `/a/b/c` does *not* let
you traverse `/a` and `/a/b` to reach it — Seatbelt checks a lookup permission on each
parent. So every granted path needs `file-read-metadata` (stat, not listing) on each of
its ancestors. `emit_ancestors` walks the chain and emits those. The payoff: ancestors
like `/Users` and your `$HOME` are *metadata-only* — reachable for traversal, but their
contents stay unlistable.

**…except the volume root `/`, which must be fully readable.** With `/` metadata-only,
*nothing launches* — even `sh -c true` fails. `/` is the one traversal grant nothing
else backstops, so it keeps `file-read*`. Listing `/` is harmless (it shows only
standard top-level directories).

**`(subpath "/System")` is a trap for reads.** That string also matches the firmlink at
`/System/Volumes/Data/…`, which is your entire data volume — *including your home
directory*. Granting `(allow file-read* (subpath "/System"))` would quietly expose
everything. sandfence grants the specific subpaths it needs (`/System/Library`,
`/System/Cryptexes`, …) and only `file-read-metadata` on `/System` itself.

**`exec` is bounded by traversal, not by read.** `process-exec` is allowed globally and
the kernel does not apply the `file-read` check to the image being exec'd. So the agent
can run a binary in any directory it can *reach*, even one it can't `cat`. This sounds
alarming but isn't: children inherit the sandbox, so this widens what can *launch*, not
what it can *do*, and `/usr/bin/*` is runnable regardless. Untraversable trees (other
users, an ungranted `/opt/homebrew`) stay blocked. (Aside: freshly *compiled* binaries
run fine — clang ad-hoc-signs them — but you can't `cp` a system binary and run the
copy; arm64 platform signatures are location-bound and the copy fails to exec even with
no sandbox at all.)

**The profile does not gate environment variables.** Seatbelt controls files and mach
services, but a child inherits the parent's environment untouched. So a profile alone
would leak every ambient secret in your shell (`AWS_*`, `GITHUB_TOKEN`,
`OPENAI_API_KEY`, `SSH_AUTH_SOCK`, …) straight to the agent. sandfence runs the command
with `env -i` and a small **allowlist** of operational variables, dropping everything
else. The matching hole on the kernel side — reading another process's environment via
`KERN_PROCARGS2` — is closed by denying `sysctl` `kern.procargs`/`kern.procargs2`.

**Denying the Keychain breaks TLS, so we redirect it.** Rust/OpenSSL tools verify
certificates against the macOS trust store, which lives behind the (denied) Keychain;
without it they fail with *"no native root CA certificates found."* sandfence points
them at the public CA bundle file (`/private/etc/ssl/cert.pem`, already a granted read)
via `SSL_CERT_FILE` — no Keychain access needed.

**Apple's `git`/`cc`/`python3` are stubs.** They resolve the real binary through the
developer-dir selectors under `/private/var/select`, and Apple's `git` stub reads the
Xcode license plist as a license check — deny it and *every* git operation fails with
"license not agreed." Both are granted read-only in the baseline. That's also why
`--python` simply prepends `/usr/bin` to `PATH`: Apple's `python3` needs no extra grants,
which keeps an ungranted Homebrew/pyenv tree out of the box.

## The working copy and history

The current directory is granted read-write — it's the unit of work. Its own top-level
`.git`/`.jj` is then write-denied, so the agent can edit code but cannot commit, amend,
rebase, or rewrite refs. **You** drive version control, from outside the sandbox, where
you can review the diff. `.git`/`.jj` *elsewhere* (a scratch checkout, a nested repo)
stays writable, so `git init`/`clone` still work.

sandfence refuses to run if the working copy would be `/`, `$HOME`, or a parent of
`$HOME` — that would hand the agent read-write to every secret under your home. Run it
from a project subdirectory.

Because jj snapshots the working copy into `.jj` on almost every command (a write, and
`.jj` is read-only), read-only jj commands must be run as `jj --ignore-working-copy …`.
sandfence deliberately doesn't auto-wrap `jj` (that breaks subcommands like `jj git
init`); tell the agent to add the flag.

## Worktrees and workspaces

When the working copy is a git *worktree* or a secondary jj *workspace*, its
`.git`/`.jj` is a pointer into a **main repo somewhere else**. sandfence resolves the
pointer and grants **read-only access to the main repo's VCS store only** — never the
main repo's working copy, which may hold its own `.env`/secrets.

The subtlety: that pointer file lives *inside* the workspace, so it's repo-controlled —
a malicious repo could forge it to point at `$HOME` or `/`. So the auto-grant fires only
when **both** hold: the target is a *real* VCS store (git: a `.git` dir with `HEAD` +
`objects/`; jj: a `.jj/repo` with `store/`), **and** the main repo is a *direct sibling*
of the workspace (same parent directory). That bounds a forged pointer to, at worst, "a
repo right next to mine," read-only — never your home or an arbitrary store. Other
layouts aren't auto-detected; pass the store explicitly with `-r ../main/.git`.

(A jj workspace also needs the main repo's colocated `.git`, because jj keeps commits in
a git backend. It's validated the same way — canonical path, real git store, sitting
exactly where expected — so a symlinked or forged `.git` can't redirect the grant.)

## Agent bundles

`claude`/`codex` as the tool (or `--claude`/`--codex` as a flag) adds a bundle for that
agent: read+exec of its own binary, and read-write to its own state directory. Two
deliberate choices:

- **Auth is a file, never the Keychain.** Each agent authenticates from a credential
  file in its own granted state dir (`~/.claude/.credentials.json`,
  `~/.codex/auth.json`) and refreshes it in place. The login Keychain is never granted,
  and the token never sits in the environment. The only credential the agent can reach
  is its own — which is what makes leaving the network open acceptable.
- **Persistence files are write-denied.** `~/.claude/settings.json` and
  `~/.codex/config.toml` carry hooks, MCP servers, and notify commands that would run on
  a *later, unsandboxed* invocation. They're readable but not writable (same
  last-match-wins trick as `.git`), so a sandboxed run can't plant something that fires
  outside the box later.

Note that Seatbelt grants are **per-process-tree, not per-executable**. So
`--codex claude` (run codex from inside a claude session) grants `~/.codex` to the whole
session — the claude process can read it too. That's the deliberate price of running one
agent inside the other; by default each tool gets only its own bundle.

## Toolchain presets

`--rust`/`--node`/`--python` are nothing more than named bundles of the same `-r`/`-w`
grants you could pass by hand. The principle is consistent throughout: **build caches
are writable, but registry/publish tokens and PATH-plant vectors stay denied.** So
`cargo build` and `npm install` work, while `~/.cargo/bin` (a binary planted there would
land on your PATH), `~/.cargo/credentials.toml` (the crates.io token), and `~/.npmrc`
(the registry token) do not.

They assume the common layouts — rustup/cargo, nvm, Apple's `python3`. Other toolchains
(Homebrew, pyenv, fnm, volta, pnpm, yarn) aren't auto-detected on purpose: a preset is a
real grant, and guessing wrong either over-exposes a tree or silently misses one.
Instead, grant exactly what they need with `-r`/`-w`. This is also where you'd add a new
preset — copy the shape of an existing `case` branch: grant the cache read-write, then
`(deny …)` the token/bin/config paths *after* the grant so the denies win.

## Widening the surface

`-r PATH` (read-only) and `-w PATH` (read-write) add access to a directory or a single
file. They're emitted **after** the presets and agent bundles, so an explicit grant
*wins* over a preset deny — e.g. `-r ~/.cargo/config.toml` re-opens what `--rust`
denied. The `.git`/`.jj` history denies come after even that, so they stay
non-overridable. A `-w` directory keeps its own `.git`/`.jj` read-only, just like the
working copy; `-r` directories are read-only wholesale. These are explicit opt-ins, so —
unlike the working copy — they aren't home-guarded; that's your responsibility.

Remember that anything you grant is visible not just to the agent but to **everything it
runs**. With the network open, a read grant is also an exfiltration surface for a
poisoned dependency. That's the boundary of what this tool defends — see the threat
model in the README.

## Testing

`test.sh <dir>` is the real test: it runs actual commands *inside* the sandbox and
asserts each allow/deny, rather than pattern-matching the profile text. A useful piece
of discipline in it: every "this should be denied" probe first confirms the target is
*readable unsandboxed*, so an in-sandbox denial is provably the sandbox's doing and not
a missing file (which would be a false pass).

Pass it a **real** directory, not `/tmp` — temp is granted read-write wholesale (tools
need it), which would mask the file-isolation tests. And run it in a plain shell:
`sandbox-exec` can't nest, so it won't run from inside an already-sandboxed session.
