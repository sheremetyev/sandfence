# Sandfence

Run a coding agent — **Claude Code** or **Codex** — on a repo in its own
"skip-permissions" mode, while the **macOS sandbox**, not the agent, enforces what it
can touch. A wrong `rm -rf`, a stray `git reset --hard`, a `pip install` into your
system: the sandbox turns these from incidents into errors.

```sh
s claude          # run Claude Code, confined to the current repo (setup below)
```

It's one short, auditable shell script around macOS `sandbox-exec` (the Seatbelt
sandbox). The agent gets read-write access to your working copy and the bare minimum to
run itself and your tests; everything else is denied by default and opened only when you
ask.

- **Native, in place** — the agent edits your real working copy with your real macOS
  toolchain. No Linux guest, no copied files, no syncing changes back.
- **Lightweight** — a sandboxed process, not a machine: no VM to boot, no image, no
  daemon; nothing to install beyond one script.
- **OS-enforced** — the kernel, not the agent, decides what it can touch, so you can let
  it run unattended in skip-permissions mode.
- **Auditable** — read the one script before you trust it; `--print` shows exactly what
  any invocation grants, and [DESIGN.md](DESIGN.md) explains how it works.

## Threat model

**In scope:** the agent runs the *wrong* command — `rm -rf` in the wrong place,
`git reset --hard`, clobbering files outside the task, installing junk system-wide.
sandfence turns these from incidents into errors.

**Out of scope:** a *malicious* agent, prompt injection, or a poisoned dependency
actively trying to escape or exfiltrate. `sandbox-exec` shares your kernel and user
account — it's a guardrail, not a containment boundary. The network is open and your
working copy is readable, so code the agent runs (`npm install`, a build hook) *can*
read secrets in your repo and send them out. For untrusted code, use a VM or a separate
user account.

## Setup

Requires **macOS on Apple Silicon**. Clone it, then make a short `s` wrapper so daily
use is just `s claude`:

```sh
# Clone — and read it; it's a security tool
git clone https://github.com/sheremetyev/sandfence ~/.config/sandfence

# A short `s` wrapper with the toolchains (and extra paths) you use day to day
cat > ~/.local/bin/s <<'EOF'
#!/bin/sh
exec ~/.config/sandfence/sandfence.sh --rust --node --python "$@"
EOF
chmod +x ~/.local/bin/s
```

`s` is yours to tune: keep only the presets you use, and add `-r DIR` / `-w DIR` for
paths you reach for often. Each preset and grant is a real widening of the sandbox.

**Auth (once).** Each agent keeps its own token in a file the sandbox grants — never the
login Keychain, never your shell environment.

- **Claude Code** — run `s claude`, then `/login`; paste the printed URL into your
  browser (the sandbox can't open one). It writes `~/.claude/.credentials.json` and
  refreshes it from then on.
- **Codex** — run `codex login` once (anywhere); its token lives in `~/.codex/auth.json`,
  which the sandbox reads.

## What the agent can touch

| | |
|---|---|
| **Read-write** | the current directory — your working copy |
| **Read-only** | its own `.git` / `.jj` — you drive version control outside the sandbox; the agent can't commit or rewrite history |
| **Denied** | the rest of `$HOME` — `~/.ssh`, `~/.aws`, `gh`/`glab` tokens, the login Keychain, `~/.gitconfig` credentials, other repos |

Widen it explicitly: **`-r PATH`** / **`-w PATH`** add a directory or file, and the
**`--rust` / `--node` / `--python`** presets grant build caches read-write while keeping
registry tokens and PATH-plant vectors denied. **`--print`** shows exactly what an
invocation grants; [DESIGN.md](DESIGN.md) explains why each grant is there.

## Limitations

- **macOS on Apple Silicon**, default toolchains (`rustup`, `nvm` + stock `npm`, Apple
  `python3`). Homebrew, pyenv, pnpm, and yarn aren't auto-detected — grant them with `-r`/`-w`.
- **`sandbox-exec` is deprecated by Apple (2017) but fully functional** — only the CLI
  is deprecated; the Seatbelt engine under it still powers the macOS App Sandbox and
  Chrome's renderer sandbox, so it isn't going away. A future macOS could change the CLI.
- `/tmp` and `/var/folders` are read-write wholesale — don't expect repo isolation there.
- Under **jj**, `.jj` is read-only; run read-only commands as `jj --ignore-working-copy …`.

## Testing

`./test.sh ~/sandfence-tests` runs real commands *inside* the sandbox and asserts each
allow/deny — so you verify what's granted, not just read it. Use a real dir (not `/tmp`),
and run it in a plain shell (`sandbox-exec` can't nest).

## License

MIT — see [LICENSE](LICENSE).
