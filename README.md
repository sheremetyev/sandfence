# Sandfence

Run a coding agent (Claude Code, Codex) on a repo under the macOS sandbox, in the
agent's own "skip permissions" mode — while the **OS**, not the agent, enforces what
it can touch.

`sandfence` is a single, auditable shell script around macOS `sandbox-exec` (the
Seatbelt sandbox). The agent gets read-write access to your working copy and the bare
minimum to run itself and your tests; everything else is denied by default and opened
only when you explicitly allow.

```sh
sandfence claude          # run claude, confined to the current repo
```

## Threat model

**In scope:** the agent runs the *wrong* command — `rm -rf` in the wrong place,
`git reset --hard`, clobbering files outside the task, installing junk system-wide.
sandfence turns these from incidents into errors.

**Out of scope:** a *malicious* agent or prompt-injection adversary actively trying to
escape or exfiltrate. `sandbox-exec` shares your kernel and user account — it's a
guardrail, not a containment boundary - for that, use a VM.
