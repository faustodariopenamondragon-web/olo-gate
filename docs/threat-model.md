# Threat model

olo-gate sits between an AI coding agent and the actions it is about to take. This page states plainly
what it protects against, what it does not, and why.

## What it is

A **guard against slips and unsupervised actions**. Agents run for minutes or hours, often while you are
away, and a single `git push --force` or `rm -rf` can cost days. olo-gate recognises those actions
*before* they run and puts a person in the loop, with the real effect on screen.

## What it is not

- **Not a sandbox.** An agent with terminal access acts with your permissions. If it wants to evade a
  guard it can (for example by building a command at runtime, `eval`, or running a script it just wrote).
  Use the agent's own sandbox, containers, or a separate user for real isolation.
- **Not a replacement for code review**, backups or branch protection. It complements them.
- **Not a prompt-injection filter.** It does not read what the agent read. It only watches what the agent *does*.

## Design decisions

| Decision | Why |
| --- | --- |
| **No network, no telemetry.** The binary opens no sockets and CI fails if network code appears. | You can verify the privacy claim by reading the source. |
| **Reads policy only from the user's directory/environment, never from the project.** | A cloned repository must not be able to ship a file that allows `rm -rf`. |
| **Allow-list entries are exact commands.** | Allowing `npm publish` must not allow `npm publish --tag evil`. |
| **It can only add a question or a block, never grant.** | The agent's own permission flow still applies. |
| **Fails silent on internal errors.** | A guard that wedges the agent gets uninstalled. A malformed payload, empty input or crash produces no output and exit 0. |
| **Effects are read-only, offline and capped.** | `git` runs with fsmonitor and external diff disabled, no credentials prompts, a 1.5 s budget, and only counts are reported, never file names. |
| **Masking before display.** | Tokens, passwords, bearer headers, URL credentials and key-like strings are replaced with `•••` in everything shown. |

## Known limits

- The shell tokenizer is deliberately small: it does not expand variables, globs, aliases, functions or
  here-documents. `bash -c "…"` is parsed up to three levels deep.
- Commands hidden in a file the agent writes and then executes are not seen at write time (only the
  later execution is).
- Effect previews compare with what you last fetched; the server may have newer commits. The text says so.
- On Codex and Gemini CLI a hook cannot ask: "ask" mode becomes a block, with a hint to allow the exact command.

## Reporting a bypass

Please do it privately: see [SECURITY.md](../SECURITY.md). A command that should be caught and is not is a
vulnerability, and we would like to thank you for it.
