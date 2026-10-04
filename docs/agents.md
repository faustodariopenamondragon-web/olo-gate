# Connecting your agent

`olo-gate init <agent>` prints the hook configuration and **changes nothing**; you merge it yourself.
Put the `olo-gate` binary on your `PATH` first.

| Agent | Status | Notes |
| --- | --- | --- |
| **Claude Code** | Supported | `ask` and `deny`. Format follows the documented `PreToolUse` contract. |
| **Cursor** | Experimental | `beforeShellExecution`, `ask` and `deny`. Answers `allow` explicitly for safe commands. |
| **Codex** | Experimental | `PreToolUse`; blocks only (a hook cannot ask). |
| **Gemini CLI** | Experimental | `BeforeTool`; blocks only. |
| Anything with MCP / hooks | Use `olo-gate check` in your own wrapper | Exit codes 0 / 10 / 20. |

"Experimental" means the output follows each tool's documented hook format and is covered by our tests,
but has not been verified against every release. Please [report mismatches](../../../issues/new/choose).

## Claude Code

```bash
olo-gate init claude
```

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit|mcp__.*",
        "hooks": [{ "type": "command", "command": "olo-gate hook claude", "timeout": 10 }]
      }
    ]
  }
}
```

Merge it into `~/.claude/settings.json`. Remove the entry to uninstall; nothing else is touched.

## Cursor, Codex, Gemini CLI

```bash
olo-gate init cursor   # → ~/.cursor/hooks.json
olo-gate init codex    # → ~/.codex/hooks.json
olo-gate init gemini   # → ~/.gemini/settings.json
```
