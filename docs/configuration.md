# Configuration

Configuration lives in the **user's** config directory, never in the project (a cloned repo must not be able
to weaken the guard). Environment variables override the file.

| Where | Path |
| --- | --- |
| macOS / Linux | `$XDG_CONFIG_HOME/olo-gate/config.json`, else `~/.config/olo-gate/config.json` |
| Windows | `%APPDATA%\olo-gate\config.json` |
| Any | the file named by `OLO_GATE_CONFIG` |

```json
{
  "level": "high",
  "mode": "ask",
  "allow": ["npm publish", "git push --force-with-lease origin my-feature"],
  "deny": ["dropdb prod*", "psql -h prod*", "rm -rf /*"]
}
```

| Key | Values | Meaning |
| --- | --- | --- |
| `level` | `high` (default), `medium` | `high`: only the irreversible and sensitive. `medium`: also plain `git push`, installs, config files… |
| `mode` | `ask` (default), `deny` | `ask`: the agent's own prompt asks you and shows why. `deny`: block outright. Codex and Gemini CLI cannot ask from a hook, so `ask` blocks there. |
| `allow` | list of strings | Exact commands (trimmed) that are never questioned. |
| `deny` | list of strings | Commands that must **never** run. Blocked outright, whatever the `mode`, even if olo-gate would not otherwise call them risky, and **beating `allow`**. An entry is a whole command, or a prefix ending in `*` (`dropdb prod*` matches `dropdb production`). It is compared with the command and with each piece of it, so `cd app && dropdb prod`, `sudo dropdb prod` and `bash -c 'dropdb prod'` are caught. A lone `*` matches nothing. Only shell commands are matched. |

`deny` answers "which command should never run on this machine?": write it down once and every agent you
connect obeys it.

Environment: `OLO_GATE_LEVEL`, `OLO_GATE_MODE`, `OLO_GATE_CONFIG`.

## Try a command without an agent

```bash
olo-gate check git push --force origin main     # exit 20 (high), 10 (medium), 0 (ok)
olo-gate check --json rm -rf build
echo 'curl -H "Authorization: Bearer sk-live-…"' | olo-gate redact
```
