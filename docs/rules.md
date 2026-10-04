# What it recognises

High risk always asks; medium asks only with `"level": "medium"`. The authoritative list is the test suite in
[`src/rules.rs`](../src/rules.rs): every row below has a test.

## Shell commands

| Risk | Examples |
| --- | --- |
| **High** | `rm -rf`, `find … -delete`, `git push --force` / `-f` / `+ref` / `--delete`, `git reset --hard`, `git clean -fd`, `git branch -D`, `git rebase` / `filter-branch`, `sudo`, `curl … \| sh`, `irm … \| iex`, `npm|cargo|pnpm publish`, `docker system prune` / `push`, `kubectl delete|apply`, `terraform apply|destroy`, `vercel --prod`, `supabase db push`, `gh release create` / `repo delete`, `aws … rm|delete|terminate`, `chmod -R`, `dd of=/dev/…`, `mkfs`, SQL `DROP` / `TRUNCATE` / `DELETE` without `WHERE`, `redis-cli flushall`, `mail`, `curl -X DELETE`, `systemctl`/`launchctl` changes |
| **Medium** | `git push`, `rm file`, `kill`, global installs, `brew|apt|pip install`, `chmod +x`, `curl -X POST|PUT|PATCH`, SQL `UPDATE`/`ALTER` |
| *Ignored* | `ls`, `git status`/`diff`/`log`/`commit`, `npm test`/`run build`, `curl` reads, `cargo test`, `docker ps`/`build`, `kubectl get`, `terraform plan`, `echo "rm -rf /"` |

Chains (`a && b`), wrappers (`env`, `nohup`, `time`, `xargs`), and `bash -c "…"` are looked through.

## File edits

| Risk | Files |
| --- | --- |
| **High** | `~/.ssh/*`, `authorized_keys`, `~/.aws/credentials`, `~/.gnupg/`, shell startup files, `/etc/`, LaunchAgents, agent configuration (`~/.claude/settings*`, `~/.codex/`, `~/.cursor/hooks.json`, `~/.gemini/settings*`) |
| **Medium** | `.env*`, `.npmrc`, `.pypirc`, `.netrc`, `.gitconfig`, `.git/hooks/`, `.github/workflows/` |

Only the file *name* is ever shown, never the path or contents.

## MCP tools

Judged by the verb in the tool name: `delete`, `deploy`, `publish`, `send`, `merge`, `transfer`, `pay`,
`refund`… are high; `create`, `update`, `execute_sql`, `apply_migration`… are medium; `get`, `list`,
`read`, `search` are ignored.

## Real effect (offline, read-only)

| Command | What you are told |
| --- | --- |
| `git push --force` | commits on the remote you do not have locally |
| `git push --delete` | commits that exist on no local branch |
| `git reset --hard` | files with uncommitted changes, and commits that leave your branch |
| `git clean -f` | untracked files that would be removed |
| `git branch -D` | commits that exist on no remote |
| `git stash clear/drop` | stashes lost |
| `rm -r` | files and bytes under the target, or a warning for wildcards, `$VARS`, `/` and `~` |
