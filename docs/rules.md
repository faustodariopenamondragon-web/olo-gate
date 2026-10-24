# What it recognises

High risk always asks; medium asks only with `"level": "medium"`. The authoritative list is the test suite in
[`src/rules.rs`](../src/rules.rs): every row below has a test.

## Shell commands

| Risk | Examples |
| --- | --- |
| **High** | `rm -rf`, `shred`, `ls \| xargs rm`, `find … -delete`, `git push --force` / `-f` / `+ref` / `:branch` / `--delete` (also through `git -C dir …`), `git reset --hard`, `git checkout -- .` / `git restore .` / `checkout -f`, `git clean -fd`, `git branch -D`, `git stash clear`, `git update-ref -d`, `git rebase` / `filter-branch`, `sudo`, `curl … \| sh`, `bash <(curl …)`, `sh -c "$(curl …)"`, `eval` of `base64` / `curl` output, `irm … \| iex`, `npm|cargo|pnpm publish`, `docker system prune` / `push` / `rm -f`, `kubectl delete|apply`, `terraform apply|destroy`, `ansible-playbook` (not with `--check`), `vercel --prod`, `supabase db push`, `gh release create` / `repo delete`, `aws … rm|delete|terminate`, `gsutil rm`, `rclone sync|purge|delete`, `rsync --delete*` / `--remove-source-files` (not with `--dry-run`), `chmod -R`, `dd of=/dev/…`, `mkfs`, SQL `DROP` / `TRUNCATE` / `DELETE` without `WHERE`, `dropdb`, `dropuser`, `pg_restore --clean`, `mongosh` `dropDatabase` / `deleteMany`, `redis-cli flushall`, `mail`, `curl -X DELETE`, `systemctl`/`launchctl` changes, `python -c` / `node -e` that `rmtree` / `rmSync` |
| **High, on another machine** | a risky command run through `ssh host "…"`, `docker exec … …` or `kubectl exec … -- …` is judged as if it ran here, and is high: nothing there can be undone from here |
| **High, sensitive places** | writing to `~/.ssh`, `/etc`, shell startup files or cloud credentials from the shell: `tee`, `cp`, `mv`, `install`, `> file`, `>> file` |
| **Medium** | `git push`, `rm file`, `git checkout -- file`, `git stash drop`, `kill`, global installs, `brew|apt|pip install`, `chmod +x`, `curl -X POST|PUT|PATCH`, SQL `UPDATE`/`ALTER`, `truncate`, `: > file` / `> file` / `cat /dev/null > file` (emptying a file), `tar -x … -C /`, a command whose NAME is built at run time (`$(echo rm) -rf x`) |
| *Ignored* | `ls`, `git status`/`diff`/`log`/`commit`, `npm test`/`run build`, `curl` reads, `cargo test`, `docker ps`/`build`, `kubectl get`, `terraform plan`, `echo "rm -rf /"` |

Chains (`a && b`), wrappers (`env`, `nohup`, `time`, `xargs`, `busybox`), shell blocks (`if …; then …; fi`,
`for …; do …; done`), aliases defined in the same command (`alias g=git; g push -f`) and `bash -c "…"` are looked
through. A redirect that writes something (`echo hi > file`) is an ordinary write and is not questioned; only one
that leaves the file blank is.

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
