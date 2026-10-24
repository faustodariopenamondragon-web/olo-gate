# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may change rules).

## [Unreleased]

Found by probing the guard with 108 destructive commands: about a third passed without a question.

### Added
- `deny` list in the user config: commands that must never run, blocked outright whatever the mode and beating `allow`.
- Database drops (`dropdb`, `dropuser`, `pg_restore --clean`, `mysqladmin drop`, `mongosh` `dropDatabase` / `deleteMany`).
- Syncs that delete (`rsync --delete*`, `rclone sync|purge|delete`, `gsutil rm|rsync -d`); `--dry-run` stays silent.
- `truncate` and redirects that leave a file blank (`: > f`, `> f`, `cat /dev/null > f`).
- Commands run on another machine are judged as if local: `ssh host "…"`, `docker exec`, `kubectl exec`.
- `eval` of `base64` / `curl` output, `bash <(curl …)`, `sh -c "$(curl …)"`, `python -c` / `node -e` that delete, and
  commands whose name is built at run time.
- Shell blocks (`if` / `for` / `while`), aliases in the same command, `busybox`, and `xargs rm`.
- Writes to sensitive places from the shell (`tee`, `cp`, `mv`, `install`, redirects into `~/.ssh`, `/etc`, shell startup files).
- `ansible-playbook` (not with `--check`).

### Fixed
- `git -C dir push --force` (and `-c`, `--git-dir`) was not recognised: the option's value was taken for the subcommand.
- `git checkout -- .`, `git restore .`, `git checkout -f` and `git stash clear` are now high (they lose unsaved work for good);
  `git restore --staged` stays silent; `git push origin :branch` is high; `shred` is high.

## [0.1.0] - 2026-10-03

First public release.

### Added
- Classifier for shell commands, file edits and MCP tool calls (high / medium risk).
- Secret masking for everything shown to a person.
- Real effect of `git push --force`, `reset --hard`, `clean`, `branch -D`, `stash clear` and `rm -r`, computed locally and read-only.
- Hook adapters for Claude Code, Codex, Cursor and Gemini CLI.
- `check`, `init`, `redact` and `hook` commands.
- User-level configuration (level, ask/deny mode, exact-command allow list).
