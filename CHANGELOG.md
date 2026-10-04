# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may change rules).

## [0.1.0] - 2026-10-03

First public release.

### Added
- Classifier for shell commands, file edits and MCP tool calls (high / medium risk).
- Secret masking for everything shown to a person.
- Real effect of `git push --force`, `reset --hard`, `clean`, `branch -D`, `stash clear` and `rm -r`, computed locally and read-only.
- Hook adapters for Claude Code, Codex, Cursor and Gemini CLI.
- `check`, `init`, `redact` and `hook` commands.
- User-level configuration (level, ask/deny mode, exact-command allow list).
