## What and why

## Checklist
- [ ] Tests added first (a failing test for the rule or bug)
- [ ] `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` pass
- [ ] No ordinary command now asks for approval (no new false positives)
- [ ] No secrets or file contents can reach the reason text
- [ ] Commits are signed off (`git commit -s`)
