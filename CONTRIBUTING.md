# Contributing

Thank you for helping. The most valuable contributions are **rules**: commands, tools and files that
should (or should not) ask for a person's approval.

## Quick start

```bash
git clone https://github.com/faustodariopenamondragon-web/olo-gate && cd olo-gate
cargo test            # unit + CLI tests (needs git on PATH)
cargo fmt --check && cargo clippy --all-targets -- -D warnings
```

## Adding or fixing a rule

1. Add the command to the right list in `src/rules.rs` tests: `destructive_commands_are_high`,
   `medium_commands` or `ordinary_commands_are_not_gated`. **Write the test first.**
2. Make it pass in `classify_program` (or `classify_path`, `classify_mcp`).
3. Run the whole suite. An "ordinary command" that now asks is a regression: false positives make people
   switch the guard off, so we treat them as seriously as misses.

False positive or miss but no time for a patch? Open an issue with the "Rule request" template.

## Ground rules

- **No network, no telemetry**, ever. The binary must work offline and must not open a socket.
- **Dependencies stay minimal** (`serde`, `serde_json`). Justify any addition.
- **Configuration is user-level only.** Never read policy from the project directory.
- Masking and effect text must never include secrets or file contents. Add a test.
- Keep messages short, in English, and free of jargon.

## Sign your commits (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/) instead of a CLA.
Add `Signed-off-by: Your Name <you@example.com>` to each commit (`git commit -s`). By doing so you
certify that you wrote the change or have the right to submit it under the Apache-2.0 license.

## Security issues

Do not open a public issue; see [SECURITY.md](SECURITY.md).
