# Security policy

olo-gate is a security-relevant tool: a false negative is a vulnerability.

## Reporting

Please **do not open a public issue** for a vulnerability or a bypass.

- Use GitHub's private reporting: **Security → Report a vulnerability** on this repository, or
- email **ops@olomni.com** with the subject `olo-gate security`.

Include the command, file edit or tool call that is not caught (or the secret that is not masked),
the agent and OS you used, and the version (`olo-gate --version`).

We aim to acknowledge within 3 business days and to ship a fix or a clear mitigation within 30 days.
We credit reporters in the changelog unless you prefer otherwise.

## What counts

In scope:

- A destructive or irreversible command that is **not** classified as high risk, in a form an agent would plausibly write.
- A secret that is not masked in the reason shown to the person.
- A way for a file inside a project to weaken the guard (configuration is deliberately read only from the user's own directory).
- Crashes or hangs in `olo-gate hook` (it must never wedge an agent).

Out of scope (documented limits, see [docs/threat-model.md](docs/threat-model.md)): an agent that
deliberately evades a shell tokenizer by building a command at runtime (`eval`, variable expansion,
downloaded scripts), and anything a sandbox is meant to contain.

## Supported versions

The latest release. The project is pre-1.0.
