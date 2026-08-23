# Contributing to Ignite

Thanks for considering a contribution. This project is a compliance
gatekeeper for onboarding code into a GitHub org — most of the logic lives
in `server.js`, with the twelve-plus external-tool checks, codebase-intel
checks, and CLI/MCP surfaces layered around it. See `CLAUDE.md` for the
full architecture writeup before diving in.

## Getting started

```bash
npm install
npm start          # → http://localhost:51337
npm test            # node --test test/*.test.js
```

Prerequisites: Node ≥22, `git` on PATH. Full pipeline runs (provisioning +
push) also need `gh` CLI authenticated with repo-create permission. Most
external-tool checks (`trivy`, `checkov`, `semgrep`, `bearer`, etc.) are
optional soft-dependencies — every check soft-skips to a built-in fallback
when its binary is absent, and their integration tests self-skip the same
way, so a normal dev machine can run the full suite without installing all
of them.

## Making changes

- Keep changes focused — a bug fix shouldn't carry unrelated refactors.
- Match the existing style: no unnecessary comments, no speculative
  abstractions, no added dependencies unless the task needs them.
- If you add a new check or soft-dependency tool, follow the established
  pattern (see `CLAUDE.md`'s "Expanded diagnostic engine" section): a
  `<tool>Tooling()` probe, a `CONFIG` block with env-var overrides, a
  check/generate function with a graceful fallback, and a dedicated test
  file covering config wiring, fake-CLI parsing, and a self-skipping
  real-binary end-to-end case.
- Add or update tests for any behavior change. Run `npm test` before
  opening a PR.
- Don't relax the hardening invariants (zip-slip guards, size caps,
  `execFile`-only git/gh calls, staging cleanup in `finally`) without a
  strong, explicitly stated reason.

## Submitting a pull request

1. Fork the repo and create a branch off `main`.
2. Make your change, with tests, and confirm `npm test` passes.
3. Open a PR with a clear description of the change and why it's needed.
4. Be responsive to review feedback — small, focused PRs get merged faster.

## Reporting bugs / requesting features

Open a GitHub issue. Include repro steps, expected vs. actual behavior, and
relevant environment details (Node version, OS, which optional tools are
installed).

## Security issues

Do not open a public issue for a security vulnerability — see
[SECURITY.md](SECURITY.md) instead.

## Code of Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). By
participating, you agree to uphold it.
