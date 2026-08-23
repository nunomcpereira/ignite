# Security Policy

## Supported Versions

Ignite is developed on `main`; only the latest commit/release is supported
with security fixes.

| Version | Supported          |
| ------- | ------------------ |
| latest (`main`) | :white_check_mark: |
| older releases  | :x:                 |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report it privately by emailing **nunocpereira@gmail.com** with:

- A description of the vulnerability and its potential impact
- Steps to reproduce (a minimal PoC if possible)
- Any relevant logs, stack traces, or affected file/line references

You should expect an initial response within a few days. We'll work with
you to confirm the issue, assess severity, and coordinate a fix and
disclosure timeline before any public details are published.

## Scope

Ignite handles untrusted user uploads (arbitrary ZIPs/folders), shells out
to `git`/`gh` and a number of optional external scanning tools, and can
provision + push to a GitHub org on a user's behalf. Security-relevant
areas of particular interest:

- Zip-slip / path traversal during archive extraction
- Zip-bomb / resource-exhaustion during extraction or scanning
- Command/argument injection in any `git`/`gh`/external-tool invocation
- Auth/session handling (`auth.js`), API key handling, and override
  attribution
- Anything that could let a scanned project's contents escape the staging
  sandbox or persist after a run completes

See `CLAUDE.md`'s "Hardening invariants" section for the specific
guarantees the codebase currently maintains — a report that identifies a
way to violate one of those invariants is especially valuable.

## Disclosure

We follow coordinated disclosure: please give us a reasonable window to
ship a fix before any public write-up. We'll credit reporters (unless you'd
prefer to stay anonymous) once a fix is released.
