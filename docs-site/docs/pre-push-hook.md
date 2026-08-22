---
title: Pre-push hook
sidebar_position: 7
---

# Pre-push hook — check before you push, not after

Uploading a ZIP to a web app is an extra step most people would rather
skip. Ignite's `validate-all` endpoint takes a local `projectPath` and runs
phases 1–5 synchronously — no upload, no UI — which is exactly what a git
`pre-push` hook needs. A ready-to-use one ships in the repo:

**[⬇ Download `hooks/pre-push`](https://raw.githubusercontent.com/nunomcpereira/ignite/main/hooks/pre-push)**

Install it into any repo:

```bash
# One repo:
curl -o .git/hooks/pre-push https://raw.githubusercontent.com/nunomcpereira/ignite/main/hooks/pre-push
chmod +x .git/hooks/pre-push

# Every repo on this machine, instead of copy-pasting into each one
# (.git/hooks/ isn't itself tracked by git, so a shared dir is the way to
# cover every repo at once):
mkdir -p ~/.git-hooks
curl -o ~/.git-hooks/pre-push https://raw.githubusercontent.com/nunomcpereira/ignite/main/hooks/pre-push
chmod +x ~/.git-hooks/pre-push
git config --global core.hooksPath ~/.git-hooks
```

It needs a running Ignite server reachable at `IGNITE_BASE_URL` (default
`http://localhost:51337`) and `node` on `PATH`. On `git push`, it posts the
repo's absolute path to `/api/pipeline/validate-all`, blocks the push if any
check fails, and prints the failing phase's logs so you don't have to open
the UI just to see what broke:

```bash
$ git push
→ Running Ignite checks against /Users/you/projects/some-repo ...
✗ Ignite checks failed - push blocked.
  Phase 4 - Security & AI Compliance Scan
    ✗ python/config.py:3 - Hardcoded password

✗ 1 blocking finding(s) need a justification or a source fix.
  Edit /Users/you/projects/some-repo/.ignite/acknowledgments.md, fill in "Acknowledge:"
  for whichever you want to override, then push again - or fix them in the
  source instead.
```

## Acknowledge findings from the terminal — no browser needed

A blocking finding isn't a dead end: the hook writes
`.ignite/acknowledgments.md` at the repo root, one entry per finding, each
with a blank `Acknowledge:` line. Every run also drops a point-in-time
snapshot of every finding at `.ignite/scans/<timestamp>/findings.md`:

```
ID: secret::python/config.py::3
# [ERROR] secret - Hardcoded password
#   python/config.py:3
Acknowledge:
```

Fill in a justification, save, `git push` again — the hook resubmits every
filled-in line as a real, attributed override (using your `git config
user.name`/`user.email`), the same justify-and-override step the web UI's
review gate does, just from your own editor. The file is rewritten from
scratch every run to match the current scan: a justified entry survives as
long as its finding is still reported (including across a pure line-number
shift, carried forward automatically), but once the underlying issue is
actually fixed, its entry is dropped rather than lingering forever. Each
surviving entry is also numbered (`# Issue #1`, `#2`, …) as a running count,
recomputed every push.

Fast by default — `runLocalCi` is off (skips Phase 5's `act`/Docker
governance CI, which is slow and typically belongs in real CI, not on
every push) and only blocking errors gate the push, not warnings. Both are
configurable via env vars documented at the top of the script
(`IGNITE_RUN_LOCAL_CI`, `IGNITE_WARNING_MODE`), along with a one-push
`IGNITE_PREPUSH_SKIP=true` escape hatch that's logged rather than silent
like `git push --no-verify`.

---

Full setup, every environment variable, tool-by-tool install instructions,
and the REST/MCP API reference: [github.com/nunomcpereira/ignite](https://github.com/nunomcpereira/ignite).
