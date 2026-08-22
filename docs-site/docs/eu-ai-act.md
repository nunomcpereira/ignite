---
title: EU AI Act coverage
sidebar_position: 4
---

# EU AI Act coverage

Ignite can only speak to the **code-detectable slice** of the EU AI Act.
Most of the Act is an org-process artifact, not something a static scan of
a repo can see: the risk-management-system process, conformity assessment,
FRIA, human-oversight procedure. Two built-in mechanisms cover what's
actually detectable in code, and both are **advisory-only by default**.
They never block a push, and they don't feed the same issue/override model
secrets or SAST findings do, unless you explicitly opt in.

## What's detected

### Three posture categories

The [Compliance & Feature Posture Engine](/what-gets-checked), the same
Semgrep-backed DETECTED/PARTIAL/MISSING engine that classifies SSO, RBAC,
and audit logging, carries three EU AI Act-specific categories, defined in
`ignite-posture-rules.yaml`:

| Category | Article | What it looks for |
|---|---|---|
| `ai-act-prohibited-practice` | Art. 5 | Biometric-categorization, emotion-inference, and social-scoring libraries and call sites. Unlike every other posture category, **`DETECTED` here flags a risk to review**, not a safeguard in place. |
| `ai-act-transparency-disclosure` | Art. 13/50 | User-facing "AI-generated" / "you're talking to an AI" disclosure strings. |
| `ai-act-ai-logging` | Art. 12 | Model input/output/decision logging (MLflow, Weights & Biases, LangSmith-style), distinct from the general-purpose `audit-logging` category. |

Falls back to a built-in regex scanner (same weak/strong model) when
Semgrep isn't installed, same as every other posture category.

### Process-obligation document scan

`checkComplianceDocuments` is a built-in, no-external-tool filename/path
scan for the process documents the posture engine can't detect by code
signature:

| Document | Article |
|---|---|
| Risk-management-system documentation | Art. 9 |
| Annex IV technical documentation | Art. 11 |
| Fundamental Rights Impact Assessment (FRIA) | Art. 27 |
| GPAI training-data summary / model card | Art. 53 |
| Post-market monitoring plan | Art. 72 |

Each is `DETECTED`/`MISSING`, no `PARTIAL` tier, since there's no
weak/strong distinction for "does this file exist." Absence in one repo's
tree isn't proof the document doesn't exist org-wide (a GRC tool, a wiki, a
separate compliance repo might hold it). This is context for a human to
follow up on, never a gate.

## Where it shows up

Both mechanisms attach their output as **documents**, not issues, by
default:

- `posture-report.json`, the three `ai-act-*` categories alongside every
  other posture category
- `ai-act-documents-report.json`, the document-presence scan

Neither appears in the blocking issue list, and neither requires a
justified override to push, unless you turn on the findings toggle below.

## Turning findings on

Set `compliance.euAiAct.reportAsFindings` (`config.json`) or
`EU_AI_ACT_REPORT_AS_FINDINGS=true` (env) to route the three posture
categories' matches and any `MISSING` document category into the same
addressable-issue list every other Phase 4 check feeds. Findings from this
path are always `severity: warning` regardless of the toggle — these are
heuristic regex/filename signals, never promoted to a hard blocker the way
a secret or a known CVE is.

Independently, `EU_AI_ACT_DOCS_ENABLED=false` turns the document-presence
scan off entirely (on by default).

## Related config

```bash
EU_AI_ACT_DOCS_ENABLED=true        # document-presence scan, on by default
EU_AI_ACT_REPORT_AS_FINDINGS=false # advisory-only by default; true routes into the issue list
```

See [What gets checked](/what-gets-checked) for how these two mechanisms
sit alongside Ignite's other eleven external-tool integrations and four
built-in codebase-intelligence checks.
