---
title: Detection quality
sidebar_position: 11
---

# Detection quality — measured against the OWASP Benchmark

Ignite's code-analysis findings come mostly from the external engines it
orchestrates (Semgrep, Bearer, CodeQL). The built-in fallbacks that run when
those tools are missing are safety nets for secrets, configuration and
dependencies, not SAST engines. This page puts numbers on both, so claims
about what Ignite catches rest on a measurement rather than a feature list.

## How it's measured

`sast-bench` (`rust/crates/sast-bench`) runs Ignite's full Phase 4 against
the [OWASP Benchmark for Java](https://github.com/OWASP-Benchmark/BenchmarkJava)
— 2,740 small Java test cases across 11 vulnerability categories, each
labelled as a real vulnerability or a deliberate false-positive trap — and
scores the results against the Benchmark's own expected-results file.

- **Two modes per run.** `full` uses whatever external tools are installed;
  `fallback` registers none of them, so every check takes its built-in path.
  The gap between the two is the point of the exercise.
- **Matching.** A test case counts as flagged when Ignite reports a finding
  in that test's file whose CWE is accepted for the test's category. A small
  table of closely related CWEs is accepted per category (for example
  CWE-338 "weak PRNG" for a weak-randomness test); the scorecard lists it in
  the *Accepted CWEs* column. A finding with a CWE from a different category
  is ignored for that test case, as in OWASP's own scorecards; a finding with
  no CWE at all is listed as unmapped and never counts as a true positive.
- **Score.** The Benchmark score is recall (true-positive rate) minus
  false-positive rate: 0% is no better than guessing, 100% is perfect.
  "Average category score" is the mean over the 11 categories, so a large
  category can't dominate the headline number.
- **Licensing.** The Benchmark is GPL-2.0. `sast-bench` fetches it at a
  pinned commit into a cache directory outside this repository
  (`~/.cache/ignite/sast-bench` by default) and never commits it.

```bash
cd rust
cargo build --release -p ignite-sast-bench
cd ..
./rust/target/release/sast-bench --mode both --ignite-root . --out-dir bench-out
# before/after for engine consensus:
./rust/target/release/sast-bench --mode consensus --ignite-root . --out-dir bench-out
```

Outputs `bench-out/sast-bench-results.json` and
`bench-out/sast-bench-scorecard.md`. A scheduled GitHub Actions workflow
(`.github/workflows/sast-bench.yml`) runs fallback mode weekly and on demand;
full-mode numbers need the external tools installed and are produced locally
with the same binary.

## Engine consensus: fewer false positives without losing recall

Reporting every engine's findings as blocking adds up every engine's false
positives. With `security.sastConsensus.enabled` (`SAST_CONSENSUS_ENABLED`),
a blocking code-analysis finding keeps blocking only if:

- it came from a trusted engine (`trustedEngines`, default `["codeql"]`), or
- the file's language wasn't analyzed by a trusted engine this run, and at
  least `minEngines` (default 2) engines reported the same weakness: same
  file, same CWE family, within `lineWindow` lines (default 10; 0 = anywhere
  in the file).

In a file CodeQL analyzed, Semgrep and Bearer findings become warnings:
still reported and visible, with a note saying why, but no longer blocking.
Findings without a CWE can't be matched across engines and are left alone.
It's off by default so an existing installation's gate doesn't change
silently.

Measured with `sast-bench --mode consensus`, which scans the Benchmark twice
through the real pipeline, consensus off then on, and compares what each
run would block on:

### Before / after: `full` → `full-consensus` (blocking findings only)

| Metric | Before | After | Change |
|---|---|---|---|
| Average category score | 51.8% | 62.0% | +10.2 pts |
| Recall (real vulnerabilities blocked) | 100.0% | 100.0% | +0.0 pts |
| False-positive rate (safe cases blocked) | 52.9% | 40.1% | -12.8 pts |
| Precision | 66.9% | 72.7% | +5.8 pts |
| True positives | 1415 | 1415 | +0 |
| False positives | 701 | 531 | -170 |

Per category (Benchmark score):

| Category | Before | After | Change | FP before → after |
|---|---|---|---|---|
| cmdi | 8.8% | 48.8% | +40.0 pts | 114 → 64 |
| crypto | 76.7% | 76.7% | +0.0 pts | 27 → 27 |
| hash | 69.2% | 69.2% | +0.0 pts | 33 → 33 |
| ldapi | 59.4% | 59.4% | +0.0 pts | 13 → 13 |
| pathtraver | 7.4% | 51.1% | +43.7 pts | 125 → 66 |
| securecookie | 100.0% | 100.0% | +0.0 pts | 0 → 0 |
| sqli | 3.5% | 10.8% | +7.3 pts | 224 → 207 |
| trustbound | 44.2% | 44.2% | +0.0 pts | 24 → 24 |
| weakrand | 100.0% | 100.0% | +0.0 pts | 0 → 0 |
| xpathi | 65.0% | 65.0% | +0.0 pts | 7 → 7 |
| xss | 35.9% | 56.9% | +21.1 pts | 134 → 90 |


Why not "two engines must agree" everywhere? On this benchmark, CodeQL
already catches every real case. Requiring two engines drops recall to 74%,
and keeping Semgrep+Bearer agreements on top of CodeQL adds 95 false
positives and no true positives. Hence: trust CodeQL where it ran; use agreement
only where it didn't. That conclusion is from Java; re-check with other
languages before relying on it there.

## Latest results

Generated 2026-10-03T09:59:12Z against [OWASP Benchmark for Java](https://github.com/OWASP-Benchmark/BenchmarkJava) commit `8b67a88d73b2594570fc21150705283de884620b` (2740 test cases), Ignite commit `7d637fe7847128f7a89d8546f7784aefeb384ea9`.

### What the numbers say

- **Built-in fallbacks do no Java SAST** (0% in `fallback` mode). Ignite's
  code-level detection on Java comes entirely from the external engines;
  without them, a Java repo is checked for secrets, dependencies and
  configuration only. Install the engines before relying on Ignite as a SAST.
- **CodeQL is the strongest single engine here** (62% average category score,
  100% recall, 40% false-positive rate), then Semgrep (45%) and Bearer (39%).
- **Combining all three engines scores lower than CodeQL alone** (38.9%):
  findings from every engine are reported together, so the combined run gets
  every engine's true positives (recall 100%) but also every engine's false
  positives (57% false-positive rate). Categories with good sanitizer
  modelling (weak randomness, secure cookies, crypto, hashing) stay strong;
  injection categories (SQL, command, path traversal, LDAP, trust boundary)
  carry most of the false positives.
- These numbers are for the engines' default rule sets as Ignite runs them
  (Semgrep `p/security-audit`, CodeQL `java-security-extended` pinned in
  `config.json`, Bearer defaults) on one Java benchmark. They don't measure
  other languages, secrets, dependency or IaC checks.

### Mode: `full`

Average category score **38.9%** · overall recall 100.0% · overall false-positive rate 57.0% · precision 65.2% · run time 236s

| Category | CWE | Accepted CWEs | Tests | TP | FP | FN | TN | Recall | FPR | Precision | Score | Tools |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | 78, 77 | 251 | 126 | 114 | 0 | 11 | 100.0% | 91.2% | 52.5% | 8.8% | bearer, codeql, semgrep |
| crypto | 327 | 327, 326 | 246 | 130 | 27 | 0 | 89 | 100.0% | 23.3% | 82.8% | 76.7% | bearer, codeql, semgrep |
| hash | 328 | 328, 327, 916 | 236 | 129 | 33 | 0 | 74 | 100.0% | 30.8% | 79.6% | 69.2% | bearer, codeql, semgrep |
| ldapi | 90 | 90 | 59 | 27 | 28 | 0 | 4 | 100.0% | 87.5% | 49.1% | 12.5% | bearer, codeql, semgrep |
| pathtraver | 22 | 22, 23, 36, 73 | 268 | 133 | 125 | 0 | 10 | 100.0% | 92.6% | 51.5% | 7.4% | bearer, codeql, semgrep |
| securecookie | 614 | 614 | 67 | 36 | 0 | 0 | 31 | 100.0% | 0.0% | 100.0% | 100.0% | bearer, codeql, semgrep |
| sqli | 89 | 89, 564 | 504 | 272 | 224 | 0 | 8 | 100.0% | 96.5% | 54.8% | 3.5% | bearer, codeql, semgrep |
| trustbound | 501 | 501 | 126 | 83 | 41 | 0 | 2 | 100.0% | 95.3% | 66.9% | 4.7% | bearer, codeql, semgrep |
| weakrand | 330 | 330, 338 | 493 | 218 | 0 | 0 | 275 | 100.0% | 0.0% | 100.0% | 100.0% | bearer, codeql, semgrep |
| xpathi | 643 | 643 | 35 | 15 | 17 | 0 | 3 | 100.0% | 85.0% | 46.9% | 15.0% | bearer, codeql, semgrep |
| xss | 79 | 79, 80, 83 | 455 | 246 | 146 | 0 | 63 | 100.0% | 69.9% | 62.8% | 30.1% | bearer, codeql, semgrep |

Findings in test-case files: 9029 (off-category: 3238, unmapped/no CWE: 0). Findings outside test cases: 1642.

Each engine scored on its own findings:

| Engine | TP | FP | FN | TN | Recall | FPR | Precision | Average category score |
|---|---|---|---|---|---|---|---|---|
| bearer | 1060 | 447 | 355 | 878 | 74.9% | 33.7% | 70.3% | 39.2% |
| codeql | 1415 | 531 | 0 | 794 | 100.0% | 40.1% | 72.7% | 62.0% |
| semgrep | 1224 | 512 | 191 | 813 | 86.5% | 38.6% | 70.5% | 45.0% |

Code-analysis engines this run:

- `codeql`: completed — engine `codeql`
- `pii`: completed — engine `bearer`
- `semanticSast`: completed — engine `semgrep`

### Mode: `fallback`

Average category score **0.0%** · overall recall 0.0% · overall false-positive rate 0.0% · precision n/a · run time 2s

| Category | CWE | Accepted CWEs | Tests | TP | FP | FN | TN | Recall | FPR | Precision | Score | Tools |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | 78, 77 | 251 | 0 | 0 | 126 | 125 | 0.0% | 0.0% | n/a | 0.0% | — |
| crypto | 327 | 327, 326 | 246 | 0 | 0 | 130 | 116 | 0.0% | 0.0% | n/a | 0.0% | — |
| hash | 328 | 328, 327, 916 | 236 | 0 | 0 | 129 | 107 | 0.0% | 0.0% | n/a | 0.0% | — |
| ldapi | 90 | 90 | 59 | 0 | 0 | 27 | 32 | 0.0% | 0.0% | n/a | 0.0% | — |
| pathtraver | 22 | 22, 23, 36, 73 | 268 | 0 | 0 | 133 | 135 | 0.0% | 0.0% | n/a | 0.0% | — |
| securecookie | 614 | 614 | 67 | 0 | 0 | 36 | 31 | 0.0% | 0.0% | n/a | 0.0% | — |
| sqli | 89 | 89, 564 | 504 | 0 | 0 | 272 | 232 | 0.0% | 0.0% | n/a | 0.0% | — |
| trustbound | 501 | 501 | 126 | 0 | 0 | 83 | 43 | 0.0% | 0.0% | n/a | 0.0% | — |
| weakrand | 330 | 330, 338 | 493 | 0 | 0 | 218 | 275 | 0.0% | 0.0% | n/a | 0.0% | — |
| xpathi | 643 | 643 | 35 | 0 | 0 | 15 | 20 | 0.0% | 0.0% | n/a | 0.0% | — |
| xss | 79 | 79, 80, 83 | 455 | 0 | 0 | 246 | 209 | 0.0% | 0.0% | n/a | 0.0% | — |

Findings in test-case files: 0 (off-category: 0, unmapped/no CWE: 0). Findings outside test cases: 1578.

Code-analysis engines this run:

- `codeql`: disabled — engine `none`
- `pii`: disabled — engine `none`
- `semanticSast`: unavailable — engine `none`

