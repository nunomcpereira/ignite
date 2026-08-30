# Ignite pre-push acknowledgments - meant to be committed: a filled-in
# justification is a real audit record, reviewable like code.
#
# Fill in a justification after "Acknowledge:" for any issue below you want
# to override, save, then `git push` again. Blank = stays blocking.
# Refreshed every run: only entries for findings still reported by the
# current scan are kept - a filled-in justification survives as long
# as its finding does, but once the underlying issue is fixed (or a
# pure line-number shift carries its justification to a new id), the
# stale entry is dropped rather than kept forever.
# A `# Code:` line, when present, is the flagged source line own text -
# used to auto-carry-forward this justification if an unrelated edit
# elsewhere in the file later shifts its line number. Do not hand-edit it.
# The `# Issue #N` line is just a running count of entries in this file
# - recomputed on every push, not a stable id. Use the `ID:` line to
# refer to a specific finding.

# Scanned against commit: 2d6a1af730a5a4e5d01f05a66a7c1f874a71b15d (working tree at push time - findings/justifications below reflect this commit's code, not necessarily what ends up pushed if the tree changes after)

ID: secret::rust/crates/secrets/src/lib.rs::445
# Issue #1
# [ERROR] secret - Hardcoded api_key
#   rust/crates/secrets/src/lib.rs:445
Acknowledge: False positive: test-fixture literal inside a #[test]/#[tokio::test] function in Ignite's own Rust test suite (asserting the scanner itself detects this pattern), not a real credential. Verified by reading the surrounding code.

ID: secret::rust/crates/secrets/src/lib.rs::481
# Issue #2
# [ERROR] secret - Hardcoded api_key
#   rust/crates/secrets/src/lib.rs:481
Acknowledge: False positive: test-fixture literal inside a #[test]/#[tokio::test] function in Ignite's own Rust test suite (asserting the scanner itself detects this pattern), not a real credential. Verified by reading the surrounding code.

ID: secret::rust/crates/secrets/src/lib.rs::495
# Issue #3
# [ERROR] secret - Hardcoded api_key
#   rust/crates/secrets/src/lib.rs:495
Acknowledge: False positive: test-fixture literal inside a #[test]/#[tokio::test] function in Ignite's own Rust test suite (asserting the scanner itself detects this pattern), not a real credential. Verified by reading the surrounding code.

ID: secret::rust/crates/secrets/src/lib.rs::518
# Issue #4
# [ERROR] secret - Hardcoded api_key
#   rust/crates/secrets/src/lib.rs:518
Acknowledge: False positive: test-fixture literal inside a #[test]/#[tokio::test] function in Ignite's own Rust test suite (asserting the scanner itself detects this pattern), not a real credential. Verified by reading the surrounding code.

ID: secret::rust/crates/server/src/routes/studio.rs::610
# Issue #5
# [ERROR] secret - Hardcoded password
#   rust/crates/server/src/routes/studio.rs:610
Acknowledge: False positive: test-fixture literal inside a #[test]/#[tokio::test] function in Ignite's own Rust test suite (asserting the scanner itself detects this pattern), not a real credential. Verified by reading the surrounding code.

ID: secret::rust/crates/server/src/routes/studio.rs::612
# Issue #6
# [ERROR] secret - Hardcoded password
#   rust/crates/server/src/routes/studio.rs:612
Acknowledge: False positive: test-fixture literal inside a #[test]/#[tokio::test] function in Ignite's own Rust test suite (asserting the scanner itself detects this pattern), not a real credential. Verified by reading the surrounding code.

ID: secret::rust/crates/llm-deep-scan/src/lib.rs::569
# Issue #7
# [ERROR] secret - Hardcoded password
#   rust/crates/llm-deep-scan/src/lib.rs:569
Acknowledge: False positive: test-fixture literal inside a #[test]/#[tokio::test] function in Ignite's own Rust test suite (asserting the scanner itself detects this pattern), not a real credential. Verified by reading the surrounding code.

ID: pii-dataflow::vscode-extension/src/panels/reportPanel.ts::4
# Issue #8
# [ERROR] pii-dataflow - Usage of manual HTML sanitization (XSS)
#   vscode-extension/src/panels/reportPanel.ts:4
Acknowledge: Reviewed vscode-extension/src/panels/reportPanel.ts: every dynamic value interpolated into the webview HTML template goes through the local escapeHtml() helper (escapes &<>"'), including all table cells, badges, and the raw-JSON fallback view. The finding flags manual sanitization vs. a library on principle, but this is a correct, complete character-escape covering every interpolation site in the file - no unescaped sink exists.

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::595
# Issue #9
# [ERROR] secret - Hardcoded password
#   rust/crates/phase4-orchestrator/src/lib.rs:595
Acknowledge: False positive: test-fixture literal inside a #[test]/#[tokio::test] function in Ignite's own Rust test suite (asserting the scanner itself detects this pattern), not a real credential. Verified by reading the surrounding code.

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::645
# Issue #10
# [ERROR] secret - Hardcoded password
#   rust/crates/phase4-orchestrator/src/lib.rs:645
Acknowledge: False positive: test-fixture literal inside a #[test]/#[tokio::test] function in Ignite's own Rust test suite (asserting the scanner itself detects this pattern), not a real credential. Verified by reading the surrounding code.
