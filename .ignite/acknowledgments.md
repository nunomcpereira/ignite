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

# Scanned against commit: b979e6e5bb721b673b34a936e96be1b5a5167162 (working tree at push time - findings/justifications below reflect this commit's code, not necessarily what ends up pushed if the tree changes after)

ID: secret::rust/crates/malicious-dependencies/src/lib.rs::193
# Issue #1
# [ERROR] secret - Hardcoded generic-api-key
#   rust/crates/malicious-dependencies/src/lib.rs:193
Acknowledge: Test-fixture literal ("malicious-pkg==1.0.0") in a unit test assertion, not a real credential.

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::1031
# Issue #2
# [ERROR] secret - Hardcoded aws-access-token
#   rust/crates/server/src/routes/pipeline_interactive.rs:1031
Acknowledge: Fake AWS access key ID embedded in an in-memory test-zip fixture used to verify the pipeline's own secret detection, not a real credential.

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::660
# Issue #3
# [ERROR] secret - Hardcoded gcp-api-key
#   rust/crates/phase4-orchestrator/src/lib.rs:660
Acknowledge: Fake GCP API key literal written to a scratch fixture file within a unit test, not a real credential.

ID: secret::rust/crates/pii-dataflow/src/lib.rs::353
# Issue #4
# [ERROR] secret - Hardcoded gcp-api-key
#   rust/crates/pii-dataflow/src/lib.rs:353
Acknowledge: Fake GCP API key literal used as test input to verify the secret scanner's own detection, not a real credential.
