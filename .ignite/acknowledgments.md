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

# Scanned against commit: 257d9edb71721cc845692e94851fc24271d58ddc (working tree at push time - findings/justifications below reflect this commit's code, not necessarily what ends up pushed if the tree changes after)

ID: secret::rust/crates/malicious-dependencies/src/lib.rs::193
# Issue #1
# [ERROR] secret - Hardcoded generic-api-key
#   rust/crates/malicious-dependencies/src/lib.rs:193
Acknowledge: Test-fixture literal ("malicious-pkg==1.0.0") in a unit test assertion, not a real credential.

ID: secret::rust/crates/pii-dataflow/src/lib.rs::353
# Issue #2
# [ERROR] secret - Hardcoded gcp-api-key
#   rust/crates/pii-dataflow/src/lib.rs:353
Acknowledge: Fake GCP API key literal used as test input to verify the secret scanner's own detection, not a real credential.

ID: gha-security::.github/workflows/deploy-docs.yml::13
# Issue #3
# [ERROR] gha-security - overly broad permissions (  pages: write)
#   .github/workflows/deploy-docs.yml:13
Acknowledge: `pages: write` + `id-token: write` (next entry) are exactly the two permissions GitHub's own actions/deploy-pages documentation requires for OIDC-based Pages deployment - already the minimal job-level set (no broader contents:write, etc.). zizmor's excessive-permissions rule flags any explicit write scope without knowing what the job's own actions actually need; this is that documented minimum, not excessive in practice.

ID: gha-security::.github/workflows/deploy-docs.yml::14
# Issue #4
# [ERROR] gha-security - overly broad permissions (  id-token: write)
#   .github/workflows/deploy-docs.yml:14
Acknowledge: Same justification as the `pages: write` entry above - the minimal, documented permission pair actions/deploy-pages needs for OIDC-based deployment.

ID: secret::config.json::14
# Issue #5
# [ERROR] secret - Base64 High Entropy String
#   config.json:14
Acknowledge: Real GitHub OAuth client secret in this developer's local config.json, per CLAUDE.md's own documented note that this file "contain[s] this developer's real org name, SMTP creds, etc." — confirmed gitignored (`git check-ignore` matches `.gitignore:3:config.json`), never committed or pushed. The pre-push gate scans the whole working tree regardless of git tracking, so a real local-only secret still needs an override to unblock a push whose diff never touches this file.

ID: secret::rust/crates/llm-client/src/lib.rs::363
# Issue #6
# [ERROR] secret - Hardcoded api_key
#   rust/crates/llm-client/src/lib.rs:363
# Code: LlmClientConfig { provider: Provider::Anthropic, openai_api_key: String::new(), openai_base_url: String::new(), openai_model: String::new(), anthropic_api_key: "sk-ant-test".to_string(), anthropic_base_url: "https://api.anthropic.com/v1/".to_string(), anthropic_model: "claude-opus-5".to_string(), azure_foundry_api_key: String::new(), azure_foundry_endpoint: String::new(), azure_foundry_deployment: String::new(), azure_foundry_api_version: String::new(), scan_url: String::new(), scan_model: String::new() }
Acknowledge: Fake Anthropic API key literal ("sk-ant-test") used as test-fixture config in an llm-client unit test, not a real credential. (auto-carried-forward from secret::rust/crates/llm-client/src/lib.rs::353 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/auth/oidc.rs::319
# Issue #7
# [ERROR] secret - Hardcoded secret
#   rust/crates/server/src/auth/oidc.rs:319
# Code: config.auth.oidc.client_secret = "test-secret".into();
Acknowledge: Literal test-fixture OIDC client secret used only to construct an in-process test Config for oidc.rs's own unit tests, not a real credential. (auto-carried-forward from secret::rust/crates/server/src/auth/oidc.rs::317 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/auth/oidc.rs::318 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/auth/github_oauth.rs::290
# Issue #8
# [ERROR] secret - Hardcoded secret
#   rust/crates/server/src/auth/github_oauth.rs:290
# Code: config.github.oauth.client_secret = "secret-123".into();
Acknowledge: Literal test-fixture GitHub OAuth client secret used only to construct an in-process test Config for github_oauth.rs's own unit tests, not a real credential. (auto-carried-forward from secret::rust/crates/server/src/auth/github_oauth.rs::289 - pure line-number drift, flagged code unchanged)

ID: secret::docs-site/docs/ci-integration.md::384
# Issue #9
# [ERROR] secret - Hardcoded token
#   docs-site/docs/ci-integration.md:384
# Code: -d '{"regex": "acme_live_[a-zA-Z0-9]{24}", "sample": "token: acme_live_abcdef0123456789ghijklmn"}'
Acknowledge: Fictional pattern/sample pair in a docs-site example curl command demonstrating the custom-secret-pattern playground endpoint - "acme_live_..." isn't a real vendor token format, and the sample string is fabricated for the example, not a real credential.

ID: secret::rust/crates/secrets/src/lib.rs::694
# Issue #10
# [ERROR] secret - Hardcoded api_key
#   rust/crates/secrets/src/lib.rs:694
# Code: fs::write(root.join("config.js"), "const api_key = 'sk-proj-abcdefghijklmnop';\n").unwrap();
Acknowledge: Fake API key literal used as test input for run_gitleaks_history_scan_no_ops_without_a_git_directory (verifies the history scan is a no-op with no .git directory) - not a real credential, same fixture literal already acknowledged elsewhere in this file for the same reason. (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::579 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::798
# Issue #11
# [ERROR] secret - Hardcoded connection-string credential
#   rust/crates/secrets/src/lib.rs:798
# Code: "DATABASE_URL = \"postgresql://testuser:not-a-real-pw@x@example.com:5432/testdb\"\n",
Acknowledge: Test-fixture connection string for flags_a_password_embedded_in_a_connection_string - example.com is IANA/RFC 2606-reserved for documentation and the password is labeled a placeholder outright in the surrounding comment, not a real credential. (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::683 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::731
# Issue #12
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:731
# Code: let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
Acknowledge: Fake AWS access key literal used as a fixture file inside a review-gate integration test (uploaded as a zip so the secret scanner flags a real blocking finding to pause the run for review), not a real credential. (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1397 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1401 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::676 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::711 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::712 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::793
# Issue #13
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:793
# Code: let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
Acknowledge: Same fake AWS access key literal as the entry above, reused in a second review-gate integration test in this same file, not a real credential. (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1453 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1457 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::732 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::773 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::774 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::875
# Issue #14
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:875
# Code: let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
Acknowledge: Same fake AWS access key literal as the entries above, reused in a third review-gate integration test in this same file, not a real credential. (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1523 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1527 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::802 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::854 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::855 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::920
# Issue #15
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:920
# Code: let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
Acknowledge: Same fake AWS access key literal as the entries above, reused in a fourth review-gate integration test in this same file, not a real credential. (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1567 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1571 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::846 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::898 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::899 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/routes/custom_secret_patterns.rs::193
# Issue #16
# [ERROR] secret - Hardcoded generic-api-key
#   rust/crates/server/src/routes/custom_secret_patterns.rs:193
# Code: let req = Request::post("/api/secret-patterns/test").header("content-type", "application/json").body(Body::from(r#"{"regex":"sk_live_[a-z0-9]+","sample":"key: sk_live_abc123"}"#)).unwrap();
Acknowledge: Fabricated Stripe-format sample string used as request-body input to the custom-secret-pattern playground's own unit test (test_pattern_route_reports_matches_without_persisting_anything) - the whole point of this endpoint is to test a regex against sample text, so a plausible-looking fake match is expected input, not a real credential.

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::974
# Issue #17
# [ERROR] secret - Hardcoded gcp-api-key
#   rust/crates/phase4-orchestrator/src/lib.rs:974
# Code: fs::write(root.join("config.js"), format!("export const environment = {{ firebase: {{ apiKey: '{}' }} }};\n", "AIzaSyDGX6-TCqxyZv3m1avbP8-hZxD2-Zb6bXk")).unwrap();
Acknowledge: Fake GCP/Firebase web API key literal used as test input to verify the built-in secret scanner (SECRET_RE) doesn't false-positive on a `firebase: { apiKey: ... }` nested property shape, not a real credential. (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::868 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::875 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::881 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::942 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::1008
# Issue #18
# [ERROR] secret - Hardcoded gcp-api-key
#   rust/crates/phase4-orchestrator/src/lib.rs:1008
# Code: fs::write(root.join("config.js"), format!("export const apiKey = '{}';\n", "AIzaSyDGX6-TCqxyZv3m1avbP8-hZxD2-Zb6bXk")).unwrap();
Acknowledge: Fake GCP/Firebase web API key literal, same fixture value as the other AIzaSy... entry above, written to a scratch test repo to verify gitleaks-based secret detection - not a real credential. (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::976 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::1051
# Issue #19
# [ERROR] secret - Hardcoded github-pat
#   rust/crates/phase4-orchestrator/src/lib.rs:1051
# Code: fs::write(root.join("config.js"), "headers.set(\"Authorization\", \"Bearer ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\");\n").unwrap();
Acknowledge: Fake GitHub PAT literal (high-entropy but never issued) used to verify gitleaks flags it as github-pat and that the off-by-default secret_verification path never appends a VERIFIED LIVE marker - not a real credential, never sent anywhere but api.github.com's own 401 rejection path in the sibling test below. (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1019 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::1086
# Issue #20
# [ERROR] secret - Hardcoded github-pat
#   rust/crates/phase4-orchestrator/src/lib.rs:1086
# Code: fs::write(root.join("config.js"), "headers.set(\"Authorization\", \"Bearer ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\");\n").unwrap();
Acknowledge: Same fake GitHub PAT fixture as the entry above, used in secret_verification_when_enabled_never_flags_a_fake_token_as_verified_live to confirm a live GitHub API 401 for this token is correctly reported as not-live - not a real credential. (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1054 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::927
# Issue #21
# [ERROR] secret - Hardcoded stripe-access-token
#   rust/crates/secrets/src/lib.rs:927
# Code: let matches = test_pattern_against_sample(r"sk_live_[a-zA-Z0-9]{16,}", "key one: sk_live_abcdef0123456789, key two: sk_live_zzzzzz9999999999").unwrap();
Acknowledge: Fabricated Stripe-format sample text (test_pattern_against_sample_finds_all_matches) verifying the custom-secret-pattern regex tester finds every match in a sample, not a real credential - same fixture literal flagged again at the two assert_eq! lines immediately below for the same reason.

ID: secret::rust/crates/secrets/src/lib.rs::929
# Issue #22
# [ERROR] secret - Hardcoded stripe-access-token
#   rust/crates/secrets/src/lib.rs:929
# Code: assert_eq!(matches[0].matched_text, "sk_live_abcdef0123456789");
Acknowledge: Same fabricated Stripe-format fixture literal as the entry above, asserted as the expected match text in the same test - not a real credential.

ID: secret::rust/crates/secrets/src/lib.rs::930
# Issue #23
# [ERROR] secret - Hardcoded stripe-access-token
#   rust/crates/secrets/src/lib.rs:930
# Code: assert_eq!(matches[1].matched_text, "sk_live_zzzzzz9999999999");
Acknowledge: Same fabricated Stripe-format fixture literal as the two entries above, asserted as the second expected match text in the same test - not a real credential.

ID: codeql-sast::public/index.html::842::js/xss-through-dom
# Issue #24
# [ERROR] codeql-sast - DOM text is reinterpreted as HTML without escaping meta-characters.
#   public/index.html:842
# Code: document.querySelectorAll('[data-i18n-html]').forEach((el) => { el.innerHTML = t(el.getAttribute('data-i18n-html')); });
Acknowledge: Narrowed replacement for the previously-acknowledged finding at the old [data-i18n] innerHTML call (now textContent - see the applyStaticTranslations doc comment above it). Only elements explicitly opted in via data-i18n-html still use innerHTML, for the handful of translation keys whose copy deliberately carries inline markup (bold spans in upload.dropSubtitle, a line break in footer.note, etc). t()'s only inputs remain (1) the fixed attribute-name string 'data-i18n-html' read off the DOM and (2) a lookup into window.IGNITE_I18N.translations, entirely defined by public/i18n.js - a file committed to this repo and only ever edited by a developer/operator, never populated from user input, the network, or any request parameter. No untrusted data reaches this call. (auto-carried-forward from codeql-sast::public/index.html::781::js/xss-through-dom - pure line-number drift, flagged code unchanged) (auto-carried-forward from codeql-sast::public/index.html::813::js/xss-through-dom - pure line-number drift, flagged code unchanged) (auto-carried-forward from codeql-sast::public/index.html::821::js/xss-through-dom - pure line-number drift, flagged code unchanged) (auto-carried-forward from codeql-sast::public/index.html::822::js/xss-through-dom - pure line-number drift, flagged code unchanged)
