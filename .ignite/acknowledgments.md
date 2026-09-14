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

ID: gha-security::.github/workflows/deploy-docs.yml::13
# Issue #1
# [ERROR] gha-security - overly broad permissions (  pages: write)
#   .github/workflows/deploy-docs.yml:13
Acknowledge: `pages: write` + `id-token: write` (next entry) are exactly the two permissions GitHub's own actions/deploy-pages documentation requires for OIDC-based Pages deployment - already the minimal job-level set (no broader contents:write, etc.). zizmor's excessive-permissions rule flags any explicit write scope without knowing what the job's own actions actually need; this is that documented minimum, not excessive in practice.

ID: gha-security::.github/workflows/deploy-docs.yml::14
# Issue #2
# [ERROR] gha-security - overly broad permissions (  id-token: write)
#   .github/workflows/deploy-docs.yml:14
Acknowledge: Same justification as the `pages: write` entry above - the minimal, documented permission pair actions/deploy-pages needs for OIDC-based deployment.

ID: secret::config.json::14
# Issue #3
# [ERROR] secret - Base64 High Entropy String
#   config.json:14
Acknowledge: Real GitHub OAuth client secret in this developer's local config.json, per CLAUDE.md's own documented note that this file "contain[s] this developer's real org name, SMTP creds, etc." — confirmed gitignored (`git check-ignore` matches `.gitignore:3:config.json`), never committed or pushed. The pre-push gate scans the whole working tree regardless of git tracking, so a real local-only secret still needs an override to unblock a push whose diff never touches this file.

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::920
# Issue #4
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:920
# Code: let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
Acknowledge: Same fake AWS access key literal as the entries above, reused in a fourth review-gate integration test in this same file, not a real credential. (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1567 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1571 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::846 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::898 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::899 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/llm-client/src/lib.rs::364
# Issue #5
# [ERROR] secret - Hardcoded api_key
#   rust/crates/llm-client/src/lib.rs:364
# Code: LlmClientConfig { provider: Provider::Anthropic, openai_api_key: String::new(), openai_base_url: String::new(), openai_model: String::new(), anthropic_api_key: "sk-ant-test".to_string(), anthropic_base_url: "https://api.anthropic.com/v1/".to_string(), anthropic_model: "claude-opus-5".to_string(), azure_foundry_api_key: String::new(), azure_foundry_endpoint: String::new(), azure_foundry_deployment: String::new(), azure_foundry_api_version: String::new(), scan_url: String::new(), scan_model: String::new() }
Acknowledge: Fake Anthropic API key literal ("sk-ant-test") used as test-fixture config in an llm-client unit test, not a real credential. (auto-carried-forward from secret::rust/crates/llm-client/src/lib.rs::353 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/llm-client/src/lib.rs::363 - pure line-number drift, flagged code unchanged)

ID: secret::docs-site/docs/ci-integration.md::493
# Issue #6
# [ERROR] secret - Hardcoded token
#   docs-site/docs/ci-integration.md:493
# Code: -d '{"regex": "acme_live_[a-zA-Z0-9]{24}", "sample": "token: acme_live_abcdef0123456789ghijklmn"}'
Acknowledge: Fictional pattern/sample pair in a docs-site example curl command demonstrating the custom-secret-pattern playground endpoint - "acme_live_..." isn't a real vendor token format, and the sample string is fabricated for the example, not a real credential. (auto-carried-forward from secret::docs-site/docs/ci-integration.md::384 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::docs-site/docs/ci-integration.md::457 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/auth/oidc.rs::322
# Issue #7
# [ERROR] secret - Hardcoded secret
#   rust/crates/server/src/auth/oidc.rs:322
# Code: config.auth.oidc.client_secret = "test-secret".into();
Acknowledge: Literal test-fixture OIDC client secret used only to construct an in-process test Config for oidc.rs's own unit tests, not a real credential. (auto-carried-forward from secret::rust/crates/server/src/auth/oidc.rs::317 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/auth/oidc.rs::318 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/auth/oidc.rs::319 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/auth/github_oauth.rs::293
# Issue #8
# [ERROR] secret - Hardcoded secret
#   rust/crates/server/src/auth/github_oauth.rs:293
# Code: config.github.oauth.client_secret = "secret-123".into();
Acknowledge: Literal test-fixture GitHub OAuth client secret used only to construct an in-process test Config for github_oauth.rs's own unit tests, not a real credential. (auto-carried-forward from secret::rust/crates/server/src/auth/github_oauth.rs::289 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/auth/github_oauth.rs::290 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/malicious-dependencies/src/lib.rs::196
# Issue #9
# [ERROR] secret - Hardcoded generic-api-key
#   rust/crates/malicious-dependencies/src/lib.rs:196
# Code: assert_eq!(verdicts[0].pkg_key, "malicious-pkg==1.0.0");
Acknowledge: False-positive match on a plain test package-name string ("malicious-pkg==1.0.0") asserting guarddog_verdicts_from_report's numeric-issues-shape parsing - no secret, credential, or high-entropy value anywhere in this line. (auto-carried-forward from secret::rust/crates/malicious-dependencies/src/lib.rs::194 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::759
# Issue #10
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:759
# Code: let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
Acknowledge: Fake AWS access key literal used as a fixture file inside a review-gate integration test (uploaded as a zip so the secret scanner flags a real blocking finding to pause the run for review), not a real credential. (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1397 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1401 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::676 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::711 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::712 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::731 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::823
# Issue #11
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:823
# Code: let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
Acknowledge: Same fake AWS access key literal as the entry above, reused in a second review-gate integration test in this same file, not a real credential. (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1453 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1457 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::732 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::773 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::774 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::793 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::975
# Issue #12
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:975
# Code: let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
Acknowledge: Same fake AWS access key literal as the entries above, reused in a third review-gate integration test in this same file, not a real credential. (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1523 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1527 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::802 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::854 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::855 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::875 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/pii-dataflow/src/lib.rs::393
# Issue #13
# [ERROR] secret - Hardcoded apikey
#   rust/crates/pii-dataflow/src/lib.rs:393
# Code: let line = r#"const apiKey = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe";"#;
Acknowledge: Fake Firebase public web API key literal used as test input to verify is_firebase_public_api_key_finding correctly excludes this shape only for the "hard-coded secret" finding title, not for other titles - not a real credential. (auto-carried-forward from secret::rust/crates/pii-dataflow/src/lib.rs::354 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/pii-dataflow/src/lib.rs::377 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::1062
# Issue #14
# [ERROR] secret - Hardcoded gcp-api-key
#   rust/crates/phase4-orchestrator/src/lib.rs:1062
# Code: fs::write(root.join("config.js"), format!("export const environment = {{ firebase: {{ apiKey: '{}' }} }};\n", "AIzaSyDGX6-TCqxyZv3m1avbP8-hZxD2-Zb6bXk")).unwrap();
Acknowledge: Fake GCP/Firebase web API key literal used as test input to verify the built-in secret scanner (SECRET_RE) doesn't false-positive on a `firebase: { apiKey: ... }` nested property shape, not a real credential. (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::868 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::875 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::881 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::942 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::974 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1010 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1011 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::1138
# Issue #15
# [ERROR] secret - Hardcoded gcp-api-key
#   rust/crates/phase4-orchestrator/src/lib.rs:1138
# Code: fs::write(root.join("config.js"), format!("export const apiKey = '{}';\n", "AIzaSyDGX6-TCqxyZv3m1avbP8-hZxD2-Zb6bXk")).unwrap();
Acknowledge: Fake GCP/Firebase web API key literal, same fixture value as the other AIzaSy... entry above, written to a scratch test repo to verify gitleaks-based secret detection - not a real credential. (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::976 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1008 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1078 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1086 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1087 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::1181
# Issue #16
# [ERROR] secret - Hardcoded github-pat
#   rust/crates/phase4-orchestrator/src/lib.rs:1181
# Code: fs::write(root.join("config.js"), "headers.set(\"Authorization\", \"Bearer ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\");\n").unwrap();
Acknowledge: Fake GitHub PAT literal (high-entropy but never issued) used to verify gitleaks flags it as github-pat and that the off-by-default secret_verification path never appends a VERIFIED LIVE marker - not a real credential, never sent anywhere but api.github.com's own 401 rejection path in the sibling test below. (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1019 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1051 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1121 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1129 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1130 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::1216
# Issue #17
# [ERROR] secret - Hardcoded github-pat
#   rust/crates/phase4-orchestrator/src/lib.rs:1216
# Code: fs::write(root.join("config.js"), "headers.set(\"Authorization\", \"Bearer ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\");\n").unwrap();
Acknowledge: Same fake GitHub PAT fixture as the entry above, used in secret_verification_when_enabled_never_flags_a_fake_token_as_verified_live to confirm a live GitHub API 401 for this token is correctly reported as not-live - not a real credential. (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1054 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1086 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1156 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1164 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1165 - pure line-number drift, flagged code unchanged)

ID: codeql-sast::public/index.html::1063::js/xss-through-dom
# Issue #18
# [ERROR] codeql-sast - DOM text is reinterpreted as HTML without escaping meta-characters.
#   public/index.html:1063
# Code: document.querySelectorAll('[data-i18n-html]').forEach((el) => { el.innerHTML = t(el.getAttribute('data-i18n-html')); });
Acknowledge: Narrowed replacement for the previously-acknowledged finding at the old [data-i18n] innerHTML call (now textContent - see the applyStaticTranslations doc comment above it). Only elements explicitly opted in via data-i18n-html still use innerHTML, for the handful of translation keys whose copy deliberately carries inline markup (bold spans in upload.dropSubtitle, a line break in footer.note, etc). t()'s only inputs remain (1) the fixed attribute-name string 'data-i18n-html' read off the DOM and (2) a lookup into window.IGNITE_I18N.translations, entirely defined by public/i18n.js - a file committed to this repo and only ever edited by a developer/operator, never populated from user input, the network, or any request parameter. No untrusted data reaches this call. (auto-carried-forward from codeql-sast::public/index.html::781::js/xss-through-dom - pure line-number drift, flagged code unchanged) (auto-carried-forward from codeql-sast::public/index.html::813::js/xss-through-dom - pure line-number drift, flagged code unchanged) (auto-carried-forward from codeql-sast::public/index.html::821::js/xss-through-dom - pure line-number drift, flagged code unchanged) (auto-carried-forward from codeql-sast::public/index.html::822::js/xss-through-dom - pure line-number drift, flagged code unchanged) (auto-carried-forward from codeql-sast::public/index.html::842::js/xss-through-dom - pure line-number drift, flagged code unchanged) (auto-carried-forward from codeql-sast::public/index.html::841::js/xss-through-dom - pure line-number drift, flagged code unchanged) (auto-carried-forward from codeql-sast::public/index.html::967::js/xss-through-dom - pure line-number drift, flagged code unchanged) (auto-carried-forward from codeql-sast::public/index.html::1055::js/xss-through-dom - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::57
# Issue #19
# [ERROR] secret - Hardcoded connection-string credential
#   rust/crates/secrets/src/lib.rs:57
# Code: // (`"postgres://usr:pwd@host1/db"; "redis://admin:secret@host2"`) doesn't
Acknowledge: Doc-comment example illustrating URI_CREDENTIAL_RE's greedy-match boundary behavior across two adjacent connection strings on one line - not a real credential, and not even executable code (a `//` comment).

ID: secret::rust/crates/config/src/lib.rs::1340
# Issue #20
# [ERROR] secret - Hardcoded api_key
#   rust/crates/config/src/lib.rs:1340
# Code: cfg.llm.openai.api_key = "sk-live-supersecret".to_string();
Acknowledge: Fabricated OpenAI-format API key literal used only to verify Config's new redacting Debug impl (debug_redacts_secret_fields_but_keeps_non_secret_fields_visible) actually hides secret fields from {:?} output - not a real credential. (auto-carried-forward from secret::rust/crates/config/src/lib.rs::1290 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/config/src/lib.rs::1307 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/config/src/lib.rs::1323 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/config/src/lib.rs::1341
# Issue #21
# [ERROR] secret - Hardcoded secret
#   rust/crates/config/src/lib.rs:1341
# Code: cfg.github.oauth.client_secret = "oauth-secret-value".to_string();
Acknowledge: Same test as the entry above - a fabricated OAuth client secret literal used only to verify the redacting Debug impl, not a real credential. (auto-carried-forward from secret::rust/crates/config/src/lib.rs::1291 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/config/src/lib.rs::1308 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/config/src/lib.rs::1324 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::790
# Issue #22
# [ERROR] secret - Hardcoded api_key
#   rust/crates/secrets/src/lib.rs:790
# Code: fs::write(root.join("config.js"), "const api_key = 'sk-proj-abcdefghijklmnop';\n").unwrap();
Acknowledge: Fake API key literal used as test input for run_gitleaks_history_scan_no_ops_without_a_git_directory (verifies the history scan is a no-op with no .git directory) - not a real credential, same fixture literal already acknowledged elsewhere in this file for the same reason. (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::579 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::694 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::710 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::726 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::757 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::778 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::894
# Issue #23
# [ERROR] secret - Hardcoded connection-string credential
#   rust/crates/secrets/src/lib.rs:894
# Code: "DATABASE_URL = \"postgresql://testuser:not-a-real-pw@x@example.com:5432/testdb\"\n",
Acknowledge: Test-fixture connection string for flags_a_password_embedded_in_a_connection_string - example.com is IANA/RFC 2606-reserved for documentation and the password is labeled a placeholder outright in the surrounding comment, not a real credential. (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::683 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::798 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::814 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::830 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::861 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::882 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/routes/custom_secret_patterns.rs::210
# Issue #24
# [ERROR] secret - Hardcoded generic-api-key
#   rust/crates/server/src/routes/custom_secret_patterns.rs:210
# Code: let req = Request::post("/api/secret-patterns/test").header("content-type", "application/json").body(Body::from(r#"{"regex":"sk_live_[a-z0-9]+","sample":"key: sk_live_abc123"}"#)).unwrap();
Acknowledge: Fabricated Stripe-format sample string used as request-body input to the custom-secret-pattern playground's own unit test (test_pattern_route_reports_matches_without_persisting_anything) - the whole point of this endpoint is to test a regex against sample text, so a plausible-looking fake match is expected input, not a real credential. (auto-carried-forward from secret::rust/crates/server/src/routes/custom_secret_patterns.rs::193 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/custom_secret_patterns.rs::203 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/custom_secret_patterns.rs::207 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::1022
# Issue #25
# [ERROR] secret - Hardcoded stripe-access-token
#   rust/crates/secrets/src/lib.rs:1022
# Code: let matches = test_pattern_against_sample(r"sk_live_[a-zA-Z0-9]{16,}", "key one: sk_live_abcdef0123456789, key two: sk_live_zzzzzz9999999999").unwrap();
Acknowledge: Fabricated Stripe-format sample text (test_pattern_against_sample_finds_all_matches) verifying the custom-secret-pattern regex tester finds every match in a sample, not a real credential - same fixture literal flagged again at the two assert_eq! lines immediately below for the same reason. (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::927 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::943 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::959 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::990 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::989 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::1010 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::1024
# Issue #26
# [ERROR] secret - Hardcoded stripe-access-token
#   rust/crates/secrets/src/lib.rs:1024
# Code: assert_eq!(matches[0].matched_text, "sk_live_abcdef0123456789");
Acknowledge: Same fabricated Stripe-format fixture literal as the entry above, asserted as the expected match text in the same test - not a real credential. (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::929 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::945 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::961 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::992 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::991 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::1012 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::1025
# Issue #27
# [ERROR] secret - Hardcoded stripe-access-token
#   rust/crates/secrets/src/lib.rs:1025
# Code: assert_eq!(matches[1].matched_text, "sk_live_zzzzzz9999999999");
Acknowledge: Same fabricated Stripe-format fixture literal as the two entries above, asserted as the expected second match in the same regex-tester unit test — not a real credential. (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::992 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::1013 - pure line-number drift, flagged code unchanged)

ID: iac-security::Dockerfile::1::629a3996
# Issue #28
# [WARNING] iac-security - No HEALTHCHECK defined
#   Dockerfile:1
# Code: # Ignite, self-contained: the Rust server/CLI/MCP binaries plus every
Acknowledge: 

ID: iac-security::Dockerfile::1::5c411837
# Issue #29
# [WARNING] iac-security - Ensure that HEALTHCHECK instructions have been added to container images
#   Dockerfile:1
# Code: # Ignite, self-contained: the Rust server/CLI/MCP binaries plus every
Acknowledge: 

ID: iac-security::Dockerfile::127
# Issue #30
# [WARNING] iac-security - Pin versions in apt get install. Instead of `apt-get install <package>` use `apt-get install <package>=<version>`
#   Dockerfile:127
# Code: RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
Acknowledge: 

ID: iac-security::Dockerfile::149
# Issue #31
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:149
# Code: RUN if [ "$INSTALL_ORT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::158
# Issue #32
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:158
# Code: RUN if [ "$INSTALL_TRIVY" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::162
# Issue #33
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:162
# Code: RUN if [ "$INSTALL_CHECKOV" = "true" ]; then pipx install checkov --pip-args="--no-compile" && pipx ensurepath; fi
Acknowledge: 

ID: iac-security::Dockerfile::171
# Issue #34
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:171
# Code: RUN if [ "$INSTALL_GITLEAKS" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::177
# Issue #35
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:177
# Code: RUN if [ "$INSTALL_SYFT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::187
# Issue #36
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:187
# Code: RUN if [ "$INSTALL_SEMGREP" = "true" ]; then pipx install semgrep --pip-args="--no-compile" && pipx ensurepath; fi
Acknowledge: 

ID: iac-security::Dockerfile::188
# Issue #37
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:188
# Code: RUN if [ "$INSTALL_BEARER" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::212::09cd120f
# Issue #38
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:212
# Code: RUN if [ "$INSTALL_GUARDDOG" = "true" ] || [ "$INSTALL_LICENSEE" = "true" ] || [ "$INSTALL_COCOAPODS" = "true" ] || [ "$INSTALL_ORT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::212::bdfb7069
# Issue #39
# [WARNING] iac-security - Pin versions in apt get install. Instead of `apt-get install <package>` use `apt-get install <package>=<version>`
#   Dockerfile:212
# Code: RUN if [ "$INSTALL_GUARDDOG" = "true" ] || [ "$INSTALL_LICENSEE" = "true" ] || [ "$INSTALL_COCOAPODS" = "true" ] || [ "$INSTALL_ORT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::212::19c88dc5
# Issue #40
# [WARNING] iac-security - Pin versions in gem install. Instead of `gem install <gem>` use `gem install <gem>:<version>`
#   Dockerfile:212
# Code: RUN if [ "$INSTALL_GUARDDOG" = "true" ] || [ "$INSTALL_LICENSEE" = "true" ] || [ "$INSTALL_COCOAPODS" = "true" ] || [ "$INSTALL_ORT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::225
# Issue #41
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:225
# Code: RUN if [ "$INSTALL_PICKLESCAN" = "true" ]; then pipx install picklescan --pip-args="--no-compile" && pipx ensurepath; fi
Acknowledge: 

ID: iac-security::Dockerfile::226
# Issue #42
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:226
# Code: RUN if [ "$INSTALL_ZIZMOR" = "true" ]; then pipx install zizmor --pip-args="--no-compile" && pipx ensurepath; fi
Acknowledge: 

ID: iac-security::Dockerfile::227
# Issue #43
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:227
# Code: RUN if [ "$INSTALL_OASDIFF" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::255
# Issue #44
# [WARNING] iac-security - Pin versions in npm. Instead of `npm install <package>` use `npm install <package>@<version>`
#   Dockerfile:255
# Code: RUN if [ "$INSTALL_JSCPD" = "true" ]; then npm install -g jscpd; fi
Acknowledge: 

ID: iac-security::Dockerfile::256::2ddec02b
# Issue #45
# [WARNING] iac-security - Multiple consecutive `RUN` instructions. Consider consolidation.
#   Dockerfile:256
# Code: RUN if [ "$INSTALL_SPECTRAL" = "true" ]; then npm install -g @stoplight/spectral-cli; fi
Acknowledge: 

ID: iac-security::Dockerfile::256::37ad8298
# Issue #46
# [WARNING] iac-security - Pin versions in npm. Instead of `npm install <package>` use `npm install <package>@<version>`
#   Dockerfile:256
# Code: RUN if [ "$INSTALL_SPECTRAL" = "true" ]; then npm install -g @stoplight/spectral-cli; fi
Acknowledge: 

ID: iac-security::Dockerfile::277
# Issue #47
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:277
# Code: RUN if [ "$INSTALL_ACT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::291
# Issue #48
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:291
# Code: RUN if [ "$INSTALL_DOCKER_CLI" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::343
# Issue #49
# [WARNING] iac-security - Non-numeric user-id may not be resolvable by host system
#   Dockerfile:343
# Code: USER ignite
Acknowledge: 

ID: gha-security::.github/workflows/check-env-var-drift.yml::25
# Issue #50
# [WARNING] gha-security - credential persistence through GitHub Actions artifacts (uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4)
#   .github/workflows/check-env-var-drift.yml:25
# Code: - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
Acknowledge: 

ID: gha-security::.github/workflows/deploy-docs.yml::24
# Issue #51
# [WARNING] gha-security - credential persistence through GitHub Actions artifacts (uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4)
#   .github/workflows/deploy-docs.yml:24
# Code: - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
Acknowledge: 

ID: image-provenance::Dockerfile::19
# Issue #52
# [WARNING] image-provenance - Base image "rust:1-bookworm" has no verifiable Sigstore/cosign signature — supply-chain provenance can't be confirmed.
#   Dockerfile:19
# Code: FROM rust:1-bookworm AS rust-builder
Acknowledge: 

ID: image-provenance::Dockerfile::30
# Issue #53
# [WARNING] image-provenance - Base image "node:24-bookworm-slim" has no verifiable Sigstore/cosign signature — supply-chain provenance can't be confirmed.
#   Dockerfile:30
# Code: FROM node:24-bookworm-slim
Acknowledge: 

ID: code-duplication::public/index.html::2918
# Issue #54
# [WARNING] code-duplication - 20-line duplicate block, also found in public/index.html:5814-5833.
#   public/index.html:2918
# Code: list.innerHTML = sortedIssueIndices(issues).map((idx) => safeRenderIssueCard(issues[idx], idx, { interactive: issues[idx].status !== 'overridden' })).join('');
Acknowledge: 

ID: code-duplication::public/index.html::4782
# Issue #55
# [WARNING] code-duplication - 25-line duplicate block, also found in public/index.html:4948-4972.
#   public/index.html:4782
# Code: body: JSON.stringify({ language }),
Acknowledge: 

ID: code-duplication::rust/crates/db-store/src/overrides.rs::198::777e8c20
# Issue #56
# [WARNING] code-duplication - 18-line duplicate block, also found in rust/crates/db-store/src/overrides.rs:246-263.
#   rust/crates/db-store/src/overrides.rs:198
# Code: stmt.query_map(params![project_id], |row| {
Acknowledge: 

ID: code-duplication::rust/crates/llm-client/src/lib.rs::233
# Issue #57
# [WARNING] code-duplication - 16-line duplicate block, also found in rust/crates/llm-client/src/lib.rs:302-317.
#   rust/crates/llm-client/src/lib.rs:233
# Code: return Err(LlmError::Timeout(timeout_ms));
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/audit_log.rs::105::e3a52b99
# Issue #58
# [WARNING] code-duplication - 33-line duplicate block, also found in rust/crates/server/src/routes/compliance.rs:104-136.
#   rust/crates/server/src/routes/audit_log.rs:105
# Code: Router::new().route("/api/audit-log", get(list)).route("/api/audit-log/verify", get(verify))
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/history.rs::219
# Issue #59
# [WARNING] code-duplication - 16-line duplicate block, also found in rust/crates/server/src/routes/pipeline_interactive.rs:411-427.
#   rust/crates/server/src/routes/history.rs:219
# Code: review_gate: ReviewGate::default(),
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_interactive.rs::473
# Issue #60
# [WARNING] code-duplication - 31-line duplicate block, also found in rust/crates/server/src/routes/pipeline_interactive.rs:699-729.
#   rust/crates/server/src/routes/pipeline_interactive.rs:473
# Code: let zip = zip_bytes(&[("app.js", b"console.log(1);"), ("package.json", b"{\"name\":\"fixture\"}")]);
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_interactive.rs::474
# Issue #61
# [WARNING] code-duplication - 22-line duplicate block, also found in rust/crates/server/src/routes/pipeline_interactive.rs:923-944.
#   rust/crates/server/src/routes/pipeline_interactive.rs:474
# Code: let form = Form::new().text("org", "-bad-").text("repo", "widgets").text("dryRun", "true").part("archive", Part::bytes(zip).file_name("p.zip"));
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_onboard.rs::29
# Issue #62
# [WARNING] code-duplication - 59-line duplicate block, also found in rust/crates/server/src/routes/pipeline_validate.rs:32-90.
#   rust/crates/server/src/routes/pipeline_onboard.rs:29
# Code: static REPO_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,100}$").unwrap());
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_onboard.rs::88
# Issue #63
# [WARNING] code-duplication - 18-line duplicate block, also found in rust/crates/server/src/routes/pipeline_validate.rs:92-109.
#   rust/crates/server/src/routes/pipeline_onboard.rs:88
# Code: self.inner.lock().unwrap().project_id = Some(id);
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_onboard.rs::161
# Issue #64
# [WARNING] code-duplication - 16-line duplicate block, also found in rust/crates/server/src/routes/pipeline_validate.rs:239-253.
#   rust/crates/server/src/routes/pipeline_onboard.rs:161
# Code: let dry_run = body.get("dryRun").and_then(|v| v.as_bool()).unwrap_or(false);
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_onboard.rs::384
# Issue #65
# [WARNING] code-duplication - 20-line duplicate block, also found in rust/crates/server/src/routes/pipeline_validate.rs:490-509.
#   rust/crates/server/src/routes/pipeline_onboard.rs:384
# Code: actor_name: None,
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/push_protection_webhook.rs::239
# Issue #66
# [WARNING] code-duplication - 17-line duplicate block, also found in rust/crates/server/src/routes/repository_events_webhook.rs:180-196.
#   rust/crates/server/src/routes/push_protection_webhook.rs:239
# Code: async fn push_protection_webhook_404s_when_unconfigured() {
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/repository_events_webhook.rs::67
# Issue #67
# [WARNING] code-duplication - 20-line duplicate block, also found in rust/crates/server/src/routes/secret_scanning_webhook.rs:79-98.
#   rust/crates/server/src/routes/repository_events_webhook.rs:67
# Code: return err(StatusCode::NOT_FOUND, "Inbound repository-events webhook is not configured.".to_string());
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/repository_events_webhook.rs::179
# Issue #68
# [WARNING] code-duplication - 18-line duplicate block, also found in rust/crates/server/src/routes/secret_scanning_webhook.rs:242-259.
#   rust/crates/server/src/routes/repository_events_webhook.rs:179
# Code: #[tokio::test]
Acknowledge: 

ID: code-structure::rust/crates/config/src/lib.rs::1
# Issue #69
# [WARNING] code-structure - rust/crates/config/src/lib.rs is 1513 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/config/src/lib.rs:1
# Code: //! Ignite configuration — config.json < environment variables. Faithful
Acknowledge: 

ID: code-structure::rust/crates/secrets/src/lib.rs::1
# Issue #70
# [WARNING] code-structure - rust/crates/secrets/src/lib.rs is 1085 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/secrets/src/lib.rs:1
# Code: //! Regex-based secret scan + optional gitleaks supplement. Faithful port
Acknowledge: 

ID: code-structure::rust/crates/auto-fix-pr/src/lib.rs::1
# Issue #71
# [WARNING] code-structure - rust/crates/auto-fix-pr/src/lib.rs is 1456 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/auto-fix-pr/src/lib.rs:1
# Code: //! Auto-fix PR bot — the Dependabot-parity gap `scheduled-rescan` leaves
Acknowledge: 

ID: code-structure::rust/crates/server/src/routes/studio.rs::1
# Issue #72
# [WARNING] code-structure - rust/crates/server/src/routes/studio.rs is 1071 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/server/src/routes/studio.rs:1
# Code: //! `/api/pipeline/:jobId/studio/*` — faithful (partial) port of
Acknowledge: 

ID: code-structure::rust/crates/server/src/routes/pipeline_interactive.rs::1
# Issue #73
# [WARNING] code-structure - rust/crates/server/src/routes/pipeline_interactive.rs is 1010 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/server/src/routes/pipeline_interactive.rs:1
# Code: //! POST /api/pipeline — faithful port of routes/pipeline-interactive.js:
Acknowledge: 

ID: code-structure::rust/crates/fix-pr/src/lib.rs::1
# Issue #74
# [WARNING] code-structure - rust/crates/fix-pr/src/lib.rs is 1199 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/fix-pr/src/lib.rs:1
# Code: //! Bulk "fix all findings" PR generator — the scan-wide counterpart to
Acknowledge: 

ID: code-structure::rust/crates/dependency-license-scan/src/lib.rs::1
# Issue #75
# [WARNING] code-structure - rust/crates/dependency-license-scan/src/lib.rs is 1808 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/dependency-license-scan/src/lib.rs:1
# Code: //! Dependency license/vulnerability scan orchestrators. Faithful port of
Acknowledge: 

ID: code-structure::rust/crates/phase4-orchestrator/src/lib.rs::1
# Issue #76
# [WARNING] code-structure - rust/crates/phase4-orchestrator/src/lib.rs is 1270 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/phase4-orchestrator/src/lib.rs:1
# Code: //! Phase 4 check orchestrator. Faithful port of server.js's
Acknowledge: 

ID: code-structure::public/i18n.js::1
# Issue #77
# [WARNING] code-structure - public/i18n.js is 1314 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   public/i18n.js:1
# Code: // Ignite web UI translations — static UI chrome only (buttons, labels,
Acknowledge: 

ID: codeql-sast::public/index.html::1489::js/incomplete-html-attribute-sanitization
# Issue #78
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:1489
# Code: <button type="button" class="shrink-0 text-slate-300 hover:text-slate-600" aria-label="${escapeHtml(t('common.close'))}">
Acknowledge: 

ID: codeql-sast::public/index.html::2868::js/incomplete-html-attribute-sanitization
# Issue #79
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:2868
# Code: <span class="w-40 shrink-0 truncate text-slate-700" title="${escapeHtml(name)}">${escapeHtml(name)}${isBottleneck ? ' <span class="text-rose-500" title="Bottleneck — slowest check this run">⬤</span>' : ''}</span>
Acknowledge: 

ID: codeql-sast::public/index.html::4609::js/incomplete-html-attribute-sanitization
# Issue #80
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:4609
# Code: <textarea id="studioQueryText" class="w-full flex-1 min-h-[180px] font-mono text-[12px] leading-relaxed border border-slate-200 rounded-lg p-2" spellcheck="false" placeholder="import ${escapeHtml(defaultLanguage)}\n\nfrom ...\nselect ...">${escapeHtml(initialText)}</textarea>
Acknowledge: 

ID: codeql-sast::public/index.html::6432::js/incomplete-html-attribute-sanitization
# Issue #81
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:6432
# Code: select.innerHTML = orgs.map((o) => `<option value="${escapeHtml(o)}">${escapeHtml(o)}</option>`).join('');
Acknowledge: 

ID: codeql-sast::public/index.html::6521::js/incomplete-html-attribute-sanitization::e40e5cb3
# Issue #82
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:6521
# Code: <button type="button" class="hist-view-checks-report text-[11px] font-semibold text-slate-500 hover:underline shrink-0" data-id="${p.id}" data-org="${escapeHtml(p.org)}" data-repo="${escapeHtml(p.repo)}">${t('history.checksBtn')}</button>
Acknowledge: 

ID: codeql-sast::public/index.html::6523::js/incomplete-html-attribute-sanitization::e40e5cb3
# Issue #83
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:6523
# Code: ${p.issue_count > 0 ? `<button type="button" class="hist-open-studio text-[11px] font-semibold text-violet-600 hover:underline shrink-0" data-id="${p.id}" data-job-id="${escapeAttr(p.job_id || '')}" data-retained="${p.retained ? '1' : ''}" data-org="${escapeHtml(p.org)}" data-repo="${escapeHtml(p.repo)}" title="${escapeAttr(p.retained ? t('history.fullStudioTitle') : t('history.readOnlyStudioTitle'))}">${p.retained ? `${t('history.studioBtn')}${p.retained_tier === 'pruned' ? ` (${t('history.flaggedFilesOnly')})` : ` (${t('common.full')})`}` : t('history.studioBtn')}</button>` : ''}
Acknowledge: 

ID: codeql-sast::public/index.html::6524::js/incomplete-html-attribute-sanitization::e40e5cb3
# Issue #84
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:6524
# Code: ${p.issue_count > 0 ? `<button type="button" class="hist-view-issues text-[11px] font-semibold text-brand-600 hover:underline shrink-0" data-id="${p.id}" data-count="${p.issue_count}" data-org="${escapeHtml(p.org)}" data-repo="${escapeHtml(p.repo)}">${t('history.issueCount', { count: p.issue_count })}</button>` : ''}
Acknowledge: 

ID: dead-code::docs-site/.docusaurus/client-modules.js::1::unused-file
# Issue #85
# [WARNING] dead-code - docs-site/.docusaurus/client-modules.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/.docusaurus/client-modules.js:1
# Code: export default [
Acknowledge: 

ID: dead-code::docs-site/.docusaurus/registry.js::1::unused-file
# Issue #86
# [WARNING] dead-code - docs-site/.docusaurus/registry.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/.docusaurus/registry.js:1
# Code: export default {
Acknowledge: 

ID: dead-code::docs-site/.docusaurus/routes.js::1::unused-file
# Issue #87
# [WARNING] dead-code - docs-site/.docusaurus/routes.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/.docusaurus/routes.js:1
# Code: import React from 'react';
Acknowledge: 

ID: dead-code::docs-site/sidebars.js::1::unused-file
# Issue #88
# [WARNING] dead-code - docs-site/sidebars.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/sidebars.js:1
# Code: // @ts-check
Acknowledge: 

ID: dead-code::docs-site/src/clientModules/eagerImages.js::1::unused-file
# Issue #89
# [WARNING] dead-code - docs-site/src/clientModules/eagerImages.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/src/clientModules/eagerImages.js:1
# Code: // Docusaurus's MDX <img> component auto-sets loading="lazy" on every doc
Acknowledge: 

ID: dead-code::public/i18n.js::1::unused-file
# Issue #90
# [WARNING] dead-code - public/i18n.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   public/i18n.js:1
# Code: // Ignite web UI translations — static UI chrome only (buttons, labels,
Acknowledge: 

ID: dead-code::vscode-extension/src/progress.ts::1::unused-file
# Issue #91
# [WARNING] dead-code - vscode-extension/src/progress.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/progress.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/panels/findingsTree.ts::1::unused-file
# Issue #92
# [WARNING] dead-code - vscode-extension/src/panels/findingsTree.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/panels/findingsTree.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/panels/reportPanel.ts::1::unused-file
# Issue #93
# [WARNING] dead-code - vscode-extension/src/panels/reportPanel.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/panels/reportPanel.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/panels/toolsStatusTree.ts::1::unused-file
# Issue #94
# [WARNING] dead-code - vscode-extension/src/panels/toolsStatusTree.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/panels/toolsStatusTree.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/extension.ts::1::unused-file
# Issue #95
# [WARNING] dead-code - vscode-extension/src/extension.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/extension.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/diagnostics.ts::1::unused-file
# Issue #96
# [WARNING] dead-code - vscode-extension/src/diagnostics.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/diagnostics.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/prePushHook.ts::1::unused-file
# Issue #97
# [WARNING] dead-code - vscode-extension/src/prePushHook.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/prePushHook.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::rust/crates/override-engine/src/collect.rs::1::low-maintainability
# Issue #98
# [WARNING] complexity-health - Maintainability Index 25/100 — below the 40 threshold (complexity 108 over 539 lines of code).
#   rust/crates/override-engine/src/collect.rs:1
# Code: //! Turns every check's raw findings (`RawFinding`/`CodeqlFinding`/license
Acknowledge: 

ID: complexity-health::rust/crates/staging/src/lib.rs::1::low-maintainability
# Issue #99
# [WARNING] complexity-health - Maintainability Index 32/100 — below the 40 threshold (complexity 47 over 491 lines of code).
#   rust/crates/staging/src/lib.rs:1
# Code: //! Faithful port of `server.js`'s staging/extraction layer — the guarded
Acknowledge: 

ID: complexity-health::rust/crates/image-provenance/src/lib.rs::1::low-maintainability
# Issue #100
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 29 over 280 lines of code).
#   rust/crates/image-provenance/src/lib.rs:1
# Code: //! Sigstore/cosign keyless-signature verification for external Dockerfile
Acknowledge: 

ID: complexity-health::rust/crates/auto-fix/src/lib.rs::1::low-maintainability
# Issue #101
# [WARNING] complexity-health - Maintainability Index 38/100 — below the 40 threshold (complexity 27 over 374 lines of code).
#   rust/crates/auto-fix/src/lib.rs:1
# Code: //! Faithful port of `lib/auto-fix.js` — turns a subset of dead-code and
Acknowledge: 

ID: complexity-health::rust/crates/codeql-cross-file/src/lib.rs::1::low-maintainability
# Issue #102
# [WARNING] complexity-health - Maintainability Index 24/100 — below the 40 threshold (complexity 79 over 860 lines of code).
#   rust/crates/codeql-cross-file/src/lib.rs:1
# Code: //! Cross-file static analysis via the CodeQL CLI. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/secret-verifier/src/lib.rs::1::low-maintainability
# Issue #103
# [WARNING] complexity-health - Maintainability Index 27/100 — below the 40 threshold (complexity 60 over 827 lines of code).
#   rust/crates/secret-verifier/src/lib.rs:1
# Code: //! Active, read-only credential verification — the GHAS-parity gap noted
Acknowledge: 

ID: complexity-health::rust/crates/config/src/lib.rs::1::low-maintainability
# Issue #104
# [WARNING] complexity-health - Maintainability Index 14/100 — below the 40 threshold (complexity 191 over 1421 lines of code).
#   rust/crates/config/src/lib.rs:1
# Code: //! Ignite configuration — config.json < environment variables. Faithful
Acknowledge: 

ID: complexity-health::rust/crates/pipeline-core/src/lib.rs::1::low-maintainability
# Issue #105
# [WARNING] complexity-health - Maintainability Index 37/100 — below the 40 threshold (complexity 31 over 355 lines of code).
#   rust/crates/pipeline-core/src/lib.rs:1
# Code: //! Pipeline orchestration helpers shared across `validate-all`/`onboard`/
Acknowledge: 

ID: complexity-health::rust/crates/iac-security/src/lib.rs::1::low-maintainability
# Issue #106
# [WARNING] complexity-health - Maintainability Index 31/100 — below the 40 threshold (complexity 57 over 475 lines of code).
#   rust/crates/iac-security/src/lib.rs:1
# Code: //! IaC/container misconfiguration scan (Dockerfiles, Terraform, Kubernetes
Acknowledge: 

ID: complexity-health::rust/crates/secrets/src/lib.rs::1::low-maintainability
# Issue #107
# [WARNING] complexity-health - Maintainability Index 26/100 — below the 40 threshold (complexity 58 over 983 lines of code).
#   rust/crates/secrets/src/lib.rs:1
# Code: //! Regex-based secret scan + optional gitleaks supplement. Faithful port
Acknowledge: 

ID: complexity-health::rust/crates/auto-fix-pr/src/lib.rs::1::low-maintainability
# Issue #108
# [WARNING] complexity-health - Maintainability Index 20/100 — below the 40 threshold (complexity 96 over 1344 lines of code).
#   rust/crates/auto-fix-pr/src/lib.rs:1
# Code: //! Auto-fix PR bot — the Dependabot-parity gap `scheduled-rescan` leaves
Acknowledge: 

ID: complexity-health::rust/crates/deps-dev-client/src/lib.rs::1::low-maintainability
# Issue #109
# [WARNING] complexity-health - Maintainability Index 28/100 — below the 40 threshold (complexity 63 over 623 lines of code).
#   rust/crates/deps-dev-client/src/lib.rs:1
# Code: //! deps.dev API client + npm-registry/unpkg license fallbacks, shared by
Acknowledge: 

ID: complexity-health::rust/crates/mcp-server/src/main.rs::1::low-maintainability
# Issue #110
# [WARNING] complexity-health - Maintainability Index 34/100 — below the 40 threshold (complexity 26 over 784 lines of code).
#   rust/crates/mcp-server/src/main.rs:1
# Code: //! MCP server exposing the company AI validation guidelines, faithful
Acknowledge: 

ID: complexity-health::rust/crates/boundaries/src/lib.rs::1::low-maintainability
# Issue #111
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 26 over 325 lines of code).
#   rust/crates/boundaries/src/lib.rs:1
# Code: //! Built-in architecture-boundary enforcement. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/studio-manifests/src/lib.rs::1::low-maintainability
# Issue #112
# [WARNING] complexity-health - Maintainability Index 25/100 — below the 40 threshold (complexity 99 over 619 lines of code).
#   rust/crates/studio-manifests/src/lib.rs:1
# Code: //! The manifest parsers server.js's dependency license/vulnerability
Acknowledge: 

ID: complexity-health::rust/crates/server/src/auth.rs::1::low-maintainability
# Issue #113
# [WARNING] complexity-health - Maintainability Index 37/100 — below the 40 threshold (complexity 28 over 433 lines of code).
#   rust/crates/server/src/auth.rs:1
# Code: //! Session/API-key auth route wiring — Rust port of `auth.js`'s Express
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/studio.rs::1::low-maintainability
# Issue #114
# [WARNING] complexity-health - Maintainability Index 28/100 — below the 40 threshold (complexity 47 over 969 lines of code).
#   rust/crates/server/src/routes/studio.rs:1
# Code: //! `/api/pipeline/:jobId/studio/*` — faithful (partial) port of
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/pipeline_onboard.rs::1::low-maintainability
# Issue #115
# [WARNING] complexity-health - Maintainability Index 31/100 — below the 40 threshold (complexity 54 over 502 lines of code).
#   rust/crates/server/src/routes/pipeline_onboard.rs:1
# Code: //! POST /api/pipeline/onboard — faithful port of routes/pipeline-onboard.js:
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/pipeline_interactive/run.rs::1::low-maintainability
# Issue #116
# [WARNING] complexity-health - Maintainability Index 23/100 — below the 40 threshold (complexity 101 over 745 lines of code).
#   rust/crates/server/src/routes/pipeline_interactive/run.rs:1
# Code: //! The actual phase-by-phase driver for `POST /api/pipeline` — split
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/pipeline_interactive.rs::1::low-maintainability
# Issue #117
# [WARNING] complexity-health - Maintainability Index 29/100 — below the 40 threshold (complexity 44 over 925 lines of code).
#   rust/crates/server/src/routes/pipeline_interactive.rs:1
# Code: //! POST /api/pipeline — faithful port of routes/pipeline-interactive.js:
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/github_pr_status.rs::1::low-maintainability
# Issue #118
# [WARNING] complexity-health - Maintainability Index 33/100 — below the 40 threshold (complexity 57 over 337 lines of code).
#   rust/crates/server/src/routes/github_pr_status.rs:1
# Code: //! POST /api/pipeline/:jobId/github-check — faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/pipeline_validate.rs::1::low-maintainability
# Issue #119
# [WARNING] complexity-health - Maintainability Index 26/100 — below the 40 threshold (complexity 70 over 750 lines of code).
#   rust/crates/server/src/routes/pipeline_validate.rs:1
# Code: //! POST /api/pipeline/validate-all — faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/github-api/src/lib.rs::1::low-maintainability
# Issue #120
# [WARNING] complexity-health - Maintainability Index 28/100 — below the 40 threshold (complexity 53 over 751 lines of code).
#   rust/crates/github-api/src/lib.rs:1
# Code: //! Faithful port of `lib/github-api.js` — GitHub API access without
Acknowledge: 

ID: complexity-health::rust/crates/fs-utils/src/lib.rs::1::low-maintainability
# Issue #121
# [WARNING] complexity-health - Maintainability Index 30/100 — below the 40 threshold (complexity 56 over 570 lines of code).
#   rust/crates/fs-utils/src/lib.rs:1
# Code: //! Pure filesystem/content helpers shared by Ignite's checks — file
Acknowledge: 

ID: complexity-health::rust/crates/fix-pr/src/lib.rs::1::low-maintainability
# Issue #122
# [WARNING] complexity-health - Maintainability Index 24/100 — below the 40 threshold (complexity 71 over 1093 lines of code).
#   rust/crates/fix-pr/src/lib.rs:1
# Code: //! Bulk "fix all findings" PR generator — the scan-wide counterpart to
Acknowledge: 

ID: complexity-health::rust/crates/cli/src/acknowledgments.rs::1::low-maintainability
# Issue #123
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 24 over 344 lines of code).
#   rust/crates/cli/src/acknowledgments.rs:1
# Code: //! Parsing and regeneration of `.ignite/acknowledgments.md` — ported from
Acknowledge: 

ID: complexity-health::rust/crates/llm-deep-scan/src/lib.rs::1::low-maintainability
# Issue #124
# [WARNING] complexity-health - Maintainability Index 28/100 — below the 40 threshold (complexity 66 over 602 lines of code).
#   rust/crates/llm-deep-scan/src/lib.rs:1
# Code: //! Local LLM (Ollama/llama.cpp-compatible, or OpenAI) security/quality
Acknowledge: 

ID: complexity-health::rust/crates/dependency-license-scan/src/lib.rs::1::low-maintainability
# Issue #125
# [WARNING] complexity-health - Maintainability Index 16/100 — below the 40 threshold (complexity 131 over 1664 lines of code).
#   rust/crates/dependency-license-scan/src/lib.rs:1
# Code: //! Dependency license/vulnerability scan orchestrators. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/llm-client/src/lib.rs::1::low-maintainability
# Issue #126
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 20 over 438 lines of code).
#   rust/crates/llm-client/src/lib.rs:1
# Code: //! Shared local-LLM/OpenAI chat-completions client. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/phase4-orchestrator/src/lib.rs::1::low-maintainability
# Issue #127
# [WARNING] complexity-health - Maintainability Index 27/100 — below the 40 threshold (complexity 46 over 1185 lines of code).
#   rust/crates/phase4-orchestrator/src/lib.rs:1
# Code: //! Phase 4 check orchestrator. Faithful port of server.js's
Acknowledge: 

ID: complexity-health::rust/crates/package-hallucination/src/lib.rs::1::low-maintainability
# Issue #128
# [WARNING] complexity-health - Maintainability Index 36/100 — below the 40 threshold (complexity 33 over 365 lines of code).
#   rust/crates/package-hallucination/src/lib.rs:1
# Code: //! AI package-hallucination / slopsquat detection. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/gha-security/src/lib.rs::1::low-maintainability
# Issue #129
# [WARNING] complexity-health - Maintainability Index 38/100 — below the 40 threshold (complexity 22 over 436 lines of code).
#   rust/crates/gha-security/src/lib.rs:1
# Code: //! GitHub Actions workflow security scan via zizmor (Trail of Bits'
Acknowledge: 

ID: complexity-health::rust/crates/tool-runner/src/lib.rs::1::low-maintainability
# Issue #130
# [WARNING] complexity-health - Maintainability Index 27/100 — below the 40 threshold (complexity 67 over 640 lines of code).
#   rust/crates/tool-runner/src/lib.rs:1
# Code: //! External-tool process execution + the sanitizers that guard it — every
Acknowledge: 

ID: complexity-health::rust/crates/complexity-health/src/lib.rs::1::low-maintainability
# Issue #131
# [WARNING] complexity-health - Maintainability Index 31/100 — below the 40 threshold (complexity 51 over 543 lines of code).
#   rust/crates/complexity-health/src/lib.rs:1
# Code: //! Built-in complexity/maintainability health scan. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/container-image-vulnerabilities/src/lib.rs::1::low-maintainability
# Issue #132
# [WARNING] complexity-health - Maintainability Index 38/100 — below the 40 threshold (complexity 30 over 316 lines of code).
#   rust/crates/container-image-vulnerabilities/src/lib.rs:1
# Code: //! Builds every discovered Dockerfile and runs `trivy image` against the
Acknowledge: 

ID: complexity-health::rust/crates/module-graph/src/lib.rs::1::low-maintainability
# Issue #133
# [WARNING] complexity-health - Maintainability Index 31/100 — below the 40 threshold (complexity 54 over 474 lines of code).
#   rust/crates/module-graph/src/lib.rs:1
# Code: //! Lightweight JS/TS module graph: parses import/require/export statements
Acknowledge: 

ID: complexity-health::rust/crates/enforce-gate-branch-protection/src/lib.rs::1::low-maintainability
# Issue #134
# [WARNING] complexity-health - Maintainability Index 35/100 — below the 40 threshold (complexity 23 over 676 lines of code).
#   rust/crates/enforce-gate-branch-protection/src/lib.rs:1
# Code: //! `enforce-gate-branch-protection <org/repo> [<org/repo>...] [--apply]` —
Acknowledge: 

ID: complexity-health::rust/crates/report-vulnerability/src/main.rs::1::low-maintainability
# Issue #135
# [WARNING] complexity-health - Maintainability Index 34/100 — below the 40 threshold (complexity 30 over 568 lines of code).
#   rust/crates/report-vulnerability/src/main.rs:1
# Code: //! `report-vulnerability <org/repo> --summary <str> --severity <level>
Acknowledge: 

ID: complexity-health::rust/crates/pii-dataflow/src/lib.rs::1::low-maintainability
# Issue #136
# [WARNING] complexity-health - Maintainability Index 33/100 — below the 40 threshold (complexity 47 over 403 lines of code).
#   rust/crates/pii-dataflow/src/lib.rs:1
# Code: //! Sensitive data-flow (PII/GDPR) SAST via Bearer. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/governance-ci/src/lib.rs::1::low-maintainability
# Issue #137
# [WARNING] complexity-health - Maintainability Index 38/100 — below the 40 threshold (complexity 33 over 290 lines of code).
#   rust/crates/governance-ci/src/lib.rs:1
# Code: //! Phase 5: org governance CI, run locally via `act`. Faithful port of
Acknowledge: 

ID: complexity-health::public/i18n.js::1::low-maintainability
# Issue #138
# [WARNING] complexity-health - Maintainability Index 30/100 — below the 40 threshold (complexity 31 over 1246 lines of code).
#   public/i18n.js:1
# Code: // Ignite web UI translations — static UI chrome only (buttons, labels,
Acknowledge: 

ID: complexity-health::vscode-extension/src/panels/findingsTree.ts::1::low-maintainability
# Issue #139
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 41 over 179 lines of code).
#   vscode-extension/src/panels/findingsTree.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::vscode-extension/src/panels/reportPanel.ts::1::low-maintainability
# Issue #140
# [WARNING] complexity-health - Maintainability Index 34/100 — below the 40 threshold (complexity 56 over 273 lines of code).
#   vscode-extension/src/panels/reportPanel.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::vscode-extension/src/extension.ts::1::low-maintainability
# Issue #141
# [WARNING] complexity-health - Maintainability Index 27/100 — below the 40 threshold (complexity 91 over 488 lines of code).
#   vscode-extension/src/extension.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::vscode-extension/src/api.ts::1::low-maintainability
# Issue #142
# [WARNING] complexity-health - Maintainability Index 30/100 — below the 40 threshold (complexity 68 over 397 lines of code).
#   vscode-extension/src/api.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::vscode-extension/src/reviewFile.ts::1::low-maintainability
# Issue #143
# [WARNING] complexity-health - Maintainability Index 37/100 — below the 40 threshold (complexity 46 over 226 lines of code).
#   vscode-extension/src/reviewFile.ts:1
# Code: import * as fs from 'fs/promises';
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::7aa895fb
# Issue #144
# [WARNING] css-dead-code - CSS class ".infima" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::3239fc7e
# Issue #145
# [WARNING] css-dead-code - CSS class ".theme-common" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::8b93d74d
# Issue #146
# [WARNING] css-dead-code - CSS class ".theme-classic" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::7246118d
# Issue #147
# [WARNING] css-dead-code - CSS class ".core" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::c98c98f5
# Issue #148
# [WARNING] css-dead-code - CSS class ".plugin-debug" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::ae40698e
# Issue #149
# [WARNING] css-dead-code - CSS class ".theme-mermaid" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::f63f75e9
# Issue #150
# [WARNING] css-dead-code - CSS class ".theme-live-codeblock" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::59b3bc2f
# Issue #151
# [WARNING] css-dead-code - CSS class ".theme-search-algolia" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::9cc5937b
# Issue #152
# [WARNING] css-dead-code - CSS class ".docsearch" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::32::unused-css-class
# Issue #153
# [WARNING] css-dead-code - CSS class ".markdown" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:32
# Code: .markdown {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::88::unused-css-class
# Issue #154
# [WARNING] css-dead-code - CSS class ".theme-admonition" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:88
# Code: .theme-admonition {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::95::unused-css-class
# Issue #155
# [WARNING] css-dead-code - CSS class ".theme-doc-markdown" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:95
# Code: .theme-doc-markdown table {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::173::unused-css-class
# Issue #156
# [WARNING] css-dead-code - CSS class ".heroShot" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:173
# Code: .heroShot {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::193::unused-css-class
# Issue #157
# [WARNING] css-dead-code - CSS class ".phaseDiagram" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:193
# Code: .phaseDiagram {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::209::unused-css-class
# Issue #158
# [WARNING] css-dead-code - CSS class ".phase-link" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:209
# Code: .phase-link {
Acknowledge: 

ID: css-dead-code::docs/assets/css/style.scss::4::unused-css-class
# Issue #159
# [WARNING] css-dead-code - CSS class ".theme" is declared in docs/assets/css/style.scss but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs/assets/css/style.scss:4
# Code: @import "{{ site.theme }}";
Acknowledge: 

ID: css-dead-code::docs/assets/css/style.scss::6::unused-css-class
# Issue #160
# [WARNING] css-dead-code - CSS class ".main-content" is declared in docs/assets/css/style.scss but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs/assets/css/style.scss:6
# Code: // Cayman's default .main-content is a fixed ~64rem column with no overflow
Acknowledge: 

ID: dependency-vulnerability::rust/crates/server/Cargo.toml::60::jsonwebtoken::GHSA-h395-gr6q-cpjc
# Issue #161
# [WARNING] dependency-vulnerability - jsonwebtoken@9.3.1 — GHSA-h395-gr6q-cpjc: jsonwebtoken has Type Confusion that leads to potential authorization bypass (CVE-2026-25537) (CVSS 0)
#   rust/crates/server/Cargo.toml:60
# Code: jsonwebtoken = "9"
Acknowledge: 

ID: code-duplication::rust/crates/db-store/src/overrides.rs::198::8f3adedb
# Issue #162
# [WARNING] code-duplication - 19-line duplicate block, also found in rust/crates/db-store/src/projects.rs:285-303.
#   rust/crates/db-store/src/overrides.rs:198
# Code: stmt.query_map(params![project_id], |row| {
Acknowledge: 

ID: code-duplication::rust/crates/mcp-server/src/main.rs::620
# Issue #163
# [WARNING] code-duplication - 36-line duplicate block, also found in rust/crates/mcp-server/src/main.rs:772-806.
#   rust/crates/mcp-server/src/main.rs:620
# Code: let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/audit_log.rs::105::6f31953d
# Issue #164
# [WARNING] code-duplication - 35-line duplicate block, also found in rust/crates/server/src/routes/custom_secret_patterns.rs:162-196.
#   rust/crates/server/src/routes/audit_log.rs:105
# Code: Router::new().route("/api/audit-log", get(list)).route("/api/audit-log/verify", get(verify))
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/effectivate.rs::298
# Issue #165
# [WARNING] code-duplication - 16-line duplicate block, also found in rust/crates/server/src/routes/pipeline_interactive.rs:403-418.
#   rust/crates/server/src/routes/effectivate.rs:298
# Code: fn build_state() -> (Arc<AppState>, tempfile::TempDir) {
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/studio.rs::336::9cf59e7c
# Issue #166
# [WARNING] code-duplication - 19-line duplicate block, also found in rust/crates/server/src/routes/studio.rs:439-457.
#   rust/crates/server/src/routes/studio.rs:336
# Code: async fn codeql_run(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/studio.rs::336::189d9a56
# Issue #167
# [WARNING] code-duplication - 22-line duplicate block, also found in rust/crates/server/src/routes/studio.rs:554-574.
#   rust/crates/server/src/routes/studio.rs:336
# Code: async fn codeql_run(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/e3ecd6a8-1a46-43fa-beb0-39fe1d989ff9-api-validation/CLAUDE.md:markdown::72
# Issue #168
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/e3ecd6a8-1a46-43fa-beb0-39fe1d989ff9-api-validation/CLAUDE.md:markdown:72-95.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/e3ecd6a8-1a46-43fa-beb0-39fe1d989ff9-api-validation/CLAUDE.md:markdown:72
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/e3ecd6a8-1a46-43fa-beb0-39fe1d989ff9-api-validation/README.md:markdown::110
# Issue #169
# [WARNING] code-duplication - 28-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/e3ecd6a8-1a46-43fa-beb0-39fe1d989ff9-api-validation/README.md:markdown:427-502.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/e3ecd6a8-1a46-43fa-beb0-39fe1d989ff9-api-validation/README.md:markdown:110
Acknowledge: 
