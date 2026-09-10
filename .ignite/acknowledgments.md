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

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::731
# Issue #9
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:731
# Code: let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
Acknowledge: Fake AWS access key literal used as a fixture file inside a review-gate integration test (uploaded as a zip so the secret scanner flags a real blocking finding to pause the run for review), not a real credential. (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1397 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1401 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::676 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::711 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::712 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::793
# Issue #10
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:793
# Code: let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
Acknowledge: Same fake AWS access key literal as the entry above, reused in a second review-gate integration test in this same file, not a real credential. (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1453 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1457 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::732 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::773 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::774 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::875
# Issue #11
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:875
# Code: let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
Acknowledge: Same fake AWS access key literal as the entries above, reused in a third review-gate integration test in this same file, not a real credential. (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1523 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1527 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::802 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::854 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::855 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::920
# Issue #12
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:920
# Code: let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
Acknowledge: Same fake AWS access key literal as the entries above, reused in a fourth review-gate integration test in this same file, not a real credential. (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1567 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::1571 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::846 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::898 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/pipeline_interactive.rs::899 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/routes/custom_secret_patterns.rs::193
# Issue #13
# [ERROR] secret - Hardcoded generic-api-key
#   rust/crates/server/src/routes/custom_secret_patterns.rs:193
# Code: let req = Request::post("/api/secret-patterns/test").header("content-type", "application/json").body(Body::from(r#"{"regex":"sk_live_[a-z0-9]+","sample":"key: sk_live_abc123"}"#)).unwrap();
Acknowledge: Fabricated Stripe-format sample string used as request-body input to the custom-secret-pattern playground's own unit test (test_pattern_route_reports_matches_without_persisting_anything) - the whole point of this endpoint is to test a regex against sample text, so a plausible-looking fake match is expected input, not a real credential.

ID: secret::docs-site/docs/ci-integration.md::457
# Issue #14
# [ERROR] secret - Hardcoded token
#   docs-site/docs/ci-integration.md:457
# Code: -d '{"regex": "acme_live_[a-zA-Z0-9]{24}", "sample": "token: acme_live_abcdef0123456789ghijklmn"}'
Acknowledge: Fictional pattern/sample pair in a docs-site example curl command demonstrating the custom-secret-pattern playground endpoint - "acme_live_..." isn't a real vendor token format, and the sample string is fabricated for the example, not a real credential. (auto-carried-forward from secret::docs-site/docs/ci-integration.md::384 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::710
# Issue #15
# [ERROR] secret - Hardcoded api_key
#   rust/crates/secrets/src/lib.rs:710
# Code: fs::write(root.join("config.js"), "const api_key = 'sk-proj-abcdefghijklmnop';\n").unwrap();
Acknowledge: Fake API key literal used as test input for run_gitleaks_history_scan_no_ops_without_a_git_directory (verifies the history scan is a no-op with no .git directory) - not a real credential, same fixture literal already acknowledged elsewhere in this file for the same reason. (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::579 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::694 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::814
# Issue #16
# [ERROR] secret - Hardcoded connection-string credential
#   rust/crates/secrets/src/lib.rs:814
# Code: "DATABASE_URL = \"postgresql://testuser:not-a-real-pw@x@example.com:5432/testdb\"\n",
Acknowledge: Test-fixture connection string for flags_a_password_embedded_in_a_connection_string - example.com is IANA/RFC 2606-reserved for documentation and the password is labeled a placeholder outright in the surrounding comment, not a real credential. (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::683 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::798 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::943
# Issue #17
# [ERROR] secret - Hardcoded stripe-access-token
#   rust/crates/secrets/src/lib.rs:943
# Code: let matches = test_pattern_against_sample(r"sk_live_[a-zA-Z0-9]{16,}", "key one: sk_live_abcdef0123456789, key two: sk_live_zzzzzz9999999999").unwrap();
Acknowledge: Fabricated Stripe-format sample text (test_pattern_against_sample_finds_all_matches) verifying the custom-secret-pattern regex tester finds every match in a sample, not a real credential - same fixture literal flagged again at the two assert_eq! lines immediately below for the same reason. (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::927 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::945
# Issue #18
# [ERROR] secret - Hardcoded stripe-access-token
#   rust/crates/secrets/src/lib.rs:945
# Code: assert_eq!(matches[0].matched_text, "sk_live_abcdef0123456789");
Acknowledge: Same fabricated Stripe-format fixture literal as the entry above, asserted as the expected match text in the same test - not a real credential. (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::929 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::946
# Issue #19
# [ERROR] secret - Hardcoded stripe-access-token
#   rust/crates/secrets/src/lib.rs:946
# Code: assert_eq!(matches[1].matched_text, "sk_live_zzzzzz9999999999");
Acknowledge: Same fabricated Stripe-format fixture literal as the two entries above, asserted as the second expected match text in the same test - not a real credential. (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::930 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::1010
# Issue #20
# [ERROR] secret - Hardcoded gcp-api-key
#   rust/crates/phase4-orchestrator/src/lib.rs:1010
# Code: fs::write(root.join("config.js"), format!("export const environment = {{ firebase: {{ apiKey: '{}' }} }};\n", "AIzaSyDGX6-TCqxyZv3m1avbP8-hZxD2-Zb6bXk")).unwrap();
Acknowledge: Fake GCP/Firebase web API key literal used as test input to verify the built-in secret scanner (SECRET_RE) doesn't false-positive on a `firebase: { apiKey: ... }` nested property shape, not a real credential. (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::868 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::875 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::881 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::942 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::974 - pure line-number drift, flagged code unchanged)

ID: codeql-sast::public/index.html::967::js/xss-through-dom
# Issue #21
# [ERROR] codeql-sast - DOM text is reinterpreted as HTML without escaping meta-characters.
#   public/index.html:967
# Code: document.querySelectorAll('[data-i18n-html]').forEach((el) => { el.innerHTML = t(el.getAttribute('data-i18n-html')); });
Acknowledge: Narrowed replacement for the previously-acknowledged finding at the old [data-i18n] innerHTML call (now textContent - see the applyStaticTranslations doc comment above it). Only elements explicitly opted in via data-i18n-html still use innerHTML, for the handful of translation keys whose copy deliberately carries inline markup (bold spans in upload.dropSubtitle, a line break in footer.note, etc). t()'s only inputs remain (1) the fixed attribute-name string 'data-i18n-html' read off the DOM and (2) a lookup into window.IGNITE_I18N.translations, entirely defined by public/i18n.js - a file committed to this repo and only ever edited by a developer/operator, never populated from user input, the network, or any request parameter. No untrusted data reaches this call. (auto-carried-forward from codeql-sast::public/index.html::781::js/xss-through-dom - pure line-number drift, flagged code unchanged) (auto-carried-forward from codeql-sast::public/index.html::813::js/xss-through-dom - pure line-number drift, flagged code unchanged) (auto-carried-forward from codeql-sast::public/index.html::821::js/xss-through-dom - pure line-number drift, flagged code unchanged) (auto-carried-forward from codeql-sast::public/index.html::822::js/xss-through-dom - pure line-number drift, flagged code unchanged) (auto-carried-forward from codeql-sast::public/index.html::842::js/xss-through-dom - pure line-number drift, flagged code unchanged) (auto-carried-forward from codeql-sast::public/index.html::841::js/xss-through-dom - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::1129
# Issue #22
# [ERROR] secret - Hardcoded github-pat
#   rust/crates/phase4-orchestrator/src/lib.rs:1129
# Code: fs::write(root.join("config.js"), "headers.set(\"Authorization\", \"Bearer ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\");\n").unwrap();
Acknowledge: Fake GitHub PAT literal (high-entropy but never issued) used to verify gitleaks flags it as github-pat and that the off-by-default secret_verification path never appends a VERIFIED LIVE marker - not a real credential, never sent anywhere but api.github.com's own 401 rejection path in the sibling test below. (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1019 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1051 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1121 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::1164
# Issue #23
# [ERROR] secret - Hardcoded github-pat
#   rust/crates/phase4-orchestrator/src/lib.rs:1164
# Code: fs::write(root.join("config.js"), "headers.set(\"Authorization\", \"Bearer ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\");\n").unwrap();
Acknowledge: Same fake GitHub PAT fixture as the entry above, used in secret_verification_when_enabled_never_flags_a_fake_token_as_verified_live to confirm a live GitHub API 401 for this token is correctly reported as not-live - not a real credential. (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1054 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1086 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1156 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::1086
# Issue #24
# [ERROR] secret - Hardcoded gcp-api-key
#   rust/crates/phase4-orchestrator/src/lib.rs:1086
# Code: fs::write(root.join("config.js"), format!("export const apiKey = '{}';\n", "AIzaSyDGX6-TCqxyZv3m1avbP8-hZxD2-Zb6bXk")).unwrap();
Acknowledge: Fake GCP/Firebase web API key literal, same fixture value as the other AIzaSy... entry above, written to a scratch test repo to verify gitleaks-based secret detection - not a real credential. (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::976 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1008 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/phase4-orchestrator/src/lib.rs::1078 - pure line-number drift, flagged code unchanged)

ID: iac-security::Dockerfile::1::629a3996
# Issue #25
# [WARNING] iac-security - No HEALTHCHECK defined
#   Dockerfile:1
# Code: # Ignite, self-contained: the Rust server/CLI/MCP binaries plus every
Acknowledge: 

ID: iac-security::Dockerfile::1::5c411837
# Issue #26
# [WARNING] iac-security - Ensure that HEALTHCHECK instructions have been added to container images
#   Dockerfile:1
# Code: # Ignite, self-contained: the Rust server/CLI/MCP binaries plus every
Acknowledge: 

ID: iac-security::Dockerfile::127
# Issue #27
# [WARNING] iac-security - Pin versions in apt get install. Instead of `apt-get install <package>` use `apt-get install <package>=<version>`
#   Dockerfile:127
# Code: RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
Acknowledge: 

ID: iac-security::Dockerfile::149
# Issue #28
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:149
# Code: RUN if [ "$INSTALL_ORT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::158
# Issue #29
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:158
# Code: RUN if [ "$INSTALL_TRIVY" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::162
# Issue #30
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:162
# Code: RUN if [ "$INSTALL_CHECKOV" = "true" ]; then pipx install checkov --pip-args="--no-compile" && pipx ensurepath; fi
Acknowledge: 

ID: iac-security::Dockerfile::171
# Issue #31
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:171
# Code: RUN if [ "$INSTALL_GITLEAKS" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::177
# Issue #32
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:177
# Code: RUN if [ "$INSTALL_SYFT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::187
# Issue #33
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:187
# Code: RUN if [ "$INSTALL_SEMGREP" = "true" ]; then pipx install semgrep --pip-args="--no-compile" && pipx ensurepath; fi
Acknowledge: 

ID: iac-security::Dockerfile::188
# Issue #34
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:188
# Code: RUN if [ "$INSTALL_BEARER" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::212::09cd120f
# Issue #35
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:212
# Code: RUN if [ "$INSTALL_GUARDDOG" = "true" ] || [ "$INSTALL_LICENSEE" = "true" ] || [ "$INSTALL_COCOAPODS" = "true" ] || [ "$INSTALL_ORT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::212::bdfb7069
# Issue #36
# [WARNING] iac-security - Pin versions in apt get install. Instead of `apt-get install <package>` use `apt-get install <package>=<version>`
#   Dockerfile:212
# Code: RUN if [ "$INSTALL_GUARDDOG" = "true" ] || [ "$INSTALL_LICENSEE" = "true" ] || [ "$INSTALL_COCOAPODS" = "true" ] || [ "$INSTALL_ORT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::212::19c88dc5
# Issue #37
# [WARNING] iac-security - Pin versions in gem install. Instead of `gem install <gem>` use `gem install <gem>:<version>`
#   Dockerfile:212
# Code: RUN if [ "$INSTALL_GUARDDOG" = "true" ] || [ "$INSTALL_LICENSEE" = "true" ] || [ "$INSTALL_COCOAPODS" = "true" ] || [ "$INSTALL_ORT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::225
# Issue #38
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:225
# Code: RUN if [ "$INSTALL_PICKLESCAN" = "true" ]; then pipx install picklescan --pip-args="--no-compile" && pipx ensurepath; fi
Acknowledge: 

ID: iac-security::Dockerfile::226
# Issue #39
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:226
# Code: RUN if [ "$INSTALL_ZIZMOR" = "true" ]; then pipx install zizmor --pip-args="--no-compile" && pipx ensurepath; fi
Acknowledge: 

ID: iac-security::Dockerfile::227
# Issue #40
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:227
# Code: RUN if [ "$INSTALL_OASDIFF" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::255
# Issue #41
# [WARNING] iac-security - Pin versions in npm. Instead of `npm install <package>` use `npm install <package>@<version>`
#   Dockerfile:255
# Code: RUN if [ "$INSTALL_JSCPD" = "true" ]; then npm install -g jscpd; fi
Acknowledge: 

ID: iac-security::Dockerfile::256::2ddec02b
# Issue #42
# [WARNING] iac-security - Multiple consecutive `RUN` instructions. Consider consolidation.
#   Dockerfile:256
# Code: RUN if [ "$INSTALL_SPECTRAL" = "true" ]; then npm install -g @stoplight/spectral-cli; fi
Acknowledge: 

ID: iac-security::Dockerfile::256::37ad8298
# Issue #43
# [WARNING] iac-security - Pin versions in npm. Instead of `npm install <package>` use `npm install <package>@<version>`
#   Dockerfile:256
# Code: RUN if [ "$INSTALL_SPECTRAL" = "true" ]; then npm install -g @stoplight/spectral-cli; fi
Acknowledge: 

ID: iac-security::Dockerfile::277
# Issue #44
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:277
# Code: RUN if [ "$INSTALL_ACT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::291
# Issue #45
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:291
# Code: RUN if [ "$INSTALL_DOCKER_CLI" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::343
# Issue #46
# [WARNING] iac-security - Non-numeric user-id may not be resolvable by host system
#   Dockerfile:343
# Code: USER ignite
Acknowledge: 

ID: gha-security::.github/workflows/deploy-docs.yml::24
# Issue #47
# [WARNING] gha-security - credential persistence through GitHub Actions artifacts (uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4)
#   .github/workflows/deploy-docs.yml:24
# Code: - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
Acknowledge: 

ID: image-provenance::Dockerfile::19
# Issue #48
# [WARNING] image-provenance - Base image "rust:1-bookworm" has no verifiable Sigstore/cosign signature — supply-chain provenance can't be confirmed.
#   Dockerfile:19
# Code: FROM rust:1-bookworm AS rust-builder
Acknowledge: 

ID: image-provenance::Dockerfile::30
# Issue #49
# [WARNING] image-provenance - Base image "node:24-bookworm-slim" has no verifiable Sigstore/cosign signature — supply-chain provenance can't be confirmed.
#   Dockerfile:30
# Code: FROM node:24-bookworm-slim
Acknowledge: 

ID: pii-dataflow::e2e/helpers.js::75
# Issue #50
# [WARNING] pii-dataflow - Missing secure HTTP server configuration
#   e2e/helpers.js:75
# Code: const server = http.createServer((req, res) => {
Acknowledge: 

ID: pii-dataflow::vscode-extension/src/reviewFile.ts::82
# Issue #51
# [WARNING] pii-dataflow - Unsanitized dynamic input in file path
#   vscode-extension/src/reviewFile.ts:82
# Code: return await fs.readFile(p, 'utf8');
Acknowledge: 

ID: pii-dataflow::vscode-extension/src/reviewFile.ts::143
# Issue #52
# [WARNING] pii-dataflow - Unsanitized dynamic input in file path
#   vscode-extension/src/reviewFile.ts:143
# Code: await fs.mkdir(path.dirname(filePath), { recursive: true });
Acknowledge: 

ID: pii-dataflow::vscode-extension/src/reviewFile.ts::144
# Issue #53
# [WARNING] pii-dataflow - Unsanitized dynamic input in file path
#   vscode-extension/src/reviewFile.ts:144
# Code: await fs.writeFile(filePath, HEADER + numberBlocks([...remainingExisting, ...newBlocks]).join('\n\n') + '\n');
Acknowledge: 

ID: pii-dataflow::vscode-extension/src/reviewFile.ts::188
# Issue #54
# [WARNING] pii-dataflow - Unsanitized dynamic input in file path
#   vscode-extension/src/reviewFile.ts:188
# Code: await fs.mkdir(path.dirname(filePath), { recursive: true });
Acknowledge: 

ID: pii-dataflow::vscode-extension/src/reviewFile.ts::189
# Issue #55
# [WARNING] pii-dataflow - Unsanitized dynamic input in file path
#   vscode-extension/src/reviewFile.ts:189
# Code: await fs.writeFile(filePath, lines.join('\n'));
Acknowledge: 

ID: pii-dataflow::vscode-extension/src/reviewFile.ts::228
# Issue #56
# [WARNING] pii-dataflow - Unsanitized dynamic input in file path
#   vscode-extension/src/reviewFile.ts:228
# Code: await fs.mkdir(path.dirname(filePath), { recursive: true });
Acknowledge: 

ID: pii-dataflow::vscode-extension/src/reviewFile.ts::229
# Issue #57
# [WARNING] pii-dataflow - Unsanitized dynamic input in file path
#   vscode-extension/src/reviewFile.ts:229
# Code: await fs.writeFile(filePath, HEADER + numberBlocks(all).join('\n\n') + '\n');
Acknowledge: 

ID: pii-dataflow::vscode-extension/src/panels/findingsTree.ts::145
# Issue #58
# [WARNING] pii-dataflow - Unsanitized dynamic input in file path
#   vscode-extension/src/panels/findingsTree.ts:145
# Code: const abs = path.isAbsolute(issue.file) ? issue.file : path.join(this.workspaceRoot, issue.file);
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1
# Issue #59
# [WARNING] code-duplication - 2468-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T23-32-33Z/findings.md:markdown:1-2468.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::7
# Issue #60
# [WARNING] code-duplication - 2624-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:19-2600.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:7
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::19
# Issue #61
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:19-39.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:19
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::37::e20b25c4
# Issue #62
# [WARNING] code-duplication - 347-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:49-395.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:37
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::37::93c3d1a1
# Issue #63
# [WARNING] code-duplication - 23-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:61-83.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:37
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::37::cb951a52
# Issue #64
# [WARNING] code-duplication - 1336-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:61-1404.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:37
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::157::54f92e36
# Issue #65
# [WARNING] code-duplication - 1774-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:193-1966.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:157
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::157::c6d7a1bf
# Issue #66
# [WARNING] code-duplication - 2159-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:205-2370.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:157
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::385
# Issue #67
# [WARNING] code-duplication - 34-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:390-423.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:385
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::413
# Issue #68
# [WARNING] code-duplication - 279-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:425-703.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:413
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::693
# Issue #69
# [WARNING] code-duplication - 34-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:698-731.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:693
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::721
# Issue #70
# [WARNING] code-duplication - 27-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:733-759.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:721
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::749
# Issue #71
# [WARNING] code-duplication - 34-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:754-787.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:749
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::777
# Issue #72
# [WARNING] code-duplication - 27-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:789-815.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:777
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::805
# Issue #73
# [WARNING] code-duplication - 34-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:810-843.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:805
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::833
# Issue #74
# [WARNING] code-duplication - 475-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:845-1319.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:833
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1302
# Issue #75
# [WARNING] code-duplication - 2491-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:1321-3708.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1302
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1349
# Issue #76
# [WARNING] code-duplication - 1282-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:1404-2636.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1349
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1449
# Issue #77
# [WARNING] code-duplication - 160-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1617-1776.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1449
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1601::94c4af40
# Issue #78
# [WARNING] code-duplication - 22-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2364-2385.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1601
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1601::451fb03b
# Issue #79
# [WARNING] code-duplication - 22-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:1959-1980.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1601
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1769
# Issue #80
# [WARNING] code-duplication - 22-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1916-1937.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1769
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1862::018f7afc
# Issue #81
# [WARNING] code-duplication - 62-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1932-1993.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1862
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1862::a13b8903
# Issue #82
# [WARNING] code-duplication - 209-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:2372-2580.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1862
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1988
# Issue #83
# [WARNING] code-duplication - 583-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:1975-2505.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1988
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2468
# Issue #84
# [WARNING] code-duplication - 447-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T23-32-33Z/findings.md:markdown:2498-2944.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2468
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2493
# Issue #85
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:2578-2601.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2493
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2518::e744c309
# Issue #86
# [WARNING] code-duplication - 53-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2535-2587.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2518
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2518::1e87b444
# Issue #87
# [WARNING] code-duplication - 165-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:2610-2773.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2518
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2560
# Issue #88
# [WARNING] code-duplication - 591-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:2602-3166.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2560
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2567
# Issue #89
# [WARNING] code-duplication - 96-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2591-2686.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2567
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2676
# Issue #90
# [WARNING] code-duplication - 65-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2712-2776.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2676
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2778
# Issue #91
# [WARNING] code-duplication - 23-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2832-2854.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2778
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2808::b99ed2dd
# Issue #92
# [WARNING] code-duplication - 59-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2874-2932.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2808
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2808::6910e70c
# Issue #93
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:2973-3001.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2808
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2862
# Issue #94
# [WARNING] code-duplication - 53-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2934-2986.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2862
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3078::948c84a8
# Issue #95
# [WARNING] code-duplication - 209-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T23-32-33Z/findings.md:markdown:2940-3148.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3078
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3078::a02630b6
# Issue #96
# [WARNING] code-duplication - 35-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2994-3028.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3078
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3108::82c913a0
# Issue #97
# [WARNING] code-duplication - 71-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3036-3106.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3108
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3108::3f562f1d
# Issue #98
# [WARNING] code-duplication - 71-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3123-3193.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3108
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3180
# Issue #99
# [WARNING] code-duplication - 41-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3126-3166.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3180
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3264
# Issue #100
# [WARNING] code-duplication - 23-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3240-3262.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3264
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3408
# Issue #101
# [WARNING] code-duplication - 124-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T23-32-33Z/findings.md:markdown:3144-3267.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3408
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3414
# Issue #102
# [WARNING] code-duplication - 41-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3210-3250.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3414
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3420::bb055c16
# Issue #103
# [WARNING] code-duplication - 196-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3324-3507.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3420
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3420::7d162edd
# Issue #104
# [WARNING] code-duplication - 277-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3411-3702.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3420
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3420::595c5c6d
# Issue #105
# [WARNING] code-duplication - 114-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3447-3559.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3420
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3555
# Issue #106
# [WARNING] code-duplication - 31-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T23-32-33Z/findings.md:markdown:3267-3297.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3555
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3589::91f64ef6
# Issue #107
# [WARNING] code-duplication - 63-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T23-32-33Z/findings.md:markdown:3295-3357.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3589
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3589::47abdb9e
# Issue #108
# [WARNING] code-duplication - 75-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3403-3477.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3589
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3601
# Issue #109
# [WARNING] code-duplication - 23-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3583-3605.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3601
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3649
# Issue #110
# [WARNING] code-duplication - 205-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T23-32-33Z/findings.md:markdown:3379-3583.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3649
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3687
# Issue #111
# [WARNING] code-duplication - 134-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3511-3644.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3687
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3746::f7e92375
# Issue #112
# [WARNING] code-duplication - 40-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3756-3795.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3746
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3746::d4151c1b
# Issue #113
# [WARNING] code-duplication - 40-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3849-3888.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3746
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3748
# Issue #114
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3894-3917.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3748
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3822
# Issue #115
# [WARNING] code-duplication - 32-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3646-3677.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3822
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::1::099301af
# Issue #116
# [WARNING] code-duplication - 3341-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T14-44-39Z/findings.md:markdown:1-3341.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::1::8c034bd9
# Issue #117
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:1-21.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::1::99ad6cc2
# Issue #118
# [WARNING] code-duplication - 3491-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T11-06-25Z/findings.md:markdown:1-3496.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::1::5d249bcc
# Issue #119
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:1-21.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::1::fb4daa70
# Issue #120
# [WARNING] code-duplication - 27-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:1-27.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::1::69d3e027
# Issue #121
# [WARNING] code-duplication - 27-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:1-27.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::3162
# Issue #122
# [WARNING] code-duplication - 53-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3270-3322.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3162
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::3373::83152f8c
# Issue #123
# [WARNING] code-duplication - 117-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T14-44-39Z/findings.md:markdown:3397-3513.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3373
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::3373::7e9608e6
# Issue #124
# [WARNING] code-duplication - 35-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3535-3569.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3373
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::3489::52b0db03
# Issue #125
# [WARNING] code-duplication - 189-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T14-44-39Z/findings.md:markdown:3513-3701.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3489
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::3489::7816542b
# Issue #126
# [WARNING] code-duplication - 32-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3675-3706.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3489
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::3489::b2dc8180
# Issue #127
# [WARNING] code-duplication - 32-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3768-3799.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3489
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::3489::6459b8f7
# Issue #128
# [WARNING] code-duplication - 86-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3804-3889.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3489
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::3645
# Issue #129
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3844-3868.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3645
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T14-44-39Z/findings.md:markdown::3336
# Issue #130
# [WARNING] code-duplication - 174-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3567-3750.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T14-44-39Z/findings.md:markdown:3336
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T14-44-39Z/findings.md:markdown::3499
# Issue #131
# [WARNING] code-duplication - 203-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T11-06-25Z/findings.md:markdown:3506-3708.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-21T14-44-39Z/findings.md:markdown:3499
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T21-40-37Z/findings.md:markdown::1
# Issue #132
# [WARNING] code-duplication - 27-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-23-19Z/findings.md:markdown:1-27.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T21-40-37Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::6
# Issue #133
# [WARNING] code-duplication - 76-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:6-81.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:6
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::25
# Issue #134
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:37-57.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:25
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::55
# Issue #135
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:55-83.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:55
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::65
# Issue #136
# [WARNING] code-duplication - 141-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:65-205.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:65
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::2493
# Issue #137
# [WARNING] code-duplication - 63-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:2493-2555.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2493
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::2570
# Issue #138
# [WARNING] code-duplication - 51-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:2645-2695.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2570
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::2669
# Issue #139
# [WARNING] code-duplication - 61-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:2669-2729.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2669
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::2700
# Issue #140
# [WARNING] code-duplication - 77-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:2775-2851.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2700
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::2772
# Issue #141
# [WARNING] code-duplication - 269-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:2853-3121.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2772
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::2778
# Issue #142
# [WARNING] code-duplication - 35-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:2859-2893.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2778
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::2850
# Issue #143
# [WARNING] code-duplication - 23-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:2949-2971.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2850
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::2928
# Issue #144
# [WARNING] code-duplication - 71-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3027-3097.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2928
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3089
# Issue #145
# [WARNING] code-duplication - 55-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:3089-3143.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3089
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3120
# Issue #146
# [WARNING] code-duplication - 155-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3207-3361.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3120
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3174
# Issue #147
# [WARNING] code-duplication - 23-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3285-3307.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3174
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3228
# Issue #148
# [WARNING] code-duplication - 95-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3351-3445.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3228
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3304
# Issue #149
# [WARNING] code-duplication - 41-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:3304-3344.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3304
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3491
# Issue #150
# [WARNING] code-duplication - 65-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:3491-3555.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3491
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3551
# Issue #151
# [WARNING] code-duplication - 50-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:3551-3600.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3551
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3587
# Issue #152
# [WARNING] code-duplication - 101-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:3587-3687.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3587
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3629
# Issue #153
# [WARNING] code-duplication - 17-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3722-3738.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3629
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3692
# Issue #154
# [WARNING] code-duplication - 83-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:3692-3774.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3692
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3781
# Issue #155
# [WARNING] code-duplication - 80-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:3781-3860.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3781
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3797
# Issue #156
# [WARNING] code-duplication - 72-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3890-3961.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3797
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3806
# Issue #157
# [WARNING] code-duplication - 63-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3942-4004.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3806
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3854
# Issue #158
# [WARNING] code-duplication - 1157-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:3854-5012.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3854
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3876::c1500dbb
# Issue #159
# [WARNING] code-duplication - 159-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3969-4127.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3876
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3876::27f81e00
# Issue #160
# [WARNING] code-duplication - 149-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:4012-4160.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3876
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4032
# Issue #161
# [WARNING] code-duplication - 225-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4131-4355.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4032
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4250
# Issue #162
# [WARNING] code-duplication - 31-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4355-4385.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4250
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4274
# Issue #163
# [WARNING] code-duplication - 73-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4391-4463.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4274
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4320
# Issue #164
# [WARNING] code-duplication - 39-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:4498-4536.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4320
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4346
# Issue #165
# [WARNING] code-duplication - 37-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4463-4499.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4346
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4360
# Issue #166
# [WARNING] code-duplication - 59-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:4538-4596.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4360
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4382
# Issue #167
# [WARNING] code-duplication - 37-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4499-4535.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4382
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4418::544449f3
# Issue #168
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4535-4559.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4418
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4418::976c5d87
# Issue #169
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:4596-4614.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4418
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4450
# Issue #170
# [WARNING] code-duplication - 17-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4567-4583.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4450
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4478
# Issue #171
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4595-4619.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4478
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4520
# Issue #172
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4637-4661.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4520
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown::25
# Issue #173
# [WARNING] code-duplication - 33-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:31-63.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:25
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown::2757
# Issue #174
# [WARNING] code-duplication - 101-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:2757-2857.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:2757
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown::3117
# Issue #175
# [WARNING] code-duplication - 35-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3135-3169.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3117
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown::3189
# Issue #176
# [WARNING] code-duplication - 53-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3207-3259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3189
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown::3718
# Issue #177
# [WARNING] code-duplication - 39-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3754-3792.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3718
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown::4125
# Issue #178
# [WARNING] code-duplication - 315-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:4174-4488.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4125
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown::4553
# Issue #179
# [WARNING] code-duplication - 43-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:4620-4662.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4553
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown::4631
# Issue #180
# [WARNING] code-duplication - 37-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:4698-4734.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4631
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::1::69697f44
# Issue #181
# [WARNING] code-duplication - 65-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-24-27Z/findings.md:markdown:1-65.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::1::c1318da4
# Issue #182
# [WARNING] code-duplication - 2039-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-00-07Z/findings.md:markdown:1-2077.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::1::82d46751
# Issue #183
# [WARNING] code-duplication - 81-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-02-22Z/findings.md:markdown:1-81.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::1::854b21b2
# Issue #184
# [WARNING] code-duplication - 97-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-20-15Z/findings.md:markdown:1-97.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::1::c8cab452
# Issue #185
# [WARNING] code-duplication - 97-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-22-58Z/findings.md:markdown:1-97.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::3
# Issue #186
# [WARNING] code-duplication - 67-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-28-25Z/findings.md:markdown:5-71.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:3
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::73
# Issue #187
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-02-22Z/findings.md:markdown:73-97.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:73
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::79::d8d9a2f6
# Issue #188
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-28-25Z/findings.md:markdown:81-99.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:79
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::79::f558f804
# Issue #189
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-01-37Z/findings.md:markdown:81-105.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:79
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-24-27Z/findings.md:markdown::79
# Issue #190
# [WARNING] code-duplication - 1257-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-14-12Z/findings.md:markdown:81-1337.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-24-27Z/findings.md:markdown:79
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-24-27Z/findings.md:markdown::1613
# Issue #191
# [WARNING] code-duplication - 383-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:1626-2008.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T13-24-27Z/findings.md:markdown:1613
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-03-21Z/findings.md:markdown::1::56e482e4
# Issue #192
# [WARNING] code-duplication - 1239-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-21-30Z/findings.md:markdown:1-1239.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-03-21Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-03-21Z/findings.md:markdown::1::336503d2
# Issue #193
# [WARNING] code-duplication - 1829-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-26-54Z/findings.md:markdown:1-1825.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-03-21Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-03-21Z/findings.md:markdown::3
# Issue #194
# [WARNING] code-duplication - 1825-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-34-18Z/findings.md:markdown:5-1821.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-03-21Z/findings.md:markdown:3
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-28-25Z/findings.md:markdown::1::febff752
# Issue #195
# [WARNING] code-duplication - 71-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-01-37Z/findings.md:markdown:1-71.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-28-25Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-28-25Z/findings.md:markdown::1::056a9a83
# Issue #196
# [WARNING] code-duplication - 83-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-14-12Z/findings.md:markdown:1-83.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-28-25Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-34-18Z/findings.md:markdown::1::ee9afd0d
# Issue #197
# [WARNING] code-duplication - 1821-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-40-55Z/findings.md:markdown:1-1821.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-34-18Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-34-18Z/findings.md:markdown::1::e992c94a
# Issue #198
# [WARNING] code-duplication - 1821-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-07-21Z/findings.md:markdown:1-1821.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T14-34-18Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown::5::1c5585a8
# Issue #199
# [WARNING] code-duplication - 73-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-47-42Z/findings.md:markdown:5-77.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown::5::4f7a8a6d
# Issue #200
# [WARNING] code-duplication - 3291-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T18-00-32Z/findings.md:markdown:5-3295.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown::5::925fbae5
# Issue #201
# [WARNING] code-duplication - 64-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T18-46-14Z/findings.md:markdown:5-68.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown::5::cfd867a4
# Issue #202
# [WARNING] code-duplication - 3859-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T20-46-36Z/findings.md:markdown:5-3863.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown::5::66c1e1c3
# Issue #203
# [WARNING] code-duplication - 52-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T21-26-22Z/findings.md:markdown:5-56.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown::86
# Issue #204
# [WARNING] code-duplication - 3778-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-47-42Z/findings.md:markdown:86-3863.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown:86
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown::3305
# Issue #205
# [WARNING] code-duplication - 559-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T18-00-32Z/findings.md:markdown:3305-3863.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown:3305
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown::3419
# Issue #206
# [WARNING] code-duplication - 445-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T18-46-14Z/findings.md:markdown:3419-3863.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown:3419
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-47-42Z/findings.md:markdown::79
# Issue #207
# [WARNING] code-duplication - 3291-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T18-46-14Z/findings.md:markdown:79-3369.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-30T15-47-42Z/findings.md:markdown:79
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-37-40Z/findings.md:markdown::5::d932df99
# Issue #208
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:5-33.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-37-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-37-40Z/findings.md:markdown::5::80329924
# Issue #209
# [WARNING] code-duplication - 17-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T19-39-48Z/findings.md:markdown:5-21.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-37-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-37-40Z/findings.md:markdown::5::81f84b36
# Issue #210
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T19-40-39Z/findings.md:markdown:5-23.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-37-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::23::caaf1156
# Issue #211
# [WARNING] code-duplication - 1175-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T19-07-01Z/findings.md:markdown:23-1197.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:23
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::23::dcc8d85c
# Issue #212
# [WARNING] code-duplication - 1463-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T19-40-39Z/findings.md:markdown:23-1485.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:23
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::30
# Issue #213
# [WARNING] code-duplication - 1120-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T21-05-59Z/findings.md:markdown:30-1149.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:30
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::1177
# Issue #214
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T21-05-59Z/findings.md:markdown:1177-1197.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:1177
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::1203
# Issue #215
# [WARNING] code-duplication - 97-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T19-07-01Z/findings.md:markdown:1203-1299.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:1203
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::1209
# Issue #216
# [WARNING] code-duplication - 91-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T21-05-59Z/findings.md:markdown:1209-1299.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:1209
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::1305
# Issue #217
# [WARNING] code-duplication - 365-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T19-07-01Z/findings.md:markdown:1305-1669.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:1305
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::1437
# Issue #218
# [WARNING] code-duplication - 85-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T21-05-59Z/findings.md:markdown:1437-1521.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:1437
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::1485
# Issue #219
# [WARNING] code-duplication - 185-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T19-40-39Z/findings.md:markdown:1485-1669.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:1485
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::1521
# Issue #220
# [WARNING] code-duplication - 149-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T21-05-59Z/findings.md:markdown:1521-1669.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:1521
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T19-07-01Z/findings.md:markdown::1299
# Issue #221
# [WARNING] code-duplication - 139-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T21-05-59Z/findings.md:markdown:1299-1437.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T19-07-01Z/findings.md:markdown:1299
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T19-40-39Z/findings.md:markdown::16
# Issue #222
# [WARNING] code-duplication - 1146-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T19-53-42Z/findings.md:markdown:16-1161.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T19-40-39Z/findings.md:markdown:16
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T19-53-42Z/findings.md:markdown::5
# Issue #223
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T21-05-59Z/findings.md:markdown:5-28.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-08-31T19-53-42Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T21-55-27Z/findings.md:markdown::23
# Issue #224
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown:26-54.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T21-55-27Z/findings.md:markdown:23
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T21-55-27Z/findings.md:markdown::48
# Issue #225
# [WARNING] code-duplication - 118-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-15-12Z/findings.md:markdown:51-168.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T21-55-27Z/findings.md:markdown:48
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-15-12Z/findings.md:markdown::1
# Issue #226
# [WARNING] code-duplication - 40-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown:1-40.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-15-12Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-15-12Z/findings.md:markdown::12
# Issue #227
# [WARNING] code-duplication - 47-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-01-23Z/findings.md:markdown:11-57.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-15-12Z/findings.md:markdown:12
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown::44
# Issue #228
# [WARNING] code-duplication - 31-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-49-45Z/findings.md:markdown:44-74.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown:44
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown::51
# Issue #229
# [WARNING] code-duplication - 2258-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T00-40-33Z/findings.md:markdown:51-2347.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown:51
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown::3286::6d73dbf2
# Issue #230
# [WARNING] code-duplication - 524-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-44-54Z/findings.md:markdown:3286-3809.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown:3286
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown::3286::af0db44b
# Issue #231
# [WARNING] code-duplication - 232-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:3286-3517.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown:3286
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown::3517
# Issue #232
# [WARNING] code-duplication - 293-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:3517-3809.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown:3517
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::ed1cfb9d
# Issue #233
# [WARNING] code-duplication - 2295-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown:5-2299.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::52b19dbb
# Issue #234
# [WARNING] code-duplication - 2304-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T00-22-33Z/findings.md:markdown:5-2347.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::2a890a48
# Issue #235
# [WARNING] code-duplication - 50-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T00-40-33Z/findings.md:markdown:5-54.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::157ec8e8
# Issue #236
# [WARNING] code-duplication - 38-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown:5-42.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::5c78d7dc
# Issue #237
# [WARNING] code-duplication - 68-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown:5-65.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::2f4c01b1
# Issue #238
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-48-30Z/findings.md:markdown:5-33.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::235641fe
# Issue #239
# [WARNING] code-duplication - 40-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-49-45Z/findings.md:markdown:5-44.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::b8a17b81
# Issue #240
# [WARNING] code-duplication - 2295-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T16-46-55Z/findings.md:markdown:5-2323.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::96fada65
# Issue #241
# [WARNING] code-duplication - 2295-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T18-46-03Z/findings.md:markdown:5-2323.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::b2646d35
# Issue #242
# [WARNING] code-duplication - 45-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T23-23-37Z/findings.md:markdown:5-49.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::545a5cce
# Issue #243
# [WARNING] code-duplication - 22-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:5-26.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::ec4a7adf
# Issue #244
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-04-18Z/findings.md:markdown:5-30.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::7e73b69d
# Issue #245
# [WARNING] code-duplication - 36-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown:5-40.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::abb2e450
# Issue #246
# [WARNING] code-duplication - 68-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T19-57-51Z/findings.md:markdown:5-68.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::f8f8f9be
# Issue #247
# [WARNING] code-duplication - 2301-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T19-59-28Z/findings.md:markdown:5-2358.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::627d3992
# Issue #248
# [WARNING] code-duplication - 2310-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T20-15-30Z/findings.md:markdown:5-2402.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::4d5c06df
# Issue #249
# [WARNING] code-duplication - 2313-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T20-34-08Z/findings.md:markdown:5-2406.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::2e7c908d
# Issue #250
# [WARNING] code-duplication - 2303-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T21-17-34Z/findings.md:markdown:5-2358.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::ef219ac9
# Issue #251
# [WARNING] code-duplication - 2303-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T21-22-02Z/findings.md:markdown:5-2358.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::09c72dad
# Issue #252
# [WARNING] code-duplication - 2199-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T22-02-49Z/findings.md:markdown:5-2198.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::5acec201
# Issue #253
# [WARNING] code-duplication - 43-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T22-05-02Z/findings.md:markdown:5-47.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::0d7f9ed9
# Issue #254
# [WARNING] code-duplication - 2199-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T22-47-20Z/findings.md:markdown:5-2198.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::ab6e305f
# Issue #255
# [WARNING] code-duplication - 2303-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T22-52-48Z/findings.md:markdown:5-2358.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::1bb865f8
# Issue #256
# [WARNING] code-duplication - 2313-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T23-36-56Z/findings.md:markdown:5-2406.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::c12918bb
# Issue #257
# [WARNING] code-duplication - 22-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown:5-26.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::36c424c6
# Issue #258
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:5-30.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::f5907ae2
# Issue #259
# [WARNING] code-duplication - 74-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:5-79.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::caf7126c
# Issue #260
# [WARNING] code-duplication - 80-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-44-53Z/findings.md:markdown:5-84.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::1bafb877
# Issue #261
# [WARNING] code-duplication - 76-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-49-22Z/findings.md:markdown:5-82.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::8f6a6549
# Issue #262
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown:5-28.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::2644316c
# Issue #263
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T10-39-34Z/findings.md:markdown:5-30.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::de70b0a5
# Issue #264
# [WARNING] code-duplication - 48-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T10-42-01Z/findings.md:markdown:5-54.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::a8d66058
# Issue #265
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:5-28.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::4a958956
# Issue #266
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown:5-30.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::8cfec830
# Issue #267
# [WARNING] code-duplication - 74-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T23-22-04Z/findings.md:markdown:5-82.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::e587d6a3
# Issue #268
# [WARNING] code-duplication - 2352-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T23-37-13Z/findings.md:markdown:5-2526.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown::3334::7688f886
# Issue #269
# [WARNING] code-duplication - 190-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T00-22-33Z/findings.md:markdown:3334-3523.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown:3334
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown::3334::a85ecd47
# Issue #270
# [WARNING] code-duplication - 190-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T00-40-33Z/findings.md:markdown:3334-3523.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown:3334
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown::3523::b4c5153a
# Issue #271
# [WARNING] code-duplication - 115-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T00-22-33Z/findings.md:markdown:3523-3637.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown:3523
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown::3523::e8e38c7f
# Issue #272
# [WARNING] code-duplication - 335-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T00-40-33Z/findings.md:markdown:3523-3857.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown:3523
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown::3637
# Issue #273
# [WARNING] code-duplication - 221-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T00-22-33Z/findings.md:markdown:3637-3857.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown:3637
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown::1188
# Issue #274
# [WARNING] code-duplication - 320-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:1181-1500.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown:1188
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown::1509
# Issue #275
# [WARNING] code-duplication - 145-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:1503-1647.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown:1509
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown::1655
# Issue #276
# [WARNING] code-duplication - 453-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:1650-2102.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown:1655
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown::2109
# Issue #277
# [WARNING] code-duplication - 82-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:2105-2186.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown:2109
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown::65
# Issue #278
# [WARNING] code-duplication - 1405-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T23-23-37Z/findings.md:markdown:67-1471.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown:65
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown::1471
# Issue #279
# [WARNING] code-duplication - 145-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T23-23-37Z/findings.md:markdown:1474-1618.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown:1471
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown::1617
# Issue #280
# [WARNING] code-duplication - 453-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T23-23-37Z/findings.md:markdown:1621-2073.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown:1617
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown::2071
# Issue #281
# [WARNING] code-duplication - 82-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T23-23-37Z/findings.md:markdown:2076-2157.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown:2071
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown::8
# Issue #282
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-04-18Z/findings.md:markdown:8-31.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:8
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown::32
# Issue #283
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown:33-51.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:32
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown::62
# Issue #284
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:63-86.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:62
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown::64
# Issue #285
# [WARNING] code-duplication - 460-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T19-57-51Z/findings.md:markdown:68-527.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:64
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown::538
# Issue #286
# [WARNING] code-duplication - 642-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T19-57-51Z/findings.md:markdown:544-1185.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:538
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown::1489
# Issue #287
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T19-57-51Z/findings.md:markdown:1496-1519.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:1489
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown::1636
# Issue #288
# [WARNING] code-duplication - 22-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T19-57-51Z/findings.md:markdown:1643-1664.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:1636
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown::2091
# Issue #289
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T19-57-51Z/findings.md:markdown:2098-2121.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:2091
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-04-18Z/findings.md:markdown::80
# Issue #290
# [WARNING] code-duplication - 22-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:77-98.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-04-18Z/findings.md:markdown:80
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown::65
# Issue #291
# [WARNING] code-duplication - 2300-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T22-05-02Z/findings.md:markdown:65-2358.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown:65
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown::76
# Issue #292
# [WARNING] code-duplication - 91-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T10-42-01Z/findings.md:markdown:76-166.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown:76
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown::190
# Issue #293
# [WARNING] code-duplication - 50-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T10-42-01Z/findings.md:markdown:190-239.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown:190
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown::703
# Issue #294
# [WARNING] code-duplication - 566-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T10-39-34Z/findings.md:markdown:727-1292.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown:703
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T19-57-51Z/findings.md:markdown::65
# Issue #295
# [WARNING] code-duplication - 22-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:65-86.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T19-57-51Z/findings.md:markdown:65
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T21-17-34Z/findings.md:markdown::3627
# Issue #296
# [WARNING] code-duplication - 627-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T21-22-02Z/findings.md:markdown:3627-4253.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-03T21-17-34Z/findings.md:markdown:3627
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown::8
# Issue #297
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:8-31.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown:8
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown::36
# Issue #298
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown:36-61.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown:36
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown::38
# Issue #299
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:40-65.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown:38
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown::65
# Issue #300
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-49-22Z/findings.md:markdown:68-86.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown:65
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::37
# Issue #301
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T10-42-01Z/findings.md:markdown:37-65.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:37
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::72
# Issue #302
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:72-97.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:72
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::88
# Issue #303
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:86-114.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:88
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::106
# Issue #304
# [WARNING] code-duplication - 65-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:106-170.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:106
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::160
# Issue #305
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:166-194.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:160
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::178
# Issue #306
# [WARNING] code-duplication - 113-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:178-290.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:178
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::280
# Issue #307
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:302-330.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:280
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::298
# Issue #308
# [WARNING] code-duplication - 215-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:298-512.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:298
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::502
# Issue #309
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:557-585.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:502
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::518
# Issue #310
# [WARNING] code-duplication - 73-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:518-590.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:518
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::580
# Issue #311
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:644-672.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:580
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::610
# Issue #312
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:675-703.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:610
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::628
# Issue #313
# [WARNING] code-duplication - 496-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:628-1123.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:628
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::1114
# Issue #314
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:1259-1287.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:1114
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::1144
# Issue #315
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:1290-1318.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:1144
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::1162
# Issue #316
# [WARNING] code-duplication - 87-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:1162-1248.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:1162
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::1302
# Issue #317
# [WARNING] code-duplication - 31-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:1302-1332.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:1302
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-49-22Z/findings.md:markdown::1
# Issue #318
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:1-21.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-49-22Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown::1240
# Issue #319
# [WARNING] code-duplication - 73-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown:1237-1309.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:1240
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown::1324
# Issue #320
# [WARNING] code-duplication - 183-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown:1321-1503.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:1324
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown::1498
# Issue #321
# [WARNING] code-duplication - 536-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown:1495-2028.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:1498
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown::12
# Issue #322
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T10-39-34Z/findings.md:markdown:12-31.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown:12
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown::47
# Issue #323
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T10-42-01Z/findings.md:markdown:49-66.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown:47
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown::12
# Issue #324
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown:12-31.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:12
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown::48::a18f4418
# Issue #325
# [WARNING] code-duplication - 44-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-42-43Z/findings.md:markdown:46-92.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:48
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown::48::6c901241
# Issue #326
# [WARNING] code-duplication - 51-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T11-30-14Z/findings.md:markdown:47-103.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:48
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown::50
# Issue #327
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown:54-79.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:50
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown::54::4bada2d4
# Issue #328
# [WARNING] code-duplication - 206-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T13-30-38Z/findings.md:markdown:58-259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:54
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown::54::ad86fa45
# Issue #329
# [WARNING] code-duplication - 206-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T16-03-24Z/findings.md:markdown:58-259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:54
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown::57
# Issue #330
# [WARNING] code-duplication - 42-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown:56-103.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:57
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown::84
# Issue #331
# [WARNING] code-duplication - 2278-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T23-22-19Z/findings.md:markdown:89-2366.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:84
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown::51::2cdb5420
# Issue #332
# [WARNING] code-duplication - 196-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:51-246.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown:51
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown::51::0fea1c04
# Issue #333
# [WARNING] code-duplication - 208-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown:51-259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown:51
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown::79
# Issue #334
# [WARNING] code-duplication - 224-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T22-04-15Z/findings.md:markdown:79-312.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown:79
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown::100
# Issue #335
# [WARNING] code-duplication - 154-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T23-17-25Z/findings.md:markdown:101-259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown:100
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T23-22-04Z/findings.md:markdown::1
# Issue #336
# [WARNING] code-duplication - 96-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T23-22-19Z/findings.md:markdown:1-96.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T23-22-04Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T23-22-04Z/findings.md:markdown::82
# Issue #337
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T22-03-13Z/findings.md:markdown:81-99.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T23-22-04Z/findings.md:markdown:82
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T23-22-19Z/findings.md:markdown::2353
# Issue #338
# [WARNING] code-duplication - 18-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T23-33-03Z/findings.md:markdown:2353-2368.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-04T23-22-19Z/findings.md:markdown:2353
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-42-43Z/findings.md:markdown::78
# Issue #339
# [WARNING] code-duplication - 17-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T22-03-13Z/findings.md:markdown:83-100.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-42-43Z/findings.md:markdown:78
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::5::28936ff1
# Issue #340
# [WARNING] code-duplication - 73-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T22-03-13Z/findings.md:markdown:5-77.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::5::17edc1cb
# Issue #341
# [WARNING] code-duplication - 75-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T22-04-15Z/findings.md:markdown:5-79.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::5::580d41c7
# Issue #342
# [WARNING] code-duplication - 78-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T23-12-57Z/findings.md:markdown:5-82.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::5::afe34213
# Issue #343
# [WARNING] code-duplication - 82-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T23-14-16Z/findings.md:markdown:5-86.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::5::5b3558aa
# Issue #344
# [WARNING] code-duplication - 260-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T23-44-50Z/findings.md:markdown:5-259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::1952
# Issue #345
# [WARNING] code-duplication - 59-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T22-04-15Z/findings.md:markdown:1952-2010.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:1952
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::2022
# Issue #346
# [WARNING] code-duplication - 176-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T22-04-15Z/findings.md:markdown:2022-2197.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:2022
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::2197
# Issue #347
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T22-04-15Z/findings.md:markdown:2197-2221.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:2197
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::2221
# Issue #348
# [WARNING] code-duplication - 103-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T22-04-15Z/findings.md:markdown:2221-2323.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:2221
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::2323
# Issue #349
# [WARNING] code-duplication - 73-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T22-04-15Z/findings.md:markdown:2323-2395.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:2323
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::2407
# Issue #350
# [WARNING] code-duplication - 191-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T22-04-15Z/findings.md:markdown:2407-2597.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:2407
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T23-12-57Z/findings.md:markdown::88
# Issue #351
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T23-14-16Z/findings.md:markdown:89-114.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T23-12-57Z/findings.md:markdown:88
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T23-14-16Z/findings.md:markdown::1
# Issue #352
# [WARNING] code-duplication - 92-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T23-17-25Z/findings.md:markdown:1-94.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T23-14-16Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T23-17-25Z/findings.md:markdown::2086
# Issue #353
# [WARNING] code-duplication - 18-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T13-30-38Z/findings.md:markdown:2086-2103.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T23-17-25Z/findings.md:markdown:2086
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T23-17-25Z/findings.md:markdown::2153
# Issue #354
# [WARNING] code-duplication - 88-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T13-30-38Z/findings.md:markdown:2153-2240.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-05T23-17-25Z/findings.md:markdown:2153
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown::5::7a3d967b
# Issue #355
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown:5-28.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown::5::1e677524
# Issue #356
# [WARNING] code-duplication - 103-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T15-03-49Z/findings.md:markdown:5-103.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown::5::fa2322f1
# Issue #357
# [WARNING] code-duplication - 52-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T15-18-02Z/findings.md:markdown:5-56.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown::5::f4bfcb65
# Issue #358
# [WARNING] code-duplication - 255-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T07-50-02Z/findings.md:markdown:5-259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown::5::0d75edcf
# Issue #359
# [WARNING] code-duplication - 255-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T07-53-01Z/findings.md:markdown:5-259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown::5::5fd52746
# Issue #360
# [WARNING] code-duplication - 103-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-03-22Z/findings.md:markdown:5-105.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown::5::75e273a6
# Issue #361
# [WARNING] code-duplication - 255-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-21-03Z/findings.md:markdown:5-259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown::1
# Issue #362
# [WARNING] code-duplication - 30-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T13-30-38Z/findings.md:markdown:1-30.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown::12
# Issue #363
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T13-30-38Z/findings.md:markdown:12-31.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown:12
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown::50
# Issue #364
# [WARNING] code-duplication - 54-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T15-04-38Z/findings.md:markdown:54-107.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown:50
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown::54
# Issue #365
# [WARNING] code-duplication - 50-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T15-18-02Z/findings.md:markdown:58-107.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown:54
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T15-03-49Z/findings.md:markdown::1
# Issue #366
# [WARNING] code-duplication - 58-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T15-04-38Z/findings.md:markdown:1-58.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T15-03-49Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T15-18-02Z/findings.md:markdown::1
# Issue #367
# [WARNING] code-duplication - 58-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T16-03-24Z/findings.md:markdown:1-58.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T15-18-02Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T16-03-24Z/findings.md:markdown::2086
# Issue #368
# [WARNING] code-duplication - 711-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T07-50-02Z/findings.md:markdown:2086-2796.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-06T16-03-24Z/findings.md:markdown:2086
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-03-22Z/findings.md:markdown::1
# Issue #369
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-05-27Z/findings.md:markdown:1-21.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-03-22Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-05-27Z/findings.md:markdown::2121
# Issue #370
# [WARNING] code-duplication - 718-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-21-03Z/findings.md:markdown:2121-2838.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-05-27Z/findings.md:markdown:2121
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-49-04Z/findings.md:markdown::17
# Issue #371
# [WARNING] code-duplication - 68-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-50-52Z/findings.md:markdown:19-86.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-49-04Z/findings.md:markdown:17
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-49-04Z/findings.md:markdown::56
# Issue #372
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T23-33-11Z/findings.md:markdown:58-82.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-49-04Z/findings.md:markdown:56
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-50-52Z/findings.md:markdown::5
# Issue #373
# [WARNING] code-duplication - 262-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-58-10Z/findings.md:markdown:5-266.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-50-52Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-50-52Z/findings.md:markdown::2123
# Issue #374
# [WARNING] code-duplication - 723-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-58-10Z/findings.md:markdown:2123-2845.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-07T23-50-52Z/findings.md:markdown:2123
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T21-18-48Z/findings.md:markdown::15
# Issue #375
# [WARNING] code-duplication - 80-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T21-25-45Z/findings.md:markdown:16-95.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T21-18-48Z/findings.md:markdown:15
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T21-18-48Z/findings.md:markdown::17
# Issue #376
# [WARNING] code-duplication - 82-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T21-20-34Z/findings.md:markdown:19-100.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T21-18-48Z/findings.md:markdown:17
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T21-20-34Z/findings.md:markdown::16
# Issue #377
# [WARNING] code-duplication - 109-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T21-26-39Z/findings.md:markdown:16-124.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T21-20-34Z/findings.md:markdown:16
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T21-30-06Z/findings.md:markdown::5
# Issue #378
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T23-04-57Z/findings.md:markdown:5-28.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T21-30-06Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T21-30-06Z/findings.md:markdown::65
# Issue #379
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown:65-93.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T21-30-06Z/findings.md:markdown:65
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T21-30-06Z/findings.md:markdown::68
# Issue #380
# [WARNING] code-duplication - 50-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T23-04-57Z/findings.md:markdown:62-111.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T21-30-06Z/findings.md:markdown:68
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T23-04-57Z/findings.md:markdown::60
# Issue #381
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-23-13Z/findings.md:markdown:59-82.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-08T23-04-57Z/findings.md:markdown:60
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-23-13Z/findings.md:markdown::23
# Issue #382
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown:26-44.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-23-13Z/findings.md:markdown:23
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-23-13Z/findings.md:markdown::130
# Issue #383
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-40-42Z/findings.md:markdown:145-168.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-23-13Z/findings.md:markdown:130
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown::5::be2a5fb0
# Issue #384
# [WARNING] code-duplication - 92-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-40-42Z/findings.md:markdown:5-96.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown::5::12435aa2
# Issue #385
# [WARNING] code-duplication - 318-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-42-59Z/findings.md:markdown:5-322.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown::5::119e47a6
# Issue #386
# [WARNING] code-duplication - 141-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-55-32Z/findings.md:markdown:5-145.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown::142
# Issue #387
# [WARNING] code-duplication - 181-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-55-32Z/findings.md:markdown:142-322.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown:142
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/CLAUDE.md:markdown::72
# Issue #388
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/CLAUDE.md:markdown:72-95.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/CLAUDE.md:markdown:72
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/README.md:markdown::110
# Issue #389
# [WARNING] code-duplication - 28-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/README.md:markdown:427-502.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/11f93cc4-37e0-464d-9230-aa4e8483e834-api-validation/README.md:markdown:110
Acknowledge: 

ID: code-duplication::public/index.html::2770
# Issue #390
# [WARNING] code-duplication - 20-line duplicate block, also found in public/index.html:5630-5649.
#   public/index.html:2770
# Code: list.innerHTML = sortedIssueIndices(issues).map((idx) => safeRenderIssueCard(issues[idx], idx, { interactive: issues[idx].status !== 'overridden' })).join('');
Acknowledge: 

ID: code-duplication::public/index.html::4598
# Issue #391
# [WARNING] code-duplication - 25-line duplicate block, also found in public/index.html:4764-4788.
#   public/index.html:4598
# Code: body: JSON.stringify({ language }),
Acknowledge: 

ID: code-duplication::rust/crates/db-store/src/overrides.rs::184::06755a3d
# Issue #392
# [WARNING] code-duplication - 18-line duplicate block, also found in rust/crates/db-store/src/overrides.rs:232-249.
#   rust/crates/db-store/src/overrides.rs:184
# Code: stmt.query_map(params![project_id], |row| {
Acknowledge: 

ID: code-duplication::rust/crates/db-store/src/overrides.rs::184::52f9dcb6
# Issue #393
# [WARNING] code-duplication - 20-line duplicate block, also found in rust/crates/db-store/src/projects.rs:219-238.
#   rust/crates/db-store/src/overrides.rs:184
# Code: stmt.query_map(params![project_id], |row| {
Acknowledge: 

ID: code-duplication::rust/crates/llm-client/src/lib.rs::232
# Issue #394
# [WARNING] code-duplication - 16-line duplicate block, also found in rust/crates/llm-client/src/lib.rs:301-316.
#   rust/crates/llm-client/src/lib.rs:232
# Code: return Err(LlmError::Timeout(timeout_ms));
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/code_scanning_webhook.rs::83::53b4ac79
# Issue #395
# [WARNING] code-duplication - 16-line duplicate block, also found in rust/crates/server/src/routes/repository_events_webhook.rs:88-103.
#   rust/crates/server/src/routes/code_scanning_webhook.rs:83
# Code: return err(StatusCode::NOT_FOUND, "Inbound code-scanning webhook is not configured.".to_string());
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/code_scanning_webhook.rs::83::727b9eba
# Issue #396
# [WARNING] code-duplication - 16-line duplicate block, also found in rust/crates/server/src/routes/secret_scanning_webhook.rs:101-116.
#   rust/crates/server/src/routes/code_scanning_webhook.rs:83
# Code: return err(StatusCode::NOT_FOUND, "Inbound code-scanning webhook is not configured.".to_string());
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/code_scanning_webhook.rs::184
# Issue #397
# [WARNING] code-duplication - 20-line duplicate block, also found in rust/crates/server/src/routes/secret_scanning_webhook.rs:226-245.
#   rust/crates/server/src/routes/code_scanning_webhook.rs:184
# Code: }
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/code_scanning_webhook.rs::186
# Issue #398
# [WARNING] code-duplication - 18-line duplicate block, also found in rust/crates/server/src/routes/push_protection_webhook.rs:190-207.
#   rust/crates/server/src/routes/code_scanning_webhook.rs:186
# Code: #[test]
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/compliance.rs::104
# Issue #399
# [WARNING] code-duplication - 36-line duplicate block, also found in rust/crates/server/src/routes/custom_secret_patterns.rs:155-190.
#   rust/crates/server/src/routes/compliance.rs:104
# Code: Router::new().route("/api/compliance/audit-pack", get(audit_pack))
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/effectivate.rs::306
# Issue #400
# [WARNING] code-duplication - 16-line duplicate block, also found in rust/crates/server/src/routes/pipeline_interactive.rs:394-409.
#   rust/crates/server/src/routes/effectivate.rs:306
# Code: fn build_state() -> (Arc<AppState>, tempfile::TempDir) {
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/history.rs::199
# Issue #401
# [WARNING] code-duplication - 16-line duplicate block, also found in rust/crates/server/src/routes/pipeline_interactive.rs:402-418.
#   rust/crates/server/src/routes/history.rs:199
# Code: review_gate: ReviewGate::default(),
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_interactive.rs::451
# Issue #402
# [WARNING] code-duplication - 30-line duplicate block, also found in rust/crates/server/src/routes/pipeline_interactive.rs:673-702.
#   rust/crates/server/src/routes/pipeline_interactive.rs:451
# Code: let zip = zip_bytes(&[("app.js", b"console.log(1);"), ("package.json", b"{\"name\":\"fixture\"}")]);
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_interactive.rs::452
# Issue #403
# [WARNING] code-duplication - 22-line duplicate block, also found in rust/crates/server/src/routes/pipeline_interactive.rs:877-898.
#   rust/crates/server/src/routes/pipeline_interactive.rs:452
# Code: let form = Form::new().text("org", "-bad-").text("repo", "widgets").text("dryRun", "true").part("archive", Part::bytes(zip).file_name("p.zip"));
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_onboard.rs::28
# Issue #404
# [WARNING] code-duplication - 59-line duplicate block, also found in rust/crates/server/src/routes/pipeline_validate.rs:31-89.
#   rust/crates/server/src/routes/pipeline_onboard.rs:28
# Code: static REPO_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,100}$").unwrap());
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_onboard.rs::87
# Issue #405
# [WARNING] code-duplication - 20-line duplicate block, also found in rust/crates/server/src/routes/pipeline_validate.rs:91-110.
#   rust/crates/server/src/routes/pipeline_onboard.rs:87
# Code: self.inner.lock().unwrap().project_id = Some(id);
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_onboard.rs::144
# Issue #406
# [WARNING] code-duplication - 16-line duplicate block, also found in rust/crates/server/src/routes/pipeline_validate.rs:153-167.
#   rust/crates/server/src/routes/pipeline_onboard.rs:144
# Code: let dry_run = body.get("dryRun").and_then(|v| v.as_bool()).unwrap_or(false);
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/push_protection_webhook.rs::183
# Issue #407
# [WARNING] code-duplication - 24-line duplicate block, also found in rust/crates/server/src/routes/repository_events_webhook.rs:166-189.
#   rust/crates/server/src/routes/push_protection_webhook.rs:183
# Code: Router::new().route("/api/webhooks/github/push-protection", post(push_protection_webhook))
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/push_protection_webhook.rs::260
# Issue #408
# [WARNING] code-duplication - 17-line duplicate block, also found in rust/crates/server/src/routes/repository_events_webhook.rs:190-206.
#   rust/crates/server/src/routes/push_protection_webhook.rs:260
# Code: async fn push_protection_webhook_404s_when_unconfigured() {
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/repository_events_webhook.rs::186
# Issue #409
# [WARNING] code-duplication - 21-line duplicate block, also found in rust/crates/server/src/routes/secret_scanning_webhook.rs:256-276.
#   rust/crates/server/src/routes/repository_events_webhook.rs:186
# Code: assert!(!verify_signature("wrongsecret", b"hello world", &format!("sha256={sig}")));
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/studio.rs::302::892d29bc
# Issue #410
# [WARNING] code-duplication - 19-line duplicate block, also found in rust/crates/server/src/routes/studio.rs:405-423.
#   rust/crates/server/src/routes/studio.rs:302
# Code: async fn codeql_run(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/studio.rs::302::963d18f2
# Issue #411
# [WARNING] code-duplication - 22-line duplicate block, also found in rust/crates/server/src/routes/studio.rs:511-531.
#   rust/crates/server/src/routes/studio.rs:302
# Code: async fn codeql_run(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
Acknowledge: 

ID: code-duplication::rust/server.log::243
# Issue #412
# [WARNING] code-duplication - 27-line duplicate block, also found in rust/server.log:666-692.
#   rust/server.log:243
# Code: [2m2026-09-06T14:02:39.483095Z[0m [32m INFO[0m [2mignite_tool_runner[0m[2m:[0m tool-runner: completed [3mtool[0m[2m=[0mpicklescan [3margs[0m[2m=[0m--help [3mcwd[0m[2m=[0m/var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/ [3mexit_code[0m[2m=[0m0 [3mstdout[0m[2m=[0musage: picklescan [-h] [-p PATH | -u URL | -hf HUGGINGFACE_MODEL] [-g]
Acknowledge: 

ID: code-duplication::rust/server.log::272
# Issue #413
# [WARNING] code-duplication - 16-line duplicate block, also found in rust/server.log:492-507.
#   rust/server.log:272
# Code: [2m2026-09-06T14:02:39.670680Z[0m [32m INFO[0m [2mignite_tool_runner[0m[2m:[0m tool-runner: completed [3mtool[0m[2m=[0mcosign [3margs[0m[2m=[0mversion [3mcwd[0m[2m=[0m/var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/ [3mexit_code[0m[2m=[0m0 [3mstdout[0m[2m=[0m______   ______        _______. __    _______ .__   __.
Acknowledge: 

ID: code-duplication::rust/server.log::311
# Issue #414
# [WARNING] code-duplication - 43-line duplicate block, also found in rust/server.log:704-746.
#   rust/server.log:311
# Code: [2m2026-09-06T14:02:41.055541Z[0m [32m INFO[0m [2mignite_tool_runner[0m[2m:[0m tool-runner: completed [3mtool[0m[2m=[0mcodeql [3margs[0m[2m=[0mversion --format=json [3mcwd[0m[2m=[0m/var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/ [3mexit_code[0m[2m=[0m0 [3mstdout[0m[2m=[0m{
Acknowledge: 

ID: code-structure::rust/crates/config/src/lib.rs::1
# Issue #415
# [WARNING] code-structure - rust/crates/config/src/lib.rs is 1388 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/config/src/lib.rs:1
# Code: //! Ignite configuration — config.json < environment variables. Faithful
Acknowledge: 

ID: code-structure::rust/crates/secrets/src/lib.rs::1
# Issue #416
# [WARNING] code-structure - rust/crates/secrets/src/lib.rs is 1018 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/secrets/src/lib.rs:1
# Code: //! Regex-based secret scan + optional gitleaks supplement. Faithful port
Acknowledge: 

ID: code-structure::rust/crates/auto-fix-pr/src/lib.rs::1
# Issue #417
# [WARNING] code-structure - rust/crates/auto-fix-pr/src/lib.rs is 1316 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/auto-fix-pr/src/lib.rs:1
# Code: //! Auto-fix PR bot — the Dependabot-parity gap `scheduled-rescan` leaves
Acknowledge: 

ID: code-structure::rust/crates/server/src/routes/studio.rs::1
# Issue #418
# [WARNING] code-structure - rust/crates/server/src/routes/studio.rs is 1045 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/server/src/routes/studio.rs:1
# Code: //! `/api/pipeline/:jobId/studio/*` — faithful (partial) port of
Acknowledge: 

ID: code-structure::rust/crates/fix-pr/src/lib.rs::1
# Issue #419
# [WARNING] code-structure - rust/crates/fix-pr/src/lib.rs is 1049 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/fix-pr/src/lib.rs:1
# Code: //! Bulk "fix all findings" PR generator — the scan-wide counterpart to
Acknowledge: 

ID: code-structure::rust/crates/dependency-license-scan/src/lib.rs::1
# Issue #420
# [WARNING] code-structure - rust/crates/dependency-license-scan/src/lib.rs is 1776 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/dependency-license-scan/src/lib.rs:1
# Code: //! Dependency license/vulnerability scan orchestrators. Faithful port of
Acknowledge: 

ID: code-structure::rust/crates/phase4-orchestrator/src/lib.rs::1
# Issue #421
# [WARNING] code-structure - rust/crates/phase4-orchestrator/src/lib.rs is 1218 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/phase4-orchestrator/src/lib.rs:1
# Code: //! Phase 4 check orchestrator. Faithful port of server.js's
Acknowledge: 

ID: code-structure::public/i18n.js::1
# Issue #422
# [WARNING] code-structure - public/i18n.js is 1280 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   public/i18n.js:1
# Code: // Ignite web UI translations — static UI chrome only (buttons, labels,
Acknowledge: 

ID: codeql-sast::public/index.html::1393::js/incomplete-html-attribute-sanitization
# Issue #423
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:1393
# Code: <button type="button" class="shrink-0 text-slate-300 hover:text-slate-600" aria-label="${escapeHtml(t('common.close'))}">
Acknowledge: 

ID: codeql-sast::public/index.html::4425::js/incomplete-html-attribute-sanitization
# Issue #424
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:4425
# Code: <textarea id="studioQueryText" class="w-full flex-1 min-h-[180px] font-mono text-[12px] leading-relaxed border border-slate-200 rounded-lg p-2" spellcheck="false" placeholder="import ${escapeHtml(defaultLanguage)}\n\nfrom ...\nselect ...">${escapeHtml(initialText)}</textarea>
Acknowledge: 

ID: codeql-sast::public/index.html::6247::js/incomplete-html-attribute-sanitization
# Issue #425
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:6247
# Code: select.innerHTML = orgs.map((o) => `<option value="${escapeHtml(o)}">${escapeHtml(o)}</option>`).join('');
Acknowledge: 

ID: codeql-sast::public/index.html::6336::js/incomplete-html-attribute-sanitization::e40e5cb3
# Issue #426
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:6336
# Code: <button type="button" class="hist-view-checks-report text-[11px] font-semibold text-slate-500 hover:underline shrink-0" data-id="${p.id}" data-org="${escapeHtml(p.org)}" data-repo="${escapeHtml(p.repo)}">${t('history.checksBtn')}</button>
Acknowledge: 

ID: codeql-sast::public/index.html::6337::js/incomplete-html-attribute-sanitization::e40e5cb3
# Issue #427
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:6337
# Code: ${p.issue_count > 0 ? `<button type="button" class="hist-open-studio text-[11px] font-semibold text-violet-600 hover:underline shrink-0" data-id="${p.id}" data-job-id="${escapeAttr(p.job_id || '')}" data-retained="${p.retained ? '1' : ''}" data-org="${escapeHtml(p.org)}" data-repo="${escapeHtml(p.repo)}" title="${escapeAttr(p.retained ? t('history.fullStudioTitle') : t('history.readOnlyStudioTitle'))}">${p.retained ? `${t('history.studioBtn')}${p.retained_tier === 'pruned' ? ` (${t('history.flaggedFilesOnly')})` : ` (${t('common.full')})`}` : t('history.studioBtn')}</button>` : ''}
Acknowledge: 

ID: codeql-sast::public/index.html::6338::js/incomplete-html-attribute-sanitization::e40e5cb3
# Issue #428
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:6338
# Code: ${p.issue_count > 0 ? `<button type="button" class="hist-view-issues text-[11px] font-semibold text-brand-600 hover:underline shrink-0" data-id="${p.id}" data-count="${p.issue_count}" data-org="${escapeHtml(p.org)}" data-repo="${escapeHtml(p.repo)}">${t('history.issueCount', { count: p.issue_count })}</button>` : ''}
Acknowledge: 

ID: codeql-sast::public/index.html::6959::js/incomplete-html-attribute-sanitization
# Issue #429
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:6959
# Code: ${p.repo_url ? `<a href="${escapeHtml(p.repo_url)}" target="_blank" rel="noopener" class="block text-[11px] font-mono text-brand-600 hover:text-brand-800 underline underline-offset-2 truncate mb-2">${escapeHtml(p.repo_url)}</a>` : ''}
Acknowledge: 

ID: dead-code::docs-site/.docusaurus/client-modules.js::1::unused-file
# Issue #430
# [WARNING] dead-code - docs-site/.docusaurus/client-modules.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/.docusaurus/client-modules.js:1
# Code: export default [
Acknowledge: 

ID: dead-code::docs-site/.docusaurus/registry.js::1::unused-file
# Issue #431
# [WARNING] dead-code - docs-site/.docusaurus/registry.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/.docusaurus/registry.js:1
# Code: export default {
Acknowledge: 

ID: dead-code::docs-site/.docusaurus/routes.js::1::unused-file
# Issue #432
# [WARNING] dead-code - docs-site/.docusaurus/routes.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/.docusaurus/routes.js:1
# Code: import React from 'react';
Acknowledge: 

ID: dead-code::docs-site/sidebars.js::1::unused-file
# Issue #433
# [WARNING] dead-code - docs-site/sidebars.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/sidebars.js:1
# Code: // @ts-check
Acknowledge: 

ID: dead-code::docs-site/src/clientModules/eagerImages.js::1::unused-file
# Issue #434
# [WARNING] dead-code - docs-site/src/clientModules/eagerImages.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/src/clientModules/eagerImages.js:1
# Code: // Docusaurus's MDX <img> component auto-sets loading="lazy" on every doc
Acknowledge: 

ID: dead-code::public/i18n.js::1::unused-file
# Issue #435
# [WARNING] dead-code - public/i18n.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   public/i18n.js:1
# Code: // Ignite web UI translations — static UI chrome only (buttons, labels,
Acknowledge: 

ID: dead-code::vscode-extension/src/progress.ts::1::unused-file
# Issue #436
# [WARNING] dead-code - vscode-extension/src/progress.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/progress.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/panels/findingsTree.ts::1::unused-file
# Issue #437
# [WARNING] dead-code - vscode-extension/src/panels/findingsTree.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/panels/findingsTree.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/panels/reportPanel.ts::1::unused-file
# Issue #438
# [WARNING] dead-code - vscode-extension/src/panels/reportPanel.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/panels/reportPanel.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/panels/toolsStatusTree.ts::1::unused-file
# Issue #439
# [WARNING] dead-code - vscode-extension/src/panels/toolsStatusTree.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/panels/toolsStatusTree.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/extension.ts::1::unused-file
# Issue #440
# [WARNING] dead-code - vscode-extension/src/extension.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/extension.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/diagnostics.ts::1::unused-file
# Issue #441
# [WARNING] dead-code - vscode-extension/src/diagnostics.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/diagnostics.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/prePushHook.ts::1::unused-file
# Issue #442
# [WARNING] dead-code - vscode-extension/src/prePushHook.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/prePushHook.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::rust/crates/db-store/src/overrides.rs::1::high-complexity
# Issue #443
# [WARNING] complexity-health - Cyclomatic complexity 113 (cognitive 528) — over the 20 threshold past which functions become difficult to test exhaustively. CRAP score 12882 (no coverage data ingested — treated as 0% for CRAP).
#   rust/crates/db-store/src/overrides.rs:1
# Code: //! Override audit log: who justified which issue, and why.
Acknowledge: 

ID: complexity-health::rust/crates/db-store/src/lib.rs::1::low-maintainability
# Issue #444
# [WARNING] complexity-health - Maintainability Index 35/100 — below the 40 threshold (complexity 22 over 770 lines of code).
#   rust/crates/db-store/src/lib.rs:1
# Code: //! SQLite-backed store — faithful port of `db-store.js`. Same schema
Acknowledge: 

ID: complexity-health::rust/crates/db-store/src/issues.rs::1::high-complexity
# Issue #445
# [WARNING] complexity-health - Cyclomatic complexity 68 (cognitive 318) — over the 20 threshold past which functions become difficult to test exhaustively. CRAP score 4692 (no coverage data ingested — treated as 0% for CRAP).
#   rust/crates/db-store/src/issues.rs:1
# Code: //! Flagged-issue persistence (the `issues` table) for one project's scan.
Acknowledge: 

ID: complexity-health::rust/crates/db-store/src/caches.rs::1::high-complexity
# Issue #446
# [WARNING] complexity-health - Cyclomatic complexity 60 (cognitive 235) — over the 20 threshold past which functions become difficult to test exhaustively. CRAP score 3660 (no coverage data ingested — treated as 0% for CRAP).
#   rust/crates/db-store/src/caches.rs:1
# Code: //! Per-file/manifest/CodeQL/governance-workflow scan-result caches.
Acknowledge: 

ID: complexity-health::rust/crates/db-store/src/api_keys.rs::1::high-complexity
# Issue #447
# [WARNING] complexity-health - Cyclomatic complexity 23 (cognitive 105) — over the 20 threshold past which functions become difficult to test exhaustively. CRAP score 552 (no coverage data ingested — treated as 0% for CRAP).
#   rust/crates/db-store/src/api_keys.rs:1
# Code: //! Headless API key issuance/lookup/revocation.
Acknowledge: 

ID: complexity-health::rust/crates/db-store/src/projects.rs::1::high-complexity
# Issue #448
# [WARNING] complexity-health - Cyclomatic complexity 145 (cognitive 754) — over the 20 threshold past which functions become difficult to test exhaustively. CRAP score 21170 (no coverage data ingested — treated as 0% for CRAP).
#   rust/crates/db-store/src/projects.rs:1
# Code: //! Project/step/document CRUD — the core `projects`/`steps`/`documents` tables.
Acknowledge: 

ID: complexity-health::rust/crates/db-store/src/sla.rs::1::high-complexity
# Issue #449
# [WARNING] complexity-health - Cyclomatic complexity 24 (cognitive 120) — over the 20 threshold past which functions become difficult to test exhaustively. CRAP score 600 (no coverage data ingested — treated as 0% for CRAP).
#   rust/crates/db-store/src/sla.rs:1
# Code: //! SLA-breach queries backing `governance.sla` (see `ignite_config::SlaConfig`):
Acknowledge: 

ID: complexity-health::rust/crates/db-store/src/scheduled.rs::1::high-complexity
# Issue #450
# [WARNING] complexity-health - Cyclomatic complexity 28 (cognitive 141) — over the 20 threshold past which functions become difficult to test exhaustively. CRAP score 812 (no coverage data ingested — treated as 0% for CRAP).
#   rust/crates/db-store/src/scheduled.rs:1
# Code: //! Scheduled re-check bookkeeping for effectivated projects.
Acknowledge: 

ID: complexity-health::rust/crates/override-engine/src/scoring.rs::1::low-maintainability
# Issue #451
# [WARNING] complexity-health - Maintainability Index 37/100 — below the 40 threshold (complexity 50 over 182 lines of code).
#   rust/crates/override-engine/src/scoring.rs:1
# Code: //! Severity scoring, CWE/OWASP derivation, and the file-path heuristics
Acknowledge: 

ID: complexity-health::rust/crates/override-engine/src/collect.rs::1::low-maintainability
# Issue #452
# [WARNING] complexity-health - Maintainability Index 23/100 — below the 40 threshold (complexity 127 over 539 lines of code).
#   rust/crates/override-engine/src/collect.rs:1
# Code: //! Turns every check's raw findings (`RawFinding`/`CodeqlFinding`/license
Acknowledge: 

ID: complexity-health::rust/crates/staging/src/lib.rs::1::low-maintainability
# Issue #453
# [WARNING] complexity-health - Maintainability Index 28/100 — below the 40 threshold (complexity 78 over 468 lines of code).
#   rust/crates/staging/src/lib.rs:1
# Code: //! Faithful port of `server.js`'s staging/extraction layer — the guarded
Acknowledge: 

ID: complexity-health::rust/crates/image-provenance/src/lib.rs::1::low-maintainability
# Issue #454
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 31 over 235 lines of code).
#   rust/crates/image-provenance/src/lib.rs:1
# Code: //! Sigstore/cosign keyless-signature verification for external Dockerfile
Acknowledge: 

ID: complexity-health::rust/crates/auto-fix/src/lib.rs::1::low-maintainability
# Issue #455
# [WARNING] complexity-health - Maintainability Index 34/100 — below the 40 threshold (complexity 44 over 344 lines of code).
#   rust/crates/auto-fix/src/lib.rs:1
# Code: //! Faithful port of `lib/auto-fix.js` — turns a subset of dead-code and
Acknowledge: 

ID: complexity-health::rust/crates/codeql-cross-file/src/lib.rs::1::low-maintainability
# Issue #456
# [WARNING] complexity-health - Maintainability Index 20/100 — below the 40 threshold (complexity 134 over 840 lines of code).
#   rust/crates/codeql-cross-file/src/lib.rs:1
# Code: //! Cross-file static analysis via the CodeQL CLI. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/secret-verifier/src/lib.rs::1::low-maintainability
# Issue #457
# [WARNING] complexity-health - Maintainability Index 25/100 — below the 40 threshold (complexity 84 over 773 lines of code).
#   rust/crates/secret-verifier/src/lib.rs:1
# Code: //! Active, read-only credential verification — the GHAS-parity gap noted
Acknowledge: 

ID: complexity-health::rust/crates/config/src/lib.rs::1::low-maintainability
# Issue #458
# [WARNING] complexity-health - Maintainability Index 15/100 — below the 40 threshold (complexity 199 over 1301 lines of code).
#   rust/crates/config/src/lib.rs:1
# Code: //! Ignite configuration — config.json < environment variables. Faithful
Acknowledge: 

ID: complexity-health::rust/crates/license-classification/src/lib.rs::1::low-maintainability
# Issue #459
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 33 over 254 lines of code).
#   rust/crates/license-classification/src/lib.rs:1
# Code: //! SPDX license tier classification and version-range helpers shared by
Acknowledge: 

ID: complexity-health::rust/crates/unit-test-runner/src/lib.rs::1::low-maintainability
# Issue #460
# [WARNING] complexity-health - Maintainability Index 36/100 — below the 40 threshold (complexity 48 over 227 lines of code).
#   rust/crates/unit-test-runner/src/lib.rs:1
# Code: //! Runs the onboarded project's own unit test suite, sandboxed inside a
Acknowledge: 

ID: complexity-health::rust/crates/feature-posture/src/lib.rs::1::low-maintainability
# Issue #461
# [WARNING] complexity-health - Maintainability Index 37/100 — below the 40 threshold (complexity 32 over 318 lines of code).
#   rust/crates/feature-posture/src/lib.rs:1
# Code: //! Compliance & Feature Posture Engine — detects the PRESENCE of security/
Acknowledge: 

ID: complexity-health::rust/crates/pipeline-core/src/lib.rs::1::low-maintainability
# Issue #462
# [WARNING] complexity-health - Maintainability Index 34/100 — below the 40 threshold (complexity 48 over 322 lines of code).
#   rust/crates/pipeline-core/src/lib.rs:1
# Code: //! Pipeline orchestration helpers shared across `validate-all`/`onboard`/
Acknowledge: 

ID: complexity-health::rust/crates/iac-security/src/lib.rs::1::low-maintainability
# Issue #463
# [WARNING] complexity-health - Maintainability Index 30/100 — below the 40 threshold (complexity 66 over 451 lines of code).
#   rust/crates/iac-security/src/lib.rs:1
# Code: //! IaC/container misconfiguration scan (Dockerfiles, Terraform, Kubernetes
Acknowledge: 

ID: complexity-health::rust/crates/dead-code/src/lib.rs::1::low-maintainability
# Issue #464
# [WARNING] complexity-health - Maintainability Index 28/100 — below the 40 threshold (complexity 82 over 426 lines of code).
#   rust/crates/dead-code/src/lib.rs:1
# Code: //! Built-in dead-code / unused-export / unused-dependency / circular-import
Acknowledge: 

ID: complexity-health::rust/crates/secrets/src/lib.rs::1::low-maintainability
# Issue #465
# [WARNING] complexity-health - Maintainability Index 22/100 — below the 40 threshold (complexity 106 over 919 lines of code).
#   rust/crates/secrets/src/lib.rs:1
# Code: //! Regex-based secret scan + optional gitleaks supplement. Faithful port
Acknowledge: 

ID: complexity-health::rust/crates/auto-fix-pr/src/lib.rs::1::low-maintainability
# Issue #466
# [WARNING] complexity-health - Maintainability Index 18/100 — below the 40 threshold (complexity 133 over 1209 lines of code).
#   rust/crates/auto-fix-pr/src/lib.rs:1
# Code: //! Auto-fix PR bot — the Dependabot-parity gap `scheduled-rescan` leaves
Acknowledge: 

ID: complexity-health::rust/crates/deps-dev-client/src/lib.rs::1::low-maintainability
# Issue #467
# [WARNING] complexity-health - Maintainability Index 26/100 — below the 40 threshold (complexity 93 over 533 lines of code).
#   rust/crates/deps-dev-client/src/lib.rs:1
# Code: //! deps.dev API client + npm-registry/unpkg license fallbacks, shared by
Acknowledge: 

ID: complexity-health::rust/crates/mcp-server/src/main.rs::1::low-maintainability
# Issue #468
# [WARNING] complexity-health - Maintainability Index 35/100 — below the 40 threshold (complexity 30 over 487 lines of code).
#   rust/crates/mcp-server/src/main.rs:1
# Code: //! MCP server exposing the company AI validation guidelines, faithful
Acknowledge: 

ID: complexity-health::rust/crates/css-dead-code/src/lib.rs::1::low-maintainability
# Issue #469
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 36 over 217 lines of code).
#   rust/crates/css-dead-code/src/lib.rs:1
# Code: //! Built-in CSS/Tailwind dead-class scan. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/boundaries/src/lib.rs::1::low-maintainability
# Issue #470
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 29 over 300 lines of code).
#   rust/crates/boundaries/src/lib.rs:1
# Code: //! Built-in architecture-boundary enforcement. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/studio-manifests/src/lib.rs::1::low-maintainability
# Issue #471
# [WARNING] complexity-health - Maintainability Index 23/100 — below the 40 threshold (complexity 127 over 552 lines of code).
#   rust/crates/studio-manifests/src/lib.rs:1
# Code: //! The manifest parsers server.js's dependency license/vulnerability
Acknowledge: 

ID: complexity-health::rust/crates/server/src/auth/github_oauth.rs::1::low-maintainability
# Issue #472
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 27 over 324 lines of code).
#   rust/crates/server/src/auth/github_oauth.rs:1
# Code: //! GitHub sign-in (`auth.js`'s `mode === 'github'`) and GitHub *account
Acknowledge: 

ID: complexity-health::rust/crates/server/src/auth.rs::1::low-maintainability
# Issue #473
# [WARNING] complexity-health - Maintainability Index 36/100 — below the 40 threshold (complexity 32 over 423 lines of code).
#   rust/crates/server/src/auth.rs:1
# Code: //! Session/API-key auth route wiring — Rust port of `auth.js`'s Express
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/studio.rs::1::low-maintainability
# Issue #474
# [WARNING] complexity-health - Maintainability Index 24/100 — below the 40 threshold (complexity 79 over 943 lines of code).
#   rust/crates/server/src/routes/studio.rs:1
# Code: //! `/api/pipeline/:jobId/studio/*` — faithful (partial) port of
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/issues.rs::1::low-maintainability
# Issue #475
# [WARNING] complexity-health - Maintainability Index 36/100 — below the 40 threshold (complexity 34 over 345 lines of code).
#   rust/crates/server/src/routes/issues.rs:1
# Code: //! /api/issues/{explain,suggest-fix} — faithful port of routes/issues.js.
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/pipeline_onboard.rs::1::low-maintainability
# Issue #476
# [WARNING] complexity-health - Maintainability Index 30/100 — below the 40 threshold (complexity 70 over 410 lines of code).
#   rust/crates/server/src/routes/pipeline_onboard.rs:1
# Code: //! POST /api/pipeline/onboard — faithful port of routes/pipeline-onboard.js:
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/pipeline_interactive/run.rs::1::low-maintainability
# Issue #477
# [WARNING] complexity-health - Maintainability Index 22/100 — below the 40 threshold (complexity 124 over 698 lines of code).
#   rust/crates/server/src/routes/pipeline_interactive/run.rs:1
# Code: //! The actual phase-by-phase driver for `POST /api/pipeline` — split
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/effectivate.rs::1::low-maintainability
# Issue #478
# [WARNING] complexity-health - Maintainability Index 37/100 — below the 40 threshold (complexity 28 over 428 lines of code).
#   rust/crates/server/src/routes/effectivate.rs:1
# Code: //! `POST /api/projects/:projectId/effectivate` — faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/pipeline_interactive.rs::1::low-maintainability
# Issue #479
# [WARNING] complexity-health - Maintainability Index 25/100 — below the 40 threshold (complexity 77 over 871 lines of code).
#   rust/crates/server/src/routes/pipeline_interactive.rs:1
# Code: //! POST /api/pipeline — faithful port of routes/pipeline-interactive.js:
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/github_pr_status.rs::1::low-maintainability
# Issue #480
# [WARNING] complexity-health - Maintainability Index 31/100 — below the 40 threshold (complexity 71 over 322 lines of code).
#   rust/crates/server/src/routes/github_pr_status.rs:1
# Code: //! POST /api/pipeline/:jobId/github-check — faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/pipeline_validate.rs::1::low-maintainability
# Issue #481
# [WARNING] complexity-health - Maintainability Index 27/100 — below the 40 threshold (complexity 73 over 580 lines of code).
#   rust/crates/server/src/routes/pipeline_validate.rs:1
# Code: //! POST /api/pipeline/validate-all — faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/fix_pr.rs::1::low-maintainability
# Issue #482
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 32 over 252 lines of code).
#   rust/crates/server/src/routes/fix_pr.rs:1
# Code: //! `POST /api/pipeline/:job_id/fix-pr/preview` and
Acknowledge: 

ID: complexity-health::rust/crates/github-api/src/lib.rs::1::low-maintainability
# Issue #483
# [WARNING] complexity-health - Maintainability Index 21/100 — below the 40 threshold (complexity 136 over 690 lines of code).
#   rust/crates/github-api/src/lib.rs:1
# Code: //! Faithful port of `lib/github-api.js` — GitHub API access without
Acknowledge: 

ID: complexity-health::rust/crates/fs-utils/src/lib.rs::1::low-maintainability
# Issue #484
# [WARNING] complexity-health - Maintainability Index 26/100 — below the 40 threshold (complexity 83 over 569 lines of code).
#   rust/crates/fs-utils/src/lib.rs:1
# Code: //! Pure filesystem/content helpers shared by Ignite's checks — file
Acknowledge: 

ID: complexity-health::rust/crates/fix-pr/src/lib.rs::1::low-maintainability
# Issue #485
# [WARNING] complexity-health - Maintainability Index 20/100 — below the 40 threshold (complexity 134 over 953 lines of code).
#   rust/crates/fix-pr/src/lib.rs:1
# Code: //! Bulk "fix all findings" PR generator — the scan-wide counterpart to
Acknowledge: 

ID: complexity-health::rust/crates/shipping/src/lib.rs::1::low-maintainability
# Issue #486
# [WARNING] complexity-health - Maintainability Index 37/100 — below the 40 threshold (complexity 38 over 269 lines of code).
#   rust/crates/shipping/src/lib.rs:1
# Code: //! Faithful port of `lib/shipping.js` — Phase 5/6: git + gh shipping.
Acknowledge: 

ID: complexity-health::rust/crates/llm-deep-scan/src/lib.rs::1::low-maintainability
# Issue #487
# [WARNING] complexity-health - Maintainability Index 22/100 — below the 40 threshold (complexity 144 over 573 lines of code).
#   rust/crates/llm-deep-scan/src/lib.rs:1
# Code: //! Local LLM (Ollama/llama.cpp-compatible, or OpenAI) security/quality
Acknowledge: 

ID: complexity-health::rust/crates/api-schema-drift/src/lib.rs::1::low-maintainability
# Issue #488
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 32 over 260 lines of code).
#   rust/crates/api-schema-drift/src/lib.rs:1
# Code: //! API breaking-change / shadow-endpoint detection via oasdiff. Faithful
Acknowledge: 

ID: complexity-health::rust/crates/dependency-license-scan/src/lib.rs::1::low-maintainability
# Issue #489
# [WARNING] complexity-health - Maintainability Index 13/100 — below the 40 threshold (complexity 203 over 1634 lines of code).
#   rust/crates/dependency-license-scan/src/lib.rs:1
# Code: //! Dependency license/vulnerability scan orchestrators. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/dependency-license-scan/src/dependency_diff.rs::1::low-maintainability
# Issue #490
# [WARNING] complexity-health - Maintainability Index 38/100 — below the 40 threshold (complexity 31 over 303 lines of code).
#   rust/crates/dependency-license-scan/src/dependency_diff.rs:1
# Code: //! PR "Dependency Review" comment — GHAS-parity gap: `dependency-review-action`
Acknowledge: 

ID: complexity-health::rust/crates/dependency-license-scan/src/reachability.rs::1::low-maintainability
# Issue #491
# [WARNING] complexity-health - Maintainability Index 37/100 — below the 40 threshold (complexity 36 over 286 lines of code).
#   rust/crates/dependency-license-scan/src/reachability.rs:1
# Code: //! Go function-level transitive reachability: for advisories whose OSV
Acknowledge: 

ID: complexity-health::rust/crates/llm-client/src/lib.rs::1::low-maintainability
# Issue #492
# [WARNING] complexity-health - Maintainability Index 35/100 — below the 40 threshold (complexity 34 over 437 lines of code).
#   rust/crates/llm-client/src/lib.rs:1
# Code: //! Shared local-LLM/OpenAI chat-completions client. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/phase4-orchestrator/src/lib.rs::1::low-maintainability
# Issue #493
# [WARNING] complexity-health - Maintainability Index 23/100 — below the 40 threshold (complexity 72 over 1132 lines of code).
#   rust/crates/phase4-orchestrator/src/lib.rs:1
# Code: //! Phase 4 check orchestrator. Faithful port of server.js's
Acknowledge: 

ID: complexity-health::rust/crates/package-hallucination/src/lib.rs::1::low-maintainability
# Issue #494
# [WARNING] complexity-health - Maintainability Index 38/100 — below the 40 threshold (complexity 32 over 305 lines of code).
#   rust/crates/package-hallucination/src/lib.rs:1
# Code: //! AI package-hallucination / slopsquat detection. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/gha-security/src/lib.rs::1::low-maintainability
# Issue #495
# [WARNING] complexity-health - Maintainability Index 36/100 — below the 40 threshold (complexity 32 over 383 lines of code).
#   rust/crates/gha-security/src/lib.rs:1
# Code: //! GitHub Actions workflow security scan via zizmor (Trail of Bits'
Acknowledge: 

ID: complexity-health::rust/crates/tool-runner/src/lib.rs::1::low-maintainability
# Issue #496
# [WARNING] complexity-health - Maintainability Index 25/100 — below the 40 threshold (complexity 92 over 639 lines of code).
#   rust/crates/tool-runner/src/lib.rs:1
# Code: //! External-tool process execution + the sanitizers that guard it — every
Acknowledge: 

ID: complexity-health::rust/crates/complexity-health/src/lib.rs::1::low-maintainability
# Issue #497
# [WARNING] complexity-health - Maintainability Index 30/100 — below the 40 threshold (complexity 65 over 408 lines of code).
#   rust/crates/complexity-health/src/lib.rs:1
# Code: //! Built-in complexity/maintainability health scan. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/container-image-vulnerabilities/src/lib.rs::1::low-maintainability
# Issue #498
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 30 over 279 lines of code).
#   rust/crates/container-image-vulnerabilities/src/lib.rs:1
# Code: //! Builds every discovered Dockerfile and runs `trivy image` against the
Acknowledge: 

ID: complexity-health::rust/crates/module-graph/src/lib.rs::1::low-maintainability
# Issue #499
# [WARNING] complexity-health - Maintainability Index 29/100 — below the 40 threshold (complexity 74 over 446 lines of code).
#   rust/crates/module-graph/src/lib.rs:1
# Code: //! Lightweight JS/TS module graph: parses import/require/export statements
Acknowledge: 

ID: complexity-health::rust/crates/guidelines/src/checks.rs::1::low-maintainability
# Issue #500
# [WARNING] complexity-health - Maintainability Index 23/100 — below the 40 threshold (complexity 130 over 588 lines of code).
#   rust/crates/guidelines/src/checks.rs:1
# Code: //! Mechanical checks for the automated subset of the guideline catalog.
Acknowledge: 

ID: complexity-health::rust/crates/enforce-gate-branch-protection/src/lib.rs::1::low-maintainability
# Issue #501
# [WARNING] complexity-health - Maintainability Index 29/100 — below the 40 threshold (complexity 58 over 614 lines of code).
#   rust/crates/enforce-gate-branch-protection/src/lib.rs:1
# Code: //! `enforce-gate-branch-protection <org/repo> [<org/repo>...] [--apply]` —
Acknowledge: 

ID: complexity-health::rust/crates/report-vulnerability/src/main.rs::1::low-maintainability
# Issue #502
# [WARNING] complexity-health - Maintainability Index 29/100 — below the 40 threshold (complexity 66 over 540 lines of code).
#   rust/crates/report-vulnerability/src/main.rs:1
# Code: //! `report-vulnerability <org/repo> --summary <str> --severity <level>
Acknowledge: 

ID: complexity-health::rust/crates/callgraph/src/lib.rs::1::low-maintainability
# Issue #503
# [WARNING] complexity-health - Maintainability Index 31/100 — below the 40 threshold (complexity 60 over 426 lines of code).
#   rust/crates/callgraph/src/lib.rs:1
# Code: //! Studio's "Call Graph" feature: caller -> callee edges across a project,
Acknowledge: 

ID: complexity-health::rust/crates/pii-dataflow/src/lib.rs::1::low-maintainability
# Issue #504
# [WARNING] complexity-health - Maintainability Index 30/100 — below the 40 threshold (complexity 72 over 363 lines of code).
#   rust/crates/pii-dataflow/src/lib.rs:1
# Code: //! Sensitive data-flow (PII/GDPR) SAST via Bearer. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/governance-ci/src/lib.rs::1::low-maintainability
# Issue #505
# [WARNING] complexity-health - Maintainability Index 34/100 — below the 40 threshold (complexity 53 over 279 lines of code).
#   rust/crates/governance-ci/src/lib.rs:1
# Code: //! Phase 5: org governance CI, run locally via `act`. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/semantic-sast/src/lib.rs::1::low-maintainability
# Issue #506
# [WARNING] complexity-health - Maintainability Index 38/100 — below the 40 threshold (complexity 33 over 258 lines of code).
#   rust/crates/semantic-sast/src/lib.rs:1
# Code: //! Semantic pattern-matching SAST via Semgrep OSS. Faithful port of
Acknowledge: 

ID: complexity-health::public/i18n.js::1::low-maintainability
# Issue #507
# [WARNING] complexity-health - Maintainability Index 27/100 — below the 40 threshold (complexity 42 over 1212 lines of code).
#   public/i18n.js:1
# Code: // Ignite web UI translations — static UI chrome only (buttons, labels,
Acknowledge: 

ID: complexity-health::vscode-extension/src/panels/findingsTree.ts::1::low-maintainability
# Issue #508
# [WARNING] complexity-health - Maintainability Index 38/100 — below the 40 threshold (complexity 47 over 179 lines of code).
#   vscode-extension/src/panels/findingsTree.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::vscode-extension/src/panels/reportPanel.ts::1::low-maintainability
# Issue #509
# [WARNING] complexity-health - Maintainability Index 31/100 — below the 40 threshold (complexity 79 over 273 lines of code).
#   vscode-extension/src/panels/reportPanel.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::vscode-extension/src/extension.ts::1::low-maintainability
# Issue #510
# [WARNING] complexity-health - Maintainability Index 25/100 — below the 40 threshold (complexity 118 over 488 lines of code).
#   vscode-extension/src/extension.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::vscode-extension/src/api.ts::1::low-maintainability
# Issue #511
# [WARNING] complexity-health - Maintainability Index 30/100 — below the 40 threshold (complexity 74 over 397 lines of code).
#   vscode-extension/src/api.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::vscode-extension/src/reviewFile.ts::1::low-maintainability
# Issue #512
# [WARNING] complexity-health - Maintainability Index 36/100 — below the 40 threshold (complexity 53 over 226 lines of code).
#   vscode-extension/src/reviewFile.ts:1
# Code: import * as fs from 'fs/promises';
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::7aa895fb
# Issue #513
# [WARNING] css-dead-code - CSS class ".infima" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::3239fc7e
# Issue #514
# [WARNING] css-dead-code - CSS class ".theme-common" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::8b93d74d
# Issue #515
# [WARNING] css-dead-code - CSS class ".theme-classic" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::7246118d
# Issue #516
# [WARNING] css-dead-code - CSS class ".core" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::c98c98f5
# Issue #517
# [WARNING] css-dead-code - CSS class ".plugin-debug" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::ae40698e
# Issue #518
# [WARNING] css-dead-code - CSS class ".theme-mermaid" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::f63f75e9
# Issue #519
# [WARNING] css-dead-code - CSS class ".theme-live-codeblock" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::59b3bc2f
# Issue #520
# [WARNING] css-dead-code - CSS class ".theme-search-algolia" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::9cc5937b
# Issue #521
# [WARNING] css-dead-code - CSS class ".docsearch" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::32::unused-css-class
# Issue #522
# [WARNING] css-dead-code - CSS class ".markdown" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:32
# Code: .markdown {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::88::unused-css-class
# Issue #523
# [WARNING] css-dead-code - CSS class ".theme-admonition" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:88
# Code: .theme-admonition {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::95::unused-css-class
# Issue #524
# [WARNING] css-dead-code - CSS class ".theme-doc-markdown" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:95
# Code: .theme-doc-markdown table {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::117::unused-css-class
# Issue #525
# [WARNING] css-dead-code - CSS class ".zoomableImg" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:117
# Code: .zoomableImg {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::173::unused-css-class
# Issue #526
# [WARNING] css-dead-code - CSS class ".heroShot" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:173
# Code: .heroShot {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::193::unused-css-class
# Issue #527
# [WARNING] css-dead-code - CSS class ".phaseDiagram" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:193
# Code: .phaseDiagram {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::209::unused-css-class
# Issue #528
# [WARNING] css-dead-code - CSS class ".phase-link" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:209
# Code: .phase-link {
Acknowledge: 

ID: css-dead-code::docs/assets/css/style.scss::4::unused-css-class
# Issue #529
# [WARNING] css-dead-code - CSS class ".theme" is declared in docs/assets/css/style.scss but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs/assets/css/style.scss:4
# Code: @import "{{ site.theme }}";
Acknowledge: 

ID: css-dead-code::docs/assets/css/style.scss::6::unused-css-class
# Issue #530
# [WARNING] css-dead-code - CSS class ".main-content" is declared in docs/assets/css/style.scss but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs/assets/css/style.scss:6
# Code: // Cayman's default .main-content is a fixed ~64rem column with no overflow
Acknowledge: 
