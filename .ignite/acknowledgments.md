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

ID: iac-security::Dockerfile::1::629a3996
# Issue #20
# [WARNING] iac-security - No HEALTHCHECK defined
#   Dockerfile:1
# Code: # Ignite, self-contained: the Rust server/CLI/MCP binaries plus every
Acknowledge: 

ID: iac-security::Dockerfile::1::5c411837
# Issue #21
# [WARNING] iac-security - Ensure that HEALTHCHECK instructions have been added to container images
#   Dockerfile:1
# Code: # Ignite, self-contained: the Rust server/CLI/MCP binaries plus every
Acknowledge: 

ID: iac-security::Dockerfile::127
# Issue #22
# [WARNING] iac-security - Pin versions in apt get install. Instead of `apt-get install <package>` use `apt-get install <package>=<version>`
#   Dockerfile:127
# Code: RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
Acknowledge: 

ID: iac-security::Dockerfile::149
# Issue #23
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:149
# Code: RUN if [ "$INSTALL_ORT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::158
# Issue #24
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:158
# Code: RUN if [ "$INSTALL_TRIVY" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::162
# Issue #25
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:162
# Code: RUN if [ "$INSTALL_CHECKOV" = "true" ]; then pipx install checkov --pip-args="--no-compile" && pipx ensurepath; fi
Acknowledge: 

ID: iac-security::Dockerfile::171
# Issue #26
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:171
# Code: RUN if [ "$INSTALL_GITLEAKS" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::177
# Issue #27
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:177
# Code: RUN if [ "$INSTALL_SYFT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::187
# Issue #28
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:187
# Code: RUN if [ "$INSTALL_SEMGREP" = "true" ]; then pipx install semgrep --pip-args="--no-compile" && pipx ensurepath; fi
Acknowledge: 

ID: iac-security::Dockerfile::188
# Issue #29
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:188
# Code: RUN if [ "$INSTALL_BEARER" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::212::09cd120f
# Issue #30
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:212
# Code: RUN if [ "$INSTALL_GUARDDOG" = "true" ] || [ "$INSTALL_LICENSEE" = "true" ] || [ "$INSTALL_COCOAPODS" = "true" ] || [ "$INSTALL_ORT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::212::bdfb7069
# Issue #31
# [WARNING] iac-security - Pin versions in apt get install. Instead of `apt-get install <package>` use `apt-get install <package>=<version>`
#   Dockerfile:212
# Code: RUN if [ "$INSTALL_GUARDDOG" = "true" ] || [ "$INSTALL_LICENSEE" = "true" ] || [ "$INSTALL_COCOAPODS" = "true" ] || [ "$INSTALL_ORT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::212::19c88dc5
# Issue #32
# [WARNING] iac-security - Pin versions in gem install. Instead of `gem install <gem>` use `gem install <gem>:<version>`
#   Dockerfile:212
# Code: RUN if [ "$INSTALL_GUARDDOG" = "true" ] || [ "$INSTALL_LICENSEE" = "true" ] || [ "$INSTALL_COCOAPODS" = "true" ] || [ "$INSTALL_ORT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::225
# Issue #33
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:225
# Code: RUN if [ "$INSTALL_PICKLESCAN" = "true" ]; then pipx install picklescan --pip-args="--no-compile" && pipx ensurepath; fi
Acknowledge: 

ID: iac-security::Dockerfile::226
# Issue #34
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:226
# Code: RUN if [ "$INSTALL_ZIZMOR" = "true" ]; then pipx install zizmor --pip-args="--no-compile" && pipx ensurepath; fi
Acknowledge: 

ID: iac-security::Dockerfile::227
# Issue #35
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:227
# Code: RUN if [ "$INSTALL_OASDIFF" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::255
# Issue #36
# [WARNING] iac-security - Pin versions in npm. Instead of `npm install <package>` use `npm install <package>@<version>`
#   Dockerfile:255
# Code: RUN if [ "$INSTALL_JSCPD" = "true" ]; then npm install -g jscpd; fi
Acknowledge: 

ID: iac-security::Dockerfile::256::2ddec02b
# Issue #37
# [WARNING] iac-security - Multiple consecutive `RUN` instructions. Consider consolidation.
#   Dockerfile:256
# Code: RUN if [ "$INSTALL_SPECTRAL" = "true" ]; then npm install -g @stoplight/spectral-cli; fi
Acknowledge: 

ID: iac-security::Dockerfile::256::37ad8298
# Issue #38
# [WARNING] iac-security - Pin versions in npm. Instead of `npm install <package>` use `npm install <package>@<version>`
#   Dockerfile:256
# Code: RUN if [ "$INSTALL_SPECTRAL" = "true" ]; then npm install -g @stoplight/spectral-cli; fi
Acknowledge: 

ID: iac-security::Dockerfile::277
# Issue #39
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:277
# Code: RUN if [ "$INSTALL_ACT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::291
# Issue #40
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:291
# Code: RUN if [ "$INSTALL_DOCKER_CLI" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::343
# Issue #41
# [WARNING] iac-security - Non-numeric user-id may not be resolvable by host system
#   Dockerfile:343
# Code: USER ignite
Acknowledge: 

ID: gha-security::.github/workflows/check-env-var-drift.yml::25
# Issue #42
# [WARNING] gha-security - credential persistence through GitHub Actions artifacts (uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4)
#   .github/workflows/check-env-var-drift.yml:25
# Code: - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
Acknowledge: 

ID: gha-security::.github/workflows/deploy-docs.yml::24
# Issue #43
# [WARNING] gha-security - credential persistence through GitHub Actions artifacts (uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4)
#   .github/workflows/deploy-docs.yml:24
# Code: - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
Acknowledge: 

ID: image-provenance::Dockerfile::19
# Issue #44
# [WARNING] image-provenance - Base image "rust:1-bookworm" has no verifiable Sigstore/cosign signature — supply-chain provenance can't be confirmed.
#   Dockerfile:19
# Code: FROM rust:1-bookworm AS rust-builder
Acknowledge: 

ID: image-provenance::Dockerfile::30
# Issue #45
# [WARNING] image-provenance - Base image "node:24-bookworm-slim" has no verifiable Sigstore/cosign signature — supply-chain provenance can't be confirmed.
#   Dockerfile:30
# Code: FROM node:24-bookworm-slim
Acknowledge: 

ID: code-duplication::public/index.html::2918
# Issue #46
# [WARNING] code-duplication - 20-line duplicate block, also found in public/index.html:5814-5833.
#   public/index.html:2918
# Code: list.innerHTML = sortedIssueIndices(issues).map((idx) => safeRenderIssueCard(issues[idx], idx, { interactive: issues[idx].status !== 'overridden' })).join('');
Acknowledge: 

ID: code-duplication::public/index.html::4782
# Issue #47
# [WARNING] code-duplication - 25-line duplicate block, also found in public/index.html:4948-4972.
#   public/index.html:4782
# Code: body: JSON.stringify({ language }),
Acknowledge: 

ID: code-duplication::rust/crates/db-store/src/overrides.rs::198::777e8c20
# Issue #48
# [WARNING] code-duplication - 18-line duplicate block, also found in rust/crates/db-store/src/overrides.rs:246-263.
#   rust/crates/db-store/src/overrides.rs:198
# Code: stmt.query_map(params![project_id], |row| {
Acknowledge: 

ID: code-duplication::rust/crates/llm-client/src/lib.rs::233
# Issue #49
# [WARNING] code-duplication - 16-line duplicate block, also found in rust/crates/llm-client/src/lib.rs:302-317.
#   rust/crates/llm-client/src/lib.rs:233
# Code: return Err(LlmError::Timeout(timeout_ms));
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/audit_log.rs::105::e3a52b99
# Issue #50
# [WARNING] code-duplication - 33-line duplicate block, also found in rust/crates/server/src/routes/compliance.rs:104-136.
#   rust/crates/server/src/routes/audit_log.rs:105
# Code: Router::new().route("/api/audit-log", get(list)).route("/api/audit-log/verify", get(verify))
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/history.rs::219
# Issue #51
# [WARNING] code-duplication - 16-line duplicate block, also found in rust/crates/server/src/routes/pipeline_interactive.rs:411-427.
#   rust/crates/server/src/routes/history.rs:219
# Code: review_gate: ReviewGate::default(),
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_interactive.rs::473
# Issue #52
# [WARNING] code-duplication - 31-line duplicate block, also found in rust/crates/server/src/routes/pipeline_interactive.rs:699-729.
#   rust/crates/server/src/routes/pipeline_interactive.rs:473
# Code: let zip = zip_bytes(&[("app.js", b"console.log(1);"), ("package.json", b"{\"name\":\"fixture\"}")]);
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_interactive.rs::474
# Issue #53
# [WARNING] code-duplication - 22-line duplicate block, also found in rust/crates/server/src/routes/pipeline_interactive.rs:923-944.
#   rust/crates/server/src/routes/pipeline_interactive.rs:474
# Code: let form = Form::new().text("org", "-bad-").text("repo", "widgets").text("dryRun", "true").part("archive", Part::bytes(zip).file_name("p.zip"));
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_onboard.rs::29
# Issue #54
# [WARNING] code-duplication - 59-line duplicate block, also found in rust/crates/server/src/routes/pipeline_validate.rs:32-90.
#   rust/crates/server/src/routes/pipeline_onboard.rs:29
# Code: static REPO_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,100}$").unwrap());
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_onboard.rs::88
# Issue #55
# [WARNING] code-duplication - 18-line duplicate block, also found in rust/crates/server/src/routes/pipeline_validate.rs:92-109.
#   rust/crates/server/src/routes/pipeline_onboard.rs:88
# Code: self.inner.lock().unwrap().project_id = Some(id);
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_onboard.rs::161
# Issue #56
# [WARNING] code-duplication - 16-line duplicate block, also found in rust/crates/server/src/routes/pipeline_validate.rs:239-253.
#   rust/crates/server/src/routes/pipeline_onboard.rs:161
# Code: let dry_run = body.get("dryRun").and_then(|v| v.as_bool()).unwrap_or(false);
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_onboard.rs::384
# Issue #57
# [WARNING] code-duplication - 20-line duplicate block, also found in rust/crates/server/src/routes/pipeline_validate.rs:490-509.
#   rust/crates/server/src/routes/pipeline_onboard.rs:384
# Code: actor_name: None,
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/push_protection_webhook.rs::239
# Issue #58
# [WARNING] code-duplication - 17-line duplicate block, also found in rust/crates/server/src/routes/repository_events_webhook.rs:180-196.
#   rust/crates/server/src/routes/push_protection_webhook.rs:239
# Code: async fn push_protection_webhook_404s_when_unconfigured() {
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/repository_events_webhook.rs::67
# Issue #59
# [WARNING] code-duplication - 20-line duplicate block, also found in rust/crates/server/src/routes/secret_scanning_webhook.rs:79-98.
#   rust/crates/server/src/routes/repository_events_webhook.rs:67
# Code: return err(StatusCode::NOT_FOUND, "Inbound repository-events webhook is not configured.".to_string());
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/repository_events_webhook.rs::179
# Issue #60
# [WARNING] code-duplication - 18-line duplicate block, also found in rust/crates/server/src/routes/secret_scanning_webhook.rs:242-259.
#   rust/crates/server/src/routes/repository_events_webhook.rs:179
# Code: #[tokio::test]
Acknowledge: 

ID: code-structure::rust/crates/config/src/lib.rs::1
# Issue #61
# [WARNING] code-structure - rust/crates/config/src/lib.rs is 1513 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/config/src/lib.rs:1
# Code: //! Ignite configuration — config.json < environment variables. Faithful
Acknowledge: 

ID: code-structure::rust/crates/secrets/src/lib.rs::1
# Issue #62
# [WARNING] code-structure - rust/crates/secrets/src/lib.rs is 1085 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/secrets/src/lib.rs:1
# Code: //! Regex-based secret scan + optional gitleaks supplement. Faithful port
Acknowledge: 

ID: code-structure::rust/crates/auto-fix-pr/src/lib.rs::1
# Issue #63
# [WARNING] code-structure - rust/crates/auto-fix-pr/src/lib.rs is 1456 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/auto-fix-pr/src/lib.rs:1
# Code: //! Auto-fix PR bot — the Dependabot-parity gap `scheduled-rescan` leaves
Acknowledge: 

ID: code-structure::rust/crates/server/src/routes/studio.rs::1
# Issue #64
# [WARNING] code-structure - rust/crates/server/src/routes/studio.rs is 1071 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/server/src/routes/studio.rs:1
# Code: //! `/api/pipeline/:jobId/studio/*` — faithful (partial) port of
Acknowledge: 

ID: code-structure::rust/crates/server/src/routes/pipeline_interactive.rs::1
# Issue #65
# [WARNING] code-structure - rust/crates/server/src/routes/pipeline_interactive.rs is 1010 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/server/src/routes/pipeline_interactive.rs:1
# Code: //! POST /api/pipeline — faithful port of routes/pipeline-interactive.js:
Acknowledge: 

ID: code-structure::rust/crates/fix-pr/src/lib.rs::1
# Issue #66
# [WARNING] code-structure - rust/crates/fix-pr/src/lib.rs is 1199 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/fix-pr/src/lib.rs:1
# Code: //! Bulk "fix all findings" PR generator — the scan-wide counterpart to
Acknowledge: 

ID: code-structure::rust/crates/dependency-license-scan/src/lib.rs::1
# Issue #67
# [WARNING] code-structure - rust/crates/dependency-license-scan/src/lib.rs is 1808 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/dependency-license-scan/src/lib.rs:1
# Code: //! Dependency license/vulnerability scan orchestrators. Faithful port of
Acknowledge: 

ID: code-structure::rust/crates/phase4-orchestrator/src/lib.rs::1
# Issue #68
# [WARNING] code-structure - rust/crates/phase4-orchestrator/src/lib.rs is 1270 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/phase4-orchestrator/src/lib.rs:1
# Code: //! Phase 4 check orchestrator. Faithful port of server.js's
Acknowledge: 

ID: code-structure::public/i18n.js::1
# Issue #69
# [WARNING] code-structure - public/i18n.js is 1314 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   public/i18n.js:1
# Code: // Ignite web UI translations — static UI chrome only (buttons, labels,
Acknowledge: 

ID: codeql-sast::public/index.html::1489::js/incomplete-html-attribute-sanitization
# Issue #70
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:1489
# Code: <button type="button" class="shrink-0 text-slate-300 hover:text-slate-600" aria-label="${escapeHtml(t('common.close'))}">
Acknowledge: 

ID: codeql-sast::public/index.html::2868::js/incomplete-html-attribute-sanitization
# Issue #71
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:2868
# Code: <span class="w-40 shrink-0 truncate text-slate-700" title="${escapeHtml(name)}">${escapeHtml(name)}${isBottleneck ? ' <span class="text-rose-500" title="Bottleneck — slowest check this run">⬤</span>' : ''}</span>
Acknowledge: 

ID: codeql-sast::public/index.html::4609::js/incomplete-html-attribute-sanitization
# Issue #72
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:4609
# Code: <textarea id="studioQueryText" class="w-full flex-1 min-h-[180px] font-mono text-[12px] leading-relaxed border border-slate-200 rounded-lg p-2" spellcheck="false" placeholder="import ${escapeHtml(defaultLanguage)}\n\nfrom ...\nselect ...">${escapeHtml(initialText)}</textarea>
Acknowledge: 

ID: codeql-sast::public/index.html::6432::js/incomplete-html-attribute-sanitization
# Issue #73
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:6432
# Code: select.innerHTML = orgs.map((o) => `<option value="${escapeHtml(o)}">${escapeHtml(o)}</option>`).join('');
Acknowledge: 

ID: codeql-sast::public/index.html::6521::js/incomplete-html-attribute-sanitization::e40e5cb3
# Issue #74
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:6521
# Code: <button type="button" class="hist-view-checks-report text-[11px] font-semibold text-slate-500 hover:underline shrink-0" data-id="${p.id}" data-org="${escapeHtml(p.org)}" data-repo="${escapeHtml(p.repo)}">${t('history.checksBtn')}</button>
Acknowledge: 

ID: codeql-sast::public/index.html::6523::js/incomplete-html-attribute-sanitization::e40e5cb3
# Issue #75
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:6523
# Code: ${p.issue_count > 0 ? `<button type="button" class="hist-open-studio text-[11px] font-semibold text-violet-600 hover:underline shrink-0" data-id="${p.id}" data-job-id="${escapeAttr(p.job_id || '')}" data-retained="${p.retained ? '1' : ''}" data-org="${escapeHtml(p.org)}" data-repo="${escapeHtml(p.repo)}" title="${escapeAttr(p.retained ? t('history.fullStudioTitle') : t('history.readOnlyStudioTitle'))}">${p.retained ? `${t('history.studioBtn')}${p.retained_tier === 'pruned' ? ` (${t('history.flaggedFilesOnly')})` : ` (${t('common.full')})`}` : t('history.studioBtn')}</button>` : ''}
Acknowledge: 

ID: codeql-sast::public/index.html::6524::js/incomplete-html-attribute-sanitization::e40e5cb3
# Issue #76
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:6524
# Code: ${p.issue_count > 0 ? `<button type="button" class="hist-view-issues text-[11px] font-semibold text-brand-600 hover:underline shrink-0" data-id="${p.id}" data-count="${p.issue_count}" data-org="${escapeHtml(p.org)}" data-repo="${escapeHtml(p.repo)}">${t('history.issueCount', { count: p.issue_count })}</button>` : ''}
Acknowledge: 

ID: dead-code::docs-site/.docusaurus/client-modules.js::1::unused-file
# Issue #77
# [WARNING] dead-code - docs-site/.docusaurus/client-modules.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/.docusaurus/client-modules.js:1
# Code: export default [
Acknowledge: 

ID: dead-code::docs-site/.docusaurus/registry.js::1::unused-file
# Issue #78
# [WARNING] dead-code - docs-site/.docusaurus/registry.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/.docusaurus/registry.js:1
# Code: export default {
Acknowledge: 

ID: dead-code::docs-site/.docusaurus/routes.js::1::unused-file
# Issue #79
# [WARNING] dead-code - docs-site/.docusaurus/routes.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/.docusaurus/routes.js:1
# Code: import React from 'react';
Acknowledge: 

ID: dead-code::docs-site/sidebars.js::1::unused-file
# Issue #80
# [WARNING] dead-code - docs-site/sidebars.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/sidebars.js:1
# Code: // @ts-check
Acknowledge: 

ID: dead-code::docs-site/src/clientModules/eagerImages.js::1::unused-file
# Issue #81
# [WARNING] dead-code - docs-site/src/clientModules/eagerImages.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/src/clientModules/eagerImages.js:1
# Code: // Docusaurus's MDX <img> component auto-sets loading="lazy" on every doc
Acknowledge: 

ID: dead-code::public/i18n.js::1::unused-file
# Issue #82
# [WARNING] dead-code - public/i18n.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   public/i18n.js:1
# Code: // Ignite web UI translations — static UI chrome only (buttons, labels,
Acknowledge: 

ID: dead-code::vscode-extension/src/progress.ts::1::unused-file
# Issue #83
# [WARNING] dead-code - vscode-extension/src/progress.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/progress.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/panels/findingsTree.ts::1::unused-file
# Issue #84
# [WARNING] dead-code - vscode-extension/src/panels/findingsTree.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/panels/findingsTree.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/panels/reportPanel.ts::1::unused-file
# Issue #85
# [WARNING] dead-code - vscode-extension/src/panels/reportPanel.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/panels/reportPanel.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/panels/toolsStatusTree.ts::1::unused-file
# Issue #86
# [WARNING] dead-code - vscode-extension/src/panels/toolsStatusTree.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/panels/toolsStatusTree.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/extension.ts::1::unused-file
# Issue #87
# [WARNING] dead-code - vscode-extension/src/extension.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/extension.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/diagnostics.ts::1::unused-file
# Issue #88
# [WARNING] dead-code - vscode-extension/src/diagnostics.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/diagnostics.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/prePushHook.ts::1::unused-file
# Issue #89
# [WARNING] dead-code - vscode-extension/src/prePushHook.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/prePushHook.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::rust/crates/override-engine/src/collect.rs::1::low-maintainability
# Issue #90
# [WARNING] complexity-health - Maintainability Index 25/100 — below the 40 threshold (complexity 108 over 539 lines of code).
#   rust/crates/override-engine/src/collect.rs:1
# Code: //! Turns every check's raw findings (`RawFinding`/`CodeqlFinding`/license
Acknowledge: 

ID: complexity-health::rust/crates/staging/src/lib.rs::1::low-maintainability
# Issue #91
# [WARNING] complexity-health - Maintainability Index 32/100 — below the 40 threshold (complexity 47 over 491 lines of code).
#   rust/crates/staging/src/lib.rs:1
# Code: //! Faithful port of `server.js`'s staging/extraction layer — the guarded
Acknowledge: 

ID: complexity-health::rust/crates/image-provenance/src/lib.rs::1::low-maintainability
# Issue #92
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 29 over 280 lines of code).
#   rust/crates/image-provenance/src/lib.rs:1
# Code: //! Sigstore/cosign keyless-signature verification for external Dockerfile
Acknowledge: 

ID: complexity-health::rust/crates/auto-fix/src/lib.rs::1::low-maintainability
# Issue #93
# [WARNING] complexity-health - Maintainability Index 38/100 — below the 40 threshold (complexity 27 over 374 lines of code).
#   rust/crates/auto-fix/src/lib.rs:1
# Code: //! Faithful port of `lib/auto-fix.js` — turns a subset of dead-code and
Acknowledge: 

ID: complexity-health::rust/crates/codeql-cross-file/src/lib.rs::1::low-maintainability
# Issue #94
# [WARNING] complexity-health - Maintainability Index 24/100 — below the 40 threshold (complexity 79 over 860 lines of code).
#   rust/crates/codeql-cross-file/src/lib.rs:1
# Code: //! Cross-file static analysis via the CodeQL CLI. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/secret-verifier/src/lib.rs::1::low-maintainability
# Issue #95
# [WARNING] complexity-health - Maintainability Index 27/100 — below the 40 threshold (complexity 60 over 827 lines of code).
#   rust/crates/secret-verifier/src/lib.rs:1
# Code: //! Active, read-only credential verification — the GHAS-parity gap noted
Acknowledge: 

ID: complexity-health::rust/crates/config/src/lib.rs::1::low-maintainability
# Issue #96
# [WARNING] complexity-health - Maintainability Index 14/100 — below the 40 threshold (complexity 191 over 1421 lines of code).
#   rust/crates/config/src/lib.rs:1
# Code: //! Ignite configuration — config.json < environment variables. Faithful
Acknowledge: 

ID: complexity-health::rust/crates/pipeline-core/src/lib.rs::1::low-maintainability
# Issue #97
# [WARNING] complexity-health - Maintainability Index 37/100 — below the 40 threshold (complexity 31 over 355 lines of code).
#   rust/crates/pipeline-core/src/lib.rs:1
# Code: //! Pipeline orchestration helpers shared across `validate-all`/`onboard`/
Acknowledge: 

ID: complexity-health::rust/crates/iac-security/src/lib.rs::1::low-maintainability
# Issue #98
# [WARNING] complexity-health - Maintainability Index 31/100 — below the 40 threshold (complexity 57 over 475 lines of code).
#   rust/crates/iac-security/src/lib.rs:1
# Code: //! IaC/container misconfiguration scan (Dockerfiles, Terraform, Kubernetes
Acknowledge: 

ID: complexity-health::rust/crates/secrets/src/lib.rs::1::low-maintainability
# Issue #99
# [WARNING] complexity-health - Maintainability Index 26/100 — below the 40 threshold (complexity 58 over 983 lines of code).
#   rust/crates/secrets/src/lib.rs:1
# Code: //! Regex-based secret scan + optional gitleaks supplement. Faithful port
Acknowledge: 

ID: complexity-health::rust/crates/auto-fix-pr/src/lib.rs::1::low-maintainability
# Issue #100
# [WARNING] complexity-health - Maintainability Index 20/100 — below the 40 threshold (complexity 96 over 1344 lines of code).
#   rust/crates/auto-fix-pr/src/lib.rs:1
# Code: //! Auto-fix PR bot — the Dependabot-parity gap `scheduled-rescan` leaves
Acknowledge: 

ID: complexity-health::rust/crates/deps-dev-client/src/lib.rs::1::low-maintainability
# Issue #101
# [WARNING] complexity-health - Maintainability Index 28/100 — below the 40 threshold (complexity 63 over 623 lines of code).
#   rust/crates/deps-dev-client/src/lib.rs:1
# Code: //! deps.dev API client + npm-registry/unpkg license fallbacks, shared by
Acknowledge: 

ID: complexity-health::rust/crates/mcp-server/src/main.rs::1::low-maintainability
# Issue #102
# [WARNING] complexity-health - Maintainability Index 34/100 — below the 40 threshold (complexity 26 over 784 lines of code).
#   rust/crates/mcp-server/src/main.rs:1
# Code: //! MCP server exposing the company AI validation guidelines, faithful
Acknowledge: 

ID: complexity-health::rust/crates/boundaries/src/lib.rs::1::low-maintainability
# Issue #103
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 26 over 325 lines of code).
#   rust/crates/boundaries/src/lib.rs:1
# Code: //! Built-in architecture-boundary enforcement. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/studio-manifests/src/lib.rs::1::low-maintainability
# Issue #104
# [WARNING] complexity-health - Maintainability Index 25/100 — below the 40 threshold (complexity 99 over 619 lines of code).
#   rust/crates/studio-manifests/src/lib.rs:1
# Code: //! The manifest parsers server.js's dependency license/vulnerability
Acknowledge: 

ID: complexity-health::rust/crates/server/src/auth.rs::1::low-maintainability
# Issue #105
# [WARNING] complexity-health - Maintainability Index 37/100 — below the 40 threshold (complexity 28 over 433 lines of code).
#   rust/crates/server/src/auth.rs:1
# Code: //! Session/API-key auth route wiring — Rust port of `auth.js`'s Express
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/studio.rs::1::low-maintainability
# Issue #106
# [WARNING] complexity-health - Maintainability Index 28/100 — below the 40 threshold (complexity 47 over 969 lines of code).
#   rust/crates/server/src/routes/studio.rs:1
# Code: //! `/api/pipeline/:jobId/studio/*` — faithful (partial) port of
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/pipeline_onboard.rs::1::low-maintainability
# Issue #107
# [WARNING] complexity-health - Maintainability Index 31/100 — below the 40 threshold (complexity 54 over 502 lines of code).
#   rust/crates/server/src/routes/pipeline_onboard.rs:1
# Code: //! POST /api/pipeline/onboard — faithful port of routes/pipeline-onboard.js:
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/pipeline_interactive/run.rs::1::low-maintainability
# Issue #108
# [WARNING] complexity-health - Maintainability Index 23/100 — below the 40 threshold (complexity 101 over 745 lines of code).
#   rust/crates/server/src/routes/pipeline_interactive/run.rs:1
# Code: //! The actual phase-by-phase driver for `POST /api/pipeline` — split
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/pipeline_interactive.rs::1::low-maintainability
# Issue #109
# [WARNING] complexity-health - Maintainability Index 29/100 — below the 40 threshold (complexity 44 over 925 lines of code).
#   rust/crates/server/src/routes/pipeline_interactive.rs:1
# Code: //! POST /api/pipeline — faithful port of routes/pipeline-interactive.js:
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/github_pr_status.rs::1::low-maintainability
# Issue #110
# [WARNING] complexity-health - Maintainability Index 33/100 — below the 40 threshold (complexity 57 over 337 lines of code).
#   rust/crates/server/src/routes/github_pr_status.rs:1
# Code: //! POST /api/pipeline/:jobId/github-check — faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/pipeline_validate.rs::1::low-maintainability
# Issue #111
# [WARNING] complexity-health - Maintainability Index 26/100 — below the 40 threshold (complexity 70 over 750 lines of code).
#   rust/crates/server/src/routes/pipeline_validate.rs:1
# Code: //! POST /api/pipeline/validate-all — faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/github-api/src/lib.rs::1::low-maintainability
# Issue #112
# [WARNING] complexity-health - Maintainability Index 28/100 — below the 40 threshold (complexity 53 over 751 lines of code).
#   rust/crates/github-api/src/lib.rs:1
# Code: //! Faithful port of `lib/github-api.js` — GitHub API access without
Acknowledge: 

ID: complexity-health::rust/crates/fs-utils/src/lib.rs::1::low-maintainability
# Issue #113
# [WARNING] complexity-health - Maintainability Index 30/100 — below the 40 threshold (complexity 56 over 570 lines of code).
#   rust/crates/fs-utils/src/lib.rs:1
# Code: //! Pure filesystem/content helpers shared by Ignite's checks — file
Acknowledge: 

ID: complexity-health::rust/crates/fix-pr/src/lib.rs::1::low-maintainability
# Issue #114
# [WARNING] complexity-health - Maintainability Index 24/100 — below the 40 threshold (complexity 71 over 1093 lines of code).
#   rust/crates/fix-pr/src/lib.rs:1
# Code: //! Bulk "fix all findings" PR generator — the scan-wide counterpart to
Acknowledge: 

ID: complexity-health::rust/crates/cli/src/acknowledgments.rs::1::low-maintainability
# Issue #115
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 24 over 344 lines of code).
#   rust/crates/cli/src/acknowledgments.rs:1
# Code: //! Parsing and regeneration of `.ignite/acknowledgments.md` — ported from
Acknowledge: 

ID: complexity-health::rust/crates/llm-deep-scan/src/lib.rs::1::low-maintainability
# Issue #116
# [WARNING] complexity-health - Maintainability Index 28/100 — below the 40 threshold (complexity 66 over 602 lines of code).
#   rust/crates/llm-deep-scan/src/lib.rs:1
# Code: //! Local LLM (Ollama/llama.cpp-compatible, or OpenAI) security/quality
Acknowledge: 

ID: complexity-health::rust/crates/dependency-license-scan/src/lib.rs::1::low-maintainability
# Issue #117
# [WARNING] complexity-health - Maintainability Index 16/100 — below the 40 threshold (complexity 131 over 1664 lines of code).
#   rust/crates/dependency-license-scan/src/lib.rs:1
# Code: //! Dependency license/vulnerability scan orchestrators. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/llm-client/src/lib.rs::1::low-maintainability
# Issue #118
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 20 over 438 lines of code).
#   rust/crates/llm-client/src/lib.rs:1
# Code: //! Shared local-LLM/OpenAI chat-completions client. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/phase4-orchestrator/src/lib.rs::1::low-maintainability
# Issue #119
# [WARNING] complexity-health - Maintainability Index 27/100 — below the 40 threshold (complexity 46 over 1185 lines of code).
#   rust/crates/phase4-orchestrator/src/lib.rs:1
# Code: //! Phase 4 check orchestrator. Faithful port of server.js's
Acknowledge: 

ID: complexity-health::rust/crates/package-hallucination/src/lib.rs::1::low-maintainability
# Issue #120
# [WARNING] complexity-health - Maintainability Index 36/100 — below the 40 threshold (complexity 33 over 365 lines of code).
#   rust/crates/package-hallucination/src/lib.rs:1
# Code: //! AI package-hallucination / slopsquat detection. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/gha-security/src/lib.rs::1::low-maintainability
# Issue #121
# [WARNING] complexity-health - Maintainability Index 38/100 — below the 40 threshold (complexity 22 over 436 lines of code).
#   rust/crates/gha-security/src/lib.rs:1
# Code: //! GitHub Actions workflow security scan via zizmor (Trail of Bits'
Acknowledge: 

ID: complexity-health::rust/crates/tool-runner/src/lib.rs::1::low-maintainability
# Issue #122
# [WARNING] complexity-health - Maintainability Index 27/100 — below the 40 threshold (complexity 67 over 640 lines of code).
#   rust/crates/tool-runner/src/lib.rs:1
# Code: //! External-tool process execution + the sanitizers that guard it — every
Acknowledge: 

ID: complexity-health::rust/crates/complexity-health/src/lib.rs::1::low-maintainability
# Issue #123
# [WARNING] complexity-health - Maintainability Index 31/100 — below the 40 threshold (complexity 51 over 543 lines of code).
#   rust/crates/complexity-health/src/lib.rs:1
# Code: //! Built-in complexity/maintainability health scan. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/container-image-vulnerabilities/src/lib.rs::1::low-maintainability
# Issue #124
# [WARNING] complexity-health - Maintainability Index 38/100 — below the 40 threshold (complexity 30 over 316 lines of code).
#   rust/crates/container-image-vulnerabilities/src/lib.rs:1
# Code: //! Builds every discovered Dockerfile and runs `trivy image` against the
Acknowledge: 

ID: complexity-health::rust/crates/module-graph/src/lib.rs::1::low-maintainability
# Issue #125
# [WARNING] complexity-health - Maintainability Index 31/100 — below the 40 threshold (complexity 54 over 474 lines of code).
#   rust/crates/module-graph/src/lib.rs:1
# Code: //! Lightweight JS/TS module graph: parses import/require/export statements
Acknowledge: 

ID: complexity-health::rust/crates/enforce-gate-branch-protection/src/lib.rs::1::low-maintainability
# Issue #126
# [WARNING] complexity-health - Maintainability Index 35/100 — below the 40 threshold (complexity 23 over 676 lines of code).
#   rust/crates/enforce-gate-branch-protection/src/lib.rs:1
# Code: //! `enforce-gate-branch-protection <org/repo> [<org/repo>...] [--apply]` —
Acknowledge: 

ID: complexity-health::rust/crates/report-vulnerability/src/main.rs::1::low-maintainability
# Issue #127
# [WARNING] complexity-health - Maintainability Index 34/100 — below the 40 threshold (complexity 30 over 568 lines of code).
#   rust/crates/report-vulnerability/src/main.rs:1
# Code: //! `report-vulnerability <org/repo> --summary <str> --severity <level>
Acknowledge: 

ID: complexity-health::rust/crates/pii-dataflow/src/lib.rs::1::low-maintainability
# Issue #128
# [WARNING] complexity-health - Maintainability Index 33/100 — below the 40 threshold (complexity 47 over 403 lines of code).
#   rust/crates/pii-dataflow/src/lib.rs:1
# Code: //! Sensitive data-flow (PII/GDPR) SAST via Bearer. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/governance-ci/src/lib.rs::1::low-maintainability
# Issue #129
# [WARNING] complexity-health - Maintainability Index 38/100 — below the 40 threshold (complexity 33 over 290 lines of code).
#   rust/crates/governance-ci/src/lib.rs:1
# Code: //! Phase 5: org governance CI, run locally via `act`. Faithful port of
Acknowledge: 

ID: complexity-health::public/i18n.js::1::low-maintainability
# Issue #130
# [WARNING] complexity-health - Maintainability Index 30/100 — below the 40 threshold (complexity 31 over 1246 lines of code).
#   public/i18n.js:1
# Code: // Ignite web UI translations — static UI chrome only (buttons, labels,
Acknowledge: 

ID: complexity-health::vscode-extension/src/panels/findingsTree.ts::1::low-maintainability
# Issue #131
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 41 over 179 lines of code).
#   vscode-extension/src/panels/findingsTree.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::vscode-extension/src/panels/reportPanel.ts::1::low-maintainability
# Issue #132
# [WARNING] complexity-health - Maintainability Index 34/100 — below the 40 threshold (complexity 56 over 273 lines of code).
#   vscode-extension/src/panels/reportPanel.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::vscode-extension/src/extension.ts::1::low-maintainability
# Issue #133
# [WARNING] complexity-health - Maintainability Index 27/100 — below the 40 threshold (complexity 91 over 488 lines of code).
#   vscode-extension/src/extension.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::vscode-extension/src/api.ts::1::low-maintainability
# Issue #134
# [WARNING] complexity-health - Maintainability Index 30/100 — below the 40 threshold (complexity 68 over 397 lines of code).
#   vscode-extension/src/api.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::vscode-extension/src/reviewFile.ts::1::low-maintainability
# Issue #135
# [WARNING] complexity-health - Maintainability Index 37/100 — below the 40 threshold (complexity 46 over 226 lines of code).
#   vscode-extension/src/reviewFile.ts:1
# Code: import * as fs from 'fs/promises';
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::7aa895fb
# Issue #136
# [WARNING] css-dead-code - CSS class ".infima" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::3239fc7e
# Issue #137
# [WARNING] css-dead-code - CSS class ".theme-common" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::8b93d74d
# Issue #138
# [WARNING] css-dead-code - CSS class ".theme-classic" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::7246118d
# Issue #139
# [WARNING] css-dead-code - CSS class ".core" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::c98c98f5
# Issue #140
# [WARNING] css-dead-code - CSS class ".plugin-debug" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::ae40698e
# Issue #141
# [WARNING] css-dead-code - CSS class ".theme-mermaid" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::f63f75e9
# Issue #142
# [WARNING] css-dead-code - CSS class ".theme-live-codeblock" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::59b3bc2f
# Issue #143
# [WARNING] css-dead-code - CSS class ".theme-search-algolia" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::9cc5937b
# Issue #144
# [WARNING] css-dead-code - CSS class ".docsearch" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::32::unused-css-class
# Issue #145
# [WARNING] css-dead-code - CSS class ".markdown" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:32
# Code: .markdown {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::88::unused-css-class
# Issue #146
# [WARNING] css-dead-code - CSS class ".theme-admonition" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:88
# Code: .theme-admonition {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::95::unused-css-class
# Issue #147
# [WARNING] css-dead-code - CSS class ".theme-doc-markdown" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:95
# Code: .theme-doc-markdown table {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::173::unused-css-class
# Issue #148
# [WARNING] css-dead-code - CSS class ".heroShot" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:173
# Code: .heroShot {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::193::unused-css-class
# Issue #149
# [WARNING] css-dead-code - CSS class ".phaseDiagram" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:193
# Code: .phaseDiagram {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::209::unused-css-class
# Issue #150
# [WARNING] css-dead-code - CSS class ".phase-link" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs-site/src/css/custom.css:209
# Code: .phase-link {
Acknowledge: 

ID: css-dead-code::docs/assets/css/style.scss::4::unused-css-class
# Issue #151
# [WARNING] css-dead-code - CSS class ".theme" is declared in docs/assets/css/style.scss but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs/assets/css/style.scss:4
# Code: @import "{{ site.theme }}";
Acknowledge: 

ID: css-dead-code::docs/assets/css/style.scss::6::unused-css-class
# Issue #152
# [WARNING] css-dead-code - CSS class ".main-content" is declared in docs/assets/css/style.scss but never referenced in a class/className attribute across 32 scanned markup file(s).
#   docs/assets/css/style.scss:6
# Code: // Cayman's default .main-content is a fixed ~64rem column with no overflow
Acknowledge: 

ID: dependency-vulnerability::rust/crates/server/Cargo.toml::60::jsonwebtoken::GHSA-h395-gr6q-cpjc
# Issue #153
# [WARNING] dependency-vulnerability - jsonwebtoken@9.3.1 — GHSA-h395-gr6q-cpjc: jsonwebtoken has Type Confusion that leads to potential authorization bypass (CVE-2026-25537) (CVSS 0)
#   rust/crates/server/Cargo.toml:60
# Code: jsonwebtoken = "9"
Acknowledge: 

ID: secret::rust/crates/config/src/lib.rs::1340
# Issue #154
# [ERROR] secret - Hardcoded api_key
#   rust/crates/config/src/lib.rs:1340
# Code: cfg.llm.openai.api_key = "sk-live-supersecret".to_string();
Acknowledge: Fabricated OpenAI-format API key literal used only to verify Config's new redacting Debug impl (debug_redacts_secret_fields_but_keeps_non_secret_fields_visible) actually hides secret fields from {:?} output - not a real credential. (auto-carried-forward from secret::rust/crates/config/src/lib.rs::1290 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/config/src/lib.rs::1307 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/config/src/lib.rs::1323 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/config/src/lib.rs::1341
# Issue #155
# [ERROR] secret - Hardcoded secret
#   rust/crates/config/src/lib.rs:1341
# Code: cfg.github.oauth.client_secret = "oauth-secret-value".to_string();
Acknowledge: Same test as the entry above - a fabricated OAuth client secret literal used only to verify the redacting Debug impl, not a real credential. (auto-carried-forward from secret::rust/crates/config/src/lib.rs::1291 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/config/src/lib.rs::1308 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/config/src/lib.rs::1324 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::790
# Issue #156
# [ERROR] secret - Hardcoded api_key
#   rust/crates/secrets/src/lib.rs:790
# Code: fs::write(root.join("config.js"), "const api_key = 'sk-proj-abcdefghijklmnop';\n").unwrap();
Acknowledge: Fake API key literal used as test input for run_gitleaks_history_scan_no_ops_without_a_git_directory (verifies the history scan is a no-op with no .git directory) - not a real credential, same fixture literal already acknowledged elsewhere in this file for the same reason. (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::579 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::694 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::710 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::726 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::757 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::778 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::894
# Issue #157
# [ERROR] secret - Hardcoded connection-string credential
#   rust/crates/secrets/src/lib.rs:894
# Code: "DATABASE_URL = \"postgresql://testuser:not-a-real-pw@x@example.com:5432/testdb\"\n",
Acknowledge: Test-fixture connection string for flags_a_password_embedded_in_a_connection_string - example.com is IANA/RFC 2606-reserved for documentation and the password is labeled a placeholder outright in the surrounding comment, not a real credential. (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::683 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::798 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::814 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::830 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::861 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::882 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/server/src/routes/custom_secret_patterns.rs::210
# Issue #158
# [ERROR] secret - Hardcoded generic-api-key
#   rust/crates/server/src/routes/custom_secret_patterns.rs:210
# Code: let req = Request::post("/api/secret-patterns/test").header("content-type", "application/json").body(Body::from(r#"{"regex":"sk_live_[a-z0-9]+","sample":"key: sk_live_abc123"}"#)).unwrap();
Acknowledge: Fabricated Stripe-format sample string used as request-body input to the custom-secret-pattern playground's own unit test (test_pattern_route_reports_matches_without_persisting_anything) - the whole point of this endpoint is to test a regex against sample text, so a plausible-looking fake match is expected input, not a real credential. (auto-carried-forward from secret::rust/crates/server/src/routes/custom_secret_patterns.rs::193 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/custom_secret_patterns.rs::203 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/server/src/routes/custom_secret_patterns.rs::207 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::1022
# Issue #159
# [ERROR] secret - Hardcoded stripe-access-token
#   rust/crates/secrets/src/lib.rs:1022
# Code: let matches = test_pattern_against_sample(r"sk_live_[a-zA-Z0-9]{16,}", "key one: sk_live_abcdef0123456789, key two: sk_live_zzzzzz9999999999").unwrap();
Acknowledge: Fabricated Stripe-format sample text (test_pattern_against_sample_finds_all_matches) verifying the custom-secret-pattern regex tester finds every match in a sample, not a real credential - same fixture literal flagged again at the two assert_eq! lines immediately below for the same reason. (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::927 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::943 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::959 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::990 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::989 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::1010 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::1024
# Issue #160
# [ERROR] secret - Hardcoded stripe-access-token
#   rust/crates/secrets/src/lib.rs:1024
# Code: assert_eq!(matches[0].matched_text, "sk_live_abcdef0123456789");
Acknowledge: Same fabricated Stripe-format fixture literal as the entry above, asserted as the expected match text in the same test - not a real credential. (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::929 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::945 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::961 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::992 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::991 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::1012 - pure line-number drift, flagged code unchanged)

ID: secret::rust/crates/secrets/src/lib.rs::1025
# Issue #161
# [ERROR] secret - Hardcoded stripe-access-token
#   rust/crates/secrets/src/lib.rs:1025
# Code: assert_eq!(matches[1].matched_text, "sk_live_zzzzzz9999999999");
Acknowledge: Same fabricated Stripe-format fixture literal as the two entries above, asserted as the expected second match in the same regex-tester unit test — not a real credential. (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::992 - pure line-number drift, flagged code unchanged) (auto-carried-forward from secret::rust/crates/secrets/src/lib.rs::1013 - pure line-number drift, flagged code unchanged)

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1
# Issue #162
# [WARNING] code-duplication - 2468-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T23-32-33Z/findings.md:markdown:1-2468.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::7
# Issue #163
# [WARNING] code-duplication - 2624-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:19-2600.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:7
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::19
# Issue #164
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:19-39.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:19
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::37::d777631f
# Issue #165
# [WARNING] code-duplication - 347-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:49-395.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:37
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::37::d11ec663
# Issue #166
# [WARNING] code-duplication - 23-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:61-83.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:37
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::37::2c9bc329
# Issue #167
# [WARNING] code-duplication - 1336-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:61-1404.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:37
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::157::5ea8132b
# Issue #168
# [WARNING] code-duplication - 1774-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:193-1966.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:157
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::157::31cadcdb
# Issue #169
# [WARNING] code-duplication - 2159-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:205-2370.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:157
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::385
# Issue #170
# [WARNING] code-duplication - 34-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:390-423.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:385
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::413
# Issue #171
# [WARNING] code-duplication - 279-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:425-703.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:413
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::693
# Issue #172
# [WARNING] code-duplication - 34-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:698-731.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:693
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::721
# Issue #173
# [WARNING] code-duplication - 27-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:733-759.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:721
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::749
# Issue #174
# [WARNING] code-duplication - 34-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:754-787.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:749
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::777
# Issue #175
# [WARNING] code-duplication - 27-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:789-815.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:777
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::805
# Issue #176
# [WARNING] code-duplication - 34-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:810-843.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:805
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::833
# Issue #177
# [WARNING] code-duplication - 475-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:845-1319.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:833
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1302
# Issue #178
# [WARNING] code-duplication - 2491-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:1321-3708.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1302
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1349
# Issue #179
# [WARNING] code-duplication - 1282-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:1404-2636.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1349
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1449
# Issue #180
# [WARNING] code-duplication - 160-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1617-1776.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1449
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1601::1c71e55a
# Issue #181
# [WARNING] code-duplication - 22-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2364-2385.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1601
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1601::9ab2706b
# Issue #182
# [WARNING] code-duplication - 22-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:1959-1980.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1601
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1769
# Issue #183
# [WARNING] code-duplication - 22-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1916-1937.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1769
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1862::8e957f71
# Issue #184
# [WARNING] code-duplication - 62-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1932-1993.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1862
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1862::f96d8035
# Issue #185
# [WARNING] code-duplication - 209-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:2372-2580.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1862
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1988
# Issue #186
# [WARNING] code-duplication - 583-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:1975-2505.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1988
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2468
# Issue #187
# [WARNING] code-duplication - 447-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T23-32-33Z/findings.md:markdown:2498-2944.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2468
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2493
# Issue #188
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:2578-2601.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2493
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2518::2ce71a3c
# Issue #189
# [WARNING] code-duplication - 53-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2535-2587.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2518
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2518::0c716063
# Issue #190
# [WARNING] code-duplication - 165-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:2610-2773.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2518
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2560
# Issue #191
# [WARNING] code-duplication - 591-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:2602-3166.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2560
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2567
# Issue #192
# [WARNING] code-duplication - 96-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2591-2686.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2567
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2676
# Issue #193
# [WARNING] code-duplication - 65-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2712-2776.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2676
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2778
# Issue #194
# [WARNING] code-duplication - 23-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2832-2854.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2778
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2808::55f9e092
# Issue #195
# [WARNING] code-duplication - 59-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2874-2932.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2808
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2808::dee4ee7f
# Issue #196
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:2973-3001.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2808
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::2862
# Issue #197
# [WARNING] code-duplication - 53-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2934-2986.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2862
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3078::b2415995
# Issue #198
# [WARNING] code-duplication - 209-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T23-32-33Z/findings.md:markdown:2940-3148.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3078
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3078::b2986824
# Issue #199
# [WARNING] code-duplication - 35-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2994-3028.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3078
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3108::d7b66c38
# Issue #200
# [WARNING] code-duplication - 71-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3036-3106.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3108
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3108::ef5d5c8c
# Issue #201
# [WARNING] code-duplication - 71-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3123-3193.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3108
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3180
# Issue #202
# [WARNING] code-duplication - 41-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3126-3166.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3180
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3264
# Issue #203
# [WARNING] code-duplication - 23-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3240-3262.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3264
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3408
# Issue #204
# [WARNING] code-duplication - 124-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T23-32-33Z/findings.md:markdown:3144-3267.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3408
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3414
# Issue #205
# [WARNING] code-duplication - 41-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3210-3250.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3414
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3420::f24a55e7
# Issue #206
# [WARNING] code-duplication - 196-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3324-3507.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3420
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3420::dd6a639d
# Issue #207
# [WARNING] code-duplication - 277-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3411-3702.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3420
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3420::ac18ae69
# Issue #208
# [WARNING] code-duplication - 114-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3447-3559.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3420
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3555
# Issue #209
# [WARNING] code-duplication - 31-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T23-32-33Z/findings.md:markdown:3267-3297.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3555
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3589::4eb20dac
# Issue #210
# [WARNING] code-duplication - 63-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T23-32-33Z/findings.md:markdown:3295-3357.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3589
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3589::da00e72f
# Issue #211
# [WARNING] code-duplication - 75-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3403-3477.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3589
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3601
# Issue #212
# [WARNING] code-duplication - 23-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3583-3605.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3601
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3649
# Issue #213
# [WARNING] code-duplication - 205-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T23-32-33Z/findings.md:markdown:3379-3583.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3649
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3687
# Issue #214
# [WARNING] code-duplication - 134-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3511-3644.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3687
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3746::2c991cb6
# Issue #215
# [WARNING] code-duplication - 40-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3756-3795.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3746
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3746::f60a96c7
# Issue #216
# [WARNING] code-duplication - 40-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3849-3888.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3746
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3748
# Issue #217
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3894-3917.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3748
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::3822
# Issue #218
# [WARNING] code-duplication - 32-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3646-3677.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:3822
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::1::d99b668c
# Issue #219
# [WARNING] code-duplication - 3341-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T14-44-39Z/findings.md:markdown:1-3341.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::1::42b978eb
# Issue #220
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T10-55-25Z/findings.md:markdown:1-21.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::1::4c885fe7
# Issue #221
# [WARNING] code-duplication - 3491-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T11-06-25Z/findings.md:markdown:1-3496.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::1::e39e20c9
# Issue #222
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:1-21.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::1::feca0e32
# Issue #223
# [WARNING] code-duplication - 27-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:1-27.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::1::3e58a765
# Issue #224
# [WARNING] code-duplication - 27-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:1-27.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::3162
# Issue #225
# [WARNING] code-duplication - 53-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3270-3322.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3162
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::3373::ab910920
# Issue #226
# [WARNING] code-duplication - 117-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T14-44-39Z/findings.md:markdown:3397-3513.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3373
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::3373::6f27c6f6
# Issue #227
# [WARNING] code-duplication - 35-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3535-3569.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3373
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::3489::3eb26946
# Issue #228
# [WARNING] code-duplication - 189-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T14-44-39Z/findings.md:markdown:3513-3701.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3489
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::3489::e028ca19
# Issue #229
# [WARNING] code-duplication - 32-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3675-3706.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3489
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::3489::9290f604
# Issue #230
# [WARNING] code-duplication - 32-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3768-3799.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3489
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::3489::bb307fcc
# Issue #231
# [WARNING] code-duplication - 86-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3804-3889.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3489
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown::3645
# Issue #232
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3844-3868.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T00-30-10Z/findings.md:markdown:3645
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T14-44-39Z/findings.md:markdown::3336
# Issue #233
# [WARNING] code-duplication - 174-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3567-3750.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T14-44-39Z/findings.md:markdown:3336
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T14-44-39Z/findings.md:markdown::3499
# Issue #234
# [WARNING] code-duplication - 203-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T11-06-25Z/findings.md:markdown:3506-3708.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-21T14-44-39Z/findings.md:markdown:3499
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T21-40-37Z/findings.md:markdown::1
# Issue #235
# [WARNING] code-duplication - 27-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-23-19Z/findings.md:markdown:1-27.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T21-40-37Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::6
# Issue #236
# [WARNING] code-duplication - 76-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:6-81.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:6
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::25
# Issue #237
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:37-57.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:25
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::55
# Issue #238
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:55-83.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:55
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::65
# Issue #239
# [WARNING] code-duplication - 141-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:65-205.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:65
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::2493
# Issue #240
# [WARNING] code-duplication - 63-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:2493-2555.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2493
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::2570
# Issue #241
# [WARNING] code-duplication - 51-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:2645-2695.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2570
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::2669
# Issue #242
# [WARNING] code-duplication - 61-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:2669-2729.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2669
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::2700
# Issue #243
# [WARNING] code-duplication - 77-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:2775-2851.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2700
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::2772
# Issue #244
# [WARNING] code-duplication - 269-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:2853-3121.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2772
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::2778
# Issue #245
# [WARNING] code-duplication - 35-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:2859-2893.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2778
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::2850
# Issue #246
# [WARNING] code-duplication - 23-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:2949-2971.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2850
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::2928
# Issue #247
# [WARNING] code-duplication - 71-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3027-3097.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:2928
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3089
# Issue #248
# [WARNING] code-duplication - 55-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:3089-3143.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3089
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3120
# Issue #249
# [WARNING] code-duplication - 155-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3207-3361.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3120
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3174
# Issue #250
# [WARNING] code-duplication - 23-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3285-3307.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3174
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3228
# Issue #251
# [WARNING] code-duplication - 95-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3351-3445.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3228
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3304
# Issue #252
# [WARNING] code-duplication - 41-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:3304-3344.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3304
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3491
# Issue #253
# [WARNING] code-duplication - 65-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:3491-3555.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3491
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3551
# Issue #254
# [WARNING] code-duplication - 50-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:3551-3600.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3551
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3587
# Issue #255
# [WARNING] code-duplication - 101-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:3587-3687.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3587
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3629
# Issue #256
# [WARNING] code-duplication - 17-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3722-3738.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3629
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3692
# Issue #257
# [WARNING] code-duplication - 83-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:3692-3774.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3692
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3781
# Issue #258
# [WARNING] code-duplication - 80-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:3781-3860.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3781
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3797
# Issue #259
# [WARNING] code-duplication - 72-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3890-3961.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3797
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3806
# Issue #260
# [WARNING] code-duplication - 63-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3942-4004.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3806
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3854
# Issue #261
# [WARNING] code-duplication - 1157-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T23-28-59Z/findings.md:markdown:3854-5012.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3854
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3876::dab55e59
# Issue #262
# [WARNING] code-duplication - 159-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3969-4127.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3876
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::3876::c89620ee
# Issue #263
# [WARNING] code-duplication - 149-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:4012-4160.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:3876
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4032
# Issue #264
# [WARNING] code-duplication - 225-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4131-4355.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4032
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4250
# Issue #265
# [WARNING] code-duplication - 31-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4355-4385.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4250
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4274
# Issue #266
# [WARNING] code-duplication - 73-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4391-4463.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4274
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4320
# Issue #267
# [WARNING] code-duplication - 39-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:4498-4536.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4320
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4346
# Issue #268
# [WARNING] code-duplication - 37-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4463-4499.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4346
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4360
# Issue #269
# [WARNING] code-duplication - 59-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:4538-4596.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4360
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4382
# Issue #270
# [WARNING] code-duplication - 37-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4499-4535.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4382
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4418::192df351
# Issue #271
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4535-4559.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4418
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4418::7403f82a
# Issue #272
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:4596-4614.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4418
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4450
# Issue #273
# [WARNING] code-duplication - 17-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4567-4583.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4450
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4478
# Issue #274
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4595-4619.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4478
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown::4520
# Issue #275
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4637-4661.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-22T22-30-23Z/findings.md:markdown:4520
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown::25
# Issue #276
# [WARNING] code-duplication - 33-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:31-63.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:25
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown::2757
# Issue #277
# [WARNING] code-duplication - 101-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:2757-2857.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:2757
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown::3117
# Issue #278
# [WARNING] code-duplication - 35-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3135-3169.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3117
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown::3189
# Issue #279
# [WARNING] code-duplication - 53-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3207-3259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3189
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown::3718
# Issue #280
# [WARNING] code-duplication - 39-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:3754-3792.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:3718
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown::4125
# Issue #281
# [WARNING] code-duplication - 315-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:4174-4488.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4125
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown::4553
# Issue #282
# [WARNING] code-duplication - 43-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:4620-4662.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4553
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown::4631
# Issue #283
# [WARNING] code-duplication - 37-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T10-12-23Z/findings.md:markdown:4698-4734.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-23T00-59-55Z/findings.md:markdown:4631
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::1::f95e88a1
# Issue #284
# [WARNING] code-duplication - 65-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-24-27Z/findings.md:markdown:1-65.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::1::3020b0bf
# Issue #285
# [WARNING] code-duplication - 2039-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-00-07Z/findings.md:markdown:1-2077.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::1::cb5dfa99
# Issue #286
# [WARNING] code-duplication - 81-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-02-22Z/findings.md:markdown:1-81.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::1::2e3f54f0
# Issue #287
# [WARNING] code-duplication - 97-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-20-15Z/findings.md:markdown:1-97.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::1::2b040d16
# Issue #288
# [WARNING] code-duplication - 97-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-22-58Z/findings.md:markdown:1-97.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::3
# Issue #289
# [WARNING] code-duplication - 67-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-28-25Z/findings.md:markdown:5-71.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:3
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::73
# Issue #290
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-02-22Z/findings.md:markdown:73-97.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:73
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::79::99d2f61b
# Issue #291
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-28-25Z/findings.md:markdown:81-99.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:79
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown::79::b22fa695
# Issue #292
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-01-37Z/findings.md:markdown:81-105.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-03-44Z/findings.md:markdown:79
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-24-27Z/findings.md:markdown::79
# Issue #293
# [WARNING] code-duplication - 1257-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-14-12Z/findings.md:markdown:81-1337.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-24-27Z/findings.md:markdown:79
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-24-27Z/findings.md:markdown::1613
# Issue #294
# [WARNING] code-duplication - 383-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:1626-2008.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T13-24-27Z/findings.md:markdown:1613
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-03-21Z/findings.md:markdown::1::4c88215b
# Issue #295
# [WARNING] code-duplication - 1239-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-21-30Z/findings.md:markdown:1-1239.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-03-21Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-03-21Z/findings.md:markdown::1::1b2556c0
# Issue #296
# [WARNING] code-duplication - 1829-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-26-54Z/findings.md:markdown:1-1825.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-03-21Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-03-21Z/findings.md:markdown::3
# Issue #297
# [WARNING] code-duplication - 1825-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-34-18Z/findings.md:markdown:5-1821.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-03-21Z/findings.md:markdown:3
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-28-25Z/findings.md:markdown::1::0a59ad2d
# Issue #298
# [WARNING] code-duplication - 71-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-01-37Z/findings.md:markdown:1-71.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-28-25Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-28-25Z/findings.md:markdown::1::9082c56c
# Issue #299
# [WARNING] code-duplication - 83-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-14-12Z/findings.md:markdown:1-83.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-28-25Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-34-18Z/findings.md:markdown::1::28e3c460
# Issue #300
# [WARNING] code-duplication - 1821-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-40-55Z/findings.md:markdown:1-1821.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-34-18Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-34-18Z/findings.md:markdown::1::3185d8e8
# Issue #301
# [WARNING] code-duplication - 1821-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-07-21Z/findings.md:markdown:1-1821.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T14-34-18Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown::5::1c81aab2
# Issue #302
# [WARNING] code-duplication - 73-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-47-42Z/findings.md:markdown:5-77.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown::5::2764c0f8
# Issue #303
# [WARNING] code-duplication - 3291-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T18-00-32Z/findings.md:markdown:5-3295.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown::5::718e38e9
# Issue #304
# [WARNING] code-duplication - 64-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T18-46-14Z/findings.md:markdown:5-68.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown::5::3f459835
# Issue #305
# [WARNING] code-duplication - 3859-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T20-46-36Z/findings.md:markdown:5-3863.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown::5::b25d3202
# Issue #306
# [WARNING] code-duplication - 52-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T21-26-22Z/findings.md:markdown:5-56.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown::86
# Issue #307
# [WARNING] code-duplication - 3778-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-47-42Z/findings.md:markdown:86-3863.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown:86
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown::3305
# Issue #308
# [WARNING] code-duplication - 559-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T18-00-32Z/findings.md:markdown:3305-3863.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown:3305
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown::3419
# Issue #309
# [WARNING] code-duplication - 445-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T18-46-14Z/findings.md:markdown:3419-3863.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-46-54Z/findings.md:markdown:3419
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-47-42Z/findings.md:markdown::79
# Issue #310
# [WARNING] code-duplication - 3291-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T18-46-14Z/findings.md:markdown:79-3369.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-30T15-47-42Z/findings.md:markdown:79
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-37-40Z/findings.md:markdown::5::06303443
# Issue #311
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:5-33.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-37-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-37-40Z/findings.md:markdown::5::63f6e60a
# Issue #312
# [WARNING] code-duplication - 17-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T19-39-48Z/findings.md:markdown:5-21.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-37-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-37-40Z/findings.md:markdown::5::62366a77
# Issue #313
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T19-40-39Z/findings.md:markdown:5-23.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-37-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::23::a2194d1e
# Issue #314
# [WARNING] code-duplication - 1175-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T19-07-01Z/findings.md:markdown:23-1197.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:23
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::23::d6bf86fc
# Issue #315
# [WARNING] code-duplication - 1463-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T19-40-39Z/findings.md:markdown:23-1485.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:23
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::30
# Issue #316
# [WARNING] code-duplication - 1120-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T21-05-59Z/findings.md:markdown:30-1149.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:30
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::1177
# Issue #317
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T21-05-59Z/findings.md:markdown:1177-1197.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:1177
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::1203
# Issue #318
# [WARNING] code-duplication - 97-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T19-07-01Z/findings.md:markdown:1203-1299.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:1203
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::1209
# Issue #319
# [WARNING] code-duplication - 91-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T21-05-59Z/findings.md:markdown:1209-1299.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:1209
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::1305
# Issue #320
# [WARNING] code-duplication - 365-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T19-07-01Z/findings.md:markdown:1305-1669.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:1305
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::1437
# Issue #321
# [WARNING] code-duplication - 85-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T21-05-59Z/findings.md:markdown:1437-1521.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:1437
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::1485
# Issue #322
# [WARNING] code-duplication - 185-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T19-40-39Z/findings.md:markdown:1485-1669.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:1485
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown::1521
# Issue #323
# [WARNING] code-duplication - 149-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T21-05-59Z/findings.md:markdown:1521-1669.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T18-39-43Z/findings.md:markdown:1521
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T19-07-01Z/findings.md:markdown::1299
# Issue #324
# [WARNING] code-duplication - 139-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T21-05-59Z/findings.md:markdown:1299-1437.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T19-07-01Z/findings.md:markdown:1299
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T19-40-39Z/findings.md:markdown::16
# Issue #325
# [WARNING] code-duplication - 1146-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T19-53-42Z/findings.md:markdown:16-1161.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T19-40-39Z/findings.md:markdown:16
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T19-53-42Z/findings.md:markdown::5
# Issue #326
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T21-05-59Z/findings.md:markdown:5-28.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-08-31T19-53-42Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T21-55-27Z/findings.md:markdown::23
# Issue #327
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown:26-54.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T21-55-27Z/findings.md:markdown:23
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T21-55-27Z/findings.md:markdown::48
# Issue #328
# [WARNING] code-duplication - 118-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-15-12Z/findings.md:markdown:51-168.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T21-55-27Z/findings.md:markdown:48
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-15-12Z/findings.md:markdown::1
# Issue #329
# [WARNING] code-duplication - 40-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown:1-40.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-15-12Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-15-12Z/findings.md:markdown::12
# Issue #330
# [WARNING] code-duplication - 47-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-01-23Z/findings.md:markdown:11-57.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-15-12Z/findings.md:markdown:12
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown::44
# Issue #331
# [WARNING] code-duplication - 31-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-49-45Z/findings.md:markdown:44-74.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown:44
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown::51
# Issue #332
# [WARNING] code-duplication - 2258-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T00-40-33Z/findings.md:markdown:51-2347.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown:51
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown::3286::e8bad232
# Issue #333
# [WARNING] code-duplication - 524-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-44-54Z/findings.md:markdown:3286-3809.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown:3286
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown::3286::3cda3db6
# Issue #334
# [WARNING] code-duplication - 232-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:3286-3517.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown:3286
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown::3517
# Issue #335
# [WARNING] code-duplication - 293-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:3517-3809.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T22-43-30Z/findings.md:markdown:3517
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::1fb2f556
# Issue #336
# [WARNING] code-duplication - 2295-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown:5-2299.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::a5540059
# Issue #337
# [WARNING] code-duplication - 2304-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T00-22-33Z/findings.md:markdown:5-2347.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::8369a02c
# Issue #338
# [WARNING] code-duplication - 50-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T00-40-33Z/findings.md:markdown:5-54.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::ad3a3415
# Issue #339
# [WARNING] code-duplication - 38-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown:5-42.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::31cb6953
# Issue #340
# [WARNING] code-duplication - 68-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown:5-65.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::d250c917
# Issue #341
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-48-30Z/findings.md:markdown:5-33.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::37e576b3
# Issue #342
# [WARNING] code-duplication - 40-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-49-45Z/findings.md:markdown:5-44.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::3670f4e3
# Issue #343
# [WARNING] code-duplication - 2295-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T16-46-55Z/findings.md:markdown:5-2323.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::33f234aa
# Issue #344
# [WARNING] code-duplication - 2295-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T18-46-03Z/findings.md:markdown:5-2323.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::9eb60188
# Issue #345
# [WARNING] code-duplication - 45-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T23-23-37Z/findings.md:markdown:5-49.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::344e5f2b
# Issue #346
# [WARNING] code-duplication - 22-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:5-26.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::0dc2945b
# Issue #347
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-04-18Z/findings.md:markdown:5-30.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::84ae6d3d
# Issue #348
# [WARNING] code-duplication - 36-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown:5-40.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::816dcea8
# Issue #349
# [WARNING] code-duplication - 68-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T19-57-51Z/findings.md:markdown:5-68.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::6e35ce5d
# Issue #350
# [WARNING] code-duplication - 2301-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T19-59-28Z/findings.md:markdown:5-2358.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::f5f13c63
# Issue #351
# [WARNING] code-duplication - 2310-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T20-15-30Z/findings.md:markdown:5-2402.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::a3a69f6a
# Issue #352
# [WARNING] code-duplication - 2313-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T20-34-08Z/findings.md:markdown:5-2406.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::39164363
# Issue #353
# [WARNING] code-duplication - 2303-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T21-17-34Z/findings.md:markdown:5-2358.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::75fd7fb7
# Issue #354
# [WARNING] code-duplication - 2303-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T21-22-02Z/findings.md:markdown:5-2358.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::59e9c6b5
# Issue #355
# [WARNING] code-duplication - 2199-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T22-02-49Z/findings.md:markdown:5-2198.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::972d9d79
# Issue #356
# [WARNING] code-duplication - 43-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T22-05-02Z/findings.md:markdown:5-47.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::a400f97b
# Issue #357
# [WARNING] code-duplication - 2199-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T22-47-20Z/findings.md:markdown:5-2198.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::935195ae
# Issue #358
# [WARNING] code-duplication - 2303-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T22-52-48Z/findings.md:markdown:5-2358.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::4db55bda
# Issue #359
# [WARNING] code-duplication - 2313-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T23-36-56Z/findings.md:markdown:5-2406.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::157b0387
# Issue #360
# [WARNING] code-duplication - 22-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown:5-26.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::35753d98
# Issue #361
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:5-30.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::025f75d8
# Issue #362
# [WARNING] code-duplication - 74-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:5-79.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::85aa7fd5
# Issue #363
# [WARNING] code-duplication - 80-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-44-53Z/findings.md:markdown:5-84.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::1e431a90
# Issue #364
# [WARNING] code-duplication - 76-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-49-22Z/findings.md:markdown:5-82.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::7e5e829a
# Issue #365
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown:5-28.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::096e22a5
# Issue #366
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T10-39-34Z/findings.md:markdown:5-30.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::0488b107
# Issue #367
# [WARNING] code-duplication - 48-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T10-42-01Z/findings.md:markdown:5-54.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::ffa4350b
# Issue #368
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:5-28.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::9ab1401a
# Issue #369
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown:5-30.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::3480da65
# Issue #370
# [WARNING] code-duplication - 74-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T23-22-04Z/findings.md:markdown:5-82.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown::5::f9b84466
# Issue #371
# [WARNING] code-duplication - 2352-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T23-37-13Z/findings.md:markdown:5-2526.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-02-27Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown::3334::8c87f015
# Issue #372
# [WARNING] code-duplication - 190-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T00-22-33Z/findings.md:markdown:3334-3523.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown:3334
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown::3334::f7d53a7f
# Issue #373
# [WARNING] code-duplication - 190-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T00-40-33Z/findings.md:markdown:3334-3523.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown:3334
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown::3523::aa90a3df
# Issue #374
# [WARNING] code-duplication - 115-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T00-22-33Z/findings.md:markdown:3523-3637.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown:3523
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown::3523::9a43f285
# Issue #375
# [WARNING] code-duplication - 335-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T00-40-33Z/findings.md:markdown:3523-3857.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown:3523
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown::3637
# Issue #376
# [WARNING] code-duplication - 221-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T00-22-33Z/findings.md:markdown:3637-3857.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-01T23-48-19Z/findings.md:markdown:3637
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown::1188
# Issue #377
# [WARNING] code-duplication - 320-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:1181-1500.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown:1188
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown::1509
# Issue #378
# [WARNING] code-duplication - 145-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:1503-1647.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown:1509
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown::1655
# Issue #379
# [WARNING] code-duplication - 453-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:1650-2102.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown:1655
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown::2109
# Issue #380
# [WARNING] code-duplication - 82-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:2105-2186.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-42-56Z/findings.md:markdown:2109
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown::65
# Issue #381
# [WARNING] code-duplication - 1405-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T23-23-37Z/findings.md:markdown:67-1471.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown:65
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown::1471
# Issue #382
# [WARNING] code-duplication - 145-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T23-23-37Z/findings.md:markdown:1474-1618.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown:1471
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown::1617
# Issue #383
# [WARNING] code-duplication - 453-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T23-23-37Z/findings.md:markdown:1621-2073.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown:1617
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown::2071
# Issue #384
# [WARNING] code-duplication - 82-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T23-23-37Z/findings.md:markdown:2076-2157.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-02T15-45-36Z/findings.md:markdown:2071
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown::8
# Issue #385
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-04-18Z/findings.md:markdown:8-31.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:8
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown::32
# Issue #386
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown:33-51.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:32
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown::62
# Issue #387
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:63-86.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:62
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown::64
# Issue #388
# [WARNING] code-duplication - 460-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T19-57-51Z/findings.md:markdown:68-527.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:64
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown::538
# Issue #389
# [WARNING] code-duplication - 642-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T19-57-51Z/findings.md:markdown:544-1185.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:538
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown::1489
# Issue #390
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T19-57-51Z/findings.md:markdown:1496-1519.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:1489
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown::1636
# Issue #391
# [WARNING] code-duplication - 22-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T19-57-51Z/findings.md:markdown:1643-1664.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:1636
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown::2091
# Issue #392
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T19-57-51Z/findings.md:markdown:2098-2121.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-02-02Z/findings.md:markdown:2091
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-04-18Z/findings.md:markdown::80
# Issue #393
# [WARNING] code-duplication - 22-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:77-98.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-04-18Z/findings.md:markdown:80
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown::65
# Issue #394
# [WARNING] code-duplication - 2300-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T22-05-02Z/findings.md:markdown:65-2358.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown:65
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown::76
# Issue #395
# [WARNING] code-duplication - 91-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T10-42-01Z/findings.md:markdown:76-166.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown:76
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown::190
# Issue #396
# [WARNING] code-duplication - 50-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T10-42-01Z/findings.md:markdown:190-239.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown:190
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown::703
# Issue #397
# [WARNING] code-duplication - 566-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T10-39-34Z/findings.md:markdown:727-1292.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T15-05-51Z/findings.md:markdown:703
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T19-57-51Z/findings.md:markdown::65
# Issue #398
# [WARNING] code-duplication - 22-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:65-86.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T19-57-51Z/findings.md:markdown:65
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T21-17-34Z/findings.md:markdown::3627
# Issue #399
# [WARNING] code-duplication - 627-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T21-22-02Z/findings.md:markdown:3627-4253.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-03T21-17-34Z/findings.md:markdown:3627
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown::8
# Issue #400
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:8-31.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown:8
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown::36
# Issue #401
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown:36-61.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown:36
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown::38
# Issue #402
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:40-65.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown:38
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown::65
# Issue #403
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-49-22Z/findings.md:markdown:68-86.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-16-02Z/findings.md:markdown:65
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::37
# Issue #404
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T10-42-01Z/findings.md:markdown:37-65.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:37
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::72
# Issue #405
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:72-97.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:72
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::88
# Issue #406
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:86-114.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:88
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::106
# Issue #407
# [WARNING] code-duplication - 65-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:106-170.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:106
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::160
# Issue #408
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:166-194.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:160
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::178
# Issue #409
# [WARNING] code-duplication - 113-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:178-290.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:178
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::280
# Issue #410
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:302-330.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:280
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::298
# Issue #411
# [WARNING] code-duplication - 215-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:298-512.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:298
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::502
# Issue #412
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:557-585.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:502
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::518
# Issue #413
# [WARNING] code-duplication - 73-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:518-590.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:518
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::580
# Issue #414
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:644-672.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:580
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::610
# Issue #415
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:675-703.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:610
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::628
# Issue #416
# [WARNING] code-duplication - 496-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:628-1123.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:628
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::1114
# Issue #417
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:1259-1287.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:1114
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::1144
# Issue #418
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-51Z/findings.md:markdown:1290-1318.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:1144
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::1162
# Issue #419
# [WARNING] code-duplication - 87-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:1162-1248.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:1162
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown::1302
# Issue #420
# [WARNING] code-duplication - 31-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:1302-1332.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-22-01Z/findings.md:markdown:1302
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-49-22Z/findings.md:markdown::1
# Issue #421
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:1-21.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-49-22Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown::1240
# Issue #422
# [WARNING] code-duplication - 73-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown:1237-1309.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:1240
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown::1324
# Issue #423
# [WARNING] code-duplication - 183-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown:1321-1503.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:1324
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown::1498
# Issue #424
# [WARNING] code-duplication - 536-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown:1495-2028.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T07-54-15Z/findings.md:markdown:1498
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown::12
# Issue #425
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T10-39-34Z/findings.md:markdown:12-31.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown:12
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown::47
# Issue #426
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T10-42-01Z/findings.md:markdown:49-66.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T10-32-25Z/findings.md:markdown:47
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown::12
# Issue #427
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown:12-31.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:12
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown::48::d12414b2
# Issue #428
# [WARNING] code-duplication - 44-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-42-43Z/findings.md:markdown:46-92.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:48
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown::48::c653e7bf
# Issue #429
# [WARNING] code-duplication - 51-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T11-30-14Z/findings.md:markdown:47-103.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:48
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown::50
# Issue #430
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown:54-79.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:50
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown::54::4fd784b1
# Issue #431
# [WARNING] code-duplication - 206-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T13-30-38Z/findings.md:markdown:58-259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:54
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown::54::527342e8
# Issue #432
# [WARNING] code-duplication - 206-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T16-03-24Z/findings.md:markdown:58-259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:54
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown::57
# Issue #433
# [WARNING] code-duplication - 42-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown:56-103.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:57
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown::84
# Issue #434
# [WARNING] code-duplication - 2278-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T23-22-19Z/findings.md:markdown:89-2366.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-44-40Z/findings.md:markdown:84
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown::51::207033b3
# Issue #435
# [WARNING] code-duplication - 196-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:51-246.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown:51
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown::51::4bf5c257
# Issue #436
# [WARNING] code-duplication - 208-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown:51-259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown:51
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown::79
# Issue #437
# [WARNING] code-duplication - 224-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T22-04-15Z/findings.md:markdown:79-312.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown:79
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown::100
# Issue #438
# [WARNING] code-duplication - 154-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T23-17-25Z/findings.md:markdown:101-259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T20-46-52Z/findings.md:markdown:100
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T23-22-04Z/findings.md:markdown::1
# Issue #439
# [WARNING] code-duplication - 96-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T23-22-19Z/findings.md:markdown:1-96.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T23-22-04Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T23-22-04Z/findings.md:markdown::82
# Issue #440
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T22-03-13Z/findings.md:markdown:81-99.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T23-22-04Z/findings.md:markdown:82
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T23-22-19Z/findings.md:markdown::2353
# Issue #441
# [WARNING] code-duplication - 18-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T23-33-03Z/findings.md:markdown:2353-2368.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-04T23-22-19Z/findings.md:markdown:2353
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-42-43Z/findings.md:markdown::78
# Issue #442
# [WARNING] code-duplication - 17-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T22-03-13Z/findings.md:markdown:83-100.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-42-43Z/findings.md:markdown:78
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::5::26842094
# Issue #443
# [WARNING] code-duplication - 73-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T22-03-13Z/findings.md:markdown:5-77.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::5::f658e825
# Issue #444
# [WARNING] code-duplication - 75-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T22-04-15Z/findings.md:markdown:5-79.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::5::4ddd5f57
# Issue #445
# [WARNING] code-duplication - 78-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T23-12-57Z/findings.md:markdown:5-82.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::5::a242e9d4
# Issue #446
# [WARNING] code-duplication - 82-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T23-14-16Z/findings.md:markdown:5-86.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::5::fa2cfcde
# Issue #447
# [WARNING] code-duplication - 260-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T23-44-50Z/findings.md:markdown:5-259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::1952
# Issue #448
# [WARNING] code-duplication - 59-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T22-04-15Z/findings.md:markdown:1952-2010.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:1952
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::2022
# Issue #449
# [WARNING] code-duplication - 176-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T22-04-15Z/findings.md:markdown:2022-2197.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:2022
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::2197
# Issue #450
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T22-04-15Z/findings.md:markdown:2197-2221.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:2197
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::2221
# Issue #451
# [WARNING] code-duplication - 103-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T22-04-15Z/findings.md:markdown:2221-2323.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:2221
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::2323
# Issue #452
# [WARNING] code-duplication - 73-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T22-04-15Z/findings.md:markdown:2323-2395.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:2323
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown::2407
# Issue #453
# [WARNING] code-duplication - 191-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T22-04-15Z/findings.md:markdown:2407-2597.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T17-44-58Z/findings.md:markdown:2407
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T23-12-57Z/findings.md:markdown::88
# Issue #454
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T23-14-16Z/findings.md:markdown:89-114.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T23-12-57Z/findings.md:markdown:88
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T23-14-16Z/findings.md:markdown::1
# Issue #455
# [WARNING] code-duplication - 92-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T23-17-25Z/findings.md:markdown:1-94.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T23-14-16Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T23-17-25Z/findings.md:markdown::2086
# Issue #456
# [WARNING] code-duplication - 18-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T13-30-38Z/findings.md:markdown:2086-2103.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T23-17-25Z/findings.md:markdown:2086
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T23-17-25Z/findings.md:markdown::2153
# Issue #457
# [WARNING] code-duplication - 88-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T13-30-38Z/findings.md:markdown:2153-2240.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-05T23-17-25Z/findings.md:markdown:2153
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown::5::03910b26
# Issue #458
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown:5-28.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown::5::35d2ff36
# Issue #459
# [WARNING] code-duplication - 103-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T15-03-49Z/findings.md:markdown:5-103.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown::5::36f1dbd6
# Issue #460
# [WARNING] code-duplication - 52-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T15-18-02Z/findings.md:markdown:5-56.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown::5::8896c449
# Issue #461
# [WARNING] code-duplication - 255-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T07-50-02Z/findings.md:markdown:5-259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown::5::4635dfe2
# Issue #462
# [WARNING] code-duplication - 255-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T07-53-01Z/findings.md:markdown:5-259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown::5::efecf640
# Issue #463
# [WARNING] code-duplication - 103-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-03-22Z/findings.md:markdown:5-105.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown::5::29590bc5
# Issue #464
# [WARNING] code-duplication - 255-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-21-03Z/findings.md:markdown:5-259.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T11-31-40Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown::1
# Issue #465
# [WARNING] code-duplication - 30-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T13-30-38Z/findings.md:markdown:1-30.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown::12
# Issue #466
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T13-30-38Z/findings.md:markdown:12-31.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown:12
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown::50
# Issue #467
# [WARNING] code-duplication - 54-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T15-04-38Z/findings.md:markdown:54-107.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown:50
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown::54
# Issue #468
# [WARNING] code-duplication - 50-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T15-18-02Z/findings.md:markdown:58-107.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T13-28-30Z/findings.md:markdown:54
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T15-03-49Z/findings.md:markdown::1
# Issue #469
# [WARNING] code-duplication - 58-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T15-04-38Z/findings.md:markdown:1-58.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T15-03-49Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T15-18-02Z/findings.md:markdown::1
# Issue #470
# [WARNING] code-duplication - 58-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T16-03-24Z/findings.md:markdown:1-58.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T15-18-02Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T16-03-24Z/findings.md:markdown::2086
# Issue #471
# [WARNING] code-duplication - 711-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T07-50-02Z/findings.md:markdown:2086-2796.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-06T16-03-24Z/findings.md:markdown:2086
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-03-22Z/findings.md:markdown::1
# Issue #472
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-05-27Z/findings.md:markdown:1-21.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-03-22Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-05-27Z/findings.md:markdown::2121
# Issue #473
# [WARNING] code-duplication - 718-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-21-03Z/findings.md:markdown:2121-2838.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-05-27Z/findings.md:markdown:2121
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-49-04Z/findings.md:markdown::17
# Issue #474
# [WARNING] code-duplication - 68-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-50-52Z/findings.md:markdown:19-86.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-49-04Z/findings.md:markdown:17
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-49-04Z/findings.md:markdown::56
# Issue #475
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T23-33-11Z/findings.md:markdown:58-82.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-49-04Z/findings.md:markdown:56
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-50-52Z/findings.md:markdown::5
# Issue #476
# [WARNING] code-duplication - 262-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-58-10Z/findings.md:markdown:5-266.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-50-52Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-50-52Z/findings.md:markdown::2123
# Issue #477
# [WARNING] code-duplication - 723-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-58-10Z/findings.md:markdown:2123-2845.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-07T23-50-52Z/findings.md:markdown:2123
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T21-18-48Z/findings.md:markdown::15
# Issue #478
# [WARNING] code-duplication - 80-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T21-25-45Z/findings.md:markdown:16-95.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T21-18-48Z/findings.md:markdown:15
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T21-18-48Z/findings.md:markdown::17
# Issue #479
# [WARNING] code-duplication - 82-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T21-20-34Z/findings.md:markdown:19-100.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T21-18-48Z/findings.md:markdown:17
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T21-20-34Z/findings.md:markdown::16
# Issue #480
# [WARNING] code-duplication - 109-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T21-26-39Z/findings.md:markdown:16-124.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T21-20-34Z/findings.md:markdown:16
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T21-30-06Z/findings.md:markdown::5
# Issue #481
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T23-04-57Z/findings.md:markdown:5-28.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T21-30-06Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T21-30-06Z/findings.md:markdown::65
# Issue #482
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown:65-93.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T21-30-06Z/findings.md:markdown:65
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T21-30-06Z/findings.md:markdown::68
# Issue #483
# [WARNING] code-duplication - 50-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T23-04-57Z/findings.md:markdown:62-111.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T21-30-06Z/findings.md:markdown:68
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T23-04-57Z/findings.md:markdown::60
# Issue #484
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-23-13Z/findings.md:markdown:59-82.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-08T23-04-57Z/findings.md:markdown:60
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-23-13Z/findings.md:markdown::21
# Issue #485
# [WARNING] code-duplication - 50-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T16-42-27Z/findings.md:markdown:21-72.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-23-13Z/findings.md:markdown:21
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-23-13Z/findings.md:markdown::23
# Issue #486
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown:26-44.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-23-13Z/findings.md:markdown:23
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-23-13Z/findings.md:markdown::37
# Issue #487
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-03-27Z/findings.md:markdown:35-63.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-23-13Z/findings.md:markdown:37
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-23-13Z/findings.md:markdown::128
# Issue #488
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-11-36Z/findings.md:markdown:140-165.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-23-13Z/findings.md:markdown:128
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-23-13Z/findings.md:markdown::130
# Issue #489
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-40-42Z/findings.md:markdown:145-168.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-23-13Z/findings.md:markdown:130
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown::5::59d986d3
# Issue #490
# [WARNING] code-duplication - 92-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-40-42Z/findings.md:markdown:5-96.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown::5::1bef8589
# Issue #491
# [WARNING] code-duplication - 318-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-42-59Z/findings.md:markdown:5-322.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown::5::e4568c01
# Issue #492
# [WARNING] code-duplication - 141-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-55-32Z/findings.md:markdown:5-145.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown::23
# Issue #493
# [WARNING] code-duplication - 57-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-04-36Z/findings.md:markdown:23-79.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown:23
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown::142::f7fc8d41
# Issue #494
# [WARNING] code-duplication - 181-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-55-32Z/findings.md:markdown:142-322.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown:142
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown::142::ba9043ee
# Issue #495
# [WARNING] code-duplication - 25-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-13-28Z/findings.md:markdown:142-166.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown:142
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown::142::71b785e2
# Issue #496
# [WARNING] code-duplication - 235-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-59-52Z/findings.md:markdown:142-370.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown:142
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown::596::e14663e8
# Issue #497
# [WARNING] code-duplication - 82-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T17-29-54Z/findings.md:markdown:598-679.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown:596
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown::596::896957a6
# Issue #498
# [WARNING] code-duplication - 82-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:599-680.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-09T22-29-01Z/findings.md:markdown:596
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T16-42-27Z/findings.md:markdown::1
# Issue #499
# [WARNING] code-duplication - 27-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-03-27Z/findings.md:markdown:1-27.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T16-42-27Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T16-42-27Z/findings.md:markdown::78
# Issue #500
# [WARNING] code-duplication - 22-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-04-36Z/findings.md:markdown:82-103.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T16-42-27Z/findings.md:markdown:78
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T16-42-27Z/findings.md:markdown::99
# Issue #501
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-03-27Z/findings.md:markdown:89-107.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T16-42-27Z/findings.md:markdown:99
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-04-36Z/findings.md:markdown::5::38d91492
# Issue #502
# [WARNING] code-duplication - 94-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-11-36Z/findings.md:markdown:5-98.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-04-36Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-04-36Z/findings.md:markdown::5::d110d4a7
# Issue #503
# [WARNING] code-duplication - 92-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-13-28Z/findings.md:markdown:5-96.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-04-36Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-04-36Z/findings.md:markdown::5::3b94a808
# Issue #504
# [WARNING] code-duplication - 113-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-59-52Z/findings.md:markdown:5-117.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-04-36Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-13-28Z/findings.md:markdown::78
# Issue #505
# [WARNING] code-duplication - 87-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T19-09-13Z/findings.md:markdown:78-164.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-13-28Z/findings.md:markdown:78
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-13-28Z/findings.md:markdown::121
# Issue #506
# [WARNING] code-duplication - 250-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T19-11-25Z/findings.md:markdown:121-370.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-13-28Z/findings.md:markdown:121
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-13-28Z/findings.md:markdown::2353
# Issue #507
# [WARNING] code-duplication - 885-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-59-52Z/findings.md:markdown:2353-3237.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-13-28Z/findings.md:markdown:2353
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-59-52Z/findings.md:markdown::1
# Issue #508
# [WARNING] code-duplication - 370-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T19-00-24Z/findings.md:markdown:1-370.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T17-59-52Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T19-09-13Z/findings.md:markdown::1
# Issue #509
# [WARNING] code-duplication - 98-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T19-11-25Z/findings.md:markdown:1-98.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T19-09-13Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T19-09-13Z/findings.md:markdown::2353
# Issue #510
# [WARNING] code-duplication - 873-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T19-11-25Z/findings.md:markdown:2353-3225.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-10T19-09-13Z/findings.md:markdown:2353
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-08-07Z/findings.md:markdown::5
# Issue #511
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-10-00Z/findings.md:markdown:5-28.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-08-07Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-08-07Z/findings.md:markdown::34
# Issue #512
# [WARNING] code-duplication - 54-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T11-39-06Z/findings.md:markdown:36-89.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-08-07Z/findings.md:markdown:34
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-08-07Z/findings.md:markdown::36
# Issue #513
# [WARNING] code-duplication - 47-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-10-00Z/findings.md:markdown:38-84.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-08-07Z/findings.md:markdown:36
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-08-07Z/findings.md:markdown::47
# Issue #514
# [WARNING] code-duplication - 50-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T17-26-42Z/findings.md:markdown:51-100.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-08-07Z/findings.md:markdown:47
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-08-07Z/findings.md:markdown::50
# Issue #515
# [WARNING] code-duplication - 44-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T16-45-35Z/findings.md:markdown:51-95.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-08-07Z/findings.md:markdown:50
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-08-07Z/findings.md:markdown::158
# Issue #516
# [WARNING] code-duplication - 17-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-42-28Z/findings.md:markdown:157-173.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-08-07Z/findings.md:markdown:158
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-10-00Z/findings.md:markdown::24
# Issue #517
# [WARNING] code-duplication - 68-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-11-54Z/findings.md:markdown:26-93.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-10-00Z/findings.md:markdown:24
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-10-00Z/findings.md:markdown::35
# Issue #518
# [WARNING] code-duplication - 57-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T11-41-47Z/findings.md:markdown:37-93.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-10-00Z/findings.md:markdown:35
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-10-00Z/findings.md:markdown::153::09304e9b
# Issue #519
# [WARNING] code-duplication - 30-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-55-59Z/findings.md:markdown:156-185.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-10-00Z/findings.md:markdown:153
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-10-00Z/findings.md:markdown::153::571c666a
# Issue #520
# [WARNING] code-duplication - 29-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T16-45-35Z/findings.md:markdown:149-177.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-10-00Z/findings.md:markdown:153
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-10-00Z/findings.md:markdown::156
# Issue #521
# [WARNING] code-duplication - 27-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T17-26-42Z/findings.md:markdown:158-184.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-10-00Z/findings.md:markdown:156
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-11-54Z/findings.md:markdown::5::f2806976
# Issue #522
# [WARNING] code-duplication - 127-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-55-59Z/findings.md:markdown:5-131.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-11-54Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-11-54Z/findings.md:markdown::5::7183d8e7
# Issue #523
# [WARNING] code-duplication - 155-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-58-59Z/findings.md:markdown:5-159.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-11-54Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-11-54Z/findings.md:markdown::5::ea2db4dc
# Issue #524
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T11-39-06Z/findings.md:markdown:5-28.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-11-54Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-11-54Z/findings.md:markdown::5::381d3fb8
# Issue #525
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T11-41-47Z/findings.md:markdown:5-30.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-11-54Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-11-54Z/findings.md:markdown::9
# Issue #526
# [WARNING] code-duplication - 36-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T17-26-42Z/findings.md:markdown:9-44.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-11-54Z/findings.md:markdown:9
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-11-54Z/findings.md:markdown::128
# Issue #527
# [WARNING] code-duplication - 32-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T16-45-35Z/findings.md:markdown:121-152.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-11-54Z/findings.md:markdown:128
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-11-54Z/findings.md:markdown::156
# Issue #528
# [WARNING] code-duplication - 235-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-58-59Z/findings.md:markdown:156-390.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-11-54Z/findings.md:markdown:156
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-11-54Z/findings.md:markdown::399
# Issue #529
# [WARNING] code-duplication - 843-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-58-59Z/findings.md:markdown:399-1241.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-11-54Z/findings.md:markdown:399
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-55-59Z/findings.md:markdown::131
# Issue #530
# [WARNING] code-duplication - 52-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T11-39-06Z/findings.md:markdown:124-175.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T00-55-59Z/findings.md:markdown:131
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T11-39-06Z/findings.md:markdown::12
# Issue #531
# [WARNING] code-duplication - 30-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T16-45-35Z/findings.md:markdown:11-41.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T11-39-06Z/findings.md:markdown:12
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T11-39-06Z/findings.md:markdown::73
# Issue #532
# [WARNING] code-duplication - 21-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T11-41-47Z/findings.md:markdown:75-94.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T11-39-06Z/findings.md:markdown:73
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T16-45-35Z/findings.md:markdown::5
# Issue #533
# [WARNING] code-duplication - 120-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T17-03-57Z/findings.md:markdown:5-124.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T16-45-35Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T16-45-35Z/findings.md:markdown::117
# Issue #534
# [WARNING] code-duplication - 204-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T17-29-54Z/findings.md:markdown:124-336.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T16-45-35Z/findings.md:markdown:117
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T17-26-42Z/findings.md:markdown::5
# Issue #535
# [WARNING] code-duplication - 106-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T17-29-54Z/findings.md:markdown:5-110.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-12T17-26-42Z/findings.md:markdown:5
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-42-28Z/findings.md:markdown::42
# Issue #536
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-52-22Z/findings.md:markdown:46-64.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-42-28Z/findings.md:markdown:42
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-42-28Z/findings.md:markdown::94
# Issue #537
# [WARNING] code-duplication - 19-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-52-22Z/findings.md:markdown:102-120.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-42-28Z/findings.md:markdown:94
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-42-28Z/findings.md:markdown::150
# Issue #538
# [WARNING] code-duplication - 26-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-52-22Z/findings.md:markdown:165-190.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-42-28Z/findings.md:markdown:150
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-52-22Z/findings.md:markdown::1::7aec0c13
# Issue #539
# [WARNING] code-duplication - 30-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:1-30.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-52-22Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-52-22Z/findings.md:markdown::1::d57c5185
# Issue #540
# [WARNING] code-duplication - 139-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-56-24Z/findings.md:markdown:1-138.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-52-22Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-52-22Z/findings.md:markdown::1::ef9145ca
# Issue #541
# [WARNING] code-duplication - 116-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-59-12Z/findings.md:markdown:1-117.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-52-22Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-52-22Z/findings.md:markdown::32
# Issue #542
# [WARNING] code-duplication - 78-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:33-110.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-52-22Z/findings.md:markdown:32
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-52-22Z/findings.md:markdown::134
# Issue #543
# [WARNING] code-duplication - 32-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:135-166.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-52-22Z/findings.md:markdown:134
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown::1
# Issue #544
# [WARNING] code-duplication - 110-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T01-00-27Z/findings.md:markdown:1-110.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown::23
# Issue #545
# [WARNING] code-duplication - 321-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T01-20-08Z/findings.md:markdown:23-343.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:23
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown::163::8042c8fd
# Issue #546
# [WARNING] code-duplication - 181-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-56-24Z/findings.md:markdown:163-343.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:163
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown::163::57a00ac2
# Issue #547
# [WARNING] code-duplication - 181-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-59-12Z/findings.md:markdown:163-343.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:163
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown::163::f0ab9814
# Issue #548
# [WARNING] code-duplication - 181-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T01-23-23Z/findings.md:markdown:163-343.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:163
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown::352::cb77fe2b
# Issue #549
# [WARNING] code-duplication - 717-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-56-24Z/findings.md:markdown:352-1068.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:352
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown::352::47a02746
# Issue #550
# [WARNING] code-duplication - 717-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-58-01Z/findings.md:markdown:352-1068.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:352
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown::352::3fdc3850
# Issue #551
# [WARNING] code-duplication - 717-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-59-12Z/findings.md:markdown:352-1068.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:352
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown::352::6af7b63c
# Issue #552
# [WARNING] code-duplication - 717-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T01-00-27Z/findings.md:markdown:352-1068.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:352
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown::352::0684f72e
# Issue #553
# [WARNING] code-duplication - 717-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T01-02-07Z/findings.md:markdown:352-1068.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:352
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown::352::507b49cd
# Issue #554
# [WARNING] code-duplication - 130-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T01-20-08Z/findings.md:markdown:352-481.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:352
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown::352::5976f958
# Issue #555
# [WARNING] code-duplication - 717-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T01-23-23Z/findings.md:markdown:352-1068.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:352
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown::481
# Issue #556
# [WARNING] code-duplication - 236-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T01-20-08Z/findings.md:markdown:481-716.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:481
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown::716
# Issue #557
# [WARNING] code-duplication - 91-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T01-20-08Z/findings.md:markdown:716-806.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:716
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown::806
# Issue #558
# [WARNING] code-duplication - 263-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T01-20-08Z/findings.md:markdown:806-1068.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-54-27Z/findings.md:markdown:806
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-56-24Z/findings.md:markdown::120
# Issue #559
# [WARNING] code-duplication - 66-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T01-02-07Z/findings.md:markdown:120-185.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-56-24Z/findings.md:markdown:120
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-59-12Z/findings.md:markdown::142
# Issue #560
# [WARNING] code-duplication - 202-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T01-00-27Z/findings.md:markdown:142-343.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T00-59-12Z/findings.md:markdown:142
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T01-20-08Z/findings.md:markdown::1
# Issue #561
# [WARNING] code-duplication - 131-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T01-23-23Z/findings.md:markdown:1-131.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/.ignite/scans/2026-09-13T01-20-08Z/findings.md:markdown:1
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/CLAUDE.md:markdown::72
# Issue #562
# [WARNING] code-duplication - 24-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/CLAUDE.md:markdown:72-95.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/CLAUDE.md:markdown:72
Acknowledge: 

ID: code-duplication::../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/README.md:markdown::110
# Issue #563
# [WARNING] code-duplication - 28-line duplicate block, also found in ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/README.md:markdown:427-502.
#   ../../../../../../../../var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/gatekeeper-staging/7a35b9ba-9fb9-4f85-897d-5ddac277fc78-api-validation/README.md:markdown:110
Acknowledge: 

ID: code-duplication::rust/crates/db-store/src/overrides.rs::198::8f3adedb
# Issue #564
# [WARNING] code-duplication - 19-line duplicate block, also found in rust/crates/db-store/src/projects.rs:285-303.
#   rust/crates/db-store/src/overrides.rs:198
# Code: stmt.query_map(params![project_id], |row| {
Acknowledge: 

ID: code-duplication::rust/crates/mcp-server/src/main.rs::620
# Issue #565
# [WARNING] code-duplication - 36-line duplicate block, also found in rust/crates/mcp-server/src/main.rs:772-806.
#   rust/crates/mcp-server/src/main.rs:620
# Code: let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/audit_log.rs::105::6f31953d
# Issue #566
# [WARNING] code-duplication - 35-line duplicate block, also found in rust/crates/server/src/routes/custom_secret_patterns.rs:162-196.
#   rust/crates/server/src/routes/audit_log.rs:105
# Code: Router::new().route("/api/audit-log", get(list)).route("/api/audit-log/verify", get(verify))
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/effectivate.rs::298
# Issue #567
# [WARNING] code-duplication - 16-line duplicate block, also found in rust/crates/server/src/routes/pipeline_interactive.rs:403-418.
#   rust/crates/server/src/routes/effectivate.rs:298
# Code: fn build_state() -> (Arc<AppState>, tempfile::TempDir) {
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/studio.rs::336::9cf59e7c
# Issue #568
# [WARNING] code-duplication - 19-line duplicate block, also found in rust/crates/server/src/routes/studio.rs:439-457.
#   rust/crates/server/src/routes/studio.rs:336
# Code: async fn codeql_run(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/studio.rs::336::189d9a56
# Issue #569
# [WARNING] code-duplication - 22-line duplicate block, also found in rust/crates/server/src/routes/studio.rs:554-574.
#   rust/crates/server/src/routes/studio.rs:336
# Code: async fn codeql_run(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
Acknowledge: 

ID: code-duplication::rust/server.log::243
# Issue #570
# [WARNING] code-duplication - 27-line duplicate block, also found in rust/server.log:666-692.
#   rust/server.log:243
# Code: [2m2026-09-06T14:02:39.483095Z[0m [32m INFO[0m [2mignite_tool_runner[0m[2m:[0m tool-runner: completed [3mtool[0m[2m=[0mpicklescan [3margs[0m[2m=[0m--help [3mcwd[0m[2m=[0m/var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/ [3mexit_code[0m[2m=[0m0 [3mstdout[0m[2m=[0musage: picklescan [-h] [-p PATH | -u URL | -hf HUGGINGFACE_MODEL] [-g]
Acknowledge: 

ID: code-duplication::rust/server.log::272
# Issue #571
# [WARNING] code-duplication - 16-line duplicate block, also found in rust/server.log:492-507.
#   rust/server.log:272
# Code: [2m2026-09-06T14:02:39.670680Z[0m [32m INFO[0m [2mignite_tool_runner[0m[2m:[0m tool-runner: completed [3mtool[0m[2m=[0mcosign [3margs[0m[2m=[0mversion [3mcwd[0m[2m=[0m/var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/ [3mexit_code[0m[2m=[0m0 [3mstdout[0m[2m=[0m______   ______        _______. __    _______ .__   __.
Acknowledge: 

ID: code-duplication::rust/server.log::311
# Issue #572
# [WARNING] code-duplication - 43-line duplicate block, also found in rust/server.log:704-746.
#   rust/server.log:311
# Code: [2m2026-09-06T14:02:41.055541Z[0m [32m INFO[0m [2mignite_tool_runner[0m[2m:[0m tool-runner: completed [3mtool[0m[2m=[0mcodeql [3margs[0m[2m=[0mversion --format=json [3mcwd[0m[2m=[0m/var/folders/s1/72d38yqs3sv1m0sjtqyl8tm00000gn/T/ [3mexit_code[0m[2m=[0m0 [3mstdout[0m[2m=[0m{
Acknowledge: 
