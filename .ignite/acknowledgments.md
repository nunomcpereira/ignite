# Ignite pre-push acknowledgments - meant to be committed: a filled-in
# justification is a real audit record, reviewable like code.
#
# Fill in a justification after "Acknowledge:" for any issue below you want
# to override, save, commit, then `git push` again. Blank = stays blocking.
# Entries are sorted by ID, one per finding. The file is only rewritten when
# a new finding needs an entry - then entries for findings that are no
# longer reported are dropped.
# A `# Code:` line, when present, is the flagged source line's own text -
# it lets this justification keep matching after an unrelated edit
# elsewhere in the file shifts its line number. Do not hand-edit it.

ID: codeql-sast::public/index.html::1375::js/xss-through-dom
# [ERROR] codeql-sast - DOM text is reinterpreted as HTML without escaping meta-characters.
#   public/index.html:1375
# Code: document.querySelectorAll('[data-i18n-html]').forEach((el) => { el.innerHTML = t(el.getAttribute('data-i18n-html')); });
Acknowledge: Narrowed replacement for the previously-acknowledged finding at the old [data-i18n] innerHTML call (now textContent - see the applyStaticTranslations doc comment above it). Only elements explicitly opted in via data-i18n-html still use innerHTML, for the handful of translation keys whose copy deliberately carries inline markup (bold spans in upload.dropSubtitle, a line break in footer.note, etc). t()'s only inputs remain (1) the fixed attribute-name string 'data-i18n-html' read off the DOM and (2) a lookup into window.IGNITE_I18N.translations, entirely defined by public/i18n.js - a file committed to this repo and only ever edited by a developer/operator, never populated from user input, the network, or any request parameter. No untrusted data reaches this call.

ID: dependency-vulnerability::rust/crates/staging/Cargo.toml::12::zip::RUSTSEC-2026-0367
# [ERROR] dependency-vulnerability - zip@2.4.2 — RUSTSEC-2026-0367: Insecure Preservation of SUID/SGID Bits during ZIP Extraction Leading to Potential Privilege Escalation (CVSS 7.3)
#   rust/crates/staging/Cargo.toml:12
# Code: zip = { version = "2", default-features = false, features = ["deflate"] }
Acknowledge: Not reachable in Ignite. The advisory is about zip's own extract() helpers preserving SUID/SGID bits from the archive. rust/crates/staging never calls ZipArchive::extract() or ZipStreamReader::extract(): it walks entries itself, writes each file with fs::File::create and immediately forces mode 0o600 (staging/src/lib.rs set_permissions), so no mode bits from the archive are ever applied. Fixed only in zip 9.0.0 (major bump from 2.x); upgrade tracked as a separate change.

ID: dependency-vulnerability::rust/crates/staging/Cargo.toml::12::zip::RUSTSEC-2026-0369
# [ERROR] dependency-vulnerability - zip@2.4.2 — RUSTSEC-2026-0369: ZipStreamReader::extract() and ZipArchive::extract() apply Unix permissions through symlinks without confining the target (CVSS 9.1)
#   rust/crates/staging/Cargo.toml:12
# Code: zip = { version = "2", default-features = false, features = ["deflate"] }
Acknowledge: Not reachable in Ignite. The advisory is about zip's extract() helpers applying Unix permissions through symlinks. rust/crates/staging never calls ZipArchive::extract() or ZipStreamReader::extract(); it skips every symlink entry (S_IFLNK check before writing), resolves each path inside the staging root (zip-slip guard), and forces mode 0o600 on each regular file it writes, so no permission is ever applied through a link. Fixed only in zip 9.0.0 (major bump from 2.x); upgrade tracked as a separate change.

ID: gha-security::.github/workflows/deploy-docs.yml::13
# [ERROR] gha-security - overly broad permissions (  pages: write)
#   .github/workflows/deploy-docs.yml:13
Acknowledge: `pages: write` + `id-token: write` (next entry) are exactly the two permissions GitHub's own actions/deploy-pages documentation requires for OIDC-based Pages deployment - already the minimal job-level set (no broader contents:write, etc.). zizmor's excessive-permissions rule flags any explicit write scope without knowing what the job's own actions actually need; this is that documented minimum, not excessive in practice.

ID: gha-security::.github/workflows/deploy-docs.yml::14
# [ERROR] gha-security - overly broad permissions (  id-token: write)
#   .github/workflows/deploy-docs.yml:14
Acknowledge: Same justification as the `pages: write` entry above - the minimal, documented permission pair actions/deploy-pages needs for OIDC-based deployment.

ID: secret::docs-site/docs/ci-integration.md::493
# [ERROR] secret - Hardcoded token
#   docs-site/docs/ci-integration.md:493
# Code: -d '{"regex": "acme_live_[a-zA-Z0-9]{24}", "sample": "token: acme_live_abcdef0123456789ghijklmn"}'
Acknowledge: Fictional pattern/sample pair in a docs-site example curl command demonstrating the custom-secret-pattern playground endpoint - "acme_live_..." isn't a real vendor token format, and the sample string is fabricated for the example, not a real credential.

ID: secret::docs-site/docs/getting-started.md::127
# [ERROR] secret - Hardcoded secret
#   docs-site/docs/getting-started.md:127
# Code: secret: { secretName: ignite-tls }
Acknowledge: False positive in a documentation Kubernetes YAML example - the line is the pod volume source that names the ignite-tls Secret object by name; it carries no credential value.

ID: secret::rust/crates/config/src/lib.rs::1475
# [ERROR] secret - Hardcoded api_key
#   rust/crates/config/src/lib.rs:1475
# Code: cfg.llm.openai.api_key = "sk-live-supersecret".to_string();
Acknowledge: Fabricated OpenAI-format API key literal used only to verify Config's new redacting Debug impl (debug_redacts_secret_fields_but_keeps_non_secret_fields_visible) actually hides secret fields from {:?} output - not a real credential.

ID: secret::rust/crates/config/src/lib.rs::1476
# [ERROR] secret - Hardcoded secret
#   rust/crates/config/src/lib.rs:1476
# Code: cfg.github.oauth.client_secret = "oauth-secret-value".to_string();
Acknowledge: Same test as the entry above - a fabricated OAuth client secret literal used only to verify the redacting Debug impl, not a real credential.

ID: secret::rust/crates/guidelines/src/catalog.rs::340
# [ERROR] secret - Hardcoded connection-string credential
#   rust/crates/guidelines/src/catalog.rs:340
# Code: description: "A URL or connection string carries an inline password (`postgres://user:s3cret@db.prod:5432/app`, `https://user:token@host/...`). Placeholders (`${DB_PASSWORD}`, `<password>`, `password`, `changeme`) and loopback hosts are not flagged.",
Acknowledge: 

ID: secret::rust/crates/guidelines/src/checks.rs::1863
# [ERROR] secret - Hardcoded private-key
#   rust/crates/guidelines/src/checks.rs:1863
# Code: assert_eq!(lines_of("noCommittedPrivateKeys", &format!("x\n-----BEGIN RSA PRIVATE KEY-----\n{body}\n"), "key.pem"), vec![2]);
Acknowledge: 

ID: secret::rust/crates/guidelines/src/checks.rs::1866
# [ERROR] secret - Hardcoded private-key
#   rust/crates/guidelines/src/checks.rs:1866
# Code: assert_eq!(lines_of("noCommittedPrivateKeys", &format!("k = \"-----BEGIN OPENSSH PRIVATE KEY-----\\n{body}\\n\""), "a.py"), vec![1]);
Acknowledge: 

ID: secret::rust/crates/guidelines/src/checks.rs::1872
# [ERROR] secret - Hardcoded connection-string credential
#   rust/crates/guidelines/src/checks.rs:1872
# Code: let hits = run_check("noCredentialsInUrls", "DB = 'postgres://app:S3cr3tPw@db.prod.internal:5432/app'\n", "settings.py").unwrap();
Acknowledge: 

ID: secret::rust/crates/guidelines/src/checks.rs::1875
# [ERROR] secret - Hardcoded connection-string credential
#   rust/crates/guidelines/src/checks.rs:1875
# Code: assert!(lines_of("noCredentialsInUrls", "url: postgres://app:${DB_PASSWORD}@db:5432/app\n", "compose.yml").is_empty());
Acknowledge: 

ID: secret::rust/crates/guidelines/src/checks.rs::1876
# [ERROR] secret - Hardcoded connection-string credential
#   rust/crates/guidelines/src/checks.rs:1876
# Code: assert!(lines_of("noCredentialsInUrls", "postgres://user:password@db.example.com/x\n", "README.md").is_empty());
Acknowledge: 

ID: secret::rust/crates/guidelines/src/checks.rs::1877
# [ERROR] secret - Hardcoded connection-string credential
#   rust/crates/guidelines/src/checks.rs:1877
# Code: assert!(lines_of("noCredentialsInUrls", "postgres://postgres:postgres@localhost:5432/dev\n", "x.env.example").is_empty());
Acknowledge: 

ID: secret::rust/crates/guidelines/src/checks.rs::2069
# [ERROR] secret - Hardcoded private-key
#   rust/crates/guidelines/src/checks.rs:2069
# Code: assert!(lines_of("noCommittedPrivateKeys", "placeholder=\"-----BEGIN PRIVATE KEY-----…\"\n", "a.tsx").is_empty());
Acknowledge: 

ID: secret::rust/crates/guidelines/src/checks.rs::765
# [ERROR] secret - Hardcoded connection-string credential
#   rust/crates/guidelines/src/checks.rs:765
# Code: // scheme://user:password@host — group 1 is the password, group 2 the host.
Acknowledge: 

ID: secret::rust/crates/llm-client/src/lib.rs::482
# [ERROR] secret - Hardcoded api_key
#   rust/crates/llm-client/src/lib.rs:482
# Code: LlmClientConfig { provider: Provider::Anthropic, openai_api_key: String::new(), openai_base_url: String::new(), openai_model: String::new(), anthropic_api_key: "sk-ant-test".to_string(), anthropic_base_url: "https://api.anthropic.com/v1/".to_string(), anthropic_model: "claude-opus-5".to_string(), azure_foundry_api_key: String::new(), azure_foundry_endpoint: String::new(), azure_foundry_deployment: String::new(), azure_foundry_api_version: String::new(), scan_url: String::new(), scan_model: String::new() }
Acknowledge: Fake Anthropic API key literal ("sk-ant-test") used as test-fixture config in an llm-client unit test, not a real credential.

ID: secret::rust/crates/malicious-dependencies/src/lib.rs::196
# [ERROR] secret - Hardcoded generic-api-key
#   rust/crates/malicious-dependencies/src/lib.rs:196
# Code: assert_eq!(verdicts[0].pkg_key, "malicious-pkg==1.0.0");
Acknowledge: False-positive match on a plain test package-name string ("malicious-pkg==1.0.0") asserting guarddog_verdicts_from_report's numeric-issues-shape parsing - no secret, credential, or high-entropy value anywhere in this line.

ID: secret::rust/crates/malicious-dependencies/src/lib.rs::265
# [ERROR] secret - Hardcoded generic-api-key
#   rust/crates/malicious-dependencies/src/lib.rs:265
# Code: assert_eq!(verdicts[0].pkg_key, "evil-pkg==0.0.1");
Acknowledge: False-positive match on a plain test package-name string ("evil-pkg==0.0.1") asserting guarddog_verdicts_from_report's GuardDog 3.x array-shape parsing - no secret, credential, or high-entropy value anywhere in this line.

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::1173
# [ERROR] secret - Hardcoded gcp-api-key
#   rust/crates/phase4-orchestrator/src/lib.rs:1173
# Code: fs::write(root.join("config.js"), format!("export const environment = {{ firebase: {{ apiKey: '{}' }} }};\n", "AIzaSyDGX6-TCqxyZv3m1avbP8-hZxD2-Zb6bXk")).unwrap();
Acknowledge: Fake GCP/Firebase web API key literal used as test input to verify the built-in secret scanner (SECRET_RE) doesn't false-positive on a `firebase: { apiKey: ... }` nested property shape, not a real credential.

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::1249
# [ERROR] secret - Hardcoded gcp-api-key
#   rust/crates/phase4-orchestrator/src/lib.rs:1249
# Code: fs::write(root.join("config.js"), format!("export const apiKey = '{}';\n", "AIzaSyDGX6-TCqxyZv3m1avbP8-hZxD2-Zb6bXk")).unwrap();
Acknowledge: Fake GCP/Firebase web API key literal, same fixture value as the other AIzaSy... entry above, written to a scratch test repo to verify gitleaks-based secret detection - not a real credential.

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::1292
# [ERROR] secret - Hardcoded github-pat
#   rust/crates/phase4-orchestrator/src/lib.rs:1292
# Code: fs::write(root.join("config.js"), "headers.set(\"Authorization\", \"Bearer ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\");\n").unwrap();
Acknowledge: Fake GitHub PAT literal (high-entropy but never issued) used to verify gitleaks flags it as github-pat and that the off-by-default secret_verification path never appends a VERIFIED LIVE marker - not a real credential, never sent anywhere but api.github.com's own 401 rejection path in the sibling test below.

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::1327
# [ERROR] secret - Hardcoded github-pat
#   rust/crates/phase4-orchestrator/src/lib.rs:1327
# Code: fs::write(root.join("config.js"), "headers.set(\"Authorization\", \"Bearer ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\");\n").unwrap();
Acknowledge: Same fake GitHub PAT fixture as the entry above, used in secret_verification_when_enabled_never_flags_a_fake_token_as_verified_live to confirm a live GitHub API 401 for this token is correctly reported as not-live - not a real credential.

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::1446
# [ERROR] secret - Hardcoded github-pat
#   rust/crates/phase4-orchestrator/src/lib.rs:1446
# Code: fs::write(root.join("config.js"), "headers.set(\"Authorization\", \"Bearer ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\");\n").unwrap();
Acknowledge: Same fake GitHub PAT fixture as the entries above (test moved to this line), used in secret_verification_when_enabled_never_flags_a_fake_token_as_verified_live to confirm a live GitHub API 401 for this token is correctly reported as not-live - not a real credential.

ID: secret::rust/crates/pii-dataflow/src/lib.rs::444
# [ERROR] secret - Hardcoded apikey
#   rust/crates/pii-dataflow/src/lib.rs:444
# Code: let line = r#"const apiKey = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe";"#;
Acknowledge: Fake Firebase public web API key literal used as test input to verify is_firebase_public_api_key_finding correctly excludes this shape only for the "hard-coded secret" finding title, not for other titles - not a real credential.

ID: secret::rust/crates/secrets/src/lib.rs::1022
# [ERROR] secret - Hardcoded stripe-access-token
#   rust/crates/secrets/src/lib.rs:1022
# Code: let matches = test_pattern_against_sample(r"sk_live_[a-zA-Z0-9]{16,}", "key one: sk_live_abcdef0123456789, key two: sk_live_zzzzzz9999999999").unwrap();
Acknowledge: Fabricated Stripe-format sample text (test_pattern_against_sample_finds_all_matches) verifying the custom-secret-pattern regex tester finds every match in a sample, not a real credential - same fixture literal flagged again at the two assert_eq! lines immediately below for the same reason.

ID: secret::rust/crates/secrets/src/lib.rs::1024
# [ERROR] secret - Hardcoded stripe-access-token
#   rust/crates/secrets/src/lib.rs:1024
# Code: assert_eq!(matches[0].matched_text, "sk_live_abcdef0123456789");
Acknowledge: Same fabricated Stripe-format fixture literal as the entry above, asserted as the expected match text in the same test - not a real credential.

ID: secret::rust/crates/secrets/src/lib.rs::1026
# [ERROR] secret - Hardcoded stripe-access-token
#   rust/crates/secrets/src/lib.rs:1026
# Code: assert_eq!(matches[1].matched_text, "sk_live_zzzzzz9999999999");
Acknowledge: Same fabricated Stripe-format fixture literal as the two entries above, asserted as the expected second match in the same regex-tester unit test — not a real credential.

ID: secret::rust/crates/secrets/src/lib.rs::57
# [ERROR] secret - Hardcoded connection-string credential
#   rust/crates/secrets/src/lib.rs:57
# Code: // (`"postgres://usr:pwd@host1/db"; "redis://admin:secret@host2"`) doesn't
Acknowledge: Doc-comment example illustrating URI_CREDENTIAL_RE's greedy-match boundary behavior across two adjacent connection strings on one line - not a real credential, and not even executable code (a `//` comment).

ID: secret::rust/crates/secrets/src/lib.rs::790
# [ERROR] secret - Hardcoded api_key
#   rust/crates/secrets/src/lib.rs:790
# Code: fs::write(root.join("config.js"), "const api_key = 'sk-proj-abcdefghijklmnop';\n").unwrap();
Acknowledge: Fake API key literal used as test input for run_gitleaks_history_scan_no_ops_without_a_git_directory (verifies the history scan is a no-op with no .git directory) - not a real credential, same fixture literal already acknowledged elsewhere in this file for the same reason.

ID: secret::rust/crates/secrets/src/lib.rs::894
# [ERROR] secret - Hardcoded connection-string credential
#   rust/crates/secrets/src/lib.rs:894
# Code: "DATABASE_URL = \"postgresql://testuser:not-a-real-pw@x@example.com:5432/testdb\"\n",
Acknowledge: Test-fixture connection string for flags_a_password_embedded_in_a_connection_string - example.com is IANA/RFC 2606-reserved for documentation and the password is labeled a placeholder outright in the surrounding comment, not a real credential.

ID: secret::rust/crates/server/src/auth/github_oauth.rs::282
# [ERROR] secret - Hardcoded secret
#   rust/crates/server/src/auth/github_oauth.rs:282
# Code: config.github.oauth.client_secret = "secret-123".into();
Acknowledge: Literal test-fixture GitHub OAuth client secret used only to construct an in-process test Config for github_oauth.rs's own unit tests, not a real credential.

ID: secret::rust/crates/server/src/auth/oidc.rs::311
# [ERROR] secret - Hardcoded secret
#   rust/crates/server/src/auth/oidc.rs:311
# Code: config.auth.oidc.client_secret = "test-secret".into();
Acknowledge: Literal test-fixture OIDC client secret used only to construct an in-process test Config for oidc.rs's own unit tests, not a real credential.

ID: secret::rust/crates/server/src/routes/custom_secret_patterns.rs::199
# [ERROR] secret - Hardcoded generic-api-key
#   rust/crates/server/src/routes/custom_secret_patterns.rs:199
# Code: let req = Request::post("/api/secret-patterns/test").header("content-type", "application/json").body(Body::from(r#"{"regex":"sk_live_[a-z0-9]+","sample":"key: sk_live_abc123"}"#)).unwrap();
Acknowledge: Fabricated Stripe-format sample string used as request-body input to the custom-secret-pattern playground's own unit test (test_pattern_route_reports_matches_without_persisting_anything) - the whole point of this endpoint is to test a regex against sample text, so a plausible-looking fake match is expected input, not a real credential.

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::747
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:747
# Code: let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
Acknowledge: Same fake AWS access key literal as the entries above, reused in a fourth review-gate integration test in this same file, not a real credential.

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::811
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:811
# Code: let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
Acknowledge: Fake AWS access key literal used as a fixture file inside a review-gate integration test (uploaded as a zip so the secret scanner flags a real blocking finding to pause the run for review), not a real credential.

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::908
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:908
# Code: let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
Acknowledge: Same fake AWS access key literal as the entry above, reused in a second review-gate integration test in this same file, not a real credential.

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::963
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:963
# Code: let zip = zip_bytes(&[("app.js", b"const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n")]);
Acknowledge: Same fake AWS access key literal as the entries above, reused in a third review-gate integration test in this same file, not a real credential.
