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

ID: code-duplication::CLAUDE.md:markdown::102
# [WARNING] code-duplication - 25-line duplicate block, also found in CLAUDE.md:markdown:102-126.
#   CLAUDE.md:markdown:102
Acknowledge: 

ID: code-duplication::README.md:markdown::110
# [WARNING] code-duplication - 28-line duplicate block, also found in README.md:markdown:441-516.
#   README.md:markdown:110
Acknowledge: 

ID: code-duplication::hooks/pre-push::1
# [WARNING] code-duplication - 125-line duplicate block, also found in vscode-extension/resources/pre-push:1-125.
#   hooks/pre-push:1
# Code: #!/usr/bin/env bash
Acknowledge: 

ID: code-duplication::public/index.html::3454
# [WARNING] code-duplication - 20-line duplicate block, also found in public/index.html:6362-6381.
#   public/index.html:3454
# Code: list.innerHTML = sortedIssueIndices(issues).map((idx) => safeRenderIssueCard(issues[idx], idx, { interactive: issues[idx].status !== 'overridden' })).join('');
Acknowledge: 

ID: code-duplication::public/index.html::5330
# [WARNING] code-duplication - 25-line duplicate block, also found in public/index.html:5496-5520.
#   public/index.html:5330
# Code: body: JSON.stringify({ language }),
Acknowledge: 

ID: code-duplication::rust/crates/db-store/src/overrides.rs::247::13f5b9b5
# [WARNING] code-duplication - 19-line duplicate block, also found in rust/crates/db-store/src/overrides.rs:296-314.
#   rust/crates/db-store/src/overrides.rs:247
# Code: stmt.query_map(params![project_id], |row| {
Acknowledge: 

ID: code-duplication::rust/crates/db-store/src/overrides.rs::247::e2d31a16
# [WARNING] code-duplication - 19-line duplicate block, also found in rust/crates/db-store/src/projects.rs:351-369.
#   rust/crates/db-store/src/overrides.rs:247
# Code: stmt.query_map(params![project_id], |row| {
Acknowledge: 

ID: code-duplication::rust/crates/mcp-server/src/main.rs::956
# [WARNING] code-duplication - 36-line duplicate block, also found in rust/crates/mcp-server/src/main.rs:1108-1142.
#   rust/crates/mcp-server/src/main.rs:956
# Code: let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/audit_log.rs::126::8cfb44e0
# [WARNING] code-duplication - 22-line duplicate block, also found in rust/crates/server/src/routes/compliance.rs:104-125.
#   rust/crates/server/src/routes/audit_log.rs:126
# Code: .route("/api/audit-log/:id/log", get(download_log))
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/audit_log.rs::126::c72e88b4
# [WARNING] code-duplication - 24-line duplicate block, also found in rust/crates/server/src/routes/custom_secret_patterns.rs:162-185.
#   rust/crates/server/src/routes/audit_log.rs:126
# Code: .route("/api/audit-log/:id/log", get(download_log))
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/effectivate.rs::52
# [WARNING] code-duplication - 25-line duplicate block, also found in rust/crates/server/src/routes/project_overrides.rs:35-59.
#   rust/crates/server/src/routes/effectivate.rs:52
# Code: score: i32::try_from(r.score.unwrap_or(0)).unwrap_or(i32::MAX),
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_interactive.rs::461
# [WARNING] code-duplication - 31-line duplicate block, also found in rust/crates/server/src/routes/pipeline_interactive.rs:687-717.
#   rust/crates/server/src/routes/pipeline_interactive.rs:461
# Code: let zip = zip_bytes(&[("app.js", b"console.log(1);"), ("package.json", b"{\"name\":\"fixture\"}")]);
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_interactive.rs::462
# [WARNING] code-duplication - 22-line duplicate block, also found in rust/crates/server/src/routes/pipeline_interactive.rs:911-932.
#   rust/crates/server/src/routes/pipeline_interactive.rs:462
# Code: let form = Form::new().text("org", "-bad-").text("repo", "widgets").text("dryRun", "true").part("archive", Part::bytes(zip).file_name("p.zip"));
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_onboard.rs::29
# [WARNING] code-duplication - 59-line duplicate block, also found in rust/crates/server/src/routes/pipeline_validate.rs:30-88.
#   rust/crates/server/src/routes/pipeline_onboard.rs:29
# Code: static REPO_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,100}$").unwrap());
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_onboard.rs::398
# [WARNING] code-duplication - 24-line duplicate block, also found in rust/crates/server/src/routes/pipeline_validate.rs:445-468.
#   rust/crates/server/src/routes/pipeline_onboard.rs:398
# Code: logger.log(4, &format!("⚠ {} flagged issue(s) overridden by {}:", plan.applied.len(), actor.email));
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_onboard.rs::668
# [WARNING] code-duplication - 37-line duplicate block, also found in rust/crates/server/src/routes/pipeline_validate.rs:798-834.
#   rust/crates/server/src/routes/pipeline_onboard.rs:668
# Code: state.db.finish_project("failed", Some(&e.message), None, None, project_id);
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/pipeline_onboard.rs::88
# [WARNING] code-duplication - 18-line duplicate block, also found in rust/crates/server/src/routes/pipeline_validate.rs:90-107.
#   rust/crates/server/src/routes/pipeline_onboard.rs:88
# Code: self.inner.lock().unwrap().project_id = Some(id);
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/repository_events_webhook.rs::67
# [WARNING] code-duplication - 20-line duplicate block, also found in rust/crates/server/src/routes/secret_scanning_webhook.rs:79-98.
#   rust/crates/server/src/routes/repository_events_webhook.rs:67
# Code: return err(StatusCode::NOT_FOUND, "Inbound repository-events webhook is not configured.".to_string());
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/studio.rs::349::34308faa
# [WARNING] code-duplication - 22-line duplicate block, also found in rust/crates/server/src/routes/studio.rs:567-587.
#   rust/crates/server/src/routes/studio.rs:349
# Code: async fn codeql_run(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
Acknowledge: 

ID: code-duplication::rust/crates/server/src/routes/studio.rs::349::f8d6eb75
# [WARNING] code-duplication - 19-line duplicate block, also found in rust/crates/server/src/routes/studio.rs:452-470.
#   rust/crates/server/src/routes/studio.rs:349
# Code: async fn codeql_run(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
Acknowledge: 

ID: code-structure::public/i18n.js::1
# [WARNING] code-structure - public/i18n.js is 1828 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   public/i18n.js:1
# Code: // Ignite web UI translations — static UI chrome only (buttons, labels,
Acknowledge: 

ID: code-structure::rust/crates/auto-fix-pr/src/lib.rs::1
# [WARNING] code-structure - rust/crates/auto-fix-pr/src/lib.rs is 1456 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/auto-fix-pr/src/lib.rs:1
# Code: //! Auto-fix PR bot — the Dependabot-parity gap `scheduled-rescan` leaves
Acknowledge: 

ID: code-structure::rust/crates/config/src/lib.rs::1
# [WARNING] code-structure - rust/crates/config/src/lib.rs is 1916 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/config/src/lib.rs:1
# Code: //! Ignite configuration — config.json < environment variables. Faithful
Acknowledge: 

ID: code-structure::rust/crates/db-store/src/lib.rs::1
# [WARNING] code-structure - rust/crates/db-store/src/lib.rs is 1075 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/db-store/src/lib.rs:1
# Code: //! SQLite-backed store — faithful port of `db-store.js`. Same schema
Acknowledge: 

ID: code-structure::rust/crates/dependency-license-scan/src/lib.rs::1
# [WARNING] code-structure - rust/crates/dependency-license-scan/src/lib.rs is 1826 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/dependency-license-scan/src/lib.rs:1
# Code: //! Dependency license/vulnerability scan orchestrators. Faithful port of
Acknowledge: 

ID: code-structure::rust/crates/fix-pr/src/lib.rs::1
# [WARNING] code-structure - rust/crates/fix-pr/src/lib.rs is 1325 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/fix-pr/src/lib.rs:1
# Code: //! Bulk "fix all findings" PR generator — the scan-wide counterpart to
Acknowledge: 

ID: code-structure::rust/crates/mcp-server/src/main.rs::1
# [WARNING] code-structure - rust/crates/mcp-server/src/main.rs is 1219 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/mcp-server/src/main.rs:1
# Code: //! MCP server exposing the company AI validation guidelines, faithful
Acknowledge: 

ID: code-structure::rust/crates/phase4-orchestrator/src/lib.rs::1
# [WARNING] code-structure - rust/crates/phase4-orchestrator/src/lib.rs is 1479 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/phase4-orchestrator/src/lib.rs:1
# Code: //! Phase 4 check orchestrator. Faithful port of server.js's
Acknowledge: 

ID: code-structure::rust/crates/secrets/src/lib.rs::1
# [WARNING] code-structure - rust/crates/secrets/src/lib.rs is 1097 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/secrets/src/lib.rs:1
# Code: //! Regex-based secret scan + optional gitleaks supplement. Faithful port
Acknowledge: 

ID: code-structure::rust/crates/server/src/routes/daily_report.rs::1
# [WARNING] code-structure - rust/crates/server/src/routes/daily_report.rs is 1166 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/server/src/routes/daily_report.rs:1
# Code: //! Org-level daily findings report: once a day (default 23:59 server-local
Acknowledge: 

ID: code-structure::rust/crates/server/src/routes/pipeline_validate.rs::1
# [WARNING] code-structure - rust/crates/server/src/routes/pipeline_validate.rs is 1167 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/server/src/routes/pipeline_validate.rs:1
# Code: //! POST /api/pipeline/validate-all — faithful port of
Acknowledge: 

ID: code-structure::rust/crates/server/src/routes/studio.rs::1
# [WARNING] code-structure - rust/crates/server/src/routes/studio.rs is 1099 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.
#   rust/crates/server/src/routes/studio.rs:1
# Code: //! `/api/pipeline/:jobId/studio/*` — faithful (partial) port of
Acknowledge: 

ID: codeql-sast::public/index.html::1375::js/xss-through-dom
# [ERROR] codeql-sast - DOM text is reinterpreted as HTML without escaping meta-characters.
#   public/index.html:1375
# Code: document.querySelectorAll('[data-i18n-html]').forEach((el) => { el.innerHTML = t(el.getAttribute('data-i18n-html')); });
Acknowledge: Narrowed replacement for the previously-acknowledged finding at the old [data-i18n] innerHTML call (now textContent - see the applyStaticTranslations doc comment above it). Only elements explicitly opted in via data-i18n-html still use innerHTML, for the handful of translation keys whose copy deliberately carries inline markup (bold spans in upload.dropSubtitle, a line break in footer.note, etc). t()'s only inputs remain (1) the fixed attribute-name string 'data-i18n-html' read off the DOM and (2) a lookup into window.IGNITE_I18N.translations, entirely defined by public/i18n.js - a file committed to this repo and only ever edited by a developer/operator, never populated from user input, the network, or any request parameter. No untrusted data reaches this call.

ID: codeql-sast::public/index.html::1805::js/incomplete-html-attribute-sanitization
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:1805
# Code: <button type="button" class="shrink-0 text-slate-300 hover:text-slate-600" aria-label="${escapeHtml(t('common.close'))}">
Acknowledge: 

ID: codeql-sast::public/index.html::3404::js/incomplete-html-attribute-sanitization
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:3404
# Code: <span class="w-56 shrink-0 truncate text-slate-700" title="${escapeHtml(label)}">${escapeHtml(label)}${isBottleneck ? ' <span class="text-rose-500" title="Bottleneck — slowest check this run">⬤</span>' : ''}</span>
Acknowledge: 

ID: codeql-sast::public/index.html::5157::js/incomplete-html-attribute-sanitization
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:5157
# Code: <textarea id="studioQueryText" class="w-full flex-1 min-h-[180px] font-mono text-[12px] leading-relaxed border border-slate-200 rounded-lg p-2" spellcheck="false" placeholder="import ${escapeHtml(defaultLanguage)}\n\nfrom ...\nselect ...">${escapeHtml(initialText)}</textarea>
Acknowledge: 

ID: codeql-sast::public/index.html::6982::js/incomplete-html-attribute-sanitization
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:6982
# Code: select.innerHTML = orgs.map((o) => `<option value="${escapeHtml(o)}">${escapeHtml(o)}</option>`).join('');
Acknowledge: 

ID: codeql-sast::public/index.html::7074::js/incomplete-html-attribute-sanitization::e40e5cb3
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:7074
# Code: <button type="button" class="hist-view-checks-report text-[11px] font-semibold text-slate-500 hover:underline shrink-0" data-id="${p.id}" data-org="${escapeHtml(p.org)}" data-repo="${escapeHtml(p.repo)}">${t('history.checksBtn')}</button>
Acknowledge: 

ID: codeql-sast::public/index.html::7076::js/incomplete-html-attribute-sanitization::e40e5cb3
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:7076
# Code: ${p.issue_count > 0 ? `<button type="button" class="hist-open-studio text-[11px] font-semibold text-violet-600 hover:underline shrink-0" data-id="${p.id}" data-job-id="${escapeAttr(p.job_id || '')}" data-retained="${p.retained ? '1' : ''}" data-org="${escapeHtml(p.org)}" data-repo="${escapeHtml(p.repo)}" title="${escapeAttr(p.retained ? t('history.fullStudioTitle') : t('history.readOnlyStudioTitle'))}">${p.retained ? `${t('history.studioBtn')}${p.retained_tier === 'pruned' ? ` (${t('history.flaggedFilesOnly')})` : ` (${t('common.full')})`}` : t('history.studioBtn')}</button>` : ''}
Acknowledge: 

ID: codeql-sast::public/index.html::7077::js/incomplete-html-attribute-sanitization::e40e5cb3
# [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.
#   public/index.html:7077
# Code: ${p.issue_count > 0 ? `<button type="button" class="hist-view-issues text-[11px] font-semibold text-brand-600 hover:underline shrink-0" data-id="${p.id}" data-count="${p.issue_count}" data-org="${escapeHtml(p.org)}" data-repo="${escapeHtml(p.repo)}" data-job-id="${escapeAttr(p.job_id || '')}">${t('history.issueCount', { count: p.issue_count })}</button>` : ''}
Acknowledge: 

ID: complexity-health::rust/crates/acknowledgments/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 35/100 — below the 40 threshold (complexity 33 over 456 lines of code).
#   rust/crates/acknowledgments/src/lib.rs:1
# Code: //! Parsing and regeneration of `.ignite/acknowledgments.md` — ported from
Acknowledge: 

ID: complexity-health::rust/crates/auto-fix-pr/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 20/100 — below the 40 threshold (complexity 96 over 1344 lines of code).
#   rust/crates/auto-fix-pr/src/lib.rs:1
# Code: //! Auto-fix PR bot — the Dependabot-parity gap `scheduled-rescan` leaves
Acknowledge: 

ID: complexity-health::rust/crates/auto-fix/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 38/100 — below the 40 threshold (complexity 28 over 374 lines of code).
#   rust/crates/auto-fix/src/lib.rs:1
# Code: //! Faithful port of `lib/auto-fix.js` — turns a subset of dead-code and
Acknowledge: 

ID: complexity-health::rust/crates/boundaries/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 26 over 325 lines of code).
#   rust/crates/boundaries/src/lib.rs:1
# Code: //! Built-in architecture-boundary enforcement. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/callgraph/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 29/100 — below the 40 threshold (complexity 62 over 593 lines of code).
#   rust/crates/callgraph/src/lib.rs:1
# Code: //! Studio's "Call Graph" feature: caller -> callee edges across a project,
Acknowledge: 

ID: complexity-health::rust/crates/cli/src/report.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 34/100 — below the 40 threshold (complexity 54 over 288 lines of code).
#   rust/crates/cli/src/report.rs:1
# Code: //! `ignite report [org] [--channels email,webhook,azure_blob,pdf] [--webhook-url URL]
Acknowledge: 

ID: complexity-health::rust/crates/codeql-cross-file/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 24/100 — below the 40 threshold (complexity 79 over 860 lines of code).
#   rust/crates/codeql-cross-file/src/lib.rs:1
# Code: //! Cross-file static analysis via the CodeQL CLI. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/complexity-health/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 28/100 — below the 40 threshold (complexity 63 over 626 lines of code).
#   rust/crates/complexity-health/src/lib.rs:1
# Code: //! Built-in complexity/maintainability health scan. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/config/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 12/100 — below the 40 threshold (complexity 208 over 1812 lines of code).
#   rust/crates/config/src/lib.rs:1
# Code: //! Ignite configuration — config.json < environment variables. Faithful
Acknowledge: 

ID: complexity-health::rust/crates/container-image-vulnerabilities/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 38/100 — below the 40 threshold (complexity 30 over 316 lines of code).
#   rust/crates/container-image-vulnerabilities/src/lib.rs:1
# Code: //! Builds every discovered Dockerfile and runs `trivy image` against the
Acknowledge: 

ID: complexity-health::rust/crates/css-dead-code/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 32/100 — below the 40 threshold (complexity 59 over 353 lines of code).
#   rust/crates/css-dead-code/src/lib.rs:1
# Code: //! Built-in CSS/Tailwind dead-class scan. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/dead-code/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 30/100 — below the 40 threshold (complexity 66 over 437 lines of code).
#   rust/crates/dead-code/src/lib.rs:1
# Code: //! Built-in dead-code / unused-export / unused-dependency / circular-import
Acknowledge: 

ID: complexity-health::rust/crates/dependency-license-scan/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 16/100 — below the 40 threshold (complexity 132 over 1682 lines of code).
#   rust/crates/dependency-license-scan/src/lib.rs:1
# Code: //! Dependency license/vulnerability scan orchestrators. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/deps-dev-client/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 27/100 — below the 40 threshold (complexity 67 over 657 lines of code).
#   rust/crates/deps-dev-client/src/lib.rs:1
# Code: //! deps.dev API client + npm-registry/unpkg license fallbacks, shared by
Acknowledge: 

ID: complexity-health::rust/crates/enforce-gate-branch-protection/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 35/100 — below the 40 threshold (complexity 23 over 676 lines of code).
#   rust/crates/enforce-gate-branch-protection/src/lib.rs:1
# Code: //! `enforce-gate-branch-protection <org/repo> [<org/repo>...] [--apply]` —
Acknowledge: 

ID: complexity-health::rust/crates/fix-pr/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 22/100 — below the 40 threshold (complexity 83 over 1209 lines of code).
#   rust/crates/fix-pr/src/lib.rs:1
# Code: //! Bulk "fix all findings" PR generator — the scan-wide counterpart to
Acknowledge: 

ID: complexity-health::rust/crates/fs-utils/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 35/100 — below the 40 threshold (complexity 32 over 497 lines of code).
#   rust/crates/fs-utils/src/lib.rs:1
# Code: //! Pure filesystem/content helpers shared by Ignite's checks — file
Acknowledge: 

ID: complexity-health::rust/crates/gha-security/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 38/100 — below the 40 threshold (complexity 22 over 436 lines of code).
#   rust/crates/gha-security/src/lib.rs:1
# Code: //! GitHub Actions workflow security scan via zizmor (Trail of Bits'
Acknowledge: 

ID: complexity-health::rust/crates/github-api/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 27/100 — below the 40 threshold (complexity 57 over 835 lines of code).
#   rust/crates/github-api/src/lib.rs:1
# Code: //! Faithful port of `lib/github-api.js` — GitHub API access without
Acknowledge: 

ID: complexity-health::rust/crates/governance-ci/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 38/100 — below the 40 threshold (complexity 33 over 290 lines of code).
#   rust/crates/governance-ci/src/lib.rs:1
# Code: //! Phase 5: org governance CI, run locally via `act`. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/guidelines/src/checks.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 25/100 — below the 40 threshold (complexity 87 over 680 lines of code).
#   rust/crates/guidelines/src/checks.rs:1
# Code: //! Mechanical checks for the automated subset of the guideline catalog.
Acknowledge: 

ID: complexity-health::rust/crates/iac-security/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 31/100 — below the 40 threshold (complexity 57 over 475 lines of code).
#   rust/crates/iac-security/src/lib.rs:1
# Code: //! IaC/container misconfiguration scan (Dockerfiles, Terraform, Kubernetes
Acknowledge: 

ID: complexity-health::rust/crates/image-provenance/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 29 over 280 lines of code).
#   rust/crates/image-provenance/src/lib.rs:1
# Code: //! Sigstore/cosign keyless-signature verification for external Dockerfile
Acknowledge: 

ID: complexity-health::rust/crates/license-classification/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 25 over 314 lines of code).
#   rust/crates/license-classification/src/lib.rs:1
# Code: //! SPDX license tier classification and version-range helpers shared by
Acknowledge: 

ID: complexity-health::rust/crates/llm-client/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 37/100 — below the 40 threshold (complexity 22 over 546 lines of code).
#   rust/crates/llm-client/src/lib.rs:1
# Code: //! Shared local-LLM/OpenAI chat-completions client. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/llm-deep-scan/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 23/100 — below the 40 threshold (complexity 120 over 602 lines of code).
#   rust/crates/llm-deep-scan/src/lib.rs:1
# Code: //! Local LLM (Ollama/llama.cpp-compatible, or OpenAI) security/quality
Acknowledge: 

ID: complexity-health::rust/crates/mcp-server/src/main.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 25/100 — below the 40 threshold (complexity 62 over 1128 lines of code).
#   rust/crates/mcp-server/src/main.rs:1
# Code: //! MCP server exposing the company AI validation guidelines, faithful
Acknowledge: 

ID: complexity-health::rust/crates/module-graph/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 29/100 — below the 40 threshold (complexity 53 over 660 lines of code).
#   rust/crates/module-graph/src/lib.rs:1
# Code: //! Lightweight JS/TS module graph: parses import/require/export statements
Acknowledge: 

ID: complexity-health::rust/crates/notifications/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 32/100 — below the 40 threshold (complexity 33 over 815 lines of code).
#   rust/crates/notifications/src/lib.rs:1
# Code: //! Faithful port of `lib/notifications.js`'s email-building and sending
Acknowledge: 

ID: complexity-health::rust/crates/override-engine/src/collect.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 25/100 — below the 40 threshold (complexity 109 over 545 lines of code).
#   rust/crates/override-engine/src/collect.rs:1
# Code: //! Turns every check's raw findings (`RawFinding`/`CodeqlFinding`/license
Acknowledge: 

ID: complexity-health::rust/crates/package-hallucination/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 36/100 — below the 40 threshold (complexity 33 over 370 lines of code).
#   rust/crates/package-hallucination/src/lib.rs:1
# Code: //! AI package-hallucination / slopsquat detection. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/phase4-orchestrator/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 24/100 — below the 40 threshold (complexity 58 over 1381 lines of code).
#   rust/crates/phase4-orchestrator/src/lib.rs:1
# Code: //! Phase 4 check orchestrator. Faithful port of server.js's
Acknowledge: 

ID: complexity-health::rust/crates/pii-dataflow/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 30/100 — below the 40 threshold (complexity 57 over 506 lines of code).
#   rust/crates/pii-dataflow/src/lib.rs:1
# Code: //! Sensitive data-flow (PII/GDPR) SAST via Bearer. Faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/pipeline-core/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 32/100 — below the 40 threshold (complexity 43 over 511 lines of code).
#   rust/crates/pipeline-core/src/lib.rs:1
# Code: //! Pipeline orchestration helpers shared across `validate-all`/`onboard`/
Acknowledge: 

ID: complexity-health::rust/crates/report-vulnerability/src/main.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 34/100 — below the 40 threshold (complexity 30 over 568 lines of code).
#   rust/crates/report-vulnerability/src/main.rs:1
# Code: //! `report-vulnerability <org/repo> --summary <str> --severity <level>
Acknowledge: 

ID: complexity-health::rust/crates/secret-verifier/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 27/100 — below the 40 threshold (complexity 60 over 837 lines of code).
#   rust/crates/secret-verifier/src/lib.rs:1
# Code: //! Active, read-only credential verification — the GHAS-parity gap noted
Acknowledge: 

ID: complexity-health::rust/crates/secrets/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 23/100 — below the 40 threshold (complexity 82 over 995 lines of code).
#   rust/crates/secrets/src/lib.rs:1
# Code: //! Regex-based secret scan + optional gitleaks supplement. Faithful port
Acknowledge: 

ID: complexity-health::rust/crates/server/src/auth.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 31/100 — below the 40 threshold (complexity 41 over 730 lines of code).
#   rust/crates/server/src/auth.rs:1
# Code: //! Session/API-key auth route wiring — Rust port of `auth.js`'s Express
Acknowledge: 

ID: complexity-health::rust/crates/server/src/main.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 35/100 — below the 40 threshold (complexity 20 over 890 lines of code).
#   rust/crates/server/src/main.rs:1
# Code: //! Ignite's HTTP server — Rust port of `server.js`'s route layer.
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/daily_report.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 23/100 — below the 40 threshold (complexity 79 over 1074 lines of code).
#   rust/crates/server/src/routes/daily_report.rs:1
# Code: //! Org-level daily findings report: once a day (default 23:59 server-local
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/effectivate.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 35/100 — below the 40 threshold (complexity 25 over 647 lines of code).
#   rust/crates/server/src/routes/effectivate.rs:1
# Code: //! `POST /api/projects/:projectId/effectivate` — faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/github_pr_status.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 32/100 — below the 40 threshold (complexity 59 over 361 lines of code).
#   rust/crates/server/src/routes/github_pr_status.rs:1
# Code: //! POST /api/pipeline/:jobId/github-check — faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/issues.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 21 over 427 lines of code).
#   rust/crates/server/src/routes/issues.rs:1
# Code: //! /api/issues/{explain,suggest-fix} — faithful port of routes/issues.js.
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/org_repos.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 30/100 — below the 40 threshold (complexity 55 over 590 lines of code).
#   rust/crates/server/src/routes/org_repos.rs:1
# Code: //! `GET /api/org-repos/:org` — the web UI's "GitHub Org" view: explore
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/pipeline_interactive.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 29/100 — below the 40 threshold (complexity 44 over 912 lines of code).
#   rust/crates/server/src/routes/pipeline_interactive.rs:1
# Code: //! POST /api/pipeline — faithful port of routes/pipeline-interactive.js:
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/pipeline_interactive/run.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 22/100 — below the 40 threshold (complexity 108 over 816 lines of code).
#   rust/crates/server/src/routes/pipeline_interactive/run.rs:1
# Code: //! The actual phase-by-phase driver for `POST /api/pipeline` — split
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/pipeline_onboard.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 26/100 — below the 40 threshold (complexity 76 over 707 lines of code).
#   rust/crates/server/src/routes/pipeline_onboard.rs:1
# Code: //! POST /api/pipeline/onboard — faithful port of routes/pipeline-onboard.js:
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/pipeline_validate.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 22/100 — below the 40 threshold (complexity 88 over 1082 lines of code).
#   rust/crates/server/src/routes/pipeline_validate.rs:1
# Code: //! POST /api/pipeline/validate-all — faithful port of
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/settings.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 39/100 — below the 40 threshold (complexity 24 over 360 lines of code).
#   rust/crates/server/src/routes/settings.rs:1
# Code: //! Admin settings for the org daily report (`/api/admin/settings/daily-report`).
Acknowledge: 

ID: complexity-health::rust/crates/server/src/routes/studio.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 27/100 — below the 40 threshold (complexity 52 over 994 lines of code).
#   rust/crates/server/src/routes/studio.rs:1
# Code: //! `/api/pipeline/:jobId/studio/*` — faithful (partial) port of
Acknowledge: 

ID: complexity-health::rust/crates/staging/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 31/100 — below the 40 threshold (complexity 50 over 521 lines of code).
#   rust/crates/staging/src/lib.rs:1
# Code: //! Faithful port of `server.js`'s staging/extraction layer — the guarded
Acknowledge: 

ID: complexity-health::rust/crates/studio-manifests/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 24/100 — below the 40 threshold (complexity 113 over 619 lines of code).
#   rust/crates/studio-manifests/src/lib.rs:1
# Code: //! The manifest parsers server.js's dependency license/vulnerability
Acknowledge: 

ID: complexity-health::rust/crates/tool-runner/src/lib.rs::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 27/100 — below the 40 threshold (complexity 67 over 640 lines of code).
#   rust/crates/tool-runner/src/lib.rs:1
# Code: //! External-tool process execution + the sanitizers that guard it — every
Acknowledge: 

ID: complexity-health::vscode-extension/src/api.ts::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 23/100 — below the 40 threshold (complexity 133 over 547 lines of code).
#   vscode-extension/src/api.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::vscode-extension/src/dailyReport.ts::1::high-complexity
# [WARNING] complexity-health - Cyclomatic complexity 41 (cognitive 102) — over the 20 threshold past which functions become difficult to test exhaustively. CRAP score 1722 (no coverage data ingested — treated as 0% for CRAP).
#   vscode-extension/src/dailyReport.ts:1
# Code: /**
Acknowledge: 

ID: complexity-health::vscode-extension/src/extension.ts::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 19/100 — below the 40 threshold (complexity 159 over 790 lines of code).
#   vscode-extension/src/extension.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::vscode-extension/src/panels/controlPanel.ts::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 32/100 — below the 40 threshold (complexity 36 over 640 lines of code).
#   vscode-extension/src/panels/controlPanel.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: complexity-health::vscode-extension/src/reviewFile.ts::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 37/100 — below the 40 threshold (complexity 43 over 239 lines of code).
#   vscode-extension/src/reviewFile.ts:1
# Code: import * as fs from 'fs/promises';
Acknowledge: 

ID: complexity-health::vscode-extension/src/upload.ts::1::low-maintainability
# [WARNING] complexity-health - Maintainability Index 37/100 — below the 40 threshold (complexity 48 over 194 lines of code).
#   vscode-extension/src/upload.ts:1
# Code: /**
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::012ed889
# [WARNING] css-dead-code - CSS class ".docsearch" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 40 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::04a53937
# [WARNING] css-dead-code - CSS class ".theme-live-codeblock" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 40 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::52d7aa74
# [WARNING] css-dead-code - CSS class ".theme-mermaid" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 40 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::7f1b5cb7
# [WARNING] css-dead-code - CSS class ".core" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 40 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::d7d2e041
# [WARNING] css-dead-code - CSS class ".infima" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 40 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::e94cad3e
# [WARNING] css-dead-code - CSS class ".theme-search-algolia" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 40 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::f7a17797
# [WARNING] css-dead-code - CSS class ".theme-common" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 40 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::fc15df4f
# [WARNING] css-dead-code - CSS class ".plugin-debug" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 40 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css::1::unused-css-class::fed58fab
# [WARNING] css-dead-code - CSS class ".theme-classic" is declared in docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css but never referenced in a class/className attribute across 40 scanned markup file(s).
#   docs-site/.docusaurus/docusaurus-plugin-css-cascade-layers/default/layers.css:1
# Code: @layer docusaurus.infima, docusaurus.theme-common, docusaurus.theme-classic, docusaurus.core, docusaurus.plugin-debug, docusaurus.theme-mermaid, docusaurus.theme-live-codeblock, docusaurus.theme-search-algolia.docsearch, docusaurus.theme-search-algolia;
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::173::unused-css-class
# [WARNING] css-dead-code - CSS class ".heroShot" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 38 scanned markup file(s).
#   docs-site/src/css/custom.css:173
# Code: .heroShot {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::193::unused-css-class
# [WARNING] css-dead-code - CSS class ".phaseDiagram" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 38 scanned markup file(s).
#   docs-site/src/css/custom.css:193
# Code: .phaseDiagram {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::209::unused-css-class
# [WARNING] css-dead-code - CSS class ".phase-link" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 38 scanned markup file(s).
#   docs-site/src/css/custom.css:209
# Code: .phase-link {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::32::unused-css-class
# [WARNING] css-dead-code - CSS class ".markdown" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 38 scanned markup file(s).
#   docs-site/src/css/custom.css:32
# Code: .markdown {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::88::unused-css-class
# [WARNING] css-dead-code - CSS class ".theme-admonition" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 38 scanned markup file(s).
#   docs-site/src/css/custom.css:88
# Code: .theme-admonition {
Acknowledge: 

ID: css-dead-code::docs-site/src/css/custom.css::95::unused-css-class
# [WARNING] css-dead-code - CSS class ".theme-doc-markdown" is declared in docs-site/src/css/custom.css but never referenced in a class/className attribute across 38 scanned markup file(s).
#   docs-site/src/css/custom.css:95
# Code: .theme-doc-markdown table {
Acknowledge: 

ID: css-dead-code::docs/assets/css/style.scss::4::unused-css-class
# [WARNING] css-dead-code - CSS class ".theme" is declared in docs/assets/css/style.scss but never referenced in a class/className attribute across 38 scanned markup file(s).
#   docs/assets/css/style.scss:4
# Code: @import "{{ site.theme }}";
Acknowledge: 

ID: css-dead-code::docs/assets/css/style.scss::6::unused-css-class
# [WARNING] css-dead-code - CSS class ".main-content" is declared in docs/assets/css/style.scss but never referenced in a class/className attribute across 38 scanned markup file(s).
#   docs/assets/css/style.scss:6
# Code: // Cayman's default .main-content is a fixed ~64rem column with no overflow
Acknowledge: 

ID: dead-code::docs-site/.docusaurus/client-modules.js::1::unused-file
# [WARNING] dead-code - docs-site/.docusaurus/client-modules.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/.docusaurus/client-modules.js:1
# Code: export default [
Acknowledge: 

ID: dead-code::docs-site/.docusaurus/registry.js::1::unused-file
# [WARNING] dead-code - docs-site/.docusaurus/registry.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/.docusaurus/registry.js:1
# Code: export default {
Acknowledge: 

ID: dead-code::docs-site/.docusaurus/routes.js::1::unused-file
# [WARNING] dead-code - docs-site/.docusaurus/routes.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/.docusaurus/routes.js:1
# Code: import React from 'react';
Acknowledge: 

ID: dead-code::docs-site/sidebars.js::1::unused-file
# [WARNING] dead-code - docs-site/sidebars.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/sidebars.js:1
# Code: // @ts-check
Acknowledge: 

ID: dead-code::docs-site/src/clientModules/eagerImages.js::1::unused-file
# [WARNING] dead-code - docs-site/src/clientModules/eagerImages.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   docs-site/src/clientModules/eagerImages.js:1
# Code: // Docusaurus's MDX <img> component auto-sets loading="lazy" on every doc
Acknowledge: 

ID: dead-code::public/i18n.js::1::unused-file
# [WARNING] dead-code - public/i18n.js is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   public/i18n.js:1
# Code: // Ignite web UI translations — static UI chrome only (buttons, labels,
Acknowledge: 

ID: dead-code::vscode-extension/src/diagnostics.ts::1::unused-file
# [WARNING] dead-code - vscode-extension/src/diagnostics.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/diagnostics.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/extension.ts::1::unused-file
# [WARNING] dead-code - vscode-extension/src/extension.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/extension.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/panels/controlPanel.ts::1::unused-file
# [WARNING] dead-code - vscode-extension/src/panels/controlPanel.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/panels/controlPanel.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/panels/findingsTree.ts::1::unused-file
# [WARNING] dead-code - vscode-extension/src/panels/findingsTree.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/panels/findingsTree.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/panels/reportPanel.ts::1::unused-file
# [WARNING] dead-code - vscode-extension/src/panels/reportPanel.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/panels/reportPanel.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/panels/toolsStatusTree.ts::1::unused-file
# [WARNING] dead-code - vscode-extension/src/panels/toolsStatusTree.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/panels/toolsStatusTree.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/prePushHook.ts::1::unused-file
# [WARNING] dead-code - vscode-extension/src/prePushHook.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/prePushHook.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/progress.ts::1::unused-file
# [WARNING] dead-code - vscode-extension/src/progress.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/progress.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/reviewFile.ts::26::unused-export
# [WARNING] dead-code - Export "cleanJustification" in vscode-extension/src/reviewFile.ts is never imported by name anywhere else in the project — a candidate for removal.
#   vscode-extension/src/reviewFile.ts:26
# Code: export function cleanJustification(justification: string): string {
Acknowledge: 

ID: dead-code::vscode-extension/src/uiState.ts::1::unused-file
# [WARNING] dead-code - vscode-extension/src/uiState.ts is never imported/required from any detected entry point (package.json main/exports/bin, index/main/server/app files, config files, or tests) — a candidate for deletion.
#   vscode-extension/src/uiState.ts:1
# Code: import * as vscode from 'vscode';
Acknowledge: 

ID: dead-code::vscode-extension/src/upload.ts::19::unused-export
# [WARNING] dead-code - Export "MAX_UPLOAD_FILES" in vscode-extension/src/upload.ts is never imported by name anywhere else in the project — a candidate for removal.
#   vscode-extension/src/upload.ts:19
# Code: export const MAX_UPLOAD_FILES = 100_000;
Acknowledge: 

ID: dead-code::vscode-extension/src/upload.ts::20::unused-export
# [WARNING] dead-code - Export "MAX_UPLOAD_BYTES" in vscode-extension/src/upload.ts is never imported by name anywhere else in the project — a candidate for removal.
#   vscode-extension/src/upload.ts:20
# Code: export const MAX_UPLOAD_BYTES = 1024 * 1024 * 1024;
Acknowledge: 

ID: dependency-vulnerability::rust/crates/server/Cargo.toml::66::jsonwebtoken::GHSA-h395-gr6q-cpjc
# [WARNING] dependency-vulnerability - jsonwebtoken@9.3.1 — GHSA-h395-gr6q-cpjc: jsonwebtoken has Type Confusion that leads to potential authorization bypass (CVE-2026-25537) (CVSS 0)
#   rust/crates/server/Cargo.toml:66
# Code: jsonwebtoken = "9"
Acknowledge: 

ID: gha-security::.github/workflows/check-env-var-drift.yml::25
# [WARNING] gha-security - credential persistence through GitHub Actions artifacts (uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4)
#   .github/workflows/check-env-var-drift.yml:25
# Code: - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
Acknowledge: 

ID: gha-security::.github/workflows/deploy-docs.yml::13
# [ERROR] gha-security - overly broad permissions (  pages: write)
#   .github/workflows/deploy-docs.yml:13
Acknowledge: `pages: write` + `id-token: write` (next entry) are exactly the two permissions GitHub's own actions/deploy-pages documentation requires for OIDC-based Pages deployment - already the minimal job-level set (no broader contents:write, etc.). zizmor's excessive-permissions rule flags any explicit write scope without knowing what the job's own actions actually need; this is that documented minimum, not excessive in practice.

ID: gha-security::.github/workflows/deploy-docs.yml::14
# [ERROR] gha-security - overly broad permissions (  id-token: write)
#   .github/workflows/deploy-docs.yml:14
Acknowledge: Same justification as the `pages: write` entry above - the minimal, documented permission pair actions/deploy-pages needs for OIDC-based deployment.

ID: gha-security::.github/workflows/deploy-docs.yml::24
# [WARNING] gha-security - credential persistence through GitHub Actions artifacts (uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4)
#   .github/workflows/deploy-docs.yml:24
# Code: - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
Acknowledge: 

ID: iac-security::Dockerfile::140
# [WARNING] iac-security - Pin versions in apt get install. Instead of `apt-get install <package>` use `apt-get install <package>=<version>`
#   Dockerfile:140
# Code: RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
Acknowledge: 

ID: iac-security::Dockerfile::162
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:162
# Code: RUN if [ "$INSTALL_ORT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::171
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:171
# Code: RUN if [ "$INSTALL_TRIVY" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::175
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:175
# Code: RUN if [ "$INSTALL_CHECKOV" = "true" ]; then pipx install checkov --pip-args="--no-compile" && pipx ensurepath; fi
Acknowledge: 

ID: iac-security::Dockerfile::184
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:184
# Code: RUN if [ "$INSTALL_GITLEAKS" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::190
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:190
# Code: RUN if [ "$INSTALL_SYFT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::1::5c411837
# [WARNING] iac-security - Ensure that HEALTHCHECK instructions have been added to container images
#   Dockerfile:1
# Code: # Ignite, self-contained: the Rust server/CLI/MCP binaries plus every
Acknowledge: 

ID: iac-security::Dockerfile::1::629a3996
# [WARNING] iac-security - No HEALTHCHECK defined
#   Dockerfile:1
# Code: # Ignite, self-contained: the Rust server/CLI/MCP binaries plus every
Acknowledge: 

ID: iac-security::Dockerfile::200
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:200
# Code: RUN if [ "$INSTALL_SEMGREP" = "true" ]; then pipx install semgrep --pip-args="--no-compile" && pipx ensurepath; fi
Acknowledge: 

ID: iac-security::Dockerfile::201
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:201
# Code: RUN if [ "$INSTALL_BEARER" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::225::09cd120f
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:225
# Code: RUN if [ "$INSTALL_GUARDDOG" = "true" ] || [ "$INSTALL_LICENSEE" = "true" ] || [ "$INSTALL_COCOAPODS" = "true" ] || [ "$INSTALL_ORT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::225::19c88dc5
# [WARNING] iac-security - Pin versions in gem install. Instead of `gem install <gem>` use `gem install <gem>:<version>`
#   Dockerfile:225
# Code: RUN if [ "$INSTALL_GUARDDOG" = "true" ] || [ "$INSTALL_LICENSEE" = "true" ] || [ "$INSTALL_COCOAPODS" = "true" ] || [ "$INSTALL_ORT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::225::bdfb7069
# [WARNING] iac-security - Pin versions in apt get install. Instead of `apt-get install <package>` use `apt-get install <package>=<version>`
#   Dockerfile:225
# Code: RUN if [ "$INSTALL_GUARDDOG" = "true" ] || [ "$INSTALL_LICENSEE" = "true" ] || [ "$INSTALL_COCOAPODS" = "true" ] || [ "$INSTALL_ORT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::238
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:238
# Code: RUN if [ "$INSTALL_PICKLESCAN" = "true" ]; then pipx install picklescan --pip-args="--no-compile" && pipx ensurepath; fi
Acknowledge: 

ID: iac-security::Dockerfile::239
# [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`
#   Dockerfile:239
# Code: RUN if [ "$INSTALL_ZIZMOR" = "true" ]; then pipx install zizmor --pip-args="--no-compile" && pipx ensurepath; fi
Acknowledge: 

ID: iac-security::Dockerfile::240
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:240
# Code: RUN if [ "$INSTALL_OASDIFF" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::268
# [WARNING] iac-security - Pin versions in npm. Instead of `npm install <package>` use `npm install <package>@<version>`
#   Dockerfile:268
# Code: RUN if [ "$INSTALL_JSCPD" = "true" ]; then npm install -g jscpd; fi
Acknowledge: 

ID: iac-security::Dockerfile::269::2ddec02b
# [WARNING] iac-security - Multiple consecutive `RUN` instructions. Consider consolidation.
#   Dockerfile:269
# Code: RUN if [ "$INSTALL_SPECTRAL" = "true" ]; then npm install -g @stoplight/spectral-cli; fi
Acknowledge: 

ID: iac-security::Dockerfile::269::37ad8298
# [WARNING] iac-security - Pin versions in npm. Instead of `npm install <package>` use `npm install <package>@<version>`
#   Dockerfile:269
# Code: RUN if [ "$INSTALL_SPECTRAL" = "true" ]; then npm install -g @stoplight/spectral-cli; fi
Acknowledge: 

ID: iac-security::Dockerfile::290
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:290
# Code: RUN if [ "$INSTALL_ACT" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::304
# [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check
#   Dockerfile:304
# Code: RUN if [ "$INSTALL_DOCKER_CLI" = "true" ]; then \
Acknowledge: 

ID: iac-security::Dockerfile::356
# [WARNING] iac-security - Non-numeric user-id may not be resolvable by host system
#   Dockerfile:356
# Code: USER ignite
Acknowledge: 

ID: image-provenance::Dockerfile::19
# [WARNING] image-provenance - Base image "rust:1-bookworm" has no verifiable Sigstore/cosign signature — supply-chain provenance can't be confirmed.
#   Dockerfile:19
# Code: FROM rust:1-bookworm AS rust-builder
Acknowledge: 

ID: image-provenance::Dockerfile::30
# [WARNING] image-provenance - Base image "node:24-bookworm-slim" has no verifiable Sigstore/cosign signature — supply-chain provenance can't be confirmed.
#   Dockerfile:30
# Code: FROM node:24-bookworm-slim
Acknowledge: 

ID: secret::config.json::20
# [ERROR] secret - Base64 High Entropy String
#   config.json:20
# Code: "clientSecret": "59121bde39f195d1d18562a131e1e7d05d32175d",
Acknowledge: config.json is gitignored (.gitignore:3) and confirmed untracked (git ls-files returns nothing for it) - it never leaves this machine via git. The pre-push scan covers the whole working tree regardless of what's actually being pushed, so this local-only file still surfaces here.

ID: secret::docs-site/docs/ci-integration.md::493
# [ERROR] secret - Hardcoded token
#   docs-site/docs/ci-integration.md:493
# Code: -d '{"regex": "acme_live_[a-zA-Z0-9]{24}", "sample": "token: acme_live_abcdef0123456789ghijklmn"}'
Acknowledge: Fictional pattern/sample pair in a docs-site example curl command demonstrating the custom-secret-pattern playground endpoint - "acme_live_..." isn't a real vendor token format, and the sample string is fabricated for the example, not a real credential.

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

ID: secret::rust/crates/secrets/src/lib.rs::1025
# [ERROR] secret - Hardcoded stripe-access-token
#   rust/crates/secrets/src/lib.rs:1025
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

ID: secret::rust/crates/server/src/tests/pipeline_sequence.rs::10
# [WARNING] secret - Hardcoded aws_secret (in a test file — likely a fixture, not a real credential)
#   rust/crates/server/src/tests/pipeline_sequence.rs:10
# Code: std::fs::write(dir.path().join("config.js"), "const aws_secret_key = 'AKIAABCDEFGHIJKLMNOP';\nconsole.log(aws_secret_key);\n").unwrap();
Acknowledge: 

ID: secret::vscode-extension/src/serverUrl.test.ts::28
# [WARNING] secret - Hardcoded generic-api-key (in a test file — likely a fixture, not a real credential)
#   vscode-extension/src/serverUrl.test.ts:28
# Code: const key = 'ignite_0123456789abcdef';
Acknowledge: 
