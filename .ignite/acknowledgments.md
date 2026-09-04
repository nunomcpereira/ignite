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

# Scanned against commit: c7b0b07961d6f1cb618ef1a27ba9e3d7390b996e (working tree at push time - findings/justifications below reflect this commit's code, not necessarily what ends up pushed if the tree changes after)

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

ID: secret::rust/crates/server/src/auth/oidc.rs::316
# Issue #3
# [ERROR] secret - Hardcoded secret
#   rust/crates/server/src/auth/oidc.rs:316
Acknowledge: Test-only OIDC client_secret ("test-secret") configured against a local mock IdP spawned within the same unit test, not a real credential.

ID: secret::rust/crates/server/src/auth/github_oauth.rs::288
# Issue #4
# [ERROR] secret - Hardcoded secret
#   rust/crates/server/src/auth/github_oauth.rs:288
Acknowledge: Test-only GitHub OAuth client_secret ("secret-123") configured against a local mock GitHub server spawned within the same unit test, not a real credential.

ID: secret::rust/crates/secrets/src/lib.rs::565
# Issue #5
# [ERROR] secret - Hardcoded connection-string credential
#   rust/crates/secrets/src/lib.rs:565
Acknowledge: Fake DATABASE_URL connection-string literal written to a scratch fixture file within a unit test for the URI_CREDENTIAL_RE detector, not a real credential - uses example.com (IANA/RFC 2606-reserved for documentation) and an explicitly-labeled placeholder password.

ID: gha-security::.github/workflows/deploy-docs.yml::13
# Issue #6
# [ERROR] gha-security - overly broad permissions (  pages: write)
#   .github/workflows/deploy-docs.yml:13
Acknowledge: `pages: write` + `id-token: write` (next entry) are exactly the two permissions GitHub's own actions/deploy-pages documentation requires for OIDC-based Pages deployment - already the minimal job-level set (no broader contents:write, etc.). zizmor's excessive-permissions rule flags any explicit write scope without knowing what the job's own actions actually need; this is that documented minimum, not excessive in practice.

ID: gha-security::.github/workflows/deploy-docs.yml::14
# Issue #7
# [ERROR] gha-security - overly broad permissions (  id-token: write)
#   .github/workflows/deploy-docs.yml:14
Acknowledge: Same justification as the `pages: write` entry above - the minimal, documented permission pair actions/deploy-pages needs for OIDC-based deployment.

ID: secret::rust/crates/llm-client/src/lib.rs::327
# Issue #8
# [ERROR] secret - Hardcoded api_key
#   rust/crates/llm-client/src/lib.rs:327
Acknowledge: Fake Anthropic API key literal ("sk-ant-test") used as test-fixture input to verify the new Anthropic-provider request/auth-header wiring, not a real credential.

ID: codeql-sast::public/index.html::776::js/xss-through-dom
# Issue #9
# [ERROR] codeql-sast - DOM text is reinterpreted as HTML without escaping meta-characters.
#   public/index.html:776
# Code: document.querySelectorAll('[data-i18n]').forEach((el) => { el.innerHTML = t(el.getAttribute('data-i18n')); });
Acknowledge: t()'s only inputs are (1) the fixed attribute-name strings 'data-i18n'/'data-i18n-title'/'data-i18n-placeholder' read off the DOM and (2) a lookup into window.IGNITE_I18N.translations, which is entirely defined by public/i18n.js - a file committed to this repo and only ever edited by a developer/operator, never populated from user input, the network, or any request parameter. innerHTML (not textContent) is used deliberately so a handful of translated strings can carry inline markup (e.g. the upload screen's bolded "folder"/".zip" spans) - switching to textContent would silently break those. No untrusted data ever reaches this call. (auto-carried-forward from codeql-sast::public/index.html::732::js/xss-through-dom - pure line-number drift, flagged code unchanged) (auto-carried-forward from codeql-sast::public/index.html::775::js/xss-through-dom - pure line-number drift, flagged code unchanged)

ID: container-image-cve::Dockerfile::1::cve-2026-53613@bsdutils
# Issue #10
# [ERROR] container-image-cve - bsdutils@1:2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-76642@bsdutils
# Issue #11
# [ERROR] container-image-cve - bsdutils@1:2.38.1-5+deb12u3: util-linux: util-linux: failed external mount helper still runs privileged X-mount post-hooks
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78408@bsdutils
# Issue #12
# [ERROR] container-image-cve - bsdutils@1:2.38.1-5+deb12u3: util-linux: util-linux: nsenter --join-cgroup leaks root cgroup migration authority
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78409@bsdutils
# Issue #13
# [ERROR] container-image-cve - bsdutils@1:2.38.1-5+deb12u3: util-linux: util-linux: X-mount.subdir detached-tree resolution can escape via intermediate symlinks
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78410@bsdutils
# Issue #14
# [ERROR] container-image-cve - bsdutils@1:2.38.1-5+deb12u3: util-linux: util-linux: restricted bind mounts do not pin the source, allowing X-mount.owner/group/mode redirection
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-12064@curl
# Issue #15
# [ERROR] container-image-cve - curl@7.88.1-10+deb12u15: curl: curl: SSH host verification bypass when using schemeless URLs with SFTP/SCP
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-6276@curl
# Issue #16
# [ERROR] container-image-cve - curl@7.88.1-10+deb12u15: curl: libcurl: Information disclosure due to cookie leak when reusing connections with custom Host headers
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-8286@curl
# Issue #17
# [ERROR] container-image-cve - curl@7.88.1-10+deb12u15: curl: curl: Insecure connection establishment due to TLS configuration mismatch
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-8458@curl
# Issue #18
# [ERROR] container-image-cve - curl@7.88.1-10+deb12u15: curl: libcurl: Unauthorized connection reuse due to a logical error
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-8927@curl
# Issue #19
# [ERROR] container-image-cve - curl@7.88.1-10+deb12u15: curl: Information disclosure due to uncleared proxy authentication state
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-41992@gzip
# Issue #20
# [ERROR] container-image-cve - gzip@1.12-1: gzip: gzip: Information disclosure via global buffer overflow in LZH decompression
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-54369@libacl1
# Issue #21
# [ERROR] container-image-cve - libacl1@2.3.1-3: acl: Symlink traversal privilege escalation via libacl functions
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-53613@libblkid1
# Issue #22
# [ERROR] container-image-cve - libblkid1@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-76642@libblkid1
# Issue #23
# [ERROR] container-image-cve - libblkid1@2.38.1-5+deb12u3: util-linux: util-linux: failed external mount helper still runs privileged X-mount post-hooks
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78408@libblkid1
# Issue #24
# [ERROR] container-image-cve - libblkid1@2.38.1-5+deb12u3: util-linux: util-linux: nsenter --join-cgroup leaks root cgroup migration authority
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78409@libblkid1
# Issue #25
# [ERROR] container-image-cve - libblkid1@2.38.1-5+deb12u3: util-linux: util-linux: X-mount.subdir detached-tree resolution can escape via intermediate symlinks
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78410@libblkid1
# Issue #26
# [ERROR] container-image-cve - libblkid1@2.38.1-5+deb12u3: util-linux: util-linux: restricted bind mounts do not pin the source, allowing X-mount.owner/group/mode redirection
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-12064@libcurl3-gnutls
# Issue #27
# [ERROR] container-image-cve - libcurl3-gnutls@7.88.1-10+deb12u15: curl: curl: SSH host verification bypass when using schemeless URLs with SFTP/SCP
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-6276@libcurl3-gnutls
# Issue #28
# [ERROR] container-image-cve - libcurl3-gnutls@7.88.1-10+deb12u15: curl: libcurl: Information disclosure due to cookie leak when reusing connections with custom Host headers
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-8286@libcurl3-gnutls
# Issue #29
# [ERROR] container-image-cve - libcurl3-gnutls@7.88.1-10+deb12u15: curl: curl: Insecure connection establishment due to TLS configuration mismatch
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-8458@libcurl3-gnutls
# Issue #30
# [ERROR] container-image-cve - libcurl3-gnutls@7.88.1-10+deb12u15: curl: libcurl: Unauthorized connection reuse due to a logical error
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-8927@libcurl3-gnutls
# Issue #31
# [ERROR] container-image-cve - libcurl3-gnutls@7.88.1-10+deb12u15: curl: Information disclosure due to uncleared proxy authentication state
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-12064@libcurl4
# Issue #32
# [ERROR] container-image-cve - libcurl4@7.88.1-10+deb12u15: curl: curl: SSH host verification bypass when using schemeless URLs with SFTP/SCP
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-6276@libcurl4
# Issue #33
# [ERROR] container-image-cve - libcurl4@7.88.1-10+deb12u15: curl: libcurl: Information disclosure due to cookie leak when reusing connections with custom Host headers
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-8286@libcurl4
# Issue #34
# [ERROR] container-image-cve - libcurl4@7.88.1-10+deb12u15: curl: curl: Insecure connection establishment due to TLS configuration mismatch
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-8458@libcurl4
# Issue #35
# [ERROR] container-image-cve - libcurl4@7.88.1-10+deb12u15: curl: libcurl: Unauthorized connection reuse due to a logical error
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-8927@libcurl4
# Issue #36
# [ERROR] container-image-cve - libcurl4@7.88.1-10+deb12u15: curl: Information disclosure due to uncleared proxy authentication state
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-59375@libexpat1
# Issue #37
# [ERROR] container-image-cve - libexpat1@2.5.0-1+deb12u3: firefox: thunderbird: expat: libexpat in Expat allows attackers to trigger large dynamic memory allocations via a small document that is submitted for parsing
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-25210@libexpat1
# Issue #38
# [ERROR] container-image-cve - libexpat1@2.5.0-1+deb12u3: libexpat: libexpat: Information disclosure and data integrity issues due to integer overflow in buffer reallocation
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-45186@libexpat1
# Issue #39
# [ERROR] container-image-cve - libexpat1@2.5.0-1+deb12u3: libexpat: denial of service via crafted XML input
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-66046@libexpat1
# Issue #40
# [ERROR] container-image-cve - libexpat1@2.5.0-1+deb12u3: Expat through 2.8.3 contains a denial of service vulnerability caused  ...
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2023-2953@libldap-2.5-0
# Issue #41
# [ERROR] container-image-cve - libldap-2.5-0@2.5.13+dfsg-5: openldap: null pointer dereference in  ber_memalloc_x  function
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-53613@libmount1
# Issue #42
# [ERROR] container-image-cve - libmount1@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-76642@libmount1
# Issue #43
# [ERROR] container-image-cve - libmount1@2.38.1-5+deb12u3: util-linux: util-linux: failed external mount helper still runs privileged X-mount post-hooks
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78408@libmount1
# Issue #44
# [ERROR] container-image-cve - libmount1@2.38.1-5+deb12u3: util-linux: util-linux: nsenter --join-cgroup leaks root cgroup migration authority
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78409@libmount1
# Issue #45
# [ERROR] container-image-cve - libmount1@2.38.1-5+deb12u3: util-linux: util-linux: X-mount.subdir detached-tree resolution can escape via intermediate symlinks
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78410@libmount1
# Issue #46
# [ERROR] container-image-cve - libmount1@2.38.1-5+deb12u3: util-linux: util-linux: restricted bind mounts do not pin the source, allowing X-mount.owner/group/mode redirection
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-69720@libncurses6
# Issue #47
# [ERROR] container-image-cve - libncurses6@6.4-4: ncurses: ncurses: Buffer overflow vulnerability may lead to arbitrary code execution.
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-69720@libncursesw6
# Issue #48
# [ERROR] container-image-cve - libncursesw6@6.4-4: ncurses: ncurses: Buffer overflow vulnerability may lead to arbitrary code execution.
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-13221@libperl5.36
# Issue #49
# [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl: Perl: Incorrect regular expression processing via large regular expressions
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42496@libperl5.36
# Issue #50
# [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl-archive-tar: perl-archive-tar: Path traversal via crafted symlinks allows arbitrary file access
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-8376@libperl5.36
# Issue #51
# [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl: Perl: Heap buffer overflow when compiling regular expressions on 32-bit builds
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42497@libperl5.36
# Issue #52
# [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Arbitrary file modification via crafted hardlinks during archive extraction
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-48962@libperl5.36
# Issue #53
# [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl-IO-Compress: perl-IO-Compress: Arbitrary code execution via attacker-controlled output glob
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-57432@libperl5.36
# Issue #54
# [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl: Perl: Information disclosure via integer overflow in pack/unpack operations
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-57433@libperl5.36
# Issue #55
# [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: Storable: Storable: Denial of Service via signed integer overflow in deserialization
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-9538@libperl5.36
# Issue #56
# [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Denial of Service via crafted tar header with large entry size
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-69534@libpython3.11-minimal
# Issue #57
# [ERROR] container-image-cve - libpython3.11-minimal@3.11.2-6+deb12u8: python-markdown: denial of service via malformed HTML-like sequences
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-11940@libpython3.11-minimal
# Issue #58
# [ERROR] container-image-cve - libpython3.11-minimal@3.11.2-6+deb12u8: python: cpython: CPython: tarfile extraction filter bypass allows escaping the destination directory
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-15308@libpython3.11-minimal
# Issue #59
# [ERROR] container-image-cve - libpython3.11-minimal@3.11.2-6+deb12u8: python: Python: CPU Denial of Service in HTML parser via repeated unterminated markup declarations
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-3644@libpython3.11-minimal
# Issue #60
# [ERROR] container-image-cve - libpython3.11-minimal@3.11.2-6+deb12u8: cpython: Incomplete control character validation in http.cookies
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-7210@libpython3.11-minimal
# Issue #61
# [ERROR] container-image-cve - libpython3.11-minimal@3.11.2-6+deb12u8: python: expat: Python/Expat: Denial of Service via crafted XML document
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-69534@libpython3.11-stdlib
# Issue #62
# [ERROR] container-image-cve - libpython3.11-stdlib@3.11.2-6+deb12u8: python-markdown: denial of service via malformed HTML-like sequences
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-11940@libpython3.11-stdlib
# Issue #63
# [ERROR] container-image-cve - libpython3.11-stdlib@3.11.2-6+deb12u8: python: cpython: CPython: tarfile extraction filter bypass allows escaping the destination directory
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-15308@libpython3.11-stdlib
# Issue #64
# [ERROR] container-image-cve - libpython3.11-stdlib@3.11.2-6+deb12u8: python: Python: CPU Denial of Service in HTML parser via repeated unterminated markup declarations
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-3644@libpython3.11-stdlib
# Issue #65
# [ERROR] container-image-cve - libpython3.11-stdlib@3.11.2-6+deb12u8: cpython: Incomplete control character validation in http.cookies
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-7210@libpython3.11-stdlib
# Issue #66
# [ERROR] container-image-cve - libpython3.11-stdlib@3.11.2-6+deb12u8: python: expat: Python/Expat: Denial of Service via crafted XML document
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-27820@libruby3.1
# Issue #67
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: zlib: zlib: Memory corruption via buffer overflow in Zlib::GzipReader
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42257@libruby3.1
# Issue #68
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection via CRLF sequences in unvalidated input
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2024-41123@libruby3.1
# Issue #69
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: rexml: rubygem-rexml: DoS when parsing an XML having many specific characters such as whitespace character, >] and ]>
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2024-41946@libruby3.1
# Issue #70
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: rexml: DoS vulnerability in REXML
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2024-49761@libruby3.1
# Issue #71
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: rexml: REXML ReDoS vulnerability
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-27219@libruby3.1
# Issue #72
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: CGI: Denial of Service in CGI::Cookie.parse
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-27220@libruby3.1
# Issue #73
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: CGI: ReDoS in CGI::Util#escapeElement
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-61594@libruby3.1
# Issue #74
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: uri: URI module: Credential exposure via URI + operator
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-41316@libruby3.1
# Issue #75
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: erb: ERB: Arbitrary code execution via deserialization bypass
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42245@libruby3.1
# Issue #76
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: ruby: net-imap: Net::IMAP: Denial of Service via crafted IMAP responses
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42246@libruby3.1
# Issue #77
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: net-imap: ruby: Net::IMAP: Information disclosure via man-in-the-middle attack bypassing TLS
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-47242@libruby3.1
# Issue #78
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection due to improper input validation
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-53613@libsmartcols1
# Issue #79
# [ERROR] container-image-cve - libsmartcols1@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-76642@libsmartcols1
# Issue #80
# [ERROR] container-image-cve - libsmartcols1@2.38.1-5+deb12u3: util-linux: util-linux: failed external mount helper still runs privileged X-mount post-hooks
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78408@libsmartcols1
# Issue #81
# [ERROR] container-image-cve - libsmartcols1@2.38.1-5+deb12u3: util-linux: util-linux: nsenter --join-cgroup leaks root cgroup migration authority
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78409@libsmartcols1
# Issue #82
# [ERROR] container-image-cve - libsmartcols1@2.38.1-5+deb12u3: util-linux: util-linux: X-mount.subdir detached-tree resolution can escape via intermediate symlinks
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78410@libsmartcols1
# Issue #83
# [ERROR] container-image-cve - libsmartcols1@2.38.1-5+deb12u3: util-linux: util-linux: restricted bind mounts do not pin the source, allowing X-mount.owner/group/mode redirection
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-7458@libsqlite3-0
# Issue #84
# [ERROR] container-image-cve - libsqlite3-0@3.40.1-2+deb12u2: sqlite: SQLite integer overflow
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-11822@libsqlite3-0
# Issue #85
# [ERROR] container-image-cve - libsqlite3-0@3.40.1-2+deb12u2: sqlite: SQLite: Arbitrary code execution via crafted FTS5 full-text search data
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-11824@libsqlite3-0
# Issue #86
# [ERROR] container-image-cve - libsqlite3-0@3.40.1-2+deb12u2: sqlite: SQLite: Arbitrary code execution and crash via heap-based buffer overflow in FTS5
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-58050@libssh2-1
# Issue #87
# [ERROR] container-image-cve - libssh2-1@1.10.0-3+b1: libssh2: libssh2: Heap buffer overflow via integer overflow in publickey attribute allocation
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-7598@libssh2-1
# Issue #88
# [ERROR] container-image-cve - libssh2-1@1.10.0-3+b1: libssh2: integer overflow via large username or password arguments
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-16742@libsystemd0
# Issue #89
# [ERROR] container-image-cve - libsystemd0@252.39-1~deb12u2: systemd: systemd-homed: Local privilege escalation via missing home-record signature verification
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-69720@libtinfo6
# Issue #90
# [ERROR] container-image-cve - libtinfo6@6.4-4: ncurses: ncurses: Buffer overflow vulnerability may lead to arbitrary code execution.
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-16742@libudev1
# Issue #91
# [ERROR] container-image-cve - libudev1@252.39-1~deb12u2: systemd: systemd-homed: Local privilege escalation via missing home-record signature verification
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-53613@libuuid1
# Issue #92
# [ERROR] container-image-cve - libuuid1@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-76642@libuuid1
# Issue #93
# [ERROR] container-image-cve - libuuid1@2.38.1-5+deb12u3: util-linux: util-linux: failed external mount helper still runs privileged X-mount post-hooks
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78408@libuuid1
# Issue #94
# [ERROR] container-image-cve - libuuid1@2.38.1-5+deb12u3: util-linux: util-linux: nsenter --join-cgroup leaks root cgroup migration authority
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78409@libuuid1
# Issue #95
# [ERROR] container-image-cve - libuuid1@2.38.1-5+deb12u3: util-linux: util-linux: X-mount.subdir detached-tree resolution can escape via intermediate symlinks
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78410@libuuid1
# Issue #96
# [ERROR] container-image-cve - libuuid1@2.38.1-5+deb12u3: util-linux: util-linux: restricted bind mounts do not pin the source, allowing X-mount.owner/group/mode redirection
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-53613@mount
# Issue #97
# [ERROR] container-image-cve - mount@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-76642@mount
# Issue #98
# [ERROR] container-image-cve - mount@2.38.1-5+deb12u3: util-linux: util-linux: failed external mount helper still runs privileged X-mount post-hooks
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78408@mount
# Issue #99
# [ERROR] container-image-cve - mount@2.38.1-5+deb12u3: util-linux: util-linux: nsenter --join-cgroup leaks root cgroup migration authority
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78409@mount
# Issue #100
# [ERROR] container-image-cve - mount@2.38.1-5+deb12u3: util-linux: util-linux: X-mount.subdir detached-tree resolution can escape via intermediate symlinks
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78410@mount
# Issue #101
# [ERROR] container-image-cve - mount@2.38.1-5+deb12u3: util-linux: util-linux: restricted bind mounts do not pin the source, allowing X-mount.owner/group/mode redirection
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-69720@ncurses-base
# Issue #102
# [ERROR] container-image-cve - ncurses-base@6.4-4: ncurses: ncurses: Buffer overflow vulnerability may lead to arbitrary code execution.
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-69720@ncurses-bin
# Issue #103
# [ERROR] container-image-cve - ncurses-bin@6.4-4: ncurses: ncurses: Buffer overflow vulnerability may lead to arbitrary code execution.
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-13221@perl
# Issue #104
# [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl: Perl: Incorrect regular expression processing via large regular expressions
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42496@perl
# Issue #105
# [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl-archive-tar: perl-archive-tar: Path traversal via crafted symlinks allows arbitrary file access
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-8376@perl
# Issue #106
# [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl: Perl: Heap buffer overflow when compiling regular expressions on 32-bit builds
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42497@perl
# Issue #107
# [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Arbitrary file modification via crafted hardlinks during archive extraction
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-48962@perl
# Issue #108
# [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl-IO-Compress: perl-IO-Compress: Arbitrary code execution via attacker-controlled output glob
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-57432@perl
# Issue #109
# [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl: Perl: Information disclosure via integer overflow in pack/unpack operations
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-57433@perl
# Issue #110
# [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: Storable: Storable: Denial of Service via signed integer overflow in deserialization
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-9538@perl
# Issue #111
# [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Denial of Service via crafted tar header with large entry size
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-13221@perl-base
# Issue #112
# [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl: Perl: Incorrect regular expression processing via large regular expressions
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42496@perl-base
# Issue #113
# [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl-archive-tar: perl-archive-tar: Path traversal via crafted symlinks allows arbitrary file access
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-8376@perl-base
# Issue #114
# [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl: Perl: Heap buffer overflow when compiling regular expressions on 32-bit builds
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42497@perl-base
# Issue #115
# [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Arbitrary file modification via crafted hardlinks during archive extraction
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-48962@perl-base
# Issue #116
# [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl-IO-Compress: perl-IO-Compress: Arbitrary code execution via attacker-controlled output glob
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-57432@perl-base
# Issue #117
# [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl: Perl: Information disclosure via integer overflow in pack/unpack operations
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-57433@perl-base
# Issue #118
# [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: Storable: Storable: Denial of Service via signed integer overflow in deserialization
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-9538@perl-base
# Issue #119
# [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Denial of Service via crafted tar header with large entry size
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-13221@perl-modules-5.36
# Issue #120
# [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl: Perl: Incorrect regular expression processing via large regular expressions
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42496@perl-modules-5.36
# Issue #121
# [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl-archive-tar: perl-archive-tar: Path traversal via crafted symlinks allows arbitrary file access
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-8376@perl-modules-5.36
# Issue #122
# [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl: Perl: Heap buffer overflow when compiling regular expressions on 32-bit builds
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42497@perl-modules-5.36
# Issue #123
# [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Arbitrary file modification via crafted hardlinks during archive extraction
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-48962@perl-modules-5.36
# Issue #124
# [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl-IO-Compress: perl-IO-Compress: Arbitrary code execution via attacker-controlled output glob
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-57432@perl-modules-5.36
# Issue #125
# [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl: Perl: Information disclosure via integer overflow in pack/unpack operations
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-57433@perl-modules-5.36
# Issue #126
# [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: Storable: Storable: Denial of Service via signed integer overflow in deserialization
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-9538@perl-modules-5.36
# Issue #127
# [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Denial of Service via crafted tar header with large entry size
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-7246@python3-click
# Issue #128
# [ERROR] container-image-cve - python3-click@8.1.3-2: github.com/pallets/click: Pallets Click: Arbitrary command execution via command injection in click.edit()
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-69534@python3.11
# Issue #129
# [ERROR] container-image-cve - python3.11@3.11.2-6+deb12u8: python-markdown: denial of service via malformed HTML-like sequences
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-11940@python3.11
# Issue #130
# [ERROR] container-image-cve - python3.11@3.11.2-6+deb12u8: python: cpython: CPython: tarfile extraction filter bypass allows escaping the destination directory
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-15308@python3.11
# Issue #131
# [ERROR] container-image-cve - python3.11@3.11.2-6+deb12u8: python: Python: CPU Denial of Service in HTML parser via repeated unterminated markup declarations
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-3644@python3.11
# Issue #132
# [ERROR] container-image-cve - python3.11@3.11.2-6+deb12u8: cpython: Incomplete control character validation in http.cookies
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-7210@python3.11
# Issue #133
# [ERROR] container-image-cve - python3.11@3.11.2-6+deb12u8: python: expat: Python/Expat: Denial of Service via crafted XML document
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-69534@python3.11-minimal
# Issue #134
# [ERROR] container-image-cve - python3.11-minimal@3.11.2-6+deb12u8: python-markdown: denial of service via malformed HTML-like sequences
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-11940@python3.11-minimal
# Issue #135
# [ERROR] container-image-cve - python3.11-minimal@3.11.2-6+deb12u8: python: cpython: CPython: tarfile extraction filter bypass allows escaping the destination directory
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-15308@python3.11-minimal
# Issue #136
# [ERROR] container-image-cve - python3.11-minimal@3.11.2-6+deb12u8: python: Python: CPU Denial of Service in HTML parser via repeated unterminated markup declarations
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-3644@python3.11-minimal
# Issue #137
# [ERROR] container-image-cve - python3.11-minimal@3.11.2-6+deb12u8: cpython: Incomplete control character validation in http.cookies
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-7210@python3.11-minimal
# Issue #138
# [ERROR] container-image-cve - python3.11-minimal@3.11.2-6+deb12u8: python: expat: Python/Expat: Denial of Service via crafted XML document
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-69534@python3.11-venv
# Issue #139
# [ERROR] container-image-cve - python3.11-venv@3.11.2-6+deb12u8: python-markdown: denial of service via malformed HTML-like sequences
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-11940@python3.11-venv
# Issue #140
# [ERROR] container-image-cve - python3.11-venv@3.11.2-6+deb12u8: python: cpython: CPython: tarfile extraction filter bypass allows escaping the destination directory
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-15308@python3.11-venv
# Issue #141
# [ERROR] container-image-cve - python3.11-venv@3.11.2-6+deb12u8: python: Python: CPU Denial of Service in HTML parser via repeated unterminated markup declarations
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-3644@python3.11-venv
# Issue #142
# [ERROR] container-image-cve - python3.11-venv@3.11.2-6+deb12u8: cpython: Incomplete control character validation in http.cookies
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-7210@python3.11-venv
# Issue #143
# [ERROR] container-image-cve - python3.11-venv@3.11.2-6+deb12u8: python: expat: Python/Expat: Denial of Service via crafted XML document
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-61594@ruby-rubygems
# Issue #144
# [ERROR] container-image-cve - ruby-rubygems@3.3.15-2+deb12u1: uri: URI module: Credential exposure via URI + operator
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-27820@ruby3.1
# Issue #145
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: zlib: zlib: Memory corruption via buffer overflow in Zlib::GzipReader
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42257@ruby3.1
# Issue #146
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection via CRLF sequences in unvalidated input
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2024-41123@ruby3.1
# Issue #147
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: rexml: rubygem-rexml: DoS when parsing an XML having many specific characters such as whitespace character, >] and ]>
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2024-41946@ruby3.1
# Issue #148
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: rexml: DoS vulnerability in REXML
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2024-49761@ruby3.1
# Issue #149
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: rexml: REXML ReDoS vulnerability
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-27219@ruby3.1
# Issue #150
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: CGI: Denial of Service in CGI::Cookie.parse
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-27220@ruby3.1
# Issue #151
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: CGI: ReDoS in CGI::Util#escapeElement
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-61594@ruby3.1
# Issue #152
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: uri: URI module: Credential exposure via URI + operator
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-41316@ruby3.1
# Issue #153
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: erb: ERB: Arbitrary code execution via deserialization bypass
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42245@ruby3.1
# Issue #154
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: ruby: net-imap: Net::IMAP: Denial of Service via crafted IMAP responses
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42246@ruby3.1
# Issue #155
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: net-imap: ruby: Net::IMAP: Information disclosure via man-in-the-middle attack bypassing TLS
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-47242@ruby3.1
# Issue #156
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection due to improper input validation
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-27820@ruby3.1-dev
# Issue #157
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: zlib: zlib: Memory corruption via buffer overflow in Zlib::GzipReader
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42257@ruby3.1-dev
# Issue #158
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection via CRLF sequences in unvalidated input
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2024-41123@ruby3.1-dev
# Issue #159
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: rexml: rubygem-rexml: DoS when parsing an XML having many specific characters such as whitespace character, >] and ]>
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2024-41946@ruby3.1-dev
# Issue #160
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: rexml: DoS vulnerability in REXML
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2024-49761@ruby3.1-dev
# Issue #161
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: rexml: REXML ReDoS vulnerability
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-27219@ruby3.1-dev
# Issue #162
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: CGI: Denial of Service in CGI::Cookie.parse
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-27220@ruby3.1-dev
# Issue #163
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: CGI: ReDoS in CGI::Util#escapeElement
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-61594@ruby3.1-dev
# Issue #164
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: uri: URI module: Credential exposure via URI + operator
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-41316@ruby3.1-dev
# Issue #165
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: erb: ERB: Arbitrary code execution via deserialization bypass
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42245@ruby3.1-dev
# Issue #166
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: ruby: net-imap: Net::IMAP: Denial of Service via crafted IMAP responses
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42246@ruby3.1-dev
# Issue #167
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: net-imap: ruby: Net::IMAP: Information disclosure via man-in-the-middle attack bypassing TLS
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-47242@ruby3.1-dev
# Issue #168
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection due to improper input validation
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-27820@ruby3.1-doc
# Issue #169
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: zlib: zlib: Memory corruption via buffer overflow in Zlib::GzipReader
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42257@ruby3.1-doc
# Issue #170
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection via CRLF sequences in unvalidated input
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2024-41123@ruby3.1-doc
# Issue #171
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: rexml: rubygem-rexml: DoS when parsing an XML having many specific characters such as whitespace character, >] and ]>
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2024-41946@ruby3.1-doc
# Issue #172
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: rexml: DoS vulnerability in REXML
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2024-49761@ruby3.1-doc
# Issue #173
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: rexml: REXML ReDoS vulnerability
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-27219@ruby3.1-doc
# Issue #174
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: CGI: Denial of Service in CGI::Cookie.parse
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-27220@ruby3.1-doc
# Issue #175
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: CGI: ReDoS in CGI::Util#escapeElement
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-61594@ruby3.1-doc
# Issue #176
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: uri: URI module: Credential exposure via URI + operator
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-41316@ruby3.1-doc
# Issue #177
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: erb: ERB: Arbitrary code execution via deserialization bypass
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42245@ruby3.1-doc
# Issue #178
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: ruby: net-imap: Net::IMAP: Denial of Service via crafted IMAP responses
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42246@ruby3.1-doc
# Issue #179
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: net-imap: ruby: Net::IMAP: Information disclosure via man-in-the-middle attack bypassing TLS
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-47242@ruby3.1-doc
# Issue #180
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection due to improper input validation
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-53613@util-linux
# Issue #181
# [ERROR] container-image-cve - util-linux@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-76642@util-linux
# Issue #182
# [ERROR] container-image-cve - util-linux@2.38.1-5+deb12u3: util-linux: util-linux: failed external mount helper still runs privileged X-mount post-hooks
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78408@util-linux
# Issue #183
# [ERROR] container-image-cve - util-linux@2.38.1-5+deb12u3: util-linux: util-linux: nsenter --join-cgroup leaks root cgroup migration authority
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78409@util-linux
# Issue #184
# [ERROR] container-image-cve - util-linux@2.38.1-5+deb12u3: util-linux: util-linux: X-mount.subdir detached-tree resolution can escape via intermediate symlinks
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78410@util-linux
# Issue #185
# [ERROR] container-image-cve - util-linux@2.38.1-5+deb12u3: util-linux: util-linux: restricted bind mounts do not pin the source, allowing X-mount.owner/group/mode redirection
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-53613@util-linux-extra
# Issue #186
# [ERROR] container-image-cve - util-linux-extra@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-76642@util-linux-extra
# Issue #187
# [ERROR] container-image-cve - util-linux-extra@2.38.1-5+deb12u3: util-linux: util-linux: failed external mount helper still runs privileged X-mount post-hooks
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78408@util-linux-extra
# Issue #188
# [ERROR] container-image-cve - util-linux-extra@2.38.1-5+deb12u3: util-linux: util-linux: nsenter --join-cgroup leaks root cgroup migration authority
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78409@util-linux-extra
# Issue #189
# [ERROR] container-image-cve - util-linux-extra@2.38.1-5+deb12u3: util-linux: util-linux: X-mount.subdir detached-tree resolution can escape via intermediate symlinks
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-78410@util-linux-extra
# Issue #190
# [ERROR] container-image-cve - util-linux-extra@2.38.1-5+deb12u3: util-linux: util-linux: restricted bind mounts do not pin the source, allowing X-mount.owner/group/mode redirection
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2023-45853@zlib1g
# Issue #191
# [ERROR] container-image-cve - zlib1g@1:1.2.13.dfsg-1: zlib: integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_6
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-14257@brace-expansion
# Issue #192
# [ERROR] container-image-cve - brace-expansion@5.0.7: brace-expansion: Brace-expansion: Denial of Service via memory exhaustion in expand() function (fixed in 5.0.8, 3.0.3, 2.1.3, 1.1.17)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-69152@brace-expansion
# Issue #193
# [ERROR] container-image-cve - brace-expansion@5.0.7: brace-expansion: DoS via unbounded intermediate arrays, bypassing the CVE-2026-14257 mitigation (fixed in 1.1.18, 2.1.4, 3.0.6, 5.0.9)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-69192@ip-address
# Issue #194
# [ERROR] container-image-cve - ip-address@10.2.0: ip-address: ip-address: Inconsistent IP address parsing leads to Server-Side Request Forgery (SSRF) and trust-boundary bypass (fixed in 10.3.1)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-73566@tar
# Issue #195
# [ERROR] container-image-cve - tar@7.5.19: tar: node-tar: Denial of Service via crafted long-path tar archive (fixed in 7.5.21)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2024-23342@ecdsa
# Issue #196
# [ERROR] container-image-cve - ecdsa@0.19.2: python-ecdsa: vulnerable to the Minerva attack
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::ghsa-6v7p-g79w-8964@msgpack
# Issue #197
# [ERROR] container-image-cve - msgpack@1.1.2: MessagePack for Python: Out-of-bounds read / crash on Unpacker reuse after a caught error (fixed in 1.2.1)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-47273@setuptools
# Issue #198
# [ERROR] container-image-cve - setuptools@70.3.0: setuptools: Path Traversal Vulnerability in setuptools PackageIndex (fixed in 78.1.1)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-79770@nokogiri
# Issue #199
# [ERROR] container-image-cve - nokogiri@1.18.10: nokogiri: Nokogiri: Denial of Service via crafted CSS selectors (fixed in 1.19.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::ghsa-c4rq-3m3g-8wgx@nokogiri
# Issue #200
# [ERROR] container-image-cve - nokogiri@1.18.10: Nokogiri CSS selector tokenizer has regular expression backtracking (fixed in >= 1.19.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-45022@github.com/go-git/go-git/v5
# Issue #201
# [ERROR] container-image-cve - github.com/go-git/go-git/v5@v5.16.5: go-git is an extensible git implementation library written in pure Go. ... (fixed in 5.19.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-71556@github.com/go-git/go-git/v5
# Issue #202
# [ERROR] container-image-cve - github.com/go-git/go-git/v5@v5.16.5: github.com/go-git/go-git/v5: go-git: Arbitrary file read/write via symbolic link resolution (fixed in 5.19.2)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-17106@github.com/moby/go-archive
# Issue #203
# [ERROR] container-image-cve - github.com/moby/go-archive@v0.1.0: github.com/moby/go-archive: moby/go-archive: Arbitrary file write via link following in tar extraction (fixed in 0.3.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56854@golang.org/x/crypto::5fbec327
# Issue #204
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Authentication bypass due to unenforced source-address restrictions (fixed in 0.55.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39828@golang.org/x/crypto::50694955
# Issue #205
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Unauthorized command execution via discarded SSH permissions (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39829@golang.org/x/crypto::26aa317c
# Issue #206
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of Service via crafted public key with excessive parameters (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39830@golang.org/x/crypto::058c7e80
# Issue #207
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of Service via resource leak from unsolicited SSH responses (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39831@golang.org/x/crypto::b13dea40
# Issue #208
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Security key bypass due to missing user presence check (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39832@golang.org/x/crypto::76403545
# Issue #209
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh/agent: golang.org/x/crypto/ssh/agent: Security bypass due to improper handling of key restrictions (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39835@golang.org/x/crypto::2ec91926
# Issue #210
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang: golang.org/x/crypto/ssh: Denial of Service via crafted SSH certificate (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42508@golang.org/x/crypto::1e0f1764
# Issue #211
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh/knownhosts: golang: golang.org/x/crypto/ssh/knownhosts: Revocation bypass via unchecked SignatureKey (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-46595@golang.org/x/crypto::1315c9d3
# Issue #212
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Authorization bypass due to skipped source-address validation (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-46597@golang.org/x/crypto::6af1565f
# Issue #213
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of Service via crafted AES-GCM packet decoder inputs (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-25681@golang.org/x/net
# Issue #214
# [ERROR] container-image-cve - golang.org/x/net@v0.53.0: golang.org/x/net/html: golang.org/x/net/html: Arbitrary code execution via Cross-Site Scripting (fixed in 0.55.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-27136@golang.org/x/net
# Issue #215
# [ERROR] container-image-cve - golang.org/x/net@v0.53.0: golang.org/x/net/html: golang: golang.org/x/net/html: Cross-Site Scripting via HTML parsing bypass (fixed in 0.55.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39821@golang.org/x/net
# Issue #216
# [ERROR] container-image-cve - golang.org/x/net@v0.53.0: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 0.55.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-46600@golang.org/x/net
# Issue #217
# [ERROR] container-image-cve - golang.org/x/net@v0.53.0: golang.org/x/net/dns/dnsmessage: golang.org/x/net/dns/dnsmessage: Denial of Service via invalid DNS record parsing (fixed in 0.56.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56852@golang.org/x/text::c7858c9f
# Issue #218
# [ERROR] container-image-cve - golang.org/x/text@v0.36.0: golang.org/x/text: golang.org/x/text: Denial of Service via invalid UTF-8 input (fixed in 0.39.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-68121@stdlib::218a0dde
# Issue #219
# [ERROR] container-image-cve - stdlib@v1.25.0: crypto/tls: crypto/tls: Incorrect certificate validation during TLS session resumption (fixed in 1.24.13, 1.25.7, 1.26.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-61726@stdlib::2d442b96
# Issue #220
# [ERROR] container-image-cve - stdlib@v1.25.0: golang: net/url: Memory exhaustion in query parameter parsing in net/url (fixed in 1.24.12, 1.25.6)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-61729@stdlib::49244acc
# Issue #221
# [ERROR] container-image-cve - stdlib@v1.25.0: crypto/x509: golang: Denial of Service due to excessive resource consumption via crafted certificate (fixed in 1.24.11, 1.25.5)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-25679@stdlib::58f82e79
# Issue #222
# [ERROR] container-image-cve - stdlib@v1.25.0: net/url: Incorrect parsing of IPv6 host literals in net/url (fixed in 1.25.8, 1.26.1)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-27145@stdlib::72bc8d77
# Issue #223
# [ERROR] container-image-cve - stdlib@v1.25.0: crypto/x509: golang: golang crypto/x509: Denial of Service via excessive processing of DNS SAN entries (fixed in 1.25.11, 1.26.4)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-32280@stdlib::043bde82
# Issue #224
# [ERROR] container-image-cve - stdlib@v1.25.0: crypto/x509: crypto/tls: golang: Go: Denial of Service vulnerability in certificate chain building (fixed in 1.25.9, 1.26.2)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-32281@stdlib::aa9e6240
# Issue #225
# [ERROR] container-image-cve - stdlib@v1.25.0: crypto/x509: golang: Go crypto/x509: Denial of Service via inefficient certificate chain validation (fixed in 1.25.9, 1.26.2)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-32283@stdlib::c3a0b257
# Issue #226
# [ERROR] container-image-cve - stdlib@v1.25.0: crypto/tls: golang: Go crypto/tls: Denial of Service via multiple TLS 1.3 key update messages (fixed in 1.25.9, 1.26.2)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-33811@stdlib::310aac27
# Issue #227
# [ERROR] container-image-cve - stdlib@v1.25.0: net: golang: Go net package: Denial of Service via long CNAME response in LookupCNAME (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-33814@stdlib::ac023842
# Issue #228
# [ERROR] container-image-cve - stdlib@v1.25.0: net/http/internal/http2: golang: golang.org/x/net: Go HTTP/2: Denial of Service via malformed SETTINGS_MAX_FRAME_SIZE frame (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-33818@stdlib::196f588c
# Issue #229
# [ERROR] container-image-cve - stdlib@v1.25.0: encoding/asn1: golang: Go encoding/asn1: Denial of Service via excessive recursion in Unmarshal (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39820@stdlib::ca613e32
# Issue #230
# [ERROR] container-image-cve - stdlib@v1.25.0: net/mail: golang: Go net/mail: Denial of Service via crafted email inputs (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39821@stdlib::a45ce301
# Issue #231
# [ERROR] container-image-cve - stdlib@v1.25.0: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39822@stdlib::e0f8ec73
# Issue #232
# [ERROR] container-image-cve - stdlib@v1.25.0: golang: Go os.Root: Symlink following vulnerability allows directory traversal (fixed in 1.25.12, 1.26.5, 1.27.0-rc.2)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39836@stdlib::1f37a139
# Issue #233
# [ERROR] container-image-cve - stdlib@v1.25.0: net: golang: Go net package: Denial of Service via NUL byte in Dial and LookupPort on Windows (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42499@stdlib::16a677dc
# Issue #234
# [ERROR] container-image-cve - stdlib@v1.25.0: net/mail: golang: net/mail: Denial of Service via pathological email address parsing (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42504@stdlib::8a912dcc
# Issue #235
# [ERROR] container-image-cve - stdlib@v1.25.0: mime: golang: Golang MIME: Denial of Service via maliciously-crafted MIME header (fixed in 1.25.11, 1.26.4)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56853@stdlib::e1c54b3b
# Issue #236
# [ERROR] container-image-cve - stdlib@v1.25.0: net/http: golang: Go net/http: Unencrypted HTTP/2 connections vulnerable to Denial of Service (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56858@stdlib::1a4b2c15
# Issue #237
# [ERROR] container-image-cve - stdlib@v1.25.0: html/template: golang: Go html/template: Cross-Site Scripting via pathological input (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56859@stdlib::b68bd7c0
# Issue #238
# [ERROR] container-image-cve - stdlib@v1.25.0: encoding/xml: golang: Go: Denial of Service via XML decoding recursion depth issue (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56860@stdlib::abc8ce85
# Issue #239
# [ERROR] container-image-cve - stdlib@v1.25.0: net/url: golang: golang net/url: Denial of Service from quadratic complexity in path resolution (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56862@stdlib::95144fe3
# Issue #240
# [ERROR] container-image-cve - stdlib@v1.25.0: crypto/tls: golang: Golang crypto/tls: Denial of Service via indefinite KeyUpdate messages (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56854@golang.org/x/crypto::b830b9a5
# Issue #241
# [ERROR] container-image-cve - golang.org/x/crypto@v0.53.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Authentication bypass due to unenforced source-address restrictions (fixed in 0.55.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56864@golang.org/x/mod::908d0a88
# Issue #242
# [ERROR] container-image-cve - golang.org/x/mod@v0.37.0: A malicious GOSUMDB was capable of serving arbitrary module content no ... (fixed in 0.40.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56865@golang.org/x/mod::e91d03cf
# Issue #243
# [ERROR] container-image-cve - golang.org/x/mod@v0.37.0: golang.org/x/mod/sumdb/tlog: golang.org/x/mod/sumdb/tlog: Supply chain compromise via transparency log tile verification bypass (fixed in 0.40.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56852@golang.org/x/text::388e33ea
# Issue #244
# [ERROR] container-image-cve - golang.org/x/text@v0.38.0: golang.org/x/text: golang.org/x/text: Denial of Service via invalid UTF-8 input (fixed in 0.39.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-84304@google.golang.org/grpc::dd169ae1
# Issue #245
# [ERROR] container-image-cve - google.golang.org/grpc@v1.82.0: gRPC-Go is the Go language implementation of gRPC. Prior to 1.83.1, in ... (fixed in 1.83.1)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::ghsa-hrxh-6v49-42gf@google.golang.org/grpc
# Issue #246
# [ERROR] container-image-cve - google.golang.org/grpc@v1.82.0: gRPC-Go: xDS RBAC and HTTP/2 Vulnerabilities (fixed in 1.82.1)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-33818@stdlib::e355c1cb
# Issue #247
# [ERROR] container-image-cve - stdlib@v1.26.4: encoding/asn1: golang: Go encoding/asn1: Denial of Service via excessive recursion in Unmarshal (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39821@stdlib::129a7dda
# Issue #248
# [ERROR] container-image-cve - stdlib@v1.26.4: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39822@stdlib::9b4e0b9c
# Issue #249
# [ERROR] container-image-cve - stdlib@v1.26.4: golang: Go os.Root: Symlink following vulnerability allows directory traversal (fixed in 1.25.12, 1.26.5, 1.27.0-rc.2)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-46600@stdlib::5d57ea47
# Issue #250
# [ERROR] container-image-cve - stdlib@v1.26.4: golang.org/x/net/dns/dnsmessage: golang.org/x/net/dns/dnsmessage: Denial of Service via invalid DNS record parsing (fixed in 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56853@stdlib::fc380717
# Issue #251
# [ERROR] container-image-cve - stdlib@v1.26.4: net/http: golang: Go net/http: Unencrypted HTTP/2 connections vulnerable to Denial of Service (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56858@stdlib::cdd5093e
# Issue #252
# [ERROR] container-image-cve - stdlib@v1.26.4: html/template: golang: Go html/template: Cross-Site Scripting via pathological input (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56859@stdlib::ff81b311
# Issue #253
# [ERROR] container-image-cve - stdlib@v1.26.4: encoding/xml: golang: Go: Denial of Service via XML decoding recursion depth issue (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56860@stdlib::404af46c
# Issue #254
# [ERROR] container-image-cve - stdlib@v1.26.4: net/url: golang: golang net/url: Denial of Service from quadratic complexity in path resolution (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56862@stdlib::357b0054
# Issue #255
# [ERROR] container-image-cve - stdlib@v1.26.4: crypto/tls: golang: Golang crypto/tls: Denial of Service via indefinite KeyUpdate messages (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-33818@stdlib::9d41afbd
# Issue #256
# [ERROR] container-image-cve - stdlib@v1.26.5: encoding/asn1: golang: Go encoding/asn1: Denial of Service via excessive recursion in Unmarshal (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39821@stdlib::c7bf8858
# Issue #257
# [ERROR] container-image-cve - stdlib@v1.26.5: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-46600@stdlib::1bd915b0
# Issue #258
# [ERROR] container-image-cve - stdlib@v1.26.5: golang.org/x/net/dns/dnsmessage: golang.org/x/net/dns/dnsmessage: Denial of Service via invalid DNS record parsing (fixed in 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56853@stdlib::e2f4dd20
# Issue #259
# [ERROR] container-image-cve - stdlib@v1.26.5: net/http: golang: Go net/http: Unencrypted HTTP/2 connections vulnerable to Denial of Service (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56858@stdlib::e031dcdc
# Issue #260
# [ERROR] container-image-cve - stdlib@v1.26.5: html/template: golang: Go html/template: Cross-Site Scripting via pathological input (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56859@stdlib::c95bb42e
# Issue #261
# [ERROR] container-image-cve - stdlib@v1.26.5: encoding/xml: golang: Go: Denial of Service via XML decoding recursion depth issue (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56860@stdlib::9ebe33f0
# Issue #262
# [ERROR] container-image-cve - stdlib@v1.26.5: net/url: golang: golang net/url: Denial of Service from quadratic complexity in path resolution (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56862@stdlib::eca672ed
# Issue #263
# [ERROR] container-image-cve - stdlib@v1.26.5: crypto/tls: golang: Golang crypto/tls: Denial of Service via indefinite KeyUpdate messages (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56864@golang.org/x/mod::9d06ba10
# Issue #264
# [ERROR] container-image-cve - golang.org/x/mod@v0.39.0: A malicious GOSUMDB was capable of serving arbitrary module content no ... (fixed in 0.40.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56865@golang.org/x/mod::85d1184f
# Issue #265
# [ERROR] container-image-cve - golang.org/x/mod@v0.39.0: golang.org/x/mod/sumdb/tlog: golang.org/x/mod/sumdb/tlog: Supply chain compromise via transparency log tile verification bypass (fixed in 0.40.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56854@golang.org/x/crypto::cb565a27
# Issue #266
# [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Authentication bypass due to unenforced source-address restrictions (fixed in 0.55.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-47913@golang.org/x/crypto
# Issue #267
# [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh/agent: golang.org/x/crypto/ssh/agent: SSH client panic due to unexpected SSH_AGENT_SUCCESS (fixed in 0.43.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39828@golang.org/x/crypto::ba979102
# Issue #268
# [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Unauthorized command execution via discarded SSH permissions (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39829@golang.org/x/crypto::bfdce9dc
# Issue #269
# [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of Service via crafted public key with excessive parameters (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39830@golang.org/x/crypto::5215e16b
# Issue #270
# [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of Service via resource leak from unsolicited SSH responses (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39831@golang.org/x/crypto::4b1517a1
# Issue #271
# [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Security key bypass due to missing user presence check (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39832@golang.org/x/crypto::ea6f3fca
# Issue #272
# [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh/agent: golang.org/x/crypto/ssh/agent: Security bypass due to improper handling of key restrictions (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39835@golang.org/x/crypto::e8b4c1e2
# Issue #273
# [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh: golang: golang.org/x/crypto/ssh: Denial of Service via crafted SSH certificate (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42508@golang.org/x/crypto::1620737a
# Issue #274
# [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh/knownhosts: golang: golang.org/x/crypto/ssh/knownhosts: Revocation bypass via unchecked SignatureKey (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-46595@golang.org/x/crypto::a0530cbc
# Issue #275
# [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Authorization bypass due to skipped source-address validation (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-46597@golang.org/x/crypto::b395e48a
# Issue #276
# [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of Service via crafted AES-GCM packet decoder inputs (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56852@golang.org/x/text::dbc9c966
# Issue #277
# [ERROR] container-image-cve - golang.org/x/text@v0.22.0: golang.org/x/text: golang.org/x/text: Denial of Service via invalid UTF-8 input (fixed in 0.39.0)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-68121@stdlib::1830ea23
# Issue #278
# [ERROR] container-image-cve - stdlib@v1.24.11: crypto/tls: crypto/tls: Incorrect certificate validation during TLS session resumption (fixed in 1.24.13, 1.25.7, 1.26.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-61726@stdlib::dd60c802
# Issue #279
# [ERROR] container-image-cve - stdlib@v1.24.11: golang: net/url: Memory exhaustion in query parameter parsing in net/url (fixed in 1.24.12, 1.25.6)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-25679@stdlib::d45e091e
# Issue #280
# [ERROR] container-image-cve - stdlib@v1.24.11: net/url: Incorrect parsing of IPv6 host literals in net/url (fixed in 1.25.8, 1.26.1)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-27145@stdlib::ba179694
# Issue #281
# [ERROR] container-image-cve - stdlib@v1.24.11: crypto/x509: golang: golang crypto/x509: Denial of Service via excessive processing of DNS SAN entries (fixed in 1.25.11, 1.26.4)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-32280@stdlib::f62a6293
# Issue #282
# [ERROR] container-image-cve - stdlib@v1.24.11: crypto/x509: crypto/tls: golang: Go: Denial of Service vulnerability in certificate chain building (fixed in 1.25.9, 1.26.2)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-32281@stdlib::df299a45
# Issue #283
# [ERROR] container-image-cve - stdlib@v1.24.11: crypto/x509: golang: Go crypto/x509: Denial of Service via inefficient certificate chain validation (fixed in 1.25.9, 1.26.2)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-32283@stdlib::f4dd951b
# Issue #284
# [ERROR] container-image-cve - stdlib@v1.24.11: crypto/tls: golang: Go crypto/tls: Denial of Service via multiple TLS 1.3 key update messages (fixed in 1.25.9, 1.26.2)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-33811@stdlib::7c4bfe39
# Issue #285
# [ERROR] container-image-cve - stdlib@v1.24.11: net: golang: Go net package: Denial of Service via long CNAME response in LookupCNAME (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-33814@stdlib::cb8db337
# Issue #286
# [ERROR] container-image-cve - stdlib@v1.24.11: net/http/internal/http2: golang: golang.org/x/net: Go HTTP/2: Denial of Service via malformed SETTINGS_MAX_FRAME_SIZE frame (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-33818@stdlib::7b17d7b8
# Issue #287
# [ERROR] container-image-cve - stdlib@v1.24.11: encoding/asn1: golang: Go encoding/asn1: Denial of Service via excessive recursion in Unmarshal (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39820@stdlib::3bfd4808
# Issue #288
# [ERROR] container-image-cve - stdlib@v1.24.11: net/mail: golang: Go net/mail: Denial of Service via crafted email inputs (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39821@stdlib::6d7bdb08
# Issue #289
# [ERROR] container-image-cve - stdlib@v1.24.11: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39822@stdlib::e9bc29df
# Issue #290
# [ERROR] container-image-cve - stdlib@v1.24.11: golang: Go os.Root: Symlink following vulnerability allows directory traversal (fixed in 1.25.12, 1.26.5, 1.27.0-rc.2)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39836@stdlib::d95368cc
# Issue #291
# [ERROR] container-image-cve - stdlib@v1.24.11: net: golang: Go net package: Denial of Service via NUL byte in Dial and LookupPort on Windows (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42499@stdlib::9450b4d1
# Issue #292
# [ERROR] container-image-cve - stdlib@v1.24.11: net/mail: golang: net/mail: Denial of Service via pathological email address parsing (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42504@stdlib::412c5eb2
# Issue #293
# [ERROR] container-image-cve - stdlib@v1.24.11: mime: golang: Golang MIME: Denial of Service via maliciously-crafted MIME header (fixed in 1.25.11, 1.26.4)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56853@stdlib::56a69742
# Issue #294
# [ERROR] container-image-cve - stdlib@v1.24.11: net/http: golang: Go net/http: Unencrypted HTTP/2 connections vulnerable to Denial of Service (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56858@stdlib::431f962f
# Issue #295
# [ERROR] container-image-cve - stdlib@v1.24.11: html/template: golang: Go html/template: Cross-Site Scripting via pathological input (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56859@stdlib::d86be6dd
# Issue #296
# [ERROR] container-image-cve - stdlib@v1.24.11: encoding/xml: golang: Go: Denial of Service via XML decoding recursion depth issue (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56860@stdlib::37b7b369
# Issue #297
# [ERROR] container-image-cve - stdlib@v1.24.11: net/url: golang: golang net/url: Denial of Service from quadratic complexity in path resolution (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56862@stdlib::f24b40b2
# Issue #298
# [ERROR] container-image-cve - stdlib@v1.24.11: crypto/tls: golang: Golang crypto/tls: Denial of Service via indefinite KeyUpdate messages (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-68121@stdlib::d77657c9
# Issue #299
# [ERROR] container-image-cve - stdlib@v1.23.7: crypto/tls: crypto/tls: Incorrect certificate validation during TLS session resumption (fixed in 1.24.13, 1.25.7, 1.26.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-61726@stdlib::561b8e75
# Issue #300
# [ERROR] container-image-cve - stdlib@v1.23.7: golang: net/url: Memory exhaustion in query parameter parsing in net/url (fixed in 1.24.12, 1.25.6)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2025-61729@stdlib::2f323c22
# Issue #301
# [ERROR] container-image-cve - stdlib@v1.23.7: crypto/x509: golang: Denial of Service due to excessive resource consumption via crafted certificate (fixed in 1.24.11, 1.25.5)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-25679@stdlib::db1113aa
# Issue #302
# [ERROR] container-image-cve - stdlib@v1.23.7: net/url: Incorrect parsing of IPv6 host literals in net/url (fixed in 1.25.8, 1.26.1)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-27145@stdlib::ffae4b09
# Issue #303
# [ERROR] container-image-cve - stdlib@v1.23.7: crypto/x509: golang: golang crypto/x509: Denial of Service via excessive processing of DNS SAN entries (fixed in 1.25.11, 1.26.4)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-32280@stdlib::97cbcd16
# Issue #304
# [ERROR] container-image-cve - stdlib@v1.23.7: crypto/x509: crypto/tls: golang: Go: Denial of Service vulnerability in certificate chain building (fixed in 1.25.9, 1.26.2)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-32281@stdlib::09d1c626
# Issue #305
# [ERROR] container-image-cve - stdlib@v1.23.7: crypto/x509: golang: Go crypto/x509: Denial of Service via inefficient certificate chain validation (fixed in 1.25.9, 1.26.2)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-32283@stdlib::07fad89e
# Issue #306
# [ERROR] container-image-cve - stdlib@v1.23.7: crypto/tls: golang: Go crypto/tls: Denial of Service via multiple TLS 1.3 key update messages (fixed in 1.25.9, 1.26.2)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-33811@stdlib::2ef14196
# Issue #307
# [ERROR] container-image-cve - stdlib@v1.23.7: net: golang: Go net package: Denial of Service via long CNAME response in LookupCNAME (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-33814@stdlib::1ef19471
# Issue #308
# [ERROR] container-image-cve - stdlib@v1.23.7: net/http/internal/http2: golang: golang.org/x/net: Go HTTP/2: Denial of Service via malformed SETTINGS_MAX_FRAME_SIZE frame (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-33818@stdlib::b7410294
# Issue #309
# [ERROR] container-image-cve - stdlib@v1.23.7: encoding/asn1: golang: Go encoding/asn1: Denial of Service via excessive recursion in Unmarshal (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39820@stdlib::7c28570d
# Issue #310
# [ERROR] container-image-cve - stdlib@v1.23.7: net/mail: golang: Go net/mail: Denial of Service via crafted email inputs (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39821@stdlib::52dac56b
# Issue #311
# [ERROR] container-image-cve - stdlib@v1.23.7: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39822@stdlib::77a8fdf1
# Issue #312
# [ERROR] container-image-cve - stdlib@v1.23.7: golang: Go os.Root: Symlink following vulnerability allows directory traversal (fixed in 1.25.12, 1.26.5, 1.27.0-rc.2)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39836@stdlib::821eb1a5
# Issue #313
# [ERROR] container-image-cve - stdlib@v1.23.7: net: golang: Go net package: Denial of Service via NUL byte in Dial and LookupPort on Windows (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42499@stdlib::d64e90b2
# Issue #314
# [ERROR] container-image-cve - stdlib@v1.23.7: net/mail: golang: net/mail: Denial of Service via pathological email address parsing (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42504@stdlib::0159aa70
# Issue #315
# [ERROR] container-image-cve - stdlib@v1.23.7: mime: golang: Golang MIME: Denial of Service via maliciously-crafted MIME header (fixed in 1.25.11, 1.26.4)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56853@stdlib::78a96946
# Issue #316
# [ERROR] container-image-cve - stdlib@v1.23.7: net/http: golang: Go net/http: Unencrypted HTTP/2 connections vulnerable to Denial of Service (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56858@stdlib::96ef3edc
# Issue #317
# [ERROR] container-image-cve - stdlib@v1.23.7: html/template: golang: Go html/template: Cross-Site Scripting via pathological input (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56859@stdlib::24e5321d
# Issue #318
# [ERROR] container-image-cve - stdlib@v1.23.7: encoding/xml: golang: Go: Denial of Service via XML decoding recursion depth issue (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56860@stdlib::6c74b286
# Issue #319
# [ERROR] container-image-cve - stdlib@v1.23.7: net/url: golang: golang net/url: Denial of Service from quadratic complexity in path resolution (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56862@stdlib::fba423d8
# Issue #320
# [ERROR] container-image-cve - stdlib@v1.23.7: crypto/tls: golang: Golang crypto/tls: Denial of Service via indefinite KeyUpdate messages (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-84304@google.golang.org/grpc::68c76669
# Issue #321
# [ERROR] container-image-cve - google.golang.org/grpc@v1.83.0: gRPC-Go is the Go language implementation of gRPC. Prior to 1.83.1, in ... (fixed in 1.83.1)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-27145@stdlib::de88cadb
# Issue #322
# [ERROR] container-image-cve - stdlib@v1.26.3: crypto/x509: golang: golang crypto/x509: Denial of Service via excessive processing of DNS SAN entries (fixed in 1.25.11, 1.26.4)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-33818@stdlib::156eb198
# Issue #323
# [ERROR] container-image-cve - stdlib@v1.26.3: encoding/asn1: golang: Go encoding/asn1: Denial of Service via excessive recursion in Unmarshal (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39821@stdlib::5cae206b
# Issue #324
# [ERROR] container-image-cve - stdlib@v1.26.3: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-39822@stdlib::460fe5b6
# Issue #325
# [ERROR] container-image-cve - stdlib@v1.26.3: golang: Go os.Root: Symlink following vulnerability allows directory traversal (fixed in 1.25.12, 1.26.5, 1.27.0-rc.2)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-42504@stdlib::c4f8064e
# Issue #326
# [ERROR] container-image-cve - stdlib@v1.26.3: mime: golang: Golang MIME: Denial of Service via maliciously-crafted MIME header (fixed in 1.25.11, 1.26.4)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-46600@stdlib::ffe01a2d
# Issue #327
# [ERROR] container-image-cve - stdlib@v1.26.3: golang.org/x/net/dns/dnsmessage: golang.org/x/net/dns/dnsmessage: Denial of Service via invalid DNS record parsing (fixed in 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56853@stdlib::16d4acef
# Issue #328
# [ERROR] container-image-cve - stdlib@v1.26.3: net/http: golang: Go net/http: Unencrypted HTTP/2 connections vulnerable to Denial of Service (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56858@stdlib::e2812682
# Issue #329
# [ERROR] container-image-cve - stdlib@v1.26.3: html/template: golang: Go html/template: Cross-Site Scripting via pathological input (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56859@stdlib::81beb686
# Issue #330
# [ERROR] container-image-cve - stdlib@v1.26.3: encoding/xml: golang: Go: Denial of Service via XML decoding recursion depth issue (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56860@stdlib::928e7b70
# Issue #331
# [ERROR] container-image-cve - stdlib@v1.26.3: net/url: golang: golang net/url: Denial of Service from quadratic complexity in path resolution (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-56862@stdlib::e5ea5b3c
# Issue #332
# [ERROR] container-image-cve - stdlib@v1.26.3: crypto/tls: golang: Golang crypto/tls: Denial of Service via indefinite KeyUpdate messages (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: container-image-cve::Dockerfile::1::cve-2026-84304@google.golang.org/grpc::8aec2ddd
# Issue #333
# [ERROR] container-image-cve - google.golang.org/grpc@v1.82.1: gRPC-Go is the Go language implementation of gRPC. Prior to 1.83.1, in ... (fixed in 1.83.1)
#   Dockerfile:1
Acknowledge: Base-image/bundled-tool package, not Ignite's own source (Dockerfile's `FROM node:24-bookworm-slim` and the pinned third-party tool binaries it installs) — tracked per the Dockerfile's own documented policy of deliberate, reviewed version bumps (`--no-cache` rebuild + full self-scan) rather than implicit upgrades on every build. No source-code fix applies on the Ignite side.

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::1287
# Issue #334
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:1287
Acknowledge: Test-fixture literal AWS-shaped key embedded in a unit test's synthetic zip upload to deterministically trigger a Phase 4 finding, not a real credential.

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::1340
# Issue #335
# [ERROR] secret - Hardcoded aws_secret
#   rust/crates/server/src/routes/pipeline_interactive.rs:1340
Acknowledge: Same synthetic AWS-shaped test fixture as the sibling review-gate regression test in this file, used only to guarantee a Phase 4 finding for the test's dry-run path — not a real credential.

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::867
# Issue #336
# [ERROR] secret - Hardcoded gcp-api-key
#   rust/crates/phase4-orchestrator/src/lib.rs:867
Acknowledge: Fake GCP/Firebase web API key literal used as test input to verify the secrets checker's gitleaks-only detection path (not the built-in regex), not a real credential.

ID: secret::.ignite/acknowledgments.md::2023
# Issue #337
# [ERROR] secret - Hardcoded aws-access-token
#   .ignite/acknowledgments.md:2023
Acknowledge: 
