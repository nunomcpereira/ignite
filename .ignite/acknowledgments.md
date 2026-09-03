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

# Scanned against commit: 1ec7e80cd85434ed17219961b3cec3d72659b894 (working tree at push time - findings/justifications below reflect this commit's code, not necessarily what ends up pushed if the tree changes after)

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

ID: container-image-cve::Dockerfile::1::cve-2026-53613@bsdutils
# Issue #5
# [ERROR] container-image-cve - bsdutils@1:2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-12064@curl
# Issue #6
# [ERROR] container-image-cve - curl@7.88.1-10+deb12u15: curl: curl: SSH host verification bypass when using schemeless URLs with SFTP/SCP
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-6276@curl
# Issue #7
# [ERROR] container-image-cve - curl@7.88.1-10+deb12u15: curl: libcurl: Information disclosure due to cookie leak when reusing connections with custom Host headers
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-8286@curl
# Issue #8
# [ERROR] container-image-cve - curl@7.88.1-10+deb12u15: curl: curl: Insecure connection establishment due to TLS configuration mismatch
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-8458@curl
# Issue #9
# [ERROR] container-image-cve - curl@7.88.1-10+deb12u15: curl: libcurl: Unauthorized connection reuse due to a logical error
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-8927@curl
# Issue #10
# [ERROR] container-image-cve - curl@7.88.1-10+deb12u15: curl: Information disclosure due to uncleared proxy authentication state
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-41992@gzip
# Issue #11
# [ERROR] container-image-cve - gzip@1.12-1: gzip: gzip: Information disclosure via global buffer overflow in LZH decompression
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-54369@libacl1
# Issue #12
# [ERROR] container-image-cve - libacl1@2.3.1-3: acl: Symlink traversal privilege escalation via libacl functions
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-53613@libblkid1
# Issue #13
# [ERROR] container-image-cve - libblkid1@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-12064@libcurl3-gnutls
# Issue #14
# [ERROR] container-image-cve - libcurl3-gnutls@7.88.1-10+deb12u15: curl: curl: SSH host verification bypass when using schemeless URLs with SFTP/SCP
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-6276@libcurl3-gnutls
# Issue #15
# [ERROR] container-image-cve - libcurl3-gnutls@7.88.1-10+deb12u15: curl: libcurl: Information disclosure due to cookie leak when reusing connections with custom Host headers
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-8286@libcurl3-gnutls
# Issue #16
# [ERROR] container-image-cve - libcurl3-gnutls@7.88.1-10+deb12u15: curl: curl: Insecure connection establishment due to TLS configuration mismatch
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-8458@libcurl3-gnutls
# Issue #17
# [ERROR] container-image-cve - libcurl3-gnutls@7.88.1-10+deb12u15: curl: libcurl: Unauthorized connection reuse due to a logical error
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-8927@libcurl3-gnutls
# Issue #18
# [ERROR] container-image-cve - libcurl3-gnutls@7.88.1-10+deb12u15: curl: Information disclosure due to uncleared proxy authentication state
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-12064@libcurl4
# Issue #19
# [ERROR] container-image-cve - libcurl4@7.88.1-10+deb12u15: curl: curl: SSH host verification bypass when using schemeless URLs with SFTP/SCP
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-6276@libcurl4
# Issue #20
# [ERROR] container-image-cve - libcurl4@7.88.1-10+deb12u15: curl: libcurl: Information disclosure due to cookie leak when reusing connections with custom Host headers
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-8286@libcurl4
# Issue #21
# [ERROR] container-image-cve - libcurl4@7.88.1-10+deb12u15: curl: curl: Insecure connection establishment due to TLS configuration mismatch
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-8458@libcurl4
# Issue #22
# [ERROR] container-image-cve - libcurl4@7.88.1-10+deb12u15: curl: libcurl: Unauthorized connection reuse due to a logical error
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-8927@libcurl4
# Issue #23
# [ERROR] container-image-cve - libcurl4@7.88.1-10+deb12u15: curl: Information disclosure due to uncleared proxy authentication state
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-59375@libexpat1
# Issue #24
# [ERROR] container-image-cve - libexpat1@2.5.0-1+deb12u2: firefox: thunderbird: expat: libexpat in Expat allows attackers to trigger large dynamic memory allocations via a small document that is submitted for parsing
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-25210@libexpat1
# Issue #25
# [ERROR] container-image-cve - libexpat1@2.5.0-1+deb12u2: libexpat: libexpat: Information disclosure and data integrity issues due to integer overflow in buffer reallocation
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-45186@libexpat1
# Issue #26
# [ERROR] container-image-cve - libexpat1@2.5.0-1+deb12u2: libexpat: denial of service via crafted XML input
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-66046@libexpat1
# Issue #27
# [ERROR] container-image-cve - libexpat1@2.5.0-1+deb12u2: Expat through 2.8.3 contains a denial of service vulnerability caused  ...
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2023-2953@libldap-2.5-0
# Issue #28
# [ERROR] container-image-cve - libldap-2.5-0@2.5.13+dfsg-5: openldap: null pointer dereference in  ber_memalloc_x  function
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-53613@libmount1
# Issue #29
# [ERROR] container-image-cve - libmount1@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-69720@libncurses6
# Issue #30
# [ERROR] container-image-cve - libncurses6@6.4-4: ncurses: ncurses: Buffer overflow vulnerability may lead to arbitrary code execution.
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-69720@libncursesw6
# Issue #31
# [ERROR] container-image-cve - libncursesw6@6.4-4: ncurses: ncurses: Buffer overflow vulnerability may lead to arbitrary code execution.
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-13221@libperl5.36
# Issue #32
# [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl: Perl: Incorrect regular expression processing via large regular expressions
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42496@libperl5.36
# Issue #33
# [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl-archive-tar: perl-archive-tar: Path traversal via crafted symlinks allows arbitrary file access
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-8376@libperl5.36
# Issue #34
# [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl: Perl: Heap buffer overflow when compiling regular expressions on 32-bit builds
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42497@libperl5.36
# Issue #35
# [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Arbitrary file modification via crafted hardlinks during archive extraction
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-48962@libperl5.36
# Issue #36
# [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl-IO-Compress: perl-IO-Compress: Arbitrary code execution via attacker-controlled output glob
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-57432@libperl5.36
# Issue #37
# [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl: Perl: Information disclosure via integer overflow in pack/unpack operations
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-57433@libperl5.36
# Issue #38
# [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: Storable: Storable: Denial of Service via signed integer overflow in deserialization
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-9538@libperl5.36
# Issue #39
# [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Denial of Service via crafted tar header with large entry size
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-69534@libpython3.11-minimal
# Issue #40
# [ERROR] container-image-cve - libpython3.11-minimal@3.11.2-6+deb12u8: python-markdown: denial of service via malformed HTML-like sequences
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-11940@libpython3.11-minimal
# Issue #41
# [ERROR] container-image-cve - libpython3.11-minimal@3.11.2-6+deb12u8: python: cpython: CPython: tarfile extraction filter bypass allows escaping the destination directory
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-15308@libpython3.11-minimal
# Issue #42
# [ERROR] container-image-cve - libpython3.11-minimal@3.11.2-6+deb12u8: python: Python: CPU Denial of Service in HTML parser via repeated unterminated markup declarations
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-3644@libpython3.11-minimal
# Issue #43
# [ERROR] container-image-cve - libpython3.11-minimal@3.11.2-6+deb12u8: cpython: Incomplete control character validation in http.cookies
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-7210@libpython3.11-minimal
# Issue #44
# [ERROR] container-image-cve - libpython3.11-minimal@3.11.2-6+deb12u8: python: expat: Python/Expat: Denial of Service via crafted XML document
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-69534@libpython3.11-stdlib
# Issue #45
# [ERROR] container-image-cve - libpython3.11-stdlib@3.11.2-6+deb12u8: python-markdown: denial of service via malformed HTML-like sequences
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-11940@libpython3.11-stdlib
# Issue #46
# [ERROR] container-image-cve - libpython3.11-stdlib@3.11.2-6+deb12u8: python: cpython: CPython: tarfile extraction filter bypass allows escaping the destination directory
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-15308@libpython3.11-stdlib
# Issue #47
# [ERROR] container-image-cve - libpython3.11-stdlib@3.11.2-6+deb12u8: python: Python: CPU Denial of Service in HTML parser via repeated unterminated markup declarations
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-3644@libpython3.11-stdlib
# Issue #48
# [ERROR] container-image-cve - libpython3.11-stdlib@3.11.2-6+deb12u8: cpython: Incomplete control character validation in http.cookies
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-7210@libpython3.11-stdlib
# Issue #49
# [ERROR] container-image-cve - libpython3.11-stdlib@3.11.2-6+deb12u8: python: expat: Python/Expat: Denial of Service via crafted XML document
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-27820@libruby3.1
# Issue #50
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: zlib: zlib: Memory corruption via buffer overflow in Zlib::GzipReader
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42257@libruby3.1
# Issue #51
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection via CRLF sequences in unvalidated input
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2024-41123@libruby3.1
# Issue #52
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: rexml: rubygem-rexml: DoS when parsing an XML having many specific characters such as whitespace character, >] and ]>
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2024-41946@libruby3.1
# Issue #53
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: rexml: DoS vulnerability in REXML
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2024-49761@libruby3.1
# Issue #54
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: rexml: REXML ReDoS vulnerability
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-27219@libruby3.1
# Issue #55
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: CGI: Denial of Service in CGI::Cookie.parse
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-27220@libruby3.1
# Issue #56
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: CGI: ReDoS in CGI::Util#escapeElement
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-61594@libruby3.1
# Issue #57
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: uri: URI module: Credential exposure via URI + operator
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-41316@libruby3.1
# Issue #58
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: erb: ERB: Arbitrary code execution via deserialization bypass
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42245@libruby3.1
# Issue #59
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: ruby: net-imap: Net::IMAP: Denial of Service via crafted IMAP responses
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42246@libruby3.1
# Issue #60
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: net-imap: ruby: Net::IMAP: Information disclosure via man-in-the-middle attack bypassing TLS
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-47242@libruby3.1
# Issue #61
# [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection due to improper input validation
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-53613@libsmartcols1
# Issue #62
# [ERROR] container-image-cve - libsmartcols1@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-7458@libsqlite3-0
# Issue #63
# [ERROR] container-image-cve - libsqlite3-0@3.40.1-2+deb12u2: sqlite: SQLite integer overflow
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-11822@libsqlite3-0
# Issue #64
# [ERROR] container-image-cve - libsqlite3-0@3.40.1-2+deb12u2: sqlite: SQLite: Arbitrary code execution via crafted FTS5 full-text search data
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-11824@libsqlite3-0
# Issue #65
# [ERROR] container-image-cve - libsqlite3-0@3.40.1-2+deb12u2: sqlite: SQLite: Arbitrary code execution and crash via heap-based buffer overflow in FTS5
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-58050@libssh2-1
# Issue #66
# [ERROR] container-image-cve - libssh2-1@1.10.0-3+b1: libssh2: libssh2: Heap buffer overflow via integer overflow in publickey attribute allocation
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-7598@libssh2-1
# Issue #67
# [ERROR] container-image-cve - libssh2-1@1.10.0-3+b1: libssh2: integer overflow via large username or password arguments
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-69720@libtinfo6
# Issue #68
# [ERROR] container-image-cve - libtinfo6@6.4-4: ncurses: ncurses: Buffer overflow vulnerability may lead to arbitrary code execution.
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-53613@libuuid1
# Issue #69
# [ERROR] container-image-cve - libuuid1@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-53613@mount
# Issue #70
# [ERROR] container-image-cve - mount@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-69720@ncurses-base
# Issue #71
# [ERROR] container-image-cve - ncurses-base@6.4-4: ncurses: ncurses: Buffer overflow vulnerability may lead to arbitrary code execution.
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-69720@ncurses-bin
# Issue #72
# [ERROR] container-image-cve - ncurses-bin@6.4-4: ncurses: ncurses: Buffer overflow vulnerability may lead to arbitrary code execution.
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-13221@perl
# Issue #73
# [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl: Perl: Incorrect regular expression processing via large regular expressions
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42496@perl
# Issue #74
# [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl-archive-tar: perl-archive-tar: Path traversal via crafted symlinks allows arbitrary file access
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-8376@perl
# Issue #75
# [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl: Perl: Heap buffer overflow when compiling regular expressions on 32-bit builds
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42497@perl
# Issue #76
# [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Arbitrary file modification via crafted hardlinks during archive extraction
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-48962@perl
# Issue #77
# [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl-IO-Compress: perl-IO-Compress: Arbitrary code execution via attacker-controlled output glob
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-57432@perl
# Issue #78
# [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl: Perl: Information disclosure via integer overflow in pack/unpack operations
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-57433@perl
# Issue #79
# [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: Storable: Storable: Denial of Service via signed integer overflow in deserialization
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-9538@perl
# Issue #80
# [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Denial of Service via crafted tar header with large entry size
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-13221@perl-base
# Issue #81
# [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl: Perl: Incorrect regular expression processing via large regular expressions
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42496@perl-base
# Issue #82
# [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl-archive-tar: perl-archive-tar: Path traversal via crafted symlinks allows arbitrary file access
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-8376@perl-base
# Issue #83
# [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl: Perl: Heap buffer overflow when compiling regular expressions on 32-bit builds
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42497@perl-base
# Issue #84
# [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Arbitrary file modification via crafted hardlinks during archive extraction
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-48962@perl-base
# Issue #85
# [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl-IO-Compress: perl-IO-Compress: Arbitrary code execution via attacker-controlled output glob
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-57432@perl-base
# Issue #86
# [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl: Perl: Information disclosure via integer overflow in pack/unpack operations
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-57433@perl-base
# Issue #87
# [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: Storable: Storable: Denial of Service via signed integer overflow in deserialization
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-9538@perl-base
# Issue #88
# [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Denial of Service via crafted tar header with large entry size
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-13221@perl-modules-5.36
# Issue #89
# [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl: Perl: Incorrect regular expression processing via large regular expressions
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42496@perl-modules-5.36
# Issue #90
# [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl-archive-tar: perl-archive-tar: Path traversal via crafted symlinks allows arbitrary file access
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-8376@perl-modules-5.36
# Issue #91
# [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl: Perl: Heap buffer overflow when compiling regular expressions on 32-bit builds
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42497@perl-modules-5.36
# Issue #92
# [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Arbitrary file modification via crafted hardlinks during archive extraction
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-48962@perl-modules-5.36
# Issue #93
# [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl-IO-Compress: perl-IO-Compress: Arbitrary code execution via attacker-controlled output glob
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-57432@perl-modules-5.36
# Issue #94
# [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl: Perl: Information disclosure via integer overflow in pack/unpack operations
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-57433@perl-modules-5.36
# Issue #95
# [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: Storable: Storable: Denial of Service via signed integer overflow in deserialization
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-9538@perl-modules-5.36
# Issue #96
# [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Denial of Service via crafted tar header with large entry size
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-7246@python3-click
# Issue #97
# [ERROR] container-image-cve - python3-click@8.1.3-2: github.com/pallets/click: Pallets Click: Arbitrary command execution via command injection in click.edit()
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-69534@python3.11
# Issue #98
# [ERROR] container-image-cve - python3.11@3.11.2-6+deb12u8: python-markdown: denial of service via malformed HTML-like sequences
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-11940@python3.11
# Issue #99
# [ERROR] container-image-cve - python3.11@3.11.2-6+deb12u8: python: cpython: CPython: tarfile extraction filter bypass allows escaping the destination directory
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-15308@python3.11
# Issue #100
# [ERROR] container-image-cve - python3.11@3.11.2-6+deb12u8: python: Python: CPU Denial of Service in HTML parser via repeated unterminated markup declarations
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-3644@python3.11
# Issue #101
# [ERROR] container-image-cve - python3.11@3.11.2-6+deb12u8: cpython: Incomplete control character validation in http.cookies
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-7210@python3.11
# Issue #102
# [ERROR] container-image-cve - python3.11@3.11.2-6+deb12u8: python: expat: Python/Expat: Denial of Service via crafted XML document
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-69534@python3.11-minimal
# Issue #103
# [ERROR] container-image-cve - python3.11-minimal@3.11.2-6+deb12u8: python-markdown: denial of service via malformed HTML-like sequences
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-11940@python3.11-minimal
# Issue #104
# [ERROR] container-image-cve - python3.11-minimal@3.11.2-6+deb12u8: python: cpython: CPython: tarfile extraction filter bypass allows escaping the destination directory
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-15308@python3.11-minimal
# Issue #105
# [ERROR] container-image-cve - python3.11-minimal@3.11.2-6+deb12u8: python: Python: CPU Denial of Service in HTML parser via repeated unterminated markup declarations
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-3644@python3.11-minimal
# Issue #106
# [ERROR] container-image-cve - python3.11-minimal@3.11.2-6+deb12u8: cpython: Incomplete control character validation in http.cookies
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-7210@python3.11-minimal
# Issue #107
# [ERROR] container-image-cve - python3.11-minimal@3.11.2-6+deb12u8: python: expat: Python/Expat: Denial of Service via crafted XML document
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-69534@python3.11-venv
# Issue #108
# [ERROR] container-image-cve - python3.11-venv@3.11.2-6+deb12u8: python-markdown: denial of service via malformed HTML-like sequences
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-11940@python3.11-venv
# Issue #109
# [ERROR] container-image-cve - python3.11-venv@3.11.2-6+deb12u8: python: cpython: CPython: tarfile extraction filter bypass allows escaping the destination directory
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-15308@python3.11-venv
# Issue #110
# [ERROR] container-image-cve - python3.11-venv@3.11.2-6+deb12u8: python: Python: CPU Denial of Service in HTML parser via repeated unterminated markup declarations
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-3644@python3.11-venv
# Issue #111
# [ERROR] container-image-cve - python3.11-venv@3.11.2-6+deb12u8: cpython: Incomplete control character validation in http.cookies
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-7210@python3.11-venv
# Issue #112
# [ERROR] container-image-cve - python3.11-venv@3.11.2-6+deb12u8: python: expat: Python/Expat: Denial of Service via crafted XML document
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-61594@ruby-rubygems
# Issue #113
# [ERROR] container-image-cve - ruby-rubygems@3.3.15-2+deb12u1: uri: URI module: Credential exposure via URI + operator
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-27820@ruby3.1
# Issue #114
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: zlib: zlib: Memory corruption via buffer overflow in Zlib::GzipReader
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42257@ruby3.1
# Issue #115
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection via CRLF sequences in unvalidated input
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2024-41123@ruby3.1
# Issue #116
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: rexml: rubygem-rexml: DoS when parsing an XML having many specific characters such as whitespace character, >] and ]>
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2024-41946@ruby3.1
# Issue #117
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: rexml: DoS vulnerability in REXML
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2024-49761@ruby3.1
# Issue #118
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: rexml: REXML ReDoS vulnerability
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-27219@ruby3.1
# Issue #119
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: CGI: Denial of Service in CGI::Cookie.parse
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-27220@ruby3.1
# Issue #120
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: CGI: ReDoS in CGI::Util#escapeElement
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-61594@ruby3.1
# Issue #121
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: uri: URI module: Credential exposure via URI + operator
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-41316@ruby3.1
# Issue #122
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: erb: ERB: Arbitrary code execution via deserialization bypass
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42245@ruby3.1
# Issue #123
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: ruby: net-imap: Net::IMAP: Denial of Service via crafted IMAP responses
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42246@ruby3.1
# Issue #124
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: net-imap: ruby: Net::IMAP: Information disclosure via man-in-the-middle attack bypassing TLS
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-47242@ruby3.1
# Issue #125
# [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection due to improper input validation
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-27820@ruby3.1-dev
# Issue #126
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: zlib: zlib: Memory corruption via buffer overflow in Zlib::GzipReader
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42257@ruby3.1-dev
# Issue #127
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection via CRLF sequences in unvalidated input
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2024-41123@ruby3.1-dev
# Issue #128
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: rexml: rubygem-rexml: DoS when parsing an XML having many specific characters such as whitespace character, >] and ]>
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2024-41946@ruby3.1-dev
# Issue #129
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: rexml: DoS vulnerability in REXML
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2024-49761@ruby3.1-dev
# Issue #130
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: rexml: REXML ReDoS vulnerability
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-27219@ruby3.1-dev
# Issue #131
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: CGI: Denial of Service in CGI::Cookie.parse
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-27220@ruby3.1-dev
# Issue #132
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: CGI: ReDoS in CGI::Util#escapeElement
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-61594@ruby3.1-dev
# Issue #133
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: uri: URI module: Credential exposure via URI + operator
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-41316@ruby3.1-dev
# Issue #134
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: erb: ERB: Arbitrary code execution via deserialization bypass
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42245@ruby3.1-dev
# Issue #135
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: ruby: net-imap: Net::IMAP: Denial of Service via crafted IMAP responses
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42246@ruby3.1-dev
# Issue #136
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: net-imap: ruby: Net::IMAP: Information disclosure via man-in-the-middle attack bypassing TLS
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-47242@ruby3.1-dev
# Issue #137
# [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection due to improper input validation
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-27820@ruby3.1-doc
# Issue #138
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: zlib: zlib: Memory corruption via buffer overflow in Zlib::GzipReader
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42257@ruby3.1-doc
# Issue #139
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection via CRLF sequences in unvalidated input
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2024-41123@ruby3.1-doc
# Issue #140
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: rexml: rubygem-rexml: DoS when parsing an XML having many specific characters such as whitespace character, >] and ]>
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2024-41946@ruby3.1-doc
# Issue #141
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: rexml: DoS vulnerability in REXML
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2024-49761@ruby3.1-doc
# Issue #142
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: rexml: REXML ReDoS vulnerability
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-27219@ruby3.1-doc
# Issue #143
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: CGI: Denial of Service in CGI::Cookie.parse
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-27220@ruby3.1-doc
# Issue #144
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: CGI: ReDoS in CGI::Util#escapeElement
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-61594@ruby3.1-doc
# Issue #145
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: uri: URI module: Credential exposure via URI + operator
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-41316@ruby3.1-doc
# Issue #146
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: erb: ERB: Arbitrary code execution via deserialization bypass
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42245@ruby3.1-doc
# Issue #147
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: ruby: net-imap: Net::IMAP: Denial of Service via crafted IMAP responses
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-42246@ruby3.1-doc
# Issue #148
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: net-imap: ruby: Net::IMAP: Information disclosure via man-in-the-middle attack bypassing TLS
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-47242@ruby3.1-doc
# Issue #149
# [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection due to improper input validation
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-53613@util-linux
# Issue #150
# [ERROR] container-image-cve - util-linux@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-53613@util-linux-extra
# Issue #151
# [ERROR] container-image-cve - util-linux-extra@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2023-45853@zlib1g
# Issue #152
# [ERROR] container-image-cve - zlib1g@1:1.2.13.dfsg-1: zlib: integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_6
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-14257@brace-expansion
# Issue #153
# [ERROR] container-image-cve - brace-expansion@5.0.7: brace-expansion: Brace-expansion: Denial of Service via memory exhaustion in expand() function (fixed in 5.0.8, 3.0.3, 2.1.3, 1.1.17)
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-69152@brace-expansion
# Issue #154
# [ERROR] container-image-cve - brace-expansion@5.0.7: brace-expansion: DoS via unbounded intermediate arrays, bypassing the CVE-2026-14257 mitigation (fixed in 1.1.18, 2.1.4, 3.0.6, 5.0.9)
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-69192@ip-address
# Issue #155
# [ERROR] container-image-cve - ip-address@10.2.0: ip-address: ip-address: Inconsistent IP address parsing leads to Server-Side Request Forgery (SSRF) and trust-boundary bypass (fixed in 10.3.1)
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-73566@tar
# Issue #156
# [ERROR] container-image-cve - tar@7.5.19: tar: node-tar: Denial of Service via crafted long-path tar archive (fixed in 7.5.21)
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2024-23342@ecdsa
# Issue #157
# [ERROR] container-image-cve - ecdsa@0.19.2: python-ecdsa: vulnerable to the Minerva attack
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::ghsa-6v7p-g79w-8964@msgpack
# Issue #158
# [ERROR] container-image-cve - msgpack@1.1.2: MessagePack for Python: Out-of-bounds read / crash on Unpacker reuse after a caught error (fixed in 1.2.1)
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2025-47273@setuptools
# Issue #159
# [ERROR] container-image-cve - setuptools@70.3.0: setuptools: Path Traversal Vulnerability in setuptools PackageIndex (fixed in 78.1.1)
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::ghsa-c4rq-3m3g-8wgx@nokogiri
# Issue #160
# [ERROR] container-image-cve - nokogiri@1.18.10: Nokogiri CSS selector tokenizer has regular expression backtracking (fixed in >= 1.19.3)
#   Dockerfile:1
Acknowledge: No patched package version available anywhere yet as of this scan - confirmed via a --no-cache rebuild today (live Debian bookworm-security / npm / RubyGems / PyPI indices, not a stale cache), so this is already the newest version obtainable, not a stale pin. Re-check on the next scan once a fix ships upstream.

ID: container-image-cve::Dockerfile::1::cve-2026-45022@github.com/go-git/go-git/v5
# Issue #161
# [ERROR] container-image-cve - github.com/go-git/go-git/v5@v5.16.5: go-git is an extensible git implementation library written in pure Go. ... (fixed in 5.19.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-71556@github.com/go-git/go-git/v5
# Issue #162
# [ERROR] container-image-cve - github.com/go-git/go-git/v5@v5.16.5: github.com/go-git/go-git/v5: go-git: Arbitrary file read/write via symbolic link resolution (fixed in 5.19.2)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-17106@github.com/moby/go-archive
# Issue #163
# [ERROR] container-image-cve - github.com/moby/go-archive@v0.1.0: The tar extraction routines in moby/go-archive (Unpack, UnpackLayer, U ... (fixed in 0.3.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-56854@golang.org/x/crypto
# Issue #164
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Authentication bypass due to unenforced source-address restrictions (fixed in 0.55.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-39828@golang.org/x/crypto
# Issue #165
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Unauthorized command execution via discarded SSH permissions (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-39829@golang.org/x/crypto
# Issue #166
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of Service via crafted public key with excessive parameters (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-39830@golang.org/x/crypto
# Issue #167
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of Service via resource leak from unsolicited SSH responses (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-39831@golang.org/x/crypto
# Issue #168
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Security key bypass due to missing user presence check (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-39832@golang.org/x/crypto
# Issue #169
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh/agent: golang.org/x/crypto/ssh/agent: Security bypass due to improper handling of key restrictions (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-39835@golang.org/x/crypto
# Issue #170
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang: golang.org/x/crypto/ssh: Denial of Service via crafted SSH certificate (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-42508@golang.org/x/crypto
# Issue #171
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh/knownhosts: golang: golang.org/x/crypto/ssh/knownhosts: Revocation bypass via unchecked SignatureKey (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-46595@golang.org/x/crypto
# Issue #172
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Authorization bypass due to skipped source-address validation (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-46597@golang.org/x/crypto
# Issue #173
# [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of Service via crafted AES-GCM packet decoder inputs (fixed in 0.52.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-25681@golang.org/x/net
# Issue #174
# [ERROR] container-image-cve - golang.org/x/net@v0.53.0: golang.org/x/net/html: golang.org/x/net/html: Arbitrary code execution via Cross-Site Scripting (fixed in 0.55.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-27136@golang.org/x/net
# Issue #175
# [ERROR] container-image-cve - golang.org/x/net@v0.53.0: golang.org/x/net/html: golang: golang.org/x/net/html: Cross-Site Scripting via HTML parsing bypass (fixed in 0.55.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-39821@golang.org/x/net
# Issue #176
# [ERROR] container-image-cve - golang.org/x/net@v0.53.0: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 0.55.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-46600@golang.org/x/net
# Issue #177
# [ERROR] container-image-cve - golang.org/x/net@v0.53.0: golang.org/x/net/dns/dnsmessage: golang.org/x/net/dns/dnsmessage: Denial of Service via invalid DNS record parsing (fixed in 0.56.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-56852@golang.org/x/text
# Issue #178
# [ERROR] container-image-cve - golang.org/x/text@v0.36.0: golang.org/x/text: golang.org/x/text: Denial of Service via invalid UTF-8 input (fixed in 0.39.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2025-68121@stdlib
# Issue #179
# [ERROR] container-image-cve - stdlib@v1.25.0: crypto/tls: crypto/tls: Incorrect certificate validation during TLS session resumption (fixed in 1.24.13, 1.25.7, 1.26.0-rc.3)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2025-61726@stdlib
# Issue #180
# [ERROR] container-image-cve - stdlib@v1.25.0: golang: net/url: Memory exhaustion in query parameter parsing in net/url (fixed in 1.24.12, 1.25.6)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2025-61729@stdlib
# Issue #181
# [ERROR] container-image-cve - stdlib@v1.25.0: crypto/x509: golang: Denial of Service due to excessive resource consumption via crafted certificate (fixed in 1.24.11, 1.25.5)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-25679@stdlib
# Issue #182
# [ERROR] container-image-cve - stdlib@v1.25.0: net/url: Incorrect parsing of IPv6 host literals in net/url (fixed in 1.25.8, 1.26.1)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-27145@stdlib
# Issue #183
# [ERROR] container-image-cve - stdlib@v1.25.0: crypto/x509: golang: golang crypto/x509: Denial of Service via excessive processing of DNS SAN entries (fixed in 1.25.11, 1.26.4)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-32280@stdlib
# Issue #184
# [ERROR] container-image-cve - stdlib@v1.25.0: crypto/x509: crypto/tls: golang: Go: Denial of Service vulnerability in certificate chain building (fixed in 1.25.9, 1.26.2)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-32281@stdlib
# Issue #185
# [ERROR] container-image-cve - stdlib@v1.25.0: crypto/x509: golang: Go crypto/x509: Denial of Service via inefficient certificate chain validation (fixed in 1.25.9, 1.26.2)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-32283@stdlib
# Issue #186
# [ERROR] container-image-cve - stdlib@v1.25.0: crypto/tls: golang: Go crypto/tls: Denial of Service via multiple TLS 1.3 key update messages (fixed in 1.25.9, 1.26.2)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-33811@stdlib
# Issue #187
# [ERROR] container-image-cve - stdlib@v1.25.0: net: golang: Go net package: Denial of Service via long CNAME response in LookupCNAME (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-33814@stdlib
# Issue #188
# [ERROR] container-image-cve - stdlib@v1.25.0: net/http/internal/http2: golang: golang.org/x/net: Go HTTP/2: Denial of Service via malformed SETTINGS_MAX_FRAME_SIZE frame (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-33818@stdlib
# Issue #189
# [ERROR] container-image-cve - stdlib@v1.25.0: encoding/asn1: golang: Go encoding/asn1: Denial of Service via excessive recursion in Unmarshal (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-39820@stdlib
# Issue #190
# [ERROR] container-image-cve - stdlib@v1.25.0: net/mail: golang: Go net/mail: Denial of Service via crafted email inputs (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-39821@stdlib
# Issue #191
# [ERROR] container-image-cve - stdlib@v1.25.0: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-39822@stdlib
# Issue #192
# [ERROR] container-image-cve - stdlib@v1.25.0: golang: Go os.Root: Symlink following vulnerability allows directory traversal (fixed in 1.25.12, 1.26.5, 1.27.0-rc.2)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-39836@stdlib
# Issue #193
# [ERROR] container-image-cve - stdlib@v1.25.0: net: golang: Go net package: Denial of Service via NUL byte in Dial and LookupPort on Windows (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-42499@stdlib
# Issue #194
# [ERROR] container-image-cve - stdlib@v1.25.0: net/mail: golang: net/mail: Denial of Service via pathological email address parsing (fixed in 1.25.10, 1.26.3)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-42504@stdlib
# Issue #195
# [ERROR] container-image-cve - stdlib@v1.25.0: mime: golang: Golang MIME: Denial of Service via maliciously-crafted MIME header (fixed in 1.25.11, 1.26.4)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-56853@stdlib
# Issue #196
# [ERROR] container-image-cve - stdlib@v1.25.0: net/http: golang: Go net/http: Unencrypted HTTP/2 connections vulnerable to Denial of Service (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-56858@stdlib
# Issue #197
# [ERROR] container-image-cve - stdlib@v1.25.0: html/template: golang: Go html/template: Cross-Site Scripting via pathological input (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-56859@stdlib
# Issue #198
# [ERROR] container-image-cve - stdlib@v1.25.0: encoding/xml: golang: Go: Denial of Service via XML decoding recursion depth issue (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-56860@stdlib
# Issue #199
# [ERROR] container-image-cve - stdlib@v1.25.0: net/url: golang: golang net/url: Denial of Service from quadratic complexity in path resolution (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-56862@stdlib
# Issue #200
# [ERROR] container-image-cve - stdlib@v1.25.0: crypto/tls: golang: Golang crypto/tls: Denial of Service via indefinite KeyUpdate messages (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-56864@golang.org/x/mod
# Issue #201
# [ERROR] container-image-cve - golang.org/x/mod@v0.37.0: A malicious GOSUMDB was capable of serving arbitrary module content no ... (fixed in 0.40.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-56865@golang.org/x/mod
# Issue #202
# [ERROR] container-image-cve - golang.org/x/mod@v0.37.0: golang.org/x/mod/sumdb/tlog: golang.org/x/mod/sumdb/tlog: Supply chain compromise via transparency log tile verification bypass (fixed in 0.40.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::ghsa-hrxh-6v49-42gf@google.golang.org/grpc
# Issue #203
# [ERROR] container-image-cve - google.golang.org/grpc@v1.82.0: gRPC-Go: xDS RBAC and HTTP/2 Vulnerabilities (fixed in 1.82.1)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2026-46600@stdlib
# Issue #204
# [ERROR] container-image-cve - stdlib@v1.26.4: golang.org/x/net/dns/dnsmessage: golang.org/x/net/dns/dnsmessage: Denial of Service via invalid DNS record parsing (fixed in 1.26.6, 1.27.0-rc.3)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: container-image-cve::Dockerfile::1::cve-2025-47913@golang.org/x/crypto
# Issue #205
# [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh/agent: golang.org/x/crypto/ssh/agent: SSH client panic due to unexpected SSH_AGENT_SUCCESS (fixed in 0.43.0)
#   Dockerfile:1
Acknowledge: Bundled inside `act` v0.2.89 (nektos/act) - the latest upstream release as of this scan (verified via `gh api repos/nektos/act/releases`, published 2026-06-01, no newer release since). act vendors this dependency/Go toolchain version internally; no act release incorporating a fix has shipped yet. Re-check on the next act version bump.

ID: secret::rust/crates/secrets/src/lib.rs::565
# Issue #206
# [ERROR] secret - Hardcoded connection-string credential
#   rust/crates/secrets/src/lib.rs:565
Acknowledge: Fake DATABASE_URL connection-string literal written to a scratch fixture file within a unit test for the URI_CREDENTIAL_RE detector, not a real credential - uses example.com (IANA/RFC 2606-reserved for documentation) and an explicitly-labeled placeholder password.

ID: secret::rust/crates/phase4-orchestrator/src/lib.rs::672
# Issue #207
# [ERROR] secret - Hardcoded gcp-api-key
#   rust/crates/phase4-orchestrator/src/lib.rs:672
Acknowledge: Fake GCP/Firebase web API key literal written to an in-memory test fixture to verify gitleaks' gcp-api-key detector integration, not a real credential - same pattern as the other fake-GCP-key entries in this file, just carried to a new line number after nearby edits.

ID: gha-security::.github/workflows/deploy-docs.yml::13
# Issue #208
# [ERROR] gha-security - overly broad permissions (  pages: write)
#   .github/workflows/deploy-docs.yml:13
Acknowledge: `pages: write` + `id-token: write` (next entry) are exactly the two permissions GitHub's own actions/deploy-pages documentation requires for OIDC-based Pages deployment - already the minimal job-level set (no broader contents:write, etc.). zizmor's excessive-permissions rule flags any explicit write scope without knowing what the job's own actions actually need; this is that documented minimum, not excessive in practice.

ID: gha-security::.github/workflows/deploy-docs.yml::14
# Issue #209
# [ERROR] gha-security - overly broad permissions (  id-token: write)
#   .github/workflows/deploy-docs.yml:14
Acknowledge: Same justification as the `pages: write` entry above - the minimal, documented permission pair actions/deploy-pages needs for OIDC-based deployment.

ID: container-image-cve::Dockerfile::1::cve-2026-84304@google.golang.org/grpc
# Issue #210
# [ERROR] container-image-cve - google.golang.org/grpc@v1.82.0: gRPC-Go is the Go language implementation of gRPC. Prior to 1.83.1, in ... (fixed in 1.83.1)
#   Dockerfile:1
Acknowledge: google.golang.org/grpc CVE-2026-84304 (fixed upstream in 1.83.1) is bundled at various pre-1.83.1 versions inside several vendored Go-language release binaries in this image (confirmed for `act` v0.2.89 - see the neighboring GHSA-hrxh-6v49-42gf entry for the same package/version; likely also one or more of gh/hadolint/gocloc/syft/cosign/oasdiff, but Trivy's report collapses every hit onto this one Dockerfile:1 finding, so the exact binary per version isn't distinguishable from Ignite's own issue view). Not confirmed that every one of those upstream projects has shipped a release rebuilt against a patched grpc-go as of this scan. Re-check as each tool's pinned version is bumped.

ID: secret::rust/crates/server/src/routes/pipeline_interactive.rs::1238
# Issue #211
# [ERROR] secret - Hardcoded aws-access-token
#   rust/crates/server/src/routes/pipeline_interactive.rs:1238
Acknowledge: 

ID: license-compliance::docs-site/package.json::0::@docusaurus/core
# Issue #212
# [ERROR] license-compliance - @docusaurus/core@3.10.2 — License lookup failed (package/version not found upstream).
#   docs-site/package.json:17
Acknowledge: 

ID: license-compliance::docs-site/package.json::0::@docusaurus/faster
# Issue #213
# [ERROR] license-compliance - @docusaurus/faster@3.10.2 — License lookup failed (package/version not found upstream).
#   docs-site/package.json:18
Acknowledge: 

ID: license-compliance::docs-site/package.json::0::@docusaurus/preset-classic
# Issue #214
# [ERROR] license-compliance - @docusaurus/preset-classic@3.10.2 — License lookup failed (package/version not found upstream).
#   docs-site/package.json:19
Acknowledge: 

ID: license-compliance::docs-site/package.json::0::docusaurus-plugin-image-zoom
# Issue #215
# [ERROR] license-compliance - docusaurus-plugin-image-zoom@3.0.1 — License lookup failed (package/version not found upstream).
#   docs-site/package.json:22
Acknowledge: 

ID: license-compliance::docs-site/package.json::0::react
# Issue #216
# [ERROR] license-compliance - react@19.0.0 — License lookup failed (package/version not found upstream).
#   docs-site/package.json:24
Acknowledge: 

ID: license-compliance::docs-site/package.json::0::react-dom
# Issue #217
# [ERROR] license-compliance - react-dom@19.0.0 — License lookup failed (package/version not found upstream).
#   docs-site/package.json:25
Acknowledge: 

ID: license-compliance::docs-site/package.json::0::@docusaurus/module-type-aliases
# Issue #218
# [ERROR] license-compliance - @docusaurus/module-type-aliases@3.10.2 — License lookup failed (package/version not found upstream).
#   docs-site/package.json:28
Acknowledge: 

ID: license-compliance::docs-site/package.json::0::@docusaurus/types
# Issue #219
# [ERROR] license-compliance - @docusaurus/types@3.10.2 — License lookup failed (package/version not found upstream).
#   docs-site/package.json:29
Acknowledge: 
