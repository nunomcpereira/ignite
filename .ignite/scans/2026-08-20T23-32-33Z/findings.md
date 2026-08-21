# Ignite scan findings — 2026-08-20T23:32:33.828Z

## [WARNING] secret - Hardcoded password (in a test file — likely a fixture, not a real credential)

- ID: `secret::test/auth-security.test.js::130`
- Location: test/auth-security.test.js:130
- Score: 5

## [WARNING] secret - Hardcoded github-pat (in a test file — likely a fixture, not a real credential)

- ID: `secret::test/secrets-scan.test.js::90`
- Location: test/secrets-scan.test.js:90
- Score: 5

## [WARNING] secret - Hardcoded github-pat (in a test file — likely a fixture, not a real credential)

- ID: `secret::test/secrets-scan.test.js::208`
- Location: test/secrets-scan.test.js:208
- Score: 5

## [WARNING] secret - Hardcoded stripe-access-token (in a test file — likely a fixture, not a real credential)

- ID: `secret::test/secrets-scan.test.js::33`
- Location: test/secrets-scan.test.js:33
- Score: 5

## [WARNING] secret - Hardcoded stripe-access-token (in a test file — likely a fixture, not a real credential)

- ID: `secret::test/secrets-scan.test.js::71`
- Location: test/secrets-scan.test.js:71
- Score: 5

## [WARNING] secret - Hardcoded stripe-access-token (in a test file — likely a fixture, not a real credential)

- ID: `secret::test/secrets-scan.test.js::211`
- Location: test/secrets-scan.test.js:211
- Score: 5

## [WARNING] iac-security - No HEALTHCHECK defined

- ID: `iac-security::Dockerfile::1`
- Location: Dockerfile:1
- Score: 3

## [WARNING] iac-security - Ensure that HEALTHCHECK instructions have been added to container images

- ID: `iac-security::Dockerfile::1`
- Location: Dockerfile:1
- Score: 3

## [WARNING] iac-security - Base64 High Entropy String

- ID: `iac-security::config.json::14`
- Location: config.json:14
- Score: 3

## [WARNING] iac-security - Pin versions in apt get install. Instead of `apt-get install <package>` use `apt-get install <package>=<version>`

- ID: `iac-security::Dockerfile::67`
- Location: Dockerfile:67
- Score: 3

## [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check

- ID: `iac-security::Dockerfile::85`
- Location: Dockerfile:85
- Score: 3

## [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check

- ID: `iac-security::Dockerfile::94`
- Location: Dockerfile:94
- Score: 3

## [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`

- ID: `iac-security::Dockerfile::98`
- Location: Dockerfile:98
- Score: 3

## [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check

- ID: `iac-security::Dockerfile::107`
- Location: Dockerfile:107
- Score: 3

## [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check

- ID: `iac-security::Dockerfile::113`
- Location: Dockerfile:113
- Score: 3

## [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`

- ID: `iac-security::Dockerfile::123`
- Location: Dockerfile:123
- Score: 3

## [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check

- ID: `iac-security::Dockerfile::124`
- Location: Dockerfile:124
- Score: 3

## [WARNING] iac-security - Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`

- ID: `iac-security::Dockerfile::128`
- Location: Dockerfile:128
- Score: 3

## [WARNING] iac-security - Pin versions in npm. Instead of `npm install <package>` use `npm install <package>@<version>`

- ID: `iac-security::Dockerfile::150`
- Location: Dockerfile:150
- Score: 3

## [WARNING] iac-security - Multiple consecutive `RUN` instructions. Consider consolidation.

- ID: `iac-security::Dockerfile::151`
- Location: Dockerfile:151
- Score: 3

## [WARNING] iac-security - Pin versions in npm. Instead of `npm install <package>` use `npm install <package>@<version>`

- ID: `iac-security::Dockerfile::151`
- Location: Dockerfile:151
- Score: 3

## [WARNING] iac-security - Pin versions in gem install. Instead of `gem install <gem>` use `gem install <gem>:<version>`

- ID: `iac-security::Dockerfile::160`
- Location: Dockerfile:160
- Score: 3

## [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check

- ID: `iac-security::Dockerfile::189`
- Location: Dockerfile:189
- Score: 3

## [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check

- ID: `iac-security::Dockerfile::203`
- Location: Dockerfile:203
- Score: 3

## [WARNING] iac-security - Set the SHELL option -o pipefail before RUN with a pipe in it. If you are using /bin/sh in an alpine image or if your shell is symlinked to busybox then consider explicitly setting your SHELL to /bin/ash, or disable this check

- ID: `iac-security::Dockerfile::208`
- Location: Dockerfile:208
- Score: 3

## [WARNING] iac-security - Non-numeric user-id may not be resolvable by host system

- ID: `iac-security::Dockerfile::240`
- Location: Dockerfile:240
- Score: 3

## [ERROR] container-image-cve - bsdutils@1:2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path

- ID: `container-image-cve::Dockerfile::1::cve-2026-53613@bsdutils`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - bsdutils@1:2.38.1-5+deb12u3: [Integer Overflow or Wraparound in libblkid/src/partitions/dos.c]

- ID: `container-image-cve::Dockerfile::1::cve-2026-53615@bsdutils`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - curl@7.88.1-10+deb12u15: curl: curl: SSH host verification bypass when using schemeless URLs with SFTP/SCP

- ID: `container-image-cve::Dockerfile::1::cve-2026-12064@curl`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - curl@7.88.1-10+deb12u15: curl: libcurl: Information disclosure due to cookie leak when reusing connections with custom Host headers

- ID: `container-image-cve::Dockerfile::1::cve-2026-6276@curl`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - curl@7.88.1-10+deb12u15: curl: curl: Insecure connection establishment due to TLS configuration mismatch

- ID: `container-image-cve::Dockerfile::1::cve-2026-8286@curl`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - curl@7.88.1-10+deb12u15: curl: libcurl: Unauthorized connection reuse due to a logical error

- ID: `container-image-cve::Dockerfile::1::cve-2026-8458@curl`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - curl@7.88.1-10+deb12u15: curl: Information disclosure due to uncleared proxy authentication state

- ID: `container-image-cve::Dockerfile::1::cve-2026-8927@curl`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - gzip@1.12-1: GNU gzip contains a global buffer overflow vulnerability in the LZH de ...

- ID: `container-image-cve::Dockerfile::1::cve-2026-41992@gzip`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libacl1@2.3.1-3: acl: Symlink traversal privilege escalation via libacl functions

- ID: `container-image-cve::Dockerfile::1::cve-2026-54369@libacl1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libblkid1@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path

- ID: `container-image-cve::Dockerfile::1::cve-2026-53613@libblkid1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libblkid1@2.38.1-5+deb12u3: [Integer Overflow or Wraparound in libblkid/src/partitions/dos.c]

- ID: `container-image-cve::Dockerfile::1::cve-2026-53615@libblkid1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libcurl3-gnutls@7.88.1-10+deb12u15: curl: curl: SSH host verification bypass when using schemeless URLs with SFTP/SCP

- ID: `container-image-cve::Dockerfile::1::cve-2026-12064@libcurl3-gnutls`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libcurl3-gnutls@7.88.1-10+deb12u15: curl: libcurl: Information disclosure due to cookie leak when reusing connections with custom Host headers

- ID: `container-image-cve::Dockerfile::1::cve-2026-6276@libcurl3-gnutls`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libcurl3-gnutls@7.88.1-10+deb12u15: curl: curl: Insecure connection establishment due to TLS configuration mismatch

- ID: `container-image-cve::Dockerfile::1::cve-2026-8286@libcurl3-gnutls`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libcurl3-gnutls@7.88.1-10+deb12u15: curl: libcurl: Unauthorized connection reuse due to a logical error

- ID: `container-image-cve::Dockerfile::1::cve-2026-8458@libcurl3-gnutls`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libcurl3-gnutls@7.88.1-10+deb12u15: curl: Information disclosure due to uncleared proxy authentication state

- ID: `container-image-cve::Dockerfile::1::cve-2026-8927@libcurl3-gnutls`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libcurl4@7.88.1-10+deb12u15: curl: curl: SSH host verification bypass when using schemeless URLs with SFTP/SCP

- ID: `container-image-cve::Dockerfile::1::cve-2026-12064@libcurl4`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libcurl4@7.88.1-10+deb12u15: curl: libcurl: Information disclosure due to cookie leak when reusing connections with custom Host headers

- ID: `container-image-cve::Dockerfile::1::cve-2026-6276@libcurl4`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libcurl4@7.88.1-10+deb12u15: curl: curl: Insecure connection establishment due to TLS configuration mismatch

- ID: `container-image-cve::Dockerfile::1::cve-2026-8286@libcurl4`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libcurl4@7.88.1-10+deb12u15: curl: libcurl: Unauthorized connection reuse due to a logical error

- ID: `container-image-cve::Dockerfile::1::cve-2026-8458@libcurl4`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libcurl4@7.88.1-10+deb12u15: curl: Information disclosure due to uncleared proxy authentication state

- ID: `container-image-cve::Dockerfile::1::cve-2026-8927@libcurl4`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libexpat1@2.5.0-1+deb12u2: firefox: thunderbird: expat: libexpat in Expat allows attackers to trigger large dynamic memory allocations via a small document that is submitted for parsing

- ID: `container-image-cve::Dockerfile::1::cve-2025-59375@libexpat1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libexpat1@2.5.0-1+deb12u2: libexpat: libexpat: Information disclosure and data integrity issues due to integer overflow in buffer reallocation

- ID: `container-image-cve::Dockerfile::1::cve-2026-25210@libexpat1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libexpat1@2.5.0-1+deb12u2: libexpat: denial of service via crafted XML input

- ID: `container-image-cve::Dockerfile::1::cve-2026-45186@libexpat1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libexpat1@2.5.0-1+deb12u2: libexpat before 2.8.2 has an integer overflow in copyString.

- ID: `container-image-cve::Dockerfile::1::cve-2026-56408@libexpat1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libldap-2.5-0@2.5.13+dfsg-5: openldap: null pointer dereference in  ber_memalloc_x  function

- ID: `container-image-cve::Dockerfile::1::cve-2023-2953@libldap-2.5-0`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libmount1@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path

- ID: `container-image-cve::Dockerfile::1::cve-2026-53613@libmount1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libmount1@2.38.1-5+deb12u3: [Integer Overflow or Wraparound in libblkid/src/partitions/dos.c]

- ID: `container-image-cve::Dockerfile::1::cve-2026-53615@libmount1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libncurses6@6.4-4: ncurses: ncurses: Buffer overflow vulnerability may lead to arbitrary code execution.

- ID: `container-image-cve::Dockerfile::1::cve-2025-69720@libncurses6`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libncursesw6@6.4-4: ncurses: ncurses: Buffer overflow vulnerability may lead to arbitrary code execution.

- ID: `container-image-cve::Dockerfile::1::cve-2025-69720@libncursesw6`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl: Perl: Incorrect regular expression processing via large regular expressions

- ID: `container-image-cve::Dockerfile::1::cve-2026-13221@libperl5.36`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl-archive-tar: perl-archive-tar: Path traversal via crafted symlinks allows arbitrary file access

- ID: `container-image-cve::Dockerfile::1::cve-2026-42496@libperl5.36`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: Storable versions before 3.41 for Perl have a signed integer overflow  ...

- ID: `container-image-cve::Dockerfile::1::cve-2026-57433@libperl5.36`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl: Perl: Heap buffer overflow when compiling regular expressions on 32-bit builds

- ID: `container-image-cve::Dockerfile::1::cve-2026-8376@libperl5.36`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Arbitrary file modification via crafted hardlinks during archive extraction

- ID: `container-image-cve::Dockerfile::1::cve-2026-42497@libperl5.36`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl-IO-Compress: perl-IO-Compress: Arbitrary code execution via attacker-controlled output glob

- ID: `container-image-cve::Dockerfile::1::cve-2026-48962@libperl5.36`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl: Perl: Information disclosure via integer overflow in pack/unpack operations

- ID: `container-image-cve::Dockerfile::1::cve-2026-57432@libperl5.36`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libperl5.36@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Denial of Service via crafted tar header with large entry size

- ID: `container-image-cve::Dockerfile::1::cve-2026-9538@libperl5.36`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libpython3.11-minimal@3.11.2-6+deb12u8: python-markdown: denial of service via malformed HTML-like sequences

- ID: `container-image-cve::Dockerfile::1::cve-2025-69534@libpython3.11-minimal`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libpython3.11-minimal@3.11.2-6+deb12u8: python: cpython: CPython: tarfile extraction filter bypass allows escaping the destination directory

- ID: `container-image-cve::Dockerfile::1::cve-2026-11940@libpython3.11-minimal`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libpython3.11-minimal@3.11.2-6+deb12u8: python: Python: CPU Denial of Service in HTML parser via repeated unterminated markup declarations

- ID: `container-image-cve::Dockerfile::1::cve-2026-15308@libpython3.11-minimal`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libpython3.11-minimal@3.11.2-6+deb12u8: cpython: Incomplete control character validation in http.cookies

- ID: `container-image-cve::Dockerfile::1::cve-2026-3644@libpython3.11-minimal`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libpython3.11-minimal@3.11.2-6+deb12u8: python: expat: Python/Expat: Denial of Service via crafted XML document

- ID: `container-image-cve::Dockerfile::1::cve-2026-7210@libpython3.11-minimal`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libpython3.11-stdlib@3.11.2-6+deb12u8: python-markdown: denial of service via malformed HTML-like sequences

- ID: `container-image-cve::Dockerfile::1::cve-2025-69534@libpython3.11-stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libpython3.11-stdlib@3.11.2-6+deb12u8: python: cpython: CPython: tarfile extraction filter bypass allows escaping the destination directory

- ID: `container-image-cve::Dockerfile::1::cve-2026-11940@libpython3.11-stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libpython3.11-stdlib@3.11.2-6+deb12u8: python: Python: CPU Denial of Service in HTML parser via repeated unterminated markup declarations

- ID: `container-image-cve::Dockerfile::1::cve-2026-15308@libpython3.11-stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libpython3.11-stdlib@3.11.2-6+deb12u8: cpython: Incomplete control character validation in http.cookies

- ID: `container-image-cve::Dockerfile::1::cve-2026-3644@libpython3.11-stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libpython3.11-stdlib@3.11.2-6+deb12u8: python: expat: Python/Expat: Denial of Service via crafted XML document

- ID: `container-image-cve::Dockerfile::1::cve-2026-7210@libpython3.11-stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: zlib: zlib: Memory corruption via buffer overflow in Zlib::GzipReader

- ID: `container-image-cve::Dockerfile::1::cve-2026-27820@libruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection via CRLF sequences in unvalidated input

- ID: `container-image-cve::Dockerfile::1::cve-2026-42257@libruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: rexml: rubygem-rexml: DoS when parsing an XML having many specific characters such as whitespace character, >] and ]>

- ID: `container-image-cve::Dockerfile::1::cve-2024-41123@libruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: rexml: DoS vulnerability in REXML

- ID: `container-image-cve::Dockerfile::1::cve-2024-41946@libruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: rexml: REXML ReDoS vulnerability

- ID: `container-image-cve::Dockerfile::1::cve-2024-49761@libruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: CGI: Denial of Service in CGI::Cookie.parse

- ID: `container-image-cve::Dockerfile::1::cve-2025-27219@libruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: CGI: ReDoS in CGI::Util#escapeElement

- ID: `container-image-cve::Dockerfile::1::cve-2025-27220@libruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: uri: URI module: Credential exposure via URI + operator

- ID: `container-image-cve::Dockerfile::1::cve-2025-61594@libruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: erb: ERB: Arbitrary code execution via deserialization bypass

- ID: `container-image-cve::Dockerfile::1::cve-2026-41316@libruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: ruby: net-imap: Net::IMAP: Denial of Service via crafted IMAP responses

- ID: `container-image-cve::Dockerfile::1::cve-2026-42245@libruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: net-imap: ruby: Net::IMAP: Information disclosure via man-in-the-middle attack bypassing TLS

- ID: `container-image-cve::Dockerfile::1::cve-2026-42246@libruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libruby3.1@3.1.2-7+deb12u1: Net::IMAP implements Internet Message Access Protocol (IMAP) client fu ...

- ID: `container-image-cve::Dockerfile::1::cve-2026-47242@libruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libsmartcols1@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path

- ID: `container-image-cve::Dockerfile::1::cve-2026-53613@libsmartcols1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libsmartcols1@2.38.1-5+deb12u3: [Integer Overflow or Wraparound in libblkid/src/partitions/dos.c]

- ID: `container-image-cve::Dockerfile::1::cve-2026-53615@libsmartcols1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libsqlite3-0@3.40.1-2+deb12u2: sqlite: SQLite integer overflow

- ID: `container-image-cve::Dockerfile::1::cve-2025-7458@libsqlite3-0`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libssh2-1@1.10.0-3+b1: libssh2: libssh2: Heap buffer overflow via integer overflow in publickey attribute allocation

- ID: `container-image-cve::Dockerfile::1::cve-2026-58050@libssh2-1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libssh2-1@1.10.0-3+b1: libssh2: integer overflow via large username or password arguments

- ID: `container-image-cve::Dockerfile::1::cve-2026-7598@libssh2-1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libssl3@3.0.20-1~deb12u2: openssl: OpenSSL: Denial of Service via unbounded memory growth in QUIC server

- ID: `container-image-cve::Dockerfile::1::cve-2026-14456@libssl3`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libtinfo6@6.4-4: ncurses: ncurses: Buffer overflow vulnerability may lead to arbitrary code execution.

- ID: `container-image-cve::Dockerfile::1::cve-2025-69720@libtinfo6`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libuuid1@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path

- ID: `container-image-cve::Dockerfile::1::cve-2026-53613@libuuid1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - libuuid1@2.38.1-5+deb12u3: [Integer Overflow or Wraparound in libblkid/src/partitions/dos.c]

- ID: `container-image-cve::Dockerfile::1::cve-2026-53615@libuuid1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - mount@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path

- ID: `container-image-cve::Dockerfile::1::cve-2026-53613@mount`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - mount@2.38.1-5+deb12u3: [Integer Overflow or Wraparound in libblkid/src/partitions/dos.c]

- ID: `container-image-cve::Dockerfile::1::cve-2026-53615@mount`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ncurses-base@6.4-4: ncurses: ncurses: Buffer overflow vulnerability may lead to arbitrary code execution.

- ID: `container-image-cve::Dockerfile::1::cve-2025-69720@ncurses-base`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ncurses-bin@6.4-4: ncurses: ncurses: Buffer overflow vulnerability may lead to arbitrary code execution.

- ID: `container-image-cve::Dockerfile::1::cve-2025-69720@ncurses-bin`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - openssl@3.0.20-1~deb12u2: openssl: OpenSSL: Denial of Service via unbounded memory growth in QUIC server

- ID: `container-image-cve::Dockerfile::1::cve-2026-14456@openssl`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl: Perl: Incorrect regular expression processing via large regular expressions

- ID: `container-image-cve::Dockerfile::1::cve-2026-13221@perl`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl-archive-tar: perl-archive-tar: Path traversal via crafted symlinks allows arbitrary file access

- ID: `container-image-cve::Dockerfile::1::cve-2026-42496@perl`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: Storable versions before 3.41 for Perl have a signed integer overflow  ...

- ID: `container-image-cve::Dockerfile::1::cve-2026-57433@perl`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl: Perl: Heap buffer overflow when compiling regular expressions on 32-bit builds

- ID: `container-image-cve::Dockerfile::1::cve-2026-8376@perl`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Arbitrary file modification via crafted hardlinks during archive extraction

- ID: `container-image-cve::Dockerfile::1::cve-2026-42497@perl`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl-IO-Compress: perl-IO-Compress: Arbitrary code execution via attacker-controlled output glob

- ID: `container-image-cve::Dockerfile::1::cve-2026-48962@perl`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl: Perl: Information disclosure via integer overflow in pack/unpack operations

- ID: `container-image-cve::Dockerfile::1::cve-2026-57432@perl`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Denial of Service via crafted tar header with large entry size

- ID: `container-image-cve::Dockerfile::1::cve-2026-9538@perl`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl: Perl: Incorrect regular expression processing via large regular expressions

- ID: `container-image-cve::Dockerfile::1::cve-2026-13221@perl-base`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl-archive-tar: perl-archive-tar: Path traversal via crafted symlinks allows arbitrary file access

- ID: `container-image-cve::Dockerfile::1::cve-2026-42496@perl-base`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: Storable versions before 3.41 for Perl have a signed integer overflow  ...

- ID: `container-image-cve::Dockerfile::1::cve-2026-57433@perl-base`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl: Perl: Heap buffer overflow when compiling regular expressions on 32-bit builds

- ID: `container-image-cve::Dockerfile::1::cve-2026-8376@perl-base`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Arbitrary file modification via crafted hardlinks during archive extraction

- ID: `container-image-cve::Dockerfile::1::cve-2026-42497@perl-base`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl-IO-Compress: perl-IO-Compress: Arbitrary code execution via attacker-controlled output glob

- ID: `container-image-cve::Dockerfile::1::cve-2026-48962@perl-base`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl: Perl: Information disclosure via integer overflow in pack/unpack operations

- ID: `container-image-cve::Dockerfile::1::cve-2026-57432@perl-base`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl-base@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Denial of Service via crafted tar header with large entry size

- ID: `container-image-cve::Dockerfile::1::cve-2026-9538@perl-base`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl: Perl: Incorrect regular expression processing via large regular expressions

- ID: `container-image-cve::Dockerfile::1::cve-2026-13221@perl-modules-5.36`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl-archive-tar: perl-archive-tar: Path traversal via crafted symlinks allows arbitrary file access

- ID: `container-image-cve::Dockerfile::1::cve-2026-42496@perl-modules-5.36`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: Storable versions before 3.41 for Perl have a signed integer overflow  ...

- ID: `container-image-cve::Dockerfile::1::cve-2026-57433@perl-modules-5.36`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl: Perl: Heap buffer overflow when compiling regular expressions on 32-bit builds

- ID: `container-image-cve::Dockerfile::1::cve-2026-8376@perl-modules-5.36`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Arbitrary file modification via crafted hardlinks during archive extraction

- ID: `container-image-cve::Dockerfile::1::cve-2026-42497@perl-modules-5.36`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl-IO-Compress: perl-IO-Compress: Arbitrary code execution via attacker-controlled output glob

- ID: `container-image-cve::Dockerfile::1::cve-2026-48962@perl-modules-5.36`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl: Perl: Information disclosure via integer overflow in pack/unpack operations

- ID: `container-image-cve::Dockerfile::1::cve-2026-57432@perl-modules-5.36`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - perl-modules-5.36@5.36.0-7+deb12u3: perl-Archive-Tar: perl-Archive-Tar: Denial of Service via crafted tar header with large entry size

- ID: `container-image-cve::Dockerfile::1::cve-2026-9538@perl-modules-5.36`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - python3-click@8.1.3-2: github.com/pallets/click: Pallets Click: Arbitrary command execution via command injection in click.edit()

- ID: `container-image-cve::Dockerfile::1::cve-2026-7246@python3-click`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - python3.11@3.11.2-6+deb12u8: python-markdown: denial of service via malformed HTML-like sequences

- ID: `container-image-cve::Dockerfile::1::cve-2025-69534@python3.11`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - python3.11@3.11.2-6+deb12u8: python: cpython: CPython: tarfile extraction filter bypass allows escaping the destination directory

- ID: `container-image-cve::Dockerfile::1::cve-2026-11940@python3.11`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - python3.11@3.11.2-6+deb12u8: python: Python: CPU Denial of Service in HTML parser via repeated unterminated markup declarations

- ID: `container-image-cve::Dockerfile::1::cve-2026-15308@python3.11`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - python3.11@3.11.2-6+deb12u8: cpython: Incomplete control character validation in http.cookies

- ID: `container-image-cve::Dockerfile::1::cve-2026-3644@python3.11`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - python3.11@3.11.2-6+deb12u8: python: expat: Python/Expat: Denial of Service via crafted XML document

- ID: `container-image-cve::Dockerfile::1::cve-2026-7210@python3.11`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - python3.11-minimal@3.11.2-6+deb12u8: python-markdown: denial of service via malformed HTML-like sequences

- ID: `container-image-cve::Dockerfile::1::cve-2025-69534@python3.11-minimal`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - python3.11-minimal@3.11.2-6+deb12u8: python: cpython: CPython: tarfile extraction filter bypass allows escaping the destination directory

- ID: `container-image-cve::Dockerfile::1::cve-2026-11940@python3.11-minimal`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - python3.11-minimal@3.11.2-6+deb12u8: python: Python: CPU Denial of Service in HTML parser via repeated unterminated markup declarations

- ID: `container-image-cve::Dockerfile::1::cve-2026-15308@python3.11-minimal`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - python3.11-minimal@3.11.2-6+deb12u8: cpython: Incomplete control character validation in http.cookies

- ID: `container-image-cve::Dockerfile::1::cve-2026-3644@python3.11-minimal`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - python3.11-minimal@3.11.2-6+deb12u8: python: expat: Python/Expat: Denial of Service via crafted XML document

- ID: `container-image-cve::Dockerfile::1::cve-2026-7210@python3.11-minimal`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - python3.11-venv@3.11.2-6+deb12u8: python-markdown: denial of service via malformed HTML-like sequences

- ID: `container-image-cve::Dockerfile::1::cve-2025-69534@python3.11-venv`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - python3.11-venv@3.11.2-6+deb12u8: python: cpython: CPython: tarfile extraction filter bypass allows escaping the destination directory

- ID: `container-image-cve::Dockerfile::1::cve-2026-11940@python3.11-venv`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - python3.11-venv@3.11.2-6+deb12u8: python: Python: CPU Denial of Service in HTML parser via repeated unterminated markup declarations

- ID: `container-image-cve::Dockerfile::1::cve-2026-15308@python3.11-venv`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - python3.11-venv@3.11.2-6+deb12u8: cpython: Incomplete control character validation in http.cookies

- ID: `container-image-cve::Dockerfile::1::cve-2026-3644@python3.11-venv`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - python3.11-venv@3.11.2-6+deb12u8: python: expat: Python/Expat: Denial of Service via crafted XML document

- ID: `container-image-cve::Dockerfile::1::cve-2026-7210@python3.11-venv`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby-rubygems@3.3.15-2+deb12u1: uri: URI module: Credential exposure via URI + operator

- ID: `container-image-cve::Dockerfile::1::cve-2025-61594@ruby-rubygems`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: zlib: zlib: Memory corruption via buffer overflow in Zlib::GzipReader

- ID: `container-image-cve::Dockerfile::1::cve-2026-27820@ruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection via CRLF sequences in unvalidated input

- ID: `container-image-cve::Dockerfile::1::cve-2026-42257@ruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: rexml: rubygem-rexml: DoS when parsing an XML having many specific characters such as whitespace character, >] and ]>

- ID: `container-image-cve::Dockerfile::1::cve-2024-41123@ruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: rexml: DoS vulnerability in REXML

- ID: `container-image-cve::Dockerfile::1::cve-2024-41946@ruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: rexml: REXML ReDoS vulnerability

- ID: `container-image-cve::Dockerfile::1::cve-2024-49761@ruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: CGI: Denial of Service in CGI::Cookie.parse

- ID: `container-image-cve::Dockerfile::1::cve-2025-27219@ruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: CGI: ReDoS in CGI::Util#escapeElement

- ID: `container-image-cve::Dockerfile::1::cve-2025-27220@ruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: uri: URI module: Credential exposure via URI + operator

- ID: `container-image-cve::Dockerfile::1::cve-2025-61594@ruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: erb: ERB: Arbitrary code execution via deserialization bypass

- ID: `container-image-cve::Dockerfile::1::cve-2026-41316@ruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: ruby: net-imap: Net::IMAP: Denial of Service via crafted IMAP responses

- ID: `container-image-cve::Dockerfile::1::cve-2026-42245@ruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: net-imap: ruby: Net::IMAP: Information disclosure via man-in-the-middle attack bypassing TLS

- ID: `container-image-cve::Dockerfile::1::cve-2026-42246@ruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1@3.1.2-7+deb12u1: Net::IMAP implements Internet Message Access Protocol (IMAP) client fu ...

- ID: `container-image-cve::Dockerfile::1::cve-2026-47242@ruby3.1`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: zlib: zlib: Memory corruption via buffer overflow in Zlib::GzipReader

- ID: `container-image-cve::Dockerfile::1::cve-2026-27820@ruby3.1-dev`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection via CRLF sequences in unvalidated input

- ID: `container-image-cve::Dockerfile::1::cve-2026-42257@ruby3.1-dev`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: rexml: rubygem-rexml: DoS when parsing an XML having many specific characters such as whitespace character, >] and ]>

- ID: `container-image-cve::Dockerfile::1::cve-2024-41123@ruby3.1-dev`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: rexml: DoS vulnerability in REXML

- ID: `container-image-cve::Dockerfile::1::cve-2024-41946@ruby3.1-dev`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: rexml: REXML ReDoS vulnerability

- ID: `container-image-cve::Dockerfile::1::cve-2024-49761@ruby3.1-dev`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: CGI: Denial of Service in CGI::Cookie.parse

- ID: `container-image-cve::Dockerfile::1::cve-2025-27219@ruby3.1-dev`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: CGI: ReDoS in CGI::Util#escapeElement

- ID: `container-image-cve::Dockerfile::1::cve-2025-27220@ruby3.1-dev`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: uri: URI module: Credential exposure via URI + operator

- ID: `container-image-cve::Dockerfile::1::cve-2025-61594@ruby3.1-dev`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: erb: ERB: Arbitrary code execution via deserialization bypass

- ID: `container-image-cve::Dockerfile::1::cve-2026-41316@ruby3.1-dev`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: ruby: net-imap: Net::IMAP: Denial of Service via crafted IMAP responses

- ID: `container-image-cve::Dockerfile::1::cve-2026-42245@ruby3.1-dev`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: net-imap: ruby: Net::IMAP: Information disclosure via man-in-the-middle attack bypassing TLS

- ID: `container-image-cve::Dockerfile::1::cve-2026-42246@ruby3.1-dev`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-dev@3.1.2-7+deb12u1: Net::IMAP implements Internet Message Access Protocol (IMAP) client fu ...

- ID: `container-image-cve::Dockerfile::1::cve-2026-47242@ruby3.1-dev`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: zlib: zlib: Memory corruption via buffer overflow in Zlib::GzipReader

- ID: `container-image-cve::Dockerfile::1::cve-2026-27820@ruby3.1-doc`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: net-imap: Net::IMAP: Arbitrary IMAP command injection via CRLF sequences in unvalidated input

- ID: `container-image-cve::Dockerfile::1::cve-2026-42257@ruby3.1-doc`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: rexml: rubygem-rexml: DoS when parsing an XML having many specific characters such as whitespace character, >] and ]>

- ID: `container-image-cve::Dockerfile::1::cve-2024-41123@ruby3.1-doc`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: rexml: DoS vulnerability in REXML

- ID: `container-image-cve::Dockerfile::1::cve-2024-41946@ruby3.1-doc`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: rexml: REXML ReDoS vulnerability

- ID: `container-image-cve::Dockerfile::1::cve-2024-49761@ruby3.1-doc`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: CGI: Denial of Service in CGI::Cookie.parse

- ID: `container-image-cve::Dockerfile::1::cve-2025-27219@ruby3.1-doc`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: CGI: ReDoS in CGI::Util#escapeElement

- ID: `container-image-cve::Dockerfile::1::cve-2025-27220@ruby3.1-doc`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: uri: URI module: Credential exposure via URI + operator

- ID: `container-image-cve::Dockerfile::1::cve-2025-61594@ruby3.1-doc`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: erb: ERB: Arbitrary code execution via deserialization bypass

- ID: `container-image-cve::Dockerfile::1::cve-2026-41316@ruby3.1-doc`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: ruby: net-imap: Net::IMAP: Denial of Service via crafted IMAP responses

- ID: `container-image-cve::Dockerfile::1::cve-2026-42245@ruby3.1-doc`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: net-imap: ruby: Net::IMAP: Information disclosure via man-in-the-middle attack bypassing TLS

- ID: `container-image-cve::Dockerfile::1::cve-2026-42246@ruby3.1-doc`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ruby3.1-doc@3.1.2-7+deb12u1: Net::IMAP implements Internet Message Access Protocol (IMAP) client fu ...

- ID: `container-image-cve::Dockerfile::1::cve-2026-47242@ruby3.1-doc`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - util-linux@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path

- ID: `container-image-cve::Dockerfile::1::cve-2026-53613@util-linux`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - util-linux@2.38.1-5+deb12u3: [Integer Overflow or Wraparound in libblkid/src/partitions/dos.c]

- ID: `container-image-cve::Dockerfile::1::cve-2026-53615@util-linux`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - util-linux-extra@2.38.1-5+deb12u3: util-linux: util-linux: TOCTOU in the mount program via ancestor directory swap on target path

- ID: `container-image-cve::Dockerfile::1::cve-2026-53613@util-linux-extra`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - util-linux-extra@2.38.1-5+deb12u3: [Integer Overflow or Wraparound in libblkid/src/partitions/dos.c]

- ID: `container-image-cve::Dockerfile::1::cve-2026-53615@util-linux-extra`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - zlib1g@1:1.2.13.dfsg-1: zlib: integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_6

- ID: `container-image-cve::Dockerfile::1::cve-2023-45853@zlib1g`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - io.netty:netty-codec@4.1.135.Final: io.netty/netty-codec-compression: Netty: Infinite loop in netty-codec-compression (bzip2) (fixed in 4.1.136.Final)

- ID: `container-image-cve::Dockerfile::1::cve-2026-59901@io.netty:netty-codec`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - io.netty:netty-codec-http@4.1.135.Final: io.netty/netty-codec-http: Netty: Denial of Service via SPDY SETTINGS frame processing (fixed in 4.2.16.Final, 4.1.136.Final)

- ID: `container-image-cve::Dockerfile::1::cve-2026-55831@io.netty:netty-codec-http`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - io.netty:netty-codec-http@4.1.135.Final: netty: io.netty/netty-codec-http: Netty: Denial of Service via SPDY header decompression amplification (fixed in 4.2.16.Final, 4.1.136.Final)

- ID: `container-image-cve::Dockerfile::1::cve-2026-55833@io.netty:netty-codec-http`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - io.netty:netty-codec-http@4.1.135.Final: netty: io.netty/netty-codec-http: Netty: Denial of Service via memory exhaustion in SPDY-to-HTTP codec (fixed in 4.2.16.Final, 4.1.136.Final)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56745@io.netty:netty-codec-http`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - io.netty:netty-codec-http2@4.1.135.Final: io.netty/netty-codec-http2: Netty: Denial of Service via HTTP/2 DATA frame memory leak (fixed in 4.2.16.Final, 4.1.136.Final)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56819@io.netty:netty-codec-http2`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - brace-expansion@5.0.7: brace-expansion: Brace-expansion: Denial of Service via memory exhaustion in expand() function (fixed in 5.0.8, 3.0.3, 2.1.3, 1.1.17)

- ID: `container-image-cve::Dockerfile::1::cve-2026-14257@brace-expansion`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - brace-expansion@5.0.7: brace-expansion: DoS via unbounded intermediate arrays, bypassing the CVE-2026-14257 mitigation (fixed in 1.1.18, 2.1.4, 3.0.6, 5.0.9)

- ID: `container-image-cve::Dockerfile::1::cve-2026-69152@brace-expansion`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ip-address@10.2.0: ip-address: ip-address: Inconsistent IP address parsing leads to Server-Side Request Forgery (SSRF) and trust-boundary bypass (fixed in 10.3.1)

- ID: `container-image-cve::Dockerfile::1::cve-2026-69192@ip-address`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - ecdsa@0.19.2: python-ecdsa: vulnerable to the Minerva attack

- ID: `container-image-cve::Dockerfile::1::cve-2024-23342@ecdsa`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - msgpack@1.1.2: MessagePack for Python: Out-of-bounds read / crash on Unpacker reuse after a caught error (fixed in 1.2.1)

- ID: `container-image-cve::Dockerfile::1::ghsa-6v7p-g79w-8964@msgpack`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - setuptools@70.3.0: setuptools: Path Traversal Vulnerability in setuptools PackageIndex (fixed in 78.1.1)

- ID: `container-image-cve::Dockerfile::1::cve-2025-47273@setuptools`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - nokogiri@1.18.10: Nokogiri CSS selector tokenizer has regular expression backtracking (fixed in >= 1.19.3)

- ID: `container-image-cve::Dockerfile::1::ghsa-c4rq-3m3g-8wgx@nokogiri`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - github.com/go-git/go-git/v5@v5.16.5: go-git is an extensible git implementation library written in pure Go. ... (fixed in 5.19.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-45022@github.com/go-git/go-git/v5`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - github.com/go-git/go-git/v5@v5.16.5: github.com/go-git/go-git/v5: go-git: Arbitrary file read/write via symbolic link resolution (fixed in 5.19.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-71556@github.com/go-git/go-git/v5`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - github.com/moby/go-archive@v0.1.0: moby/go-archive: Crafted tar archive can write outside the extraction directory (fixed in 0.3.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-17106@github.com/moby/go-archive`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Unauthorized command execution via discarded SSH permissions (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39828@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of Service via crafted public key with excessive parameters (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39829@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of Service via resource leak from unsolicited SSH responses (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39830@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Security key bypass due to missing user presence check (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39831@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh/agent: golang.org/x/crypto/ssh/agent: Security bypass due to improper handling of key restrictions (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39832@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang: golang.org/x/crypto/ssh: Denial of Service via crafted SSH certificate (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39835@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh/knownhosts: golang: golang.org/x/crypto/ssh/knownhosts: Revocation bypass via unchecked SignatureKey (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-42508@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Authorization bypass due to skipped source-address validation (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-46595@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.50.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of Service via crafted AES-GCM packet decoder inputs (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-46597@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/net@v0.53.0: golang.org/x/net/html: golang.org/x/net/html: Arbitrary code execution via Cross-Site Scripting (fixed in 0.55.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-25681@golang.org/x/net`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/net@v0.53.0: golang.org/x/net/html: golang: golang.org/x/net/html: Cross-Site Scripting via HTML parsing bypass (fixed in 0.55.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-27136@golang.org/x/net`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/net@v0.53.0: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 0.55.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39821@golang.org/x/net`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/net@v0.53.0: golang.org/x/net/dns/dnsmessage: golang.org/x/net/dns/dnsmessage: Denial of Service via invalid DNS record parsing (fixed in 0.56.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-46600@golang.org/x/net`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/text@v0.36.0: golang.org/x/text: golang.org/x/text: Denial of Service via invalid UTF-8 input (fixed in 0.39.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56852@golang.org/x/text`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: crypto/tls: crypto/tls: Incorrect certificate validation during TLS session resumption (fixed in 1.24.13, 1.25.7, 1.26.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2025-68121@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: golang: net/url: Memory exhaustion in query parameter parsing in net/url (fixed in 1.24.12, 1.25.6)

- ID: `container-image-cve::Dockerfile::1::cve-2025-61726@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: crypto/x509: golang: Denial of Service due to excessive resource consumption via crafted certificate (fixed in 1.24.11, 1.25.5)

- ID: `container-image-cve::Dockerfile::1::cve-2025-61729@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: net/url: Incorrect parsing of IPv6 host literals in net/url (fixed in 1.25.8, 1.26.1)

- ID: `container-image-cve::Dockerfile::1::cve-2026-25679@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: crypto/x509: golang: golang crypto/x509: Denial of Service via excessive processing of DNS SAN entries (fixed in 1.25.11, 1.26.4)

- ID: `container-image-cve::Dockerfile::1::cve-2026-27145@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: crypto/x509: crypto/tls: golang: Go: Denial of Service vulnerability in certificate chain building (fixed in 1.25.9, 1.26.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-32280@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: crypto/x509: golang: Go crypto/x509: Denial of Service via inefficient certificate chain validation (fixed in 1.25.9, 1.26.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-32281@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: crypto/tls: golang: Go crypto/tls: Denial of Service via multiple TLS 1.3 key update messages (fixed in 1.25.9, 1.26.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-32283@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: net: golang: Go net package: Denial of Service via long CNAME response in LookupCNAME (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-33811@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: net/http/internal/http2: golang: golang.org/x/net: Go HTTP/2: Denial of Service via malformed SETTINGS_MAX_FRAME_SIZE frame (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-33814@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: encoding/asn1: golang: Go encoding/asn1: Denial of Service via excessive recursion in Unmarshal (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-33818@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: net/mail: golang: Go net/mail: Denial of Service via crafted email inputs (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39820@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39821@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: golang: Go os.Root: Symlink following vulnerability allows directory traversal (fixed in 1.25.12, 1.26.5, 1.27.0-rc.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39822@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: net: golang: Go net package: Denial of Service via NUL byte in Dial and LookupPort on Windows (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39836@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: net/mail: golang: net/mail: Denial of Service via pathological email address parsing (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-42499@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: mime: golang: Golang MIME: Denial of Service via maliciously-crafted MIME header (fixed in 1.25.11, 1.26.4)

- ID: `container-image-cve::Dockerfile::1::cve-2026-42504@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: net/http: golang: Go net/http: Unencrypted HTTP/2 connections vulnerable to Denial of Service (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56853@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: html/template: golang: Go html/template: Cross-Site Scripting via pathological input (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56858@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: encoding/xml: golang: Go: Denial of Service via XML decoding recursion depth issue (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56859@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: net/url: golang: golang net/url: Denial of Service from quadratic complexity in path resolution (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56860@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: crypto/tls: golang: Golang crypto/tls: Denial of Service via indefinite KeyUpdate messages (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56862@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/mod@v0.38.0: A malicious GOSUMDB was capable of serving arbitrary module content no ... (fixed in 0.40.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56864@golang.org/x/mod`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/mod@v0.38.0: A malicious GOPROXY was previously capable of forging up to two sumdb  ... (fixed in 0.40.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56865@golang.org/x/mod`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: crypto/tls: crypto/tls: Incorrect certificate validation during TLS session resumption (fixed in 1.24.13, 1.25.7, 1.26.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2025-68121@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: golang: net/url: Memory exhaustion in query parameter parsing in net/url (fixed in 1.24.12, 1.25.6)

- ID: `container-image-cve::Dockerfile::1::cve-2025-61726@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: crypto/x509: golang: Denial of Service due to excessive resource consumption via crafted certificate (fixed in 1.24.11, 1.25.5)

- ID: `container-image-cve::Dockerfile::1::cve-2025-61729@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: net/url: Incorrect parsing of IPv6 host literals in net/url (fixed in 1.25.8, 1.26.1)

- ID: `container-image-cve::Dockerfile::1::cve-2026-25679@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: crypto/x509: golang: golang crypto/x509: Denial of Service via excessive processing of DNS SAN entries (fixed in 1.25.11, 1.26.4)

- ID: `container-image-cve::Dockerfile::1::cve-2026-27145@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: crypto/x509: crypto/tls: golang: Go: Denial of Service vulnerability in certificate chain building (fixed in 1.25.9, 1.26.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-32280@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: crypto/x509: golang: Go crypto/x509: Denial of Service via inefficient certificate chain validation (fixed in 1.25.9, 1.26.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-32281@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: crypto/tls: golang: Go crypto/tls: Denial of Service via multiple TLS 1.3 key update messages (fixed in 1.25.9, 1.26.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-32283@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: net: golang: Go net package: Denial of Service via long CNAME response in LookupCNAME (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-33811@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: net/http/internal/http2: golang: golang.org/x/net: Go HTTP/2: Denial of Service via malformed SETTINGS_MAX_FRAME_SIZE frame (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-33814@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: encoding/asn1: golang: Go encoding/asn1: Denial of Service via excessive recursion in Unmarshal (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-33818@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: net/mail: golang: Go net/mail: Denial of Service via crafted email inputs (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39820@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39821@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: golang: Go os.Root: Symlink following vulnerability allows directory traversal (fixed in 1.25.12, 1.26.5, 1.27.0-rc.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39822@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: net: golang: Go net package: Denial of Service via NUL byte in Dial and LookupPort on Windows (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39836@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: net/mail: golang: net/mail: Denial of Service via pathological email address parsing (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-42499@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: mime: golang: Golang MIME: Denial of Service via maliciously-crafted MIME header (fixed in 1.25.11, 1.26.4)

- ID: `container-image-cve::Dockerfile::1::cve-2026-42504@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: net/http: golang: Go net/http: Unencrypted HTTP/2 connections vulnerable to Denial of Service (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56853@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: html/template: golang: Go html/template: Cross-Site Scripting via pathological input (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56858@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: encoding/xml: golang: Go: Denial of Service via XML decoding recursion depth issue (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56859@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: net/url: golang: golang net/url: Denial of Service from quadratic complexity in path resolution (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56860@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.25.0: crypto/tls: golang: Golang crypto/tls: Denial of Service via indefinite KeyUpdate messages (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56862@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/mod@v0.37.0: A malicious GOSUMDB was capable of serving arbitrary module content no ... (fixed in 0.40.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56864@golang.org/x/mod`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/mod@v0.37.0: A malicious GOPROXY was previously capable of forging up to two sumdb  ... (fixed in 0.40.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56865@golang.org/x/mod`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/text@v0.38.0: golang.org/x/text: golang.org/x/text: Denial of Service via invalid UTF-8 input (fixed in 0.39.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56852@golang.org/x/text`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - google.golang.org/grpc@v1.82.0: gRPC-Go: xDS RBAC and HTTP/2 Vulnerabilities (fixed in 1.82.1)

- ID: `container-image-cve::Dockerfile::1::ghsa-hrxh-6v49-42gf@google.golang.org/grpc`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.4: encoding/asn1: golang: Go encoding/asn1: Denial of Service via excessive recursion in Unmarshal (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-33818@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.4: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39821@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.4: golang: Go os.Root: Symlink following vulnerability allows directory traversal (fixed in 1.25.12, 1.26.5, 1.27.0-rc.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39822@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.4: golang.org/x/net/dns/dnsmessage: golang.org/x/net/dns/dnsmessage: Denial of Service via invalid DNS record parsing (fixed in 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-46600@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.4: net/http: golang: Go net/http: Unencrypted HTTP/2 connections vulnerable to Denial of Service (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56853@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.4: html/template: golang: Go html/template: Cross-Site Scripting via pathological input (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56858@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.4: encoding/xml: golang: Go: Denial of Service via XML decoding recursion depth issue (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56859@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.4: net/url: golang: golang net/url: Denial of Service from quadratic complexity in path resolution (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56860@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.4: crypto/tls: golang: Golang crypto/tls: Denial of Service via indefinite KeyUpdate messages (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56862@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.5: encoding/asn1: golang: Go encoding/asn1: Denial of Service via excessive recursion in Unmarshal (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-33818@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.5: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39821@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.5: golang.org/x/net/dns/dnsmessage: golang.org/x/net/dns/dnsmessage: Denial of Service via invalid DNS record parsing (fixed in 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-46600@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.5: net/http: golang: Go net/http: Unencrypted HTTP/2 connections vulnerable to Denial of Service (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56853@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.5: html/template: golang: Go html/template: Cross-Site Scripting via pathological input (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56858@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.5: encoding/xml: golang: Go: Denial of Service via XML decoding recursion depth issue (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56859@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.5: net/url: golang: golang net/url: Denial of Service from quadratic complexity in path resolution (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56860@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.5: crypto/tls: golang: Golang crypto/tls: Denial of Service via indefinite KeyUpdate messages (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56862@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/mod@v0.37.0: A malicious GOSUMDB was capable of serving arbitrary module content no ... (fixed in 0.40.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56864@golang.org/x/mod`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/mod@v0.37.0: A malicious GOPROXY was previously capable of forging up to two sumdb  ... (fixed in 0.40.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56865@golang.org/x/mod`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.5: encoding/asn1: golang: Go encoding/asn1: Denial of Service via excessive recursion in Unmarshal (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-33818@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.5: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39821@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.5: golang.org/x/net/dns/dnsmessage: golang.org/x/net/dns/dnsmessage: Denial of Service via invalid DNS record parsing (fixed in 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-46600@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.5: net/http: golang: Go net/http: Unencrypted HTTP/2 connections vulnerable to Denial of Service (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56853@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.5: html/template: golang: Go html/template: Cross-Site Scripting via pathological input (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56858@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.5: encoding/xml: golang: Go: Denial of Service via XML decoding recursion depth issue (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56859@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.5: net/url: golang: golang net/url: Denial of Service from quadratic complexity in path resolution (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56860@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.5: crypto/tls: golang: Golang crypto/tls: Denial of Service via indefinite KeyUpdate messages (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56862@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh/agent: golang.org/x/crypto/ssh/agent: SSH client panic due to unexpected SSH_AGENT_SUCCESS (fixed in 0.43.0)

- ID: `container-image-cve::Dockerfile::1::cve-2025-47913@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Unauthorized command execution via discarded SSH permissions (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39828@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of Service via crafted public key with excessive parameters (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39829@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of Service via resource leak from unsolicited SSH responses (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39830@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Security key bypass due to missing user presence check (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39831@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh/agent: golang.org/x/crypto/ssh/agent: Security bypass due to improper handling of key restrictions (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39832@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh: golang: golang.org/x/crypto/ssh: Denial of Service via crafted SSH certificate (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39835@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh/knownhosts: golang: golang.org/x/crypto/ssh/knownhosts: Revocation bypass via unchecked SignatureKey (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-42508@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Authorization bypass due to skipped source-address validation (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-46595@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/crypto@v0.35.0: golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of Service via crafted AES-GCM packet decoder inputs (fixed in 0.52.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-46597@golang.org/x/crypto`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/text@v0.22.0: golang.org/x/text: golang.org/x/text: Denial of Service via invalid UTF-8 input (fixed in 0.39.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56852@golang.org/x/text`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: crypto/tls: crypto/tls: Incorrect certificate validation during TLS session resumption (fixed in 1.24.13, 1.25.7, 1.26.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2025-68121@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: golang: net/url: Memory exhaustion in query parameter parsing in net/url (fixed in 1.24.12, 1.25.6)

- ID: `container-image-cve::Dockerfile::1::cve-2025-61726@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: net/url: Incorrect parsing of IPv6 host literals in net/url (fixed in 1.25.8, 1.26.1)

- ID: `container-image-cve::Dockerfile::1::cve-2026-25679@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: crypto/x509: golang: golang crypto/x509: Denial of Service via excessive processing of DNS SAN entries (fixed in 1.25.11, 1.26.4)

- ID: `container-image-cve::Dockerfile::1::cve-2026-27145@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: crypto/x509: crypto/tls: golang: Go: Denial of Service vulnerability in certificate chain building (fixed in 1.25.9, 1.26.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-32280@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: crypto/x509: golang: Go crypto/x509: Denial of Service via inefficient certificate chain validation (fixed in 1.25.9, 1.26.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-32281@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: crypto/tls: golang: Go crypto/tls: Denial of Service via multiple TLS 1.3 key update messages (fixed in 1.25.9, 1.26.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-32283@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: net: golang: Go net package: Denial of Service via long CNAME response in LookupCNAME (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-33811@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: net/http/internal/http2: golang: golang.org/x/net: Go HTTP/2: Denial of Service via malformed SETTINGS_MAX_FRAME_SIZE frame (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-33814@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: encoding/asn1: golang: Go encoding/asn1: Denial of Service via excessive recursion in Unmarshal (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-33818@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: net/mail: golang: Go net/mail: Denial of Service via crafted email inputs (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39820@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39821@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: golang: Go os.Root: Symlink following vulnerability allows directory traversal (fixed in 1.25.12, 1.26.5, 1.27.0-rc.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39822@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: net: golang: Go net package: Denial of Service via NUL byte in Dial and LookupPort on Windows (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39836@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: net/mail: golang: net/mail: Denial of Service via pathological email address parsing (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-42499@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: mime: golang: Golang MIME: Denial of Service via maliciously-crafted MIME header (fixed in 1.25.11, 1.26.4)

- ID: `container-image-cve::Dockerfile::1::cve-2026-42504@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: net/http: golang: Go net/http: Unencrypted HTTP/2 connections vulnerable to Denial of Service (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56853@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: html/template: golang: Go html/template: Cross-Site Scripting via pathological input (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56858@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: encoding/xml: golang: Go: Denial of Service via XML decoding recursion depth issue (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56859@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: net/url: golang: golang net/url: Denial of Service from quadratic complexity in path resolution (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56860@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.24.11: crypto/tls: golang: Golang crypto/tls: Denial of Service via indefinite KeyUpdate messages (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56862@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: crypto/tls: crypto/tls: Incorrect certificate validation during TLS session resumption (fixed in 1.24.13, 1.25.7, 1.26.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2025-68121@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: golang: net/url: Memory exhaustion in query parameter parsing in net/url (fixed in 1.24.12, 1.25.6)

- ID: `container-image-cve::Dockerfile::1::cve-2025-61726@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: crypto/x509: golang: Denial of Service due to excessive resource consumption via crafted certificate (fixed in 1.24.11, 1.25.5)

- ID: `container-image-cve::Dockerfile::1::cve-2025-61729@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: net/url: Incorrect parsing of IPv6 host literals in net/url (fixed in 1.25.8, 1.26.1)

- ID: `container-image-cve::Dockerfile::1::cve-2026-25679@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: crypto/x509: golang: golang crypto/x509: Denial of Service via excessive processing of DNS SAN entries (fixed in 1.25.11, 1.26.4)

- ID: `container-image-cve::Dockerfile::1::cve-2026-27145@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: crypto/x509: crypto/tls: golang: Go: Denial of Service vulnerability in certificate chain building (fixed in 1.25.9, 1.26.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-32280@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: crypto/x509: golang: Go crypto/x509: Denial of Service via inefficient certificate chain validation (fixed in 1.25.9, 1.26.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-32281@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: crypto/tls: golang: Go crypto/tls: Denial of Service via multiple TLS 1.3 key update messages (fixed in 1.25.9, 1.26.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-32283@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: net: golang: Go net package: Denial of Service via long CNAME response in LookupCNAME (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-33811@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: net/http/internal/http2: golang: golang.org/x/net: Go HTTP/2: Denial of Service via malformed SETTINGS_MAX_FRAME_SIZE frame (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-33814@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: encoding/asn1: golang: Go encoding/asn1: Denial of Service via excessive recursion in Unmarshal (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-33818@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: net/mail: golang: Go net/mail: Denial of Service via crafted email inputs (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39820@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39821@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: golang: Go os.Root: Symlink following vulnerability allows directory traversal (fixed in 1.25.12, 1.26.5, 1.27.0-rc.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39822@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: net: golang: Go net package: Denial of Service via NUL byte in Dial and LookupPort on Windows (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39836@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: net/mail: golang: net/mail: Denial of Service via pathological email address parsing (fixed in 1.25.10, 1.26.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-42499@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: mime: golang: Golang MIME: Denial of Service via maliciously-crafted MIME header (fixed in 1.25.11, 1.26.4)

- ID: `container-image-cve::Dockerfile::1::cve-2026-42504@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: net/http: golang: Go net/http: Unencrypted HTTP/2 connections vulnerable to Denial of Service (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56853@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: html/template: golang: Go html/template: Cross-Site Scripting via pathological input (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56858@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: encoding/xml: golang: Go: Denial of Service via XML decoding recursion depth issue (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56859@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: net/url: golang: golang net/url: Denial of Service from quadratic complexity in path resolution (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56860@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.23.7: crypto/tls: golang: Golang crypto/tls: Denial of Service via indefinite KeyUpdate messages (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56862@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/mod@v0.38.0: A malicious GOSUMDB was capable of serving arbitrary module content no ... (fixed in 0.40.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56864@golang.org/x/mod`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - golang.org/x/mod@v0.38.0: A malicious GOPROXY was previously capable of forging up to two sumdb  ... (fixed in 0.40.0)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56865@golang.org/x/mod`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.3: crypto/x509: golang: golang crypto/x509: Denial of Service via excessive processing of DNS SAN entries (fixed in 1.25.11, 1.26.4)

- ID: `container-image-cve::Dockerfile::1::cve-2026-27145@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.3: encoding/asn1: golang: Go encoding/asn1: Denial of Service via excessive recursion in Unmarshal (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-33818@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.3: golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39821@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.3: golang: Go os.Root: Symlink following vulnerability allows directory traversal (fixed in 1.25.12, 1.26.5, 1.27.0-rc.2)

- ID: `container-image-cve::Dockerfile::1::cve-2026-39822@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.3: mime: golang: Golang MIME: Denial of Service via maliciously-crafted MIME header (fixed in 1.25.11, 1.26.4)

- ID: `container-image-cve::Dockerfile::1::cve-2026-42504@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.3: golang.org/x/net/dns/dnsmessage: golang.org/x/net/dns/dnsmessage: Denial of Service via invalid DNS record parsing (fixed in 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-46600@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.3: net/http: golang: Go net/http: Unencrypted HTTP/2 connections vulnerable to Denial of Service (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56853@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.3: html/template: golang: Go html/template: Cross-Site Scripting via pathological input (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56858@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.3: encoding/xml: golang: Go: Denial of Service via XML decoding recursion depth issue (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56859@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.3: net/url: golang: golang net/url: Denial of Service from quadratic complexity in path resolution (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56860@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [ERROR] container-image-cve - stdlib@v1.26.3: crypto/tls: golang: Golang crypto/tls: Denial of Service via indefinite KeyUpdate messages (fixed in 1.25.13, 1.26.6, 1.27.0-rc.3)

- ID: `container-image-cve::Dockerfile::1::cve-2026-56862@stdlib`
- Location: Dockerfile:1
- Score: 8
- Status: overridden

## [WARNING] image-provenance - Base image "node:24-bookworm-slim" has no verifiable Sigstore/cosign signature — supply-chain provenance can't be confirmed.

- ID: `image-provenance::Dockerfile::11`
- Location: Dockerfile:11
- Score: 2

## [WARNING] semantic-sast - GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

- ID: `semantic-sast::.github/workflows/deploy-docs.yml::24`
- Location: .github/workflows/deploy-docs.yml:24
- Score: 4

## [WARNING] semantic-sast - GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

- ID: `semantic-sast::.github/workflows/deploy-docs.yml::25`
- Location: .github/workflows/deploy-docs.yml:25
- Score: 4

## [WARNING] semantic-sast - GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

- ID: `semantic-sast::.github/workflows/deploy-docs.yml::36`
- Location: .github/workflows/deploy-docs.yml:36
- Score: 4

## [WARNING] semantic-sast - GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

- ID: `semantic-sast::.github/workflows/deploy-docs.yml::37`
- Location: .github/workflows/deploy-docs.yml:37
- Score: 4

## [WARNING] semantic-sast - GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

- ID: `semantic-sast::.github/workflows/deploy-docs.yml::49`
- Location: .github/workflows/deploy-docs.yml:49
- Score: 4

## [WARNING] semantic-sast - Possible writing outside of the destination, make sure that the target path is nested in the intended destination

- ID: `semantic-sast::guidelines-api.js::74`
- Location: guidelines-api.js:74
- Score: 4

## [WARNING] semantic-sast - Possible writing outside of the destination, make sure that the target path is nested in the intended destination

- ID: `semantic-sast::routes/history.js::84`
- Location: routes/history.js:84
- Score: 4

## [WARNING] semantic-sast - Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'resp.render()' to render safely escaped HTML.

- ID: `semantic-sast::routes/history.js::124`
- Location: routes/history.js:124
- Score: 4

## [ERROR] pii-dataflow - Unsanitized dynamic input in OS command

- ID: `pii-dataflow::lib/tool-runner.js::184`
- Location: lib/tool-runner.js:184
- Score: 7
- Status: overridden

## [ERROR] pii-dataflow - Unsanitized dynamic input in OS command

- ID: `pii-dataflow::lib/tool-runner.js::188`
- Location: lib/tool-runner.js:188
- Score: 7
- Status: overridden

## [ERROR] pii-dataflow - Unsanitized dynamic input in OS command

- ID: `pii-dataflow::lib/tool-runner.js::192`
- Location: lib/tool-runner.js:192
- Score: 7
- Status: overridden

## [ERROR] pii-dataflow - Unsanitized dynamic input in OS command

- ID: `pii-dataflow::lib/tool-runner.js::196`
- Location: lib/tool-runner.js:196
- Score: 7
- Status: overridden

## [ERROR] pii-dataflow - Unsanitized dynamic input in OS command

- ID: `pii-dataflow::lib/tool-runner.js::208`
- Location: lib/tool-runner.js:208
- Score: 7
- Status: overridden

## [ERROR] pii-dataflow - Unsanitized user input in HTTP response (XSS)

- ID: `pii-dataflow::routes/history.js::124`
- Location: routes/history.js:124
- Score: 7
- Status: overridden

## [ERROR] pii-dataflow - Unsanitized user input in file path

- ID: `pii-dataflow::guidelines-api.js::74`
- Location: guidelines-api.js:74
- Score: 7
- Status: overridden

## [ERROR] pii-dataflow - Unsanitized user input in file path

- ID: `pii-dataflow::routes/history.js::84`
- Location: routes/history.js:84
- Score: 7
- Status: overridden

## [ERROR] pii-dataflow - Unsanitized user input in file path

- ID: `pii-dataflow::routes/pipeline-interactive.js::610`
- Location: routes/pipeline-interactive.js:610
- Score: 7
- Status: overridden

## [ERROR] pii-dataflow - Unsanitized user input in format string

- ID: `pii-dataflow::routes/pipeline-interactive.js::624`
- Location: routes/pipeline-interactive.js:624
- Score: 7
- Status: overridden

## [ERROR] pii-dataflow - Usage of manual HTML sanitization (XSS)

- ID: `pii-dataflow::auth.js::407`
- Location: auth.js:407
- Score: 7
- Status: overridden

## [ERROR] pii-dataflow - Usage of manual HTML sanitization (XSS)

- ID: `pii-dataflow::lib/notifications.js::30`
- Location: lib/notifications.js:30
- Score: 7
- Status: overridden

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/ai-governance.js::75`
- Location: checks/ai-governance.js:75
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/api-schema.js::44`
- Location: checks/api-schema.js:44
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/api-schema.js::79`
- Location: checks/api-schema.js:79
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/code-duplication.js::73`
- Location: checks/code-duplication.js:73
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::89`
- Location: checks/codeql-cross-file.js:89
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::180`
- Location: checks/codeql-cross-file.js:180
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::208`
- Location: checks/codeql-cross-file.js:208
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::237`
- Location: checks/codeql-cross-file.js:237
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::267`
- Location: checks/codeql-cross-file.js:267
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::268`
- Location: checks/codeql-cross-file.js:268
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::269`
- Location: checks/codeql-cross-file.js:269
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::296`
- Location: checks/codeql-cross-file.js:296
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::411`
- Location: checks/codeql-cross-file.js:411
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::415`
- Location: checks/codeql-cross-file.js:415
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::450`
- Location: checks/codeql-cross-file.js:450
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/feature-posture.js::103`
- Location: checks/feature-posture.js:103
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/feature-posture.js::105`
- Location: checks/feature-posture.js:105
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/feature-posture.js::166`
- Location: checks/feature-posture.js:166
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/file-encapsulation.js::41`
- Location: checks/file-encapsulation.js:41
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/iac-security.js::78`
- Location: checks/iac-security.js:78
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/iac-security.js::127`
- Location: checks/iac-security.js:127
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/iac-security.js::139`
- Location: checks/iac-security.js:139
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/iac-security.js::180`
- Location: checks/iac-security.js:180
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/iac-security.js::207`
- Location: checks/iac-security.js:207
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/image-provenance.js::48`
- Location: checks/image-provenance.js:48
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/image-provenance.js::125`
- Location: checks/image-provenance.js:125
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/llm-deep-scan.js::342`
- Location: checks/llm-deep-scan.js:342
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/malicious-dependencies.js::83`
- Location: checks/malicious-dependencies.js:83
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/pii-dataflow.js::183`
- Location: checks/pii-dataflow.js:183
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/provenance.js::30`
- Location: checks/provenance.js:30
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/sbom.js::42`
- Location: checks/sbom.js:42
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/secrets.js::140`
- Location: checks/secrets.js:140
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/secrets.js::189`
- Location: checks/secrets.js:189
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/secrets.js::192`
- Location: checks/secrets.js:192
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/semantic-sast.js::72`
- Location: checks/semantic-sast.js:72
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::lib/fs-utils.js::101`
- Location: lib/fs-utils.js:101
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::lib/fs-utils.js::154`
- Location: lib/fs-utils.js:154
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::lib/fs-utils.js::155`
- Location: lib/fs-utils.js:155
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::lib/shipping.js::222`
- Location: lib/shipping.js:222
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::lib/shipping.js::232`
- Location: lib/shipping.js:232
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/dependencies.js::26`
- Location: routes/dependencies.js:26
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/dependencies.js::44`
- Location: routes/dependencies.js:44
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/history.js::83`
- Location: routes/history.js:83
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/history.js::91`
- Location: routes/history.js:91
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/pipeline-interactive.js::260`
- Location: routes/pipeline-interactive.js:260
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/pipeline-interactive.js::616`
- Location: routes/pipeline-interactive.js:616
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/pipeline-interactive.js::638`
- Location: routes/pipeline-interactive.js:638
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/pipeline-interactive.js::639`
- Location: routes/pipeline-interactive.js:639
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/pipeline-interactive.js::640`
- Location: routes/pipeline-interactive.js:640
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/review-gate.js::114`
- Location: routes/review-gate.js:114
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/review-gate.js::144`
- Location: routes/review-gate.js:144
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/studio.js::165`
- Location: routes/studio.js:165
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/studio.js::179`
- Location: routes/studio.js:179
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/studio.js::202`
- Location: routes/studio.js:202
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/studio.js::203`
- Location: routes/studio.js:203
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/studio.js::206`
- Location: routes/studio.js:206
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/studio.js::207`
- Location: routes/studio.js:207
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::vscode-extension/src/reviewFile.ts::66`
- Location: vscode-extension/src/reviewFile.ts:66
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::vscode-extension/src/reviewFile.ts::127`
- Location: vscode-extension/src/reviewFile.ts:127
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::vscode-extension/src/reviewFile.ts::128`
- Location: vscode-extension/src/reviewFile.ts:128
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::vscode-extension/src/reviewFile.ts::172`
- Location: vscode-extension/src/reviewFile.ts:172
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::vscode-extension/src/reviewFile.ts::173`
- Location: vscode-extension/src/reviewFile.ts:173
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/api-schema.js::79`
- Location: checks/api-schema.js:79
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/code-duplication.js::65`
- Location: checks/code-duplication.js:65
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/code-duplication.js::68`
- Location: checks/code-duplication.js:68
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/code-duplication.js::73`
- Location: checks/code-duplication.js:73
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::142`
- Location: checks/codeql-cross-file.js:142
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::191`
- Location: checks/codeql-cross-file.js:191
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::237`
- Location: checks/codeql-cross-file.js:237
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::238`
- Location: checks/codeql-cross-file.js:238
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::239`
- Location: checks/codeql-cross-file.js:239
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::343`
- Location: checks/codeql-cross-file.js:343
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/codeql-cross-file.js::386`
- Location: checks/codeql-cross-file.js:386
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/feature-posture.js::166`
- Location: checks/feature-posture.js:166
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/iac-security.js::75`
- Location: checks/iac-security.js:75
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/iac-security.js::78`
- Location: checks/iac-security.js:78
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/iac-security.js::139`
- Location: checks/iac-security.js:139
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/iac-security.js::180`
- Location: checks/iac-security.js:180
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/image-provenance.js::125`
- Location: checks/image-provenance.js:125
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/pii-dataflow.js::39`
- Location: checks/pii-dataflow.js:39
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/pii-dataflow.js::180`
- Location: checks/pii-dataflow.js:180
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/pii-dataflow.js::183`
- Location: checks/pii-dataflow.js:183
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/secrets.js::84`
- Location: checks/secrets.js:84
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/secrets.js::134`
- Location: checks/secrets.js:134
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/secrets.js::140`
- Location: checks/secrets.js:140
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::checks/semantic-sast.js::72`
- Location: checks/semantic-sast.js:72
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::lib/fs-utils.js::152`
- Location: lib/fs-utils.js:152
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::lib/fs-utils.js::204`
- Location: lib/fs-utils.js:204
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::lib/shipping.js::51`
- Location: lib/shipping.js:51
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::lib/tool-runner.js::59`
- Location: lib/tool-runner.js:59
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::routes/studio.js::65`
- Location: routes/studio.js:65
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in file path

- ID: `pii-dataflow::vscode-extension/src/panels/findingsTree.ts::70`
- Location: vscode-extension/src/panels/findingsTree.ts:70
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::config.js::343`
- Location: config.js:343
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::guidelines-api.js::89`
- Location: guidelines-api.js:89
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::guidelines-api.js::99`
- Location: guidelines-api.js:99
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::lib/llm-client.js::70`
- Location: lib/llm-client.js:70
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::lib/llm-client.js::76`
- Location: lib/llm-client.js:76
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::lib/scheduled-rechecks.js::108`
- Location: lib/scheduled-rechecks.js:108
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::mcp-server.js::44`
- Location: mcp-server.js:44
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::mcp-server.js::62`
- Location: mcp-server.js:62
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::mcp-server.js::89`
- Location: mcp-server.js:89
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::mcp-server.js::112`
- Location: mcp-server.js:112
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::mcp-server.js::169`
- Location: mcp-server.js:169
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::mcp-server.js::187`
- Location: mcp-server.js:187
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::mcp-server.js::223`
- Location: mcp-server.js:223
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::mcp-server.js::275`
- Location: mcp-server.js:275
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::mcp-server.js::286`
- Location: mcp-server.js:286
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::mcp-server.js::292`
- Location: mcp-server.js:292
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::mcp-server.js::301`
- Location: mcp-server.js:301
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::routes/pipeline-interactive.js::585`
- Location: routes/pipeline-interactive.js:585
- Score: 4

## [WARNING] pii-dataflow - Leakage of information in logger message

- ID: `pii-dataflow::routes/pipeline-interactive.js::624`
- Location: routes/pipeline-interactive.js:624
- Score: 4
- Status: overridden

## [WARNING] pii-dataflow - Missing Helmet configuration on HTTP headers

- ID: `pii-dataflow::guidelines-api.js::15`
- Location: guidelines-api.js:15
- Score: 4

## [WARNING] pii-dataflow - Missing Helmet configuration on HTTP headers

- ID: `pii-dataflow::mcp-server.js::253`
- Location: mcp-server.js:253
- Score: 4

## [WARNING] pii-dataflow - Unsanitized user input in redirect

- ID: `pii-dataflow::routes/history.js::118`
- Location: routes/history.js:118
- Score: 4

## [WARNING] pii-dataflow - Missing server configuration to reduce server fingerprinting

- ID: `pii-dataflow::guidelines-api.js::15`
- Location: guidelines-api.js:15
- Score: 4

## [WARNING] pii-dataflow - Missing server configuration to reduce server fingerprinting

- ID: `pii-dataflow::mcp-server.js::253`
- Location: mcp-server.js:253
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in regular expression

- ID: `pii-dataflow::checks/secrets.js::63`
- Location: checks/secrets.js:63
- Score: 4

## [WARNING] pii-dataflow - Unsanitized dynamic input in regular expression

- ID: `pii-dataflow::checks/secrets.js::71`
- Location: checks/secrets.js:71
- Score: 4

## [WARNING] pii-dataflow - Observable Timing Discrepancy

- ID: `pii-dataflow::checks/ai-governance.js::80`
- Location: checks/ai-governance.js:80
- Score: 4

## [WARNING] pii-dataflow - Observable Timing Discrepancy

- ID: `pii-dataflow::checks/llm-deep-scan.js::358`
- Location: checks/llm-deep-scan.js:358
- Score: 4

## [WARNING] pii-dataflow - Observable Timing Discrepancy

- ID: `pii-dataflow::checks/llm-deep-scan.js::504`
- Location: checks/llm-deep-scan.js:504
- Score: 4

## [WARNING] pii-dataflow - Observable Timing Discrepancy

- ID: `pii-dataflow::checks/secrets.js::197`
- Location: checks/secrets.js:197
- Score: 4

## [WARNING] code-duplication - 298-line duplicate block, also found in hooks/pre-push:1-298.

- ID: `code-duplication::.git/hooks/pre-push::1`
- Location: .git/hooks/pre-push:1
- Score: 1

## [WARNING] code-duplication - 298-line duplicate block, also found in vscode-extension/resources/pre-push:1-298.

- ID: `code-duplication::.git/hooks/pre-push::1`
- Location: .git/hooks/pre-push:1
- Score: 1

## [WARNING] code-duplication - 115-line duplicate block, also found in .ignite/acknowledgments.md:markdown:1104-1218.

- ID: `code-duplication::.ignite/acknowledgments.md:markdown::994`
- Location: .ignite/acknowledgments.md:markdown:994
- Score: 1

## [WARNING] code-duplication - 16-line duplicate block, also found in .ignite/acknowledgments.md:markdown:1871-1886.

- ID: `code-duplication::.ignite/acknowledgments.md:markdown::1861`
- Location: .ignite/acknowledgments.md:markdown:1861
- Score: 1

## [WARNING] code-duplication - 160-line duplicate block, also found in .ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1617-1776.

- ID: `code-duplication::.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1449`
- Location: .ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1449
- Score: 1

## [WARNING] code-duplication - 22-line duplicate block, also found in .ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:2364-2385.

- ID: `code-duplication::.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1601`
- Location: .ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1601
- Score: 1

## [WARNING] code-duplication - 22-line duplicate block, also found in .ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1916-1937.

- ID: `code-duplication::.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1769`
- Location: .ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1769
- Score: 1

## [WARNING] code-duplication - 62-line duplicate block, also found in .ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1932-1993.

- ID: `code-duplication::.ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown::1862`
- Location: .ignite/scans/2026-08-20T22-04-15Z/findings.md:markdown:1862
- Score: 1

## [WARNING] code-duplication - 20-line duplicate block, also found in public/index.html:3853-3872.

- ID: `code-duplication::public/index.html::1692`
- Location: public/index.html:1692
- Score: 1

## [WARNING] code-duplication - 24-line duplicate block, also found in public/index.html:3153-3176.

- ID: `code-duplication::public/index.html::3033`
- Location: public/index.html:3033
- Score: 1

## [WARNING] code-duplication - 46-line duplicate block, also found in routes/pipeline-validate.js:61-106.

- ID: `code-duplication::routes/pipeline-onboard.js::85`
- Location: routes/pipeline-onboard.js:85
- Score: 1

## [WARNING] code-duplication - 24-line duplicate block, also found in routes/pipeline-validate.js:116-139.

- ID: `code-duplication::routes/pipeline-onboard.js::141`
- Location: routes/pipeline-onboard.js:141
- Score: 1

## [WARNING] code-structure - server.js is 2587 lines — over the 1000-line guideline. A single file this size usually means more than one responsibility living together, making it harder to review, test in isolation, and (for SAST tools that cache per-file) harder to scan incrementally.

- ID: `code-structure::server.js::1`
- Location: server.js:1
- Score: 1

## [WARNING] codeql-sast - This replaces 'calculateTotal' with itself.

- ID: `codeql-sast::test/metrics-scan.test.js::197::js/identity-replacement`
- Location: test/metrics-scan.test.js:197
- Score: 4

## [ERROR] codeql-sast - This route handler performs a file system access, but is not rate-limited.

- ID: `codeql-sast::guidelines-api.js::69::js/missing-rate-limiting`
- Location: guidelines-api.js:69
- Score: 8
- Status: overridden

## [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.

- ID: `codeql-sast::public/index.html::3112::js/incomplete-html-attribute-sanitization`
- Location: public/index.html:3112
- Score: 4

## [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.

- ID: `codeql-sast::public/index.html::4324::js/incomplete-html-attribute-sanitization`
- Location: public/index.html:4324
- Score: 4

## [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.

- ID: `codeql-sast::public/index.html::4412::js/incomplete-html-attribute-sanitization`
- Location: public/index.html:4412
- Score: 4

## [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.

- ID: `codeql-sast::public/index.html::4412::js/incomplete-html-attribute-sanitization`
- Location: public/index.html:4412
- Score: 4

## [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.

- ID: `codeql-sast::public/index.html::4413::js/incomplete-html-attribute-sanitization`
- Location: public/index.html:4413
- Score: 4

## [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.

- ID: `codeql-sast::public/index.html::4413::js/incomplete-html-attribute-sanitization`
- Location: public/index.html:4413
- Score: 4

## [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.

- ID: `codeql-sast::public/index.html::4414::js/incomplete-html-attribute-sanitization`
- Location: public/index.html:4414
- Score: 4

## [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.

- ID: `codeql-sast::public/index.html::4414::js/incomplete-html-attribute-sanitization`
- Location: public/index.html:4414
- Score: 4

## [WARNING] codeql-sast - Cross-site scripting vulnerability as the output of this final HTML sanitizer step may contain double quotes when it reaches this attribute definition.

- ID: `codeql-sast::public/index.html::4639::js/incomplete-html-attribute-sanitization`
- Location: public/index.html:4639
- Score: 4

## [ERROR] codeql-sast - This path depends on a user-provided value.

- ID: `codeql-sast::guidelines/checks.js::271::js/path-injection`
- Location: guidelines/checks.js:271
- Score: 8
- Status: overridden

## [ERROR] codeql-sast - This path depends on a user-provided value.

- ID: `codeql-sast::guidelines/checks.js::315::js/path-injection`
- Location: guidelines/checks.js:315
- Score: 8
- Status: overridden

## [ERROR] codeql-sast - This path depends on a user-provided value.

- ID: `codeql-sast::guidelines/checks.js::318::js/path-injection`
- Location: guidelines/checks.js:318
- Score: 8
- Status: overridden

## [ERROR] codeql-sast - This path depends on a user-provided value.

- ID: `codeql-sast::guidelines-api.js::77::js/path-injection`
- Location: guidelines-api.js:77
- Score: 8
- Status: overridden

## [ERROR] codeql-sast - This path depends on a user-provided value.

- ID: `codeql-sast::routes/pipeline-interactive.js::638::js/path-injection`
- Location: routes/pipeline-interactive.js:638
- Score: 8
- Status: overridden

## [ERROR] codeql-sast - This regular expression that depends on library input may run slow on strings with many repetitions of ')'.

- ID: `codeql-sast::server.js::677::js/polynomial-redos`
- Location: server.js:677
- Score: 8
- Status: overridden

## [WARNING] codeql-sast - Outbound network request depends on file data.

- ID: `codeql-sast::checks/llm-deep-scan.js::109::js/file-access-to-http`
- Location: checks/llm-deep-scan.js:109
- Score: 4

## [ERROR] codeql-sast - The file may have changed since it was checked.

- ID: `codeql-sast::checks/feature-posture.js::105::js/file-system-race`
- Location: checks/feature-posture.js:105
- Score: 8
- Status: overridden

## [ERROR] codeql-sast - The file may have changed since it was checked.

- ID: `codeql-sast::checks/secrets.js::192::js/file-system-race`
- Location: checks/secrets.js:192
- Score: 8
- Status: overridden

## [ERROR] codeql-sast - The file may have changed since it was checked.

- ID: `codeql-sast::guidelines/checks.js::318::js/file-system-race`
- Location: guidelines/checks.js:318
- Score: 8
- Status: overridden

## [ERROR] codeql-sast - A property name to write to depends on a user-provided value.
A property name to write to depends on a user-provided value.

- ID: `codeql-sast::auth.js::37::js/remote-property-injection`
- Location: auth.js:37
- Score: 8
- Status: overridden

## [WARNING] codeql-sast - Write to file system depends on Untrusted data.

- ID: `codeql-sast::lib/llm-client.js::19::js/http-to-file-access`
- Location: lib/llm-client.js:19
- Score: 4

## [WARNING] codeql-sast - Write to file system depends on Untrusted data.

- ID: `codeql-sast::routes/studio.js::203::js/http-to-file-access`
- Location: routes/studio.js:203
- Score: 4

## [WARNING] codeql-sast - Write to file system depends on Untrusted data.

- ID: `codeql-sast::routes/studio.js::207::js/http-to-file-access`
- Location: routes/studio.js:207
- Score: 4

## [WARNING] codeql-sast - Write to file system depends on Untrusted data.

- ID: `codeql-sast::server.js::818::js/http-to-file-access`
- Location: server.js:818
- Score: 4

## [WARNING] codeql-sast - Write to file system depends on Untrusted data.

- ID: `codeql-sast::server.js::829::js/http-to-file-access`
- Location: server.js:829
- Score: 4
