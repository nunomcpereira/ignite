# Ignite scan findings — 2026-08-21T00:03:30.532Z

## [ERROR] secret - Hardcoded api_key

- ID: `secret::README.md::779`
- Location: README.md:779
- Score: 10

## [ERROR] pii-dataflow - Usage of manual HTML sanitization (XSS)

- ID: `pii-dataflow::auth.js::437`
- Location: auth.js:437
- Score: 7

## [ERROR] codeql-sast - Password from an access to API_KEY_PREFIX is hashed insecurely.
Password from a call to generateApiKey is hashed insecurely.
Password from a call to generateApiKey is hashed insecurely.
Password from a call to generateApiKey is hashed insecurely.

- ID: `codeql-sast::auth.js::29::js/insufficient-password-hash`
- Location: auth.js:29
- Score: 8

## [ERROR] codeql-sast - A property name to write to depends on a user-provided value.
A property name to write to depends on a user-provided value.

- ID: `codeql-sast::auth.js::52::js/remote-property-injection`
- Location: auth.js:52
- Score: 8
