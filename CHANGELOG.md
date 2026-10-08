# Changelog

## 0.1.1 - 2026-10-08

### Changed

- **Breaking behavior change:** HTTP acquisition is opt-in through the `online` feature. Existing online-policy applications must explicitly enable it; unsupported online policies fail during loading.
- Require caddy-hexspell 1.1.1 so PE certificate records remain inside their declared table.
- Limit the registry archive to maintained source, documentation and synthetic test fixtures; retain Microsoft-origin interoperability fixtures in the repository only.

### Added

- Immutable validated verifier and fallible builder with read-only policy/evidence and a captured evaluation clock.
- Generic embedded/detached CMS verification, direct id-data signatures and all-signer validation.
- Generic CTL inspection and dedicated-bootstrap authentication with purpose, freshness and sequence checks.
- Indexed bounded alternative certificate path search and per-path policy callbacks.
- Timestamp path-policy callbacks, caller-supplied issuer candidates and alternative TSA paths.

Existing public verification APIs and Windows-name aliases remain available. These additions do not establish a complete RFC 5280 policy implementation or Microsoft AuthRoot/Disallowed store provider.
