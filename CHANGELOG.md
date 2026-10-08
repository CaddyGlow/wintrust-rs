# Changelog

## 0.1.2 - 2026-10-08

### Added

- RFC 5280 name-constraint processing in the shared path validator for DNS, mailbox, URI DNS-host, IP CIDR and ASCII directory-name forms, including alternative paths, issuer intersections and self-issued rollover. Unsupported international DN matching, non-DNS URI hosts, other constraint forms and distance semantics fail closed.
- RFC 5280 6.1 certificate policy processing in the new `portable::policy` module: policy tree, policy mappings, `policyConstraints` (requireExplicitPolicy and inhibitPolicyMapping), `inhibitAnyPolicy`, anyPolicy expansion (including self-issued rollover) and user-initial-policy-set intersection. Inputs are supplied through `chain::PathOptions` and `chain::validate_with_options`; defaults require no policy yet honor every constraint the certificates carry. Critical `certificatePolicies` are accepted when they carry no qualifiers (previously rejected); policy mapping, constraint and inhibit extensions are no longer rejected. Trust-anchor `policyConstraints` and `inhibitAnyPolicy` are applied as anchor constraints.
- Explicitly selected partial chains: `PathOptions::partial_chain` lets an exactly pinned, non-self-issued certificate end a path. The end-entity certificate never qualifies.
- `ChainReport` now retains valid policies, per-certificate diagnostics (role, self-issued, enforced extensions) and a bounded list of rejected candidate paths with reasons.

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
