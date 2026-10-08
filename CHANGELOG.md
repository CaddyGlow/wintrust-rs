# Changelog

## Unreleased

### Fixed

- Require fresh delta CRLs before releasing a certificate hold.
- Use supplied intermediate certificates in normal RFC3161 timestamp verification.
- Exclude self-issued CA rollover certificates from path-length counts during path search and constraint rechecks.

## 0.1.2 - 2026-10-08

### Added

- RFC 5280 name-constraint processing in the shared path validator for DNS, mailbox, URI DNS-host, IP CIDR and ASCII directory-name forms, including alternative paths, issuer intersections and self-issued rollover. Directory names compare under RFC 4518 string preparation (case and compatibility folding, NFKC, prohibited-character and bidirectional checks) across UTF8String, PrintableString, IA5String, BMPString and ASCII TeletexString. `minimum`/`maximum` level distances are honored for domain and directory names; other forms with distances, non-ASCII TeletexString and UniversalString fail closed. A URI naming an IP address or lacking an authority lies outside every domain subtree (never permitted by one, never excluded by one); a malformed URI authority still fails closed. Adds the `stringprep` dependency.
- RFC 5280 6.1 certificate policy processing in the new `portable::policy` module: policy tree, policy mappings, `policyConstraints` (requireExplicitPolicy and inhibitPolicyMapping), `inhibitAnyPolicy`, anyPolicy expansion (including self-issued rollover) and user-initial-policy-set intersection. Inputs are supplied through `chain::PathOptions` and `chain::validate_with_options`; defaults require no policy yet honor every constraint the certificates carry. Critical `certificatePolicies` are accepted when they carry no qualifiers (previously rejected); policy mapping, constraint and inhibit extensions are no longer rejected. Trust-anchor `policyConstraints` and `inhibitAnyPolicy` are applied as anchor constraints.
- Explicitly selected partial chains: `PathOptions::partial_chain` lets an exactly pinned, non-self-issued certificate end a path. The end-entity certificate never qualifies.
- RFC 5280 6.3 CRL evaluation as a set per certificate: indirect CRLs authorized by `cRLIssuer` with `certificateIssuer` entries, `issuingDistributionPoint` scope (distribution point name, user/CA-only, `onlySomeReasons` coverage unions) and delta CRLs (`deltaCRLIndicator`, base/delta pairing, `removeFromCRL`). Previously these fail-closed cases were rejected outright. Use `revocation::verify_chain_revocation_with_signers` to supply CRL signing certificates; `verify_chain_revocation` and `verify_crl` keep their signatures. Online acquisition follows `freshestCRL` and `PortableVerifier` passes its pinned intermediates as CRL signer candidates.
- `ArtifactProvenance` (kind, origin, location, digest, size, source) is recorded in `RevocationReport::provenance` for both online-acquired artifacts and policy-pinned cache files (`revocation::pinned_provenance`); `AcquiredRevocation` and `RevocationReport` gain a `provenance` field.
- CRL signing certificates other than the certificate issuer are validated by full path validation to the trust anchor (any depth, key rollover under the issuer name) via `PathOptions::crl_signer`, replacing the one-level restriction; relative distribution point names are resolved against the CRL issuer or `cRLIssuer`.
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
