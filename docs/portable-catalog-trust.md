# Portable catalog trust in Rust

`catalog-verify` and the optional external-baseline publication gate use portable
Rust verification with an explicit policy. The standalone
[`wintrust` crate](../README.md) owns the implementation and
exposes snake_case functions with Windows-name aliases. No Windows DLL is required. CMS/CTL
parsing alone does not establish trust: the verifier binds exact signed content,
verifies every primary signature, validates pinned certificate chains and
publisher authorization, authenticates timestamps, checks configured revocation,
and matches the member through its format-specific SIP hash.

## Commands

```sh
windows-uup catalog-verify --catalog update.cat --member component.mum \
  --member-kind flat-xml --trust-policy trust.json
windows-uup baseline-reconstruct --root /images/extracted \
  --manifest baseline.json --request reconstruction.json \
  --patch forward.patch --output reconstructed.mum \
  --catalog update.cat --member-kind flat-xml --trust-policy trust.json
```

Member kinds are `flat-xml`, `pe`, `cab`, and explicitly selected `flat-raw`.
Known executable/archive formats cannot silently use flat hashing. PE and CAB
hashing excludes their signature fields according to the supported SIP layouts.
See [SIP implementation and Windows oracle evidence](https://github.com/CaddyGlow/windows-uup/blob/main/docs/catalog-sip.md).

On Windows, `--native-reference` explicitly selects CryptCATAdmin/WinVerifyTrust
instead. Native `--hash-algorithm` and `--revocation` flags require that selection.
The portable backend does not inherit machine roots or host Windows policy.

## Policy

```json
{
  "schema_version": 1,
  "roots": [{"path": "roots/microsoft-root-2010.der", "sha256": "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e"}],
  "intermediates": [],
  "crls": [],
  "ocsp_responses": [],
  "publisher": "microsoft_windows",
  "revocation": "online",
  "timestamp": "use_verified",
  "allow_sha1": false,
  "revocation_max_age_seconds": 604800
}
```

Each artifact is a regular DER file pinned by its complete SHA-256 digest. Paths
resolve relative to the policy file. Obtain roots through an independently
trusted channel; the pin authenticates the supplied bytes, not their origin.
The example fingerprint identifies Microsoft Root Certificate Authority 2010.
A different issuer chain requires its appropriate explicitly configured root.

`publisher` is `explicit_roots` or `microsoft_windows`. The latter additionally
requires an allowlisted Microsoft root and the Windows component signing EKU;
subject display names never authorize a publisher. The current root allowlist
covers Microsoft Root CA 2010, Root CA 2011 and RSA Root CA 2017.

`revocation` is `require_fresh`, `online`, or `disabled`. The first requires
pinned signed CRL/OCSP evidence for every non-root signer and TSA certificate.
Online mode additionally retrieves status from signed certificate distribution
points; missing, stale or invalid evidence cannot establish good status.
Authenticated revoked status dominates good evidence. Disabling revocation is
reported explicitly and must be a deliberate policy choice.

CRLs follow RFC 5280 6.3 as a set per certificate. Direct, indirect (authorized
by the certificate's `cRLIssuer`, with `certificateIssuer` entries), scoped
(`issuingDistributionPoint` name, user/CA-only and `onlySomeReasons` partitions)
and delta CRLs (`deltaCRLIndicator`, newest delta wins, `removeFromCRL` releases
only a `certificateHold`) are combined. Good status requires fresh in-scope
evidence covering every reason; any authenticated listing is revoked. A CRL
signer other than the certificate issuer must be directly issued by it, valid
and `cRLSign`-capable; pinned intermediates serve as signer candidates. Longer
CRL-signer paths, relative-to-full distribution point name conversion and
attribute-certificate CRLs are treated as out of scope and never establish good
status. Online acquisition also follows `freshestCRL` and records each
artifact's URL, digest, size and source in the revocation report.

Certificate policies follow RFC 5280 6.1 through `chain::PathOptions`: policy
tree, mappings, `policyConstraints`, `inhibitAnyPolicy`, initial policy inputs
and explicit partial-chain selection. The report retains valid policies,
per-certificate diagnostics and rejected alternative paths.

`timestamp` is `use_verified`, `require`, or `ignore`. RFC3161 and legacy
countersignatures must authenticate the actual signer signature and TSA chain.
Advertised invalid timestamps reject verification. Unauthenticated signing time
cannot extend certificate validity. `verification_time`, if present, is an
explicit Unix time for reproducible as-of evaluation; otherwise current time is
used. SHA-1 signatures require explicit `allow_sha1: true`.

## Limits and behavior

RustCrypto RSA PKCS#1 v1.5/PSS and P-256/P-384 ECDSA support SHA-256/384/512.
Chain checks include certificate validity, CA/key usage, path length, EKU and
issuer identification. Unsupported constraints, ambiguous issuers, algorithms
and SIP layouts reject verification. This conservative policy does not claim
complete compatibility with every Windows trust provider or enterprise policy.

Default inputs are bounded: policy 1 MiB, each artifact 16 MiB, total artifacts
64 MiB, member 64 MiB, with bounded DER nesting and certificate counts. Online
retrieval allows at most 16 requests, 16 MiB per response and 32 MiB total per
chain, a 30-second chain timeout, and a 60-second overall verification budget.
Redirects and credential URLs are rejected. HTTP transport is permitted because
status acceptance requires the issuer's cryptographic signature.

Reconstruction verifies a closed temporary file, rechecks bytes after trust
verification, and publishes without overwriting an existing output. Failures
leave the requested final output absent. Reports record the policy, fingerprints,
signer/TSA chains, authenticated time, revocation evidence and matching CTL rows.

## Evidence

The genuine SSU catalog/MUM verifies under Microsoft authorization as of 2026
using its authenticated 2024 timestamp. This archived-fixture test explicitly
disables revocation. The independent test-only catalog in
[`revocation/policy.json`](../tests/fixtures/policy.json)
passes required timestamps and fresh signer/TSA revocation entirely in Rust.
Its synthetic root is for tests only; private fixture keys are not retained.

```sh
cargo test -p windows-uup --locked --test catalog_portable \
  --test portable_crypto --test portable_status --test catalog_sip \
  --test baseline --test baseline_cli
```

Tests cover tampered signed content and member bytes, incorrect roots, ambiguous
issuers, unsupported constraints, signature parameters, timestamp binding,
missing/stale/revoked status, network bounds and publication rejection. This does
not establish automatic authenticated RTM file ownership or real checkpoint
servicing correctness; see [external baseline selection](https://github.com/CaddyGlow/windows-uup/blob/main/docs/baseline-selection.md).
