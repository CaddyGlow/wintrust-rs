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
signer other than the certificate issuer must validate to the same trust anchor
by full path validation (any depth; no extended key usage is required) and carry
`cRLSign`; pinned intermediates serve as signer candidates. The signer's own
revocation status is not evaluated. Relative distribution point names resolve
against the CRL issuer or `cRLIssuer`. CRLs limited to attribute certificates
never apply to public-key certificates. Online acquisition also follows
`freshestCRL`. The revocation report records every artifact's origin (online or
policy-pinned file), location, digest, size and source.

Certificate policies follow RFC 5280 6.1 through `chain::PathOptions`: policy
tree, mappings, `policyConstraints`, `inhibitAnyPolicy`, initial policy inputs
and explicit partial-chain selection. The report retains valid policies,
per-certificate diagnostics and rejected alternative paths.

`timestamp` is `use_verified`, `require`, or `ignore`. RFC3161 and legacy
countersignatures must authenticate the actual signer signature and TSA chain.
Advertised invalid timestamps reject verification. Unauthenticated signing time
cannot extend certificate validity. `verification_time`, if present, is an
explicit Unix time for reproducible as-of evaluation; otherwise the current time
is captured once during verifier construction. Reusing a verifier reuses this
evaluation time. Build a new verifier for a later evaluation. SHA-1 signatures require explicit `allow_sha1: true`.

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

## Rust API migration

The unreleased Rust API uses a single immutable `portable::Verifier` in place of
`PortableVerifier` and `ValidatedVerifier`. Use `Verifier::load`,
`Verifier::from_policy`, or `Verifier::builder`. The injectable reader in
`from_policy_with_reader` and `VerifierBuilder::build_with_reader` enforces the
same validation as filesystem loading. Roots, intermediates, revocation evidence,
policy and limits are available through borrowed read-only accessors. To change
policy or the evaluation clock, construct a new verifier.

```rust,no_run
use std::path::Path;
use wintrust::{WinVerifyTrust, portable::{PortableLimits, Verifier, sip::SipKind}};

let verifier = Verifier::load(Path::new("trust.json"), PortableLimits::default())?;
let report = WinVerifyTrust(&verifier, Path::new("update.cat"), Path::new("component.mum"), SipKind::FlatXml)?;
assert_eq!(report.verification_time, verifier.evaluation_time());
# Ok::<(), anyhow::Error>(())
```

Timestamp functions take `timestamp::TimestampOptions` rather than positional
roots, time and policy arguments. The roots and evaluation time are required;
optional settings default to strict SHA-2 verification and bounded path search.
Issuer candidates assist path construction and never become anchors.

```rust,no_run
use wintrust::portable::{chain, timestamp::{self, TimestampOptions}};
# let roots: Vec<Vec<u8>> = vec![];
# let intermediates: Vec<Vec<u8>> = vec![];
# let token: Vec<u8> = vec![];
# let signature: Vec<u8> = vec![];
let options = TimestampOptions {
    issuer_candidates: &intermediates,
    path_limits: chain::PathLimits::default(),
    ..TimestampOptions::new(&roots, 1_791_117_219)
};
let stamp = timestamp::verify_rfc3161(&token, &signature, &options)?;
# let _ = stamp;
# Ok::<(), anyhow::Error>(())
```

`verify_rfc3161`, `verify_legacy`, `verify_timestamps`, and
`verify_timestamps_with_path_policy` share these inputs. The former `_with_policy`
wrappers are removed. RFC3161 validation selects a single path valid throughout
the signed accuracy interval. Caller path policy runs before selection, including
for exact-pinned Microsoft TSA compatibility. The main verifier checks TSA
publisher authorization and revocation during this selection, so rejection can
try another authenticated candidate path. Low-level timestamp verification
requires caller policy for revocation.

`SignedDataContent` and `VerifiedSignedData<'a>` borrow the exact CMS or detached
payload bytes; signer and certificate reports remain owned. Keep the input alive
while using content fields, or call `.to_vec()` to retain a payload independently.
`AuthenticatedCtl` continues to own its authenticated list bytes.

`member_hash_bytes` returns raw digest bytes. `member_hash` retains its hex-string
result for inspection and persisted reports. Policy JSON schema and trust-report
JSON fields retain their existing formats.

### Freestanding builds

The default crate uses `no_std` and `alloc`. Enable `std` to retain filesystem
constructors, Windows-name aliases and automatic clock capture. `online` and
`native-reference` imply `std`. In a freestanding environment, provide an
allocator, set `PortablePolicy::verification_time`, and call
`Verifier::from_artifact_reader(policy, limits, reader)`. The reader receives
`&ArtifactRef` and a byte limit; it returns owned bytes. The verifier enforces
pins, individual and aggregate budgets, DER validity and all trust policy checks.
`ArtifactRef::path` is an opaque `String` without `std` and a `PathBuf` with it;
its JSON representation is unchanged.

The pinned upstream Unicode string preparation code is preserved as a private
`alloc`-compatible module, with its licenses, so name-constraint normalization
remains the same in both builds.
