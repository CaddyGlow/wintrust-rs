# wintrust

Portable Rust catalog trust.

```toml
[dependencies]
wintrust = "0.3.0"
```

 The implementation includes CMS/CTL,
RustCrypto signatures, pinned certificate chains, publisher authorization,
timestamps, signed CRL/OCSP status, bounded online acquisition and PE/CAB/XML SIP
hashes. `windows-uup` uses this crate and keeps compatibility module re-exports.

With `std` enabled, functions use snake_case. Windows spellings are direct `pub use` aliases of the
same function items:

| Rust function | Windows alias |
| --- | --- |
| `win_verify_trust` | `WinVerifyTrust` |
| `crypt_cat_admin_acquire_context2` | `CryptCATAdminAcquireContext2` |
| `crypt_cat_admin_calc_hash_from_file_handle2` | `CryptCATAdminCalcHashFromFileHandle2` |
| `crypt_cat_admin_release_context` | `CryptCATAdminReleaseContext` |

These are safe Rust APIs with explicit policy and SIP format. They return
`Result`, reports and owned digest bytes, rather than C pointers or HRESULTs.
They do not export a Windows DLL ABI, accept arbitrary Windows provider actions,
or consult the host catalog database. Contexts are owned Rust values and also
release automatically on drop. File hashing preserves the original seek position
on success and verification errors.

For this filesystem example, enable `features = ["std"]`.

```rust,no_run
use std::path::Path;
use wintrust::{WinVerifyTrust, portable::{PortableLimits, Verifier, sip::SipKind}};

let verifier = Verifier::load(Path::new("trust.json"), PortableLimits::default())?;
let report = WinVerifyTrust(&verifier, Path::new("update.cat"), Path::new("component.mum"), SipKind::FlatXml)?;
assert!(report.trust_established);
# Ok::<(), wintrust::Error>(())
```

The default implementation is Rust on all platforms. Feature `native-reference`
enables the separate Windows oracle at `catalog_trust::verify_catalog_member`;
it never changes `win_verify_trust` or its alias. The default dependency graph
contains no HTTP client. Enable `online` explicitly for bounded CRL/OCSP
acquisition using Rustls; online policies fail during loading without that feature.

Use `portable::Verifier::load` or `portable::VerifierBuilder` to construct an
immutable runtime. Policy, limits and pinned evidence have read-only accessors.
All constructors validate configuration, artifact pins and certificate DER.
`PortablePolicy` remains the versioned JSON input. With `std`, an omitted evaluation time is
captured once when the verifier is built; reusing it reuses that time. Build a
new verifier to evaluate at a later time.

`ctl::parse` inspects exact CTL bytes independently of catalog SIP member rules.
It preserves borrowed entry identifiers and encodings, typed purpose/algorithm
OIDs, sequence identifiers, update times, and unknown attributes. Parse results
make no authentication or AuthRoot/Disallowed authorization claim.

See [policy and limits](docs/portable-catalog-trust.md).
Synthetic test fixtures originate from the independently signed fixture set in
`windows-uup/tests/fixtures/catalog/revocation`; its regeneration script discards
private keys. The root and policy in `tests/fixtures` are for tests only.

Windows naming references: [context acquisition](https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatadminacquirecontext2)
and [file hashing](https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatadmincalchashfromfilehandle2).

## Migration from 0.1

CRL/OCSP acquisition is now optional. Applications using `PortableRevocationPolicy::Online`
must enable `wintrust = { version = "0.3.0", features = ["online"] }`.
Offline parsing and verification require no HTTP client. Windows-name aliases remain available and accept the validated verifier.
See the [Rust API migration](docs/portable-catalog-trust.md#rust-api-migration)
for the unreleased verifier and timestamp changes.

The published package includes synthetic test fixtures only. Microsoft-origin
catalogs, manifests, certificates and cache-only CTL audit tests remain in the
source repository, outside the registry archive. Run the repository suite for
those interoperability regressions.

## Development

Run `cargo test --all-features --locked` and
`cargo clippy --all-targets --all-features --locked -- -D warnings`.
The `native-reference` oracle runs only on Windows.

Extracted from `CaddyGlow/windows-uup` at commit
`63e832067678635809405a9fd8c7820db0904f4e`, including the working-tree
portable verifier changes present during extraction. The MIT copyright
notice is preserved in [LICENSE](LICENSE).

Catalog parser fuzzing is maintained in [fuzz](fuzz/README.md).

### `no_std` and optional platform support

The default build uses `no_std` with `alloc`; an allocator is required. DER/CMS,
CTL inspection, SIP hashing, certificate paths, timestamps, and offline revocation
verification remain available. Construct `Verifier::from_artifact_reader` with
hash-pinned artifact bytes and an explicit `PortablePolicy::verification_time`.
Without `std`, artifact paths are opaque `String` identifiers resolved by your reader.

Enable `std` for filesystem loading, automatic clock capture, `Verifier::builder`,
and Windows-name API aliases:

```toml
wintrust = { version = "0.3.0", features = ["std"] }
```

`online` and `native-reference` automatically enable `std`. A default build is
checked against the freestanding `x86_64-unknown-none` target in CI.

Verification APIs return typed `wintrust::Error` values. Low-level verification
uses `ChainOptions`, `RevocationOptions`, `CryptoOptions`, `SignatureOptions`,
and `SignedDataOptions`; DER collections accept borrowed buffers through
`CertificateStore`. Artifact identifiers remain `String` with every feature set.
OIDs and report categories use domain types while retaining their serialized
string values. See the [API migration guide](docs/portable-catalog-trust.md#rust-api-migration).
