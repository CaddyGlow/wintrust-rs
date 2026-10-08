# wintrust

Portable Rust catalog trust.

```toml
[dependencies]
wintrust = "0.1.0"
```

 The implementation includes CMS/CTL,
RustCrypto signatures, pinned certificate chains, publisher authorization,
timestamps, signed CRL/OCSP status, bounded online acquisition and PE/CAB/XML SIP
hashes. `windows-uup` uses this crate and keeps compatibility module re-exports.

Functions use snake_case. Windows spellings are direct `pub use` aliases of the
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

```rust,no_run
use std::path::Path;
use wintrust::{WinVerifyTrust, portable::{PortableLimits, PortableVerifier, sip::SipKind}};

let verifier = PortableVerifier::load(Path::new("trust.json"), PortableLimits::default())?;
let report = WinVerifyTrust(&verifier, Path::new("update.cat"), Path::new("component.mum"), SipKind::FlatXml)?;
assert!(report.trust_established);
# Ok::<(), anyhow::Error>(())
```

The default implementation is Rust on all platforms. Feature `native-reference`
enables the separate Windows oracle at `catalog_trust::verify_catalog_member`;
it never changes `win_verify_trust` or its alias. Network TLS uses Rustls.

See [policy and limits](docs/portable-catalog-trust.md).
Synthetic test fixtures originate from the independently signed fixture set in
`windows-uup/tests/fixtures/catalog/revocation`; its regeneration script discards
private keys. The root and policy in `tests/fixtures` are for tests only.

Windows naming references: [context acquisition](https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatadminacquirecontext2)
and [file hashing](https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatadmincalchashfromfilehandle2).

## Development

Run `cargo test --all-features --locked` and
`cargo clippy --all-targets --all-features --locked -- -D warnings`.
The `native-reference` oracle runs only on Windows.

Extracted from `CaddyGlow/windows-uup` at commit
`63e832067678635809405a9fd8c7820db0904f4e`, including the working-tree
portable verifier changes present during extraction. The MIT copyright
notice is preserved in [LICENSE](LICENSE).

Catalog parser fuzzing is maintained in [fuzz](fuzz/README.md).
