use crate::portable::{
    PortableTrustReport, Verifier,
    sip::{self, DigestAlgorithm, MemberHashPolicy, SipKind},
};
use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

/// Owned portable catalog administrator context. Drop releases it automatically.
/// Algorithm, format and bounds cannot change after acquisition.
#[derive(Debug)]
pub struct CatalogAdminContext {
    algorithm: DigestAlgorithm,
    kind: SipKind,
    policy: MemberHashPolicy,
}

/// Acquire a portable hashing context with an explicit algorithm and SIP format.
/// SHA-1 requires an affirmative compatibility policy; zero bounds are invalid.
pub fn crypt_cat_admin_acquire_context2(
    algorithm: DigestAlgorithm,
    kind: SipKind,
    policy: MemberHashPolicy,
) -> Result<CatalogAdminContext> {
    ensure!(
        policy.max_member_bytes > 0,
        "member byte limit must be positive"
    );
    ensure!(
        algorithm != DigestAlgorithm::Sha1 || policy.allow_sha1,
        "SHA-1 requires explicit compatibility policy"
    );
    Ok(CatalogAdminContext {
        algorithm,
        kind,
        policy,
    })
}

/// Hash a complete regular file using the context's SIP rules.
/// The original seek position is restored after success or verification failure.
/// The returned bytes replace Windows' caller-allocated output buffer.
pub fn crypt_cat_admin_calc_hash_from_file_handle2(
    context: &CatalogAdminContext,
    file: &mut File,
) -> Result<Vec<u8>> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "member handle must refer to a regular file"
    );
    ensure!(
        metadata.len() <= context.policy.max_member_bytes as u64,
        "member byte limit exceeded"
    );
    let position = file.stream_position()?;
    let result = (|| {
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        (&mut *file)
            .take((context.policy.max_member_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= context.policy.max_member_bytes,
            "member byte limit exceeded"
        );
        sip::member_hash_bytes(&bytes, context.kind, context.algorithm, &context.policy)
    })();
    file.seek(SeekFrom::Start(position))
        .context("restore member file position")?;
    result
}

/// Release a context by consuming ownership. Ordinary Rust drop also suffices.
pub fn crypt_cat_admin_release_context(_context: CatalogAdminContext) {}

/// Verify an explicitly supplied catalog member under the portable Rust policy.
/// Requires every configured signature, chain, timestamp and revocation check;
/// rejected trust is an error rather than an HRESULT or partially trusted report.
pub fn win_verify_trust(
    verifier: &Verifier,
    catalog: &Path,
    member: &Path,
    kind: SipKind,
) -> Result<PortableTrustReport> {
    verifier.verify_catalog_member(catalog, member, kind)
}
