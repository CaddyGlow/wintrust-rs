use std::{
    fs::File,
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
};
use wintrust::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminReleaseContext, WinVerifyTrust, crypt_cat_admin_acquire_context2,
    crypt_cat_admin_calc_hash_from_file_handle2,
    portable::{
        PortableLimits, Verifier,
        sip::{DigestAlgorithm, MemberHashPolicy, SipKind},
    },
    win_verify_trust,
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn windows_aliases_verify_the_complete_portable_policy_and_reject_modified_members() {
    let verifier = Verifier::load(&fixture("policy.json"), PortableLimits::default()).unwrap();
    let report = WinVerifyTrust(
        &verifier,
        &fixture("catalog.cat"),
        &fixture("catalog-member.mum"),
        SipKind::FlatXml,
    )
    .unwrap();
    assert!(report.trust_established && report.revocation_checked);
    let rust_report = win_verify_trust(
        &verifier,
        &fixture("catalog.cat"),
        &fixture("catalog-member.mum"),
        SipKind::FlatXml,
    )
    .unwrap();
    assert_eq!(report.catalog_sha256, rust_report.catalog_sha256);
    let mut modified = tempfile::NamedTempFile::new().unwrap();
    modified
        .write_all(b"<assembly>modified</assembly>")
        .unwrap();
    assert!(
        WinVerifyTrust(
            &verifier,
            &fixture("catalog.cat"),
            modified.path(),
            SipKind::FlatXml
        )
        .is_err()
    );
}

#[test]
fn context_hashes_whole_files_with_sip_rules_and_restores_seek_position() {
    let context = CryptCATAdminAcquireContext2(
        DigestAlgorithm::Sha256,
        SipKind::FlatXml,
        MemberHashPolicy::default(),
    )
    .unwrap();
    let mut member = File::open(fixture("catalog-member.mum")).unwrap();
    member.seek(SeekFrom::Start(17)).unwrap();
    let hash = CryptCATAdminCalcHashFromFileHandle2(&context, &mut member).unwrap();
    assert_eq!(
        hex::encode(hash),
        "17aea94269fd65de53fbac7e529f6dee6eb49220a4c164f768947a1710088774"
    );
    assert_eq!(member.stream_position().unwrap(), 17);
    let rust_context = crypt_cat_admin_acquire_context2(
        DigestAlgorithm::Sha256,
        SipKind::FlatXml,
        MemberHashPolicy::default(),
    )
    .unwrap();
    assert_eq!(
        crypt_cat_admin_calc_hash_from_file_handle2(&rust_context, &mut member).unwrap(),
        CryptCATAdminCalcHashFromFileHandle2(&context, &mut member).unwrap()
    );
    CryptCATAdminReleaseContext(context);
}

#[test]
fn invalid_context_and_member_cannot_bypass_policy_and_seek_is_restored_on_failure() {
    assert!(
        CryptCATAdminAcquireContext2(
            DigestAlgorithm::Sha1,
            SipKind::FlatRaw,
            MemberHashPolicy::default()
        )
        .is_err()
    );
    let context = CryptCATAdminAcquireContext2(
        DigestAlgorithm::Sha256,
        SipKind::Pe,
        MemberHashPolicy::default(),
    )
    .unwrap();
    let mut member = File::open(fixture("catalog-member.mum")).unwrap();
    member.seek(SeekFrom::Start(7)).unwrap();
    assert!(CryptCATAdminCalcHashFromFileHandle2(&context, &mut member).is_err());
    assert_eq!(member.stream_position().unwrap(), 7);
    let bounded = CryptCATAdminAcquireContext2(
        DigestAlgorithm::Sha256,
        SipKind::FlatXml,
        MemberHashPolicy {
            max_member_bytes: 1,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(CryptCATAdminCalcHashFromFileHandle2(&bounded, &mut member).is_err());
    assert_eq!(member.stream_position().unwrap(), 7);
}
