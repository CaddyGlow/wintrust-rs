use std::path::PathBuf;
use wintrust::portable::{
    PortableLimits, PortablePolicy, PortableVerifier, PublisherPolicy, sip::SipKind,
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/microsoft-legacy-wcf")
        .join(name)
}
fn policy() -> PortablePolicy {
    serde_json::from_slice(&std::fs::read(fixture("policy.json")).unwrap()).unwrap()
}
fn verifier(policy: PortablePolicy) -> anyhow::Result<PortableVerifier> {
    PortableVerifier::from_policy(policy, &fixture(""), PortableLimits::default())
}
fn verify(engine: &PortableVerifier) -> anyhow::Result<wintrust::portable::PortableTrustReport> {
    engine.verify_catalog_member(
        &fixture("catalog.cat"),
        &fixture("member.manifest"),
        SipKind::FlatXml,
    )
}

#[test]
fn strict_default_and_wrong_certificate_pin_reject_genuine_noncritical_microsoft_timestamp() {
    let mut strict = serde_json::to_value(policy()).unwrap();
    strict
        .as_object_mut()
        .unwrap()
        .remove("noncritical_tsa_certificate_sha256");
    let strict: PortablePolicy = serde_json::from_value(strict).unwrap();
    assert!(strict.noncritical_tsa_certificate_sha256.is_empty());
    let error = verify(&verifier(strict).unwrap()).unwrap_err();
    assert!(format!("{error:#}").contains("exclusive critical TSA EKU"));
    let mut wrong = policy();
    wrong.noncritical_tsa_certificate_sha256 = vec!["0".repeat(64)];
    assert!(verify(&verifier(wrong).unwrap()).is_err());
}

#[test]
fn exact_microsoft_tsa_pin_authenticates_real_catalog_membership_and_reports_compatibility() {
    let configuration = policy();
    let report = verify(&verifier(configuration.clone()).unwrap()).unwrap();
    assert!(report.trust_established && report.microsoft_signer_verified);
    assert!(!report.revocation_checked && !report.allow_sha1);
    assert_eq!(
        report.catalog_sha256,
        "69622576702850c4b3303326bc717f27b8241086841ca022b8fffcf7b4307cab"
    );
    assert_eq!(
        report.noncritical_tsa_certificate_sha256,
        configuration.noncritical_tsa_certificate_sha256
    );
    assert!(report.signers.iter().all(|s| {
        s.timestamp
            .as_ref()
            .unwrap()
            .noncritical_tsa_compatibility_used
    }));
}

#[test]
fn compatibility_never_accepts_altered_member_or_catalog() {
    let engine = verifier(policy()).unwrap();
    let mut xml = std::fs::read(fixture("member.manifest")).unwrap();
    xml.push(b' ');
    let catalog = std::fs::read(fixture("catalog.cat")).unwrap();
    assert!(
        engine
            .verify_bytes(&catalog, &xml, SipKind::FlatXml)
            .is_err()
    );
    let mut damaged = catalog;
    damaged[100] ^= 1;
    assert!(
        engine
            .verify_bytes(
                &damaged,
                &std::fs::read(fixture("member.manifest")).unwrap(),
                SipKind::FlatXml
            )
            .is_err()
    );
}

#[test]
fn compatibility_policy_rejects_foreign_publishers_duplicate_unbounded_and_noncanonical_pins() {
    let mut p = policy();
    p.publisher = PublisherPolicy::ExplicitRoots;
    assert!(verifier(p).is_err());
    let mut p = policy();
    p.noncritical_tsa_certificate_sha256
        .push(p.noncritical_tsa_certificate_sha256[0].clone());
    assert!(verifier(p).is_err());
    for pins in [
        vec!["A".repeat(64)],
        vec!["0".repeat(63)],
        (0..9).map(|v| format!("{v:064x}")).collect(),
    ] {
        let mut p = policy();
        p.noncritical_tsa_certificate_sha256 = pins;
        assert!(verifier(p).is_err());
    }
}
