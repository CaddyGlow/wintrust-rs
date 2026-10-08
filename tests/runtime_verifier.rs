use std::path::Path;
use wintrust::catalog_trust::portable::{PortableLimits, PortablePolicy, ValidatedVerifier};

fn fixture_policy() -> PortablePolicy {
    serde_json::from_slice(include_bytes!("fixtures/policy.json")).unwrap()
}

#[test]
fn runtime_loads_pinned_evidence_and_rejects_corruption() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let verifier = ValidatedVerifier::builder(fixture_policy(), &base)
        .build()
        .unwrap();
    assert_eq!(verifier.roots().len(), 1);
    let report = verifier
        .verify_bytes(
            include_bytes!("fixtures/catalog.cat"),
            include_bytes!("fixtures/catalog-member.mum"),
            wintrust::catalog_trust::portable::sip::SipKind::FlatXml,
        )
        .unwrap();
    assert!(report.trust_established);
    assert!(
        ValidatedVerifier::builder(fixture_policy(), &base)
            .build_with_reader(|_, _| Ok(vec![1, 2, 3]))
            .is_err()
    );
    assert!(
        ValidatedVerifier::builder(fixture_policy(), &base)
            .limits(PortableLimits {
                max_artifacts: 0,
                ..Default::default()
            })
            .build()
            .is_err()
    );
}

#[test]
fn pinned_invalid_certificate_is_rejected_during_build() {
    use sha2::{Digest, Sha256};
    let bytes = vec![1, 2, 3];
    let mut policy = fixture_policy();
    policy.roots[0].sha256 = hex::encode(Sha256::digest(&bytes));
    policy.crls.clear();
    policy.ocsp_responses.clear();
    assert!(
        ValidatedVerifier::builder(policy, ".")
            .build_with_reader(|_, _| Ok(bytes.clone()))
            .unwrap_err()
            .to_string()
            .contains("certificate DER")
    );
}

#[test]
fn unspecified_clock_is_captured_in_validated_configuration() {
    let mut policy = fixture_policy();
    policy.verification_time = None;
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let verifier = ValidatedVerifier::builder(policy, base).build().unwrap();
    let captured = verifier.policy().verification_time.unwrap();
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!((before..=after).contains(&captured));
}

#[cfg(not(feature = "online"))]
#[test]
fn offline_build_rejects_online_configuration_before_loading() {
    let mut policy = fixture_policy();
    policy.revocation = wintrust::catalog_trust::portable::PortableRevocationPolicy::Online;
    let error = ValidatedVerifier::builder(policy, "missing-directory")
        .build_with_reader(|_, _| panic!("unsupported configuration must not load artifacts"))
        .unwrap_err();
    assert!(error.to_string().contains("online feature"));
}
