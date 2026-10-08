use wintrust::portable::{PortableLimits, PortablePolicy, Verifier, sip::SipKind};

fn policy() -> PortablePolicy {
    serde_json::from_slice(include_bytes!("fixtures/policy.json")).unwrap()
}

fn artifact(
    artifact: &wintrust::portable::ArtifactRef,
    _: usize,
) -> wintrust::error::Result<Vec<u8>> {
    // The reader resolves opaque locations; all fingerprints and budgets are
    // still enforced by the verifier.
    let bytes = match artifact.sha256.as_str() {
        hash if hash == policy().roots[0].sha256 => include_bytes!("fixtures/root.der").as_slice(),
        hash if hash == policy().crls[0].sha256 => {
            include_bytes!("fixtures/good.crl.der").as_slice()
        }
        hash if hash == policy().ocsp_responses[0].sha256 => {
            include_bytes!("fixtures/catalog-good.ocsp.der").as_slice()
        }
        _ => return Err(wintrust::error::Error::configuration("unexpected artifact")),
    };
    Ok(bytes.to_vec())
}

#[test]
fn verifies_pinned_artifacts_without_filesystem_or_clock_access() {
    let verifier =
        Verifier::from_artifact_reader(policy(), PortableLimits::default(), artifact).unwrap();
    let report = verifier
        .verify_bytes(
            include_bytes!("fixtures/catalog.cat"),
            include_bytes!("fixtures/catalog-member.mum"),
            SipKind::FlatXml,
        )
        .unwrap();
    assert!(report.trust_established);
    assert_eq!(
        report.verification_time,
        policy().verification_time.unwrap()
    );
    assert!(
        Verifier::from_artifact_reader(policy(), PortableLimits::default(), |_, _| Ok(vec![0]))
            .is_err()
    );
}

#[cfg(not(feature = "std"))]
#[test]
fn requires_an_explicit_evaluation_time() {
    let mut policy = policy();
    policy.verification_time = None;
    let error =
        Verifier::from_artifact_reader(policy, PortableLimits::default(), artifact).unwrap_err();
    assert!(error.to_string().contains("explicit verification_time"));
}
