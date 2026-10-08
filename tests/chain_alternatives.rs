mod support;
use der::{Decode, Encode};
use wintrust::portable::{
    chain::{self, PathLimits},
    signed,
};
use x509_cert::Certificate;

fn fixture() -> (Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let cms = signed::verify_signed_data(
        include_bytes!("fixtures/catalog.cat"),
        &signed::SignedDataOptions::new("1.3.6.1.4.1.311.10.1".parse().unwrap()),
    )
    .unwrap();
    (
        cms.signers[0].certificate_der.clone(),
        cms.certificates,
        vec![include_bytes!("fixtures/root.der").to_vec()],
    )
}
const TIME: u64 = 1791117219;
const EKU: &str = "1.3.6.1.5.5.7.3.3";

#[test]
fn alternative_same_key_issuer_does_not_make_a_valid_path_ambiguous() {
    let (leaf, mut certs, roots) = fixture();
    let mut alternative = Certificate::from_der(&roots[0]).unwrap();
    // A different certificate for the same subject/key verifies the child,
    // but its altered certificate signature cannot authenticate an anchor.
    alternative.signature = der::asn1::BitString::from_bytes(&[0; 256]).unwrap();
    let invalid_anchor = alternative.to_der().unwrap();
    // Same-key names and a valid child signature alone never establish trust.
    assert!(
        chain::validate(
            &leaf,
            &support::chain_options(&certs, std::slice::from_ref(&invalid_anchor), TIME, EKU)
        )
        .is_err()
    );
    certs.push(invalid_anchor.clone());
    let anchors = vec![invalid_anchor, roots[0].clone()];
    let expected =
        chain::validate(&leaf, &support::chain_options(&certs, &anchors, TIME, EKU)).unwrap();
    certs.reverse();
    let reordered =
        chain::validate(&leaf, &support::chain_options(&certs, &anchors, TIME, EKU)).unwrap();
    assert_eq!(expected.chain_der, reordered.chain_der);
    assert_eq!(expected.chain_der.last().unwrap(), &roots[0]);
}

#[test]
fn large_store_is_independent_of_path_work_limits() {
    let (leaf, certs, roots) = fixture();
    let mut anchors = roots.clone();
    for serial in 1000u32..1300 {
        let mut root = Certificate::from_der(&roots[0]).unwrap();
        root.tbs_certificate.serial_number =
            x509_cert::serial_number::SerialNumber::new(&serial.to_be_bytes()).unwrap();
        anchors.push(root.to_der().unwrap());
    }
    let candidates = certs.iter().cycle().take(100).cloned().collect::<Vec<_>>();
    chain::validate(
        &leaf,
        &support::chain_options(&candidates, &anchors, TIME, EKU),
    )
    .unwrap();
    for limits in [
        PathLimits {
            max_store_certificates: 1,
            ..PathLimits::default()
        },
        PathLimits {
            max_explored_candidates: 1,
            ..PathLimits::default()
        },
        PathLimits {
            max_signature_checks: 0,
            ..PathLimits::default()
        },
        PathLimits {
            max_depth: 1,
            ..PathLimits::default()
        },
        PathLimits {
            max_store_bytes: 1,
            ..PathLimits::default()
        },
    ] {
        assert!(
            chain::validate(
                &leaf,
                &chain::ChainOptions {
                    allow_sha1: false,
                    limits,
                    ..support::chain_options(&certs, &roots, TIME, EKU)
                }
            )
            .is_err()
        );
    }
}

#[test]
fn unsupported_constraints_and_wrong_purpose_still_fail() {
    let (leaf, certs, roots) = fixture();
    assert!(
        chain::validate(
            &leaf,
            &support::chain_options(&certs, &roots, TIME, "1.2.3.4")
        )
        .is_err()
    );
    let mut signer = Certificate::from_der(&leaf).unwrap();
    signer
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(x509_cert::ext::Extension {
            extn_id: "2.5.29.30".parse().unwrap(),
            critical: false,
            extn_value: der::asn1::OctetString::new(vec![0x30, 0]).unwrap(),
        });
    let error = chain::validate(
        &signer.to_der().unwrap(),
        &support::chain_options(&certs, &roots, TIME, EKU),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("unsupported certificate constraint"));
}

fn signed_alternatives() -> (Vec<u8>, Vec<Vec<u8>>) {
    let (leaf, _, roots) = fixture();
    let prepare = |certificate| support::prepare(certificate, &["2.5.29.35", "2.5.29.14"]);
    let sign = support::sign;
    let root = prepare(Certificate::from_der(&roots[0]).unwrap());
    let mut alternative = root.clone();
    alternative.tbs_certificate.serial_number =
        x509_cert::serial_number::SerialNumber::new(&[42]).unwrap();
    let mut signer = prepare(Certificate::from_der(&leaf).unwrap());
    signer.tbs_certificate.issuer = root.tbs_certificate.subject.clone();
    (sign(signer), vec![sign(root), sign(alternative)])
}

#[test]
fn path_policy_rejection_searches_another_fully_authenticated_anchor() {
    let (leaf, roots) = signed_alternatives();
    let first = chain::validate(&leaf, &support::chain_options(&[], &roots, TIME, EKU)).unwrap();
    let mut inspected = Vec::new();
    let accepted = chain::validate_with_path_policy(
        &leaf,
        &chain::ChainOptions {
            allow_sha1: false,
            limits: PathLimits::default(),
            ..support::chain_options(&[], &roots, TIME, EKU)
        },
        |path| {
            inspected.push(path.anchor_sha256.clone());
            support::require_policy(
                path.anchor_sha256 != first.anchor_sha256,
                "distrusted anchor",
            )?;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(inspected.len(), 2);
    assert_ne!(accepted.anchor_sha256, first.anchor_sha256);
    let error = chain::validate_with_path_policy(
        &leaf,
        &chain::ChainOptions {
            allow_sha1: false,
            limits: PathLimits::default(),
            ..support::chain_options(&[], &roots, TIME, EKU)
        },
        |_| Err(wintrust::error::Error::policy("revoked path")),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("revoked path"));
    assert!(
        chain::validate(
            &leaf,
            &support::chain_options(
                &[],
                &[include_bytes!("fixtures/root.der").to_vec()],
                TIME,
                EKU
            )
        )
        .is_err()
    );
}

#[test]
fn untrusted_same_key_issuer_cycles_terminate_without_establishing_trust() {
    let (leaf, candidates) = signed_alternatives();
    let anchors = vec![include_bytes!("fixtures/root.der").to_vec()];
    let error = chain::validate(
        &leaf,
        &chain::ChainOptions {
            allow_sha1: false,
            limits: PathLimits {
                max_explored_candidates: 8,
                ..PathLimits::default()
            },
            ..support::chain_options(&candidates, &anchors, TIME, EKU)
        },
    )
    .unwrap_err();
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("no acceptable certificate path"));
    assert!(!diagnostic.contains("candidate limit"));
}

#[test]
fn self_issued_rollover_is_exempt_from_path_length_but_other_cas_are_not() {
    use p256::pkcs8::EncodePublicKey;
    use signature::Signer;
    let old_key = p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let new_key = p256::ecdsa::SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
    let (leaf_der, _, roots) = fixture();
    let prepare = |mut certificate: Certificate, key: &p256::ecdsa::SigningKey| {
        certificate.tbs_certificate.subject_public_key_info =
            x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(
                key.verifying_key().to_public_key_der().unwrap().as_bytes(),
            )
            .unwrap();
        certificate.tbs_certificate.signature.oid = "1.2.840.10045.4.3.2".parse().unwrap();
        certificate.tbs_certificate.signature.parameters = None;
        certificate.signature_algorithm = certificate.tbs_certificate.signature.clone();
        certificate
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .retain(|e| !matches!(e.extn_id.to_string().as_str(), "2.5.29.14" | "2.5.29.35"));
        certificate
    };
    let sign = |mut certificate: Certificate, key: &p256::ecdsa::SigningKey| {
        let signature: p256::ecdsa::Signature =
            key.sign(&certificate.tbs_certificate.to_der().unwrap());
        certificate.signature =
            der::asn1::BitString::from_bytes(signature.to_der().as_bytes()).unwrap();
        certificate.to_der().unwrap()
    };
    let mut root = prepare(Certificate::from_der(&roots[0]).unwrap(), &old_key);
    root.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .retain(|e| e.extn_id.to_string() != "2.5.29.19");
    root.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(x509_cert::ext::Extension {
            extn_id: "2.5.29.19".parse().unwrap(),
            critical: true,
            extn_value: der::asn1::OctetString::new(
                x509_cert::ext::pkix::BasicConstraints {
                    ca: true,
                    path_len_constraint: Some(0),
                }
                .to_der()
                .unwrap(),
            )
            .unwrap(),
        });
    let mut rollover = prepare(root.clone(), &new_key);
    rollover.tbs_certificate.serial_number =
        x509_cert::serial_number::SerialNumber::new(&[99]).unwrap();
    let roots = vec![sign(root, &old_key)];
    for self_issued in [true, false] {
        let mut issuer = rollover.clone();
        if !self_issued {
            issuer.tbs_certificate.subject = "CN=Separate intermediate".parse().unwrap();
        }
        let mut leaf = prepare(Certificate::from_der(&leaf_der).unwrap(), &new_key);
        leaf.tbs_certificate.issuer = issuer.tbs_certificate.subject.clone();
        let result = chain::validate(
            &sign(leaf, &new_key),
            &support::chain_options(&[sign(issuer, &old_key)], &roots, TIME, EKU),
        );
        if self_issued {
            assert_eq!(result.unwrap().chain_der.len(), 3);
        } else {
            assert!(format!("{:#}", result.unwrap_err()).contains("CA path length exceeded"));
        }
    }
}

#[test]
fn borrowed_der_store_has_the_same_trust_and_typed_limits() {
    let (leaf, candidates, roots) = fixture();
    let candidate_slices = candidates.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let root_slices = roots.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let mut options = chain::ChainOptions::new(root_slices.as_slice(), TIME, EKU.parse().unwrap());
    options.candidates = candidate_slices.as_slice().into();
    let borrowed = chain::validate(&leaf, &options).unwrap();
    let owned = chain::validate(
        &leaf,
        &support::chain_options(&candidates, &roots, TIME, EKU),
    )
    .unwrap();
    assert_eq!(borrowed.chain_der, owned.chain_der);
    options.limits.max_store_bytes = 1;
    assert!(matches!(
        chain::validate(&leaf, &options),
        Err(wintrust::error::Error::ResourceLimit(_))
    ));
    options.roots = Default::default();
    assert!(matches!(
        chain::validate(&leaf, &options),
        Err(wintrust::error::Error::InvalidConfiguration(_))
    ));
}

#[test]
fn absent_required_purpose_or_ca_permissions_are_policy_rejections() {
    for (leaf_oid, root_oid) in [
        (Some("2.5.29.37"), None),
        (None, Some("2.5.29.19")),
        (None, Some("2.5.29.15")),
    ] {
        let (mut leaf, mut root) = support::templates(&["2.5.29.35", "2.5.29.14"]);
        for (certificate, removed) in [(&mut leaf, leaf_oid), (&mut root, root_oid)] {
            if let Some(oid) = removed {
                certificate
                    .tbs_certificate
                    .extensions
                    .as_mut()
                    .unwrap()
                    .retain(|extension| extension.extn_id != oid.parse().unwrap());
            }
        }
        let roots = [support::sign(root)];
        let options = chain::ChainOptions::new(&roots, TIME, EKU.parse().unwrap());
        assert!(matches!(
            chain::validate(&support::sign(leaf), &options),
            Err(wintrust::error::Error::PolicyRejected(_))
        ));
    }
}
