//! A timestamp's uncertainty must be covered by one authenticated path.
mod support;
use der::{Decode, Encode, asn1::ObjectIdentifier};
use p256::ecdsa::Signature;
use sha2::{Digest, Sha256};
use signature::Signer;
use std::time::Duration;
use wintrust::portable::{
    signed::VerifiedSigner,
    timestamp::{self, TimestampOptions},
};
use x509_cert::{Certificate, ext::pkix::ExtendedKeyUsage, time::Time};

const CENTER: u64 = 1791117219;
const ACCURACY: u64 = 10;
const TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        let bytes = value.len().to_be_bytes();
        let bytes = &bytes[bytes.iter().position(|b| *b != 0).unwrap()..];
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.extend_from_slice(value);
    out
}
fn seq(values: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &values.concat())
}
fn oid(value: &str) -> Vec<u8> {
    value.parse::<ObjectIdentifier>().unwrap().to_der().unwrap()
}
fn algorithm(value: &str) -> Vec<u8> {
    seq(&[oid(value)])
}
fn attribute(name: &str, value: Vec<u8>) -> Vec<u8> {
    seq(&[oid(name), tlv(0x31, &value)])
}
fn time(value: u64) -> Time {
    Time::UtcTime(der::asn1::UtcTime::from_unix_duration(Duration::from_secs(value)).unwrap())
}
fn certificates() -> (Certificate, Certificate) {
    let (mut leaf, mut root) = support::templates(&[
        "2.5.29.35",
        "2.5.29.14",
        "2.5.29.37",
        "2.5.29.17",
        "2.5.29.31",
    ]);
    leaf.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(support::extension(
            "2.5.29.37",
            ExtendedKeyUsage(vec!["1.3.6.1.5.5.7.3.8".parse().unwrap()])
                .to_der()
                .unwrap(),
            true,
        ));
    leaf.tbs_certificate.validity.not_before = time(CENTER - 100);
    leaf.tbs_certificate.validity.not_after = time(CENTER + 100);
    root.tbs_certificate.validity = leaf.tbs_certificate.validity;
    (
        support::sign_certificate(leaf),
        support::sign_certificate(root),
    )
}
fn token(leaf: &Certificate, original: &[u8]) -> Vec<u8> {
    let sha = algorithm("2.16.840.1.101.3.4.2.1");
    let info = seq(&[
        tlv(2, &[1]),
        oid("1.2.3.4"),
        seq(&[sha.clone(), tlv(4, &Sha256::digest(original))]),
        tlv(2, &[1]),
        tlv(0x18, b"20261004123339Z"),
        seq(&[tlv(2, &[ACCURACY as u8])]),
    ]);
    // Default SHA-256 ESSCertIDv2, with no optional issuerSerial.
    let ess = seq(&[seq(&[seq(&[tlv(
        4,
        &Sha256::digest(leaf.to_der().unwrap()),
    )])])]);
    let mut attrs = [
        attribute("1.2.840.113549.1.9.3", oid(TST_INFO)),
        attribute("1.2.840.113549.1.9.4", tlv(4, &Sha256::digest(&info))),
        attribute("1.2.840.113549.1.9.16.2.47", ess),
    ];
    attrs.sort();
    let signed_attrs = tlv(0x31, &attrs.concat());
    let signature: Signature = support::key().sign(&signed_attrs);
    let signer = seq(&[
        tlv(2, &[1]),
        seq(&[
            leaf.tbs_certificate.issuer.to_der().unwrap(),
            leaf.tbs_certificate.serial_number.to_der().unwrap(),
        ]),
        sha.clone(),
        tlv(0xa0, &attrs.concat()),
        algorithm("1.2.840.10045.4.3.2"),
        tlv(4, signature.to_der().as_bytes()),
    ]);
    let cms = seq(&[
        tlv(2, &[3]),
        tlv(0x31, &sha),
        seq(&[oid(TST_INFO), tlv(0xa0, &tlv(4, &info))]),
        tlv(0xa0, &leaf.to_der().unwrap()),
        tlv(0x31, &signer),
    ]);
    seq(&[oid("1.2.840.113549.1.7.2"), tlv(0xa0, &cms)])
}
fn signer(leaf: &Certificate) -> VerifiedSigner {
    let original = b"catalog signature".to_vec();
    VerifiedSigner {
        certificate_der: vec![],
        signed_attributes: vec![],
        unsigned_attributes: vec![(
            timestamp::RFC3161_ATTRIBUTE.to_owned(),
            vec![token(leaf, &original)],
        )],
        signature: original,
    }
}
#[test]
fn split_validity_roots_cannot_collectively_cover_timestamp_accuracy() {
    let (leaf, root) = certificates();
    let signer = signer(&leaf);
    let mut early = root.clone();
    early.tbs_certificate.validity.not_after = time(CENTER - 1);
    let mut late = root;
    late.tbs_certificate.validity.not_before = time(CENTER + 1);
    let roots = vec![support::sign(early), support::sign(late)];
    let options = TimestampOptions::new(&roots, CENTER + 100);
    assert!(timestamp::verify_timestamps(&signer, &options).is_err());
    let mut callbacks = 0;
    assert!(
        timestamp::verify_timestamps_with_path_policy(&signer, &options, |_, _| {
            callbacks += 1;
            Ok(())
        })
        .is_err()
    );
    assert_eq!(callbacks, 0);
}
#[test]
fn returned_timestamp_path_spans_both_accuracy_endpoints() {
    let (leaf, root) = certificates();
    let signer = signer(&leaf);
    let roots = vec![root.to_der().unwrap()];
    let options = TimestampOptions::new(&roots, CENTER + 100);
    let report = timestamp::verify_timestamps(&signer, &options)
        .unwrap()
        .unwrap();
    assert_eq!(report.unix_time, CENTER);
    assert_eq!(report.accuracy_seconds, ACCURACY);
    for bytes in report.chain_der {
        let cert = Certificate::from_der(&bytes).unwrap();
        assert!(
            cert.tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs()
                <= CENTER - ACCURACY
        );
        assert!(
            cert.tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs()
                >= CENTER + ACCURACY
        );
    }
    assert!(
        timestamp::verify_timestamps_with_path_policy(&signer, &options, |_, _| Ok(()))
            .unwrap()
            .is_some()
    );
}

fn crl(issuer: &Certificate, revoked: Option<&Certificate>) -> Vec<u8> {
    use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
    let algorithm = issuer.signature_algorithm.clone();
    let tbs = TbsCertList {
        version: x509_cert::certificate::Version::V2,
        signature: algorithm.clone(),
        issuer: issuer.tbs_certificate.subject.clone(),
        this_update: time(CENTER - 50),
        next_update: Some(time(CENTER + 200)),
        revoked_certificates: revoked.map(|certificate| {
            vec![RevokedCert {
                serial_number: certificate.tbs_certificate.serial_number.clone(),
                revocation_date: time(CENTER - 50),
                crl_entry_extensions: None,
            }]
        }),
        crl_extensions: None,
    };
    let signature: Signature = support::key().sign(&tbs.to_der().unwrap());
    CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: algorithm,
        signature: der::asn1::BitString::from_bytes(signature.to_der().as_bytes()).unwrap(),
    }
    .to_der()
    .unwrap()
}

fn catalog(leaf: &Certificate, tsa: &Certificate) -> Vec<u8> {
    let source = wintrust::portable::signed::verify_signed_data(
        include_bytes!("fixtures/catalog.cat"),
        "1.3.6.1.4.1.311.10.1",
    )
    .unwrap();
    let content = source.content_der;
    let sha = algorithm("2.16.840.1.101.3.4.2.1");
    let mut attrs = [
        attribute("1.2.840.113549.1.9.3", oid("1.3.6.1.4.1.311.10.1")),
        attribute("1.2.840.113549.1.9.4", tlv(4, &Sha256::digest(content))),
    ];
    attrs.sort();
    let signature: Signature = support::key().sign(&tlv(0x31, &attrs.concat()));
    let signature = signature.to_der();
    let unsigned = attribute(
        timestamp::RFC3161_ATTRIBUTE,
        token(tsa, signature.as_bytes()),
    );
    let signer = seq(&[
        tlv(2, &[1]),
        seq(&[
            leaf.tbs_certificate.issuer.to_der().unwrap(),
            leaf.tbs_certificate.serial_number.to_der().unwrap(),
        ]),
        sha.clone(),
        tlv(0xa0, &attrs.concat()),
        algorithm("1.2.840.10045.4.3.2"),
        tlv(4, signature.as_bytes()),
        tlv(0xa1, &unsigned),
    ]);
    let cms = seq(&[
        tlv(2, &[3]),
        tlv(0x31, &sha),
        seq(&[oid("1.3.6.1.4.1.311.10.1"), tlv(0xa0, &tlv(4, content))]),
        tlv(0xa0, &leaf.to_der().unwrap()),
        tlv(0x31, &signer),
    ]);
    seq(&[oid("1.2.840.113549.1.7.2"), tlv(0xa0, &cms)])
}

#[test]
fn verifier_retries_tsa_paths_when_first_intermediate_is_revoked() {
    use wintrust::portable::{
        ArtifactRef, PortablePolicy, Verifier, revocation::RevocationStatus, sip::SipKind,
    };
    use x509_cert::serial_number::SerialNumber;
    let (mut tsa, root) = certificates();
    let (mut primary, _) =
        support::templates(&["2.5.29.35", "2.5.29.14", "2.5.29.17", "2.5.29.31"]);
    primary.tbs_certificate.validity = root.tbs_certificate.validity;
    let primary = support::sign_certificate(primary);
    let mut first = root.clone();
    first.tbs_certificate.subject = "CN=TSA CA".parse().unwrap();
    first.tbs_certificate.serial_number = SerialNumber::new(&[41]).unwrap();
    let mut second = first.clone();
    second.tbs_certificate.serial_number = SerialNumber::new(&[42]).unwrap();
    let mut alternatives = [
        support::sign_certificate(first),
        support::sign_certificate(second),
    ];
    // Put the revoked candidate first in the supplied issuer store.
    alternatives.sort_by_key(|certificate| certificate.to_der().unwrap());
    tsa.tbs_certificate.issuer = alternatives[0].tbs_certificate.subject.clone();
    let tsa = support::sign_certificate(tsa);
    let issuer_candidates = alternatives
        .iter()
        .map(|cert| cert.to_der().unwrap())
        .collect::<Vec<_>>();
    let roots = vec![root.to_der().unwrap()];
    let mut options = TimestampOptions::new(&roots, CENTER + 100);
    options.issuer_candidates = &issuer_candidates;
    let without_revocation = timestamp::verify_timestamps(&signer(&tsa), &options)
        .unwrap()
        .unwrap();
    assert_eq!(without_revocation.chain_der[1], issuer_candidates[0]);
    let catalog = catalog(&primary, &tsa);
    let artifacts = [
        root.to_der().unwrap(),
        alternatives[0].to_der().unwrap(),
        alternatives[1].to_der().unwrap(),
        crl(&root, Some(&alternatives[0])),
        crl(&alternatives[0], None),
    ];
    let reference = |index: usize| ArtifactRef {
        path: format!("artifact-{index}").into(),
        sha256: hex::encode(Sha256::digest(&artifacts[index])),
    };
    let mut policy: PortablePolicy =
        serde_json::from_slice(include_bytes!("fixtures/policy.json")).unwrap();
    policy.roots = vec![reference(0)];
    policy.intermediates = vec![reference(1), reference(2)];
    policy.crls = vec![reference(3), reference(4)];
    policy.ocsp_responses.clear();
    policy.verification_time = Some(CENTER + 100);
    let verifier = Verifier::builder(policy.clone(), ".")
        .build_with_reader(|path, _| {
            let name = path.file_name().unwrap().to_str().unwrap();
            let index = name
                .strip_prefix("artifact-")
                .unwrap()
                .parse::<usize>()
                .unwrap();
            Ok(artifacts[index].clone())
        })
        .unwrap();
    let report = verifier
        .verify_bytes(
            &catalog,
            include_bytes!("fixtures/catalog-member.mum"),
            SipKind::FlatXml,
        )
        .unwrap();
    assert_eq!(
        report.signers[0]
            .timestamp_revocation
            .as_ref()
            .unwrap()
            .status,
        RevocationStatus::Good
    );
    let path = &report.signers[0].timestamp.as_ref().unwrap().chain_der;
    assert_eq!(path[1], alternatives[1].to_der().unwrap());
    // Removing the acceptable alternative leaves only the revoked TSA path.
    policy.intermediates.truncate(1);
    let verifier = Verifier::builder(policy, ".")
        .build_with_reader(|path, _| {
            let index = path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .strip_prefix("artifact-")
                .unwrap()
                .parse::<usize>()
                .unwrap();
            Ok(artifacts[index].clone())
        })
        .unwrap();
    assert!(
        verifier
            .verify_bytes(
                &catalog,
                include_bytes!("fixtures/catalog-member.mum"),
                SipKind::FlatXml
            )
            .is_err()
    );
}
