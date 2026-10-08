//! RFC 5280 CRL evaluation: direct, scoped, indirect and delta CRLs on
//! synthetic P-256 signed evidence.
use der::{
    Decode, Encode, EncodePem,
    asn1::{ObjectIdentifier, OctetString, Uint},
    flagset::FlagSet,
};
use p256::{
    ecdsa::{Signature, SigningKey},
    pkcs8::EncodePublicKey,
};
use signature::Signer;
use std::time::Duration;
use wintrust::portable::{
    revocation::{self, RevocationLimits, RevocationStatus},
    signed,
};
use x509_cert::{
    Certificate,
    crl::{CertificateList, RevokedCert, TbsCertList},
    ext::{
        Extension,
        pkix::{
            CrlDistributionPoints,
            crl::{
                CrlReason, IssuingDistributionPoint,
                dp::{DistributionPoint, Reasons},
            },
            name::{DistributionPointName, GeneralName},
        },
    },
    name::Name,
    serial_number::SerialNumber,
    time::Time,
};

const TIME: u64 = 1791117219;
const ALL: u16 = 0x1fe;

fn oid(s: &str) -> ObjectIdentifier {
    s.parse().unwrap()
}
fn extension(id: &str, bytes: Vec<u8>, critical: bool) -> Extension {
    Extension {
        extn_id: oid(id),
        critical,
        extn_value: OctetString::new(bytes).unwrap(),
    }
}
fn key() -> SigningKey {
    SigningKey::from_bytes((&[7; 32]).into()).unwrap()
}
fn prepare(mut cert: Certificate) -> Certificate {
    let public = key().verifying_key().to_public_key_der().unwrap();
    cert.tbs_certificate.subject_public_key_info =
        x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(public.as_bytes()).unwrap();
    cert.tbs_certificate.signature.oid = oid("1.2.840.10045.4.3.2");
    cert.tbs_certificate.signature.parameters = None;
    cert.signature_algorithm = cert.tbs_certificate.signature.clone();
    cert.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .retain(|e| {
            !matches!(
                e.extn_id.to_string().as_str(),
                "2.5.29.35" | "2.5.29.14" | "2.5.29.17" | "2.5.29.31" | "2.5.29.46"
            )
        });
    cert
}
fn sign_certificate(mut cert: Certificate) -> Certificate {
    let signature: Signature = key().sign(&cert.tbs_certificate.to_der().unwrap());
    cert.signature = der::asn1::BitString::from_bytes(signature.to_der().as_bytes()).unwrap();
    Certificate::from_der(&cert.to_der().unwrap()).unwrap()
}
fn templates() -> (Certificate, Certificate) {
    let cms = signed::verify_signed_data(
        include_bytes!("fixtures/catalog.cat"),
        "1.3.6.1.4.1.311.10.1",
    )
    .unwrap();
    (
        prepare(Certificate::from_der(&cms.signers[0].certificate_der).unwrap()),
        prepare(Certificate::from_der(include_bytes!("fixtures/root.der")).unwrap()),
    )
}
fn flags(bits: u16) -> FlagSet<Reasons> {
    FlagSet::<Reasons>::new_truncated(bits)
}
fn uri(s: &str) -> GeneralName {
    GeneralName::UniformResourceIdentifier(der::asn1::Ia5String::new(s).unwrap())
}
fn full_name(s: &str) -> DistributionPointName {
    DistributionPointName::FullName(vec![uri(s)])
}
fn name(s: &str) -> Name {
    s.parse().unwrap()
}

struct Pki {
    root: Certificate,
    leaf: Certificate,
}
fn pki(points: Option<Vec<DistributionPoint>>) -> Pki {
    let (mut leaf, root) = templates();
    if let Some(points) = points {
        leaf.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(extension(
                "2.5.29.31",
                CrlDistributionPoints(points).to_der().unwrap(),
                false,
            ));
    }
    Pki {
        root: sign_certificate(root),
        leaf: sign_certificate(leaf),
    }
}
fn signer_certificate(pki: &Pki, subject: &str) -> Certificate {
    let mut signer = pki.root.clone();
    signer.tbs_certificate.subject = name(subject);
    signer.tbs_certificate.issuer = pki.root.tbs_certificate.subject.clone();
    signer.tbs_certificate.serial_number = SerialNumber::new(&[77]).unwrap();
    sign_certificate(signer)
}

#[derive(Clone)]
struct Entry {
    serial: SerialNumber,
    reason: Option<CrlReason>,
    certificate_issuer: Option<Name>,
    date: u64,
}
fn entry(cert: &Certificate, reason: Option<CrlReason>) -> Entry {
    Entry {
        serial: cert.tbs_certificate.serial_number.clone(),
        reason,
        certificate_issuer: None,
        date: TIME - 1000,
    }
}
#[derive(Clone)]
struct Crl {
    issuer: Name,
    this_update: u64,
    next_update: Option<u64>,
    entries: Vec<Entry>,
    number: Option<u8>,
    base: Option<u8>,
    idp: Option<IssuingDistributionPoint>,
    extra: Vec<Extension>,
    signing_key: [u8; 32],
}
fn crl(pki: &Pki) -> Crl {
    Crl {
        issuer: pki.root.tbs_certificate.subject.clone(),
        this_update: TIME - 10,
        next_update: Some(TIME + 86_400),
        entries: Vec::new(),
        number: Some(1),
        base: None,
        idp: None,
        extra: Vec::new(),
        signing_key: [7; 32],
    }
}
fn time(seconds: u64) -> Time {
    Time::UtcTime(der::asn1::UtcTime::from_unix_duration(Duration::from_secs(seconds)).unwrap())
}
fn uint(n: u8) -> Vec<u8> {
    Uint::new(&[n]).unwrap().to_der().unwrap()
}
fn idp_extension(idp: &IssuingDistributionPoint) -> Extension {
    extension("2.5.29.28", idp.to_der().unwrap(), true)
}
impl Crl {
    fn der(&self) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(n) = self.number {
            extensions.push(extension("2.5.29.20", uint(n), false));
        }
        if let Some(n) = self.base {
            extensions.push(extension("2.5.29.27", uint(n), true));
        }
        if let Some(idp) = &self.idp {
            extensions.push(idp_extension(idp));
        }
        extensions.extend(self.extra.clone());
        let revoked = self
            .entries
            .iter()
            .map(|e| {
                let mut extensions = Vec::new();
                if let Some(reason) = e.reason {
                    extensions.push(extension("2.5.29.21", reason.to_der().unwrap(), false));
                }
                if let Some(issuer) = &e.certificate_issuer {
                    extensions.push(extension(
                        "2.5.29.29",
                        vec![GeneralName::DirectoryName(issuer.clone())]
                            .to_der()
                            .unwrap(),
                        true,
                    ));
                }
                RevokedCert {
                    serial_number: e.serial.clone(),
                    revocation_date: time(e.date),
                    crl_entry_extensions: (!extensions.is_empty()).then_some(extensions),
                }
            })
            .collect::<Vec<_>>();
        let algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
            oid: oid("1.2.840.10045.4.3.2"),
            parameters: None,
        };
        let tbs = TbsCertList {
            version: x509_cert::certificate::Version::V2,
            signature: algorithm.clone(),
            issuer: self.issuer.clone(),
            this_update: time(self.this_update),
            next_update: self.next_update.map(time),
            revoked_certificates: (!revoked.is_empty()).then_some(revoked),
            crl_extensions: (!extensions.is_empty()).then_some(extensions),
        };
        let signing = SigningKey::from_bytes((&self.signing_key).into()).unwrap();
        let signature: Signature = signing.sign(&tbs.to_der().unwrap());
        CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: algorithm,
            signature: der::asn1::BitString::from_bytes(signature.to_der().as_bytes()).unwrap(),
        }
        .to_der()
        .unwrap()
    }
}

fn evaluate(pki: &Pki, crls: &[Vec<u8>], signers: &[Certificate]) -> revocation::CertificateStatus {
    let path = vec![pki.leaf.to_der().unwrap(), pki.root.to_der().unwrap()];
    let signers = signers
        .iter()
        .map(|c| c.to_der().unwrap())
        .collect::<Vec<_>>();
    let report = revocation::verify_chain_revocation_with_signers(
        &path,
        crls,
        &[],
        &signers,
        TIME,
        TIME,
        RevocationLimits::default(),
    )
    .unwrap();
    report.certificates.into_iter().next().unwrap()
}
fn status(pki: &Pki, crls: &[Vec<u8>]) -> RevocationStatus {
    evaluate(pki, crls, &[]).status
}
fn idp() -> IssuingDistributionPoint {
    IssuingDistributionPoint {
        distribution_point: None,
        only_contains_user_certs: false,
        only_contains_ca_certs: false,
        only_some_reasons: None,
        indirect_crl: false,
        only_contains_attribute_certs: false,
    }
}
fn point(location: Option<&str>) -> DistributionPoint {
    DistributionPoint {
        distribution_point: location.map(full_name),
        reasons: None,
        crl_issuer: None,
    }
}

#[test]
fn direct_complete_crl_is_good_revoked_or_stale() {
    let p = pki(None);
    let good = crl(&p);
    assert_eq!(status(&p, &[good.der()]), RevocationStatus::Good);
    let mut revoked = crl(&p);
    revoked.entries.push(entry(&p.leaf, None));
    assert_eq!(status(&p, &[revoked.der()]), RevocationStatus::Revoked);
    let mut stale = crl(&p);
    stale.next_update = Some(TIME - 5);
    assert_eq!(status(&p, &[stale.der()]), RevocationStatus::Unknown);
    // A stale CRL that lists the certificate still revokes.
    stale
        .entries
        .push(entry(&p.leaf, Some(CrlReason::KeyCompromise)));
    assert_eq!(status(&p, &[stale.der()]), RevocationStatus::Revoked);
    let mut missing_next = crl(&p);
    missing_next.next_update = None;
    assert_eq!(status(&p, &[missing_next.der()]), RevocationStatus::Unknown);
}

#[test]
fn single_crl_wrapper_reports_unknown_as_error() {
    let p = pki(None);
    let limits = RevocationLimits::default();
    let ok = revocation::verify_crl(&crl(&p).der(), &p.leaf, &p.root, TIME, limits).unwrap();
    assert_eq!(ok, RevocationStatus::Good);
    let mut delta = crl(&p);
    delta.base = Some(0);
    delta.number = Some(2);
    assert!(revocation::verify_crl(&delta.der(), &p.leaf, &p.root, TIME, limits).is_err());
    let mut partial = crl(&p);
    partial.idp = Some(IssuingDistributionPoint {
        only_some_reasons: Some(flags(0x2)),
        ..idp()
    });
    assert!(revocation::verify_crl(&partial.der(), &p.leaf, &p.root, TIME, limits).is_err());
}

#[test]
fn issuing_distribution_point_scope_decides_completeness() {
    let p = pki(None);
    let scoped = |idp: IssuingDistributionPoint| {
        let mut c = crl(&p);
        c.idp = Some(idp);
        c.der()
    };
    // The certificate is an end entity.
    assert_eq!(
        status(
            &p,
            &[scoped(IssuingDistributionPoint {
                only_contains_user_certs: true,
                ..idp()
            })]
        ),
        RevocationStatus::Good
    );
    for excluded in [
        IssuingDistributionPoint {
            only_contains_ca_certs: true,
            ..idp()
        },
        IssuingDistributionPoint {
            only_contains_attribute_certs: true,
            ..idp()
        },
        // A distribution point name cannot match a certificate without one.
        IssuingDistributionPoint {
            distribution_point: Some(full_name("http://crl.test/a.crl")),
            ..idp()
        },
    ] {
        assert_eq!(status(&p, &[scoped(excluded)]), RevocationStatus::Unknown);
    }
    // Reason partitions combine; a gap leaves the status unknown.
    let key_compromise = scoped(IssuingDistributionPoint {
        only_some_reasons: Some(flags(0x2)),
        ..idp()
    });
    let others = scoped(IssuingDistributionPoint {
        only_some_reasons: Some(flags(ALL & !0x2)),
        ..idp()
    });
    assert_eq!(
        status(&p, std::slice::from_ref(&key_compromise)),
        RevocationStatus::Unknown
    );
    assert_eq!(
        status(&p, &[key_compromise, others]),
        RevocationStatus::Good
    );
    let gap = scoped(IssuingDistributionPoint {
        only_some_reasons: Some(flags(ALL & !0x2 & !0x4)),
        ..idp()
    });
    let kc = scoped(IssuingDistributionPoint {
        only_some_reasons: Some(flags(0x2)),
        ..idp()
    });
    assert_eq!(status(&p, &[kc, gap]), RevocationStatus::Unknown);
}

#[test]
fn certificate_distribution_point_names_and_reasons_bind_the_crl() {
    let located = pki(Some(vec![point(Some("http://crl.test/a.crl"))]));
    let named = |location: &str| {
        let mut c = crl(&located);
        c.idp = Some(IssuingDistributionPoint {
            distribution_point: Some(full_name(location)),
            ..idp()
        });
        c.der()
    };
    assert_eq!(
        status(&located, &[named("http://crl.test/a.crl")]),
        RevocationStatus::Good
    );
    assert_eq!(
        status(&located, &[named("http://crl.test/b.crl")]),
        RevocationStatus::Unknown
    );
    // A CRL without an IDP is complete regardless of the name.
    assert_eq!(
        status(&located, &[crl(&located).der()]),
        RevocationStatus::Good
    );
    // The distribution point's reasons limit what the CRL may be trusted for.
    let limited = pki(Some(vec![DistributionPoint {
        reasons: Some(flags(0x2)),
        ..point(Some("http://crl.test/a.crl"))
    }]));
    assert_eq!(
        status(&limited, &[crl(&limited).der()]),
        RevocationStatus::Unknown
    );
}

#[test]
fn indirect_crl_requires_cert_authorization_and_certificate_issuer_entries() {
    let crl_issuer = name("CN=CRL Signer");
    let p = pki(Some(vec![DistributionPoint {
        distribution_point: None,
        reasons: None,
        crl_issuer: Some(vec![GeneralName::DirectoryName(crl_issuer.clone())]),
    }]));
    let signer = signer_certificate(&p, "CN=CRL Signer");
    let indirect = |entries: Vec<Entry>| {
        let mut c = crl(&p);
        c.issuer = crl_issuer.clone();
        c.idp = Some(IssuingDistributionPoint {
            indirect_crl: true,
            ..idp()
        });
        c.entries = entries;
        c.der()
    };
    let on_behalf = |reason| Entry {
        certificate_issuer: Some(p.root.tbs_certificate.subject.clone()),
        ..entry(&p.leaf, reason)
    };
    let signers = std::slice::from_ref(&signer);
    let listed = evaluate(&p, &[indirect(vec![on_behalf(None)])], signers);
    assert_eq!(listed.status, RevocationStatus::Revoked);
    let clean = evaluate(&p, &[indirect(vec![])], signers);
    assert_eq!(clean.status, RevocationStatus::Good);
    // Entries without certificateIssuer belong to the CRL issuer's own namespace.
    let own = evaluate(&p, &[indirect(vec![entry(&p.leaf, None)])], signers);
    assert_eq!(own.status, RevocationStatus::Good);
    // The signing certificate must be supplied.
    let unsigned = evaluate(&p, &[indirect(vec![])], &[]);
    assert_eq!(unsigned.status, RevocationStatus::Unknown);
    assert!(unsigned.diagnostics.iter().any(|d| d.contains("CRL")));
    // A signer not issued by the certificate issuer is not authorized.
    let mut foreign = signer.clone();
    foreign.tbs_certificate.issuer = name("CN=Someone Else");
    let foreign = sign_certificate(foreign);
    assert_eq!(
        evaluate(&p, &[indirect(vec![on_behalf(None)])], &[foreign]).status,
        RevocationStatus::Unknown
    );
    // The certificate must name this CRL issuer.
    let plain = pki(None);
    let plain_signer = signer_certificate(&plain, "CN=CRL Signer");
    let mut other = crl(&plain);
    other.issuer = crl_issuer.clone();
    other.idp = Some(IssuingDistributionPoint {
        indirect_crl: true,
        ..idp()
    });
    other.entries = vec![Entry {
        certificate_issuer: Some(plain.root.tbs_certificate.subject.clone()),
        ..entry(&plain.leaf, None)
    }];
    assert_eq!(
        evaluate(&plain, &[other.der()], &[plain_signer]).status,
        RevocationStatus::Unknown
    );
    // A CRL naming another issuer must assert indirectCRL.
    let mut direct_flag = crl(&p);
    direct_flag.issuer = crl_issuer.clone();
    assert_eq!(
        evaluate(&p, &[direct_flag.der()], signers).status,
        RevocationStatus::Unknown
    );
}

#[test]
fn delta_crls_extend_a_base_crl() {
    let p = pki(None);
    let base = |entries: Vec<Entry>| {
        let mut c = crl(&p);
        c.number = Some(5);
        c.entries = entries;
        c
    };
    let delta = |entries: Vec<Entry>, base_number: u8, number: u8| {
        let mut c = crl(&p);
        c.number = Some(number);
        c.base = Some(base_number);
        c.entries = entries;
        c
    };
    let hold = entry(&p.leaf, Some(CrlReason::CertificateHold));
    let release = entry(&p.leaf, Some(CrlReason::RemoveFromCRL));
    let key_compromise = entry(&p.leaf, Some(CrlReason::KeyCompromise));

    // A delta addition revokes, with or without its base.
    let added = delta(vec![key_compromise.clone()], 5, 6).der();
    assert_eq!(
        status(&p, &[base(vec![]).der(), added.clone()]),
        RevocationStatus::Revoked
    );
    assert_eq!(status(&p, &[added]), RevocationStatus::Revoked);
    // A delta alone cannot prove absence.
    assert_eq!(
        status(&p, &[delta(vec![], 5, 6).der()]),
        RevocationStatus::Unknown
    );
    // A hold is revocation until a delta releases it.
    assert_eq!(
        status(&p, &[base(vec![hold.clone()]).der()]),
        RevocationStatus::Revoked
    );
    let released = delta(vec![release.clone()], 5, 6).der();
    assert_eq!(
        status(&p, &[base(vec![hold.clone()]).der(), released.clone()]),
        RevocationStatus::Good
    );
    // removeFromCRL never releases a permanent revocation.
    assert_eq!(
        status(
            &p,
            &[base(vec![key_compromise.clone()]).der(), released.clone()]
        ),
        RevocationStatus::Revoked
    );
    // A delta computed against a newer base does not apply to this base.
    let newer = delta(vec![release.clone()], 7, 8).der();
    assert_eq!(
        status(&p, &[base(vec![hold.clone()]).der(), newer]),
        RevocationStatus::Revoked
    );
    // The delta must be newer than the base.
    let not_newer = delta(vec![release.clone()], 4, 5).der();
    assert_eq!(
        status(&p, &[base(vec![hold.clone()]).der(), not_newer]),
        RevocationStatus::Revoked
    );
    // Only the newest delta on a base counts.
    let hold_again = delta(vec![hold.clone()], 5, 7).der();
    assert_eq!(
        status(
            &p,
            &[base(vec![hold.clone()]).der(), released.clone(), hold_again]
        ),
        RevocationStatus::Revoked
    );
    // A fresh delta carries a stale base.
    let mut stale_base = base(vec![hold.clone()]);
    stale_base.next_update = Some(TIME - 5);
    assert_eq!(
        status(&p, &[stale_base.der(), released.clone()]),
        RevocationStatus::Good
    );
    // The delta must share the base's issuing distribution point.
    let mut scoped_base = base(vec![hold]);
    scoped_base.idp = Some(IssuingDistributionPoint {
        only_contains_user_certs: true,
        ..idp()
    });
    assert_eq!(
        status(&p, &[scoped_base.der(), released]),
        RevocationStatus::Revoked
    );
}

#[test]
fn evidence_and_diagnostics_identify_the_crls_used() {
    let p = pki(None);
    let mut base = crl(&p);
    base.number = Some(5);
    let mut delta = crl(&p);
    delta.number = Some(6);
    delta.base = Some(5);
    let (base, delta) = (base.der(), delta.der());
    let mut forged = crl(&p);
    forged.signing_key = [9; 32];
    let forged = forged.der();
    let report = evaluate(&p, &[base.clone(), delta.clone(), forged], &[]);
    assert_eq!(report.status, RevocationStatus::Good);
    let hash = |bytes: &[u8]| {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(bytes))
    };
    assert!(report.evidence_sha256.contains(&hash(&base)));
    assert!(report.evidence_sha256.contains(&hash(&delta)));
    assert_eq!(report.evidence_sha256.len(), 2);
    assert!(report.diagnostics.iter().any(|d| d.contains("CRL 2")));
}

#[test]
fn malformed_and_unauthenticated_crls_are_ignored_not_trusted() {
    let p = pki(None);
    let rejected = |c: Crl| status(&p, &[c.der()]);
    let mut duplicate = crl(&p);
    duplicate.entries = vec![entry(&p.leaf, None), entry(&p.leaf, None)];
    // The duplicate list is unusable, so even the revocation is not trusted.
    assert_eq!(rejected(duplicate), RevocationStatus::Unknown);
    let mut future = crl(&p);
    future.entries = vec![Entry {
        date: TIME + 3600,
        ..entry(&p.leaf, None)
    }];
    assert_eq!(rejected(future), RevocationStatus::Unknown);
    let mut wrong_key = crl(&p);
    wrong_key.signing_key = [9; 32];
    assert_eq!(rejected(wrong_key), RevocationStatus::Unknown);
    let mut unknown_critical = crl(&p);
    unknown_critical.extra = vec![extension("1.2.3.4", vec![5, 0], true)];
    assert_eq!(rejected(unknown_critical), RevocationStatus::Unknown);
    let mut other_issuer = crl(&p);
    other_issuer.issuer = name("CN=Other");
    assert_eq!(rejected(other_issuer), RevocationStatus::Unknown);
    let mut certificate_issuer_in_direct = crl(&p);
    certificate_issuer_in_direct.entries = vec![Entry {
        certificate_issuer: Some(p.root.tbs_certificate.subject.clone()),
        ..entry(&p.leaf, None)
    }];
    assert_eq!(
        rejected(certificate_issuer_in_direct),
        RevocationStatus::Unknown
    );
    let mut conflicting = crl(&p);
    conflicting.idp = Some(IssuingDistributionPoint {
        only_contains_user_certs: true,
        only_contains_ca_certs: true,
        ..idp()
    });
    assert_eq!(rejected(conflicting), RevocationStatus::Unknown);
    let mut invalid_delta = crl(&p);
    invalid_delta.base = Some(9);
    invalid_delta.number = Some(2);
    assert_eq!(rejected(invalid_delta), RevocationStatus::Unknown);
}

#[test]
#[ignore = "independent OpenSSL oracle; invoke explicitly in the development shell"]
fn openssl_agrees_on_crl_outcomes() {
    struct Case {
        name: &'static str,
        pki: Pki,
        crls: Vec<Vec<u8>>,
        extra: Vec<&'static str>,
        expected: bool,
    }
    let p = || pki(None);
    let mut cases = Vec::new();
    {
        let p = p();
        let good = crl(&p).der();
        cases.push(Case {
            name: "good",
            pki: p,
            crls: vec![good],
            extra: vec![],
            expected: true,
        });
    }
    {
        let p = p();
        let mut c = crl(&p);
        c.entries.push(entry(&p.leaf, None));
        let der = c.der();
        cases.push(Case {
            name: "revoked",
            pki: p,
            crls: vec![der],
            extra: vec![],
            expected: false,
        });
    }
    {
        let p = p();
        let mut base = crl(&p);
        base.number = Some(5);
        base.entries = vec![entry(&p.leaf, Some(CrlReason::CertificateHold))];
        // OpenSSL only looks for a delta when the base advertises one.
        base.extra = vec![extension(
            "2.5.29.46",
            x509_cert::ext::pkix::FreshestCrl(vec![point(Some("http://crl.test/delta.crl"))])
                .to_der()
                .unwrap(),
            false,
        )];
        let mut delta = crl(&p);
        delta.number = Some(6);
        delta.base = Some(5);
        delta.entries = vec![entry(&p.leaf, Some(CrlReason::RemoveFromCRL))];
        let crls = vec![base.der(), delta.der()];
        cases.push(Case {
            name: "released hold",
            pki: p,
            crls,
            extra: vec!["-use_deltas"],
            expected: true,
        });
    }
    {
        let p = p();
        let mut base = crl(&p);
        base.number = Some(5);
        base.entries = vec![entry(&p.leaf, Some(CrlReason::CertificateHold))];
        let der = base.der();
        cases.push(Case {
            name: "unreleased hold",
            pki: p,
            crls: vec![der],
            extra: vec!["-use_deltas"],
            expected: false,
        });
    }
    let scoped = |idp: IssuingDistributionPoint, p: &Pki| {
        let mut c = crl(p);
        c.idp = Some(idp);
        c.der()
    };
    for (name, idps, expected) in [
        (
            "user certs only",
            vec![IssuingDistributionPoint {
                only_contains_user_certs: true,
                ..idp()
            }],
            true,
        ),
        (
            "ca certs only",
            vec![IssuingDistributionPoint {
                only_contains_ca_certs: true,
                ..idp()
            }],
            false,
        ),
        (
            "partial reasons",
            vec![IssuingDistributionPoint {
                only_some_reasons: Some(flags(0x2)),
                ..idp()
            }],
            false,
        ),
        (
            "reason union",
            vec![
                IssuingDistributionPoint {
                    only_some_reasons: Some(flags(0x2)),
                    ..idp()
                },
                IssuingDistributionPoint {
                    only_some_reasons: Some(flags(ALL & !0x2)),
                    ..idp()
                },
            ],
            true,
        ),
    ] {
        let p = p();
        let crls = idps.into_iter().map(|i| scoped(i, &p)).collect();
        cases.push(Case {
            name,
            pki: p,
            crls,
            extra: vec!["-extended_crl"],
            expected,
        });
    }
    {
        let p = p();
        let mut stale = crl(&p);
        stale.next_update = Some(TIME - 5);
        let der = stale.der();
        cases.push(Case {
            name: "stale",
            pki: p,
            crls: vec![der],
            extra: vec![],
            expected: false,
        });
    }
    for case in cases {
        let directory = tempfile::tempdir().unwrap();
        let pem = |bytes: &[u8]| {
            Certificate::from_der(bytes)
                .unwrap()
                .to_pem(der::pem::LineEnding::LF)
                .unwrap()
        };
        std::fs::write(
            directory.path().join("leaf.pem"),
            pem(&case.pki.leaf.to_der().unwrap()),
        )
        .unwrap();
        std::fs::write(
            directory.path().join("root.pem"),
            pem(&case.pki.root.to_der().unwrap()),
        )
        .unwrap();
        let crl_pem = case
            .crls
            .iter()
            .map(|der| der::pem::encode_string("X509 CRL", der::pem::LineEnding::LF, der).unwrap())
            .collect::<String>();
        std::fs::write(directory.path().join("crls.pem"), crl_pem).unwrap();
        let output = std::process::Command::new("openssl")
            .args([
                "verify",
                "-purpose",
                "any",
                "-crl_check",
                "-attime",
                &TIME.to_string(),
            ])
            .args(&case.extra)
            .arg("-CAfile")
            .arg(directory.path().join("root.pem"))
            .arg("-CRLfile")
            .arg(directory.path().join("crls.pem"))
            .arg(directory.path().join("leaf.pem"))
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            case.expected,
            "OpenSSL {}: {}{}",
            case.name,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let ours = evaluate(&case.pki, &case.crls, &[]).status;
        assert_eq!(
            ours == RevocationStatus::Good,
            case.expected,
            "wintrust {}",
            case.name
        );
    }
}
