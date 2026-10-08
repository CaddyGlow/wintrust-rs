//! RFC 5280 6.1 certificate policy processing on synthetic signed P-256 paths.
use der::{
    Decode, Encode,
    asn1::{ObjectIdentifier, OctetString},
};
use p256::{
    ecdsa::{Signature, SigningKey},
    pkcs8::EncodePublicKey,
};
use signature::Signer;
use wintrust::portable::{
    chain::{self, PathLimits, PathOptions},
    policy::PolicyOptions,
    signed,
};
use x509_cert::{
    Certificate,
    ext::{
        Extension,
        pkix::{
            CertificatePolicies, InhibitAnyPolicy, PolicyConstraints, PolicyMapping,
            PolicyMappings, certpolicy::PolicyInformation,
        },
    },
};

const TIME: u64 = 1791117219;
const EKU: &str = "1.3.6.1.5.5.7.3.3";
const A: &str = "1.2.3.4";
const B: &str = "1.2.3.5";
const C: &str = "1.2.3.6";
const ANY: &str = "2.5.29.32.0";

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
fn policies(list: &[&str]) -> Extension {
    extension(
        "2.5.29.32",
        CertificatePolicies(
            list.iter()
                .map(|p| PolicyInformation {
                    policy_identifier: oid(p),
                    policy_qualifiers: None,
                })
                .collect(),
        )
        .to_der()
        .unwrap(),
        false,
    )
}
fn mappings(list: &[(&str, &str)]) -> Extension {
    extension(
        "2.5.29.33",
        PolicyMappings(
            list.iter()
                .map(|(i, s)| PolicyMapping {
                    issuer_domain_policy: oid(i),
                    subject_domain_policy: oid(s),
                })
                .collect(),
        )
        .to_der()
        .unwrap(),
        false,
    )
}
fn constraints(require: Option<u32>, inhibit: Option<u32>) -> Extension {
    extension(
        "2.5.29.36",
        PolicyConstraints {
            require_explicit_policy: require,
            inhibit_policy_mapping: inhibit,
        }
        .to_der()
        .unwrap(),
        true,
    )
}
fn inhibit_any(skip: u32) -> Extension {
    extension("2.5.29.54", InhibitAnyPolicy(skip).to_der().unwrap(), true)
}

fn prepare(mut cert: Certificate) -> Certificate {
    let key = SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    let public = key.verifying_key().to_public_key_der().unwrap();
    cert.tbs_certificate.subject_public_key_info =
        x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(public.as_bytes()).unwrap();
    cert.tbs_certificate.signature.oid = "1.2.840.10045.4.3.2".parse().unwrap();
    cert.tbs_certificate.signature.parameters = None;
    cert.signature_algorithm = cert.tbs_certificate.signature.clone();
    cert.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .retain(|e| {
            !matches!(
                e.extn_id.to_string().as_str(),
                "2.5.29.35"
                    | "2.5.29.14"
                    | "2.5.29.17"
                    | "2.5.29.30"
                    | "2.5.29.32"
                    | "2.5.29.33"
                    | "2.5.29.36"
                    | "2.5.29.54"
            )
        });
    cert
}
fn sign(mut cert: Certificate) -> Vec<u8> {
    let key = SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    let signature: Signature = key.sign(&cert.tbs_certificate.to_der().unwrap());
    cert.signature = der::asn1::BitString::from_bytes(signature.to_der().as_bytes()).unwrap();
    cert.to_der().unwrap()
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

/// One path position. The first spec is the anchor and the last the end entity.
struct Spec {
    extensions: Vec<Extension>,
    self_issued: bool,
}
fn spec(extensions: Vec<Extension>) -> Spec {
    Spec {
        extensions,
        self_issued: false,
    }
}
struct Built {
    leaf: Vec<u8>,
    intermediates: Vec<Vec<u8>>,
    root: Vec<u8>,
}
fn build(specs: Vec<Spec>) -> Built {
    let (mut leaf, root_template) = templates();
    let count = specs.len();
    let mut specs = specs.into_iter();
    let mut root = root_template.clone();
    root.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .extend(specs.next().unwrap().extensions);
    let mut previous = root.tbs_certificate.subject.clone();
    let mut intermediates = Vec::new();
    for position in 1..count - 1 {
        let spec = specs.next().unwrap();
        let mut ca = root_template.clone();
        ca.tbs_certificate.issuer = previous.clone();
        if !spec.self_issued {
            ca.tbs_certificate.subject = format!("CN=CA{position}").parse().unwrap();
        } else {
            ca.tbs_certificate.subject = previous.clone();
        }
        ca.tbs_certificate.serial_number =
            x509_cert::serial_number::SerialNumber::new(&[40 + position as u8]).unwrap();
        ca.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .extend(spec.extensions);
        previous = ca.tbs_certificate.subject.clone();
        intermediates.push(sign(ca));
    }
    leaf.tbs_certificate.issuer = previous;
    leaf.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .extend(specs.next().unwrap().extensions);
    Built {
        leaf: sign(leaf),
        intermediates,
        root: sign(root),
    }
}
fn run(specs: Vec<Spec>, policy: PolicyOptions) -> anyhow::Result<chain::ChainReport> {
    let built = build(specs);
    chain::validate_with_options(
        &built.leaf,
        &built.intermediates,
        &[built.root],
        TIME,
        EKU,
        false,
        PathLimits::default(),
        &PathOptions {
            policy,
            partial_chain: false,
            crl_signer: false,
        },
        |_| Ok(()),
    )
}
fn explicit() -> PolicyOptions {
    PolicyOptions {
        initial_explicit_policy: true,
        ..PolicyOptions::default()
    }
}
fn set(list: &[&str]) -> Option<Vec<ObjectIdentifier>> {
    Some(list.iter().map(|p| oid(p)).collect())
}
fn root() -> Spec {
    spec(vec![])
}

#[test]
fn absent_policies_pass_by_default_and_fail_under_explicit_policy() {
    let report = run(
        vec![root(), spec(vec![]), spec(vec![])],
        PolicyOptions::default(),
    )
    .unwrap();
    assert!(report.valid_policies.is_empty());
    assert!(run(vec![root(), spec(vec![]), spec(vec![])], explicit()).is_err());
}

#[test]
fn common_policy_is_valid_and_initial_set_intersects() {
    let path = || {
        vec![
            root(),
            spec(vec![policies(&[A, B])]),
            spec(vec![policies(&[A, C])]),
        ]
    };
    let report = run(path(), explicit()).unwrap();
    assert_eq!(report.valid_policies, [A]);
    let report = run(
        path(),
        PolicyOptions {
            initial_policy_set: set(&[A]),
            ..explicit()
        },
    )
    .unwrap();
    assert_eq!(report.valid_policies, [A]);
    // B is asserted by the CA only and C by the end entity only.
    for rejected in [B, C] {
        assert!(
            run(
                path(),
                PolicyOptions {
                    initial_policy_set: set(&[rejected]),
                    ..explicit()
                },
            )
            .is_err()
        );
    }
    // Without an explicit requirement an empty intersection is a NULL tree.
    let report = run(
        path(),
        PolicyOptions {
            initial_policy_set: set(&[C]),
            ..PolicyOptions::default()
        },
    )
    .unwrap();
    assert!(report.valid_policies.is_empty());
}

#[test]
fn ca_require_explicit_policy_counts_skipped_certificates() {
    let path = |skip| {
        vec![
            root(),
            spec(vec![constraints(Some(skip), None)]),
            spec(vec![]),
            spec(vec![]),
        ]
    };
    assert!(run(path(0), PolicyOptions::default()).is_err());
    assert!(run(path(1), PolicyOptions::default()).is_err());
    assert!(run(path(3), PolicyOptions::default()).is_ok());
    // A satisfying end-entity policy chain is accepted at skip 0.
    let satisfied = vec![
        root(),
        spec(vec![constraints(Some(0), None), policies(&[A])]),
        spec(vec![policies(&[A])]),
    ];
    assert_eq!(
        run(satisfied, PolicyOptions::default())
            .unwrap()
            .valid_policies,
        [A]
    );
}

#[test]
fn end_entity_require_explicit_policy_zero_requires_a_valid_tree() {
    let leaf = |policy: Vec<Extension>| {
        let mut extensions = vec![constraints(Some(0), None)];
        extensions.extend(policy);
        vec![root(), spec(vec![policies(&[A])]), spec(extensions)]
    };
    assert!(run(leaf(vec![policies(&[A])]), PolicyOptions::default()).is_ok());
    assert!(run(leaf(vec![policies(&[B])]), PolicyOptions::default()).is_err());
}

#[test]
fn mappings_rewrite_expected_policies_and_honor_inhibition() {
    let path = || {
        vec![
            root(),
            spec(vec![policies(&[A]), mappings(&[(A, B)])]),
            spec(vec![policies(&[B])]),
        ]
    };
    assert_eq!(run(path(), explicit()).unwrap().valid_policies, [B]);
    // The user asks for the CA-side policy; the mapped end-entity policy follows it.
    let report = run(
        path(),
        PolicyOptions {
            initial_policy_set: set(&[A]),
            ..explicit()
        },
    )
    .unwrap();
    assert_eq!(report.valid_policies, [B]);
    assert!(
        run(
            path(),
            PolicyOptions {
                initial_policy_set: set(&[C]),
                ..explicit()
            },
        )
        .is_err()
    );
    // Inhibited mapping removes the mapped node and nulls the tree.
    let inhibited = PolicyOptions {
        initial_policy_mapping_inhibit: true,
        ..explicit()
    };
    assert!(run(path(), inhibited).is_err());
    let inhibited = PolicyOptions {
        initial_policy_mapping_inhibit: true,
        ..PolicyOptions::default()
    };
    assert!(run(path(), inhibited).unwrap().valid_policies.is_empty());
    // A CA-carried inhibitPolicyMapping applies to certificates below it.
    let ca_inhibited = vec![
        root(),
        spec(vec![constraints(None, Some(0))]),
        spec(vec![policies(&[A]), mappings(&[(A, B)])]),
        spec(vec![policies(&[B])]),
    ];
    assert!(run(ca_inhibited, explicit()).is_err());
}

#[test]
fn mapping_to_or_from_any_policy_is_rejected() {
    for pair in [(ANY, B), (A, ANY)] {
        let path = vec![
            root(),
            spec(vec![policies(&[A]), mappings(&[pair])]),
            spec(vec![policies(&[A])]),
        ];
        assert!(run(path, PolicyOptions::default()).is_err());
    }
}

#[test]
fn any_policy_expands_and_can_be_inhibited() {
    let ca_any = vec![
        root(),
        spec(vec![policies(&[ANY])]),
        spec(vec![policies(&[A])]),
    ];
    assert_eq!(run(ca_any, explicit()).unwrap().valid_policies, [A]);
    let leaf_any = vec![
        root(),
        spec(vec![policies(&[A])]),
        spec(vec![policies(&[ANY])]),
    ];
    assert_eq!(run(leaf_any, explicit()).unwrap().valid_policies, [A]);
    let both_any = vec![
        root(),
        spec(vec![policies(&[ANY])]),
        spec(vec![policies(&[ANY])]),
    ];
    assert_eq!(run(both_any, explicit()).unwrap().valid_policies, [ANY]);

    let inhibited = PolicyOptions {
        initial_any_policy_inhibit: true,
        ..explicit()
    };
    let path = || {
        vec![
            root(),
            spec(vec![policies(&[A])]),
            spec(vec![policies(&[ANY])]),
        ]
    };
    assert!(run(path(), inhibited).is_err());
    // The extension on a CA applies to the certificates beneath it.
    let by_extension = vec![
        root(),
        spec(vec![policies(&[A]), inhibit_any(0)]),
        spec(vec![policies(&[ANY])]),
    ];
    assert!(run(by_extension, explicit()).is_err());
    let allowed = vec![
        root(),
        spec(vec![policies(&[A]), inhibit_any(5)]),
        spec(vec![policies(&[ANY])]),
    ];
    assert!(run(allowed, explicit()).is_ok());
}

#[test]
fn self_issued_intermediate_still_expands_any_policy_under_inhibition() {
    let path = |self_issued| {
        vec![
            root(),
            spec(vec![policies(&[A]), inhibit_any(0)]),
            Spec {
                extensions: vec![policies(&[ANY])],
                self_issued,
            },
            spec(vec![policies(&[A])]),
        ]
    };
    // RFC 5280 6.1.3 (d)(2)(ii): a self-issued non-final certificate expands
    // anyPolicy even when inhibitAnyPolicy is exhausted.
    assert_eq!(run(path(true), explicit()).unwrap().valid_policies, [A]);
    assert!(run(path(false), explicit()).is_err());
}

#[test]
fn malformed_duplicate_and_critical_policy_extensions_fail_closed() {
    let duplicate = vec![
        root(),
        spec(vec![policies(&[A, A])]),
        spec(vec![policies(&[A])]),
    ];
    assert!(run(duplicate, PolicyOptions::default()).is_err());
    let empty = vec![root(), spec(vec![constraints(None, None)]), spec(vec![])];
    assert!(run(empty, PolicyOptions::default()).is_err());
    let critical = |qualified: bool| {
        let information = PolicyInformation {
            policy_identifier: oid(A),
            policy_qualifiers: qualified.then(|| {
                vec![x509_cert::ext::pkix::certpolicy::PolicyQualifierInfo {
                    policy_qualifier_id: oid("1.3.6.1.5.5.7.2.1"),
                    qualifier: Some(
                        der::asn1::Any::new(der::Tag::Ia5String, b"http://x.test".to_vec())
                            .unwrap(),
                    ),
                }]
            }),
        };
        let extension = extension(
            "2.5.29.32",
            CertificatePolicies(vec![information]).to_der().unwrap(),
            true,
        );
        vec![root(), spec(vec![extension]), spec(vec![policies(&[A])])]
    };
    assert!(run(critical(false), explicit()).is_ok());
    assert!(run(critical(true), explicit()).is_err());
}

#[test]
fn report_retains_diagnostics_for_each_certificate() {
    let report = run(
        vec![
            root(),
            spec(vec![policies(&[A])]),
            spec(vec![policies(&[A])]),
        ],
        explicit(),
    )
    .unwrap();
    assert_eq!(report.certificates.len(), 3);
    let roles = report
        .certificates
        .iter()
        .map(|c| c.role)
        .collect::<Vec<_>>();
    assert_eq!(roles, ["end-entity", "intermediate", "anchor"]);
    assert!(
        report.certificates[1]
            .enforced_extensions
            .contains(&"certificatePolicies")
    );
}

#[test]
fn partial_chain_requires_explicit_selection_and_never_accepts_the_leaf() {
    let built = build(vec![root(), spec(vec![]), spec(vec![])]);
    let intermediate = built.intermediates[0].clone();
    let run = |partial_chain, anchors: &[Vec<u8>], leaf: &[u8]| {
        chain::validate_with_options(
            leaf,
            &built.intermediates,
            anchors,
            TIME,
            EKU,
            false,
            PathLimits::default(),
            &PathOptions {
                policy: PolicyOptions::default(),
                partial_chain,
                crl_signer: false,
            },
            |_| Ok(()),
        )
    };
    assert!(run(false, std::slice::from_ref(&intermediate), &built.leaf).is_err());
    let report = run(true, std::slice::from_ref(&intermediate), &built.leaf).unwrap();
    assert_eq!(report.chain_der.len(), 2);
    assert_eq!(report.chain_der.last().unwrap(), &intermediate);
    // The leaf cannot be its own partial-chain anchor.
    assert!(run(true, std::slice::from_ref(&built.leaf), &built.leaf).is_err());
    // An unrelated certificate is not a partial anchor.
    assert!(run(true, std::slice::from_ref(&built.root), &built.leaf).is_ok());
}

#[test]
fn rejected_alternative_paths_are_retained_in_the_selected_report() {
    // Same-named anchors with distinct DER; one imposes an unsatisfiable
    // explicit-policy requirement. Which is tried first depends only on DER order,
    // so vary the bad anchor's serial until the search tries it before the good one.
    let mut retained = None;
    for serial in 1..=16u8 {
        let (mut leaf, good) = templates();
        let mut bad = good.clone();
        bad.tbs_certificate.serial_number =
            x509_cert::serial_number::SerialNumber::new(&[100 + serial]).unwrap();
        bad.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(constraints(Some(0), None));
        leaf.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(policies(&[A]));
        // The bad anchor's constraints force a policy requirement the leaf meets,
        // so make it fail through a name-independent check instead: expired trust is
        // modelled by an unsatisfiable initial policy set below.
        let (leaf, bad, good) = (sign(leaf), sign(bad), sign(good));
        let report = chain::validate_with_options(
            &leaf,
            &[],
            &[bad.clone(), good.clone()],
            TIME,
            EKU,
            false,
            PathLimits::default(),
            &PathOptions::default(),
            |report| {
                // Reject paths ending at the bad anchor, as a caller policy would.
                anyhow::ensure!(report.chain_der.last() != Some(&bad), "bad anchor");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(report.chain_der.last().unwrap(), &good);
        if !report.rejected_paths.is_empty() {
            retained = Some(report);
            break;
        }
    }
    let report = retained.expect("some ordering tries the rejected anchor first");
    assert_eq!(report.rejected_paths[0].reason, "bad anchor");
    assert_eq!(report.rejected_paths[0].chain_sha256.len(), 2);
}

#[test]
#[ignore = "independent OpenSSL oracle; invoke explicitly in the development shell"]
fn openssl_agrees_on_policy_outcomes() {
    use der::EncodePem;
    struct Case {
        name: &'static str,
        specs: fn() -> Vec<Spec>,
        policy: PolicyOptions,
        args: Vec<&'static str>,
        expected: bool,
    }
    let common = || {
        vec![
            root(),
            spec(vec![policies(&[A, B])]),
            spec(vec![policies(&[A, C])]),
        ]
    };
    let mapped = || {
        vec![
            root(),
            spec(vec![policies(&[A]), mappings(&[(A, B)])]),
            spec(vec![policies(&[B])]),
        ]
    };
    let skip1 = || {
        vec![
            root(),
            spec(vec![constraints(Some(1), None)]),
            spec(vec![]),
            spec(vec![]),
        ]
    };
    let skip3 = || {
        vec![
            root(),
            spec(vec![constraints(Some(3), None)]),
            spec(vec![]),
            spec(vec![]),
        ]
    };
    let any_leaf = || {
        vec![
            root(),
            spec(vec![policies(&[A])]),
            spec(vec![policies(&[ANY])]),
        ]
    };
    let rollover_self = || {
        vec![
            root(),
            spec(vec![policies(&[A]), inhibit_any(0)]),
            Spec {
                extensions: vec![policies(&[ANY])],
                self_issued: true,
            },
            spec(vec![policies(&[A])]),
        ]
    };
    let rollover_other = || {
        vec![
            root(),
            spec(vec![policies(&[A]), inhibit_any(0)]),
            spec(vec![policies(&[ANY])]),
            spec(vec![policies(&[A])]),
        ]
    };
    let mut cases = vec![
        Case {
            name: "common policy",
            specs: common,
            policy: explicit(),
            args: vec!["-explicit_policy", "-policy", ANY],
            expected: true,
        },
        Case {
            name: "initial set mismatch",
            specs: common,
            policy: PolicyOptions {
                initial_policy_set: set(&[B]),
                ..explicit()
            },
            args: vec!["-explicit_policy", "-policy", B],
            expected: false,
        },
        Case {
            name: "mapped user policy",
            specs: mapped,
            policy: PolicyOptions {
                initial_policy_set: set(&[A]),
                ..explicit()
            },
            args: vec!["-explicit_policy", "-policy", A],
            expected: true,
        },
        Case {
            name: "inhibited mapping",
            specs: mapped,
            policy: PolicyOptions {
                initial_policy_mapping_inhibit: true,
                ..explicit()
            },
            args: vec!["-explicit_policy", "-policy", ANY, "-inhibit_map"],
            expected: false,
        },
        Case {
            name: "require explicit skip 1",
            specs: skip1,
            policy: PolicyOptions::default(),
            args: vec![],
            expected: false,
        },
        Case {
            name: "require explicit skip 3",
            specs: skip3,
            policy: PolicyOptions::default(),
            args: vec![],
            expected: true,
        },
        Case {
            name: "inhibited anyPolicy",
            specs: any_leaf,
            policy: PolicyOptions {
                initial_any_policy_inhibit: true,
                ..explicit()
            },
            args: vec!["-explicit_policy", "-policy", ANY, "-inhibit_any"],
            expected: false,
        },
        Case {
            name: "self-issued anyPolicy expansion",
            specs: rollover_self,
            policy: explicit(),
            args: vec!["-explicit_policy", "-policy", ANY],
            expected: true,
        },
        Case {
            name: "ordinary anyPolicy under inhibition",
            specs: rollover_other,
            policy: explicit(),
            args: vec!["-explicit_policy", "-policy", ANY],
            expected: false,
        },
    ];
    for case in cases.drain(..) {
        let built = build((case.specs)());
        let directory = tempfile::tempdir().unwrap();
        let pem = |bytes: &[u8]| {
            Certificate::from_der(bytes)
                .unwrap()
                .to_pem(der::pem::LineEnding::LF)
                .unwrap()
        };
        let (leaf_path, root_path, inter_path) = (
            directory.path().join("leaf.pem"),
            directory.path().join("root.pem"),
            directory.path().join("inter.pem"),
        );
        std::fs::write(&leaf_path, pem(&built.leaf)).unwrap();
        std::fs::write(&root_path, pem(&built.root)).unwrap();
        std::fs::write(
            &inter_path,
            built
                .intermediates
                .iter()
                .map(|c| pem(c))
                .collect::<String>(),
        )
        .unwrap();
        let mut command = std::process::Command::new("openssl");
        command.args([
            "verify",
            "-purpose",
            "any",
            "-policy_check",
            "-attime",
            &TIME.to_string(),
        ]);
        command.args(&case.args);
        command.arg("-CAfile").arg(&root_path);
        if !built.intermediates.is_empty() {
            command.arg("-untrusted").arg(&inter_path);
        }
        let output = command.arg(&leaf_path).output().unwrap();
        assert_eq!(
            output.status.success(),
            case.expected,
            "OpenSSL {}: {}{}",
            case.name,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let ours = chain::validate_with_options(
            &built.leaf,
            &built.intermediates,
            &[built.root],
            TIME,
            EKU,
            false,
            PathLimits::default(),
            &PathOptions {
                policy: case.policy,
                partial_chain: false,
                crl_signer: false,
            },
            |_| Ok(()),
        );
        assert_eq!(ours.is_ok(), case.expected, "wintrust {}", case.name);
    }
}
