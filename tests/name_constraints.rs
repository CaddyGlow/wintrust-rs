//! Synthetic P-256 signed paths exercise RFC5280 name constraints without
//! trusting certificate names or weakening certificate signature checks.
mod support;
#[cfg(feature = "std")]
use der::Decode;
#[cfg(feature = "std")]
use der::EncodePem;
use der::{
    Encode,
    asn1::{Ia5String, OctetString},
};
use support::{extension, sign};
use wintrust::portable::chain;
use x509_cert::{
    Certificate,
    ext::pkix::{
        NameConstraints, SubjectAltName, constraints::name::GeneralSubtree, name::GeneralName,
    },
};

const TIME: u64 = 1791117219;
const EKU: &str = "1.3.6.1.5.5.7.3.3";
fn dns(s: &str) -> GeneralName {
    GeneralName::DnsName(Ia5String::new(s).unwrap())
}
fn email(s: &str) -> GeneralName {
    GeneralName::Rfc822Name(Ia5String::new(s).unwrap())
}
fn uri(s: &str) -> GeneralName {
    GeneralName::UniformResourceIdentifier(Ia5String::new(s).unwrap())
}
fn ip(bytes: &[u8]) -> GeneralName {
    GeneralName::IpAddress(OctetString::new(bytes).unwrap())
}
fn subtree(base: GeneralName) -> GeneralSubtree {
    GeneralSubtree {
        base,
        minimum: 0,
        maximum: None,
    }
}
fn constraints(permitted: Vec<GeneralName>, excluded: Vec<GeneralName>) -> NameConstraints {
    NameConstraints {
        permitted_subtrees: (!permitted.is_empty())
            .then(|| permitted.into_iter().map(subtree).collect()),
        excluded_subtrees: (!excluded.is_empty())
            .then(|| excluded.into_iter().map(subtree).collect()),
    }
}

fn templates() -> (Certificate, Certificate) {
    support::templates(&["2.5.29.35", "2.5.29.14", "2.5.29.17", "2.5.29.30"])
}
fn path(names: Vec<GeneralName>, nc: NameConstraints) -> (Vec<u8>, Vec<u8>) {
    let (mut leaf, mut root) = templates();
    if !names.is_empty() {
        leaf.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(extension(
                "2.5.29.17",
                SubjectAltName(names).to_der().unwrap(),
                false,
            ));
    }
    root.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension("2.5.29.30", nc.to_der().unwrap(), true));
    (sign(leaf), sign(root))
}
fn accepts(names: Vec<GeneralName>, nc: NameConstraints) -> bool {
    let (leaf, root) = path(names, nc);
    chain::validate(&leaf, &support::chain_options(&[], &[root], TIME, EKU)).is_ok()
}

#[test]
fn dns_label_boundaries_case_union_exclusion_and_all_names() {
    for name in ["example.com", "Sub.ExAmPlE.CoM", "a.b.example.com"] {
        assert!(accepts(
            vec![dns(name)],
            constraints(vec![dns("example.com")], vec![])
        ));
    }
    for name in [
        "notexample.com",
        "example.com.evil.test",
        "evil.test",
        "*.example.com",
        "example.com.",
    ] {
        assert!(!accepts(
            vec![dns(name)],
            constraints(vec![dns("example.com")], vec![])
        ));
    }
    assert!(accepts(
        vec![dns("good.test")],
        constraints(vec![dns("example.com"), dns("good.test")], vec![])
    ));
    assert!(!accepts(
        vec![dns("good.example.com"), dns("evil.test")],
        constraints(vec![dns("example.com")], vec![])
    ));
    assert!(!accepts(
        vec![dns("secret.example.com")],
        constraints(vec![dns("example.com")], vec![dns("secret.example.com")])
    ));
    assert!(accepts(
        vec![],
        constraints(vec![dns("example.com")], vec![])
    )); // Absent form is unrestricted.
}

#[test]
fn mailbox_local_case_host_and_descendant_semantics() {
    assert!(accepts(
        vec![email("Alice@EXAMPLE.com")],
        constraints(vec![email("Alice@example.com")], vec![])
    ));
    assert!(!accepts(
        vec![email("alice@example.com")],
        constraints(vec![email("Alice@example.com")], vec![])
    ));
    assert!(accepts(
        vec![email("a@example.com")],
        constraints(vec![email("example.com")], vec![])
    ));
    assert!(!accepts(
        vec![email("a@sub.example.com")],
        constraints(vec![email("example.com")], vec![])
    ));
    assert!(accepts(
        vec![email("a@sub.example.com")],
        constraints(vec![email(".example.com")], vec![])
    ));
    assert!(!accepts(
        vec![email("a@example.com")],
        constraints(vec![email(".example.com")], vec![])
    ));
}

#[test]
fn uri_constraints_apply_only_to_dns_host() {
    assert!(accepts(
        vec![uri("https://user@HOST.example.com:443/path?q=evil.test")],
        constraints(vec![uri("host.example.com")], vec![])
    ));
    assert!(!accepts(
        vec![uri("https://sub.host.example.com/path")],
        constraints(vec![uri("host.example.com")], vec![])
    ));
    assert!(accepts(
        vec![uri("https://host.example.com/path")],
        constraints(vec![uri(".example.com")], vec![])
    ));
    for value in [
        "https://example.com",
        "urn:example.com",
        "https://192.0.2.1",
        "https://[2001:db8::1]",
        "https://evil.test/example.com",
    ] {
        assert!(!accepts(
            vec![uri(value)],
            constraints(vec![uri(".example.com")], vec![])
        ));
    }
}

#[test]
fn ip_masks_are_family_specific_and_cidr_bounded() {
    let net = ip(&[192, 0, 2, 0, 255, 255, 255, 0]);
    assert!(accepts(
        vec![ip(&[192, 0, 2, 77])],
        constraints(vec![net.clone()], vec![])
    ));
    assert!(!accepts(
        vec![ip(&[192, 0, 3, 77])],
        constraints(vec![net], vec![])
    ));
    let mut ipv6 = vec![0; 32];
    ipv6[..4].copy_from_slice(&[0x20, 1, 0xd, 0xb8]);
    ipv6[16..20].fill(255);
    let mut address = vec![0; 16];
    address[..4].copy_from_slice(&[0x20, 1, 0xd, 0xb8]);
    address[15] = 77;
    assert!(accepts(
        vec![ip(&address)],
        constraints(vec![ip(&ipv6)], vec![])
    ));
    assert!(!accepts(
        vec![ip(&[192, 0, 2, 77])],
        constraints(vec![ip(&ipv6)], vec![])
    ));
    assert!(!accepts(
        vec![ip(&[192, 0, 2, 77])],
        constraints(vec![ip(&[192, 0, 2, 0, 255, 0, 255, 0])], vec![])
    ));
}

#[test]
fn directory_names_match_rdn_prefix_with_ascii_space_and_case_folding() {
    let (_, root) = templates();
    let permitted = GeneralName::DirectoryName("O=Example,C=US".parse().unwrap());
    let san = GeneralName::DirectoryName("CN=Signer,O= example ,C=us".parse().unwrap());
    // Both SAN and subject are independently constrained.
    let (mut leaf, _) = templates();
    leaf.tbs_certificate.subject = "CN=Signer,O=Example,C=US".parse().unwrap();
    leaf.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension(
            "2.5.29.17",
            SubjectAltName(vec![san]).to_der().unwrap(),
            false,
        ));
    let mut root = root;
    root.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension(
            "2.5.29.30",
            constraints(vec![permitted], vec![]).to_der().unwrap(),
            true,
        ));
    assert!(
        chain::validate(
            &sign(leaf.clone()),
            &support::chain_options(&[], &[sign(root.clone())], TIME, EKU)
        )
        .is_ok()
    );
    leaf.tbs_certificate.subject = "CN=Signer,O=Other,C=US".parse().unwrap();
    assert!(
        chain::validate(
            &sign(leaf),
            &support::chain_options(&[], &[sign(root)], TIME, EKU)
        )
        .is_err()
    );
}

#[test]
fn malformed_unsupported_and_leaf_constraints_fail_closed() {
    for base in [
        dns(""),
        dns("bad..test"),
        GeneralName::RegisteredId("1.2.3".parse().unwrap()),
    ] {
        assert!(!accepts(
            vec![dns("example.com")],
            constraints(vec![base], vec![])
        ));
    }
    // Distances are only defined for domain and directory names.
    for base in [email("example.com"), uri("example.com")] {
        let mut nc = constraints(vec![base], vec![]);
        nc.permitted_subtrees.as_mut().unwrap()[0].minimum = 1;
        assert!(!accepts(vec![], nc));
    }
    let mut inverted = constraints(vec![dns("example.com")], vec![]);
    inverted.permitted_subtrees.as_mut().unwrap()[0].minimum = 2;
    inverted.permitted_subtrees.as_mut().unwrap()[0].maximum = Some(1);
    assert!(!accepts(vec![dns("a.b.example.com")], inverted));
    assert!(!accepts(
        vec![],
        NameConstraints {
            permitted_subtrees: None,
            excluded_subtrees: None
        }
    ));
    let (mut leaf, root) = templates();
    leaf.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension(
            "2.5.29.30",
            constraints(vec![dns("example.com")], vec![])
                .to_der()
                .unwrap(),
            true,
        ));
    assert!(
        chain::validate(
            &sign(leaf),
            &support::chain_options(&[], &[sign(root)], TIME, EKU)
        )
        .is_err()
    );
}

#[test]
fn constraints_are_path_local_and_an_alternative_root_can_succeed() {
    let (leaf, denied) = path(
        vec![dns("good.example.com")],
        constraints(vec![dns("evil.test")], vec![]),
    );
    let (_, mut allowed) = templates();
    allowed.tbs_certificate.serial_number =
        x509_cert::serial_number::SerialNumber::new(&[42]).unwrap();
    allowed
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension(
            "2.5.29.30",
            constraints(vec![dns("example.com")], vec![])
                .to_der()
                .unwrap(),
            true,
        ));
    let allowed = sign(allowed);
    assert!(
        chain::validate(
            &leaf,
            &support::chain_options(&[], std::slice::from_ref(&denied), TIME, EKU)
        )
        .is_err()
    );
    let selected = chain::validate(
        &leaf,
        &support::chain_options(&[], &[denied, allowed.clone()], TIME, EKU),
    )
    .unwrap();
    assert_eq!(selected.chain_der.last().unwrap(), &allowed);
}

#[test]
fn issuer_permitted_unions_intersect_and_exclusions_accumulate() {
    let (mut leaf, mut root) = templates();
    let mut issuer = root.clone();
    issuer.tbs_certificate.subject = "CN=Intermediate".parse().unwrap();
    issuer.tbs_certificate.serial_number =
        x509_cert::serial_number::SerialNumber::new(&[43]).unwrap();
    leaf.tbs_certificate.issuer = issuer.tbs_certificate.subject.clone();
    root.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension(
            "2.5.29.30",
            constraints(vec![dns("example.com")], vec![dns("blocked.example.com")])
                .to_der()
                .unwrap(),
            true,
        ));
    issuer
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension(
            "2.5.29.30",
            constraints(vec![dns("sub.example.com"), dns("evil.test")], vec![])
                .to_der()
                .unwrap(),
            true,
        ));
    let issuer = sign(issuer);
    let root = sign(root);
    for (name, expected) in [
        ("good.sub.example.com", true),
        ("other.example.com", false),
        ("evil.test", false),
    ] {
        let mut leaf = leaf.clone();
        leaf.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(extension(
                "2.5.29.17",
                SubjectAltName(vec![dns(name)]).to_der().unwrap(),
                false,
            ));
        assert_eq!(
            chain::validate(
                &sign(leaf),
                &support::chain_options(
                    std::slice::from_ref(&issuer),
                    std::slice::from_ref(&root),
                    TIME,
                    EKU
                )
            )
            .is_ok(),
            expected
        );
    }
}

#[test]
fn self_issued_intermediate_names_are_exempt_but_its_constraints_still_apply() {
    let (mut leaf, mut root) = templates();
    let mut rollover = root.clone();
    rollover.tbs_certificate.serial_number =
        x509_cert::serial_number::SerialNumber::new(&[44]).unwrap();
    rollover
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension(
            "2.5.29.17",
            SubjectAltName(vec![dns("outside.test")]).to_der().unwrap(),
            false,
        ));
    rollover
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension(
            "2.5.29.30",
            constraints(vec![dns("sub.example.com")], vec![])
                .to_der()
                .unwrap(),
            true,
        ));
    root.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension(
            "2.5.29.30",
            constraints(vec![dns("example.com")], vec![])
                .to_der()
                .unwrap(),
            true,
        ));
    leaf.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension(
            "2.5.29.17",
            SubjectAltName(vec![dns("good.sub.example.com")])
                .to_der()
                .unwrap(),
            false,
        ));
    let root = sign(root);
    let rollover = sign(rollover);
    let accepted = chain::validate_with_path_policy(
        &sign(leaf.clone()),
        &chain::ChainOptions {
            allow_sha1: false,
            limits: chain::PathLimits::default(),
            ..support::chain_options(
                std::slice::from_ref(&rollover),
                std::slice::from_ref(&root),
                TIME,
                EKU,
            )
        },
        |path| {
            support::require_policy(path.chain_der.len() == 3, "require rollover path")?;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(accepted.chain_der.len(), 3);
    leaf.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .retain(|e| e.extn_id.to_string() != "2.5.29.17");
    leaf.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension(
            "2.5.29.17",
            SubjectAltName(vec![dns("other.example.com")])
                .to_der()
                .unwrap(),
            false,
        ));
    assert!(
        chain::validate_with_path_policy(
            &sign(leaf),
            &chain::ChainOptions {
                allow_sha1: false,
                limits: chain::PathLimits::default(),
                ..support::chain_options(&[rollover], &[root], TIME, EKU)
            },
            |path| {
                support::require_policy(path.chain_der.len() == 3, "require rollover path")?;
                Ok(())
            }
        )
        .is_err()
    );
}

#[test]
fn legacy_subject_email_is_constrained_when_san_is_absent() {
    let (mut leaf, mut root) = templates();
    let attribute = x509_cert::attr::AttributeTypeAndValue {
        oid: "1.2.840.113549.1.9.1".parse().unwrap(),
        value: der::asn1::Any::encode_from(&Ia5String::new("Alice@outside.test").unwrap()).unwrap(),
    };
    leaf.tbs_certificate
        .subject
        .0
        .push(x509_cert::name::RelativeDistinguishedName(
            der::asn1::SetOfVec::try_from(vec![attribute]).unwrap(),
        ));
    root.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension(
            "2.5.29.30",
            constraints(vec![email("example.com")], vec![])
                .to_der()
                .unwrap(),
            true,
        ));
    assert!(
        chain::validate(
            &sign(leaf.clone()),
            &support::chain_options(&[], &[sign(root.clone())], TIME, EKU)
        )
        .is_err()
    );
    leaf.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension(
            "2.5.29.17",
            SubjectAltName(vec![email("Alice@example.com")])
                .to_der()
                .unwrap(),
            false,
        ));
    assert!(
        chain::validate(
            &sign(leaf),
            &support::chain_options(&[], &[sign(root)], TIME, EKU)
        )
        .is_ok()
    );
}

#[test]
#[ignore = "independent OpenSSL oracle; invoke explicitly in the development shell"]
#[cfg(feature = "std")]
fn openssl_agrees_on_supported_name_constraint_outcomes() {
    let cases = [
        (
            vec![dns("good.example.com")],
            constraints(vec![dns("example.com")], vec![]),
            true,
        ),
        (
            vec![dns("notexample.com")],
            constraints(vec![dns("example.com")], vec![]),
            false,
        ),
        (
            vec![dns("blocked.example.com")],
            constraints(vec![dns("example.com")], vec![dns("blocked.example.com")]),
            false,
        ),
        (
            vec![email("Alice@example.com")],
            constraints(vec![email("example.com")], vec![]),
            true,
        ),
        (
            vec![email("Alice@sub.example.com")],
            constraints(vec![email("example.com")], vec![]),
            false,
        ),
        (
            vec![uri("https://host.example.com/path")],
            constraints(vec![uri(".example.com")], vec![]),
            true,
        ),
        (
            vec![uri("https://evil.test/example.com")],
            constraints(vec![uri(".example.com")], vec![]),
            false,
        ),
        (
            vec![ip(&[192, 0, 2, 77])],
            constraints(vec![ip(&[192, 0, 2, 0, 255, 255, 255, 0])], vec![]),
            true,
        ),
        (
            vec![ip(&[192, 0, 3, 77])],
            constraints(vec![ip(&[192, 0, 2, 0, 255, 255, 255, 0])], vec![]),
            false,
        ),
    ];
    for (names, nc, expected) in cases {
        let (leaf, root) = path(names, nc);
        let directory = tempfile::tempdir().unwrap();
        let leaf_path = directory.path().join("leaf.pem");
        let root_path = directory.path().join("root.pem");
        std::fs::write(
            &leaf_path,
            Certificate::from_der(&leaf)
                .unwrap()
                .to_pem(der::pem::LineEnding::LF)
                .unwrap(),
        )
        .unwrap();
        std::fs::write(
            &root_path,
            Certificate::from_der(&root)
                .unwrap()
                .to_pem(der::pem::LineEnding::LF)
                .unwrap(),
        )
        .unwrap();
        let result = std::process::Command::new("openssl")
            .args([
                "verify",
                "-purpose",
                "any",
                "-attime",
                &TIME.to_string(),
                "-CAfile",
            ])
            .arg(&root_path)
            .arg(&leaf_path)
            .output()
            .unwrap();
        assert_eq!(
            result.status.success(),
            expected,
            "OpenSSL: {}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            chain::validate(&leaf, &support::chain_options(&[], &[root], TIME, EKU)).is_ok(),
            expected
        );
    }
}

fn distance(permitted: bool, minimum: u32, maximum: Option<u32>) -> NameConstraints {
    let mut nc = if permitted {
        constraints(vec![dns("example.com")], vec![])
    } else {
        constraints(vec![], vec![dns("example.com")])
    };
    let subtree = if permitted {
        &mut nc.permitted_subtrees
    } else {
        &mut nc.excluded_subtrees
    };
    subtree.as_mut().unwrap()[0].minimum = minimum;
    subtree.as_mut().unwrap()[0].maximum = maximum;
    nc
}

#[test]
fn dns_minimum_and_maximum_count_labels_below_the_base() {
    // Permitted [1, 1]: exactly one label below example.com.
    for (name, expected) in [
        ("example.com", false),
        ("a.example.com", true),
        ("A.Example.COM", true),
        ("a.b.example.com", false),
    ] {
        assert_eq!(
            accepts(vec![dns(name)], distance(true, 1, Some(1))),
            expected,
            "{name}"
        );
    }
    // Excluded from depth 2: shallow names stay allowed (no permitted subtrees).
    for (name, expected) in [
        ("example.com", true),
        ("a.example.com", true),
        ("a.b.example.com", false),
        ("a.b.c.example.com", false),
    ] {
        assert_eq!(
            accepts(vec![dns(name)], distance(false, 2, None)),
            expected,
            "{name}"
        );
    }
}

#[test]
fn directory_name_minimum_and_maximum_count_rdns_below_the_base() {
    let base = || GeneralName::DirectoryName("O=Example,C=US".parse().unwrap());
    let run = |subject: &str, minimum: u32, maximum: Option<u32>| {
        let (mut leaf, mut root) = templates();
        leaf.tbs_certificate.subject = subject.parse().unwrap();
        let mut nc = constraints(vec![base()], vec![]);
        nc.permitted_subtrees.as_mut().unwrap()[0].minimum = minimum;
        nc.permitted_subtrees.as_mut().unwrap()[0].maximum = maximum;
        root.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(extension("2.5.29.30", nc.to_der().unwrap(), true));
        chain::validate(
            &sign(leaf),
            &support::chain_options(&[], &[sign(root)], TIME, EKU),
        )
        .is_ok()
    };
    assert!(run("O=Example,C=US", 0, Some(0)));
    assert!(!run("O=Example,C=US", 1, None));
    assert!(run("CN=Signer,O=Example,C=US", 1, Some(1)));
    assert!(!run("CN=Signer,O=Example,C=US", 0, Some(0)));
    assert!(!run("CN=Signer,O=Example,C=US", 2, None));
    assert!(!run("CN=Deep,OU=Unit,O=Example,C=US", 0, Some(1)));
}

#[test]
fn uri_without_a_dns_host_is_outside_domain_subtrees() {
    for value in [
        "https://192.0.2.1/x",
        "https://[2001:db8::1]:8443/",
        "urn:example:thing",
    ] {
        // Not excluded by a domain exclusion, and never permitted by a domain permission.
        assert!(accepts(
            vec![uri(value)],
            constraints(vec![], vec![uri(".example.com")])
        ));
        assert!(!accepts(
            vec![uri(value)],
            constraints(vec![uri(".example.com")], vec![])
        ));
    }
    assert!(!accepts(
        vec![uri("https://host.example.com/")],
        constraints(vec![], vec![uri(".example.com")])
    ));
    // A malformed authority still fails closed.
    assert!(!accepts(
        vec![uri("https://host.example.com:port/")],
        constraints(vec![], vec![uri(".example.com")])
    ));
}

fn dn_with(value: der::Any, oid: &str) -> Name {
    use x509_cert::{
        attr::AttributeTypeAndValue,
        name::{RdnSequence, RelativeDistinguishedName},
    };
    let attribute = AttributeTypeAndValue {
        oid: oid.parse().unwrap(),
        value,
    };
    RdnSequence(vec![RelativeDistinguishedName(
        vec![attribute].try_into().unwrap(),
    )])
}
use x509_cert::name::Name;

fn dn_accepts(permitted: Name, subject: Name) -> bool {
    let (mut leaf, mut root) = templates();
    leaf.tbs_certificate.subject = subject;
    root.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(extension(
            "2.5.29.30",
            constraints(vec![GeneralName::DirectoryName(permitted)], vec![])
                .to_der()
                .unwrap(),
            true,
        ));
    chain::validate(
        &sign(leaf),
        &support::chain_options(&[], &[sign(root)], TIME, EKU),
    )
    .is_ok()
}
fn text(tag: der::Tag, bytes: &[u8]) -> der::Any {
    der::Any::new(tag, bytes.to_vec()).unwrap()
}
fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

#[test]
fn international_directory_names_use_rfc4518_preparation() {
    let o = "2.5.4.10";
    let utf8 = |s: &str| dn_with(text(der::Tag::Utf8String, s.as_bytes()), o);
    let bmp = |s: &str| dn_with(text(der::Tag::BmpString, &utf16(s)), o);
    // Case and internal/outer space folding apply to non-ASCII letters.
    assert!(dn_accepts(
        utf8("M\u{fc}ller GmbH"),
        utf8("  M\u{dc}LLER    gmbh ")
    ));
    // Composed and decomposed forms are equal after NFKC.
    assert!(dn_accepts(utf8("M\u{fc}ller"), utf8("Mu\u{308}ller")));
    // Compatibility forms fold: full-width letters equal their ASCII forms.
    assert!(dn_accepts(utf8("Example"), utf8("\u{ff25}xample")));
    // Special case folding: sharp s equals ss.
    assert!(dn_accepts(utf8("STRASSE"), utf8("Stra\u{df}e")));
    // BMPString and UTF8String of the same text are equal.
    assert!(dn_accepts(utf8("M\u{fc}ller"), bmp("M\u{dc}ller")));
    // Different letters are different names.
    assert!(!dn_accepts(utf8("M\u{fc}ller"), utf8("Muller")));
    // Characters the profile prohibits make the name unusable.
    assert!(!dn_accepts(utf8("Example"), utf8("Exam\u{e000}ple")));
    assert!(!dn_accepts(utf8("Example"), utf8("Exam\u{fdd0}ple")));
    // Non-ASCII Teletex has no unambiguous mapping.
    assert!(!dn_accepts(
        utf8("Example"),
        dn_with(text(der::Tag::TeletexString, &[0xfc]), o)
    ));
    // Right-to-left strings must satisfy the bidirectional rule.
    assert!(!dn_accepts(utf8("Example"), utf8("\u{5d0}abc")));
    assert!(dn_accepts(utf8("\u{5d0}\u{5d1}"), utf8("\u{5d0}\u{5d1}")));
}
