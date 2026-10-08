use wintrust::{catalog, ctl};

#[test]
fn generic_ctl_accepts_entry_without_optional_attributes() {
    // Usage, thisUpdate, SHA256 subject algorithm, and an opaque identifier row.
    let bytes = hex::decode("3033300606042a030405170d3236313030383030303030305a300b0609608648016503040201300d300b0409010203040506070809").unwrap();
    let list = ctl::parse(&bytes, Default::default()).unwrap();
    assert_eq!(list.entries.len(), 1);
    assert!(list.entries[0].attributes.is_empty());
    assert_eq!(
        list.entries[0].subject_identifier,
        &[1, 2, 3, 4, 5, 6, 7, 8, 9]
    );
}

#[test]
fn generic_ctl_preserves_exact_list_and_entries_without_catalog_semantics() {
    let catalog =
        catalog::parse(include_bytes!("fixtures/catalog.cat"), Default::default()).unwrap();
    let bytes = hex::decode(catalog.ctl.encoded_hex).unwrap();
    let parsed = ctl::parse(&bytes, Default::default()).unwrap();
    assert_eq!(parsed.encoded, bytes);
    assert_eq!(parsed.entries.len(), catalog.ctl.members.len());
    assert_eq!(
        hex::encode(parsed.entries[0].subject_identifier),
        catalog.ctl.members[0].identifier_hex
    );
    assert!(!parsed.subject_usage.is_empty());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ctl::parse(&trailing, Default::default()).is_err());
    assert!(
        ctl::parse(
            &bytes,
            catalog::CatalogLimits {
                max_members: 0,
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(
        ctl::parse(
            &bytes,
            catalog::CatalogLimits {
                max_nodes: 1,
                ..Default::default()
            }
        )
        .is_err()
    );
}

#[test]
fn authenticated_ctl_requires_dedicated_anchor_purpose_freshness_and_sequence() {
    use ctl::{CtlAuthenticationPolicy, authenticate};
    let bytes = include_bytes!("fixtures/catalog.cat");
    let catalog = catalog::parse(bytes, Default::default()).unwrap();
    let roots = vec![include_bytes!("fixtures/root.der").to_vec()];
    let policy = CtlAuthenticationPolicy {
        bootstrap_anchors: (&roots).into(),
        issuer_candidates: Default::default(),
        required_signer_eku: "1.3.6.1.5.5.7.3.3".parse().unwrap(),
        required_list_usage: catalog.ctl.subject_usage[0],
        verification_time: 1791117219,
        minimum_sequence: None,
        max_age_seconds: 365 * 86400,
        allow_sha1: false,
    };
    let accepted = authenticate(bytes, &policy, Default::default()).unwrap();
    assert_eq!(accepted.inspect().unwrap().encoded, accepted.encoded());
    assert!(!accepted.signer_paths().is_empty());
    let mut forged = bytes.to_vec();
    let content_offset = bytes
        .windows(accepted.encoded().len())
        .position(|window| window == accepted.encoded())
        .unwrap();
    forged[content_offset + accepted.encoded().len() / 2] ^= 1;
    assert!(authenticate(&forged, &policy, Default::default()).is_err());
    let wrong_usage = CtlAuthenticationPolicy {
        required_list_usage: "1.2.3.4".parse().unwrap(),
        ..policy
    };
    assert!(
        authenticate(bytes, &wrong_usage, Default::default())
            .unwrap_err()
            .to_string()
            .contains("purpose")
    );
    let stale = CtlAuthenticationPolicy {
        max_age_seconds: 1,
        ..policy
    };
    assert!(authenticate(bytes, &stale, Default::default()).is_err());
    let missing_bootstrap = CtlAuthenticationPolicy {
        bootstrap_anchors: Default::default(),
        ..policy
    };
    assert!(authenticate(bytes, &missing_bootstrap, Default::default()).is_err());
    let wrong_purpose = CtlAuthenticationPolicy {
        required_signer_eku: "1.2.3.4".parse().unwrap(),
        ..policy
    };
    assert!(authenticate(bytes, &wrong_purpose, Default::default()).is_err());
    let rollback = CtlAuthenticationPolicy {
        minimum_sequence: Some(&[0x7f; 32]),
        ..policy
    };
    assert!(authenticate(bytes, &rollback, Default::default()).is_err());
}
