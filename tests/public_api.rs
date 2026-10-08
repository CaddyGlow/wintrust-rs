use wintrust::{
    CertificateStore, ObjectIdentifier,
    error::Error,
    portable::{
        PortableLimits, PortablePolicy, Verifier,
        crypto::{self, CryptoOptions, SignatureOptions},
        signed::{self, SignedDataOptions},
    },
};

const CTL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.1");
fn policy() -> PortablePolicy {
    serde_json::from_slice(include_bytes!("fixtures/policy.json")).unwrap()
}

#[test]
fn artifact_identifiers_are_strings_in_every_feature_configuration() {
    let policy = policy();
    let identifier: &String = &policy.roots[0].path;
    assert_eq!(identifier, "root.der");
    assert_eq!(
        serde_json::to_value(&policy).unwrap()["roots"][0]["path"],
        "root.der"
    );
}

#[test]
fn borrowed_collection_preserves_static_buffers_without_copying() {
    static ROOT: &[u8] = include_bytes!("fixtures/root.der");
    let buffers = [ROOT];
    let store = CertificateStore::from(&buffers);
    assert_eq!(store.len(), 1);
    assert!(core::ptr::eq(store.get(0).unwrap(), ROOT));
    assert!(core::ptr::eq(store.iter().next().unwrap(), ROOT));
    assert!(store.get(1).is_none());
}

#[test]
fn callers_can_match_error_categories_without_parsing_messages() {
    let crypto = CryptoOptions::default();
    assert!(matches!(
        crypto::digest(ObjectIdentifier::new_unwrap("1.2.3.4"), b"data", &crypto),
        Err(Error::UnsupportedAlgorithm(_))
    ));
    assert!(matches!(
        crypto::digest(
            ObjectIdentifier::new_unwrap("1.3.14.3.2.26"),
            b"data",
            &crypto
        ),
        Err(Error::PolicyRejected(_))
    ));
    assert!(matches!(
        crypto::verify_algorithm(&[0], &[0], b"data", &[0], &SignatureOptions::default()),
        Err(Error::MalformedInput(_))
    ));
    let mut invalid = policy();
    invalid.schema_version = 99;
    assert!(matches!(
        Verifier::from_artifact_reader(invalid, PortableLimits::default(), |_, _| panic!(
            "configuration must be checked before reading"
        )),
        Err(Error::InvalidConfiguration(_))
    ));
    assert!(matches!(
        Verifier::from_artifact_reader(
            policy(),
            PortableLimits {
                max_artifact_bytes: 1,
                ..Default::default()
            },
            |_, _| Ok(vec![0, 1])
        ),
        Err(Error::ResourceLimit(_))
    ));
}

#[test]
fn corrupted_signature_has_a_signature_error_even_with_context() {
    let bytes = include_bytes!("fixtures/catalog.cat");
    let options = SignedDataOptions::new(CTL);
    let verified = signed::verify_signed_data(bytes, &options).unwrap();
    let signature = &verified.signers[0].signature;
    let offset = bytes
        .windows(signature.len())
        .position(|window| window == signature)
        .unwrap();
    let mut corrupt = bytes.to_vec();
    corrupt[offset + signature.len() - 1] ^= 1;
    assert!(matches!(
        signed::verify_signed_data(&corrupt, &options),
        Err(Error::InvalidSignature(_))
    ));
}

#[test]
fn typed_oids_keep_dotted_decimal_report_values() {
    let catalog =
        wintrust::catalog::parse(include_bytes!("fixtures/catalog.cat"), Default::default())
            .unwrap();
    assert_eq!(catalog.content_type, CTL);
    let json = serde_json::to_value(&catalog).unwrap();
    assert_eq!(json["content_type"], catalog.content_type.to_string());
    assert_eq!(
        json["ctl"]["subject_algorithm"],
        catalog.ctl.subject_algorithm.to_string()
    );
}

#[test]
fn report_enums_keep_the_existing_serialized_strings() {
    use wintrust::portable::{
        chain::CertificateRole,
        revocation::{ArtifactKind, ArtifactOrigin, ArtifactSource},
        timestamp::TimestampFormat,
    };
    assert_eq!(
        serde_json::to_value(CertificateRole::EndEntity).unwrap(),
        "end-entity"
    );
    assert_eq!(
        serde_json::to_value(TimestampFormat::LegacyCountersignature).unwrap(),
        "legacy_countersignature"
    );
    assert_eq!(
        serde_json::to_value(ArtifactKind::DeltaCrl).unwrap(),
        "delta-crl"
    );
    assert_eq!(
        serde_json::to_value(ArtifactOrigin::PinnedFile).unwrap(),
        "pinned-file"
    );
    assert_eq!(
        serde_json::to_value(ArtifactSource::AuthorityInfoAccess).unwrap(),
        "authority-info-access"
    );
}

#[cfg(feature = "std")]
#[test]
fn file_failures_retain_the_io_category() {
    let directory = tempfile::tempdir().unwrap();
    assert!(matches!(
        Verifier::load(
            &directory.path().join("missing-policy.json"),
            PortableLimits::default()
        ),
        Err(Error::Io(_))
    ));
}
