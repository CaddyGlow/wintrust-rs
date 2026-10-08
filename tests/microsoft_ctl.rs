use der::Decode;
use sha2::{Digest, Sha256};
use wintrust::{
    ctl::{self, CtlAuthenticationPolicy},
    portable::signed,
};

// Real Microsoft fixtures remain outside the package until redistribution is resolved.
// Run explicitly with SIGNCODE_MICROSOFT_CTL_FIXTURES=/data/cache/signcode-ctl-audit.
fn fixture(name: &str) -> Vec<u8> {
    let dir = std::env::var("SIGNCODE_MICROSOFT_CTL_FIXTURES")
        .expect("set SIGNCODE_MICROSOFT_CTL_FIXTURES to the audited fixture directory");
    std::fs::read(std::path::Path::new(&dir).join(name)).unwrap()
}
const ROOT: &[u8] = include_bytes!("fixtures/microsoft-ber-certificates/microsoft-root-2010.der");
const NOW: u64 = 1791469034;

#[test]
#[ignore = "external audited Microsoft CTL fixtures"]
fn real_public_ctl_crypto_and_optional_attributes_preserve_metadata() {
    let authroot = fixture("authroot.stl");
    let disallowed = fixture("disallowed.stl");
    for (bytes, hash, usage, algorithm, count) in [
        (
            authroot.as_slice(),
            "107fb03b1be6653c3e9803014622e2ae65e8df7bbf2d919d3f8bae2496005d51",
            "1.3.6.1.4.1.311.10.3.9",
            "1.3.14.3.2.26",
            562,
        ),
        (
            disallowed.as_slice(),
            "400800c461437e5e304ec4a597acc79436e522afd0acb7e32cc01ff26d3133dc",
            "1.3.6.1.4.1.311.10.3.30",
            "1.3.6.1.4.1.311.10.11.15",
            88,
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(bytes)), hash);
        let verified = signed::verify_signed_data(bytes, "1.3.6.1.4.1.311.10.1").unwrap();
        assert_eq!(verified.signers.len(), 1);
        let cert = x509_cert::Certificate::from_der(&verified.signers[0].certificate_der).unwrap();
        let eku = cert
            .tbs_certificate
            .get::<x509_cert::ext::pkix::ExtendedKeyUsage>()
            .unwrap()
            .unwrap()
            .1;
        assert_eq!(eku.0[0].to_string(), "1.3.6.1.4.1.311.10.3.9");
        let list = ctl::parse(verified.content_der, Default::default()).unwrap();
        assert_eq!(list.subject_usage[0].to_string(), usage);
        assert_eq!(list.subject_algorithm.to_string(), algorithm);
        assert_eq!(list.entries.len(), count);
        assert!(list.next_update.is_none());
        if bytes == disallowed.as_slice() {
            assert!(list.entries.iter().all(|row| row.attributes.is_empty()));
            assert_eq!(
                list.entries
                    .iter()
                    .filter(|r| r.subject_identifier.len() == 16)
                    .count(),
                82
            );
            assert_eq!(
                list.entries
                    .iter()
                    .filter(|r| r.subject_identifier.len() == 48)
                    .count(),
                6
            );
        } else {
            assert!(
                list.entries
                    .iter()
                    .all(|row| row.subject_identifier.len() == 20)
            );
            assert!(list.entries.iter().any(|row| {
                row.attributes
                    .iter()
                    .any(|attr| attr.oid.to_string() == "1.3.6.1.4.1.311.10.11.127")
            }));
        }
    }
}

#[test]
#[ignore = "external audited Microsoft CTL fixtures"]
fn independently_pinned_bootstrap_and_current_vs_historical_authentication() {
    let authroot = fixture("authroot.stl");
    let disallowed = fixture("disallowed.stl");
    assert_eq!(
        hex::encode(Sha256::digest(ROOT)),
        "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e"
    );
    let roots = vec![ROOT.to_vec()];
    let policy = CtlAuthenticationPolicy {
        bootstrap_anchors: &roots,
        issuer_candidates: &[],
        required_signer_eku: "1.3.6.1.4.1.311.10.3.9",
        required_list_usage: "1.3.6.1.4.1.311.10.3.9".parse().unwrap(),
        verification_time: NOW,
        minimum_sequence: None,
        max_age_seconds: 2 * 365 * 86400,
        allow_sha1: false,
    };
    let auth = ctl::authenticate(authroot.as_slice(), &policy, Default::default()).unwrap();
    assert_eq!(auth.inspect().unwrap().entries.len(), 562);
    assert_eq!(auth.signer_paths()[0].chain_der.last().unwrap(), ROOT);
    let no_bootstrap = CtlAuthenticationPolicy {
        bootstrap_anchors: &[],
        ..policy
    };
    assert!(ctl::authenticate(authroot.as_slice(), &no_bootstrap, Default::default()).is_err());
    let disallowed_policy = CtlAuthenticationPolicy {
        required_list_usage: "1.3.6.1.4.1.311.10.3.30".parse().unwrap(),
        ..policy
    };
    let error = ctl::authenticate(
        disallowed.as_slice(),
        &disallowed_policy,
        Default::default(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("validity"), "{error:#}");
    let historical = CtlAuthenticationPolicy {
        verification_time: 1757042448,
        ..disallowed_policy
    };
    assert_eq!(
        ctl::authenticate(disallowed.as_slice(), &historical, Default::default())
            .unwrap()
            .inspect()
            .unwrap()
            .entries
            .len(),
        88
    );
    let wrong_usage = CtlAuthenticationPolicy {
        required_list_usage: policy.required_list_usage,
        ..historical
    };
    assert!(
        ctl::authenticate(disallowed.as_slice(), &wrong_usage, Default::default())
            .unwrap_err()
            .to_string()
            .contains("purpose")
    );
}

#[test]
#[ignore = "independent OpenSSL cryptographic oracle"]
fn openssl_verifies_exact_public_ctl_signatures() {
    let authroot = fixture("authroot.stl");
    let disallowed = fixture("disallowed.stl");
    for bytes in [authroot.as_slice(), disallowed.as_slice()] {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("list.stl"), bytes).unwrap();
        let result = std::process::Command::new("openssl")
            .current_dir(tmp.path())
            .args([
                "smime",
                "-verify",
                "-inform",
                "DER",
                "-in",
                "list.stl",
                "-noverify",
                "-out",
                "content.der",
            ])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stderr).contains("Verification successful"));
        let verified = signed::verify_signed_data(bytes, "1.3.6.1.4.1.311.10.1").unwrap();
        let output = std::fs::read(tmp.path().join("content.der")).unwrap();
        assert!(output == verified.content_der || output == verified.content_value);
    }
}
