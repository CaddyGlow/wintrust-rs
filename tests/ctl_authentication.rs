use der::{
    Encode,
    asn1::{ObjectIdentifier, UtcTime},
};
use std::{
    fs,
    path::Path,
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use wintrust::ctl::{CtlAuthenticationPolicy, authenticate};

fn openssl(dir: &Path, args: &[&str]) {
    let output = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn sequence(bytes: Vec<u8>) -> Vec<u8> {
    assert!(bytes.len() < 128);
    let mut result = vec![0x30, bytes.len() as u8];
    result.extend(bytes);
    result
}

#[test]
#[ignore = "independent OpenSSL authenticated CTL oracle"]
fn independent_openssl_ctl_rejects_untrusted_stale_and_wrong_usage() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    openssl(
        dir,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "key.pem",
            "-out",
            "cert.pem",
            "-subj",
            "/CN=Dedicated CTL bootstrap",
            "-days",
            "1",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyCertSign",
            "-addext",
            "extendedKeyUsage=1.3.6.1.4.1.311.10.3.1",
        ],
    );
    openssl(
        dir,
        &[
            "x509", "-in", "cert.pem", "-outform", "DER", "-out", "cert.der",
        ],
    );
    fs::rename(dir.join("cert.pem"), dir.join("root.pem")).unwrap();
    fs::rename(dir.join("key.pem"), dir.join("root.key")).unwrap();
    fs::rename(dir.join("cert.der"), dir.join("root.der")).unwrap();
    openssl(
        dir,
        &[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "key.pem",
            "-out",
            "leaf.csr",
            "-subj",
            "/CN=CTL signer",
        ],
    );
    fs::write(dir.join("leaf.ext"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=1.3.6.1.4.1.311.10.3.1\n").unwrap();
    openssl(
        dir,
        &[
            "x509",
            "-req",
            "-in",
            "leaf.csr",
            "-CA",
            "root.pem",
            "-CAkey",
            "root.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            "leaf.ext",
            "-out",
            "cert.pem",
        ],
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let usage: ObjectIdentifier = "1.3.6.1.4.1.311.10.3.1".parse().unwrap();
    let mut fields = sequence(usage.to_der().unwrap());
    fields.extend([2, 1, 7]);
    fields.extend(
        UtcTime::from_unix_duration(Duration::from_secs(now - 10))
            .unwrap()
            .to_der()
            .unwrap(),
    );
    fields.extend(
        UtcTime::from_unix_duration(Duration::from_secs(now + 60))
            .unwrap()
            .to_der()
            .unwrap(),
    );
    fields.extend(sequence(
        "2.16.840.1.101.3.4.2.1"
            .parse::<ObjectIdentifier>()
            .unwrap()
            .to_der()
            .unwrap(),
    ));
    fields.extend([0x30, 0]);
    let list = sequence(fields);
    fs::write(dir.join("list.der"), &list).unwrap();
    openssl(
        dir,
        &[
            "cms",
            "-sign",
            "-binary",
            "-nodetach",
            "-in",
            "list.der",
            "-signer",
            "cert.pem",
            "-inkey",
            "key.pem",
            "-md",
            "sha256",
            "-econtent_type",
            "1.3.6.1.4.1.311.10.1",
            "-outform",
            "DER",
            "-out",
            "list.cms",
        ],
    );
    openssl(
        dir,
        &[
            "cms",
            "-verify",
            "-binary",
            "-inform",
            "DER",
            "-in",
            "list.cms",
            "-CAfile",
            "root.pem",
            "-purpose",
            "any",
            "-out",
            "verified.der",
        ],
    );
    assert_eq!(fs::read(dir.join("verified.der")).unwrap(), list);
    let cms = fs::read(dir.join("list.cms")).unwrap();
    let anchors = vec![fs::read(dir.join("root.der")).unwrap()];
    let policy = CtlAuthenticationPolicy {
        bootstrap_anchors: &anchors,
        issuer_candidates: &[],
        required_signer_eku: "1.3.6.1.4.1.311.10.3.1",
        required_list_usage: usage,
        verification_time: now,
        minimum_sequence: Some(&[7]),
        max_age_seconds: 30,
        allow_sha1: false,
    };
    let authenticated = authenticate(&cms, &policy, Default::default()).unwrap();
    assert_eq!(authenticated.encoded(), list);
    assert!(
        authenticate(
            &cms,
            &CtlAuthenticationPolicy {
                max_age_seconds: 1,
                ..policy
            },
            Default::default()
        )
        .is_err()
    );
    assert!(
        authenticate(
            &cms,
            &CtlAuthenticationPolicy {
                required_list_usage: "1.2.3".parse().unwrap(),
                ..policy
            },
            Default::default()
        )
        .is_err()
    );
    let foreign = vec![include_bytes!("fixtures/root.der").to_vec()];
    assert!(
        authenticate(
            &cms,
            &CtlAuthenticationPolicy {
                bootstrap_anchors: &foreign,
                ..policy
            },
            Default::default()
        )
        .is_err()
    );
    assert!(
        authenticate(
            &cms,
            &CtlAuthenticationPolicy {
                minimum_sequence: Some(&[8]),
                ..policy
            },
            Default::default()
        )
        .is_err()
    );
}
