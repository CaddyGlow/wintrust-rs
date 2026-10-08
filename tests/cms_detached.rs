// Independent CMS oracle. Requires OpenSSL on PATH; explicitly run with --ignored.
use std::{fs, path::Path, process::Command};
use wintrust::{
    Result,
    portable::{
        crypto::CryptoOptions,
        signed::{SignedDataContent, SignedDataOptions, VerifiedSignedData, verify_signed_data},
    },
};

fn verify_cms_signed_data<'a>(
    bytes: &'a [u8],
    expected: &str,
    content: SignedDataContent<'a>,
    allow_sha1: bool,
) -> Result<VerifiedSignedData<'a>> {
    verify_signed_data(
        bytes,
        &SignedDataOptions {
            expected_content_oid: expected.parse().unwrap(),
            content,
            crypto: CryptoOptions { allow_sha1 },
        },
    )
}

const DATA: &str = "1.2.840.113549.1.7.1";

fn openssl(dir: &Path, args: &[&str]) {
    let result = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
#[ignore = "independent OpenSSL interoperability oracle"]
fn openssl_embedded_detached_direct_and_multiple_signers() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    fs::write(dir.join("data"), b"exact detached content\n").unwrap();
    for name in ["one", "two"] {
        openssl(
            dir,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.pem"),
                "-subj",
                &format!("/CN={name}"),
                "-days",
                "1",
            ],
        );
    }
    for (name, flags, count, embedded, digest, allow_sha1) in [
        ("detached", vec![], 1, false, "sha256", false),
        ("embedded", vec!["-nodetach"], 1, true, "sha256", false),
        ("direct", vec!["-noattr"], 1, false, "sha256", false),
        (
            "multiple",
            vec!["-signer", "two.pem", "-inkey", "two.key"],
            2,
            false,
            "sha256",
            false,
        ),
        ("sha384", vec![], 1, false, "sha384", false),
        ("sha512", vec![], 1, false, "sha512", false),
        ("sha1", vec![], 1, false, "sha1", true),
    ] {
        let mut args = vec![
            "cms", "-sign", "-binary", "-in", "data", "-signer", "one.pem", "-inkey", "one.key",
            "-md", digest, "-outform", "DER", "-out", name,
        ];
        args.extend(flags);
        openssl(dir, &args);
        let signature = fs::read(dir.join(name)).unwrap();
        let data = fs::read(dir.join("data")).unwrap();
        let content = if embedded {
            SignedDataContent::Embedded
        } else {
            SignedDataContent::Detached(&data)
        };
        let report = verify_cms_signed_data(&signature, DATA, content, allow_sha1).unwrap();
        assert_eq!(report.signers.len(), count);
        if allow_sha1 {
            assert!(verify_cms_signed_data(&signature, DATA, content, false).is_err());
        }
        assert_eq!(report.content_value, data);
        assert_eq!(report.content_der.as_ptr(), report.content_value.as_ptr());
        if !embedded {
            assert_eq!(report.content_value.as_ptr(), data.as_ptr());
        }
        assert!(
            verify_cms_signed_data(
                &signature,
                DATA,
                SignedDataContent::Detached(b"tampered"),
                false
            )
            .is_err()
        );
        if embedded {
            assert!(
                verify_cms_signed_data(&signature, DATA, SignedDataContent::Detached(&data), false)
                    .is_err()
            );
        } else {
            assert!(
                verify_cms_signed_data(&signature, DATA, SignedDataContent::Embedded, false)
                    .is_err()
            );
        }
        assert!(verify_cms_signed_data(&signature, "1.2.3", content, false).is_err());
        let mut trailing = signature.clone();
        trailing.push(0);
        assert!(verify_cms_signed_data(&trailing, DATA, content, false).is_err());
        let mut corrupted = signature;
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(verify_cms_signed_data(&corrupted, DATA, content, false).is_err());
        openssl(
            dir,
            &[
                "cms",
                "-verify",
                "-binary",
                "-inform",
                "DER",
                "-in",
                name,
                "-content",
                "data",
                "-noverify",
                "-out",
                "verified",
            ],
        );
        assert_eq!(fs::read(dir.join("verified")).unwrap(), data);
    }
}
