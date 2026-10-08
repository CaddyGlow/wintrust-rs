//! Independent RFC3161 oracle for caller-supplied issuers and alternative TSA roots.
use std::{
    fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use wintrust::portable::{chain, signed::VerifiedSigner, timestamp};

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
fn issue(dir: &Path, name: &str, issuer: &str, extensions: &str) {
    openssl(
        dir,
        &[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.csr"),
            "-subj",
            &format!("/CN={name}"),
        ],
    );
    fs::write(dir.join(format!("{name}.ext")), extensions).unwrap();
    openssl(
        dir,
        &[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            &format!("{issuer}.pem"),
            "-CAkey",
            &format!("{issuer}.key"),
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            &format!("{name}.ext"),
            "-out",
            &format!("{name}.pem"),
        ],
    );
}
fn der(dir: &Path, name: &str) -> Vec<u8> {
    openssl(
        dir,
        &[
            "x509",
            "-in",
            &format!("{name}.pem"),
            "-outform",
            "DER",
            "-out",
            &format!("{name}.der"),
        ],
    );
    fs::read(dir.join(format!("{name}.der"))).unwrap()
}

#[test]
#[ignore = "independent OpenSSL RFC3161 issuer/path oracle"]
fn supplied_intermediate_completes_tsa_path_and_rejected_root_tries_alternative() {
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
            "root.key",
            "-out",
            "root.pem",
            "-subj",
            "/CN=Timestamp Root",
            "-days",
            "1",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
    );
    openssl(
        dir,
        &[
            "x509",
            "-in",
            "root.pem",
            "-signkey",
            "root.key",
            "-set_serial",
            "2",
            "-days",
            "1",
            "-out",
            "other.pem",
        ],
    );
    issue(
        dir,
        "issuer",
        "root",
        "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n",
    );
    issue(
        dir,
        "tsa",
        "issuer",
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n",
    );
    fs::write(dir.join("serial"), "01\n").unwrap();
    fs::write(dir.join("tsa.cnf"), "[tsa]\ndefault_tsa=cfg\n[cfg]\ndir=.\nserial=serial\nsigner_cert=tsa.pem\nsigner_key=tsa.key\nsigner_digest=sha256\ndefault_policy=1.2.3.4\ndigests=sha256\nordering=no\ntsa_name=yes\ness_cert_id_chain=no\ness_cert_id_alg=sha256\n").unwrap();
    let signature = b"authenticated original signature";
    fs::write(dir.join("signature"), signature).unwrap();
    openssl(
        dir,
        &[
            "ts",
            "-query",
            "-data",
            "signature",
            "-sha256",
            "-cert",
            "-out",
            "query.tsq",
        ],
    );
    openssl(
        dir,
        &[
            "ts",
            "-reply",
            "-config",
            "tsa.cnf",
            "-queryfile",
            "query.tsq",
            "-token_out",
            "-out",
            "token.der",
        ],
    );
    openssl(
        dir,
        &[
            "ts",
            "-verify",
            "-token_in",
            "-in",
            "token.der",
            "-data",
            "signature",
            "-CAfile",
            "root.pem",
            "-untrusted",
            "issuer.pem",
        ],
    );
    let roots = vec![der(dir, "root"), der(dir, "other")];
    let issuers = vec![der(dir, "issuer")];
    let signer = VerifiedSigner {
        certificate_der: vec![],
        signature: signature.to_vec(),
        signed_attributes: vec![],
        unsigned_attributes: vec![(
            timestamp::RFC3161_ATTRIBUTE.into(),
            vec![fs::read(dir.join("token.der")).unwrap()],
        )],
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(timestamp::verify_timestamps_with_policy(&signer, &[], &roots, now, false).is_err());
    let supplied = timestamp::verify_timestamps_with_policy(&signer, &issuers, &roots, now, false)
        .unwrap()
        .unwrap();
    assert_eq!(supplied.chain_der.len(), 3);
    let mut paths = 0;
    let verified = timestamp::verify_timestamps_with_path_policy(
        &signer,
        &issuers,
        &roots,
        now,
        false,
        chain::PathLimits::default(),
        |_, _| {
            paths += 1;
            anyhow::ensure!(paths > 1, "first TSA root rejected by policy");
            Ok(())
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(paths, 2);
    assert_eq!(verified.chain_der.len(), 3);
}
