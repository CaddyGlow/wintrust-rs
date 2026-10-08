//! Pure Rust signature primitives. Unknown and weak algorithms fail closed.
use alloc::{string::ToString, vec::Vec};
use anyhow::{Context, Result, bail};
use der::{Decode, Encode};
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts};
use sha2::Digest;
use signature::Verifier;

pub fn digest(oid: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    digest_with_policy(oid, bytes, false)
}
pub fn digest_with_policy(oid: &str, bytes: &[u8], allow_sha1: bool) -> Result<Vec<u8>> {
    Ok(match oid {
        "1.3.14.3.2.26" if allow_sha1 => sha1::Sha1::digest(bytes).to_vec(),
        "2.16.840.1.101.3.4.2.1" => sha2::Sha256::digest(bytes).to_vec(),
        "2.16.840.1.101.3.4.2.2" => sha2::Sha384::digest(bytes).to_vec(),
        "2.16.840.1.101.3.4.2.3" => sha2::Sha512::digest(bytes).to_vec(),
        _ => bail!("unsupported or weak digest algorithm {oid}"),
    })
}
pub fn signature_digest(oid: &str) -> Result<&'static str> {
    Ok(match oid {
        "1.2.840.113549.1.1.5" => "1.3.14.3.2.26",
        "1.2.840.113549.1.1.11" | "1.2.840.10045.4.3.2" => "2.16.840.1.101.3.4.2.1",
        "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => "2.16.840.1.101.3.4.2.2",
        "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => "2.16.840.1.101.3.4.2.3",
        _ => bail!("unsupported certificate signature {oid}"),
    })
}
pub fn verify(
    spki_der: &[u8],
    signature_alg_oid: &str,
    digest_oid: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    verify_with_policy(
        spki_der,
        signature_alg_oid,
        digest_oid,
        message,
        signature,
        false,
    )
}
pub fn verify_with_policy(
    spki_der: &[u8],
    signature_alg_oid: &str,
    digest_oid: &str,
    message: &[u8],
    signature: &[u8],
    allow_sha1: bool,
) -> Result<()> {
    anyhow::ensure!(
        spki_der.len() <= 16 * 1024 && signature.len() <= 2 * 1024,
        "public key/signature byte limit"
    );
    digest_with_policy(digest_oid, &[], allow_sha1)?;
    let spki = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(spki_der)
        .map_err(anyhow::Error::msg)?;
    match signature_alg_oid {
        "1.2.840.113549.1.1.1"
        | "1.2.840.113549.1.1.5"
        | "1.2.840.113549.1.1.11"
        | "1.2.840.113549.1.1.12"
        | "1.2.840.113549.1.1.13" => {
            if signature_alg_oid != "1.2.840.113549.1.1.1"
                && signature_digest(signature_alg_oid)? != digest_oid
            {
                bail!("signature and digest algorithms disagree");
            }
            let key =
                rsa::RsaPublicKey::from_public_key_der(spki_der).map_err(anyhow::Error::msg)?;
            if key.n().bits() < 2048 || key.n().bits() > 8192 {
                bail!("RSA key size outside 2048..8192");
            }
            let sig = rsa::pkcs1v15::Signature::try_from(signature).map_err(anyhow::Error::msg)?;
            match digest_oid {
                "1.3.14.3.2.26" if allow_sha1 => {
                    rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(key)
                        .verify(message, &sig)
                        .map_err(anyhow::Error::msg)?
                }
                "2.16.840.1.101.3.4.2.1" => rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key)
                    .verify(message, &sig)
                    .map_err(anyhow::Error::msg)?,
                "2.16.840.1.101.3.4.2.2" => rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(key)
                    .verify(message, &sig)
                    .map_err(anyhow::Error::msg)?,
                "2.16.840.1.101.3.4.2.3" => rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(key)
                    .verify(message, &sig)
                    .map_err(anyhow::Error::msg)?,
                _ => bail!("unsupported RSA digest {digest_oid}"),
            };
        }
        "1.2.840.10045.4.3.2" | "1.2.840.10045.4.3.3" | "1.2.840.10045.4.3.4" => {
            use signature::hazmat::PrehashVerifier;
            anyhow::ensure!(
                signature_digest(signature_alg_oid)? == digest_oid,
                "ECDSA digest mismatch"
            );
            anyhow::ensure!(
                spki.algorithm.oid.to_string() == "1.2.840.10045.2.1",
                "ECDSA requires EC public key"
            );
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .context("missing EC curve")?
                .decode_as::<der::asn1::ObjectIdentifier>()
                .map_err(anyhow::Error::msg)?
                .to_string();
            let hash = digest_with_policy(digest_oid, message, allow_sha1)?;
            match curve.as_str() {
                "1.2.840.10045.3.1.7" => p256::ecdsa::VerifyingKey::from_public_key_der(spki_der)
                    .map_err(anyhow::Error::msg)?
                    .verify_prehash(
                        &hash,
                        &p256::ecdsa::Signature::from_der(signature).map_err(anyhow::Error::msg)?,
                    )
                    .map_err(anyhow::Error::msg)?,
                "1.3.132.0.34" => p384::ecdsa::VerifyingKey::from_public_key_der(spki_der)
                    .map_err(anyhow::Error::msg)?
                    .verify_prehash(
                        &hash,
                        &p384::ecdsa::Signature::from_der(signature).map_err(anyhow::Error::msg)?,
                    )
                    .map_err(anyhow::Error::msg)?,
                _ => bail!("unsupported EC curve {curve}"),
            }
        }
        _ => bail!("unsupported signature algorithm {signature_alg_oid}"),
    }
    // Parsing SPKI separately rejects malformed key algorithm parameters before crypto dispatch.
    let _ = spki;
    Ok(())
}
pub fn verify_certificate(
    child: &x509_cert::Certificate,
    issuer: &x509_cert::Certificate,
) -> Result<()> {
    verify_certificate_with_policy(child, issuer, false)
}

/// Verify a full AlgorithmIdentifier, including explicit RSA-PSS parameters.
pub fn verify_algorithm(
    spki_der: &[u8],
    algorithm_der: &[u8],
    digest_oid: Option<&str>,
    message: &[u8],
    signature: &[u8],
    allow_sha1: bool,
) -> Result<()> {
    use anyhow::ensure;
    ensure!(
        algorithm_der.len() <= 16 * 1024
            && spki_der.len() <= 16 * 1024
            && signature.len() <= 2 * 1024,
        "signature primitive byte limits"
    );
    let algorithm = x509_cert::spki::AlgorithmIdentifierOwned::from_der(algorithm_der)
        .map_err(anyhow::Error::msg)?;
    let oid = algorithm.oid.to_string();
    if oid != "1.2.840.113549.1.1.10" {
        ensure!(
            !oid.starts_with("1.2.840.10045.4.") || algorithm.parameters.is_none(),
            "ECDSA signature parameters must be absent"
        );
        if let Some(parameters) = &algorithm.parameters {
            ensure!(parameters.is_null(), "unsupported signature parameters");
        }
        let digest = match digest_oid {
            Some(d) => d,
            None => signature_digest(&oid)?,
        };
        return verify_with_policy(spki_der, &oid, digest, message, signature, allow_sha1);
    }
    let parameters = algorithm
        .parameters
        .context("RSA-PSS requires explicit parameters")?
        .to_der()
        .map_err(anyhow::Error::msg)?;
    let params = rsa::pkcs1::RsaPssParams::from_der(&parameters).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        params.hash.parameters.is_none_or(|p| p.is_null()),
        "unsupported PSS hash parameters"
    );
    anyhow::ensure!(
        params
            .mask_gen
            .parameters
            .is_some_and(|a| a.parameters.is_none_or(|p| p.is_null())),
        "unsupported PSS MGF hash parameters"
    );
    let hash = params.hash.oid.to_string();
    ensure!(digest_oid.is_none_or(|d| d == hash), "PSS digest mismatch");
    ensure!(
        params.mask_gen.oid.to_string() == "1.2.840.113549.1.1.8"
            && params
                .mask_gen
                .parameters
                .is_some_and(|p| p.oid == params.hash.oid),
        "unsupported PSS MGF"
    );
    digest_with_policy(&hash, &[], allow_sha1)?;
    let key = rsa::RsaPublicKey::from_public_key_der(spki_der).map_err(anyhow::Error::msg)?;
    ensure!(
        (2048..=8192).contains(&key.n().bits()),
        "RSA key size limit"
    );
    let sig = rsa::pss::Signature::try_from(signature).map_err(anyhow::Error::msg)?;
    let salt = usize::from(params.salt_len);
    match hash.as_str() {
        "1.3.14.3.2.26" if allow_sha1 => {
            rsa::pss::VerifyingKey::<sha1::Sha1>::new_with_salt_len(key, salt)
                .verify(message, &sig)
                .map_err(anyhow::Error::msg)?
        }
        "2.16.840.1.101.3.4.2.1" => {
            rsa::pss::VerifyingKey::<sha2::Sha256>::new_with_salt_len(key, salt)
                .verify(message, &sig)
                .map_err(anyhow::Error::msg)?
        }
        "2.16.840.1.101.3.4.2.2" => {
            rsa::pss::VerifyingKey::<sha2::Sha384>::new_with_salt_len(key, salt)
                .verify(message, &sig)
                .map_err(anyhow::Error::msg)?
        }
        "2.16.840.1.101.3.4.2.3" => {
            rsa::pss::VerifyingKey::<sha2::Sha512>::new_with_salt_len(key, salt)
                .verify(message, &sig)
                .map_err(anyhow::Error::msg)?
        }
        _ => bail!("unsupported PSS hash"),
    }
    Ok(())
}
pub fn verify_certificate_with_policy(
    child: &x509_cert::Certificate,
    issuer: &x509_cert::Certificate,
    allow_sha1: bool,
) -> Result<()> {
    anyhow::ensure!(
        child.signature_algorithm == child.tbs_certificate.signature,
        "certificate signature algorithm mismatch"
    );
    verify_algorithm(
        &issuer
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(anyhow::Error::msg)?,
        &child
            .signature_algorithm
            .to_der()
            .map_err(anyhow::Error::msg)?,
        None,
        &child.tbs_certificate.to_der().map_err(anyhow::Error::msg)?,
        child.signature.as_bytes().context("nonbyte signature")?,
        allow_sha1,
    )
}
