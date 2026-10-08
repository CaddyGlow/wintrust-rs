//! Pure Rust signature primitives. Unknown and weak algorithms fail closed.
use crate::error::{Context, Result, bail};
use alloc::{string::ToString, vec::Vec};
use der::{Decode, Encode, asn1::ObjectIdentifier};
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts};
use sha2::Digest;
use signature::Verifier;

/// Cryptographic compatibility choices. Weak digests require explicit opt-in.
#[derive(Clone, Copy, Debug, Default)]
pub struct CryptoOptions {
    pub allow_sha1: bool,
}

/// Full signature-algorithm validation options. CMS supplies its declared digest;
/// certificate signatures derive their digest from the AlgorithmIdentifier.
#[derive(Clone, Copy, Debug, Default)]
pub struct SignatureOptions {
    pub digest_oid: Option<ObjectIdentifier>,
    pub crypto: CryptoOptions,
}

pub fn digest(oid: ObjectIdentifier, bytes: &[u8], options: &CryptoOptions) -> Result<Vec<u8>> {
    if oid == ObjectIdentifier::new_unwrap("1.3.14.3.2.26") {
        if !options.allow_sha1 {
            return Err(crate::error::Error::policy(
                "SHA-1 requires explicit compatibility policy",
            ));
        }
        return Ok(sha1::Sha1::digest(bytes).to_vec());
    }
    if oid == ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1") {
        return Ok(sha2::Sha256::digest(bytes).to_vec());
    }
    if oid == ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2") {
        return Ok(sha2::Sha384::digest(bytes).to_vec());
    }
    if oid == ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3") {
        return Ok(sha2::Sha512::digest(bytes).to_vec());
    }
    Err(crate::error::Error::unsupported(alloc::format!(
        "digest algorithm {oid}"
    )))
}

pub fn signature_digest(oid: ObjectIdentifier) -> Result<ObjectIdentifier> {
    let sha1 = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
    let sha256 = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    let sha384 = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
    let sha512 = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
    for (signature, digest) in [
        (ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5"), sha1),
        (
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
            sha256,
        ),
        (
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12"),
            sha384,
        ),
        (
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13"),
            sha512,
        ),
        (ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"), sha256),
        (ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"), sha384),
        (ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4"), sha512),
    ] {
        if signature == oid {
            return Ok(digest);
        }
    }
    Err(crate::error::Error::unsupported(alloc::format!(
        "signature algorithm {oid}"
    )))
}

fn verify_signature(
    spki_der: &[u8],
    signature_alg_oid: ObjectIdentifier,
    digest_oid: ObjectIdentifier,
    message: &[u8],
    signature: &[u8],
    options: &CryptoOptions,
) -> Result<()> {
    let allow_sha1 = options.allow_sha1;
    crate::error::ensure!(
        spki_der.len() <= 16 * 1024 && signature.len() <= 2 * 1024,
        crate::error::Error::resource_limit("public key/signature byte limit")
    );
    digest(digest_oid, &[], options)?;
    let signature_algorithm = signature_alg_oid.to_string();
    let digest_algorithm = digest_oid.to_string();
    let spki = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(spki_der)
        .map_err(crate::error::Error::malformed)?;
    match signature_algorithm.as_str() {
        "1.2.840.113549.1.1.1"
        | "1.2.840.113549.1.1.5"
        | "1.2.840.113549.1.1.11"
        | "1.2.840.113549.1.1.12"
        | "1.2.840.113549.1.1.13" => {
            if signature_alg_oid != ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1")
                && signature_digest(signature_alg_oid)? != digest_oid
            {
                bail!(crate::error::Error::malformed(
                    "signature and digest algorithms disagree"
                ));
            }
            let key = rsa::RsaPublicKey::from_public_key_der(spki_der)
                .map_err(crate::error::Error::malformed)?;
            ensure_rsa_key_size(&key)?;
            let sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(crate::error::Error::malformed)?;
            match digest_algorithm.as_str() {
                "1.3.14.3.2.26" if allow_sha1 => {
                    rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(key)
                        .verify(message, &sig)
                        .map_err(crate::error::Error::signature)?
                }
                "2.16.840.1.101.3.4.2.1" => rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key)
                    .verify(message, &sig)
                    .map_err(crate::error::Error::signature)?,
                "2.16.840.1.101.3.4.2.2" => rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(key)
                    .verify(message, &sig)
                    .map_err(crate::error::Error::signature)?,
                "2.16.840.1.101.3.4.2.3" => rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(key)
                    .verify(message, &sig)
                    .map_err(crate::error::Error::signature)?,
                _ => bail!(crate::error::Error::unsupported(alloc::format!(
                    "unsupported RSA digest {digest_oid}"
                ))),
            };
        }
        "1.2.840.10045.4.3.2" | "1.2.840.10045.4.3.3" | "1.2.840.10045.4.3.4" => {
            use signature::hazmat::PrehashVerifier;
            crate::error::ensure!(
                signature_digest(signature_alg_oid)? == digest_oid,
                crate::error::Error::malformed("ECDSA digest mismatch")
            );
            crate::error::ensure!(
                spki.algorithm.oid.to_string() == "1.2.840.10045.2.1",
                "ECDSA requires EC public key"
            );
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .context("missing EC curve")?
                .decode_as::<der::asn1::ObjectIdentifier>()
                .map_err(crate::error::Error::malformed)?
                .to_string();
            let hash = digest(digest_oid, message, options)?;
            match curve.as_str() {
                "1.2.840.10045.3.1.7" => p256::ecdsa::VerifyingKey::from_public_key_der(spki_der)
                    .map_err(crate::error::Error::malformed)?
                    .verify_prehash(
                        &hash,
                        &p256::ecdsa::Signature::from_der(signature)
                            .map_err(crate::error::Error::malformed)?,
                    )
                    .map_err(crate::error::Error::signature)?,
                "1.3.132.0.34" => p384::ecdsa::VerifyingKey::from_public_key_der(spki_der)
                    .map_err(crate::error::Error::malformed)?
                    .verify_prehash(
                        &hash,
                        &p384::ecdsa::Signature::from_der(signature)
                            .map_err(crate::error::Error::malformed)?,
                    )
                    .map_err(crate::error::Error::signature)?,
                _ => bail!(crate::error::Error::unsupported(alloc::format!(
                    "unsupported EC curve {curve}"
                ))),
            }
        }
        _ => bail!(crate::error::Error::unsupported(alloc::format!(
            "unsupported signature algorithm {signature_alg_oid}"
        ))),
    }
    // Parsing SPKI separately rejects malformed key algorithm parameters before crypto dispatch.
    let _ = spki;
    Ok(())
}
/// Verify a full AlgorithmIdentifier, including explicit RSA-PSS parameters.
pub fn verify_algorithm(
    spki_der: &[u8],
    algorithm_der: &[u8],
    message: &[u8],
    signature: &[u8],
    options: &SignatureOptions,
) -> Result<()> {
    let digest_oid = options.digest_oid;
    let allow_sha1 = options.crypto.allow_sha1;
    use crate::error::ensure;
    ensure!(
        algorithm_der.len() <= 16 * 1024
            && spki_der.len() <= 16 * 1024
            && signature.len() <= 2 * 1024,
        crate::error::Error::resource_limit("signature primitive byte limits")
    );
    let algorithm = x509_cert::spki::AlgorithmIdentifierOwned::from_der(algorithm_der)
        .map_err(crate::error::Error::malformed)?;
    let oid = algorithm.oid;
    let oid_string = oid.to_string();
    if oid != ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10") {
        ensure!(
            !oid_string.starts_with("1.2.840.10045.4.") || algorithm.parameters.is_none(),
            "ECDSA signature parameters must be absent"
        );
        if let Some(parameters) = &algorithm.parameters {
            ensure!(
                parameters.is_null(),
                crate::error::Error::unsupported("unsupported signature parameters")
            );
        }
        let digest = match digest_oid {
            Some(d) => d,
            None => signature_digest(oid)?,
        };
        return verify_signature(spki_der, oid, digest, message, signature, &options.crypto);
    }
    let parameters = algorithm
        .parameters
        .context("RSA-PSS requires explicit parameters")?
        .to_der()
        .map_err(crate::error::Error::malformed)?;
    let params =
        rsa::pkcs1::RsaPssParams::from_der(&parameters).map_err(crate::error::Error::malformed)?;
    crate::error::ensure!(
        params.hash.parameters.is_none_or(|p| p.is_null()),
        crate::error::Error::unsupported("unsupported PSS hash parameters")
    );
    crate::error::ensure!(
        params
            .mask_gen
            .parameters
            .is_some_and(|a| a.parameters.is_none_or(|p| p.is_null())),
        crate::error::Error::unsupported("unsupported PSS MGF hash parameters")
    );
    let hash = params.hash.oid;
    ensure!(
        digest_oid.is_none_or(|d| d == hash),
        crate::error::Error::malformed("PSS digest mismatch")
    );
    ensure!(
        params.mask_gen.oid.to_string() == "1.2.840.113549.1.1.8"
            && params
                .mask_gen
                .parameters
                .is_some_and(|p| p.oid == params.hash.oid),
        crate::error::Error::unsupported("unsupported PSS MGF")
    );
    digest(hash, &[], &options.crypto)?;
    let key =
        rsa::RsaPublicKey::from_public_key_der(spki_der).map_err(crate::error::Error::malformed)?;
    ensure_rsa_key_size(&key)?;
    let sig = rsa::pss::Signature::try_from(signature).map_err(crate::error::Error::malformed)?;
    let salt = usize::from(params.salt_len);
    match hash.to_string().as_str() {
        "1.3.14.3.2.26" if allow_sha1 => {
            rsa::pss::VerifyingKey::<sha1::Sha1>::new_with_salt_len(key, salt)
                .verify(message, &sig)
                .map_err(crate::error::Error::signature)?
        }
        "2.16.840.1.101.3.4.2.1" => {
            rsa::pss::VerifyingKey::<sha2::Sha256>::new_with_salt_len(key, salt)
                .verify(message, &sig)
                .map_err(crate::error::Error::signature)?
        }
        "2.16.840.1.101.3.4.2.2" => {
            rsa::pss::VerifyingKey::<sha2::Sha384>::new_with_salt_len(key, salt)
                .verify(message, &sig)
                .map_err(crate::error::Error::signature)?
        }
        "2.16.840.1.101.3.4.2.3" => {
            rsa::pss::VerifyingKey::<sha2::Sha512>::new_with_salt_len(key, salt)
                .verify(message, &sig)
                .map_err(crate::error::Error::signature)?
        }
        _ => bail!(crate::error::Error::unsupported("unsupported PSS hash")),
    }
    Ok(())
}
pub fn verify_certificate(
    child: &x509_cert::Certificate,
    issuer: &x509_cert::Certificate,
    options: &CryptoOptions,
) -> Result<()> {
    crate::error::ensure!(
        child.signature_algorithm == child.tbs_certificate.signature,
        crate::error::Error::malformed("certificate signature algorithm mismatch")
    );
    verify_algorithm(
        &issuer
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(crate::error::Error::malformed)?,
        &child
            .signature_algorithm
            .to_der()
            .map_err(crate::error::Error::malformed)?,
        &child
            .tbs_certificate
            .to_der()
            .map_err(crate::error::Error::malformed)?,
        child.signature.as_bytes().context("nonbyte signature")?,
        &SignatureOptions {
            digest_oid: None,
            crypto: *options,
        },
    )
}

fn ensure_rsa_key_size(key: &rsa::RsaPublicKey) -> Result<()> {
    crate::error::ensure!(
        key.n().bits() >= 2048,
        crate::error::Error::policy("RSA key size below 2048 bits")
    );
    crate::error::ensure!(
        key.n().bits() <= 8192,
        crate::error::Error::resource_limit("RSA key size exceeds 8192 bits")
    );
    Ok(())
}
