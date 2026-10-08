//! Shared deterministic certificate mechanics; scenarios choose their extensions.
#![allow(dead_code)]
use der::{Decode, Encode, asn1::OctetString};
use p256::{
    ecdsa::{Signature, SigningKey},
    pkcs8::EncodePublicKey,
};
use signature::Signer;
use x509_cert::{Certificate, ext::Extension};

pub fn key() -> SigningKey {
    SigningKey::from_bytes((&[7; 32]).into()).unwrap()
}
pub fn extension(oid: &str, bytes: Vec<u8>, critical: bool) -> Extension {
    Extension {
        extn_id: oid.parse().unwrap(),
        critical,
        extn_value: OctetString::new(bytes).unwrap(),
    }
}
pub fn prepare(mut certificate: Certificate, remove: &[&str]) -> Certificate {
    let public = key().verifying_key().to_public_key_der().unwrap();
    certificate.tbs_certificate.subject_public_key_info =
        x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(public.as_bytes()).unwrap();
    certificate.tbs_certificate.signature.oid = "1.2.840.10045.4.3.2".parse().unwrap();
    certificate.tbs_certificate.signature.parameters = None;
    certificate.signature_algorithm = certificate.tbs_certificate.signature.clone();
    certificate
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .retain(|e| !remove.contains(&e.extn_id.to_string().as_str()));
    certificate
}
pub fn sign_certificate(mut certificate: Certificate) -> Certificate {
    let signature: Signature = key().sign(&certificate.tbs_certificate.to_der().unwrap());
    certificate.signature =
        der::asn1::BitString::from_bytes(signature.to_der().as_bytes()).unwrap();
    certificate
}
pub fn sign(certificate: Certificate) -> Vec<u8> {
    sign_certificate(certificate).to_der().unwrap()
}
pub fn templates(remove: &[&str]) -> (Certificate, Certificate) {
    let cms = wintrust::portable::signed::verify_signed_data(
        include_bytes!("../fixtures/catalog.cat"),
        &wintrust::portable::signed::SignedDataOptions::new(
            "1.3.6.1.4.1.311.10.1".parse().unwrap(),
        ),
    )
    .unwrap();
    (
        prepare(
            Certificate::from_der(&cms.signers[0].certificate_der).unwrap(),
            remove,
        ),
        prepare(
            Certificate::from_der(include_bytes!("../fixtures/root.der")).unwrap(),
            remove,
        ),
    )
}

/// Explicit owned-buffer view used by synthetic path scenarios.
pub fn chain_options<'a>(
    candidates: &'a [Vec<u8>],
    roots: &'a [Vec<u8>],
    time: u64,
    eku: &str,
) -> wintrust::portable::chain::ChainOptions<'a> {
    let mut options =
        wintrust::portable::chain::ChainOptions::new(roots, time, eku.parse().unwrap());
    options.candidates = candidates.into();
    options
}
pub fn require_policy(condition: bool, message: &str) -> wintrust::error::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(wintrust::error::Error::policy(message))
    }
}
