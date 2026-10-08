//! PKCS#7/CMS signature verification with exact signed-content binding.
use super::crypto;
use crate::error::{Context, Result, bail, ensure};
use alloc::{borrow::Cow, vec::Vec};
use der::{
    Decode, Encode,
    asn1::{AnyRef, ObjectIdentifier},
};
use x509_cert::Certificate;

/// Select embedded content or explicitly supply detached content.
/// Detached mode requires eContent to be absent and never overrides embedded bytes.
#[derive(Clone, Copy, Debug)]
pub enum SignedDataContent<'a> {
    Embedded,
    Detached(&'a [u8]),
}

#[derive(Clone, Debug)]
pub struct VerifiedSigner {
    pub certificate_der: Vec<u8>,
    pub signature: Vec<u8>,
    pub signed_attributes: Vec<(ObjectIdentifier, Vec<Vec<u8>>)>,
    pub unsigned_attributes: Vec<(ObjectIdentifier, Vec<Vec<u8>>)>,
}
/// Verified content borrows its exact bytes from the CMS or detached input.
/// Signer and certificate reports remain owned.
#[derive(Debug)]
pub struct VerifiedSignedData<'a> {
    pub content_der: &'a [u8],
    pub content_value: &'a [u8],
    pub signers: Vec<VerifiedSigner>,
    pub certificates: Vec<Vec<u8>>,
    /// Attribute/other certificate choices are retained but never used as signing keys or anchors.
    pub ignored_certificate_choices: Vec<Vec<u8>>,
}
use crate::der::{Node, node, oid};
fn all(bytes: &[u8]) -> Result<Vec<Node<'_>>> {
    Ok(crate::der::all(bytes, 100_000)?)
}
fn fields(n: Node<'_>, tag: u8) -> Result<Vec<Node<'_>>> {
    all(crate::der::tagged(n, tag)?.value)
}
fn at<'a>(f: &[Node<'a>], i: usize, tag: u8) -> Result<Node<'a>> {
    Ok(crate::der::field(f, i, tag)?)
}
fn alg(n: Node<'_>) -> Result<ObjectIdentifier> {
    let f = fields(n, 0x30)?;
    ensure!(
        (1..=2).contains(&f.len()),
        crate::error::Error::malformed("invalid algorithm identifier")
    );
    if f.len() == 2 {
        ensure!(
            f[1].tag == 5 && f[1].value.is_empty(),
            crate::error::Error::unsupported("unsupported algorithm parameters")
        );
    }
    Ok(oid(f[0])?)
}
fn attributes(n: Node<'_>) -> Result<Vec<(ObjectIdentifier, Vec<Vec<u8>>)>> {
    let list = all(n.value)?;
    ensure!(
        list.windows(2).all(|p| p[0].full < p[1].full),
        crate::error::Error::malformed("signed attributes not canonical DER SET")
    );
    let mut seen = alloc::collections::BTreeSet::new();
    list.into_iter()
        .map(|a| {
            let f = fields(a, 0x30)?;
            ensure!(
                f.len() == 2,
                crate::error::Error::malformed("invalid attribute")
            );
            let name = oid(f[0])?;
            ensure!(
                seen.insert(name),
                crate::error::Error::malformed("duplicate signed attribute")
            );
            let values = fields(f[1], 0x31)?;
            ensure!(
                !values.is_empty(),
                crate::error::Error::malformed("empty attribute")
            );
            ensure!(
                values.windows(2).all(|p| p[0].full < p[1].full),
                crate::error::Error::malformed("noncanonical attribute SET")
            );
            Ok((name, values.iter().map(|n| n.full.to_vec()).collect()))
        })
        .collect()
}
fn single(attrs: &[(ObjectIdentifier, Vec<Vec<u8>>)], name: ObjectIdentifier) -> Result<&[u8]> {
    let values = &attrs
        .iter()
        .find(|(id, _)| *id == name)
        .context("required signed attribute missing")?
        .1;
    ensure!(
        values.len() == 1,
        crate::error::Error::malformed("multiple required attribute values")
    );
    Ok(&values[0])
}
fn signer(
    n: Node<'_>,
    content: &[u8],
    content_type: Option<ObjectIdentifier>,
    certificates: &[(&[u8], Certificate)],
    allow_sha1: bool,
) -> Result<VerifiedSigner> {
    ensure!(
        certificates.len() <= 64 && certificates.iter().all(|(c, _)| c.len() <= 256 * 1024),
        crate::error::Error::resource_limit("signer certificate limits")
    );
    let f = fields(n, 0x30)?;
    let version = AnyRef::from_der(at(&f, 0, 2)?.full)
        .map_err(crate::error::Error::malformed)?
        .decode_as::<u8>()
        .map_err(crate::error::Error::malformed)?;
    let sid = *f.get(1).context("missing signer id")?;
    ensure!(
        (sid.tag == 0x30 && version == 1) || (sid.tag == 0x80 && version == 3),
        crate::error::Error::malformed("signer identifier/version mismatch")
    );
    let issuer_serial = if sid.tag == 0x30 {
        let ids = fields(sid, 0x30)?;
        ensure!(
            ids.len() == 2,
            crate::error::Error::malformed("invalid issuer serial")
        );
        Some((ids[0].full, ids[1].full))
    } else {
        None
    };
    let mut candidate = None;
    for (bytes, c) in certificates {
        let matches = if let Some((issuer, serial)) = issuer_serial {
            c.tbs_certificate
                .issuer
                .to_der()
                .map_err(crate::error::Error::malformed)?
                == issuer
                && c.tbs_certificate
                    .serial_number
                    .to_der()
                    .map_err(crate::error::Error::malformed)?
                    == serial
        } else {
            c.tbs_certificate
                .get::<x509_cert::ext::pkix::SubjectKeyIdentifier>()
                .map_err(crate::error::Error::malformed)?
                .is_some_and(|(_, ski)| ski.0.as_bytes() == sid.value)
        };
        if matches {
            ensure!(
                candidate.is_none(),
                crate::error::Error::malformed("signer certificate missing or ambiguous")
            );
            candidate = Some((bytes, c));
        }
    }
    let (certificate, cert) = candidate.context(crate::error::Error::malformed(
        "signer certificate missing or ambiguous",
    ))?;
    let digest_oid = alg(at(&f, 2, 0x30)?)?;
    let mut pos = 3;
    let attrs_node = f.get(pos).copied().filter(|n| n.tag == 0xa0);
    let signed_attributes = if let Some(attrs) = attrs_node {
        pos += 1;
        attributes(attrs)?
    } else {
        ensure!(
            content_type == Some(ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1")),
            "signed attributes required for non-data content"
        );
        Vec::new()
    };
    if attrs_node.is_some() {
        let raw_digest = single(
            &signed_attributes,
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4"),
        )?;
        let (digest_node, len) = node(raw_digest)?;
        ensure!(
            len == raw_digest.len() && digest_node.tag == 4,
            crate::error::Error::malformed("invalid messageDigest")
        );
        ensure!(
            crypto::digest(digest_oid, content, &crypto::CryptoOptions { allow_sha1 })?
                == digest_node.value,
            crate::error::Error::signature("signed content digest mismatch")
        );
        if let Some(expected) = content_type {
            let raw = single(
                &signed_attributes,
                ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3"),
            )?;
            let (n, len) = node(raw)?;
            ensure!(
                len == raw.len() && oid(n)? == expected,
                crate::error::Error::malformed("signed contentType mismatch")
            );
        } else {
            ensure!(
                !signed_attributes
                    .iter()
                    .any(|(oid, _)| *oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3")),
                "counter-signature must omit contentType"
            );
        }
    }
    let signature_algorithm = at(&f, pos, 0x30)?;
    pos += 1;
    let signature = at(&f, pos, 4)?.value.to_vec();
    pos += 1;
    let unsigned_attributes = if f.get(pos).is_some_and(|n| n.tag == 0xa1) {
        let attrs = attributes(f[pos])?;
        pos += 1;
        attrs
    } else {
        Vec::new()
    };
    ensure!(
        pos == f.len(),
        crate::error::Error::malformed("unexpected signer fields")
    );
    let signed_bytes = if let Some(attrs) = attrs_node {
        let mut bytes = attrs.full.to_vec();
        bytes[0] = 0x31;
        Cow::Owned(bytes)
    } else {
        Cow::Borrowed(content)
    };
    crypto::verify_algorithm(
        &cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(crate::error::Error::malformed)?,
        signature_algorithm.full,
        &signed_bytes,
        &signature,
        &crypto::SignatureOptions {
            digest_oid: Some(digest_oid),
            crypto: crypto::CryptoOptions { allow_sha1 },
        },
    )?;
    Ok(VerifiedSigner {
        certificate_der: certificate.to_vec(),
        signature,
        signed_attributes,
        unsigned_attributes,
    })
}
/// Bounded CMS content and cryptographic compatibility settings.
#[derive(Clone, Copy, Debug)]
pub struct SignedDataOptions<'a> {
    pub expected_content_oid: ObjectIdentifier,
    pub content: SignedDataContent<'a>,
    pub crypto: crypto::CryptoOptions,
}
impl SignedDataOptions<'_> {
    pub fn new(expected_content_oid: ObjectIdentifier) -> Self {
        Self {
            expected_content_oid,
            content: SignedDataContent::Embedded,
            crypto: crypto::CryptoOptions::default(),
        }
    }
}

/// Verify every CMS signer and exact content binding without assigning certificate trust.
/// Resource limits are 32 MiB for each input, 64 certificates and 16 signers.
/// Legacy PKCS#7 structured content retains its original content-value hashing.
pub fn verify_signed_data<'a>(
    bytes: &'a [u8],
    options: &SignedDataOptions<'a>,
) -> Result<VerifiedSignedData<'a>> {
    let expected_content_oid = options.expected_content_oid;
    let content = options.content;
    let allow_sha1 = options.crypto.allow_sha1;
    preflight(bytes)?;
    ensure!(
        bytes.len() <= 32 * 1024 * 1024,
        crate::error::Error::resource_limit("SignedData byte limit")
    );
    let (root, len) = node(bytes)?;
    ensure!(
        len == bytes.len(),
        crate::error::Error::malformed("trailing SignedData bytes")
    );
    let outer = fields(root, 0x30)?;
    ensure!(
        outer.len() == 2 && oid(outer[0])? == ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2"),
        "expected SignedData"
    );
    let wrap = fields(outer[1], 0xa0)?;
    ensure!(
        wrap.len() == 1,
        crate::error::Error::malformed("invalid SignedData wrapper")
    );
    let sd = fields(wrap[0], 0x30)?;
    let version = AnyRef::from_der(at(&sd, 0, 2)?.full)
        .map_err(crate::error::Error::malformed)?
        .decode_as::<u8>()
        .map_err(crate::error::Error::malformed)?;
    ensure!(
        (1..=5).contains(&version),
        crate::error::Error::unsupported("unsupported SignedData version")
    );
    let algorithms = fields(at(&sd, 1, 0x31)?, 0x31)?
        .into_iter()
        .map(alg)
        .collect::<Result<Vec<_>>>()?;
    let info = fields(at(&sd, 2, 0x30)?, 0x30)?;
    ensure!(
        (1..=2).contains(&info.len()) && oid(info[0])? == expected_content_oid,
        "wrong encapsulated content type"
    );
    let (content_der, content_value) = match content {
        SignedDataContent::Detached(bytes) => {
            ensure!(
                info.len() == 1,
                "detached mode requires absent embedded content"
            );
            ensure!(
                bytes.len() <= 32 * 1024 * 1024,
                crate::error::Error::resource_limit("detached content byte limit")
            );
            (bytes, bytes)
        }
        SignedDataContent::Embedded => {
            ensure!(
                info.len() == 2,
                "detached content must be supplied explicitly"
            );
            let encap = fields(info[1], 0xa0)?;
            ensure!(
                encap.len() == 1,
                crate::error::Error::malformed("invalid content wrapper")
            );
            if encap[0].tag == 4 {
                (encap[0].value, encap[0].value)
            } else {
                (encap[0].full, encap[0].value)
            }
        }
    };
    let mut pos = 3;
    let mut certificates = Vec::new();
    let mut ignored_certificate_choices = Vec::new();
    if sd.get(pos).is_some_and(|n| n.tag == 0xa0) {
        let certificate_choices = all(sd[pos].value)?;
        // RFC 5652 sections 3 and 10.2.3 permit BER CertificateSet ordering.
        // This implicit [0] collection is outside signedAttrs. Preserve each
        // original certificate's strict DER bytes; signedAttrs remain canonical
        // DER and are verified without reencoding or signature substitution.
        for c in certificate_choices {
            ensure!(
                c.full.len() <= 256 * 1024,
                crate::error::Error::resource_limit("certificate choice byte limit")
            );
            ensure!(
                certificates.len() + ignored_certificate_choices.len() < 64,
                crate::error::Error::resource_limit("certificate count limit")
            );
            if matches!(c.tag, 0xa0..=0xa3) {
                let choice_fields = all(c.value)?;
                if c.tag == 0xa3 {
                    ensure!(
                        choice_fields.len() == 2 && choice_fields[0].tag == 6,
                        crate::error::Error::malformed("malformed other certificate choice")
                    );
                    oid(choice_fields[0])?;
                } else {
                    ensure!(
                        choice_fields.len() == 3
                            && choice_fields[0].tag == 0x30
                            && choice_fields[1].tag == 0x30
                            && choice_fields[2].tag == 3,
                        crate::error::Error::malformed(
                            "malformed attribute/extended certificate choice"
                        )
                    );
                    AnyRef::from_der(choice_fields[2].full)
                        .map_err(crate::error::Error::malformed)?
                        .decode_as::<der::asn1::BitStringRef>()
                        .map_err(crate::error::Error::malformed)?;
                }
                ignored_certificate_choices.push(c.full.to_vec());
                continue;
            }
            ensure!(
                c.tag == 0x30,
                crate::error::Error::unsupported("unsupported certificate choice")
            );
            let parsed = Certificate::from_der(c.full).map_err(crate::error::Error::malformed)?;
            if !certificates
                .iter()
                .any(|(b, _): &(&[u8], Certificate)| *b == c.full)
            {
                certificates.push((c.full, parsed));
            }
        }
        pos += 1;
    }
    if sd.get(pos).is_some_and(|n| n.tag == 0xa1) {
        bail!("embedded CRLs not accepted; supply verified revocation evidence explicitly");
    }
    let raw_signers = fields(at(&sd, pos, 0x31)?, 0x31)?;
    pos += 1;
    ensure!(
        raw_signers.len() <= 16,
        crate::error::Error::resource_limit("signer count limit")
    );
    ensure!(
        pos == sd.len() && !raw_signers.is_empty(),
        crate::error::Error::malformed("invalid signer collection")
    );
    let mut signers = Vec::new();
    for raw in raw_signers {
        let f = fields(raw, 0x30)?;
        ensure!(
            algorithms.contains(&alg(at(&f, 2, 0x30)?)?),
            "signer digest not declared"
        );
        signers.push(signer(
            raw,
            content_value,
            Some(expected_content_oid),
            &certificates,
            allow_sha1,
        )?);
    }
    Ok(VerifiedSignedData {
        content_der,
        content_value,
        signers,
        certificates: certificates
            .into_iter()
            .map(|(bytes, _)| bytes.to_vec())
            .collect(),
        ignored_certificate_choices,
    })
}
/// Verify a legacy PKCS#9 counter-signature bound to the original signature bytes.
pub fn verify_counter_signer(
    signer_info_der: &[u8],
    original_signature: &[u8],
    certificates: super::CertificateStore<'_>,
    options: &crypto::CryptoOptions,
) -> Result<VerifiedSigner> {
    let allow_sha1 = options.allow_sha1;
    ensure!(
        original_signature.len() <= 16 * 1024,
        crate::error::Error::resource_limit("counter-signature target size limit")
    );
    preflight(signer_info_der)?;
    let (n, len) = node(signer_info_der)?;
    ensure!(
        len == signer_info_der.len(),
        crate::error::Error::malformed("trailing counter-signer bytes")
    );
    ensure!(
        certificates.len() <= 64 && certificates.iter().all(|c| c.len() <= 256 * 1024),
        crate::error::Error::resource_limit("signer certificate limits")
    );
    let certificates = certificates
        .iter()
        .map(|bytes| {
            Ok((
                bytes,
                Certificate::from_der(bytes).map_err(crate::error::Error::malformed)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    signer(n, original_signature, None, &certificates, allow_sha1)
}

fn preflight(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= 32 * 1024 * 1024,
        crate::error::Error::resource_limit("ASN.1 byte limit")
    );
    let (root, len) = node(bytes)?;
    ensure!(
        len == bytes.len(),
        crate::error::Error::malformed("trailing ASN.1 bytes")
    );
    crate::der::preflight(root, crate::catalog::CatalogLimits::default(), &mut 0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_attribute_value_set_is_malformed_input() {
        let (attribute_set, _) = node(&[0xa0, 9, 0x30, 7, 0x06, 3, 0x2a, 3, 4, 0x31, 0]).unwrap();
        assert!(matches!(
            attributes(attribute_set),
            Err(crate::error::Error::MalformedInput(_))
        ));
    }
}
