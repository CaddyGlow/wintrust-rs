//! PKCS#7/CMS signature verification with exact signed-content binding.
use super::crypto;
use anyhow::{Context, Result, bail, ensure};
use der::{Decode, Encode, Reader, SliceReader, asn1::AnyRef};
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
    pub signed_attributes: Vec<(String, Vec<Vec<u8>>)>,
    pub unsigned_attributes: Vec<(String, Vec<Vec<u8>>)>,
}
#[derive(Debug)]
pub struct VerifiedSignedData {
    pub content_der: Vec<u8>,
    pub content_value: Vec<u8>,
    pub signers: Vec<VerifiedSigner>,
    pub certificates: Vec<Vec<u8>>,
    /// Attribute/other certificate choices are retained but never used as signing keys or anchors.
    pub ignored_certificate_choices: Vec<Vec<u8>>,
}
#[derive(Clone, Copy)]
struct Node<'a> {
    tag: u8,
    full: &'a [u8],
    value: &'a [u8],
}
fn node(bytes: &[u8]) -> Result<(Node<'_>, usize)> {
    let mut r = SliceReader::new(bytes)?;
    let a = AnyRef::decode(&mut r)?;
    let len = usize::try_from(r.position())?;
    Ok((
        Node {
            tag: bytes[0],
            full: &bytes[..len],
            value: a.value(),
        },
        len,
    ))
}
fn all(bytes: &[u8]) -> Result<Vec<Node<'_>>> {
    let mut rest = bytes;
    let mut out = Vec::new();
    while !rest.is_empty() {
        ensure!(out.len() < 100_000, "ASN.1 collection limit");
        let (n, size) = node(rest)?;
        out.push(n);
        rest = &rest[size..];
    }
    Ok(out)
}
fn fields(n: Node<'_>, tag: u8) -> Result<Vec<Node<'_>>> {
    ensure!(n.tag == tag, "unexpected ASN.1 tag");
    all(n.value)
}
fn at<'a>(f: &[Node<'a>], i: usize, tag: u8) -> Result<Node<'a>> {
    let n = *f.get(i).context("missing field")?;
    ensure!(n.tag == tag, "unexpected field tag");
    Ok(n)
}
fn oid(n: Node<'_>) -> Result<String> {
    ensure!(n.tag == 6, "missing OID");
    Ok(AnyRef::from_der(n.full)?
        .decode_as::<der::asn1::ObjectIdentifier>()?
        .to_string())
}
fn alg(n: Node<'_>) -> Result<String> {
    let f = fields(n, 0x30)?;
    ensure!((1..=2).contains(&f.len()), "invalid algorithm identifier");
    if f.len() == 2 {
        ensure!(
            f[1].tag == 5 && f[1].value.is_empty(),
            "unsupported algorithm parameters"
        );
    }
    oid(f[0])
}
fn attributes(n: Node<'_>) -> Result<Vec<(String, Vec<Vec<u8>>)>> {
    let list = all(n.value)?;
    ensure!(
        list.windows(2).all(|p| p[0].full < p[1].full),
        "signed attributes not canonical DER SET"
    );
    let mut seen = std::collections::HashSet::new();
    list.into_iter()
        .map(|a| {
            let f = fields(a, 0x30)?;
            ensure!(f.len() == 2, "invalid attribute");
            let name = oid(f[0])?;
            ensure!(seen.insert(name.clone()), "duplicate signed attribute");
            let values = fields(f[1], 0x31)?;
            ensure!(!values.is_empty(), "empty attribute");
            ensure!(
                values.windows(2).all(|p| p[0].full < p[1].full),
                "noncanonical attribute SET"
            );
            Ok((name, values.iter().map(|n| n.full.to_vec()).collect()))
        })
        .collect()
}
fn single<'a>(attrs: &'a [(String, Vec<Vec<u8>>)], name: &str) -> Result<&'a [u8]> {
    let values = &attrs
        .iter()
        .find(|(id, _)| id == name)
        .context("required signed attribute missing")?
        .1;
    ensure!(values.len() == 1, "multiple required attribute values");
    Ok(&values[0])
}
fn signer(
    n: Node<'_>,
    content: &[u8],
    content_type: Option<&str>,
    certificates: &[Vec<u8>],
    allow_sha1: bool,
) -> Result<VerifiedSigner> {
    ensure!(
        certificates.len() <= 64 && certificates.iter().all(|c| c.len() <= 256 * 1024),
        "signer certificate limits"
    );
    let f = fields(n, 0x30)?;
    let version = AnyRef::from_der(at(&f, 0, 2)?.full)?.decode_as::<u8>()?;
    let sid = *f.get(1).context("missing signer id")?;
    ensure!(
        (sid.tag == 0x30 && version == 1) || (sid.tag == 0x80 && version == 3),
        "signer identifier/version mismatch"
    );
    let mut candidates = Vec::new();
    for bytes in certificates {
        let c = Certificate::from_der(bytes)?;
        let matches = if sid.tag == 0x30 {
            let ids = fields(sid, 0x30)?;
            ensure!(ids.len() == 2, "invalid issuer serial");
            c.tbs_certificate.issuer.to_der()? == ids[0].full
                && c.tbs_certificate.serial_number.to_der()? == ids[1].full
        } else {
            c.tbs_certificate
                .get::<x509_cert::ext::pkix::SubjectKeyIdentifier>()?
                .is_some_and(|(_, ski)| ski.0.as_bytes() == sid.value)
        };
        if matches {
            candidates.push((bytes, c));
        }
    }
    ensure!(
        candidates.len() == 1,
        "signer certificate missing or ambiguous"
    );
    let (certificate, cert) = &candidates[0];
    let digest_oid = alg(at(&f, 2, 0x30)?)?;
    let mut pos = 3;
    let attrs_node = f.get(pos).copied().filter(|n| n.tag == 0xa0);
    let signed_attributes = if let Some(attrs) = attrs_node {
        pos += 1;
        attributes(attrs)?
    } else {
        ensure!(
            content_type == Some("1.2.840.113549.1.7.1"),
            "signed attributes required for non-data content"
        );
        Vec::new()
    };
    if attrs_node.is_some() {
        let raw_digest = single(&signed_attributes, "1.2.840.113549.1.9.4")?;
        let (digest_node, len) = node(raw_digest)?;
        ensure!(
            len == raw_digest.len() && digest_node.tag == 4,
            "invalid messageDigest"
        );
        ensure!(
            crypto::digest_with_policy(&digest_oid, content, allow_sha1)? == digest_node.value,
            "signed content digest mismatch"
        );
        if let Some(expected) = content_type {
            let raw = single(&signed_attributes, "1.2.840.113549.1.9.3")?;
            let (n, len) = node(raw)?;
            ensure!(
                len == raw.len() && oid(n)? == expected,
                "signed contentType mismatch"
            );
        } else {
            ensure!(
                !signed_attributes
                    .iter()
                    .any(|(oid, _)| oid == "1.2.840.113549.1.9.3"),
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
    ensure!(pos == f.len(), "unexpected signer fields");
    let signed_bytes = if let Some(attrs) = attrs_node {
        let mut bytes = attrs.full.to_vec();
        bytes[0] = 0x31;
        bytes
    } else {
        content.to_vec()
    };
    crypto::verify_algorithm(
        &cert.tbs_certificate.subject_public_key_info.to_der()?,
        signature_algorithm.full,
        Some(&digest_oid),
        &signed_bytes,
        &signature,
        allow_sha1,
    )?;
    Ok(VerifiedSigner {
        certificate_der: certificate.to_vec(),
        signature,
        signed_attributes,
        unsigned_attributes,
    })
}
/// Verify cryptographic signatures and signed content binding; no chain or revocation trust.
pub fn verify_signed_data(bytes: &[u8], expected_content_oid: &str) -> Result<VerifiedSignedData> {
    verify_signed_data_with_policy(bytes, expected_content_oid, false)
}
pub fn verify_signed_data_with_policy(
    bytes: &[u8],
    expected_content_oid: &str,
    allow_sha1: bool,
) -> Result<VerifiedSignedData> {
    verify_cms_signed_data(
        bytes,
        expected_content_oid,
        SignedDataContent::Embedded,
        allow_sha1,
    )
}

/// Verify every CMS signer and exact content binding without assigning certificate trust.
/// Resource limits are 32 MiB for each input, 64 certificates and 16 signers.
/// Legacy PKCS#7 structured content retains its original content-value hashing.
pub fn verify_cms_signed_data(
    bytes: &[u8],
    expected_content_oid: &str,
    content: SignedDataContent<'_>,
    allow_sha1: bool,
) -> Result<VerifiedSignedData> {
    preflight(bytes)?;
    ensure!(bytes.len() <= 32 * 1024 * 1024, "SignedData byte limit");
    let (root, len) = node(bytes)?;
    ensure!(len == bytes.len(), "trailing SignedData bytes");
    let outer = fields(root, 0x30)?;
    ensure!(
        outer.len() == 2 && oid(outer[0])? == "1.2.840.113549.1.7.2",
        "expected SignedData"
    );
    let wrap = fields(outer[1], 0xa0)?;
    ensure!(wrap.len() == 1, "invalid SignedData wrapper");
    let sd = fields(wrap[0], 0x30)?;
    let version = AnyRef::from_der(at(&sd, 0, 2)?.full)?.decode_as::<u8>()?;
    ensure!((1..=5).contains(&version), "unsupported SignedData version");
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
                "detached content byte limit"
            );
            (bytes.to_vec(), bytes.to_vec())
        }
        SignedDataContent::Embedded => {
            ensure!(
                info.len() == 2,
                "detached content must be supplied explicitly"
            );
            let encap = fields(info[1], 0xa0)?;
            ensure!(encap.len() == 1, "invalid content wrapper");
            if encap[0].tag == 4 {
                (encap[0].value.to_vec(), encap[0].value.to_vec())
            } else {
                (encap[0].full.to_vec(), encap[0].value.to_vec())
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
            ensure!(c.full.len() <= 256 * 1024, "certificate choice byte limit");
            ensure!(
                certificates.len() + ignored_certificate_choices.len() < 64,
                "certificate count limit"
            );
            if matches!(c.tag, 0xa0..=0xa3) {
                let choice_fields = all(c.value)?;
                if c.tag == 0xa3 {
                    ensure!(
                        choice_fields.len() == 2 && choice_fields[0].tag == 6,
                        "malformed other certificate choice"
                    );
                    oid(choice_fields[0])?;
                } else {
                    ensure!(
                        choice_fields.len() == 3
                            && choice_fields[0].tag == 0x30
                            && choice_fields[1].tag == 0x30
                            && choice_fields[2].tag == 3,
                        "malformed attribute/extended certificate choice"
                    );
                    AnyRef::from_der(choice_fields[2].full)?
                        .decode_as::<der::asn1::BitStringRef>()?;
                }
                ignored_certificate_choices.push(c.full.to_vec());
                continue;
            }
            ensure!(c.tag == 0x30, "unsupported certificate choice");
            Certificate::from_der(c.full)?;
            if !certificates
                .iter()
                .any(|b: &Vec<u8>| b.as_slice() == c.full)
            {
                certificates.push(c.full.to_vec());
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
        pos == sd.len() && !raw_signers.is_empty() && raw_signers.len() <= 16,
        "invalid signer collection"
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
            &content_value,
            Some(expected_content_oid),
            &certificates,
            allow_sha1,
        )?);
    }
    Ok(VerifiedSignedData {
        content_der,
        content_value,
        signers,
        certificates,
        ignored_certificate_choices,
    })
}
/// Verify a legacy PKCS#9 counter-signature bound to the original signature bytes.
pub fn verify_counter_signer(
    signer_info_der: &[u8],
    original_signature: &[u8],
    certificates: &[Vec<u8>],
) -> Result<VerifiedSigner> {
    verify_counter_signer_with_policy(signer_info_der, original_signature, certificates, false)
}
pub fn verify_counter_signer_with_policy(
    signer_info_der: &[u8],
    original_signature: &[u8],
    certificates: &[Vec<u8>],
    allow_sha1: bool,
) -> Result<VerifiedSigner> {
    ensure!(
        original_signature.len() <= 16 * 1024,
        "counter-signature target size limit"
    );
    preflight(signer_info_der)?;
    let (n, len) = node(signer_info_der)?;
    ensure!(
        len == signer_info_der.len(),
        "trailing counter-signer bytes"
    );
    signer(n, original_signature, None, certificates, allow_sha1)
}

fn preflight(bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= 32 * 1024 * 1024, "ASN.1 byte limit");
    let (root, len) = node(bytes)?;
    ensure!(len == bytes.len(), "trailing ASN.1 bytes");
    let mut stack = vec![(root, 0usize)];
    let mut nodes = 0usize;
    while let Some((n, depth)) = stack.pop() {
        nodes += 1;
        ensure!(
            nodes <= 500_000 && stack.len() <= 500_000,
            "ASN.1 node limit"
        );
        ensure!(depth <= 64, "ASN.1 depth limit");
        if n.tag & 0x20 != 0 {
            let mut rest = n.value;
            let mut previous: Option<&[u8]> = None;
            while !rest.is_empty() {
                let (child, size) = node(rest)?;
                ensure!(
                    n.tag != 0x31 || previous.is_none_or(|p| p <= child.full),
                    "noncanonical DER SET order"
                );
                previous = Some(child.full);
                stack.push((child, depth + 1));
                rest = &rest[size..];
                ensure!(stack.len() <= 500_000, "ASN.1 node limit");
            }
        }
    }
    Ok(())
}
