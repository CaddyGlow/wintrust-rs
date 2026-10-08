//! Strict, bounded explicit-anchor certificate path validation.
use super::crypto;
use anyhow::{Context, Result, ensure};
use der::{Decode, Reader, SliceReader, Tag, Tagged, asn1::AnyRef};
use sha2::{Digest, Sha256};
use x509_cert::{
    Certificate,
    ext::pkix::{
        AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
    },
};

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChainReport {
    #[serde(skip)]
    pub chain_der: Vec<Vec<u8>>,
    pub anchor_sha256: String,
    /// Exact pinned CA whose critical legacy Microsoft timestamp policy was interpreted.
    pub microsoft_timestamp_policy_certificate_sha256: Option<String>,
}
const MICROSOFT_TIMESTAMP_PCA_2010: &str =
    "86ec118d1ee69670a46e2be29c4b4208be043e36600d4e1dd3f3d515ca119020";
const MICROSOFT_TIMESTAMP_POLICY: &str = "1.3.6.1.4.1.311.46.3";
const MICROSOFT_TIMESTAMP_CPS: &str = "http://www.microsoft.com/PKI/docs/CPS/default.htm";
const MICROSOFT_TIMESTAMP_NOTICE: &str = "\u{201d}Legal_Policy_Statement.\u{201d}";

// RFC5280 4.2.1.4 requires understanding critical policies including qualifiers.
// This deliberately supports only the measured, hash-pinned Microsoft TSA CA
// profile. It does not introduce generic policy-tree or constraint processing.
fn validate_microsoft_timestamp_policy(bytes: &[u8]) -> Result<()> {
    use x509_cert::ext::pkix::CertificatePolicies;
    ensure!(
        bytes.len() <= 4096,
        "timestamp certificate policy byte limit"
    );
    let policies = CertificatePolicies::from_der(bytes)?;
    ensure!(
        policies.0.len() == 1
            && policies.0[0].policy_identifier.to_string() == MICROSOFT_TIMESTAMP_POLICY,
        "unsupported Microsoft timestamp certificate policy"
    );
    let qualifiers = policies.0[0]
        .policy_qualifiers
        .as_deref()
        .context("Microsoft timestamp policy requires its qualifiers")?;
    ensure!(
        qualifiers.len() == 2,
        "unsupported timestamp policy qualifiers"
    );
    let mut seen = std::collections::HashSet::new();
    for qualifier in qualifiers {
        let oid = qualifier.policy_qualifier_id.to_string();
        ensure!(
            seen.insert(oid.clone()),
            "duplicate timestamp policy qualifier"
        );
        let value = qualifier
            .qualifier
            .as_ref()
            .context("missing policy qualifier value")?;
        match oid.as_str() {
            "1.3.6.1.5.5.7.2.1" => {
                let uri = value.decode_as::<der::asn1::Ia5StringRef<'_>>()?;
                ensure!(
                    uri.as_str() == MICROSOFT_TIMESTAMP_CPS,
                    "unsupported timestamp CPS URI"
                );
            }
            "1.3.6.1.5.5.7.2.2" => {
                ensure!(value.tag() == Tag::Sequence, "invalid timestamp UserNotice");
                let mut reader = SliceReader::new(value.value())?;
                let text = AnyRef::decode(&mut reader)?;
                ensure!(
                    reader.is_finished(),
                    "unsupported UserNotice noticeReference or extra fields"
                );
                ensure!(
                    text.tag() == Tag::BmpString,
                    "unsupported UserNotice DisplayText form"
                );
                let bytes = text.value();
                ensure!(
                    !bytes.is_empty() && bytes.len() <= 400 && bytes.len() % 2 == 0,
                    "UserNotice DisplayText length limit"
                );
                let mut message = String::new();
                for pair in bytes.as_chunks::<2>().0 {
                    let value = u16::from_be_bytes([pair[0], pair[1]]);
                    ensure!(
                        !(0xd800..=0xdfff).contains(&value),
                        "invalid BMPString surrogate"
                    );
                    message.push(char::from_u32(u32::from(value)).context("invalid BMPString")?);
                }
                ensure!(
                    message == MICROSOFT_TIMESTAMP_NOTICE,
                    "unsupported timestamp UserNotice text"
                );
            }
            _ => anyhow::bail!("unsupported critical timestamp policy qualifier {oid}"),
        }
    }
    Ok(())
}

fn validate_extensions(
    c: &Certificate,
    unix_time: u64,
    eku: &str,
    leaf: bool,
    ca_below: usize,
    certificate_der: &[u8],
    microsoft_timestamp_compatibility: bool,
) -> Result<bool> {
    let t = &c.tbs_certificate;
    ensure!(
        unix_time >= t.validity.not_before.to_unix_duration().as_secs()
            && unix_time <= t.validity.not_after.to_unix_duration().as_secs(),
        "certificate outside validity interval"
    );
    let mut seen = std::collections::HashSet::new();
    let mut interpreted_timestamp_policy = false;
    for e in t.extensions.iter().flatten() {
        ensure!(seen.insert(e.extn_id), "duplicate certificate extension");
        ensure!(
            !matches!(
                e.extn_id.to_string().as_str(),
                "2.5.29.30" | "2.5.29.36" | "2.5.29.54" | "2.5.29.33"
            ),
            "unsupported certificate constraint {} (critical or noncritical)",
            e.extn_id
        );
        if e.critical && e.extn_id.to_string() == "2.5.29.32" {
            ensure!(
                microsoft_timestamp_compatibility
                    && !leaf
                    && eku == "1.3.6.1.5.5.7.3.8"
                    && hex::encode(Sha256::digest(certificate_der)) == MICROSOFT_TIMESTAMP_PCA_2010,
                "unsupported critical certificate extension {}",
                e.extn_id
            );
            validate_microsoft_timestamp_policy(e.extn_value.as_bytes())?;
            interpreted_timestamp_policy = true;
        } else if e.critical {
            ensure!(
                matches!(
                    e.extn_id.to_string().as_str(),
                    "2.5.29.19" | "2.5.29.15" | "2.5.29.37"
                ),
                "unsupported critical certificate extension {}",
                e.extn_id
            );
        }
    }
    let basic = t.get::<BasicConstraints>()?;
    let usage = t.get::<KeyUsage>()?;
    if leaf {
        ensure!(!basic.as_ref().is_some_and(|(_, b)| b.ca), "signer is a CA");
        if let Some((_, u)) = usage {
            ensure!(
                u.digital_signature(),
                "signer key usage forbids digital signatures"
            );
        }
    } else {
        let (_, b) = basic.context("issuer lacks basic constraints")?;
        ensure!(b.ca, "issuer not a CA");
        if let Some(limit) = b.path_len_constraint {
            ensure!(ca_below <= usize::from(limit), "CA path length exceeded");
        }
        let (_, u) = usage.context("issuer lacks key usage")?;
        ensure!(
            u.key_cert_sign(),
            "issuer key usage forbids certificate signing"
        );
    }
    let eku_ext = t.get::<ExtendedKeyUsage>()?;
    if leaf {
        let (_, e) = eku_ext.context("signer lacks required EKU")?;
        ensure!(
            e.0.iter().any(|v| v.to_string() == eku),
            "signer lacks required EKU {eku}"
        );
    } else if let Some((_, e)) = eku_ext {
        ensure!(
            e.0.iter()
                .any(|v| v.to_string() == eku || v.to_string() == "2.5.29.37.0"),
            "issuer EKU restricts required usage"
        );
    }
    Ok(interpreted_timestamp_policy)
}
fn issuer_matches(child: &Certificate, parent: &Certificate) -> Result<bool> {
    if child.tbs_certificate.issuer != parent.tbs_certificate.subject {
        return Ok(false);
    }
    if let Some((_, aki)) = child.tbs_certificate.get::<AuthorityKeyIdentifier>()? {
        ensure!(
            aki.authority_cert_issuer.is_some() == aki.authority_cert_serial_number.is_some(),
            "AKI issuer and serial must appear together"
        );
        if let Some(id) = aki.key_identifier {
            let Some((_, ski)) = parent.tbs_certificate.get::<SubjectKeyIdentifier>()? else {
                return Ok(false);
            };
            if id.as_bytes() != ski.0.as_bytes() {
                return Ok(false);
            }
        }
        if let Some(serial) = aki.authority_cert_serial_number
            && serial != parent.tbs_certificate.serial_number
        {
            return Ok(false);
        }
        if let Some(names) = aki.authority_cert_issuer
            && !names.iter().any(|name|matches!(name,x509_cert::ext::pkix::name::GeneralName::DirectoryName(n) if n==&parent.tbs_certificate.issuer)) {return Ok(false);}
    }
    Ok(true)
}
/// Validate a path to an exact caller-pinned DER root. Certificate names never establish trust.
/// Revocation and timestamp verification are separate policy layers.
pub fn validate(
    leaf_der: &[u8],
    certs: &[Vec<u8>],
    roots: &[Vec<u8>],
    unix_time: u64,
    required_eku: &str,
) -> Result<ChainReport> {
    validate_with_policy(leaf_der, certs, roots, unix_time, required_eku, false)
}
pub fn validate_with_policy(
    leaf_der: &[u8],
    certs: &[Vec<u8>],
    roots: &[Vec<u8>],
    unix_time: u64,
    required_eku: &str,
    allow_sha1: bool,
) -> Result<ChainReport> {
    validate_path(
        leaf_der,
        certs,
        roots,
        unix_time,
        required_eku,
        allow_sha1,
        false,
    )
}

pub(super) fn validate_microsoft_timestamp_with_policy(
    leaf_der: &[u8],
    certs: &[Vec<u8>],
    roots: &[Vec<u8>],
    unix_time: u64,
    allow_sha1: bool,
) -> Result<ChainReport> {
    validate_path(
        leaf_der,
        certs,
        roots,
        unix_time,
        "1.3.6.1.5.5.7.3.8",
        allow_sha1,
        true,
    )
}

fn validate_path(
    leaf_der: &[u8],
    certs: &[Vec<u8>],
    roots: &[Vec<u8>],
    unix_time: u64,
    required_eku: &str,
    allow_sha1: bool,
    microsoft_timestamp_compatibility: bool,
) -> Result<ChainReport> {
    ensure!(
        !roots.is_empty() && roots.len() <= 32 && certs.len() <= 64,
        "certificate collection limits"
    );
    let mut pool = Vec::new();
    for bytes in certs.iter().chain(roots) {
        ensure!(bytes.len() <= 256 * 1024, "certificate byte limit");
        if !pool
            .iter()
            .any(|(b, _): &(Vec<u8>, Certificate)| b == bytes)
        {
            pool.push((bytes.clone(), Certificate::from_der(bytes)?));
        }
    }
    ensure!(leaf_der.len() <= 256 * 1024, "leaf certificate byte limit");
    let mut current = Certificate::from_der(leaf_der)?;
    let mut current_der = leaf_der.to_vec();
    let mut chain_der = Vec::new();
    let mut interpreted_timestamp_policy = false;
    let mut seen = std::collections::HashSet::new();
    for depth in 0usize..16 {
        ensure!(
            seen.insert(hex::encode(Sha256::digest(&current_der))),
            "certificate path cycle"
        );
        interpreted_timestamp_policy |= validate_extensions(
            &current,
            unix_time,
            required_eku,
            depth == 0,
            depth.saturating_sub(1),
            &current_der,
            microsoft_timestamp_compatibility,
        )?;
        chain_der.push(current_der.clone());
        if roots.iter().any(|r| r == &current_der) {
            ensure!(depth > 0, "leaf cannot be a trust anchor");
            ensure!(
                current.tbs_certificate.issuer == current.tbs_certificate.subject,
                "pinned root must be self-issued"
            );
            crypto::verify_certificate_with_policy(&current, &current, allow_sha1)?;
            let anchor_sha256 = hex::encode(Sha256::digest(&current_der));
            if microsoft_timestamp_compatibility {
                ensure!(
                    super::MICROSOFT_ROOTS.contains(&anchor_sha256.as_str()),
                    "Microsoft timestamp compatibility requires an authorized Microsoft root"
                );
            }
            return Ok(ChainReport {
                anchor_sha256,
                microsoft_timestamp_policy_certificate_sha256: interpreted_timestamp_policy
                    .then(|| MICROSOFT_TIMESTAMP_PCA_2010.to_owned()),
                chain_der,
            });
        }
        let mut issuers = Vec::new();
        for (bytes, parent) in &pool {
            if bytes != &current_der
                && issuer_matches(&current, parent)?
                && crypto::verify_certificate_with_policy(&current, parent, allow_sha1).is_ok()
            {
                issuers.push((bytes, parent));
            }
        }
        ensure!(
            issuers.len() == 1,
            "certificate issuer missing or ambiguous"
        );
        current_der = issuers[0].0.clone();
        current = issuers[0].1.clone();
    }
    anyhow::bail!("certificate path depth limit")
}
/// Inspect whether a leaf explicitly carries an EKU in addition to the chain's required EKU.
pub fn has_eku(certificate_der: &[u8], required: &str) -> Result<bool> {
    let c = Certificate::from_der(certificate_der)?;
    Ok(c.tbs_certificate
        .get::<ExtendedKeyUsage>()?
        .is_some_and(|(_, e)| e.0.iter().any(|v| v.to_string() == required)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;
    use x509_cert::ext::pkix::CertificatePolicies;

    fn actual_policy() -> Vec<u8> {
        let catalog = include_bytes!("../../../tests/fixtures/microsoft-legacy-wcf/catalog.cat");
        let cms = super::super::signed::verify_signed_data_with_policy(
            catalog,
            "1.3.6.1.4.1.311.10.1",
            false,
        )
        .unwrap();
        let token = &cms.signers[0]
            .unsigned_attributes
            .iter()
            .find(|(oid, _)| oid == super::super::timestamp::MICROSOFT_RFC3161_ATTRIBUTE)
            .unwrap()
            .1[0];
        let timestamp = super::super::signed::verify_signed_data_with_policy(
            token,
            "1.2.840.113549.1.9.16.1.4",
            false,
        )
        .unwrap();
        let ca = timestamp
            .certificates
            .iter()
            .find(|bytes| hex::encode(Sha256::digest(bytes)) == MICROSOFT_TIMESTAMP_PCA_2010)
            .unwrap();
        let certificate = Certificate::from_der(ca).unwrap();
        certificate
            .tbs_certificate
            .extensions
            .unwrap()
            .into_iter()
            .find(|e| e.extn_id.to_string() == "2.5.29.32")
            .unwrap()
            .extn_value
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn legacy_microsoft_policy_interprets_real_cps_and_notice_and_rejects_other_semantics() {
        let original = actual_policy();
        validate_microsoft_timestamp_policy(&original).unwrap();
        let mut policy = CertificatePolicies::from_der(&original).unwrap();
        policy.0[0].policy_identifier = "1.2.3.4".parse().unwrap();
        assert!(validate_microsoft_timestamp_policy(&policy.to_der().unwrap()).is_err());
        let mut policy = CertificatePolicies::from_der(&original).unwrap();
        policy.0.push(policy.0[0].clone());
        assert!(validate_microsoft_timestamp_policy(&policy.to_der().unwrap()).is_err());
        let mut policy = CertificatePolicies::from_der(&original).unwrap();
        policy.0[0].policy_qualifiers.as_mut().unwrap()[0].policy_qualifier_id =
            "1.2.3.4".parse().unwrap();
        assert!(validate_microsoft_timestamp_policy(&policy.to_der().unwrap()).is_err());
        let mut policy = CertificatePolicies::from_der(&original).unwrap();
        let qualifiers = policy.0[0].policy_qualifiers.as_mut().unwrap();
        qualifiers[1] = qualifiers[0].clone();
        assert!(validate_microsoft_timestamp_policy(&policy.to_der().unwrap()).is_err());
        let mut policy = CertificatePolicies::from_der(&original).unwrap();
        let notice = policy.0[0].policy_qualifiers.as_mut().unwrap()[1]
            .qualifier
            .as_mut()
            .unwrap();
        let mut fields = vec![0x30, 0];
        fields.extend_from_slice(notice.value());
        *notice = der::asn1::Any::new(Tag::Sequence, fields).unwrap();
        assert!(validate_microsoft_timestamp_policy(&policy.to_der().unwrap()).is_err());
        assert!(validate_microsoft_timestamp_policy(&vec![0; 4097]).is_err());
    }
}
