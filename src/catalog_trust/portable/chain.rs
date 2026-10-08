//! Strict, bounded explicit-anchor certificate path validation.
use super::crypto;
use anyhow::{Context, Result, ensure};
use der::{Decode, Encode, Reader, SliceReader, Tag, Tagged, asn1::AnyRef};
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

/// Independent limits for store loading and path-search work.
#[derive(Debug, Clone, Copy)]
pub struct PathLimits {
    pub max_store_certificates: usize,
    pub max_store_bytes: usize,
    pub max_depth: usize,
    pub max_explored_candidates: usize,
    pub max_signature_checks: usize,
}
impl Default for PathLimits {
    fn default() -> Self {
        Self {
            max_store_certificates: 16_384,
            max_store_bytes: 64 * 1024 * 1024,
            max_depth: 16,
            max_explored_candidates: 4096,
            max_signature_checks: 4096,
        }
    }
}

/// Search alternative issuer paths under explicit store and work budgets.
pub fn validate_with_limits(
    leaf_der: &[u8],
    certs: &[Vec<u8>],
    roots: &[Vec<u8>],
    unix_time: u64,
    required_eku: &str,
    allow_sha1: bool,
    limits: PathLimits,
) -> Result<ChainReport> {
    search_path(
        leaf_der,
        certs,
        roots,
        unix_time,
        required_eku,
        allow_sha1,
        false,
        limits,
        &mut |_| Ok(()),
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
    search_path(
        leaf_der,
        certs,
        roots,
        unix_time,
        required_eku,
        allow_sha1,
        microsoft_timestamp_compatibility,
        PathLimits::default(),
        &mut |_| Ok(()),
    )
}

/// Evaluate caller policy on each fully validated path before choosing one.
/// Rejection continues deterministic alternative search under the same work budgets.
#[allow(clippy::too_many_arguments)]
pub fn validate_with_path_policy(
    leaf_der: &[u8],
    certs: &[Vec<u8>],
    roots: &[Vec<u8>],
    unix_time: u64,
    required_eku: &str,
    allow_sha1: bool,
    limits: PathLimits,
    mut accept_path: impl FnMut(&ChainReport) -> Result<()>,
) -> Result<ChainReport> {
    search_path(
        leaf_der,
        certs,
        roots,
        unix_time,
        required_eku,
        allow_sha1,
        false,
        limits,
        &mut accept_path,
    )
}

#[allow(clippy::too_many_arguments)]
fn search_path(
    leaf_der: &[u8],
    certs: &[Vec<u8>],
    roots: &[Vec<u8>],
    unix_time: u64,
    required_eku: &str,
    allow_sha1: bool,
    microsoft_timestamp_compatibility: bool,
    limits: PathLimits,
    accept_path: &mut dyn FnMut(&ChainReport) -> Result<()>,
) -> Result<ChainReport> {
    use std::collections::{BTreeMap, HashSet};
    ensure!(!roots.is_empty(), "no trust anchors supplied");
    ensure!(limits.max_depth > 0, "certificate path depth limit");
    // Bound input before parsing, including duplicate input bytes.
    ensure!(
        certs
            .len()
            .checked_add(roots.len())
            .is_some_and(|n| n <= limits.max_store_certificates),
        "certificate store count limit"
    );
    let total = certs
        .iter()
        .chain(roots)
        .try_fold(leaf_der.len(), |n, b| n.checked_add(b.len()))
        .context("certificate store byte overflow")?;
    ensure!(
        total <= limits.max_store_bytes,
        "certificate store byte limit"
    );
    ensure!(leaf_der.len() <= 256 * 1024, "leaf certificate byte limit");
    // DER ordering makes the selected path independent of caller collection order.
    let anchors: HashSet<&[u8]> = roots.iter().map(Vec::as_slice).collect();
    let unique: std::collections::BTreeSet<&[u8]> = certs
        .iter()
        .chain(roots)
        .map(Vec::as_slice)
        .chain(std::iter::once(leaf_der))
        .collect();
    let mut pool = Vec::with_capacity(unique.len());
    let mut subjects: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
    let mut leaf_index = 0;
    for bytes in unique {
        ensure!(bytes.len() <= 256 * 1024, "certificate byte limit");
        let certificate = Certificate::from_der(bytes)?;
        let index = pool.len();
        if bytes == leaf_der {
            leaf_index = index;
        }
        subjects
            .entry(certificate.tbs_certificate.subject.to_der()?)
            .or_default()
            .push(index);
        pool.push((bytes, certificate));
    }
    // Iterative DFS retains a per-path cycle set and avoids unbounded recursion.
    let mut pending = vec![(vec![leaf_index], false)];
    let mut explored = 0usize;
    let mut signature_checks = 0usize;
    let mut last_error = anyhow::anyhow!("certificate issuer missing");
    while let Some((path, interpreted)) = pending.pop() {
        explored += 1;
        ensure!(
            explored <= limits.max_explored_candidates,
            "certificate explored candidate limit"
        );
        let index = *path.last().unwrap();
        let (bytes, current) = &pool[index];
        let depth = path.len() - 1;
        let interpreted = match validate_extensions(
            current,
            unix_time,
            required_eku,
            depth == 0,
            depth.saturating_sub(1),
            bytes,
            microsoft_timestamp_compatibility,
        ) {
            Ok(value) => interpreted || value,
            Err(error) => {
                last_error = error;
                continue;
            }
        };
        if anchors.contains(bytes) {
            if depth == 0 || current.tbs_certificate.issuer != current.tbs_certificate.subject {
                last_error = anyhow::anyhow!("pinned root must be a self-issued CA, not the leaf");
                continue;
            }
            signature_checks += 1;
            ensure!(
                signature_checks <= limits.max_signature_checks,
                "certificate signature-check limit"
            );
            if let Err(error) = crypto::verify_certificate_with_policy(current, current, allow_sha1)
            {
                last_error = error;
                continue;
            }
            let anchor_sha256 = hex::encode(Sha256::digest(bytes));
            if microsoft_timestamp_compatibility
                && !super::MICROSOFT_ROOTS.contains(&anchor_sha256.as_str())
            {
                last_error = anyhow::anyhow!(
                    "Microsoft timestamp compatibility requires an authorized Microsoft root"
                );
                continue;
            }
            let report = ChainReport {
                anchor_sha256,
                microsoft_timestamp_policy_certificate_sha256: interpreted
                    .then(|| MICROSOFT_TIMESTAMP_PCA_2010.to_owned()),
                chain_der: path.iter().map(|i| pool[*i].0.to_vec()).collect(),
            };
            match accept_path(&report) {
                Ok(()) => return Ok(report),
                Err(error) => {
                    last_error = error;
                    continue;
                }
            }
        }
        if path.len() >= limits.max_depth {
            last_error = anyhow::anyhow!("certificate path depth limit");
            continue;
        }
        if let Some(candidates) = subjects.get(&current.tbs_certificate.issuer.to_der()?) {
            for &parent_index in candidates.iter().rev() {
                if path.contains(&parent_index) {
                    continue;
                }
                let (_, parent) = &pool[parent_index];
                if !issuer_matches(current, parent)? {
                    continue;
                }
                signature_checks += 1;
                ensure!(
                    signature_checks <= limits.max_signature_checks,
                    "certificate signature-check limit"
                );
                if let Err(error) =
                    crypto::verify_certificate_with_policy(current, parent, allow_sha1)
                {
                    last_error = error;
                    continue;
                }
                // Bound the queued paths as well as paths already visited.
                ensure!(
                    explored + pending.len() < limits.max_explored_candidates,
                    "certificate explored candidate limit"
                );
                let mut next = path.clone();
                next.push(parent_index);
                pending.push((next, interpreted));
            }
        }
    }
    Err(last_error.context("no acceptable certificate path"))
}
/// Recheck purpose/time constraints on the exact already selected path.
pub(super) fn validate_report_constraints(
    report: &ChainReport,
    unix_time: u64,
    eku: &str,
) -> Result<()> {
    for (depth, bytes) in report.chain_der.iter().enumerate() {
        validate_extensions(
            &Certificate::from_der(bytes)?,
            unix_time,
            eku,
            depth == 0,
            depth.saturating_sub(1),
            bytes,
            false,
        )?;
    }
    Ok(())
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

    fn synthetic_policy() -> Vec<u8> {
        use der::asn1::{Any, BmpString, Ia5String};
        use x509_cert::ext::pkix::certpolicy::{PolicyInformation, PolicyQualifierInfo};

        let cps = Ia5String::new(MICROSOFT_TIMESTAMP_CPS).unwrap();
        // x509-cert's DisplayText currently omits BMPString, so encode the
        // sole explicitText directly inside the UserNotice sequence.
        let notice_text = BmpString::from_utf8(MICROSOFT_TIMESTAMP_NOTICE).unwrap();
        let notice = Any::new(Tag::Sequence, notice_text.to_der().unwrap()).unwrap();
        CertificatePolicies(vec![PolicyInformation {
            policy_identifier: MICROSOFT_TIMESTAMP_POLICY.parse().unwrap(),
            policy_qualifiers: Some(vec![
                PolicyQualifierInfo {
                    policy_qualifier_id: "1.3.6.1.5.5.7.2.1".parse().unwrap(),
                    qualifier: Some(Any::from_der(&cps.to_der().unwrap()).unwrap()),
                },
                PolicyQualifierInfo {
                    policy_qualifier_id: "1.3.6.1.5.5.7.2.2".parse().unwrap(),
                    qualifier: Some(notice),
                },
            ]),
        }])
        .to_der()
        .unwrap()
    }

    #[test]
    fn legacy_microsoft_policy_interprets_cps_and_notice_and_rejects_other_semantics() {
        let original = synthetic_policy();
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
