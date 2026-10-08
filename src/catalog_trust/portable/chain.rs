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
    /// RFC 5280 6.1 `valid_policy` values at the end-entity level after
    /// intersection with the initial policy set. Empty when the policy tree is NULL.
    pub valid_policies: Vec<String>,
    /// Per-certificate diagnostics for the selected path, end entity first.
    pub certificates: Vec<CertificateDiagnostic>,
    /// Bounded record of candidate paths rejected before this one was selected.
    pub rejected_paths: Vec<RejectedPath>,
}

/// Role and enforced path-validation extensions of one certificate in a selected path.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CertificateDiagnostic {
    pub sha256: String,
    pub role: &'static str,
    pub self_issued: bool,
    /// Names of the RFC 5280 path-validation extensions present and enforced.
    pub enforced_extensions: Vec<&'static str>,
}

/// A candidate path that failed validation, with the first failing reason.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RejectedPath {
    /// Certificate SHA-256 values from the end entity toward the candidate issuer.
    pub chain_sha256: Vec<String>,
    pub reason: String,
}

const MAX_REJECTED_PATHS: usize = 32;

/// Optional RFC 5280 behavior beyond the strict default.
#[derive(Debug, Clone, Default)]
pub struct PathOptions {
    /// RFC 5280 6.1.1 policy inputs.
    pub policy: super::policy::PolicyOptions,
    /// Allow an exactly pinned certificate that is not self-issued to end the
    /// path (a partial chain). The end-entity certificate itself never qualifies.
    pub partial_chain: bool,
}
const MICROSOFT_TIMESTAMP_PCA_2010: &str =
    "86ec118d1ee69670a46e2be29c4b4208be043e36600d4e1dd3f3d515ca119020";
const MICROSOFT_TIMESTAMP_POLICY: &str = "1.3.6.1.4.1.311.46.3";
const MICROSOFT_TIMESTAMP_CPS: &str = "http://www.microsoft.com/PKI/docs/CPS/default.htm";
const MICROSOFT_TIMESTAMP_NOTICE: &str = "\u{201d}Legal_Policy_Statement.\u{201d}";

// RFC5280 4.2.1.4 requires understanding critical policies including qualifiers.
// This deliberately supports only the measured, hash-pinned Microsoft TSA CA
// profile; general policy processing lives in the policy module.
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

// RFC 5280 4.2.1.10/6.1: every issuer's permitted union is intersected
// with other issuers' unions; excluded subtrees take precedence. Evaluate the
// path-local descendants instead of merging heterogeneous subtree encodings.
fn validate_name_constraints(value: &x509_cert::ext::pkix::NameConstraints) -> Result<()> {
    use x509_cert::ext::pkix::name::GeneralName;
    ensure!(
        value.permitted_subtrees.is_some() || value.excluded_subtrees.is_some(),
        "empty name constraints"
    );
    for subtrees in [&value.permitted_subtrees, &value.excluded_subtrees]
        .into_iter()
        .flatten()
    {
        ensure!(
            !subtrees.is_empty() && subtrees.len() <= 256,
            "name constraint subtree count limit"
        );
        for subtree in subtrees {
            ensure!(
                subtree.minimum == 0 && subtree.maximum.is_none(),
                "unsupported name constraint minimum/maximum"
            );
            match &subtree.base {
                GeneralName::DnsName(name) | GeneralName::UniformResourceIdentifier(name) => {
                    validate_domain(name.as_str().strip_prefix('.').unwrap_or(name.as_str()))?;
                }
                GeneralName::Rfc822Name(name) => {
                    if name.as_str().contains('@') {
                        split_mailbox(name.as_str())?;
                    } else {
                        validate_domain(name.as_str().strip_prefix('.').unwrap_or(name.as_str()))?;
                    }
                }
                GeneralName::IpAddress(bytes) => {
                    let bytes = bytes.as_bytes();
                    ensure!(
                        matches!(bytes.len(), 8 | 32),
                        "invalid IP name constraint length"
                    );
                    let half = bytes.len() / 2;
                    let mut zero = false;
                    for byte in &bytes[half..] {
                        for bit in (0..8).rev() {
                            if byte & (1 << bit) == 0 {
                                zero = true;
                            } else {
                                ensure!(!zero, "unsupported non-contiguous IP constraint mask");
                            }
                        }
                    }
                }
                GeneralName::DirectoryName(name) => {
                    ensure!(!name.0.is_empty(), "empty directory name constraint");
                    normalize_dn(name)?;
                }
                _ => anyhow::bail!("unsupported name constraint form"),
            }
        }
    }
    Ok(())
}

fn validate_domain(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name.len() <= 253,
        "invalid constrained domain length"
    );
    for label in name.split('.') {
        ensure!(
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "invalid constrained domain label"
        );
    }
    Ok(())
}

fn domain_matches(name: &str, constraint: &str, exact_host: bool) -> Result<bool> {
    validate_domain(name)?;
    let descendants_only = constraint.starts_with('.');
    let base = constraint.strip_prefix('.').unwrap_or(constraint);
    validate_domain(base)?;
    if name.eq_ignore_ascii_case(base) {
        return Ok(!descendants_only);
    }
    if exact_host && !descendants_only {
        return Ok(false);
    }
    Ok(name.len() > base.len()
        && name.as_bytes()[name.len() - base.len() - 1] == b'.'
        && name[name.len() - base.len()..].eq_ignore_ascii_case(base))
}

fn split_mailbox(mailbox: &str) -> Result<(&str, &str)> {
    let (local, host) = mailbox
        .split_once('@')
        .context("invalid constrained mailbox")?;
    ensure!(
        !local.is_empty()
            && local
                .bytes()
                .all(|byte| byte.is_ascii() && !byte.is_ascii_control() && byte != b'@'),
        "unsupported constrained mailbox local part"
    );
    validate_domain(host)?;
    Ok((local, host))
}

fn uri_host(uri: &str) -> Result<&str> {
    let (scheme, rest) = uri
        .split_once("://")
        .context("constrained URI requires a DNS authority")?;
    ensure!(
        !scheme.is_empty()
            && scheme.as_bytes()[0].is_ascii_alphabetic()
            && scheme
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')),
        "invalid URI scheme"
    );
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if let Some(port) = port {
        ensure!(
            !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid URI port"
        );
    }
    validate_domain(host)?;
    ensure!(
        host.parse::<std::net::IpAddr>().is_err(),
        "URI name constraint cannot authorize an IP host"
    );
    Ok(host)
}

// DirectoryString ASCII profiles use case/space folding across PrintableString
// and UTF8String. Wider Unicode matching requires RFC4518 preparation; fail
// closed rather than claim equivalence under incomplete Unicode normalization.
fn normalize_dn(name: &x509_cert::name::Name) -> Result<Vec<Vec<(String, String)>>> {
    name.0
        .iter()
        .map(|rdn| {
            let mut attributes = rdn
                .0
                .iter()
                .map(|attribute| {
                    let value = &attribute.value;
                    ensure!(
                        matches!(
                            value.tag(),
                            Tag::Utf8String | Tag::PrintableString | Tag::Ia5String
                        ),
                        "unsupported directory name attribute syntax"
                    );
                    let text = std::str::from_utf8(value.value())?;
                    ensure!(
                        text.is_ascii() && !text.bytes().any(|byte| byte.is_ascii_control()),
                        "unsupported international directory name constraint"
                    );
                    let oid = attribute.oid.to_string();
                    let normalized = if oid == "1.2.840.113549.1.9.1" {
                        let (local, host) = split_mailbox(text)?;
                        format!("{local}@{}", host.to_ascii_lowercase())
                    } else {
                        ensure!(
                            matches!(
                                oid.as_str(),
                                "2.5.4.3"
                                    | "2.5.4.4"
                                    | "2.5.4.5"
                                    | "2.5.4.6"
                                    | "2.5.4.7"
                                    | "2.5.4.8"
                                    | "2.5.4.9"
                                    | "2.5.4.10"
                                    | "2.5.4.11"
                                    | "2.5.4.12"
                                    | "2.5.4.13"
                                    | "2.5.4.41"
                                    | "2.5.4.42"
                                    | "2.5.4.43"
                                    | "2.5.4.44"
                                    | "2.5.4.46"
                                    | "2.5.4.65"
                                    | "0.9.2342.19200300.100.1.25"
                            ),
                            "unsupported directory name attribute matching rule {oid}"
                        );
                        text.split_whitespace()
                            .collect::<Vec<_>>()
                            .join(" ")
                            .to_ascii_lowercase()
                    };
                    Ok((oid, normalized))
                })
                .collect::<Result<Vec<_>>>()?;
            attributes.sort();
            Ok(attributes)
        })
        .collect()
}

fn same_name_form(
    a: &x509_cert::ext::pkix::name::GeneralName,
    b: &x509_cert::ext::pkix::name::GeneralName,
) -> bool {
    std::mem::discriminant(a) == std::mem::discriminant(b)
}

fn within_subtree(
    name: &x509_cert::ext::pkix::name::GeneralName,
    base: &x509_cert::ext::pkix::name::GeneralName,
) -> Result<bool> {
    use x509_cert::ext::pkix::name::GeneralName;
    match (name, base) {
        (GeneralName::DnsName(name), GeneralName::DnsName(base)) => {
            domain_matches(name.as_str(), base.as_str(), false)
        }
        (GeneralName::Rfc822Name(name), GeneralName::Rfc822Name(base)) => {
            let (local, host) = split_mailbox(name.as_str())?;
            if base.as_str().contains('@') {
                let (expected_local, expected_host) = split_mailbox(base.as_str())?;
                Ok(local == expected_local && host.eq_ignore_ascii_case(expected_host))
            } else {
                domain_matches(host, base.as_str(), true)
            }
        }
        (
            GeneralName::UniformResourceIdentifier(name),
            GeneralName::UniformResourceIdentifier(base),
        ) => domain_matches(uri_host(name.as_str())?, base.as_str(), true),
        (GeneralName::IpAddress(name), GeneralName::IpAddress(base)) => {
            let (name, base) = (name.as_bytes(), base.as_bytes());
            ensure!(
                matches!(name.len(), 4 | 16),
                "invalid subject IP address length"
            );
            if base.len() != name.len() * 2 {
                return Ok(false);
            }
            Ok(name
                .iter()
                .zip(&base[..name.len()])
                .zip(&base[name.len()..])
                .all(|((name, address), mask)| name & mask == address & mask))
        }
        (GeneralName::DirectoryName(name), GeneralName::DirectoryName(base)) => {
            Ok(normalize_dn(name)?.starts_with(&normalize_dn(base)?))
        }
        _ => Ok(false),
    }
}

fn check_certificate_names(
    certificate: &Certificate,
    constraints: &x509_cert::ext::pkix::NameConstraints,
) -> Result<()> {
    use x509_cert::ext::pkix::{SubjectAltName, name::GeneralName};
    let subject = &certificate.tbs_certificate.subject;
    let san = certificate.tbs_certificate.get::<SubjectAltName>()?;
    let mut names = san
        .as_ref()
        .map_or_else(Vec::new, |(_, names)| names.0.clone());
    ensure!(names.len() <= 256, "subject alternative name count limit");
    if !subject.0.is_empty() {
        names.push(GeneralName::DirectoryName(subject.clone()));
    }
    if san.is_none() {
        for rdn in &subject.0 {
            for attribute in rdn.0.iter() {
                if attribute.oid.to_string() == "1.2.840.113549.1.9.1" {
                    names.push(GeneralName::Rfc822Name(
                        attribute.value.decode_as::<der::asn1::Ia5String>()?,
                    ));
                }
            }
        }
    }
    for name in names {
        for excluded in constraints.excluded_subtrees.iter().flatten() {
            if same_name_form(&name, &excluded.base) {
                ensure!(
                    !within_subtree(&name, &excluded.base)?,
                    "certificate name is in excluded subtree"
                );
            }
        }
        let permitted = constraints
            .permitted_subtrees
            .iter()
            .flatten()
            .filter(|subtree| same_name_form(&name, &subtree.base))
            .collect::<Vec<_>>();
        if !permitted.is_empty() {
            let mut matched = false;
            for subtree in permitted {
                matched |= within_subtree(&name, &subtree.base)?;
            }
            ensure!(matched, "certificate name outside permitted subtrees");
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
        if e.critical && e.extn_id.to_string() == "2.5.29.32" {
            if microsoft_timestamp_compatibility
                && !leaf
                && eku == "1.3.6.1.5.5.7.3.8"
                && hex::encode(Sha256::digest(certificate_der)) == MICROSOFT_TIMESTAMP_PCA_2010
            {
                validate_microsoft_timestamp_policy(e.extn_value.as_bytes())?;
                interpreted_timestamp_policy = true;
            } else {
                // RFC 5280 4.2.1.4: a critical policy extension must be fully
                // interpreted, qualifiers included. No generic qualifier is.
                let policies =
                    x509_cert::ext::pkix::CertificatePolicies::from_der(e.extn_value.as_bytes())?;
                ensure!(
                    policies
                        .0
                        .iter()
                        .all(|p| p.policy_qualifiers.as_ref().is_none_or(Vec::is_empty)),
                    "unsupported critical certificate policy qualifier"
                );
            }
        } else if e.critical {
            ensure!(
                matches!(
                    e.extn_id.to_string().as_str(),
                    "2.5.29.19"
                        | "2.5.29.15"
                        | "2.5.29.37"
                        | "2.5.29.30"
                        | "2.5.29.17"
                        | "2.5.29.33"
                        | "2.5.29.36"
                        | "2.5.29.54"
                ),
                "unsupported critical certificate extension {}",
                e.extn_id
            );
        }
    }
    if let Some((critical, constraints)) = t.get::<x509_cert::ext::pkix::NameConstraints>()? {
        ensure!(
            !leaf && critical,
            "unsupported certificate constraint: name constraints require a critical CA extension"
        );
        validate_name_constraints(&constraints)?;
    }
    if let Some((critical, names)) = t.get::<x509_cert::ext::pkix::SubjectAltName>()? {
        use x509_cert::ext::pkix::name::GeneralName;
        ensure!(
            !names.0.is_empty() && names.0.len() <= 256,
            "subject alternative name count limit"
        );
        if critical {
            ensure!(
                names.0.iter().all(|name| matches!(
                    name,
                    GeneralName::DnsName(_)
                        | GeneralName::Rfc822Name(_)
                        | GeneralName::UniformResourceIdentifier(_)
                        | GeneralName::IpAddress(_)
                        | GeneralName::DirectoryName(_)
                )),
                "unsupported critical subject alternative name form"
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
        &PathOptions::default(),
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
        &PathOptions::default(),
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
        &PathOptions::default(),
        &mut accept_path,
    )
}

/// Like `validate_with_path_policy`, with explicit RFC 5280 policy inputs and
/// optional partial-chain selection.
#[allow(clippy::too_many_arguments)]
pub fn validate_with_options(
    leaf_der: &[u8],
    certs: &[Vec<u8>],
    roots: &[Vec<u8>],
    unix_time: u64,
    required_eku: &str,
    allow_sha1: bool,
    limits: PathLimits,
    options: &PathOptions,
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
        options,
        &mut accept_path,
    )
}

fn diagnostic(
    position: usize,
    length: usize,
    entry: &(&[u8], Certificate),
) -> CertificateDiagnostic {
    let (bytes, certificate) = entry;
    let enforced = [
        ("2.5.29.19", "basicConstraints"),
        ("2.5.29.15", "keyUsage"),
        ("2.5.29.37", "extendedKeyUsage"),
        ("2.5.29.30", "nameConstraints"),
        ("2.5.29.32", "certificatePolicies"),
        ("2.5.29.33", "policyMappings"),
        ("2.5.29.36", "policyConstraints"),
        ("2.5.29.54", "inhibitAnyPolicy"),
    ];
    CertificateDiagnostic {
        sha256: hex::encode(Sha256::digest(bytes)),
        role: if position == 0 {
            "end-entity"
        } else if position + 1 == length {
            "anchor"
        } else {
            "intermediate"
        },
        self_issued: certificate.tbs_certificate.subject == certificate.tbs_certificate.issuer,
        enforced_extensions: enforced
            .iter()
            .filter(|(oid, _)| {
                certificate
                    .tbs_certificate
                    .extensions
                    .iter()
                    .flatten()
                    .any(|e| e.extn_id.to_string() == *oid)
            })
            .map(|(_, name)| *name)
            .collect(),
    }
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
    options: &PathOptions,
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
    let mut rejected: Vec<RejectedPath> = Vec::new();
    macro_rules! reject {
        ($path:expr, $error:expr) => {{
            let error = $error;
            if rejected.len() < MAX_REJECTED_PATHS {
                rejected.push(RejectedPath {
                    chain_sha256: $path
                        .iter()
                        .map(|i| hex::encode(Sha256::digest(pool[*i].0)))
                        .collect(),
                    reason: format!("{error:#}"),
                });
            }
            last_error = error;
            continue;
        }};
    }
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
            Err(error) => reject!(path, error),
        };
        if let Some((_, constraints)) = current
            .tbs_certificate
            .get::<x509_cert::ext::pkix::NameConstraints>()?
        {
            let result = path[..depth].iter().try_for_each(|child_index| {
                let child = &pool[*child_index].1;
                if *child_index != leaf_index
                    && child.tbs_certificate.subject == child.tbs_certificate.issuer
                {
                    return Ok(());
                }
                check_certificate_names(child, &constraints)
            });
            if let Err(error) = result {
                reject!(path, error);
            }
        }
        if anchors.contains(bytes) {
            if depth == 0 {
                reject!(
                    path,
                    anyhow::anyhow!("pinned root must be a self-issued CA, not the leaf")
                );
            }
            let self_issued = current.tbs_certificate.issuer == current.tbs_certificate.subject;
            if !self_issued && !options.partial_chain {
                reject!(
                    path,
                    anyhow::anyhow!(
                        "pinned root must be a self-issued CA, not the leaf; \
                         partial chains require explicit selection"
                    )
                );
            }
            if self_issued {
                signature_checks += 1;
                ensure!(
                    signature_checks <= limits.max_signature_checks,
                    "certificate signature-check limit"
                );
                if let Err(error) =
                    crypto::verify_certificate_with_policy(current, current, allow_sha1)
                {
                    reject!(path, error);
                }
            }
            let anchor_sha256 = hex::encode(Sha256::digest(bytes));
            if microsoft_timestamp_compatibility
                && !super::MICROSOFT_ROOTS.contains(&anchor_sha256.as_str())
            {
                reject!(
                    path,
                    anyhow::anyhow!(
                        "Microsoft timestamp compatibility requires an authorized Microsoft root"
                    )
                );
            }
            let ordered = path[..depth]
                .iter()
                .rev()
                .map(|i| &pool[*i].1)
                .collect::<Vec<_>>();
            let outcome = match super::policy::process(&ordered, Some(current), &options.policy) {
                Ok(outcome) => outcome,
                Err(error) => reject!(path, error),
            };
            let report = ChainReport {
                anchor_sha256,
                microsoft_timestamp_policy_certificate_sha256: interpreted
                    .then(|| MICROSOFT_TIMESTAMP_PCA_2010.to_owned()),
                chain_der: path.iter().map(|i| pool[*i].0.to_vec()).collect(),
                valid_policies: outcome
                    .valid_policies
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                certificates: path
                    .iter()
                    .enumerate()
                    .map(|(position, i)| diagnostic(position, path.len(), &pool[*i]))
                    .collect(),
                rejected_paths: rejected.clone(),
            };
            match accept_path(&report) {
                Ok(()) => return Ok(report),
                Err(error) => reject!(path, error),
            }
        }
        if path.len() >= limits.max_depth {
            reject!(path, anyhow::anyhow!("certificate path depth limit"));
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
                    if rejected.len() < MAX_REJECTED_PATHS {
                        let mut candidate = path.clone();
                        candidate.push(parent_index);
                        rejected.push(RejectedPath {
                            chain_sha256: candidate
                                .iter()
                                .map(|i| hex::encode(Sha256::digest(pool[*i].0)))
                                .collect(),
                            reason: format!("{error:#}"),
                        });
                    }
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
    let certificates = report
        .chain_der
        .iter()
        .map(|bytes| Certificate::from_der(bytes))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (depth, (bytes, certificate)) in report.chain_der.iter().zip(&certificates).enumerate() {
        validate_extensions(
            certificate,
            unix_time,
            eku,
            depth == 0,
            depth.saturating_sub(1),
            bytes,
            false,
        )?;
        if let Some((_, constraints)) = certificate
            .tbs_certificate
            .get::<x509_cert::ext::pkix::NameConstraints>()?
        {
            for (index, child) in certificates[..depth].iter().enumerate() {
                if index != 0 && child.tbs_certificate.subject == child.tbs_certificate.issuer {
                    continue;
                }
                check_certificate_names(child, &constraints)?;
            }
        }
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
