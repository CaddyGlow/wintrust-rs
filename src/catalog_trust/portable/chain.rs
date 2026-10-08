//! Strict, bounded explicit-anchor certificate path validation.
use super::crypto;
use crate::CertificateStore;
use crate::error::{Context, Error, Result, bail, ensure};
use alloc::{
    borrow::ToOwned,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use der::{
    Decode, Encode, Reader, SliceReader, Tag, Tagged,
    asn1::{AnyRef, ObjectIdentifier},
};
use sha2::{Digest, Sha256};
use x509_cert::{
    Certificate,
    ext::pkix::{
        AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
    },
};

type ParsedPath<'a> = [(&'a [u8], &'a Certificate)];
type ParsedPathPolicy<'a> = dyn FnMut(&ChainReport, &ParsedPath<'_>) -> Result<()> + 'a;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChainReport {
    #[serde(skip)]
    pub chain_der: Vec<Vec<u8>>,
    pub anchor_sha256: String,
    /// Exact pinned CA whose critical legacy Microsoft timestamp policy was interpreted.
    pub microsoft_timestamp_policy_certificate_sha256: Option<String>,
    /// RFC 5280 6.1 `valid_policy` values at the end-entity level after
    /// intersection with the initial policy set. Empty when the policy tree is NULL.
    #[serde(with = "crate::oid_serde::vec")]
    pub valid_policies: Vec<ObjectIdentifier>,
    /// Per-certificate diagnostics for the selected path, end entity first.
    pub certificates: Vec<CertificateDiagnostic>,
    /// Bounded record of candidate paths rejected before this one was selected.
    pub rejected_paths: Vec<RejectedPath>,
}

/// Position of a certificate in the selected trust path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateRole {
    EndEntity,
    Intermediate,
    Anchor,
}

/// Role and enforced path-validation extensions of one certificate in a selected path.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CertificateDiagnostic {
    pub sha256: String,
    pub role: CertificateRole,
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
    /// Validate the end-entity certificate as a CRL signer: it may be a CA or
    /// an end entity and no extended key usage is required. The caller checks `cRLSign`.
    pub crl_signer: bool,
}
const MICROSOFT_TIMESTAMP_PCA_2010: &str =
    "86ec118d1ee69670a46e2be29c4b4208be043e36600d4e1dd3f3d515ca119020";
const MICROSOFT_TIMESTAMP_POLICY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.46.3");
const MICROSOFT_TIMESTAMP_CPS: &str = "http://www.microsoft.com/PKI/docs/CPS/default.htm";
const MICROSOFT_TIMESTAMP_NOTICE: &str = "\u{201d}Legal_Policy_Statement.\u{201d}";

// RFC5280 4.2.1.4 requires understanding critical policies including qualifiers.
// This deliberately supports only the measured, hash-pinned Microsoft TSA CA
// profile; general policy processing lives in the policy module.
fn validate_microsoft_timestamp_policy(bytes: &[u8]) -> Result<()> {
    use x509_cert::ext::pkix::CertificatePolicies;
    ensure!(
        bytes.len() <= 4096,
        Error::resource_limit("timestamp certificate policy byte limit")
    );
    let policies = CertificatePolicies::from_der(bytes).map_err(Error::malformed)?;
    ensure!(
        policies.0.len() == 1 && policies.0[0].policy_identifier == MICROSOFT_TIMESTAMP_POLICY,
        Error::unsupported("unsupported Microsoft timestamp certificate policy")
    );
    let qualifiers = policies.0[0]
        .policy_qualifiers
        .as_deref()
        .context("Microsoft timestamp policy requires its qualifiers")?;
    ensure!(
        qualifiers.len() == 2,
        Error::unsupported("unsupported timestamp policy qualifiers")
    );
    let mut seen = alloc::collections::BTreeSet::new();
    for qualifier in qualifiers {
        let oid = qualifier.policy_qualifier_id.to_string();
        ensure!(
            seen.insert(oid.clone()),
            Error::malformed("duplicate timestamp policy qualifier")
        );
        let value = qualifier
            .qualifier
            .as_ref()
            .context("missing policy qualifier value")?;
        match oid.as_str() {
            "1.3.6.1.5.5.7.2.1" => {
                let uri = value
                    .decode_as::<der::asn1::Ia5StringRef<'_>>()
                    .map_err(Error::malformed)?;
                ensure!(
                    uri.as_str() == MICROSOFT_TIMESTAMP_CPS,
                    Error::unsupported("unsupported timestamp CPS URI")
                );
            }
            "1.3.6.1.5.5.7.2.2" => {
                ensure!(
                    value.tag() == Tag::Sequence,
                    Error::malformed("invalid timestamp UserNotice")
                );
                let mut reader = SliceReader::new(value.value()).map_err(Error::malformed)?;
                let text = AnyRef::decode(&mut reader).map_err(Error::malformed)?;
                ensure!(
                    reader.is_finished(),
                    Error::unsupported("unsupported UserNotice noticeReference or extra fields")
                );
                ensure!(
                    text.tag() == Tag::BmpString,
                    Error::unsupported("unsupported UserNotice DisplayText form")
                );
                let bytes = text.value();
                ensure!(
                    !bytes.is_empty() && bytes.len() <= 400 && bytes.len() % 2 == 0,
                    Error::resource_limit("UserNotice DisplayText length limit")
                );
                let mut message = String::new();
                for pair in bytes.as_chunks::<2>().0 {
                    let value = u16::from_be_bytes([pair[0], pair[1]]);
                    ensure!(
                        !(0xd800..=0xdfff).contains(&value),
                        Error::malformed("invalid BMPString surrogate")
                    );
                    message.push(char::from_u32(u32::from(value)).context("invalid BMPString")?);
                }
                ensure!(
                    message == MICROSOFT_TIMESTAMP_NOTICE,
                    Error::unsupported("unsupported timestamp UserNotice text")
                );
            }
            _ => bail!(Error::unsupported(format!(
                "unsupported critical timestamp policy qualifier {oid}"
            ))),
        }
    }
    Ok(())
}

mod names;
use names::{check_certificate_names, validate_name_constraints};

#[allow(clippy::too_many_arguments)]
fn validate_extensions(
    c: &Certificate,
    unix_time: u64,
    eku: ObjectIdentifier,
    leaf: bool,
    ca_below: usize,
    certificate_der: &[u8],
    microsoft_timestamp_compatibility: bool,
    crl_signer: bool,
) -> Result<bool> {
    let t = &c.tbs_certificate;
    ensure!(
        unix_time >= t.validity.not_before.to_unix_duration().as_secs()
            && unix_time <= t.validity.not_after.to_unix_duration().as_secs(),
        "certificate outside validity interval"
    );
    let mut seen = alloc::collections::BTreeSet::new();
    let mut interpreted_timestamp_policy = false;
    for e in t.extensions.iter().flatten() {
        ensure!(
            seen.insert(e.extn_id),
            Error::malformed("duplicate certificate extension")
        );
        if e.critical && e.extn_id.to_string() == "2.5.29.32" {
            if microsoft_timestamp_compatibility
                && !leaf
                && eku == ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8")
                && hex::encode(Sha256::digest(certificate_der)) == MICROSOFT_TIMESTAMP_PCA_2010
            {
                validate_microsoft_timestamp_policy(e.extn_value.as_bytes())?;
                interpreted_timestamp_policy = true;
            } else {
                // RFC 5280 4.2.1.4: a critical policy extension must be fully
                // interpreted, qualifiers included. No generic qualifier is.
                let policies =
                    x509_cert::ext::pkix::CertificatePolicies::from_der(e.extn_value.as_bytes())
                        .map_err(Error::malformed)?;
                ensure!(
                    policies
                        .0
                        .iter()
                        .all(|p| p.policy_qualifiers.as_ref().is_none_or(Vec::is_empty)),
                    Error::unsupported("unsupported critical certificate policy qualifier")
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
                Error::unsupported(format!(
                    "unsupported critical certificate extension {}",
                    e.extn_id
                ))
            );
        }
    }
    if let Some((critical, constraints)) = t
        .get::<x509_cert::ext::pkix::NameConstraints>()
        .map_err(Error::malformed)?
    {
        ensure!(
            !leaf && critical,
            Error::unsupported(
                "unsupported certificate constraint: name constraints require a critical CA extension"
            )
        );
        validate_name_constraints(&constraints)?;
    }
    if let Some((critical, names)) = t
        .get::<x509_cert::ext::pkix::SubjectAltName>()
        .map_err(Error::malformed)?
    {
        use x509_cert::ext::pkix::name::GeneralName;
        ensure!(
            !names.0.is_empty() && names.0.len() <= 256,
            Error::resource_limit("subject alternative name count limit")
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
                Error::unsupported("unsupported critical subject alternative name form")
            );
        }
    }
    let basic = t.get::<BasicConstraints>().map_err(Error::malformed)?;
    let usage = t.get::<KeyUsage>().map_err(Error::malformed)?;
    if leaf && crl_signer {
        // A CRL signer may be an end entity or a CA; cRLSign is checked by the caller.
    } else if leaf {
        ensure!(!basic.as_ref().is_some_and(|(_, b)| b.ca), "signer is a CA");
        if let Some((_, u)) = usage {
            ensure!(
                u.digital_signature(),
                "signer key usage forbids digital signatures"
            );
        }
    } else {
        let (_, b) = basic.ok_or_else(|| Error::policy("issuer lacks basic constraints"))?;
        ensure!(b.ca, "issuer not a CA");
        if let Some(limit) = b.path_len_constraint {
            ensure!(ca_below <= usize::from(limit), "CA path length exceeded");
        }
        let (_, u) = usage.ok_or_else(|| Error::policy("issuer lacks key usage"))?;
        ensure!(
            u.key_cert_sign(),
            "issuer key usage forbids certificate signing"
        );
    }
    let eku_ext = t.get::<ExtendedKeyUsage>().map_err(Error::malformed)?;
    if crl_signer {
        // RFC 5280 places no extended key usage requirement on CRL signers.
    } else if leaf {
        let (_, e) = eku_ext.ok_or_else(|| Error::policy("signer lacks required EKU"))?;
        ensure!(
            e.0.contains(&eku),
            Error::policy(format!("signer lacks required EKU {eku}"))
        );
    } else if let Some((_, e)) = eku_ext {
        ensure!(
            e.0.iter()
                .any(|v| *v == eku || *v == ObjectIdentifier::new_unwrap("2.5.29.37.0")),
            "issuer EKU restricts required usage"
        );
    }
    Ok(interpreted_timestamp_policy)
}
fn issuer_matches(child: &Certificate, parent: &Certificate) -> Result<bool> {
    if child.tbs_certificate.issuer != parent.tbs_certificate.subject {
        return Ok(false);
    }
    if let Some((_, aki)) = child
        .tbs_certificate
        .get::<AuthorityKeyIdentifier>()
        .map_err(Error::malformed)?
    {
        ensure!(
            aki.authority_cert_issuer.is_some() == aki.authority_cert_serial_number.is_some(),
            "AKI issuer and serial must appear together"
        );
        if let Some(id) = aki.key_identifier {
            let Some((_, ski)) = parent
                .tbs_certificate
                .get::<SubjectKeyIdentifier>()
                .map_err(Error::malformed)?
            else {
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

/// Borrowed trust inputs and explicit validation policy for one certificate path.
#[derive(Debug, Clone)]
pub struct ChainOptions<'a> {
    pub roots: CertificateStore<'a>,
    pub candidates: CertificateStore<'a>,
    pub evaluation_time: u64,
    pub required_eku: ObjectIdentifier,
    pub allow_sha1: bool,
    pub limits: PathLimits,
    pub path: PathOptions,
}
impl<'a> ChainOptions<'a> {
    pub fn new(
        roots: impl Into<CertificateStore<'a>>,
        evaluation_time: u64,
        required_eku: ObjectIdentifier,
    ) -> Self {
        Self {
            roots: roots.into(),
            candidates: CertificateStore::default(),
            evaluation_time,
            required_eku,
            allow_sha1: false,
            limits: PathLimits::default(),
            path: PathOptions::default(),
        }
    }
}
/// Validate a path to an exact pinned anchor using the explicit options.
pub fn validate(leaf_der: &[u8], options: &ChainOptions<'_>) -> Result<ChainReport> {
    validate_with_path_policy(leaf_der, options, |_| Ok(()))
}
/// Evaluate caller policy on each fully validated candidate before choosing one.
pub fn validate_with_path_policy(
    leaf_der: &[u8],
    options: &ChainOptions<'_>,
    mut accept_path: impl FnMut(&ChainReport) -> Result<()>,
) -> Result<ChainReport> {
    search_path(
        leaf_der,
        options.candidates,
        options.roots,
        options.evaluation_time,
        options.required_eku,
        options.allow_sha1,
        false,
        options.limits,
        &options.path,
        &mut |report, _| accept_path(report),
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
            CertificateRole::EndEntity
        } else if position + 1 == length {
            CertificateRole::Anchor
        } else {
            CertificateRole::Intermediate
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
    certs: CertificateStore<'_>,
    roots: CertificateStore<'_>,
    unix_time: u64,
    required_eku: ObjectIdentifier,
    allow_sha1: bool,
    microsoft_timestamp_compatibility: bool,
    limits: PathLimits,
    options: &PathOptions,
    accept_path: &mut ParsedPathPolicy<'_>,
) -> Result<ChainReport> {
    use alloc::collections::{BTreeMap, BTreeSet};
    ensure!(
        !roots.is_empty(),
        Error::configuration("no trust anchors supplied")
    );
    ensure!(
        limits.max_depth > 0,
        Error::resource_limit("certificate path depth limit")
    );
    // Bound input before parsing, including duplicate input bytes.
    ensure!(
        certs
            .len()
            .checked_add(roots.len())
            .is_some_and(|n| n <= limits.max_store_certificates),
        Error::resource_limit("certificate store count limit")
    );
    let total = certs
        .iter()
        .chain(roots.iter())
        .try_fold(leaf_der.len(), |n, b| n.checked_add(b.len()))
        .ok_or_else(|| Error::resource_limit("certificate store byte overflow"))?;
    ensure!(
        total <= limits.max_store_bytes,
        Error::resource_limit("certificate store byte limit")
    );
    ensure!(
        leaf_der.len() <= 256 * 1024,
        Error::resource_limit("leaf certificate byte limit")
    );
    // DER ordering makes the selected path independent of caller collection order.
    let anchors: BTreeSet<&[u8]> = roots.iter().collect();
    let unique: alloc::collections::BTreeSet<&[u8]> = certs
        .iter()
        .chain(roots.iter())
        .chain(core::iter::once(leaf_der))
        .collect();
    let mut pool = Vec::with_capacity(unique.len());
    let mut subjects: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
    let mut leaf_index = 0;
    for bytes in unique {
        ensure!(
            bytes.len() <= 256 * 1024,
            Error::resource_limit("certificate byte limit")
        );
        let certificate = Certificate::from_der(bytes).map_err(Error::malformed)?;
        let index = pool.len();
        if bytes == leaf_der {
            leaf_index = index;
        }
        subjects
            .entry(
                certificate
                    .tbs_certificate
                    .subject
                    .to_der()
                    .map_err(Error::malformed)?,
            )
            .or_default()
            .push(index);
        pool.push((bytes, certificate));
    }
    // Iterative DFS retains a per-path cycle set and avoids unbounded recursion.
    let mut pending = vec![(vec![leaf_index], false)];
    let mut explored = 0usize;
    let mut signature_checks = 0usize;
    let mut last_error = Error::policy("certificate issuer missing");
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
            Error::resource_limit("certificate explored candidate limit")
        );
        let index = *path.last().unwrap();
        let (bytes, current) = &pool[index];
        let depth = path.len() - 1;
        let interpreted = match validate_extensions(
            current,
            unix_time,
            required_eku,
            depth == 0,
            subordinate_ca_count(path[..depth].iter().map(|i| &pool[*i].1)),
            bytes,
            microsoft_timestamp_compatibility,
            options.crl_signer,
        ) {
            Ok(value) => interpreted || value,
            Err(error) => reject!(path, error),
        };
        if let Err(error) =
            check_descendant_names(current, path[..depth].iter().map(|i| &pool[*i].1))
        {
            reject!(path, error);
        }
        if anchors.contains(bytes) {
            if depth == 0 {
                reject!(
                    path,
                    Error::policy("pinned root must be a self-issued CA, not the leaf")
                );
            }
            let self_issued = current.tbs_certificate.issuer == current.tbs_certificate.subject;
            if !self_issued && !options.partial_chain {
                reject!(
                    path,
                    Error::policy(
                        "pinned root must be a self-issued CA, not the leaf; \
                         partial chains require explicit selection"
                    )
                );
            }
            if self_issued {
                signature_checks += 1;
                ensure!(
                    signature_checks <= limits.max_signature_checks,
                    Error::resource_limit("certificate signature-check limit")
                );
                if let Err(error) = crypto::verify_certificate(
                    current,
                    current,
                    &crypto::CryptoOptions { allow_sha1 },
                ) {
                    reject!(path, error);
                }
            }
            let anchor_sha256 = hex::encode(Sha256::digest(bytes));
            if microsoft_timestamp_compatibility
                && !super::MICROSOFT_ROOTS.contains(&anchor_sha256.as_str())
            {
                reject!(
                    path,
                    Error::policy(
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
                valid_policies: outcome.valid_policies,
                certificates: path
                    .iter()
                    .enumerate()
                    .map(|(position, i)| diagnostic(position, path.len(), &pool[*i]))
                    .collect(),
                rejected_paths: rejected.clone(),
            };
            let parsed = path
                .iter()
                .map(|i| (pool[*i].0, &pool[*i].1))
                .collect::<Vec<_>>();
            match accept_path(&report, &parsed) {
                Ok(()) => return Ok(report),
                Err(error) => reject!(path, error),
            }
        }
        if path.len() >= limits.max_depth {
            reject!(path, Error::resource_limit("certificate path depth limit"));
        }
        if let Some(candidates) = subjects.get(
            &current
                .tbs_certificate
                .issuer
                .to_der()
                .map_err(Error::malformed)?,
        ) {
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
                    Error::resource_limit("certificate signature-check limit")
                );
                if let Err(error) = crypto::verify_certificate(
                    current,
                    parent,
                    &crypto::CryptoOptions { allow_sha1 },
                ) {
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
                    Error::resource_limit("certificate explored candidate limit")
                );
                let mut next = path.clone();
                next.push(parent_index);
                pending.push((next, interpreted));
            }
        }
    }
    Err(last_error.context("no acceptable certificate path"))
}
fn self_issued(certificate: &Certificate) -> bool {
    certificate.tbs_certificate.subject == certificate.tbs_certificate.issuer
}

fn subordinate_ca_count<'a>(descendants: impl Iterator<Item = &'a Certificate>) -> usize {
    descendants
        .skip(1)
        .filter(|certificate| !self_issued(certificate))
        .count()
}

fn check_descendant_names<'a>(
    issuer: &Certificate,
    descendants: impl Iterator<Item = &'a Certificate>,
) -> Result<()> {
    if let Some((_, constraints)) = issuer
        .tbs_certificate
        .get::<x509_cert::ext::pkix::NameConstraints>()
        .map_err(Error::malformed)?
    {
        for (index, child) in descendants.enumerate() {
            if index == 0 || !self_issued(child) {
                check_certificate_names(child, &constraints)?;
            }
        }
    }
    Ok(())
}

fn validate_parsed_constraints(
    certificates: &ParsedPath<'_>,
    unix_time: u64,
    eku: ObjectIdentifier,
    microsoft_timestamp_compatibility: bool,
) -> Result<()> {
    for (depth, (bytes, certificate)) in certificates.iter().enumerate() {
        validate_extensions(
            certificate,
            unix_time,
            eku,
            depth == 0,
            subordinate_ca_count(certificates[..depth].iter().map(|(_, c)| *c)),
            bytes,
            microsoft_timestamp_compatibility,
            false,
        )?;
        check_descendant_names(certificate, certificates[..depth].iter().map(|(_, c)| *c))?;
    }
    Ok(())
}

/// Recheck constraints on a selected report when parsed certificates are unavailable.
pub(super) fn validate_report_constraints(
    report: &ChainReport,
    unix_time: u64,
    eku: ObjectIdentifier,
) -> Result<()> {
    let parsed = report
        .chain_der
        .iter()
        .map(|bytes| Certificate::from_der(bytes))
        .collect::<core::result::Result<Vec<_>, _>>()
        .map_err(Error::malformed)?;
    let borrowed = report
        .chain_der
        .iter()
        .zip(&parsed)
        .map(|(bytes, certificate)| (bytes.as_slice(), certificate))
        .collect::<Vec<_>>();
    validate_parsed_constraints(
        &borrowed,
        unix_time,
        eku,
        report
            .microsoft_timestamp_policy_certificate_sha256
            .is_some(),
    )
}

/// Search a single timestamp path valid throughout its uncertainty interval.
#[allow(clippy::too_many_arguments)]
pub(super) fn validate_timestamp_path(
    leaf_der: &[u8],
    certs: CertificateStore<'_>,
    roots: CertificateStore<'_>,
    end_time: u64,
    start_time: u64,
    allow_sha1: bool,
    compatibility: bool,
    limits: PathLimits,
    mut accept_path: impl FnMut(&ChainReport) -> Result<()>,
) -> Result<ChainReport> {
    ensure!(
        start_time <= end_time,
        Error::malformed("invalid timestamp accuracy interval")
    );
    search_path(
        leaf_der,
        certs,
        roots,
        end_time,
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8"),
        allow_sha1,
        compatibility,
        limits,
        &PathOptions::default(),
        &mut |report, parsed| {
            if start_time != end_time {
                validate_parsed_constraints(
                    parsed,
                    start_time,
                    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8"),
                    compatibility,
                )?;
            }
            accept_path(report)
        },
    )
}

/// Inspect whether a leaf explicitly carries an EKU in addition to the chain's required EKU.
pub fn has_eku(certificate_der: &[u8], required: ObjectIdentifier) -> Result<bool> {
    let c = Certificate::from_der(certificate_der).map_err(Error::malformed)?;
    Ok(c.tbs_certificate
        .get::<ExtendedKeyUsage>()
        .map_err(Error::malformed)?
        .is_some_and(|(_, e)| e.0.contains(&required)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;
    use x509_cert::ext::pkix::CertificatePolicies;

    fn synthetic_policy() -> Vec<u8> {
        use x509_cert::ext::pkix::certpolicy::{PolicyInformation, PolicyQualifierInfo};
        let cps = der::asn1::Ia5StringRef::new(MICROSOFT_TIMESTAMP_CPS)
            .unwrap()
            .to_der()
            .unwrap();
        let text = MICROSOFT_TIMESTAMP_NOTICE
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect::<Vec<_>>();
        let bmp = der::asn1::Any::new(Tag::BmpString, text)
            .unwrap()
            .to_der()
            .unwrap();
        CertificatePolicies(vec![PolicyInformation {
            policy_identifier: MICROSOFT_TIMESTAMP_POLICY,
            policy_qualifiers: Some(vec![
                PolicyQualifierInfo {
                    policy_qualifier_id: "1.3.6.1.5.5.7.2.1".parse().unwrap(),
                    qualifier: Some(der::asn1::Any::from_der(&cps).unwrap()),
                },
                PolicyQualifierInfo {
                    policy_qualifier_id: "1.3.6.1.5.5.7.2.2".parse().unwrap(),
                    qualifier: Some(der::asn1::Any::new(Tag::Sequence, bmp).unwrap()),
                },
            ]),
        }])
        .to_der()
        .unwrap()
    }

    #[test]
    fn legacy_microsoft_policy_interprets_supported_cps_and_notice_and_rejects_other_semantics() {
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
