//! RFC 5280 sections 5 and 6.3 CRL evaluation over an explicitly supplied set.
//!
//! Direct, indirect, scoped (issuing distribution point) and delta CRLs are
//! authenticated against the certificate's already validated issuer, or against
//! a CRL signing certificate that issuer directly issued. Status is `Good` only
//! when fresh, in-scope evidence covers every revocation reason; any
//! authenticated listing of the certificate is `Revoked` regardless of
//! freshness. Everything else is `Unknown`.
use super::{RevocationLimits, RevocationStatus, extensions_supported, fresh, verify_signature};
use anyhow::{Context, Result, bail, ensure};
use der::{Decode, Encode, asn1::Uint};
use std::{cmp::Ordering, collections::BTreeSet};
use x509_cert::{
    Certificate,
    crl::CertificateList,
    ext::pkix::{
        BasicConstraints, CrlDistributionPoints, KeyUsage, SubjectKeyIdentifier,
        crl::{CrlReason, IssuingDistributionPoint, dp::DistributionPoint},
        name::{DistributionPointName, GeneralName},
    },
    name::Name,
};

/// Reason bits 1 through 8 of ReasonFlags; bit 0 is `unused`.
pub(super) const ALL_REASONS: u16 = 0x1fe;
const OID_CRL_NUMBER: &str = "2.5.29.20";
const OID_DELTA_INDICATOR: &str = "2.5.29.27";
const OID_ISSUING_DISTRIBUTION_POINT: &str = "2.5.29.28";
const OID_CERTIFICATE_ISSUER: &str = "2.5.29.29";
const OID_AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
const OID_CRL_REASON: &str = "2.5.29.21";

/// What evaluation of a CRL set established for one certificate.
#[derive(Debug)]
pub(super) struct CrlOutcome {
    pub status: RevocationStatus,
    /// Indices of CRLs that determined the status or contributed coverage.
    pub used: Vec<usize>,
    /// Indices of CRLs that authenticated and are bound to the certificate's issuer.
    #[cfg_attr(not(feature = "online"), allow(dead_code))]
    pub relevant: Vec<usize>,
    pub diagnostics: Vec<String>,
}

struct Parsed {
    list: CertificateList,
    crl_number: Option<Vec<u8>>,
    base_number: Option<Vec<u8>>,
    idp: Option<IssuingDistributionPoint>,
    idp_der: Option<Vec<u8>>,
    aki_der: Option<Vec<u8>>,
    this_update: u64,
    next_update: Option<u64>,
}

impl Parsed {
    fn is_delta(&self) -> bool {
        self.base_number.is_some()
    }
    fn issuer(&self) -> &Name {
        &self.list.tbs_cert_list.issuer
    }
}

fn number(value: &Uint) -> Vec<u8> {
    let bytes = value.as_bytes();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    bytes[start..].to_vec()
}

fn compare_numbers(a: &[u8], b: &[u8]) -> Ordering {
    (a.len(), a).cmp(&(b.len(), b))
}

fn authority_matches(aki_der: &[u8], signer: &Certificate) -> Result<bool> {
    let aki = x509_cert::ext::pkix::AuthorityKeyIdentifier::from_der(aki_der)?;
    ensure!(
        aki.authority_cert_issuer.is_some() == aki.authority_cert_serial_number.is_some(),
        "CRL authority issuer/serial must appear together"
    );
    if let Some(names) = &aki.authority_cert_issuer
        && !(names.len() == 1
            && matches!(&names[0], GeneralName::DirectoryName(name) if *name == signer.tbs_certificate.issuer))
    {
        return Ok(false);
    }
    if let Some(key) = aki.key_identifier {
        let Some((_, ski)) = signer.tbs_certificate.get::<SubjectKeyIdentifier>()? else {
            return Ok(false);
        };
        if key != ski.0 {
            return Ok(false);
        }
    }
    if let Some(serial) = aki.authority_cert_serial_number
        && serial != signer.tbs_certificate.serial_number
    {
        return Ok(false);
    }
    Ok(true)
}

/// A CRL signing certificate other than the issuer must validate to the same
/// trust anchor as the certificate being checked (RFC 5280 6.3.3 (f)): full path
/// validation with time, constraints and policies, but no purpose requirement
/// beyond `cRLSign`. The signer's own revocation status is not evaluated.
fn authorize_signer(
    candidate: &Certificate,
    ancestry: &[Certificate],
    pool: &[Certificate],
    now: u64,
    limits: RevocationLimits,
) -> Result<()> {
    use super::super::chain::{self, PathLimits, PathOptions};
    let anchor = ancestry.last().context("CRL signer path has no anchor")?;
    let mut intermediates = Vec::new();
    for certificate in ancestry[..ancestry.len() - 1].iter().chain(pool) {
        if certificate != candidate {
            intermediates.push(certificate.to_der()?);
        }
    }
    chain::validate_with_options(
        &candidate.to_der()?,
        &intermediates,
        &[anchor.to_der()?],
        now,
        "",
        limits.allow_sha1,
        PathLimits::default(),
        &PathOptions {
            crl_signer: true,
            ..PathOptions::default()
        },
        |_| Ok(()),
    )
    .map(drop)
    .context("CRL signer does not chain to the trust anchor")
}

fn authenticate(
    bytes: &[u8],
    ancestry: &[Certificate],
    signers: &[Certificate],
    now: u64,
    limits: RevocationLimits,
) -> Result<Parsed> {
    ensure!(bytes.len() <= limits.max_artifact_bytes, "CRL byte limit");
    let issuer = ancestry.first().context("CRL certificate issuer missing")?;
    let list = CertificateList::from_der(bytes)?;
    let tbs = &list.tbs_cert_list;
    ensure!(
        tbs.signature == list.signature_algorithm,
        "CRL signature algorithm mismatch"
    );
    let extensions = tbs.crl_extensions.as_deref();
    if extensions.is_some() {
        ensure!(
            tbs.version == x509_cert::certificate::Version::V2,
            "CRL extensions require a version 2 CRL"
        );
    }
    extensions_supported(
        extensions,
        &[OID_ISSUING_DISTRIBUTION_POINT, OID_DELTA_INDICATOR],
    )?;
    let mut crl_number = None;
    let mut base_number = None;
    let mut idp = None;
    let mut idp_der = None;
    let mut aki_der = None;
    for extension in extensions.unwrap_or_default() {
        let id = extension.extn_id.to_string();
        let value = extension.extn_value.as_bytes();
        match id.as_str() {
            OID_CRL_NUMBER => {
                ensure!(!extension.critical, "critical CRL number");
                crl_number = Some(number(&Uint::from_der(value)?));
            }
            OID_DELTA_INDICATOR => {
                ensure!(extension.critical, "deltaCRLIndicator must be critical");
                base_number = Some(number(&Uint::from_der(value)?));
            }
            OID_ISSUING_DISTRIBUTION_POINT => {
                ensure!(
                    extension.critical,
                    "issuingDistributionPoint must be critical"
                );
                let point = IssuingDistributionPoint::from_der(value)?;
                ensure!(
                    u8::from(point.only_contains_user_certs)
                        + u8::from(point.only_contains_ca_certs)
                        + u8::from(point.only_contains_attribute_certs)
                        <= 1,
                    "conflicting issuingDistributionPoint scope flags"
                );
                idp = Some(point);
                idp_der = Some(value.to_vec());
            }
            OID_AUTHORITY_KEY_IDENTIFIER => aki_der = Some(value.to_vec()),
            _ => {}
        }
    }
    ensure!(
        base_number.is_none() || crl_number.is_some(),
        "delta CRL lacks a CRL number"
    );
    if let (Some(base), Some(this)) = (&base_number, &crl_number) {
        ensure!(
            compare_numbers(base, this) == Ordering::Less,
            "delta CRL base number is not below its own number"
        );
    }
    let signature = list
        .signature
        .as_bytes()
        .context("unaligned CRL signature")?;
    let message = tbs.to_der()?;
    let algorithm = list.signature_algorithm.to_der()?;
    let mut last_error = anyhow::anyhow!("no CRL signing certificate for the CRL issuer");
    for (position, candidate) in std::iter::once(issuer).chain(signers).enumerate() {
        if candidate.tbs_certificate.subject != tbs.issuer {
            continue;
        }
        let attempt = (|| -> Result<()> {
            let usage = candidate
                .tbs_certificate
                .get::<KeyUsage>()?
                .context("CRL signer keyUsage missing")?;
            ensure!(usage.1.crl_sign(), "CRL signer lacks cRLSign usage");
            if position > 0 && candidate != issuer {
                authorize_signer(candidate, ancestry, signers, now, limits)?;
            }
            if let Some(aki) = &aki_der {
                ensure!(
                    authority_matches(aki, candidate)?,
                    "CRL authority key identifier mismatch"
                );
            }
            verify_signature(
                candidate,
                &algorithm,
                &message,
                signature,
                limits.allow_sha1,
            )
        })();
        match attempt {
            Ok(()) => {
                let this_update = tbs.this_update.to_unix_duration().as_secs();
                let next_update = tbs.next_update.map(|t| t.to_unix_duration().as_secs());
                return Ok(Parsed {
                    list,
                    crl_number,
                    base_number,
                    idp,
                    idp_der,
                    aki_der,
                    this_update,
                    next_update,
                });
            }
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

#[derive(Clone, Copy)]
struct Listing {
    reason: CrlReason,
}

impl Listing {
    fn revokes(self) -> bool {
        self.reason != CrlReason::RemoveFromCRL
    }
}

/// Find the entry for `certificate`, tracking `certificateIssuer` through indirect CRLs.
fn lookup(
    crl: &Parsed,
    certificate: &Certificate,
    now: u64,
    limits: RevocationLimits,
) -> Result<Option<Listing>> {
    let entries = crl
        .list
        .tbs_cert_list
        .revoked_certificates
        .as_deref()
        .unwrap_or_default();
    ensure!(entries.len() <= limits.max_entries, "CRL entry limit");
    let indirect = crl.idp.as_ref().is_some_and(|idp| idp.indirect_crl);
    let mut current_issuer = crl.issuer().clone();
    let mut seen = BTreeSet::new();
    let mut found = None;
    for entry in entries {
        let extensions = entry.crl_entry_extensions.as_deref();
        extensions_supported(extensions, &[OID_CERTIFICATE_ISSUER])?;
        let mut reason = CrlReason::Unspecified;
        for extension in extensions.unwrap_or_default() {
            match extension.extn_id.to_string().as_str() {
                OID_CERTIFICATE_ISSUER => {
                    ensure!(indirect, "certificateIssuer in a CRL that is not indirect");
                    ensure!(extension.critical, "certificateIssuer must be critical");
                    let names = Vec::<GeneralName>::from_der(extension.extn_value.as_bytes())?;
                    match names.as_slice() {
                        [GeneralName::DirectoryName(name)] => current_issuer = name.clone(),
                        _ => bail!("unsupported certificateIssuer form"),
                    }
                }
                OID_CRL_REASON => {
                    ensure!(!extension.critical, "critical CRL reason code");
                    reason = CrlReason::from_der(extension.extn_value.as_bytes())?;
                }
                _ => {}
            }
        }
        ensure!(
            seen.insert((
                current_issuer.to_der()?,
                entry.serial_number.as_bytes().to_vec()
            )),
            "duplicate CRL serial"
        );
        ensure!(
            entry.revocation_date.to_unix_duration().as_secs() <= now,
            "CRL revocation date is future"
        );
        if entry.serial_number == certificate.tbs_certificate.serial_number
            && current_issuer == certificate.tbs_certificate.issuer
        {
            found = Some(Listing { reason });
        }
    }
    Ok(found)
}

fn bits(flags: x509_cert::ext::pkix::crl::dp::ReasonFlags) -> u16 {
    flags.bits() & ALL_REASONS
}

/// RFC 5280 6.3.3: the CRL issuer must be the certificate issuer, or the
/// `cRLIssuer` the distribution point names for an indirect CRL.
fn bound(crl: &Parsed, certificate: &Certificate, point: &DistributionPoint) -> bool {
    let issuer = crl.issuer();
    match &point.crl_issuer {
        Some(names) => {
            names
                .iter()
                .any(|n| matches!(n, GeneralName::DirectoryName(name) if name == issuer))
                && (*issuer == certificate.tbs_certificate.issuer
                    || crl.idp.as_ref().is_some_and(|idp| idp.indirect_crl))
        }
        None => *issuer == certificate.tbs_certificate.issuer,
    }
}

/// Names a distribution point name denotes. A relative name extends `base`
/// (the issuer of the CRL it appears in or the `cRLIssuer` it is relative to).
fn full_names(name: &DistributionPointName, base: &Name) -> Vec<GeneralName> {
    match name {
        DistributionPointName::FullName(names) => names.clone(),
        DistributionPointName::NameRelativeToCRLIssuer(rdn) => {
            let mut full = base.clone();
            full.0.push(rdn.clone());
            vec![GeneralName::DirectoryName(full)]
        }
    }
}

/// Reasons this CRL covers for `certificate` under distribution point `point`,
/// or `None` when the CRL's scope excludes the certificate.
fn scope(
    crl: &Parsed,
    certificate: &Certificate,
    is_ca: bool,
    point: &DistributionPoint,
) -> Option<u16> {
    let mut mask = ALL_REASONS;
    if let Some(reasons) = point.reasons {
        mask &= bits(reasons);
    }
    if let Some(idp) = &crl.idp {
        if let Some(name) = &idp.distribution_point {
            let issuer = crl.issuer();
            let idp_names = full_names(name, issuer);
            let responsible = point.crl_issuer.as_ref();
            let matches = match &point.distribution_point {
                Some(point_name) => {
                    let base = responsible
                        .and_then(|names| {
                            names.iter().find_map(|n| match n {
                                GeneralName::DirectoryName(x) => Some(x),
                                _ => None,
                            })
                        })
                        .unwrap_or(&certificate.tbs_certificate.issuer);
                    let point_names = full_names(point_name, base);
                    idp_names.iter().any(|n| point_names.contains(n))
                        || responsible.is_some_and(|names| {
                            names
                                .iter()
                                .any(|n| matches!(n, GeneralName::DirectoryName(x) if x == issuer))
                        })
                }
                None => {
                    responsible.is_some_and(|names| idp_names.iter().any(|n| names.contains(n)))
                }
            };
            if !matches {
                return None;
            }
        }
        if idp.only_contains_user_certs && is_ca {
            return None;
        }
        if idp.only_contains_ca_certs && !is_ca {
            return None;
        }
        if idp.only_contains_attribute_certs {
            return None;
        }
        if let Some(reasons) = idp.only_some_reasons {
            mask &= bits(reasons);
        }
    }
    (mask != 0).then_some(mask)
}

fn delta_applies(delta: &Parsed, base: &Parsed) -> bool {
    match (
        &delta.base_number,
        &delta.crl_number,
        &base.crl_number,
        base.is_delta(),
    ) {
        (Some(base_number), Some(delta_number), Some(number), false) => {
            delta.issuer() == base.issuer()
                && delta.idp_der == base.idp_der
                && delta.aki_der == base.aki_der
                && compare_numbers(base_number, number) != Ordering::Greater
                && compare_numbers(delta_number, number) == Ordering::Greater
        }
        _ => false,
    }
}

fn is_fresh(crl: &Parsed, now: u64, limits: RevocationLimits) -> Result<()> {
    fresh(crl.this_update, crl.next_update, now, limits)
}

/// Evaluate `crls` for `certificate`. `ancestry` runs from its already validated
/// issuer up to the trust anchor.
/// `signers` are candidate CRL signing certificates and are authenticated here.
pub(super) fn evaluate(
    crls: &[&[u8]],
    certificate: &Certificate,
    ancestry: &[Certificate],
    signers: &[Certificate],
    now: u64,
    limits: RevocationLimits,
) -> Result<CrlOutcome> {
    let issuer = ancestry.first().context("CRL certificate issuer missing")?;
    ensure!(
        certificate.tbs_certificate.issuer == issuer.tbs_certificate.subject,
        "CRL certificate issuer mismatch"
    );
    let mut diagnostics = Vec::new();
    let mut parsed = Vec::new();
    for (index, bytes) in crls.iter().enumerate() {
        match authenticate(bytes, ancestry, signers, now, limits) {
            Ok(crl) => parsed.push((index, crl)),
            Err(error) => diagnostics.push(format!("CRL {index}: {error:#}")),
        }
    }
    let points = match certificate.tbs_certificate.get::<CrlDistributionPoints>()? {
        Some((_, points)) => {
            ensure!(
                !points.0.is_empty() && points.0.len() <= 64,
                "CRL distribution point count"
            );
            points.0
        }
        None => vec![DistributionPoint {
            distribution_point: None,
            reasons: None,
            crl_issuer: None,
        }],
    };
    let is_ca = certificate
        .tbs_certificate
        .get::<BasicConstraints>()?
        .is_some_and(|(_, constraints)| constraints.ca);
    // Per-CRL: whether it is bound to the issuer and the reasons it covers.
    let mut bindings = Vec::new();
    for (index, crl) in &parsed {
        let mut is_bound = false;
        let mut mask = 0u16;
        for point in &points {
            if bound(crl, certificate, point) {
                is_bound = true;
                if let Some(covered) = scope(crl, certificate, is_ca, point) {
                    mask |= covered;
                }
            }
        }
        if !is_bound {
            diagnostics.push(format!(
                "CRL {index}: issuer is not authorized for the certificate"
            ));
        }
        bindings.push((is_bound, mask));
    }
    let relevant = parsed
        .iter()
        .zip(&bindings)
        .filter(|(_, (is_bound, _))| *is_bound)
        .map(|((index, _), _)| *index)
        .collect::<Vec<_>>();
    let mut used = BTreeSet::new();
    let mut revoked = false;
    let mut coverage = 0u16;
    for (position, (index, crl)) in parsed.iter().enumerate() {
        let (is_bound, mask) = bindings[position];
        if !is_bound {
            continue;
        }
        let listing = lookup(crl, certificate, now, limits);
        let listing = match listing {
            Ok(listing) => listing,
            Err(error) => {
                diagnostics.push(format!("CRL {index}: {error:#}"));
                continue;
            }
        };
        if crl.is_delta() {
            // A delta listing is authentic revocation even without its base.
            if listing.is_some_and(Listing::revokes) {
                revoked = true;
                used.insert(*index);
            }
            continue;
        }
        // Newest applicable delta supersedes older deltas on the same base.
        let latest = parsed
            .iter()
            .enumerate()
            .filter(|(p, (_, delta))| bindings[*p].0 && delta_applies(delta, crl))
            .max_by(|(_, (_, a)), (_, (_, b))| {
                compare_numbers(
                    a.crl_number.as_deref().unwrap_or_default(),
                    b.crl_number.as_deref().unwrap_or_default(),
                )
            });
        let mut effective = listing;
        let mut delta_fresh = false;
        if let Some((_, (delta_index, delta))) = latest {
            match lookup(delta, certificate, now, limits) {
                Ok(Some(entry)) if entry.revokes() => effective = Some(entry),
                Ok(Some(_)) => {
                    // removeFromCRL only releases a certificate on hold.
                    if effective.is_some_and(|l| l.reason == CrlReason::CertificateHold) {
                        effective = None;
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    diagnostics.push(format!("CRL {delta_index}: {error:#}"));
                    continue;
                }
            }
            match is_fresh(delta, now, limits) {
                Ok(()) => delta_fresh = true,
                Err(error) => diagnostics.push(format!("CRL {delta_index}: {error:#}")),
            }
            used.insert(*delta_index);
        }
        if effective.is_some_and(Listing::revokes) {
            revoked = true;
            used.insert(*index);
            continue;
        }
        let base_fresh = match is_fresh(crl, now, limits) {
            Ok(()) => true,
            Err(error) => {
                diagnostics.push(format!("CRL {index}: {error:#}"));
                false
            }
        };
        if (base_fresh || delta_fresh) && mask != 0 {
            coverage |= mask;
            used.insert(*index);
        }
    }
    let status = if revoked {
        RevocationStatus::Revoked
    } else if coverage == ALL_REASONS {
        RevocationStatus::Good
    } else {
        if coverage != 0 {
            diagnostics.push(format!(
                "CRL coverage {coverage:#05x} does not include every revocation reason"
            ));
        }
        RevocationStatus::Unknown
    };
    Ok(CrlOutcome {
        status,
        used: used.into_iter().collect(),
        relevant,
        diagnostics,
    })
}

/// Whether `bytes` is a delta CRL and the `freshestCRL` URIs it advertises.
/// Parsing only: nothing here authenticates the CRL.
pub(super) fn locations(bytes: &[u8]) -> Result<(bool, Vec<String>)> {
    use x509_cert::ext::pkix::FreshestCrl;
    let list = CertificateList::from_der(bytes)?;
    let mut delta = false;
    let mut out = Vec::new();
    for extension in list.tbs_cert_list.crl_extensions.iter().flatten() {
        match extension.extn_id.to_string().as_str() {
            OID_DELTA_INDICATOR => delta = true,
            "2.5.29.46" => {
                let points = FreshestCrl::from_der(extension.extn_value.as_bytes())?;
                ensure!(points.0.len() <= 64, "freshestCRL point count");
                for point in &points.0 {
                    if let Some(DistributionPointName::FullName(names)) = &point.distribution_point
                    {
                        for name in names {
                            if let GeneralName::UniformResourceIdentifier(uri) = name {
                                out.push(uri.as_str().to_owned());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok((delta, out))
}
