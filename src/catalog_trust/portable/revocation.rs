//! Signed, explicitly supplied offline CRL/OCSP evidence. Missing evidence is unknown.
use super::crypto;
use anyhow::{Context, Result, ensure};
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use x509_cert::{
    Certificate,
    ext::pkix::{ExtendedKeyUsage, KeyUsage},
};
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId};

mod crl;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationStatus {
    Good,
    Revoked,
    Unknown,
}
#[derive(Debug, Clone, Serialize)]
pub struct CertificateStatus {
    pub certificate_sha256: String,
    pub status: RevocationStatus,
    pub evidence_sha256: Vec<String>,
    pub diagnostics: Vec<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct RevocationReport {
    pub status: RevocationStatus,
    pub certificates: Vec<CertificateStatus>,
    pub current_unix_time: u64,
    pub signature_verification_time: u64,
    /// Origin of the pinned and acquired evidence this report was computed from.
    pub provenance: Vec<ArtifactProvenance>,
}
#[derive(Debug, Clone, Copy)]
pub struct RevocationLimits {
    pub max_artifacts: usize,
    pub max_artifact_bytes: usize,
    pub max_chain_certificates: usize,
    pub max_entries: usize,
    /// NextUpdate alone may permit excessively old replay: also bound age.
    pub max_age_seconds: u64,
    pub allow_sha1: bool,
}
impl Default for RevocationLimits {
    fn default() -> Self {
        Self {
            max_artifacts: 256,
            max_artifact_bytes: 16 * 1024 * 1024,
            max_chain_certificates: 16,
            max_entries: 100_000,
            max_age_seconds: 7 * 24 * 3600,
            allow_sha1: false,
        }
    }
}
fn hash(bytes: &[u8]) -> Result<String> {
    Ok(hex::encode(crypto::digest(
        "2.16.840.1.101.3.4.2.1",
        bytes,
    )?))
}
fn verify_signature(
    cert: &Certificate,
    algorithm_der: &[u8],
    message: &[u8],
    signature: &[u8],
    allow_sha1: bool,
) -> Result<()> {
    crypto::verify_algorithm(
        &cert.tbs_certificate.subject_public_key_info.to_der()?,
        algorithm_der,
        None,
        message,
        signature,
        allow_sha1,
    )
}
fn fresh(this: u64, next: Option<u64>, now: u64, limits: RevocationLimits) -> Result<()> {
    let next = next.context("revocation evidence lacks nextUpdate")?;
    ensure!(
        this <= now && now <= next && this < next,
        "stale or future revocation evidence"
    );
    ensure!(
        now - this <= limits.max_age_seconds,
        "revocation evidence age exceeds policy"
    );
    Ok(())
}
fn extensions_supported(
    exts: Option<&[x509_cert::ext::Extension]>,
    allowed: &[&str],
) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for e in exts.unwrap_or_default() {
        let oid = e.extn_id.to_string();
        ensure!(seen.insert(oid.clone()), "duplicate revocation extension");
        ensure!(
            !e.critical || allowed.contains(&oid.as_str()),
            "unsupported critical revocation extension {oid}"
        );
    }
    Ok(())
}
/// Verify a CRL for `certificate` issued by `issuer` (RFC 5280 section 6.3).
///
/// Status is `Good` only when this single CRL is fresh, authenticated, in scope
/// and covers every revocation reason; a listing is `Revoked`. A delta CRL, a
/// partial-scope CRL or stale evidence cannot prove absence here and is an
/// error; use [`verify_chain_revocation_with_signers`] to combine several CRLs.
pub fn verify_crl(
    bytes: &[u8],
    certificate: &Certificate,
    issuer: &Certificate,
    now: u64,
    limits: RevocationLimits,
) -> Result<RevocationStatus> {
    let outcome = crl::evaluate(
        &[bytes],
        certificate,
        std::slice::from_ref(issuer),
        &[],
        now,
        limits,
    )?;
    ensure!(
        outcome.status != RevocationStatus::Unknown,
        "CRL does not establish certificate status: {}",
        if outcome.diagnostics.is_empty() {
            "no fresh in-scope evidence".to_owned()
        } else {
            outcome.diagnostics.join("; ")
        }
    );
    Ok(outcome.status)
}
fn responder_matches(id: &ResponderId, certificate: &Certificate) -> Result<bool> {
    Ok(match id {
        ResponderId::ByName(name) => *name == certificate.tbs_certificate.subject,
        ResponderId::ByKey(key) => {
            key.as_bytes()
                == crypto::digest_with_policy(
                    "1.3.14.3.2.26",
                    certificate
                        .tbs_certificate
                        .subject_public_key_info
                        .subject_public_key
                        .as_bytes()
                        .context("unaligned responder public key")?,
                    true,
                )?
        }
    })
}
/// Verify issuer-signed or directly delegated OCSP. Delegation requires an
/// issuer signature and OCSP EKU, never merely a matching responder name.
pub fn verify_ocsp(
    bytes: &[u8],
    certificate: &Certificate,
    issuer: &Certificate,
    now: u64,
    limits: RevocationLimits,
) -> Result<RevocationStatus> {
    ensure!(bytes.len() <= limits.max_artifact_bytes, "OCSP byte limit");
    let response = OcspResponse::from_der(bytes)?;
    ensure!(
        response.response_status == OcspResponseStatus::Successful,
        "OCSP unsuccessful response"
    );
    let response = response
        .response_bytes
        .context("missing OCSP responseBytes")?;
    ensure!(
        response.response_type.to_string() == "1.3.6.1.5.5.7.48.1.1",
        "unsupported OCSP response type"
    );
    let basic = BasicOcspResponse::from_der(response.response.as_bytes())?;
    let tbs = &basic.tbs_response_data;
    ensure!(
        certificate.tbs_certificate.issuer == issuer.tbs_certificate.subject,
        "OCSP certificate issuer mismatch"
    );
    ensure!(
        tbs.responses.len() <= limits.max_entries,
        "OCSP response limit"
    );
    extensions_supported(tbs.response_extensions.as_deref(), &[])?;
    let produced = tbs.produced_at.0.to_unix_duration().as_secs();
    ensure!(produced <= now, "future OCSP producedAt");
    let responder = if responder_matches(&tbs.responder_id, issuer)? {
        issuer.clone()
    } else {
        let certs = basic
            .certs
            .as_deref()
            .context("OCSP responder certificate absent")?;
        ensure!(
            certs.len() <= limits.max_chain_certificates,
            "OCSP certificate limit"
        );
        let candidates = certs
            .iter()
            .map(|c| responder_matches(&tbs.responder_id, c).map(|yes| (c, yes)))
            .collect::<Result<Vec<_>>>()?;
        let candidates: Vec<_> = candidates.into_iter().filter(|(_, yes)| *yes).collect();
        ensure!(candidates.len() == 1, "ambiguous OCSP responder");
        let cert = candidates[0].0;
        extensions_supported(
            cert.tbs_certificate.extensions.as_deref(),
            &[
                "2.5.29.19",
                "2.5.29.15",
                "2.5.29.37",
                "2.5.29.14",
                "2.5.29.35",
            ],
        )?;
        if let Some((_, constraints)) = cert
            .tbs_certificate
            .get::<x509_cert::ext::pkix::BasicConstraints>()?
        {
            ensure!(!constraints.ca, "OCSP delegate must be an end entity");
        }

        ensure!(
            cert.tbs_certificate.issuer == issuer.tbs_certificate.subject,
            "OCSP responder not delegated by issuer"
        );
        ensure!(
            cert.signature_algorithm == cert.tbs_certificate.signature,
            "OCSP responder signature algorithm mismatch"
        );
        verify_signature(
            issuer,
            &cert.signature_algorithm.to_der()?,
            &cert.tbs_certificate.to_der()?,
            cert.signature
                .as_bytes()
                .context("unaligned responder signature")?,
            limits.allow_sha1,
        )?;
        let eku = cert
            .tbs_certificate
            .get::<ExtendedKeyUsage>()?
            .context("OCSP responder EKU absent")?;
        ensure!(
            eku.1.0.iter().any(|o| o.to_string() == "1.3.6.1.5.5.7.3.9"),
            "OCSP responder EKU missing"
        );
        let usage = cert
            .tbs_certificate
            .get::<KeyUsage>()?
            .context("OCSP responder keyUsage absent")?;
        ensure!(
            usage.1.digital_signature(),
            "OCSP responder lacks digitalSignature"
        );
        ensure!(
            cert.tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs()
                <= produced
                && produced
                    <= cert
                        .tbs_certificate
                        .validity
                        .not_after
                        .to_unix_duration()
                        .as_secs(),
            "OCSP responder expired at producedAt"
        );
        // Delegated responder revocation is checked using issuer-signed CRLs by
        // the outer policy; until evidence is supplied, require no-check rather
        // than silently ignoring responder revocation.
        ensure!(
            cert.tbs_certificate
                .extensions
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|e| e.extn_id.to_string() == "1.3.6.1.5.5.7.48.1.5"
                    && der::asn1::Null::from_der(e.extn_value.as_bytes()).is_ok()),
            "delegated OCSP responder requires signed nocheck"
        );
        cert.clone()
    };
    verify_signature(
        &responder,
        &basic.signature_algorithm.to_der()?,
        &tbs.to_der()?,
        basic
            .signature
            .as_bytes()
            .context("unaligned OCSP signature")?,
        limits.allow_sha1,
    )?;
    let mut matches = Vec::new();
    for single in &tbs.responses {
        let id = &single.cert_id;
        let oid = id.hash_algorithm.oid.to_string();
        if let Some(parameters) = &id.hash_algorithm.parameters {
            ensure!(
                parameters.is_null(),
                "unsupported OCSP CertID hash parameters"
            );
        }
        if id.serial_number != certificate.tbs_certificate.serial_number {
            continue;
        }
        if id.issuer_name_hash.as_bytes()
            != crypto::digest_with_policy(&oid, &issuer.tbs_certificate.subject.to_der()?, true)?
            || id.issuer_key_hash.as_bytes()
                != crypto::digest_with_policy(
                    &oid,
                    issuer
                        .tbs_certificate
                        .subject_public_key_info
                        .subject_public_key
                        .as_bytes()
                        .context("unaligned issuer public key")?,
                    true,
                )?
        {
            continue;
        }
        extensions_supported(single.single_extensions.as_deref(), &[])?;
        if let CertStatus::Revoked(info) = single.cert_status {
            ensure!(
                info.revocation_time.0.to_unix_duration().as_secs() <= now,
                "OCSP revocationTime in future"
            );
            return Ok(RevocationStatus::Revoked);
        }
        ensure!(
            now - produced <= limits.max_age_seconds,
            "stale OCSP producedAt"
        );
        fresh(
            single.this_update.0.to_unix_duration().as_secs(),
            single.next_update.map(|t| t.0.to_unix_duration().as_secs()),
            now,
            limits,
        )?;
        ensure!(
            single.this_update.0.to_unix_duration().as_secs() <= produced,
            "OCSP producedAt precedes thisUpdate"
        );
        matches.push(match single.cert_status {
            CertStatus::Good(_) => RevocationStatus::Good,
            _ => RevocationStatus::Unknown,
        });
    }
    ensure!(
        matches.len() == 1,
        "OCSP absent or ambiguous certificate status"
    );
    Ok(matches[0])
}

/// Check each non-anchor certificate. Invalid artifacts are diagnostics, never
/// positive evidence. Any authenticated revocation dominates every good result.
pub fn verify_chain_revocation(
    path_der: &[Vec<u8>],
    crls: &[Vec<u8>],
    ocsp: &[Vec<u8>],
    verification_time: u64,
    now: u64,
    limits: RevocationLimits,
) -> Result<RevocationReport> {
    verify_chain_revocation_with_signers(path_der, crls, ocsp, &[], verification_time, now, limits)
}

/// Like [`verify_chain_revocation`], additionally accepting candidate CRL
/// signing certificates for indirect CRLs and CRL key rollover. Each candidate
/// is authenticated per CRL: it must be the certificate issuer or directly
/// issued by it, valid at `now`, and carry `cRLSign`. Direct, indirect, scoped
/// and delta CRLs are evaluated together per certificate (RFC 5280 6.3).
pub fn verify_chain_revocation_with_signers(
    path_der: &[Vec<u8>],
    crls: &[Vec<u8>],
    ocsp: &[Vec<u8>],
    crl_signers: &[Vec<u8>],
    verification_time: u64,
    now: u64,
    limits: RevocationLimits,
) -> Result<RevocationReport> {
    ensure!(
        !path_der.is_empty() && path_der.len() <= limits.max_chain_certificates,
        "revocation chain length limit"
    );
    ensure!(
        crls.len() + ocsp.len() <= limits.max_artifacts,
        "revocation artifact count limit"
    );
    ensure!(
        crl_signers.len() <= limits.max_chain_certificates * 16,
        "CRL signer candidate limit"
    );
    let path = path_der
        .iter()
        .map(|b| Certificate::from_der(b))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let signers = crl_signers
        .iter()
        .map(|b| Certificate::from_der(b))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let crl_refs = crls.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let mut certificates = Vec::new();
    for i in 0..path.len() - 1 {
        let mut report = CertificateStatus {
            certificate_sha256: hash(&path_der[i])?,
            status: RevocationStatus::Unknown,
            evidence_sha256: Vec::new(),
            diagnostics: Vec::new(),
        };
        if !crls.is_empty() {
            let outcome =
                crl::evaluate(&crl_refs, &path[i], &path[i + 1..], &signers, now, limits)?;
            for index in &outcome.used {
                report.evidence_sha256.push(hash(&crls[*index])?);
            }
            report
                .diagnostics
                .extend(outcome.diagnostics.into_iter().map(|d| format!("CRL: {d}")));
            report.status = outcome.status;
        }
        for artifact in ocsp {
            match verify_ocsp(artifact, &path[i], &path[i + 1], now, limits) {
                Ok(status) => {
                    report.evidence_sha256.push(hash(artifact)?);
                    if status == RevocationStatus::Revoked
                        || report.status != RevocationStatus::Revoked
                            && status == RevocationStatus::Good
                    {
                        report.status = status;
                    }
                }
                Err(error) => report.diagnostics.push(format!("OCSP: {error}")),
            }
        }
        if report.evidence_sha256.is_empty() {
            report
                .diagnostics
                .push("no authenticated fresh issuer-bound status".into());
        }
        certificates.push(report);
    }
    let status = if certificates
        .iter()
        .any(|r| r.status == RevocationStatus::Revoked)
    {
        RevocationStatus::Revoked
    } else if certificates
        .iter()
        .any(|r| r.status == RevocationStatus::Unknown)
    {
        RevocationStatus::Unknown
    } else {
        RevocationStatus::Good
    };
    Ok(RevocationReport {
        status,
        certificates,
        current_unix_time: now,
        signature_verification_time: verification_time,
        provenance: Vec::new(),
    })
}

#[derive(Debug, Clone, Copy)]
pub struct OnlineLimits {
    pub max_requests: usize,
    pub max_response_bytes: usize,
    pub max_total_bytes: usize,
    pub timeout_seconds: u64,
}
impl Default for OnlineLimits {
    fn default() -> Self {
        Self {
            max_requests: 16,
            max_response_bytes: 16 * 1024 * 1024,
            max_total_bytes: 32 * 1024 * 1024,
            timeout_seconds: 30,
        }
    }
}
/// Where one piece of revocation evidence came from.
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactProvenance {
    /// `crl`, `delta-crl` or `ocsp`.
    pub kind: &'static str,
    /// `online` for retrieved artifacts, `pinned-file` for policy-pinned cache files.
    pub origin: &'static str,
    /// The URL retrieved, or the policy artifact path.
    pub location: String,
    pub sha256: String,
    pub bytes: usize,
    /// Verification time at which an online artifact was retrieved and authenticated;
    /// absent for pinned files, whose digest was verified when the policy was loaded.
    pub retrieved_at: Option<u64>,
    /// The certificate whose status an online request concerned.
    pub certificate_sha256: Option<String>,
    /// `crl-distribution-point`, `freshest-crl`, `authority-info-access` or `policy`.
    pub source: &'static str,
}

/// Provenance for policy-pinned evidence. Each artifact's digest was checked
/// against its pin when the policy was loaded.
pub fn pinned_provenance(
    crls: &[(&std::path::Path, &[u8])],
    ocsp: &[(&std::path::Path, &[u8])],
) -> Result<Vec<ArtifactProvenance>> {
    let mut out = Vec::new();
    for (path, bytes) in crls {
        let delta = crl::locations(bytes)
            .map(|(delta, _)| delta)
            .unwrap_or(false);
        out.push(ArtifactProvenance {
            kind: if delta { "delta-crl" } else { "crl" },
            origin: "pinned-file",
            location: path.display().to_string(),
            sha256: hash(bytes)?,
            bytes: bytes.len(),
            retrieved_at: None,
            certificate_sha256: None,
            source: "policy",
        });
    }
    for (path, bytes) in ocsp {
        out.push(ArtifactProvenance {
            kind: "ocsp",
            origin: "pinned-file",
            location: path.display().to_string(),
            sha256: hash(bytes)?,
            bytes: bytes.len(),
            retrieved_at: None,
            certificate_sha256: None,
            source: "policy",
        });
    }
    Ok(out)
}
#[derive(Debug, Default)]
pub struct AcquiredRevocation {
    pub crls: Vec<Vec<u8>>,
    pub ocsp_responses: Vec<Vec<u8>>,
    pub diagnostics: Vec<String>,
    /// One entry per accepted artifact, in the order of `crls` then `ocsp_responses`.
    pub provenance: Vec<ArtifactProvenance>,
}
/// Retrieve status only when caller explicitly chose online policy. The chain
/// must already be authenticated to caller-supplied anchors. Redirects and URL
/// credentials are refused; byte/request/wall-time limits apply. HTTP transport
/// is permitted because acceptance depends on the signed issuer-bound artifact.
#[cfg(feature = "online")]
pub fn acquire_chain_revocation(
    path_der: &[Vec<u8>],
    now: u64,
    limits: RevocationLimits,
    online: OnlineLimits,
) -> Result<AcquiredRevocation> {
    acquire_chain_revocation_with_signers(path_der, &[], now, limits, online)
}

/// Like [`acquire_chain_revocation`], with candidate CRL signing certificates
/// so indirect CRLs can be authenticated. Delta CRLs are requested from the
/// certificate's and each accepted CRL's `freshestCRL` locations.
#[cfg(feature = "online")]
pub fn acquire_chain_revocation_with_signers(
    path_der: &[Vec<u8>],
    crl_signers: &[Vec<u8>],
    now: u64,
    limits: RevocationLimits,
    online: OnlineLimits,
) -> Result<AcquiredRevocation> {
    use std::io::Read;
    use x509_cert::ext::pkix::{
        AuthorityInfoAccessSyntax, CrlDistributionPoints, FreshestCrl,
        name::{DistributionPointName, GeneralName},
    };
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum Kind {
        Crl,
        Ocsp,
    }
    fn uris(points: &[x509_cert::ext::pkix::crl::dp::DistributionPoint]) -> Vec<String> {
        let mut out = Vec::new();
        for point in points {
            if let Some(DistributionPointName::FullName(names)) = &point.distribution_point {
                for name in names {
                    if let GeneralName::UniformResourceIdentifier(uri) = name {
                        out.push(uri.as_str().to_owned());
                    }
                }
            }
        }
        out
    }
    ensure!(
        path_der.len() <= limits.max_chain_certificates,
        "online chain limit"
    );
    ensure!(
        online.timeout_seconds > 0
            && online.timeout_seconds <= 120
            && online.max_requests <= 64
            && online.max_response_bytes <= limits.max_artifact_bytes,
        "invalid online limits"
    );
    ensure!(
        crl_signers.len() <= limits.max_chain_certificates * 16,
        "CRL signer candidate limit"
    );
    let path = path_der
        .iter()
        .map(|b| Certificate::from_der(b))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let signers = crl_signers
        .iter()
        .map(|b| Certificate::from_der(b))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()?;
    let start = std::time::Instant::now();
    let deadline = std::time::Duration::from_secs(online.timeout_seconds);
    let mut output = AcquiredRevocation::default();
    let mut count = 0usize;
    let mut total = 0usize;
    let mut attempted = std::collections::BTreeSet::new();
    for (position, pair) in path.windows(2).enumerate() {
        let cert = &pair[0];
        let issuer = &pair[1];
        let certificate_sha256 = hash(&path_der[position])?;
        // (kind, url, source)
        let mut requests: Vec<(Kind, String, &'static str)> = Vec::new();
        if let Some((_, points)) = cert.tbs_certificate.get::<CrlDistributionPoints>()? {
            ensure!(points.0.len() <= 64, "online distribution point limit");
            requests.extend(
                uris(&points.0)
                    .into_iter()
                    .map(|u| (Kind::Crl, u, "crl-distribution-point")),
            );
        }
        if let Some((_, points)) = cert.tbs_certificate.get::<FreshestCrl>()? {
            ensure!(points.0.len() <= 64, "online distribution point limit");
            requests.extend(
                uris(&points.0)
                    .into_iter()
                    .map(|u| (Kind::Crl, u, "freshest-crl")),
            );
        }
        if let Some((_, access)) = cert.tbs_certificate.get::<AuthorityInfoAccessSyntax>()? {
            ensure!(access.0.len() <= 64, "online AIA limit");
            for description in access.0 {
                if description.access_method.to_string() == "1.3.6.1.5.5.7.48.1"
                    && let GeneralName::UniformResourceIdentifier(uri) = description.access_location
                {
                    requests.push((Kind::Ocsp, uri.as_str().to_owned(), "authority-info-access"));
                }
            }
        }
        let mut cursor = 0;
        while cursor < requests.len() {
            let (kind, url, source) = requests[cursor].clone();
            cursor += 1;
            if !attempted.insert((
                kind,
                url.clone(),
                cert.tbs_certificate.serial_number.as_bytes().to_vec(),
            )) {
                continue;
            }
            if count >= online.max_requests
                || start.elapsed() >= deadline
                || total >= online.max_total_bytes
            {
                output
                    .diagnostics
                    .push("online revocation request/time/total byte limit reached".into());
                return Ok(output);
            }
            let is_ocsp = kind == Kind::Ocsp;
            let result = (|| -> Result<(Vec<u8>, bool, Vec<String>)> {
                ensure!(url.len() <= 8192, "revocation URL length limit");
                let parsed = reqwest::Url::parse(&url)?;
                ensure!(
                    matches!(parsed.scheme(), "http" | "https")
                        && parsed.host_str().is_some()
                        && parsed.username().is_empty()
                        && parsed.password().is_none()
                        && parsed.fragment().is_none(),
                    "unsupported revocation URL"
                );
                let timeout = deadline
                    .checked_sub(start.elapsed())
                    .context("online time limit")?;
                let request = if is_ocsp {
                    client
                        .post(parsed)
                        .header("Content-Type", "application/ocsp-request")
                        .header("Accept", "application/ocsp-response")
                        .body(ocsp_request(cert, issuer)?)
                } else {
                    client.get(parsed)
                };
                let mut response = request.timeout(timeout).send()?.error_for_status()?;
                ensure!(
                    response.status().is_success(),
                    "revocation redirect or non-success status"
                );
                let remaining = online.max_total_bytes.saturating_sub(total);
                let response_limit = online.max_response_bytes.min(remaining);
                if let Some(length) = response.content_length() {
                    ensure!(
                        length <= response_limit as u64,
                        "revocation response declared byte limit"
                    );
                }
                let mut bytes = Vec::new();
                response
                    .by_ref()
                    .take(response_limit as u64 + 1)
                    .read_to_end(&mut bytes)?;
                total = total
                    .checked_add(bytes.len())
                    .context("online total overflow")?;
                ensure!(
                    bytes.len() <= response_limit,
                    "revocation response byte limit"
                );
                ensure!(
                    total <= online.max_total_bytes,
                    "online response total byte limit"
                );
                if is_ocsp {
                    ensure!(
                        verify_ocsp(&bytes, cert, issuer, now, limits)?
                            != RevocationStatus::Unknown,
                        "online responder status unknown"
                    );
                    return Ok((bytes, false, Vec::new()));
                }
                // A CRL is accepted when authenticated and authorized for this
                // certificate. Completeness and freshness are decided later, so
                // delta and scoped CRLs are retained.
                let outcome = crl::evaluate(
                    &[&bytes],
                    cert,
                    &path[position + 1..],
                    &signers,
                    now,
                    limits,
                )?;
                ensure!(
                    !outcome.relevant.is_empty(),
                    "online CRL not authenticated for the certificate: {}",
                    outcome.diagnostics.join("; ")
                );
                let (is_delta, locations) = crl::locations(&bytes)?;
                Ok((bytes, is_delta, locations))
            })();
            count += 1;
            match result {
                Ok((bytes, is_delta, locations)) => {
                    output.provenance.push(ArtifactProvenance {
                        kind: if is_ocsp {
                            "ocsp"
                        } else if is_delta {
                            "delta-crl"
                        } else {
                            "crl"
                        },
                        origin: "online",
                        location: url,
                        sha256: hash(&bytes)?,
                        bytes: bytes.len(),
                        retrieved_at: Some(now),
                        certificate_sha256: Some(certificate_sha256.clone()),
                        source,
                    });
                    if is_ocsp {
                        output.ocsp_responses.push(bytes)
                    } else {
                        output.crls.push(bytes);
                        if requests.len() + locations.len() <= 256 {
                            requests.extend(
                                locations
                                    .into_iter()
                                    .map(|u| (Kind::Crl, u, "freshest-crl")),
                            );
                        }
                    }
                }
                Err(error) => output.diagnostics.push(format!(
                    "online {}: {error}",
                    if is_ocsp { "OCSP" } else { "CRL" }
                )),
            }
        }
    }
    Ok(output)
}
#[cfg(feature = "online")]
fn ocsp_request(certificate: &Certificate, issuer: &Certificate) -> Result<Vec<u8>> {
    use der::asn1::{Null, ObjectIdentifier, OctetString};
    let hash_oid = "1.3.14.3.2.26";
    let id = x509_ocsp::CertId {
        hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new(hash_oid)?,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(crypto::digest_with_policy(
            hash_oid,
            &issuer.tbs_certificate.subject.to_der()?,
            true,
        )?)?,
        issuer_key_hash: OctetString::new(crypto::digest_with_policy(
            hash_oid,
            issuer
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .context("unaligned issuer key")?,
            true,
        )?)?,
        serial_number: certificate.tbs_certificate.serial_number.clone(),
    };
    let request = x509_ocsp::OcspRequest {
        tbs_request: x509_ocsp::TbsRequest {
            version: Default::default(),
            requestor_name: None,
            request_list: vec![x509_ocsp::Request {
                req_cert: id,
                single_request_extensions: None,
            }],
            request_extensions: None,
        },
        optional_signature: None,
    };
    Ok(request.to_der()?)
}

/// Acquisition is unavailable unless the explicit `online` capability is enabled.
#[cfg(not(feature = "online"))]
pub fn acquire_chain_revocation(
    _path_der: &[Vec<u8>],
    _now: u64,
    _limits: RevocationLimits,
    _online: OnlineLimits,
) -> Result<AcquiredRevocation> {
    anyhow::bail!("online revocation acquisition requires the wintrust online feature")
}

/// Acquisition is unavailable unless the explicit `online` capability is enabled.
#[cfg(not(feature = "online"))]
pub fn acquire_chain_revocation_with_signers(
    _path_der: &[Vec<u8>],
    _crl_signers: &[Vec<u8>],
    _now: u64,
    _limits: RevocationLimits,
    _online: OnlineLimits,
) -> Result<AcquiredRevocation> {
    anyhow::bail!("online revocation acquisition requires the wintrust online feature")
}
