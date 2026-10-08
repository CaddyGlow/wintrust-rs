//! Portable catalog verification using explicit trust inputs and Rust cryptography.
//!
//! This policy is reproducible without inheriting a host Windows trust store.
pub mod chain;
pub mod crypto;
pub mod policy;
pub mod revocation;
mod runtime;
#[cfg(feature = "std")]
pub use runtime::VerifierBuilder;
pub mod signed;
pub mod sip;
pub mod timestamp;

pub use crate::CertificateStore;
use crate::ObjectIdentifier;
use crate::error::{Context, Error, Result, ensure};
use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(feature = "online")]
use std::time::Instant;
#[cfg(feature = "std")]
use std::{
    fs::OpenOptions,
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

/// Hash-pinned artifact location. The identifier is opaque to an injected reader;
/// filesystem adapters resolve it relative to the policy directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    pub path: String,
    pub sha256: String,
}

/// Publisher authorization applied in addition to signature and chain validation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PublisherPolicy {
    /// Trust code-signing chains ending at an explicitly pinned supplied anchor.
    ExplicitRoots,
    /// Require an official pinned Microsoft anchor and Windows component EKU.
    MicrosoftWindows,
}

/// Revocation evidence required to accept the signature.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortableRevocationPolicy {
    /// Require fresh signed CRL/OCSP evidence for every non-root certificate.
    RequireFresh,
    /// Permit bounded online retrieval, then require the same signed evidence.
    Online,
    /// Explicitly skip revocation; this never asserts non-revocation.
    Disabled,
}

/// Whether cryptographically verified timestamps may supply signing time.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimestampPolicy {
    UseVerified,
    Require,
    Ignore,
}

/// Versioned, explicit portable trust policy. No embedded certificate becomes
/// an anchor merely because it appears in the catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortablePolicy {
    pub schema_version: u32,
    pub roots: Vec<ArtifactRef>,
    #[serde(default)]
    pub intermediates: Vec<ArtifactRef>,
    #[serde(default)]
    pub crls: Vec<ArtifactRef>,
    #[serde(default)]
    pub ocsp_responses: Vec<ArtifactRef>,
    pub publisher: PublisherPolicy,
    pub revocation: PortableRevocationPolicy,
    pub timestamp: TimestampPolicy,
    /// A reproducible evaluation time. Required without `std`; with `std`,
    /// absence captures the current Unix time during construction.
    pub verification_time: Option<u64>,
    #[serde(default)]
    pub allow_sha1: bool,
    /// Explicit Microsoft TSA leaf DER fingerprints permitting a noncritical,
    /// sole Time Stamping EKU. Empty preserves strict RFC3161 behavior.
    #[serde(default)]
    pub noncritical_tsa_certificate_sha256: Vec<String>,
    /// Extra replay bound, in addition to the artifact's signed nextUpdate.
    #[serde(default = "default_revocation_age")]
    pub revocation_max_age_seconds: u64,
}
fn default_revocation_age() -> u64 {
    7 * 24 * 3600
}

/// Bounded policy and input loading. Decoder bounds remain independent.
#[derive(Debug, Clone)]
pub struct PortableLimits {
    pub max_policy_bytes: usize,
    pub max_artifact_bytes: usize,
    pub max_artifacts: usize,
    pub max_total_artifact_bytes: usize,
    pub max_member_bytes: usize,
    pub max_online_seconds: u64,
}
impl Default for PortableLimits {
    fn default() -> Self {
        Self {
            max_policy_bytes: 1024 * 1024,
            max_artifact_bytes: 16 * 1024 * 1024,
            max_artifacts: 128,
            max_total_artifact_bytes: 64 * 1024 * 1024,
            max_member_bytes: 64 * 1024 * 1024,
            max_online_seconds: 60,
        }
    }
}

/// Immutable verifier constructed from validated policy and hash-pinned evidence.
/// With `std`, an omitted evaluation time is captured once during construction.
/// Without `std`, callers must supply the evaluation time.
///
/// ```compile_fail
/// # use wintrust::portable::Verifier;
/// fn change(verifier: &mut Verifier) {
///     verifier.policy.revocation = todo!();
/// }
/// ```
#[derive(Debug)]
pub struct Verifier {
    policy: PortablePolicy,
    roots: Vec<Vec<u8>>,
    intermediates: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
    ocsp_responses: Vec<Vec<u8>>,
    limits: PortableLimits,
    evaluation_time: u64,
    pinned_provenance: Vec<revocation::ArtifactProvenance>,
}

#[cfg(feature = "std")]
pub(super) fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "portable verification inputs must be regular files"
    );
    let mut bytes = Vec::new();
    file.take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        Error::resource_limit("input exceeds portable verification byte limit")
    );
    Ok(bytes)
}

impl Verifier {
    /// Load a policy plus hash-pinned DER roots, intermediates and status evidence.
    #[cfg(feature = "std")]
    pub fn load(policy_path: &Path, limits: PortableLimits) -> Result<Self> {
        let bytes = read_bounded(policy_path, limits.max_policy_bytes)?;
        let policy: PortablePolicy = serde_json::from_slice(&bytes)?;
        Self::from_policy(
            policy,
            policy_path.parent().unwrap_or(Path::new(".")),
            limits,
        )
    }
    #[cfg(feature = "std")]
    pub fn from_policy(
        policy: PortablePolicy,
        base: &Path,
        limits: PortableLimits,
    ) -> Result<Self> {
        Self::from_policy_with_reader(policy, base, limits, read_bounded)
    }

    /// Load pinned policy artifacts through a caller-selected bounded reader.
    /// The common loader still enforces every artifact pin, count and aggregate
    /// limit. This permits access-inhibited native observations without changing
    /// cryptographic verification or granting trust to caller assertions.
    #[cfg(feature = "std")]
    pub fn from_policy_with_reader(
        policy: PortablePolicy,
        base: &Path,
        limits: PortableLimits,
        mut reader: impl FnMut(&Path, usize) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        Self::from_artifact_reader(policy, limits, |artifact, limit| {
            reader(&base.join(&artifact.path), limit)
        })
    }

    /// Construct from pinned artifacts supplied by the caller. Without `std`,
    /// policy.verification_time must specify the evaluation clock explicitly.
    pub fn from_artifact_reader(
        mut policy: PortablePolicy,
        limits: PortableLimits,
        mut reader: impl FnMut(&ArtifactRef, usize) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        ensure!(
            limits.max_policy_bytes > 0
                && limits.max_artifact_bytes > 0
                && limits.max_artifacts > 0
                && limits.max_total_artifact_bytes > 0
                && limits.max_member_bytes > 0,
            Error::configuration("runtime byte and count limits must be positive")
        );
        ensure!(
            policy.revocation != PortableRevocationPolicy::Online || limits.max_online_seconds > 0,
            Error::configuration("online policy requires a positive deadline")
        );
        ensure!(
            policy.revocation == PortableRevocationPolicy::Disabled
                || policy.revocation_max_age_seconds > 0,
            Error::configuration("revocation freshness age must be positive")
        );
        ensure!(
            policy.revocation != PortableRevocationPolicy::Online || cfg!(feature = "online"),
            Error::configuration("online policy requires the wintrust online feature")
        );
        ensure!(
            policy.schema_version == 1,
            Error::configuration("unsupported portable trust policy version")
        );
        ensure!(
            !policy.roots.is_empty(),
            Error::configuration("portable verification requires explicit trust anchors")
        );
        validate_tsa_compatibility_policy(&policy)?;
        let count = [
            &policy.roots,
            &policy.intermediates,
            &policy.crls,
            &policy.ocsp_responses,
        ]
        .iter()
        .try_fold(0usize, |sum, files| {
            sum.checked_add(files.len())
                .ok_or_else(|| Error::resource_limit("artifact count overflow"))
        })?;
        ensure!(
            count <= limits.max_artifacts,
            Error::resource_limit("portable trust artifact count exceeds limit")
        );
        let mut total = 0usize;
        let mut load = |files: &[ArtifactRef]| -> Result<Vec<Vec<u8>>> {
            files
                .iter()
                .map(|artifact| {
                    ensure!(
                        artifact.sha256.len() == 64
                            && artifact.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                        Error::configuration("invalid artifact SHA-256")
                    );
                    let bytes = reader(artifact, limits.max_artifact_bytes)?;
                    ensure!(
                        bytes.len() <= limits.max_artifact_bytes,
                        Error::resource_limit("trust artifact exceeds individual byte limit")
                    );
                    total = total
                        .checked_add(bytes.len())
                        .ok_or_else(|| Error::resource_limit("artifact size overflow"))?;
                    ensure!(
                        total <= limits.max_total_artifact_bytes,
                        Error::resource_limit("portable trust artifacts exceed total byte limit")
                    );
                    ensure!(
                        hex::encode(Sha256::digest(&bytes)) == artifact.sha256.to_ascii_lowercase(),
                        Error::policy(alloc::format!(
                            "trust artifact SHA-256 mismatch: {}",
                            artifact.path
                        ))
                    );
                    Ok(bytes)
                })
                .collect()
        };
        let roots = load(&policy.roots)?;
        let intermediates = load(&policy.intermediates)?;
        let crls = load(&policy.crls)?;
        let ocsp_responses = load(&policy.ocsp_responses)?;
        for certificate in roots.iter().chain(&intermediates) {
            use der::Decode;
            x509_cert::Certificate::from_der(certificate)
                .map_err(Error::malformed)
                .context("invalid runtime certificate DER")?;
        }
        let evaluation_time = match policy.verification_time {
            Some(time) => time,
            #[cfg(feature = "std")]
            None => SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            #[cfg(not(feature = "std"))]
            None => {
                return Err(Error::configuration(
                    "no_std verification requires an explicit verification_time",
                ));
            }
        };
        policy.verification_time = Some(evaluation_time);
        let crl_labels = artifact_labels(&policy.crls);
        let ocsp_labels = artifact_labels(&policy.ocsp_responses);
        let pinned_provenance = revocation::pinned_provenance_labels(
            &crl_labels
                .iter()
                .map(String::as_str)
                .zip(crls.iter().map(Vec::as_slice))
                .collect::<Vec<_>>(),
            &ocsp_labels
                .iter()
                .map(String::as_str)
                .zip(ocsp_responses.iter().map(Vec::as_slice))
                .collect::<Vec<_>>(),
        )?;
        Ok(Self {
            policy,
            roots,
            intermediates,
            crls,
            ocsp_responses,
            limits,
            evaluation_time,
            pinned_provenance,
        })
    }
    /// The evaluation time captured when this verifier was constructed.
    pub fn evaluation_time(&self) -> u64 {
        self.evaluation_time
    }
}

fn validate_tsa_compatibility_policy(policy: &PortablePolicy) -> Result<()> {
    let pins = &policy.noncritical_tsa_certificate_sha256;
    ensure!(
        pins.len() <= 8,
        Error::configuration("Microsoft TSA compatibility pin limit exceeded")
    );
    ensure!(
        pins.is_empty() || policy.publisher == PublisherPolicy::MicrosoftWindows,
        Error::configuration(
            "noncritical TSA compatibility requires MicrosoftWindows publisher policy"
        )
    );
    let mut unique = alloc::collections::BTreeSet::new();
    for pin in pins {
        ensure!(
            pin.len() == 64
                && pin
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            Error::configuration("invalid lowercase Microsoft TSA certificate SHA-256")
        );
        ensure!(
            unique.insert(pin),
            Error::configuration("duplicate Microsoft TSA certificate SHA-256")
        );
    }
    Ok(())
}

const CODE_SIGNING_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
const WINDOWS_COMPONENT_EKU: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.3.6");
/// Full DER fingerprints of public roots acquired from Microsoft's PKI repository.
/// Matching a display name never authorizes the Microsoft publisher policy.
const MICROSOFT_ROOTS: &[&str] = &[
    "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e",
    "847df6a78497943f27fc72eb93f9a637320a02b561d0a91b09e87a7807ed7c61",
    "c741f70f4b2a8d88bf2e71c14122ef53ef10eba0cfa5e64cfa20f418853073e0",
];

#[derive(Debug, Serialize)]
pub struct PortableSignerReport {
    pub signer_certificate_sha256: String,
    pub signature_time: u64,
    pub chain: chain::ChainReport,
    pub timestamp: Option<timestamp::TimestampReport>,
    pub revocation: Option<revocation::RevocationReport>,
    pub timestamp_revocation: Option<revocation::RevocationReport>,
}

/// A successful policy decision with the exact bytes, roots and evaluation time.
/// This is explicit portable policy, not a claim of every Windows trust setting.
#[derive(Debug, Serialize)]
pub struct PortableTrustReport {
    pub backend: &'static str,
    pub catalog_sha256: String,
    pub member_sha256: String,
    pub member_kind: sip::SipKind,
    pub matching_catalog_members: Vec<usize>,
    pub verification_time: u64,
    pub publisher: PublisherPolicy,
    pub revocation_policy: PortableRevocationPolicy,
    pub timestamp_policy: TimestampPolicy,
    pub allow_sha1: bool,
    pub noncritical_tsa_certificate_sha256: Vec<String>,
    pub signers: Vec<PortableSignerReport>,
    pub microsoft_signer_verified: bool,
    pub revocation_checked: bool,
    pub trust_established: bool,
}

fn artifact_labels(refs: &[ArtifactRef]) -> Vec<String> {
    refs.iter().map(|artifact| artifact.path.clone()).collect()
}

#[cfg(feature = "online")]
type VerificationStart = Instant;
#[cfg(not(feature = "online"))]
type VerificationStart = ();

impl Verifier {
    /// Verify an explicit catalog/member pair entirely through portable Rust.
    #[cfg(feature = "std")]
    pub fn verify_catalog_member(
        &self,
        catalog_path: &Path,
        member_path: &Path,
        kind: sip::SipKind,
    ) -> Result<PortableTrustReport> {
        let catalog = read_bounded(
            catalog_path,
            crate::catalog::CatalogLimits::default().max_bytes,
        )?;
        let member = read_bounded(member_path, self.limits.max_member_bytes)?;
        let report = self.verify_bytes(&catalog, &member, kind)?;
        // Bind the decision to stable input bytes even if verification/network took time.
        ensure!(
            read_bounded(catalog_path, catalog.len())? == catalog,
            "catalog changed during verification"
        );
        ensure!(
            read_bounded(member_path, member.len())? == member,
            "member changed during verification"
        );
        Ok(report)
    }

    /// Verify catalog signatures, exact member binding, trusted chains and policy.
    pub fn verify_bytes(
        &self,
        catalog_bytes: &[u8],
        member_bytes: &[u8],
        kind: sip::SipKind,
    ) -> Result<PortableTrustReport> {
        #[cfg(feature = "online")]
        let started = Instant::now();
        #[cfg(not(feature = "online"))]
        let started = ();
        let catalog = crate::catalog::parse(catalog_bytes, Default::default())?;
        let signed = signed::verify_signed_data(
            catalog_bytes,
            &signed::SignedDataOptions {
                crypto: crypto::CryptoOptions {
                    allow_sha1: self.policy.allow_sha1,
                },
                ..signed::SignedDataOptions::new(ObjectIdentifier::new_unwrap(
                    "1.3.6.1.4.1.311.10.1",
                ))
            },
        )
        .context("catalog signature verification")?;
        ensure!(
            hex::encode(signed.content_der) == catalog.ctl.encoded_hex,
            "signed CTL differs from inspected CTL"
        );
        let matches = sip::match_catalog_member(
            &catalog,
            member_bytes,
            kind,
            &sip::MemberHashPolicy {
                allow_sha1: self.policy.allow_sha1,
                max_member_bytes: self.limits.max_member_bytes,
            },
        )?;
        ensure!(
            !matches.is_empty(),
            "member digest is not bound to the signed catalog"
        );
        let now = self.evaluation_time();
        let certificates = signed
            .certificates
            .iter()
            .chain(&self.intermediates)
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let mut reports = Vec::new();
        for signer in signed.signers {
            let mut timestamp_revocation = None;
            let timestamp = if self.policy.timestamp == TimestampPolicy::Ignore {
                None
            } else {
                let options = timestamp::TimestampOptions {
                    issuer_candidates: (&certificates).into(),
                    crypto: crypto::CryptoOptions {
                        allow_sha1: self.policy.allow_sha1,
                    },
                    noncritical_tsa_certificate_sha256: &self
                        .policy
                        .noncritical_tsa_certificate_sha256,
                    ..timestamp::TimestampOptions::new((&self.roots).into(), now)
                };
                timestamp::verify_timestamps_with_path_policy(
                    &signer,
                    &options,
                    |candidate, time| {
                        if self.policy.publisher == PublisherPolicy::MicrosoftWindows {
                            ensure!(
                                MICROSOFT_ROOTS.contains(&candidate.anchor_sha256.as_str()),
                                "timestamp does not chain to an authorized Microsoft root"
                            );
                        }
                        let status =
                            self.check_revocation(&candidate.chain_der, time, now, started)?;
                        timestamp_revocation = status;
                        Ok(())
                    },
                )
                .context("catalog timestamp verification")?
            };
            ensure!(
                self.policy.timestamp != TimestampPolicy::Require || timestamp.is_some(),
                "portable policy requires an authenticated timestamp"
            );
            let signature_time = timestamp.as_ref().map_or(now, |stamp| stamp.unix_time);
            let mut revocation = None;
            let chain_options = chain::ChainOptions {
                candidates: (&certificates).into(),
                allow_sha1: self.policy.allow_sha1,
                ..chain::ChainOptions::new(&self.roots, signature_time, CODE_SIGNING_EKU)
            };
            let path = chain::validate_with_path_policy(
                &signer.certificate_der,
                &chain_options,
                |candidate| {
                    if self.policy.publisher == PublisherPolicy::MicrosoftWindows {
                        ensure!(
                            MICROSOFT_ROOTS.contains(&candidate.anchor_sha256.as_str()),
                            "signer does not chain to an authorized Microsoft root"
                        );
                        chain::validate_report_constraints(
                            candidate,
                            signature_time,
                            WINDOWS_COMPONENT_EKU,
                        )
                        .context("Windows component publisher EKU policy")?;
                    }
                    if let Some(stamp) = &timestamp {
                        for bound in [
                            stamp
                                .unix_time
                                .checked_sub(stamp.accuracy_seconds)
                                .context("timestamp accuracy underflow")?,
                            stamp
                                .unix_time
                                .checked_add(stamp.accuracy_seconds)
                                .context("timestamp accuracy overflow")?,
                        ] {
                            chain::validate_report_constraints(candidate, bound, CODE_SIGNING_EKU)?;
                        }
                    }
                    revocation =
                        self.check_revocation(&candidate.chain_der, signature_time, now, started)?;
                    Ok(())
                },
            )
            .context("catalog signer chain verification")?;
            reports.push(PortableSignerReport {
                signer_certificate_sha256: hex::encode(Sha256::digest(&signer.certificate_der)),
                signature_time,
                chain: path,
                timestamp,
                revocation,
                timestamp_revocation,
            });
        }
        ensure!(!reports.is_empty(), "catalog has no verified signers");
        Ok(PortableTrustReport {
            backend: "rust_catalog_policy",
            catalog_sha256: hex::encode(Sha256::digest(catalog_bytes)),
            member_sha256: hex::encode(Sha256::digest(member_bytes)),
            member_kind: kind,
            matching_catalog_members: matches,
            verification_time: now,
            publisher: self.policy.publisher,
            revocation_policy: self.policy.revocation,
            timestamp_policy: self.policy.timestamp,
            allow_sha1: self.policy.allow_sha1,
            noncritical_tsa_certificate_sha256: self
                .policy
                .noncritical_tsa_certificate_sha256
                .clone(),
            signers: reports,
            microsoft_signer_verified: self.policy.publisher == PublisherPolicy::MicrosoftWindows,
            revocation_checked: self.policy.revocation != PortableRevocationPolicy::Disabled,
            trust_established: true,
        })
    }

    fn check_revocation(
        &self,
        path: &[Vec<u8>],
        signature_time: u64,
        now: u64,
        _started: VerificationStart,
    ) -> Result<Option<revocation::RevocationReport>> {
        if self.policy.revocation == PortableRevocationPolicy::Disabled {
            return Ok(None);
        }
        let limits = revocation::RevocationLimits {
            allow_sha1: self.policy.allow_sha1,
            max_age_seconds: self.policy.revocation_max_age_seconds,
            ..Default::default()
        };
        #[cfg(feature = "online")]
        let mut acquired = revocation::AcquiredRevocation::default();
        #[cfg(not(feature = "online"))]
        let acquired = revocation::AcquiredRevocation::default();
        #[cfg(feature = "online")]
        let mut provenance = self.pinned_provenance.clone();
        #[cfg(not(feature = "online"))]
        let provenance = self.pinned_provenance.clone();
        #[cfg(feature = "online")]
        if self.policy.revocation == PortableRevocationPolicy::Online {
            let remaining = self
                .limits
                .max_online_seconds
                .checked_sub(_started.elapsed().as_secs())
                .filter(|seconds| *seconds > 0)
                .ok_or_else(|| {
                    Error::resource_limit("portable online verification deadline exceeded")
                })?;
            acquired = revocation::acquire_chain_revocation(
                path.into(),
                &revocation::AcquisitionOptions {
                    crl_signers: (&self.intermediates).into(),
                    limits,
                    online_limits: revocation::OnlineLimits {
                        timeout_seconds: remaining.min(30),
                        ..Default::default()
                    },
                    ..revocation::AcquisitionOptions::new(now)
                },
            )?;
            provenance.append(&mut acquired.provenance);
        }
        let crls = self
            .crls
            .iter()
            .chain(&acquired.crls)
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let ocsp = self
            .ocsp_responses
            .iter()
            .chain(&acquired.ocsp_responses)
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let mut report = revocation::verify_chain_revocation(
            path.into(),
            &revocation::RevocationOptions {
                crls: (&crls).into(),
                ocsp: (&ocsp).into(),
                crl_signers: (&self.intermediates).into(),
                limits,
                ..revocation::RevocationOptions::new(signature_time, now)
            },
        )?;
        report.provenance = provenance;
        if let Some(certificate) = report.certificates.first_mut() {
            certificate.diagnostics.extend(acquired.diagnostics);
        }
        ensure!(
            report.status == revocation::RevocationStatus::Good,
            "certificate revocation status is {:?}; fresh authenticated evidence is required",
            report.status
        );
        Ok(Some(report))
    }
}

#[cfg(all(test, feature = "std"))]
mod reader_tests {
    use super::*;

    #[test]
    fn injected_artifact_reader_cannot_bypass_pins_or_budgets() -> Result<()> {
        let bytes = include_bytes!("../../../tests/fixtures/root.der").to_vec();
        let policy = PortablePolicy {
            schema_version: 1,
            roots: vec![ArtifactRef {
                path: "root.der".into(),
                sha256: hex::encode(Sha256::digest(&bytes)),
            }],
            intermediates: vec![],
            crls: vec![],
            ocsp_responses: vec![],
            publisher: PublisherPolicy::MicrosoftWindows,
            revocation: PortableRevocationPolicy::Disabled,
            timestamp: TimestampPolicy::Require,
            verification_time: Some(1),
            allow_sha1: false,
            noncritical_tsa_certificate_sha256: vec![],
            revocation_max_age_seconds: default_revocation_age(),
        };
        let base = Path::new("source");
        let verified = Verifier::from_policy_with_reader(
            policy.clone(),
            base,
            PortableLimits::default(),
            |path, limit| {
                ensure!(path == base.join("root.der") && limit >= bytes.len());
                Ok(bytes.clone())
            },
        )?;
        assert_eq!(verified.roots, vec![bytes.clone()]);
        assert!(
            Verifier::from_policy_with_reader(
                policy.clone(),
                base,
                PortableLimits::default(),
                |_, _| Ok(vec![9]),
            )
            .is_err()
        );
        for limits in [
            PortableLimits {
                max_artifact_bytes: 2,
                ..PortableLimits::default()
            },
            PortableLimits {
                max_total_artifact_bytes: 2,
                ..PortableLimits::default()
            },
            PortableLimits {
                max_artifacts: 0,
                ..PortableLimits::default()
            },
        ] {
            assert!(
                Verifier::from_policy_with_reader(policy.clone(), base, limits, |_, _| Ok(
                    bytes.clone()
                ),)
                .is_err()
            );
        }
        Ok(())
    }
}
