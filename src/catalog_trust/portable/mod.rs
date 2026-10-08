//! Portable catalog verification using explicit trust inputs and Rust cryptography.
//!
//! This policy is reproducible without inheriting a host Windows trust store.
pub mod chain;
pub mod crypto;
pub mod revocation;
mod runtime;
pub use runtime::{ValidatedVerifier, VerifierBuilder};
pub mod signed;
pub mod sip;
pub mod timestamp;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

/// Explicit artifact binding; relative paths resolve beside the policy file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    pub path: PathBuf,
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
    /// A reproducible evaluation time; absence uses the current Unix time.
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

/// Legacy mutable verifier retained for source compatibility.
/// Prefer [`ValidatedVerifier`] for immutable, validated runtime configuration.
/// Loaded pinned inputs; construction validates all fingerprints and limits.
#[derive(Debug)]
pub struct PortableVerifier {
    pub policy: PortablePolicy,
    pub roots: Vec<Vec<u8>>,
    pub intermediates: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
    pub ocsp_responses: Vec<Vec<u8>>,
    pub limits: PortableLimits,
}

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
        "input exceeds portable verification byte limit"
    );
    Ok(bytes)
}

impl PortableVerifier {
    /// Load a policy plus hash-pinned DER roots, intermediates and status evidence.
    pub fn load(policy_path: &Path, limits: PortableLimits) -> Result<Self> {
        let bytes = read_bounded(policy_path, limits.max_policy_bytes)?;
        let policy: PortablePolicy = serde_json::from_slice(&bytes)?;
        Self::from_policy(
            policy,
            policy_path.parent().unwrap_or(Path::new(".")),
            limits,
        )
    }
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
    pub fn from_policy_with_reader(
        policy: PortablePolicy,
        base: &Path,
        limits: PortableLimits,
        mut reader: impl FnMut(&Path, usize) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        ensure!(
            policy.revocation != PortableRevocationPolicy::Online || cfg!(feature = "online"),
            "online policy requires the wintrust online feature"
        );
        ensure!(
            policy.schema_version == 1,
            "unsupported portable trust policy version"
        );
        ensure!(
            !policy.roots.is_empty(),
            "portable verification requires explicit trust anchors"
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
                .context("artifact count overflow")
        })?;
        ensure!(
            count <= limits.max_artifacts,
            "portable trust artifact count exceeds limit"
        );
        let mut total = 0usize;
        let mut load = |files: &[ArtifactRef]| -> Result<Vec<Vec<u8>>> {
            files
                .iter()
                .map(|artifact| {
                    ensure!(
                        artifact.sha256.len() == 64
                            && artifact.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                        "invalid artifact SHA-256"
                    );
                    let bytes = reader(&base.join(&artifact.path), limits.max_artifact_bytes)?;
                    ensure!(
                        bytes.len() <= limits.max_artifact_bytes,
                        "trust artifact exceeds individual byte limit"
                    );
                    total = total
                        .checked_add(bytes.len())
                        .context("artifact size overflow")?;
                    ensure!(
                        total <= limits.max_total_artifact_bytes,
                        "portable trust artifacts exceed total byte limit"
                    );
                    ensure!(
                        hex::encode(Sha256::digest(&bytes)) == artifact.sha256.to_ascii_lowercase(),
                        "trust artifact SHA-256 mismatch: {}",
                        artifact.path.display()
                    );
                    Ok(bytes)
                })
                .collect()
        };
        let roots = load(&policy.roots)?;
        let intermediates = load(&policy.intermediates)?;
        let crls = load(&policy.crls)?;
        let ocsp_responses = load(&policy.ocsp_responses)?;
        Ok(Self {
            policy,
            roots,
            intermediates,
            crls,
            ocsp_responses,
            limits,
        })
    }
    pub fn evaluation_time(&self) -> Result<u64> {
        self.policy
            .verification_time
            .map(Ok)
            .unwrap_or_else(|| Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()))
    }
}

fn validate_tsa_compatibility_policy(policy: &PortablePolicy) -> Result<()> {
    let pins = &policy.noncritical_tsa_certificate_sha256;
    ensure!(
        pins.len() <= 8,
        "Microsoft TSA compatibility pin limit exceeded"
    );
    ensure!(
        pins.is_empty() || policy.publisher == PublisherPolicy::MicrosoftWindows,
        "noncritical TSA compatibility requires MicrosoftWindows publisher policy"
    );
    let mut unique = std::collections::BTreeSet::new();
    for pin in pins {
        ensure!(
            pin.len() == 64
                && pin
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid lowercase Microsoft TSA certificate SHA-256"
        );
        ensure!(
            unique.insert(pin),
            "duplicate Microsoft TSA certificate SHA-256"
        );
    }
    Ok(())
}

const CODE_SIGNING_EKU: &str = "1.3.6.1.5.5.7.3.3";
const WINDOWS_COMPONENT_EKU: &str = "1.3.6.1.4.1.311.10.3.6";
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

impl PortableVerifier {
    /// Verify an explicit catalog/member pair entirely through portable Rust.
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
        validate_tsa_compatibility_policy(&self.policy)?;
        let started = Instant::now();
        let catalog = crate::catalog::parse(catalog_bytes, Default::default())?;
        let signed = signed::verify_signed_data_with_policy(
            catalog_bytes,
            "1.3.6.1.4.1.311.10.1",
            self.policy.allow_sha1,
        )
        .context("catalog signature verification")?;
        ensure!(
            hex::encode(&signed.content_der) == catalog.ctl.encoded_hex,
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
        let now = self.evaluation_time()?;
        let mut certificates = signed.certificates;
        certificates.extend(self.intermediates.iter().cloned());
        let mut reports = Vec::new();
        for signer in signed.signers {
            let timestamp = if self.policy.timestamp == TimestampPolicy::Ignore {
                None
            } else {
                timestamp::verify_timestamps_with_compatibility(
                    &signer,
                    &certificates,
                    &self.roots,
                    now,
                    self.policy.allow_sha1,
                    &self.policy.noncritical_tsa_certificate_sha256,
                )
                .context("catalog timestamp verification")?
            };
            ensure!(
                self.policy.timestamp != TimestampPolicy::Require || timestamp.is_some(),
                "portable policy requires an authenticated timestamp"
            );
            let signature_time = timestamp.as_ref().map_or(now, |stamp| stamp.unix_time);
            let mut revocation = None;
            let path = chain::validate_with_path_policy(
                &signer.certificate_der,
                &certificates,
                &self.roots,
                signature_time,
                CODE_SIGNING_EKU,
                self.policy.allow_sha1,
                chain::PathLimits::default(),
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
            if self.policy.publisher == PublisherPolicy::MicrosoftWindows
                && let Some(stamp) = &timestamp
            {
                ensure!(
                    MICROSOFT_ROOTS.contains(&stamp.tsa_anchor_sha256.as_str()),
                    "timestamp does not chain to an authorized Microsoft root"
                );
            }
            let timestamp_revocation = timestamp
                .as_ref()
                .map(|stamp| self.check_revocation(&stamp.chain_der, stamp.unix_time, now, started))
                .transpose()?
                .flatten();
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
        started: Instant,
    ) -> Result<Option<revocation::RevocationReport>> {
        if self.policy.revocation == PortableRevocationPolicy::Disabled {
            return Ok(None);
        }
        let limits = revocation::RevocationLimits {
            allow_sha1: self.policy.allow_sha1,
            max_age_seconds: self.policy.revocation_max_age_seconds,
            ..Default::default()
        };
        let mut crls = self.crls.clone();
        let mut ocsp = self.ocsp_responses.clone();
        let mut diagnostics = Vec::new();
        if self.policy.revocation == PortableRevocationPolicy::Online {
            let remaining = self
                .limits
                .max_online_seconds
                .checked_sub(started.elapsed().as_secs())
                .filter(|seconds| *seconds > 0)
                .context("portable online verification deadline exceeded")?;
            let acquired = revocation::acquire_chain_revocation(
                path,
                now,
                limits,
                revocation::OnlineLimits {
                    timeout_seconds: remaining.min(30),
                    ..Default::default()
                },
            )?;
            crls.extend(acquired.crls);
            ocsp.extend(acquired.ocsp_responses);
            diagnostics = acquired.diagnostics;
        }
        let mut report =
            revocation::verify_chain_revocation(path, &crls, &ocsp, signature_time, now, limits)?;
        if let Some(certificate) = report.certificates.first_mut() {
            certificate.diagnostics.extend(diagnostics);
        }
        ensure!(
            report.status == revocation::RevocationStatus::Good,
            "certificate revocation status is {:?}; fresh authenticated evidence is required",
            report.status
        );
        Ok(Some(report))
    }
}

#[cfg(test)]
mod reader_tests {
    use super::*;

    #[test]
    fn injected_artifact_reader_cannot_bypass_pins_or_budgets() -> Result<()> {
        let bytes = vec![1_u8, 2, 3];
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
        let verified = PortableVerifier::from_policy_with_reader(
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
            PortableVerifier::from_policy_with_reader(
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
                PortableVerifier::from_policy_with_reader(policy.clone(), base, limits, |_, _| Ok(
                    bytes.clone()
                ),)
                .is_err()
            );
        }
        Ok(())
    }
}
