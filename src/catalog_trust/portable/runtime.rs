//! Immutable runtime configuration constructed from the versioned wire policy.
use super::*;
use der::Decode;

/// A pinned verifier whose policy and evidence cannot change after validation.
///
/// ```compile_fail
/// # use wintrust::catalog_trust::portable::ValidatedVerifier;
/// fn change(verifier: &mut ValidatedVerifier) {
///     verifier.policy.revocation = todo!();
/// }
/// ```
#[derive(Debug)]
pub struct ValidatedVerifier {
    inner: PortableVerifier,
}

/// Fallible configuration builder. Artifact paths resolve against `base`.
#[derive(Debug)]
pub struct VerifierBuilder {
    policy: PortablePolicy,
    base: PathBuf,
    limits: PortableLimits,
}

impl VerifierBuilder {
    pub fn new(policy: PortablePolicy, base: impl Into<PathBuf>) -> Self {
        Self {
            policy,
            base: base.into(),
            limits: PortableLimits::default(),
        }
    }

    pub fn limits(mut self, limits: PortableLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn build(self) -> Result<ValidatedVerifier> {
        self.build_with_reader(read_bounded)
    }

    /// The common loader enforces pins and budgets even for custom readers.
    pub fn build_with_reader(
        mut self,
        reader: impl FnMut(&Path, usize) -> Result<Vec<u8>>,
    ) -> Result<ValidatedVerifier> {
        ensure!(
            self.limits.max_policy_bytes > 0
                && self.limits.max_artifact_bytes > 0
                && self.limits.max_artifacts > 0
                && self.limits.max_total_artifact_bytes > 0
                && self.limits.max_member_bytes > 0,
            "runtime byte and count limits must be positive"
        );
        ensure!(
            self.policy.revocation != PortableRevocationPolicy::Online || cfg!(feature = "online"),
            "online policy requires the wintrust online feature"
        );
        ensure!(
            self.policy.revocation != PortableRevocationPolicy::Online
                || self.limits.max_online_seconds > 0,
            "online policy requires a positive deadline"
        );
        ensure!(
            self.policy.revocation == PortableRevocationPolicy::Disabled
                || self.policy.revocation_max_age_seconds > 0,
            "revocation freshness age must be positive"
        );
        if self.policy.verification_time.is_none() {
            self.policy.verification_time =
                Some(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
        }
        let inner = PortableVerifier::from_policy_with_reader(
            self.policy,
            &self.base,
            self.limits,
            reader,
        )?;
        for certificate in inner.roots.iter().chain(&inner.intermediates) {
            x509_cert::Certificate::from_der(certificate)
                .context("invalid runtime certificate DER")?;
        }
        Ok(ValidatedVerifier { inner })
    }
}

impl ValidatedVerifier {
    pub fn builder(policy: PortablePolicy, base: impl Into<PathBuf>) -> VerifierBuilder {
        VerifierBuilder::new(policy, base)
    }

    pub fn load(path: &Path, limits: PortableLimits) -> Result<Self> {
        let bytes = read_bounded(path, limits.max_policy_bytes)?;
        Self::builder(
            serde_json::from_slice(&bytes)?,
            path.parent().unwrap_or(Path::new(".")),
        )
        .limits(limits)
        .build()
    }

    pub fn policy(&self) -> &PortablePolicy {
        &self.inner.policy
    }
    pub fn limits(&self) -> &PortableLimits {
        &self.inner.limits
    }
    pub fn roots(&self) -> &[Vec<u8>] {
        &self.inner.roots
    }
    pub fn intermediates(&self) -> &[Vec<u8>] {
        &self.inner.intermediates
    }
    pub fn crls(&self) -> &[Vec<u8>] {
        &self.inner.crls
    }
    pub fn ocsp_responses(&self) -> &[Vec<u8>] {
        &self.inner.ocsp_responses
    }

    pub fn verify_bytes(
        &self,
        catalog: &[u8],
        member: &[u8],
        kind: sip::SipKind,
    ) -> Result<PortableTrustReport> {
        self.inner.verify_bytes(catalog, member, kind)
    }

    pub fn verify_catalog_member(
        &self,
        catalog: &Path,
        member: &Path,
        kind: sip::SipKind,
    ) -> Result<PortableTrustReport> {
        self.inner.verify_catalog_member(catalog, member, kind)
    }
}
