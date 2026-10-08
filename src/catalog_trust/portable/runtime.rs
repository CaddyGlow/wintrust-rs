//! Fallible construction and read-only access to validated runtime configuration.
use super::*;

/// Fallible configuration builder. Artifact paths resolve against `base`.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct VerifierBuilder {
    policy: PortablePolicy,
    base: PathBuf,
    limits: PortableLimits,
}

#[cfg(feature = "std")]
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

    pub fn build(self) -> Result<Verifier> {
        self.build_with_reader(read_bounded)
    }

    /// Enforce artifact pins and budgets even for caller-supplied readers.
    pub fn build_with_reader(
        self,
        reader: impl FnMut(&Path, usize) -> Result<Vec<u8>>,
    ) -> Result<Verifier> {
        Verifier::from_policy_with_reader(self.policy, &self.base, self.limits, reader)
    }
}

impl Verifier {
    #[cfg(feature = "std")]
    pub fn builder(policy: PortablePolicy, base: impl Into<PathBuf>) -> VerifierBuilder {
        VerifierBuilder::new(policy, base)
    }
    pub fn policy(&self) -> &PortablePolicy {
        &self.policy
    }
    pub fn limits(&self) -> &PortableLimits {
        &self.limits
    }
    pub fn roots(&self) -> &[Vec<u8>] {
        &self.roots
    }
    pub fn intermediates(&self) -> &[Vec<u8>] {
        &self.intermediates
    }
    pub fn crls(&self) -> &[Vec<u8>] {
        &self.crls
    }
    pub fn ocsp_responses(&self) -> &[Vec<u8>] {
        &self.ocsp_responses
    }
}
