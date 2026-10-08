//! RFC 5280 section 6.1 certificate policy processing over an already
//! signature-verified path. The path is supplied from the first certificate
//! below the trust anchor to the end-entity certificate.
//!
//! Qualifiers are parsed for syntax by the certificate decoder but never
//! influence a decision, and no qualifier set is retained or reported.
use anyhow::{Context, Result, bail, ensure};
use der::asn1::ObjectIdentifier;
use x509_cert::{
    Certificate,
    ext::pkix::{CertificatePolicies, InhibitAnyPolicy, PolicyConstraints, PolicyMappings},
};

/// The special `anyPolicy` identifier.
pub const ANY_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32.0");
const MAX_NODES: usize = 4096;

/// RFC 5280 6.1.1 user inputs. The default is `any-policy` with no explicit
/// policy requirement and no inhibition, which still honors every constraint
/// that the certificates themselves carry.
#[derive(Debug, Clone, Default)]
pub struct PolicyOptions {
    /// `user-initial-policy-set`; `None` is `any-policy`.
    pub initial_policy_set: Option<Vec<ObjectIdentifier>>,
    /// `initial-explicit-policy`.
    pub initial_explicit_policy: bool,
    /// `initial-policy-mapping-inhibit`.
    pub initial_policy_mapping_inhibit: bool,
    /// `initial-any-policy-inhibit`.
    pub initial_any_policy_inhibit: bool,
}

/// Result of successful policy processing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyOutcome {
    /// Distinct `valid_policy` values at the end-entity level of the final
    /// tree, sorted. Empty when the tree is NULL.
    pub valid_policies: Vec<ObjectIdentifier>,
    /// Whether the final tree was NULL (permitted only without an explicit
    /// policy requirement).
    pub tree_is_null: bool,
}

#[derive(Debug, Clone)]
struct Node {
    policy: ObjectIdentifier,
    expected: Vec<ObjectIdentifier>,
    parent: Option<usize>,
    depth: usize,
    alive: bool,
}

#[derive(Debug)]
struct Tree {
    nodes: Vec<Node>,
}

impl Tree {
    fn new() -> Self {
        Self {
            nodes: vec![Node {
                policy: ANY_POLICY,
                expected: vec![ANY_POLICY],
                parent: None,
                depth: 0,
                alive: true,
            }],
        }
    }

    fn is_null(&self) -> bool {
        !self.nodes.iter().any(|node| node.alive)
    }

    fn nullify(&mut self) {
        self.nodes.iter_mut().for_each(|node| node.alive = false);
    }

    fn at_depth(&self, depth: usize) -> Vec<usize> {
        (0..self.nodes.len())
            .filter(|&i| self.nodes[i].alive && self.nodes[i].depth == depth)
            .collect()
    }

    fn add(
        &mut self,
        parent: usize,
        policy: ObjectIdentifier,
        expected: Vec<ObjectIdentifier>,
    ) -> Result<()> {
        ensure!(self.nodes.len() < MAX_NODES, "policy tree node limit");
        let depth = self.nodes[parent].depth + 1;
        self.nodes.push(Node {
            policy,
            expected,
            parent: Some(parent),
            depth,
            alive: true,
        });
        Ok(())
    }

    fn has_child(&self, parent: usize, policy: ObjectIdentifier) -> bool {
        self.nodes
            .iter()
            .any(|n| n.alive && n.parent == Some(parent) && n.policy == policy)
    }

    /// Delete a node together with all descendants.
    fn delete_subtree(&mut self, root: usize) {
        self.nodes[root].alive = false;
        // Children are always appended after their parents.
        for i in root + 1..self.nodes.len() {
            if let Some(parent) = self.nodes[i].parent
                && !self.nodes[parent].alive
            {
                self.nodes[i].alive = false;
            }
        }
    }

    /// Repeatedly delete nodes of depth `<= limit` that have no children.
    fn prune(&mut self, limit: usize) {
        loop {
            let mut children = vec![0usize; self.nodes.len()];
            for node in self.nodes.iter().filter(|n| n.alive) {
                if let Some(parent) = node.parent {
                    children[parent] += 1;
                }
            }
            let mut changed = false;
            for (i, node) in self.nodes.iter_mut().enumerate() {
                if node.alive && node.depth <= limit && children[i] == 0 {
                    node.alive = false;
                    changed = true;
                }
            }
            if !changed {
                return;
            }
        }
    }

    /// RFC 5280 6.1.3 (d)(1)-(3) for the certificate at depth `i`.
    fn process_certificate_policies(
        &mut self,
        i: usize,
        policies: &[ObjectIdentifier],
        any_policy_expands: bool,
    ) -> Result<()> {
        let previous = self.at_depth(i - 1);
        for &policy in policies.iter().filter(|p| **p != ANY_POLICY) {
            let mut matched = false;
            for &parent in &previous {
                if self.nodes[parent].expected.contains(&policy) {
                    self.add(parent, policy, vec![policy])?;
                    matched = true;
                }
            }
            if !matched
                && let Some(&any) = previous
                    .iter()
                    .find(|&&p| self.nodes[p].policy == ANY_POLICY)
            {
                self.add(any, policy, vec![policy])?;
            }
        }
        if policies.contains(&ANY_POLICY) && any_policy_expands {
            for &parent in &previous {
                for value in self.nodes[parent].expected.clone() {
                    if !self.has_child(parent, value) {
                        self.add(parent, value, vec![value])?;
                    }
                }
            }
        }
        self.prune(i - 1);
        Ok(())
    }

    /// RFC 5280 6.1.4 (b) for the CA certificate at depth `i`.
    fn apply_mappings(
        &mut self,
        i: usize,
        mappings: &[(ObjectIdentifier, Vec<ObjectIdentifier>)],
        mapping_allowed: bool,
    ) -> Result<()> {
        for (issuer, subjects) in mappings {
            let matching = self
                .at_depth(i)
                .into_iter()
                .filter(|&n| self.nodes[n].policy == *issuer)
                .collect::<Vec<_>>();
            if mapping_allowed {
                if matching.is_empty() {
                    if let Some(any) = self
                        .at_depth(i)
                        .into_iter()
                        .find(|&n| self.nodes[n].policy == ANY_POLICY)
                    {
                        let parent = self.nodes[any]
                            .parent
                            .context("anyPolicy node below the root has a parent")?;
                        self.add(parent, *issuer, subjects.clone())?;
                    }
                } else {
                    for node in matching {
                        self.nodes[node].expected = subjects.clone();
                    }
                }
            } else {
                for node in matching {
                    self.delete_subtree(node);
                }
                self.prune(i - 1);
            }
        }
        Ok(())
    }

    /// RFC 5280 6.1.5 (g): intersect with `user-initial-policy-set`.
    fn intersect(&mut self, n: usize, initial: &[ObjectIdentifier]) -> Result<()> {
        if self.is_null() {
            return Ok(());
        }
        let under_any = |tree: &Tree| {
            (0..tree.nodes.len())
                .filter(|&i| {
                    tree.nodes[i].alive
                        && tree.nodes[i].parent.is_some_and(|p| {
                            tree.nodes[p].alive && tree.nodes[p].policy == ANY_POLICY
                        })
                })
                .collect::<Vec<_>>()
        };
        for node in under_any(self) {
            if self.nodes[node].alive
                && self.nodes[node].policy != ANY_POLICY
                && !initial.contains(&self.nodes[node].policy)
            {
                self.delete_subtree(node);
            }
        }
        if let Some(any) = self
            .at_depth(n)
            .into_iter()
            .find(|&i| self.nodes[i].policy == ANY_POLICY)
        {
            let present = under_any(self)
                .into_iter()
                .map(|i| self.nodes[i].policy)
                .collect::<Vec<_>>();
            let parent = self.nodes[any].parent;
            if let Some(parent) = parent {
                for &policy in initial.iter().filter(|p| !present.contains(p)) {
                    self.add(parent, policy, vec![policy])?;
                }
            }
            self.nodes[any].alive = false;
        }
        self.prune(n.saturating_sub(1));
        Ok(())
    }
}

fn certificate_policies(cert: &Certificate) -> Result<Option<Vec<ObjectIdentifier>>> {
    let Some((_, policies)) = cert.tbs_certificate.get::<CertificatePolicies>()? else {
        return Ok(None);
    };
    ensure!(
        !policies.0.is_empty() && policies.0.len() <= 256,
        "certificate policies count"
    );
    let mut seen = std::collections::HashSet::new();
    for information in &policies.0 {
        ensure!(
            seen.insert(information.policy_identifier),
            "duplicate certificate policy identifier"
        );
    }
    Ok(Some(
        policies.0.iter().map(|p| p.policy_identifier).collect(),
    ))
}

fn policy_constraints(cert: &Certificate) -> Result<Option<PolicyConstraints>> {
    let Some((_, constraints)) = cert.tbs_certificate.get::<PolicyConstraints>()? else {
        return Ok(None);
    };
    ensure!(
        constraints.require_explicit_policy.is_some()
            || constraints.inhibit_policy_mapping.is_some(),
        "empty policy constraints"
    );
    Ok(Some(constraints))
}

fn policy_mappings(cert: &Certificate) -> Result<Vec<(ObjectIdentifier, Vec<ObjectIdentifier>)>> {
    let Some((_, mappings)) = cert.tbs_certificate.get::<PolicyMappings>()? else {
        return Ok(Vec::new());
    };
    ensure!(
        !mappings.0.is_empty() && mappings.0.len() <= 256,
        "policy mappings count"
    );
    let mut grouped: Vec<(ObjectIdentifier, Vec<ObjectIdentifier>)> = Vec::new();
    for mapping in &mappings.0 {
        if mapping.issuer_domain_policy == ANY_POLICY || mapping.subject_domain_policy == ANY_POLICY
        {
            bail!("policy mapping involves anyPolicy");
        }
        match grouped
            .iter_mut()
            .find(|(issuer, _)| *issuer == mapping.issuer_domain_policy)
        {
            Some((_, subjects)) => {
                if !subjects.contains(&mapping.subject_domain_policy) {
                    subjects.push(mapping.subject_domain_policy);
                }
            }
            None => grouped.push((
                mapping.issuer_domain_policy,
                vec![mapping.subject_domain_policy],
            )),
        }
    }
    Ok(grouped)
}

fn inhibit_any_policy(cert: &Certificate) -> Result<Option<u64>> {
    Ok(cert
        .tbs_certificate
        .get::<InhibitAnyPolicy>()?
        .map(|(_, value)| u64::from(value.0)))
}

fn self_issued(cert: &Certificate) -> bool {
    cert.tbs_certificate.subject == cert.tbs_certificate.issuer
}

/// Process RFC 5280 6.1 policy semantics for `path` (CA below the anchor first,
/// end entity last). `anchor` contributes only its explicit policy-constraint
/// and inhibit-anyPolicy values, as trust-anchor constraints; its own policies
/// and mappings are not processed.
pub fn process(
    path: &[&Certificate],
    anchor: Option<&Certificate>,
    options: &PolicyOptions,
) -> Result<PolicyOutcome> {
    let n = path.len();
    ensure!(n > 0, "policy processing requires at least one certificate");
    ensure!(n < 1024, "policy path length");
    let n64 = n as u64;
    let mut tree = Tree::new();
    let mut explicit = if options.initial_explicit_policy {
        0
    } else {
        n64 + 1
    };
    let mut mapping = if options.initial_policy_mapping_inhibit {
        0
    } else {
        n64 + 1
    };
    let mut inhibit_any = if options.initial_any_policy_inhibit {
        0
    } else {
        n64 + 1
    };
    if let Some(anchor) = anchor {
        if let Some(constraints) = policy_constraints(anchor)? {
            if let Some(v) = constraints.require_explicit_policy {
                explicit = explicit.min(u64::from(v));
            }
            if let Some(v) = constraints.inhibit_policy_mapping {
                mapping = mapping.min(u64::from(v));
            }
        }
        if let Some(v) = inhibit_any_policy(anchor)? {
            inhibit_any = inhibit_any.min(v);
        }
    }
    for (index, cert) in path.iter().enumerate() {
        let i = index + 1;
        let leaf = i == n;
        let issued_to_self = self_issued(cert);
        match certificate_policies(cert)? {
            Some(policies) => {
                if !tree.is_null() {
                    let expands = inhibit_any > 0 || (!leaf && issued_to_self);
                    tree.process_certificate_policies(i, &policies, expands)?;
                }
            }
            None => tree.nullify(),
        }
        ensure!(
            explicit > 0 || !tree.is_null(),
            "certificate policy requirements are not satisfied at depth {i}"
        );
        let constraints = policy_constraints(cert)?;
        if leaf {
            explicit = explicit.saturating_sub(1);
            if constraints
                .as_ref()
                .is_some_and(|c| c.require_explicit_policy == Some(0))
            {
                explicit = 0;
            }
            break;
        }
        let mappings = policy_mappings(cert)?;
        if !mappings.is_empty() {
            tree.apply_mappings(i, &mappings, mapping > 0)?;
        }
        if !issued_to_self {
            explicit = explicit.saturating_sub(1);
            mapping = mapping.saturating_sub(1);
            inhibit_any = inhibit_any.saturating_sub(1);
        }
        if let Some(constraints) = constraints {
            if let Some(v) = constraints.require_explicit_policy {
                explicit = explicit.min(u64::from(v));
            }
            if let Some(v) = constraints.inhibit_policy_mapping {
                mapping = mapping.min(u64::from(v));
            }
        }
        if let Some(v) = inhibit_any_policy(cert)? {
            inhibit_any = inhibit_any.min(v);
        }
    }
    if let Some(initial) = &options.initial_policy_set
        && !initial.contains(&ANY_POLICY)
    {
        tree.intersect(n, initial)?;
    }
    ensure!(
        explicit > 0 || !tree.is_null(),
        "no valid certificate policy satisfies the explicit policy requirement"
    );
    let mut valid_policies = tree
        .at_depth(n)
        .into_iter()
        .map(|i| tree.nodes[i].policy)
        .collect::<Vec<_>>();
    valid_policies.sort();
    valid_policies.dedup();
    Ok(PolicyOutcome {
        valid_policies,
        tree_is_null: tree.is_null(),
    })
}
