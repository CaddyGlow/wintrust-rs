//! Generic bounded CTL inspection. Parsing never authenticates a list or its entries.
use crate::catalog::{self, CatalogError, CatalogLimits, Node};
use alloc::{format, string::String, vec, vec::Vec};
use catalog::{bad, children, field, integer, node, preflight, tagged, time};
use der::asn1::ObjectIdentifier;

/// A borrowed trust-list entry with exact encoded attributes, including unknown OIDs.
#[derive(Debug)]
pub struct CtlEntry<'a> {
    pub subject_identifier: &'a [u8],
    pub attributes: Vec<CtlAttribute<'a>>,
    pub encoded: &'a [u8],
}

#[derive(Debug)]
pub struct CtlAttribute<'a> {
    pub oid: ObjectIdentifier,
    pub values: Vec<&'a [u8]>,
}

fn parse_attributes(n: Node<'_>) -> Result<Vec<CtlAttribute<'_>>, CatalogError> {
    children(tagged(n, 0x31)?)?
        .into_iter()
        .map(|attr| {
            let fields = children(tagged(attr, 0x30)?)?;
            if fields.len() != 2 {
                return Err(bad("invalid CTL attribute"));
            }
            let values = children(tagged(fields[1], 0x31)?)?;
            if values.is_empty() {
                return Err(bad("empty CTL attribute values"));
            }
            Ok(CtlAttribute {
                oid: crate::der::oid(fields[0])?,
                values: values.into_iter().map(|n| n.full).collect(),
            })
        })
        .collect()
}

/// Generic list metadata independent of catalog SIP member binding.
#[derive(Debug)]
pub struct ParsedCtl<'a> {
    pub version: u64,
    pub subject_usage: Vec<ObjectIdentifier>,
    pub list_identifier: Option<&'a [u8]>,
    pub sequence_number: Option<&'a [u8]>,
    pub this_update: String,
    pub next_update: Option<String>,
    pub subject_algorithm: ObjectIdentifier,
    pub entries: Vec<CtlEntry<'a>>,
    pub extensions: Option<&'a [u8]>,
    pub encoded: &'a [u8],
}

/// Dedicated CTL bootstrap policy. Embedded signer certificates are only issuer
/// candidates, and never implicitly become anchors.
pub struct CtlAuthenticationPolicy<'a> {
    pub bootstrap_anchors: crate::portable::CertificateStore<'a>,
    pub issuer_candidates: crate::portable::CertificateStore<'a>,
    pub required_signer_eku: ObjectIdentifier,
    pub required_list_usage: ObjectIdentifier,
    pub verification_time: u64,
    pub minimum_sequence: Option<&'a [u8]>,
    pub max_age_seconds: u64,
    pub allow_sha1: bool,
}

/// Exact authenticated list bytes and signer paths. Its private state cannot be
/// created from an inspection DTO or deserialized report.
#[derive(Debug)]
pub struct AuthenticatedCtl {
    encoded: Vec<u8>,
    signer_paths: Vec<crate::portable::chain::ChainReport>,
    limits: CatalogLimits,
}

impl AuthenticatedCtl {
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
    pub fn signer_paths(&self) -> &[crate::portable::chain::ChainReport] {
        &self.signer_paths
    }
    pub fn inspect(&self) -> Result<ParsedCtl<'_>, CatalogError> {
        parse(&self.encoded, self.limits)
    }
}

fn unix_time(value: &str) -> crate::error::Result<u64> {
    use der::Decode;
    let tag = match value.len() {
        13 => 0x17,
        15 => 0x18,
        _ => crate::error::bail!(crate::error::Error::malformed("invalid CTL time length")),
    };
    let mut encoded = vec![tag, value.len() as u8];
    encoded.extend_from_slice(value.as_bytes());
    Ok(if tag == 0x17 {
        der::asn1::UtcTime::from_der(&encoded)
            .map_err(crate::error::Error::malformed)?
            .to_unix_duration()
            .as_secs()
    } else {
        der::asn1::GeneralizedTime::from_der(&encoded)
            .map_err(crate::error::Error::malformed)?
            .to_unix_duration()
            .as_secs()
    })
}

fn unsigned_sequence(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

/// Authenticate CMS, the exact CTL content, dedicated signer purpose, list
/// purpose, update interval and optional monotonic sequence floor. This supplies
/// bootstrap authenticity; AuthRoot/Disallowed restrictions require adapters.
pub fn authenticate(
    cms: &[u8],
    policy: &CtlAuthenticationPolicy<'_>,
    limits: CatalogLimits,
) -> crate::error::Result<AuthenticatedCtl> {
    use crate::error::{Context, ensure};
    use crate::portable::{chain, signed};
    ensure!(
        !policy.bootstrap_anchors.is_empty(),
        crate::error::Error::configuration(
            "CTL authentication requires dedicated bootstrap anchors"
        )
    );
    ensure!(
        policy.max_age_seconds > 0,
        crate::error::Error::configuration("CTL freshness bound must be positive")
    );
    ensure!(
        cms.len() <= limits.max_bytes,
        crate::error::Error::resource_limit("CTL CMS byte limit")
    );
    let verified = signed::verify_signed_data(
        cms,
        &signed::SignedDataOptions {
            crypto: crate::portable::crypto::CryptoOptions {
                allow_sha1: policy.allow_sha1,
            },
            ..signed::SignedDataOptions::new(ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.1"))
        },
    )?;
    let encoded = if verified.content_der.first() == Some(&0x30) {
        verified.content_der
    } else {
        verified.content_value
    };
    let list = parse(encoded, limits)?;
    ensure!(
        list.subject_usage.as_slice() == [policy.required_list_usage],
        "CTL list purpose mismatch"
    );
    let this_update = unix_time(&list.this_update)?;
    ensure!(
        this_update <= policy.verification_time,
        "CTL update is in the future"
    );
    ensure!(
        policy.verification_time - this_update <= policy.max_age_seconds,
        "CTL is stale"
    );
    if let Some(next) = &list.next_update {
        let next = unix_time(next)?;
        ensure!(
            next >= this_update && policy.verification_time <= next,
            "CTL nextUpdate has expired or precedes thisUpdate"
        );
    }
    if let Some(minimum) = policy.minimum_sequence {
        ensure!(
            !minimum.is_empty() && minimum[0] & 0x80 == 0,
            crate::error::Error::configuration("invalid CTL sequence floor")
        );
        let sequence = unsigned_sequence(
            list.sequence_number
                .context("CTL sequence number required")?,
        );
        let minimum = unsigned_sequence(minimum);
        ensure!(
            (sequence.len(), sequence) >= (minimum.len(), minimum),
            "CTL sequence rollback"
        );
    }
    ensure!(
        verified
            .certificates
            .len()
            .checked_add(policy.issuer_candidates.len())
            .and_then(|count| count.checked_add(policy.bootstrap_anchors.len()))
            .is_some_and(|count| count <= chain::PathLimits::default().max_store_certificates),
        crate::error::Error::resource_limit("CTL certificate store count limit")
    );
    let candidate_bytes = verified
        .certificates
        .iter()
        .map(Vec::as_slice)
        .chain(policy.issuer_candidates.iter())
        .collect::<Vec<_>>();
    let candidates = crate::portable::CertificateStore::from(candidate_bytes.as_slice());
    let signer_paths = verified
        .signers
        .iter()
        .map(|signer| {
            chain::validate(
                &signer.certificate_der,
                &chain::ChainOptions {
                    candidates,
                    allow_sha1: policy.allow_sha1,
                    ..chain::ChainOptions::new(
                        policy.bootstrap_anchors,
                        policy.verification_time,
                        policy.required_signer_eku,
                    )
                },
            )
        })
        .collect::<crate::error::Result<Vec<_>>>()?;
    ensure!(!signer_paths.is_empty(), "CTL has no authenticated signers");
    Ok(AuthenticatedCtl {
        encoded: encoded.to_vec(),
        signer_paths,
        limits,
    })
}

/// Parse exact CTL DER bytes extracted by the CMS verifier. Limits apply before
/// output allocation; list-purpose authorization belongs to a trust adapter.
pub fn parse(bytes: &[u8], limits: CatalogLimits) -> Result<ParsedCtl<'_>, CatalogError> {
    if bytes.len() > limits.max_bytes {
        return Err(CatalogError::Limit("CTL bytes"));
    }
    let (root, consumed) = node(bytes)?;
    if consumed != bytes.len() {
        return Err(bad("trailing CTL bytes"));
    }
    preflight(root, limits, &mut 0)?;
    parse_node(root, limits)
}

pub(crate) fn parse_node(
    n: Node<'_>,
    limits: CatalogLimits,
) -> Result<ParsedCtl<'_>, CatalogError> {
    let fields = children(tagged(n, 0x30)?)?;
    let mut pos = 0;
    let version = if fields.first().is_some_and(|n| n.tag == 2) {
        pos += 1;
        integer(fields[0])?
    } else {
        0
    };
    if version > 1 {
        return Err(CatalogError::Unsupported(format!("CTL version {version}")));
    }
    let subject_usage = children(field(&fields, pos, 0x30)?)?
        .into_iter()
        .map(crate::der::oid)
        .collect::<Result<Vec<_>, _>>()?;
    pos += 1;
    let list_identifier = if fields.get(pos).is_some_and(|n| n.tag == 4) {
        pos += 1;
        Some(fields[pos - 1].value)
    } else {
        None
    };
    let sequence_number = if fields.get(pos).is_some_and(|n| n.tag == 2) {
        let value = fields[pos].value;
        if value.is_empty() || value[0] & 0x80 != 0 {
            return Err(bad("negative CTL sequence number"));
        }
        pos += 1;
        Some(value)
    } else {
        None
    };
    let this_update = time(*fields.get(pos).ok_or_else(|| bad("missing CTL time"))?)?;
    pos += 1;
    let next_update = if fields
        .get(pos)
        .is_some_and(|n| matches!(n.tag, 0x17 | 0x18))
    {
        pos += 1;
        Some(time(fields[pos - 1])?)
    } else {
        None
    };
    let subject_algorithm = {
        let alg = children(field(&fields, pos, 0x30)?)?;
        if !(1..=2).contains(&alg.len()) {
            return Err(bad("invalid AlgorithmIdentifier"));
        }
        crate::der::oid(alg[0])?
    };
    pos += 1;
    let mut entries = Vec::new();
    if fields.get(pos).is_some_and(|n| n.tag == 0x30) {
        let members = children(fields[pos])?;
        if members.len() > limits.max_members {
            return Err(CatalogError::Limit("CTL entries"));
        }
        for member in members {
            let row = children(tagged(member, 0x30)?)?;
            if !(1..=2).contains(&row.len()) {
                return Err(bad("invalid CTL entry"));
            }
            entries.push(CtlEntry {
                subject_identifier: tagged(row[0], 4)?.value,
                attributes: if row.len() == 2 {
                    parse_attributes(row[1])?
                } else {
                    Vec::new()
                },
                encoded: member.full,
            });
        }
        pos += 1;
    }
    let extensions = if fields.get(pos).is_some_and(|n| n.tag == 0xa0) {
        pos += 1;
        Some(fields[pos - 1].full)
    } else {
        None
    };
    if pos != fields.len() {
        return Err(bad("unexpected CTL fields"));
    }
    Ok(ParsedCtl {
        version,
        subject_usage,
        list_identifier,
        sequence_number,
        this_update,
        next_update,
        subject_algorithm,
        entries,
        extensions,
        encoded: n.full,
    })
}
