//! Authenticated timestamp binding. A signed signingTime alone is not a timestamp.
use super::{chain, crypto, signed};
use crate::error::{Context, Result, bail, ensure};
use alloc::{
    borrow::ToOwned,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use der::{
    Decode,
    asn1::{AnyRef, ObjectIdentifier},
};
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

pub const RFC3161_ATTRIBUTE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
pub const MICROSOFT_RFC3161_ATTRIBUTE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");
pub const COUNTERSIGNATURE_ATTRIBUTE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.6");
const TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const TSA_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
const SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

type TimestampPathPolicy<'a> = dyn FnMut(&chain::ChainReport, u64) -> Result<()> + 'a;

/// Authenticated timestamp encoding, serialized with stable report names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimestampFormat {
    #[serde(rename = "rfc3161")]
    Rfc3161,
    #[serde(rename = "legacy_countersignature")]
    LegacyCountersignature,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimestampReport {
    pub format: TimestampFormat,
    pub unix_time: u64,
    pub accuracy_seconds: u64,
    pub tsa_certificate_sha256: String,
    pub tsa_anchor_sha256: String,
    /// True only when the exact pinned Microsoft TSA compatibility was necessary.
    pub noncritical_tsa_compatibility_used: bool,
    /// Exact legacy CA policy profile interpreted while validating the TSA chain.
    pub microsoft_timestamp_policy_certificate_sha256: Option<String>,
    #[serde(skip)]
    pub chain_der: Vec<Vec<u8>>,
}
use crate::der::{Node, node, oid};

fn fields(n: Node<'_>) -> Result<Vec<Node<'_>>> {
    Ok(crate::der::all(n.value, 128)?)
}
fn integer(n: Node<'_>) -> Result<u64> {
    ensure!(
        n.tag == 2,
        crate::error::Error::malformed("expected INTEGER")
    );
    AnyRef::from_der(n.full)
        .map_err(crate::error::Error::malformed)?
        .decode_as::<u64>()
        .map_err(crate::error::Error::malformed)
}
fn implicit_integer(n: Node<'_>) -> Result<u64> {
    let mut der = n.full.to_vec();
    der[0] = 2;
    AnyRef::from_der(&der)
        .map_err(crate::error::Error::malformed)?
        .decode_as::<u64>()
        .map_err(crate::error::Error::malformed)
}
fn time(n: Node<'_>) -> Result<u64> {
    if n.tag == 0x17 {
        return Ok(AnyRef::from_der(n.full)
            .map_err(crate::error::Error::malformed)?
            .decode_as::<der::asn1::UtcTime>()
            .map_err(crate::error::Error::malformed)?
            .to_unix_duration()
            .as_secs());
    }
    ensure!(
        n.tag == 0x18,
        crate::error::Error::malformed("expected generalized time")
    );
    // RFC3161 allows fractional seconds. Require DER UTC encoding and validate
    // the calendar with der's DateTime after removing the fractional component.
    let value = core::str::from_utf8(n.value)?;
    ensure!(value.ends_with('Z'), "timestamp requires UTC");
    let calendar =
        if let Some((base, fraction)) = value.strip_suffix('Z').and_then(|v| v.split_once('.')) {
            ensure!(
                base.len() == 14
                    && !fraction.is_empty()
                    && fraction.len() <= 9
                    && fraction.bytes().all(|b| b.is_ascii_digit())
                    && !fraction.ends_with('0'),
                crate::error::Error::malformed("noncanonical fractional timestamp")
            );
            format!("{base}Z")
        } else {
            value.to_owned()
        };
    ensure!(
        calendar.len() == 15,
        crate::error::Error::malformed("invalid generalized time")
    );
    let mut encoded = vec![0x18, 15];
    encoded.extend_from_slice(calendar.as_bytes());
    Ok(AnyRef::from_der(&encoded)
        .map_err(crate::error::Error::malformed)?
        .decode_as::<der::asn1::GeneralizedTime>()
        .map_err(crate::error::Error::malformed)?
        .to_unix_duration()
        .as_secs())
}
fn require_tsa(der: &[u8], rfc3161: bool, noncritical_tsa_pins: &[String]) -> Result<bool> {
    let cert = Certificate::from_der(der).map_err(crate::error::Error::malformed)?;
    let extensions = cert
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or_default();
    let eku: Vec<_> = extensions
        .iter()
        .filter(|e| e.extn_id.to_string() == "2.5.29.37")
        .collect();
    ensure!(
        eku.len() == 1,
        crate::error::Error::malformed("timestamp EKU must be unique")
    );
    let purposes = x509_cert::ext::pkix::ExtendedKeyUsage::from_der(eku[0].extn_value.as_bytes())
        .map_err(crate::error::Error::malformed)?;
    ensure!(
        purposes.0.contains(&TSA_EKU),
        "timestamp signer must have TSA EKU"
    );
    let compatibility_used = rfc3161
        && !eku[0].critical
        && purposes.0.len() == 1
        && noncritical_tsa_pins.contains(&hex::encode(crypto::digest(
            ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
            der,
            &crypto::CryptoOptions::default(),
        )?));
    if rfc3161 {
        ensure!(
            purposes.0.len() == 1 && (eku[0].critical || compatibility_used),
            "RFC3161 signer requires exclusive critical TSA EKU: critical={}, purposes={:?}",
            eku[0].critical,
            purposes
                .0
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );
    }
    Ok(compatibility_used)
}

/// Explicit timestamp trust inputs. Issuer candidates help construct paths;
/// only the supplied roots can anchor trust. The evaluation clock is required.
#[derive(Debug, Clone)]
pub struct TimestampOptions<'a> {
    pub roots: super::CertificateStore<'a>,
    pub issuer_candidates: super::CertificateStore<'a>,
    pub evaluation_time: u64,
    pub crypto: crypto::CryptoOptions,
    pub path_limits: chain::PathLimits,
    /// Exact Microsoft TSA leaf fingerprints permitting a sole noncritical TSA EKU.
    pub noncritical_tsa_certificate_sha256: &'a [String],
}

impl<'a> TimestampOptions<'a> {
    pub fn new(roots: super::CertificateStore<'a>, evaluation_time: u64) -> Self {
        Self {
            roots,
            issuer_candidates: super::CertificateStore::default(),
            evaluation_time,
            crypto: crypto::CryptoOptions::default(),
            path_limits: chain::PathLimits::default(),
            noncritical_tsa_certificate_sha256: &[],
        }
    }
}

/// Authenticate the timestamp imprint, ESS binding and one TSA path covering
/// the full accuracy interval. Revocation belongs to the caller's path policy.
pub fn verify_rfc3161(
    token: &[u8],
    original_signature: &[u8],
    options: &TimestampOptions<'_>,
) -> Result<TimestampReport> {
    verify_rfc3161_inner(token, original_signature, options, &mut |_, _| Ok(()))
}

fn verify_rfc3161_inner(
    token: &[u8],
    original_signature: &[u8],
    options: &TimestampOptions<'_>,
    accept_path: &mut TimestampPathPolicy<'_>,
) -> Result<TimestampReport> {
    let roots = options.roots;
    let now = options.evaluation_time;
    let allow_sha1 = options.crypto.allow_sha1;
    let noncritical_tsa_pins = options.noncritical_tsa_certificate_sha256;
    let issuer_candidates = options.issuer_candidates;
    ensure!(
        token.len() <= 4 * 1024 * 1024,
        crate::error::Error::resource_limit("timestamp byte limit")
    );
    ensure!(
        original_signature.len() <= 16 * 1024,
        crate::error::Error::resource_limit("timestamp imprint target byte limit")
    );
    let cms = signed::verify_signed_data(
        token,
        &signed::SignedDataOptions {
            crypto: options.crypto,
            ..signed::SignedDataOptions::new(TST_INFO)
        },
    )?;
    ensure!(
        cms.certificates
            .len()
            .checked_add(issuer_candidates.len())
            .and_then(|count| count.checked_add(roots.len()))
            .is_some_and(|count| count <= options.path_limits.max_store_certificates),
        crate::error::Error::resource_limit("timestamp certificate store count limit")
    );
    let certificate_bytes = cms
        .certificates
        .iter()
        .map(Vec::as_slice)
        .chain(issuer_candidates.iter())
        .collect::<Vec<_>>();
    let candidates = super::CertificateStore::from(certificate_bytes.as_slice());
    ensure!(cms.signers.len() == 1, "timestamp requires one signer");
    let (tst, size) = node(cms.content_value)?;
    ensure!(
        size == cms.content_value.len() && tst.tag == 0x30,
        crate::error::Error::malformed("invalid TSTInfo")
    );
    let f = fields(tst)?;
    ensure!(
        f.len() >= 5,
        crate::error::Error::malformed("truncated TSTInfo")
    );
    ensure!(
        integer(f[0])? == 1,
        crate::error::Error::unsupported("unsupported TSTInfo version")
    );
    oid(f[1])?;
    ensure!(
        f[2].tag == 0x30,
        crate::error::Error::malformed("invalid message imprint")
    );
    let imprint = fields(f[2])?;
    ensure!(
        imprint.len() == 2 && imprint[0].tag == 0x30 && imprint[1].tag == 4,
        crate::error::Error::malformed("invalid message imprint")
    );
    let alg = fields(imprint[0])?;
    ensure!(
        !alg.is_empty() && alg.len() <= 2,
        crate::error::Error::malformed("invalid imprint algorithm")
    );
    if let Some(parameters) = alg.get(1) {
        ensure!(
            parameters.tag == 5 && parameters.value.is_empty(),
            crate::error::Error::unsupported("unsupported timestamp imprint parameters")
        );
    }
    let digest = crypto::digest(oid(alg[0])?, original_signature, &options.crypto)?;
    ensure!(
        digest == imprint[1].value,
        crate::error::Error::signature("timestamp is not bound to original signature")
    );
    ensure!(
        f[3].tag == 2 && !f[3].value.is_empty() && f[3].value[0] & 0x80 == 0,
        crate::error::Error::malformed("invalid timestamp serial")
    );
    let unix_time = time(f[4])?;
    ensure!(unix_time <= now, "timestamp is in future");
    let mut pos = 5;
    let mut accuracy = 0u64;
    if f.get(pos).is_some_and(|n| n.tag == 0x30) {
        let a = fields(f[pos])?;
        let mut previous = 0u8;
        for n in a {
            let rank = match n.tag {
                2 => 1,
                0x80 => 2,
                0x81 => 3,
                _ => bail!(crate::error::Error::malformed("invalid timestamp accuracy")),
            };
            ensure!(
                rank > previous,
                crate::error::Error::malformed("duplicate or unordered accuracy")
            );
            previous = rank;
            if n.tag == 2 {
                accuracy = integer(n)?;
            } else {
                let v = implicit_integer(n)?;
                ensure!(
                    (1..=999).contains(&v),
                    crate::error::Error::malformed("invalid timestamp fractional accuracy")
                );
                accuracy = accuracy.checked_add(1).context("accuracy overflow")?;
            }
        }
        pos += 1;
    }
    if f.get(pos).is_some_and(|n| n.tag == 1) {
        ensure!(
            f[pos].value == [0xff],
            crate::error::Error::malformed("noncanonical timestamp ordering")
        );
        pos += 1;
    }
    if f.get(pos).is_some_and(|n| n.tag == 2) {
        ensure!(
            f[pos].value.first().is_some_and(|b| b & 0x80 == 0),
            crate::error::Error::malformed("invalid nonce")
        );
        pos += 1;
    }
    let signer = &cms.signers[0];
    let compatibility_used = require_tsa(&signer.certificate_der, true, noncritical_tsa_pins)?;
    verify_ess(signer)?;
    if f.get(pos).is_some_and(|n| n.tag == 0xa0) {
        let names = fields(f[pos])?;
        ensure!(
            names.len() == 1 && names[0].tag == 0xa4,
            crate::error::Error::unsupported("unsupported TSA name form")
        );
        let cert = Certificate::from_der(&signer.certificate_der)
            .map_err(crate::error::Error::malformed)?;
        use der::Encode;
        ensure!(
            names[0].value
                == cert
                    .tbs_certificate
                    .subject
                    .to_der()
                    .map_err(crate::error::Error::malformed)?,
            "TSA name does not match signer"
        );
        pos += 1;
    }
    ensure!(
        pos == f.len(),
        crate::error::Error::unsupported("unsupported timestamp extensions or fields")
    );
    // Cover subsecond rounding and signed accuracy, not only the center point.
    let bound = accuracy
        .checked_add(u64::from(f[4].value.contains(&b'.')))
        .context("accuracy overflow")?;
    let start = unix_time
        .checked_sub(bound)
        .context("timestamp accuracy precedes epoch")?;
    let end = unix_time
        .checked_add(bound)
        .context("timestamp accuracy overflow")?;
    ensure!(end <= now, "timestamp uncertainty extends into future");
    let path = chain::validate_timestamp_path(
        &signer.certificate_der,
        candidates,
        roots,
        end,
        start,
        allow_sha1,
        compatibility_used,
        options.path_limits,
        |path| accept_path(path, unix_time),
    )?;
    Ok(TimestampReport {
        format: TimestampFormat::Rfc3161,
        unix_time,
        accuracy_seconds: bound,
        tsa_certificate_sha256: hex::encode(crypto::digest(
            ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
            &signer.certificate_der,
            &crypto::CryptoOptions::default(),
        )?),
        tsa_anchor_sha256: path.anchor_sha256,
        noncritical_tsa_compatibility_used: compatibility_used,
        microsoft_timestamp_policy_certificate_sha256: path
            .microsoft_timestamp_policy_certificate_sha256,
        chain_der: path.chain_der,
    })
}

/// Authenticate a legacy Authenticode countersignature and its signed time.
pub fn verify_legacy(
    counter: &[u8],
    original_signature: &[u8],
    options: &TimestampOptions<'_>,
) -> Result<TimestampReport> {
    verify_legacy_inner(counter, original_signature, options, &mut |_, _| Ok(()))
}

fn verify_legacy_inner(
    counter: &[u8],
    original_signature: &[u8],
    options: &TimestampOptions<'_>,
    accept_path: &mut TimestampPathPolicy<'_>,
) -> Result<TimestampReport> {
    ensure!(
        counter.len() <= 4 * 1024 * 1024,
        crate::error::Error::resource_limit("countersignature byte limit")
    );
    let certificates = options.issuer_candidates;
    let roots = options.roots;
    let now = options.evaluation_time;
    let allow_sha1 = options.crypto.allow_sha1;
    let signer =
        signed::verify_counter_signer(counter, original_signature, certificates, &options.crypto)?;
    require_tsa(&signer.certificate_der, false, &[])?;
    let (n, size) = node(counter)?;
    ensure!(
        n.tag == 0x30 && size == counter.len(),
        crate::error::Error::malformed("invalid countersignature")
    );
    let f = fields(n)?;
    let attrs = f
        .get(3)
        .context("missing countersignature signed attributes")?;
    ensure!(
        attrs.tag == 0xa0,
        crate::error::Error::malformed("missing signed countersignature time")
    );
    let mut times = Vec::new();
    for a in fields(*attrs)? {
        ensure!(
            a.tag == 0x30,
            crate::error::Error::malformed("invalid counter attribute")
        );
        let af = fields(a)?;
        ensure!(
            af.len() == 2 && af[1].tag == 0x31,
            crate::error::Error::malformed("invalid counter attribute")
        );
        if oid(af[0])? == SIGNING_TIME {
            let values = fields(af[1])?;
            ensure!(values.len() == 1, "ambiguous countersignature time");
            times.push(time(values[0])?);
        }
    }
    ensure!(
        times.len() == 1,
        crate::error::Error::malformed("missing or ambiguous countersignature time")
    );
    ensure!(times[0] <= now, "future countersignature time");
    let unix_time = times[0];
    let path = chain::validate_with_path_policy(
        &signer.certificate_der,
        &chain::ChainOptions {
            candidates: certificates,
            allow_sha1,
            limits: options.path_limits,
            ..chain::ChainOptions::new(roots, unix_time, TSA_EKU)
        },
        |path| accept_path(path, unix_time),
    )?;
    Ok(TimestampReport {
        format: TimestampFormat::LegacyCountersignature,
        unix_time,
        accuracy_seconds: 0,
        tsa_certificate_sha256: hex::encode(crypto::digest(
            ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
            &signer.certificate_der,
            &crypto::CryptoOptions::default(),
        )?),
        tsa_anchor_sha256: path.anchor_sha256,
        noncritical_tsa_compatibility_used: false,
        microsoft_timestamp_policy_certificate_sha256: path
            .microsoft_timestamp_policy_certificate_sha256,
        chain_der: path.chain_der,
    })
}

/// Authenticate advertised timestamps, rejecting invalid or ambiguous tokens.
pub fn verify_timestamps(
    signer: &signed::VerifiedSigner,
    options: &TimestampOptions<'_>,
) -> Result<Option<TimestampReport>> {
    verify_timestamps_with_path_policy(signer, options, |_, _| Ok(()))
}

/// Evaluate caller policy on each fully authenticated TSA path. Rejected paths
/// continue alternative search under the configured work limits.
pub fn verify_timestamps_with_path_policy(
    signer: &signed::VerifiedSigner,
    options: &TimestampOptions<'_>,
    mut accept_path: impl FnMut(&chain::ChainReport, u64) -> Result<()>,
) -> Result<Option<TimestampReport>> {
    let mut timestamp = None;
    for (oid, values) in &signer.unsigned_attributes {
        let rfc3161 = *oid == RFC3161_ATTRIBUTE || *oid == MICROSOFT_RFC3161_ATTRIBUTE;
        let legacy = *oid == COUNTERSIGNATURE_ATTRIBUTE;
        if !rfc3161 && !legacy {
            continue;
        }
        ensure!(values.len() == 1, "ambiguous timestamp values");
        ensure!(
            timestamp.is_none(),
            "ambiguous timestamps on catalog signer"
        );
        timestamp = Some(if rfc3161 {
            verify_rfc3161_inner(&values[0], &signer.signature, options, &mut accept_path)?
        } else {
            verify_legacy_inner(&values[0], &signer.signature, options, &mut accept_path)?
        });
    }
    Ok(timestamp)
}

// RFC3161 requires an authenticated ESS certificate identifier. This is an
// identity hash, not an authorization substitute or a SHA-1 signature.
fn verify_ess(signer: &signed::VerifiedSigner) -> Result<()> {
    let attributes: Vec<_> = signer
        .signed_attributes
        .iter()
        .filter(|(oid, _)| {
            *oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12")
                || *oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47")
        })
        .collect();
    ensure!(
        attributes.len() == 1 && attributes[0].1.len() == 1,
        "timestamp missing or ambiguous ESS certificate binding"
    );
    let (n, size) = node(&attributes[0].1[0])?;
    ensure!(
        n.tag == 0x30 && size == attributes[0].1[0].len(),
        crate::error::Error::malformed("invalid SigningCertificate")
    );
    let outer = fields(n)?;
    ensure!(
        !outer.is_empty() && outer.len() <= 2 && outer[0].tag == 0x30,
        crate::error::Error::malformed("invalid ESS certs")
    );
    let certs = fields(outer[0])?;
    ensure!(
        !certs.is_empty() && certs.len() <= 64 && certs[0].tag == 0x30,
        crate::error::Error::malformed("invalid ESS certificate list")
    );
    let f = fields(certs[0])?;
    let mut pos = 0;
    let mut digest =
        if attributes[0].0 == ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12") {
            ObjectIdentifier::new_unwrap("1.3.14.3.2.26")
        } else {
            ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1")
        };
    if attributes[0].0 == ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47")
        && f.first().is_some_and(|n| n.tag == 0x30)
    {
        let a = fields(f[0])?;
        ensure!(
            !a.is_empty() && a.len() <= 2,
            crate::error::Error::malformed("invalid ESS algorithm")
        );
        if let Some(parameters) = a.get(1) {
            ensure!(
                parameters.tag == 5 && parameters.value.is_empty(),
                crate::error::Error::unsupported("unsupported ESS digest parameters")
            );
        }
        digest = oid(a[0])?;
        pos += 1;
    }
    let h = f.get(pos).context("missing ESS certificate hash")?;
    ensure!(
        h.tag == 4,
        crate::error::Error::malformed("invalid ESS certificate hash")
    );
    ensure!(
        h.value
            == crypto::digest(
                digest,
                &signer.certificate_der,
                &crypto::CryptoOptions { allow_sha1: true }
            )?,
        crate::error::Error::signature("ESS certificate binding mismatch")
    );
    pos += 1;
    if let Some(serial) = f.get(pos) {
        ensure!(
            serial.tag == 0x30,
            crate::error::Error::malformed("invalid ESS issuerSerial")
        );
        let sf = fields(*serial)?;
        ensure!(
            sf.len() == 2 && sf[0].tag == 0x30 && sf[1].tag == 2,
            crate::error::Error::malformed("invalid ESS issuerSerial")
        );
        let cert = Certificate::from_der(&signer.certificate_der)
            .map_err(crate::error::Error::malformed)?;
        use der::Encode;
        ensure!(
            sf[1].full
                == cert
                    .tbs_certificate
                    .serial_number
                    .to_der()
                    .map_err(crate::error::Error::malformed)?,
            "ESS serial mismatch"
        );
        let names = fields(sf[0])?;
        ensure!(
            names.len() == 1
                && names[0].tag == 0xa4
                && names[0].value
                    == cert
                        .tbs_certificate
                        .issuer
                        .to_der()
                        .map_err(crate::error::Error::malformed)?,
            "ESS issuer mismatch"
        );
        pos += 1;
    }
    ensure!(
        pos == f.len(),
        crate::error::Error::malformed("unexpected ESS certificate fields")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;

    #[test]
    fn pinned_noncritical_tsa_still_rejects_mixed_or_duplicate_ekus() {
        let mut certificate =
            Certificate::from_der(include_bytes!("../../../tests/fixtures/root.der")).unwrap();
        let purposes = x509_cert::ext::pkix::ExtendedKeyUsage(vec![TSA_EKU]);
        let extensions = certificate.tbs_certificate.extensions.as_mut().unwrap();
        extensions.retain(|e| e.extn_id.to_string() != "2.5.29.37");
        extensions.push(x509_cert::ext::Extension {
            extn_id: "2.5.29.37".parse().unwrap(),
            critical: false,
            extn_value: der::asn1::OctetString::new(purposes.to_der().unwrap()).unwrap(),
        });
        // This test checks the isolated EKU policy, not certificate signatures.
        let original = certificate.to_der().unwrap();
        let pin = hex::encode(
            crypto::digest(
                ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
                &original,
                &crypto::CryptoOptions::default(),
            )
            .unwrap(),
        );
        assert!(require_tsa(&original, true, &[pin]).unwrap());
        assert!(require_tsa(&original, true, &[]).is_err());
        let mut certificate = Certificate::from_der(&original).unwrap();
        let extensions = certificate.tbs_certificate.extensions.as_mut().unwrap();
        let eku = extensions
            .iter_mut()
            .find(|e| e.extn_id.to_string() == "2.5.29.37")
            .unwrap();
        let mut purposes =
            x509_cert::ext::pkix::ExtendedKeyUsage::from_der(eku.extn_value.as_bytes()).unwrap();
        purposes.0.push("1.3.6.1.5.5.7.3.3".parse().unwrap());
        eku.extn_value = der::asn1::OctetString::new(purposes.to_der().unwrap()).unwrap();
        let mixed = certificate.to_der().unwrap();
        let pin = hex::encode(
            crypto::digest(
                ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
                &mixed,
                &crypto::CryptoOptions::default(),
            )
            .unwrap(),
        );
        assert!(require_tsa(&mixed, true, &[pin]).is_err());
        let mut certificate = Certificate::from_der(&original).unwrap();
        let extensions = certificate.tbs_certificate.extensions.as_mut().unwrap();
        let eku = extensions
            .iter()
            .find(|e| e.extn_id.to_string() == "2.5.29.37")
            .unwrap()
            .clone();
        extensions.push(eku);
        let duplicate = certificate.to_der().unwrap();
        let pin = hex::encode(
            crypto::digest(
                ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
                &duplicate,
                &crypto::CryptoOptions::default(),
            )
            .unwrap(),
        );
        assert!(require_tsa(&duplicate, true, &[pin]).is_err());
    }
}
