//! Authenticated timestamp binding. A signed signingTime alone is not a timestamp.
use super::{chain, crypto, signed};
use anyhow::{Context, Result, bail, ensure};
use der::{Decode, Reader, SliceReader, asn1::AnyRef};
use serde::Serialize;
use x509_cert::Certificate;

pub const RFC3161_ATTRIBUTE: &str = "1.2.840.113549.1.9.16.2.14";
pub const MICROSOFT_RFC3161_ATTRIBUTE: &str = "1.3.6.1.4.1.311.3.3.1";
pub const COUNTERSIGNATURE_ATTRIBUTE: &str = "1.2.840.113549.1.9.6";
const TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
const TSA_EKU: &str = "1.3.6.1.5.5.7.3.8";
const SIGNING_TIME: &str = "1.2.840.113549.1.9.5";

type TimestampPathPolicy<'a> = dyn FnMut(&chain::ChainReport, u64) -> Result<()> + 'a;

#[derive(Debug, Clone, Serialize)]
pub struct TimestampReport {
    pub format: String,
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
#[derive(Clone, Copy)]
struct Node<'a> {
    tag: u8,
    full: &'a [u8],
    value: &'a [u8],
}
fn node(bytes: &[u8]) -> Result<(Node<'_>, usize)> {
    ensure!(!bytes.is_empty(), "missing DER value");
    let mut r = SliceReader::new(bytes)?;
    let a = AnyRef::decode(&mut r)?;
    let size = usize::try_from(r.position())?;
    Ok((
        Node {
            tag: bytes[0],
            full: &bytes[..size],
            value: a.value(),
        },
        size,
    ))
}
fn fields(n: Node<'_>) -> Result<Vec<Node<'_>>> {
    let mut rest = n.value;
    let mut output = Vec::new();
    while !rest.is_empty() {
        ensure!(output.len() < 128, "timestamp field limit");
        let (n, size) = node(rest)?;
        output.push(n);
        rest = &rest[size..];
    }
    Ok(output)
}
fn oid(n: Node<'_>) -> Result<String> {
    ensure!(n.tag == 6, "expected OID");
    Ok(AnyRef::from_der(n.full)?
        .decode_as::<der::asn1::ObjectIdentifier>()?
        .to_string())
}
fn integer(n: Node<'_>) -> Result<u64> {
    ensure!(n.tag == 2, "expected INTEGER");
    Ok(AnyRef::from_der(n.full)?.decode_as::<u64>()?)
}
fn implicit_integer(n: Node<'_>) -> Result<u64> {
    let mut der = n.full.to_vec();
    der[0] = 2;
    Ok(AnyRef::from_der(&der)?.decode_as::<u64>()?)
}
fn time(n: Node<'_>) -> Result<u64> {
    if n.tag == 0x17 {
        return Ok(AnyRef::from_der(n.full)?
            .decode_as::<der::asn1::UtcTime>()?
            .to_unix_duration()
            .as_secs());
    }
    ensure!(n.tag == 0x18, "expected generalized time");
    // RFC3161 allows fractional seconds. Require DER UTC encoding and validate
    // the calendar with der's DateTime after removing the fractional component.
    let value = std::str::from_utf8(n.value)?;
    ensure!(value.ends_with('Z'), "timestamp requires UTC");
    let calendar =
        if let Some((base, fraction)) = value.strip_suffix('Z').and_then(|v| v.split_once('.')) {
            ensure!(
                base.len() == 14
                    && !fraction.is_empty()
                    && fraction.len() <= 9
                    && fraction.bytes().all(|b| b.is_ascii_digit())
                    && !fraction.ends_with('0'),
                "noncanonical fractional timestamp"
            );
            format!("{base}Z")
        } else {
            value.to_owned()
        };
    ensure!(calendar.len() == 15, "invalid generalized time");
    let mut encoded = vec![0x18, 15];
    encoded.extend_from_slice(calendar.as_bytes());
    Ok(AnyRef::from_der(&encoded)?
        .decode_as::<der::asn1::GeneralizedTime>()?
        .to_unix_duration()
        .as_secs())
}
fn require_tsa(der: &[u8], rfc3161: bool, noncritical_tsa_pins: &[String]) -> Result<bool> {
    let cert = Certificate::from_der(der)?;
    let extensions = cert
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or_default();
    let eku: Vec<_> = extensions
        .iter()
        .filter(|e| e.extn_id.to_string() == "2.5.29.37")
        .collect();
    ensure!(eku.len() == 1, "timestamp EKU must be unique");
    let purposes = x509_cert::ext::pkix::ExtendedKeyUsage::from_der(eku[0].extn_value.as_bytes())?;
    ensure!(
        purposes.0.iter().any(|p| p.to_string() == TSA_EKU),
        "timestamp signer must have TSA EKU"
    );
    let compatibility_used = rfc3161
        && !eku[0].critical
        && purposes.0.len() == 1
        && noncritical_tsa_pins
            .contains(&hex::encode(crypto::digest("2.16.840.1.101.3.4.2.1", der)?));
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

/// Verify RFC3161/Microsoft timestamp CMS, original signature imprint and TSA
/// chain against explicit roots at the authenticated time. Revocation is a
/// separate required caller policy; this function never claims non-revocation.
pub fn verify_rfc3161(
    token: &[u8],
    original_signature: &[u8],
    roots: &[Vec<u8>],
    now: u64,
) -> Result<TimestampReport> {
    ensure!(token.len() <= 4 * 1024 * 1024, "timestamp byte limit");
    verify_rfc3161_with_policy(token, original_signature, roots, now, false)
}
pub fn verify_rfc3161_with_policy(
    token: &[u8],
    original_signature: &[u8],
    roots: &[Vec<u8>],
    now: u64,
    allow_sha1: bool,
) -> Result<TimestampReport> {
    verify_rfc3161_with_compatibility(token, original_signature, roots, now, allow_sha1, &[])
}

fn verify_rfc3161_with_compatibility(
    token: &[u8],
    original_signature: &[u8],
    roots: &[Vec<u8>],
    now: u64,
    allow_sha1: bool,
    noncritical_tsa_pins: &[String],
) -> Result<TimestampReport> {
    verify_rfc3161_with_path_policy(
        token,
        original_signature,
        roots,
        now,
        allow_sha1,
        noncritical_tsa_pins,
        &[],
        chain::PathLimits::default(),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_rfc3161_with_path_policy(
    token: &[u8],
    original_signature: &[u8],
    roots: &[Vec<u8>],
    now: u64,
    allow_sha1: bool,
    noncritical_tsa_pins: &[String],
    issuer_candidates: &[Vec<u8>],
    limits: chain::PathLimits,
    accept_path: Option<&mut TimestampPathPolicy<'_>>,
) -> Result<TimestampReport> {
    ensure!(token.len() <= 4 * 1024 * 1024, "timestamp byte limit");
    let mut cms = signed::verify_signed_data_with_policy(token, TST_INFO, allow_sha1)?;
    cms.certificates.extend_from_slice(issuer_candidates);
    ensure!(cms.signers.len() == 1, "timestamp requires one signer");
    let (tst, size) = node(&cms.content_value)?;
    ensure!(
        size == cms.content_value.len() && tst.tag == 0x30,
        "invalid TSTInfo"
    );
    let f = fields(tst)?;
    ensure!(f.len() >= 5, "truncated TSTInfo");
    ensure!(integer(f[0])? == 1, "unsupported TSTInfo version");
    oid(f[1])?;
    ensure!(f[2].tag == 0x30, "invalid message imprint");
    let imprint = fields(f[2])?;
    ensure!(
        imprint.len() == 2 && imprint[0].tag == 0x30 && imprint[1].tag == 4,
        "invalid message imprint"
    );
    let alg = fields(imprint[0])?;
    ensure!(
        !alg.is_empty() && alg.len() <= 2,
        "invalid imprint algorithm"
    );
    if let Some(parameters) = alg.get(1) {
        ensure!(
            parameters.tag == 5 && parameters.value.is_empty(),
            "unsupported timestamp imprint parameters"
        );
    }
    let digest = crypto::digest_with_policy(&oid(alg[0])?, original_signature, allow_sha1)?;
    ensure!(
        digest == imprint[1].value,
        "timestamp is not bound to original signature"
    );
    ensure!(
        f[3].tag == 2 && !f[3].value.is_empty() && f[3].value[0] & 0x80 == 0,
        "invalid timestamp serial"
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
                _ => bail!("invalid timestamp accuracy"),
            };
            ensure!(rank > previous, "duplicate or unordered accuracy");
            previous = rank;
            if n.tag == 2 {
                accuracy = integer(n)?;
            } else {
                let v = implicit_integer(n)?;
                ensure!(
                    (1..=999).contains(&v),
                    "invalid timestamp fractional accuracy"
                );
                accuracy = accuracy.checked_add(1).context("accuracy overflow")?;
            }
        }
        pos += 1;
    }
    if f.get(pos).is_some_and(|n| n.tag == 1) {
        ensure!(f[pos].value == [0xff], "noncanonical timestamp ordering");
        pos += 1;
    }
    if f.get(pos).is_some_and(|n| n.tag == 2) {
        ensure!(
            f[pos].value.first().is_some_and(|b| b & 0x80 == 0),
            "invalid nonce"
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
            "unsupported TSA name form"
        );
        let cert = Certificate::from_der(&signer.certificate_der)?;
        use der::Encode;
        ensure!(
            names[0].value == cert.tbs_certificate.subject.to_der()?,
            "TSA name does not match signer"
        );
        pos += 1;
    }
    ensure!(pos == f.len(), "unsupported timestamp extensions or fields");
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
    let validate_chain = |at| {
        if compatibility_used {
            chain::validate_microsoft_timestamp_with_policy(
                &signer.certificate_der,
                &cms.certificates,
                roots,
                at,
                allow_sha1,
            )
        } else {
            chain::validate_with_policy(
                &signer.certificate_der,
                &cms.certificates,
                roots,
                at,
                TSA_EKU,
                allow_sha1,
            )
        }
    };
    let (start_path, path) = if let Some(accept_path) = accept_path {
        ensure!(
            !compatibility_used,
            "callback timestamp policy requires strict TSA certificates"
        );
        let path = chain::validate_with_path_policy(
            &signer.certificate_der,
            &cms.certificates,
            roots,
            end,
            TSA_EKU,
            allow_sha1,
            limits,
            |path| {
                chain::validate_report_constraints(path, start, TSA_EKU)?;
                accept_path(path, unix_time)
            },
        )?;
        (path.clone(), path)
    } else {
        (validate_chain(start)?, validate_chain(end)?)
    };
    if compatibility_used {
        ensure!(
            super::MICROSOFT_ROOTS.contains(&start_path.anchor_sha256.as_str())
                && super::MICROSOFT_ROOTS.contains(&path.anchor_sha256.as_str()),
            "pinned noncritical TSA compatibility requires an authorized Microsoft root"
        );
    }
    Ok(TimestampReport {
        format: "rfc3161".into(),
        unix_time,
        accuracy_seconds: bound,
        tsa_certificate_sha256: hex::encode(crypto::digest(
            "2.16.840.1.101.3.4.2.1",
            &signer.certificate_der,
        )?),
        tsa_anchor_sha256: path.anchor_sha256,
        noncritical_tsa_compatibility_used: compatibility_used,
        microsoft_timestamp_policy_certificate_sha256: path
            .microsoft_timestamp_policy_certificate_sha256,
        chain_der: path.chain_der,
    })
}

/// Legacy Authenticode countersignature: digest/signature authentication comes
/// from the CMS verifier, and its signed signingTime is validated with TSA trust.
pub fn verify_legacy(
    counter: &[u8],
    original_signature: &[u8],
    certificates: &[Vec<u8>],
    roots: &[Vec<u8>],
    now: u64,
) -> Result<TimestampReport> {
    ensure!(
        counter.len() <= 4 * 1024 * 1024,
        "countersignature byte limit"
    );
    verify_legacy_with_policy(counter, original_signature, certificates, roots, now, false)
}
pub fn verify_legacy_with_policy(
    counter: &[u8],
    original_signature: &[u8],
    certificates: &[Vec<u8>],
    roots: &[Vec<u8>],
    now: u64,
    allow_sha1: bool,
) -> Result<TimestampReport> {
    verify_legacy_with_path_policy(
        counter,
        original_signature,
        certificates,
        roots,
        now,
        allow_sha1,
        chain::PathLimits::default(),
        &mut |_, _| Ok(()),
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_legacy_with_path_policy(
    counter: &[u8],
    original_signature: &[u8],
    certificates: &[Vec<u8>],
    roots: &[Vec<u8>],
    now: u64,
    allow_sha1: bool,
    limits: chain::PathLimits,
    accept_path: &mut TimestampPathPolicy<'_>,
) -> Result<TimestampReport> {
    let signer = signed::verify_counter_signer_with_policy(
        counter,
        original_signature,
        certificates,
        allow_sha1,
    )?;
    require_tsa(&signer.certificate_der, false, &[])?;
    let (n, size) = node(counter)?;
    ensure!(
        n.tag == 0x30 && size == counter.len(),
        "invalid countersignature"
    );
    let f = fields(n)?;
    let attrs = f
        .get(3)
        .context("missing countersignature signed attributes")?;
    ensure!(attrs.tag == 0xa0, "missing signed countersignature time");
    let mut times = Vec::new();
    for a in fields(*attrs)? {
        ensure!(a.tag == 0x30, "invalid counter attribute");
        let af = fields(a)?;
        ensure!(
            af.len() == 2 && af[1].tag == 0x31,
            "invalid counter attribute"
        );
        if oid(af[0])? == SIGNING_TIME {
            let values = fields(af[1])?;
            ensure!(values.len() == 1, "ambiguous countersignature time");
            times.push(time(values[0])?);
        }
    }
    ensure!(
        times.len() == 1 && times[0] <= now,
        "missing, ambiguous or future countersignature time"
    );
    let unix_time = times[0];
    let path = chain::validate_with_path_policy(
        &signer.certificate_der,
        certificates,
        roots,
        unix_time,
        TSA_EKU,
        allow_sha1,
        limits,
        |path| accept_path(path, unix_time),
    )?;
    Ok(TimestampReport {
        format: "legacy_countersignature".into(),
        unix_time,
        accuracy_seconds: 0,
        tsa_certificate_sha256: hex::encode(crypto::digest(
            "2.16.840.1.101.3.4.2.1",
            &signer.certificate_der,
        )?),
        tsa_anchor_sha256: path.anchor_sha256,
        noncritical_tsa_compatibility_used: false,
        microsoft_timestamp_policy_certificate_sha256: path
            .microsoft_timestamp_policy_certificate_sha256,
        chain_der: path.chain_der,
    })
}

/// Authenticate every advertised timestamp; reject ambiguity and invalid tokens
/// instead of treating failed timestamp verification as an absent timestamp.
pub fn verify_timestamps(
    signer: &signed::VerifiedSigner,
    certificates: &[Vec<u8>],
    roots: &[Vec<u8>],
    now: u64,
) -> Result<Option<TimestampReport>> {
    verify_timestamps_with_policy(signer, certificates, roots, now, false)
}
pub fn verify_timestamps_with_policy(
    signer: &signed::VerifiedSigner,
    certificates: &[Vec<u8>],
    roots: &[Vec<u8>],
    now: u64,
    allow_sha1: bool,
) -> Result<Option<TimestampReport>> {
    verify_timestamps_with_compatibility(signer, certificates, roots, now, allow_sha1, &[])
}

pub(super) fn verify_timestamps_with_compatibility(
    signer: &signed::VerifiedSigner,
    certificates: &[Vec<u8>],
    roots: &[Vec<u8>],
    now: u64,
    allow_sha1: bool,
    noncritical_tsa_pins: &[String],
) -> Result<Option<TimestampReport>> {
    verify_timestamps_inner(
        signer,
        certificates,
        roots,
        now,
        allow_sha1,
        noncritical_tsa_pins,
        chain::PathLimits::default(),
        None,
    )
}

/// Verify timestamp binding and search TSA paths with a caller policy before
/// selecting a path. The callback receives the authenticated timestamp time.
#[allow(clippy::too_many_arguments)]
pub fn verify_timestamps_with_path_policy(
    signer: &signed::VerifiedSigner,
    certificates: &[Vec<u8>],
    roots: &[Vec<u8>],
    now: u64,
    allow_sha1: bool,
    limits: chain::PathLimits,
    mut accept_path: impl FnMut(&chain::ChainReport, u64) -> Result<()>,
) -> Result<Option<TimestampReport>> {
    verify_timestamps_inner(
        signer,
        certificates,
        roots,
        now,
        allow_sha1,
        &[],
        limits,
        Some(&mut accept_path),
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_timestamps_inner(
    signer: &signed::VerifiedSigner,
    certificates: &[Vec<u8>],
    roots: &[Vec<u8>],
    now: u64,
    allow_sha1: bool,
    noncritical_tsa_pins: &[String],
    limits: chain::PathLimits,
    mut accept_path: Option<&mut TimestampPathPolicy<'_>>,
) -> Result<Option<TimestampReport>> {
    let mut timestamps = Vec::new();
    for (oid, values) in &signer.unsigned_attributes {
        if oid == RFC3161_ATTRIBUTE || oid == MICROSOFT_RFC3161_ATTRIBUTE {
            ensure!(values.len() == 1, "ambiguous RFC3161 timestamp values");
            timestamps.push(verify_rfc3161_with_path_policy(
                &values[0],
                &signer.signature,
                roots,
                now,
                allow_sha1,
                noncritical_tsa_pins,
                if accept_path.is_some() {
                    certificates
                } else {
                    &[]
                },
                limits,
                accept_path
                    .as_mut()
                    .map(|callback| &mut **callback as &mut TimestampPathPolicy<'_>),
            )?);
        } else if oid == COUNTERSIGNATURE_ATTRIBUTE {
            ensure!(
                values.len() == 1,
                "ambiguous legacy countersignature values"
            );
            let mut noop = |_: &chain::ChainReport, _: u64| Ok(());
            let callback = accept_path
                .as_mut()
                .map(|callback| &mut **callback as &mut TimestampPathPolicy<'_>)
                .unwrap_or(&mut noop);
            timestamps.push(verify_legacy_with_path_policy(
                &values[0],
                &signer.signature,
                certificates,
                roots,
                now,
                allow_sha1,
                limits,
                callback,
            )?);
        }
    }
    ensure!(
        timestamps.len() <= 1,
        "ambiguous timestamps on catalog signer"
    );
    Ok(timestamps.pop())
}

// RFC3161 requires an authenticated ESS certificate identifier. This is an
// identity hash, not an authorization substitute or a SHA-1 signature.
fn verify_ess(signer: &signed::VerifiedSigner) -> Result<()> {
    let attributes: Vec<_> = signer
        .signed_attributes
        .iter()
        .filter(|(oid, _)| {
            oid == "1.2.840.113549.1.9.16.2.12" || oid == "1.2.840.113549.1.9.16.2.47"
        })
        .collect();
    ensure!(
        attributes.len() == 1 && attributes[0].1.len() == 1,
        "timestamp missing or ambiguous ESS certificate binding"
    );
    let (n, size) = node(&attributes[0].1[0])?;
    ensure!(
        n.tag == 0x30 && size == attributes[0].1[0].len(),
        "invalid SigningCertificate"
    );
    let outer = fields(n)?;
    ensure!(
        !outer.is_empty() && outer.len() <= 2 && outer[0].tag == 0x30,
        "invalid ESS certs"
    );
    let certs = fields(outer[0])?;
    ensure!(
        !certs.is_empty() && certs.len() <= 64 && certs[0].tag == 0x30,
        "invalid ESS certificate list"
    );
    let f = fields(certs[0])?;
    let mut pos = 0;
    let mut digest = if attributes[0].0 == "1.2.840.113549.1.9.16.2.12" {
        "1.3.14.3.2.26".to_owned()
    } else {
        "2.16.840.1.101.3.4.2.1".to_owned()
    };
    if attributes[0].0 == "1.2.840.113549.1.9.16.2.47" && f.first().is_some_and(|n| n.tag == 0x30) {
        let a = fields(f[0])?;
        ensure!(!a.is_empty() && a.len() <= 2, "invalid ESS algorithm");
        if let Some(parameters) = a.get(1) {
            ensure!(
                parameters.tag == 5 && parameters.value.is_empty(),
                "unsupported ESS digest parameters"
            );
        }
        digest = oid(a[0])?;
        pos += 1;
    }
    let h = f.get(pos).context("missing ESS certificate hash")?;
    ensure!(h.tag == 4, "invalid ESS certificate hash");
    ensure!(
        h.value == crypto::digest_with_policy(&digest, &signer.certificate_der, true)?,
        "ESS certificate binding mismatch"
    );
    pos += 1;
    if let Some(serial) = f.get(pos) {
        ensure!(serial.tag == 0x30, "invalid ESS issuerSerial");
        let sf = fields(*serial)?;
        ensure!(
            sf.len() == 2 && sf[0].tag == 0x30 && sf[1].tag == 2,
            "invalid ESS issuerSerial"
        );
        let cert = Certificate::from_der(&signer.certificate_der)?;
        use der::Encode;
        ensure!(
            sf[1].full == cert.tbs_certificate.serial_number.to_der()?,
            "ESS serial mismatch"
        );
        let names = fields(sf[0])?;
        ensure!(
            names.len() == 1
                && names[0].tag == 0xa4
                && names[0].value == cert.tbs_certificate.issuer.to_der()?,
            "ESS issuer mismatch"
        );
        pos += 1;
    }
    ensure!(pos == f.len(), "unexpected ESS certificate fields");
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
        let purposes = x509_cert::ext::pkix::ExtendedKeyUsage(vec![TSA_EKU.parse().unwrap()]);
        let extensions = certificate.tbs_certificate.extensions.as_mut().unwrap();
        extensions.retain(|e| e.extn_id.to_string() != "2.5.29.37");
        extensions.push(x509_cert::ext::Extension {
            extn_id: "2.5.29.37".parse().unwrap(),
            critical: false,
            extn_value: der::asn1::OctetString::new(purposes.to_der().unwrap()).unwrap(),
        });
        // This test checks the isolated EKU policy, not certificate signatures.
        let original = certificate.to_der().unwrap();
        let pin = hex::encode(crypto::digest("2.16.840.1.101.3.4.2.1", &original).unwrap());
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
        let pin = hex::encode(crypto::digest("2.16.840.1.101.3.4.2.1", &mixed).unwrap());
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
        let pin = hex::encode(crypto::digest("2.16.840.1.101.3.4.2.1", &duplicate).unwrap());
        assert!(require_tsa(&duplicate, true, &[pin]).is_err());
    }
}
