use std::{fs, path::PathBuf};
use wintrust::portable::{PortableLimits, Verifier, sip::SipKind};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/microsoft-ber-certificates")
        .join(name)
}
fn verifier() -> Verifier {
    Verifier::load(&fixture("policy.json"), PortableLimits::default()).unwrap()
}
fn children(bytes: &[u8], start: usize) -> Vec<(u8, std::ops::Range<usize>)> {
    let mut result = Vec::new();
    let mut at = start;
    while at < bytes.len() {
        let tag = bytes[at];
        let mut head = 2;
        let mut length = usize::from(bytes[at + 1]);
        if length & 0x80 != 0 {
            let count = length & 0x7f;
            assert!(count > 0 && count <= 4);
            length = 0;
            for byte in &bytes[at + 2..at + 2 + count] {
                length = (length << 8) | usize::from(*byte);
            }
            head += count;
        }
        let end = at + head + length;
        assert!(end <= bytes.len());
        result.push((tag, at..end));
        at = end;
    }
    result
}
fn body(bytes: &[u8], start: usize) -> usize {
    let length = bytes[start + 1];
    start
        + 2
        + if length & 0x80 == 0 {
            0
        } else {
            usize::from(length & 0x7f)
        }
}
fn signer_attributes(
    bytes: &[u8],
    range: std::ops::Range<usize>,
) -> Option<std::ops::Range<usize>> {
    if bytes[range.start] & 0x20 == 0 {
        return None;
    }
    let fields = children(&bytes[..range.end], body(bytes, range.start));
    if bytes[range.start] == 0x30
        && fields.len() >= 6
        && fields[..6].iter().map(|field| field.0).collect::<Vec<_>>()
            == [2, 0x30, 0x30, 0xa0, 0x30, 4]
    {
        return Some(fields[3].1.clone());
    }
    fields
        .into_iter()
        .find_map(|(_, child)| signer_attributes(bytes, child))
}

#[test]
fn genuine_unordered_certificate_set_preserves_verified_timestamp_and_membership() {
    let report = verifier()
        .verify_catalog_member(
            &fixture("catalog.cat"),
            &fixture("member.mum"),
            SipKind::FlatXml,
        )
        .unwrap();
    assert!(report.trust_established && report.microsoft_signer_verified);
    assert_eq!(
        report.catalog_sha256,
        "65377930eb23d0b0f4fe56a61580a2dae0aaeca4abfad63b59a46d7b99018f42"
    );
    assert!(
        report
            .signers
            .iter()
            .all(|signer| signer.timestamp.is_some())
    );
    assert!(!report.revocation_checked && !report.allow_sha1);
}

#[test]
fn certificate_set_support_never_accepts_noncanonical_signed_attributes_or_altered_member() {
    let engine = verifier();
    let original = fs::read(fixture("catalog.cat")).unwrap();
    let member = fs::read(fixture("member.mum")).unwrap();
    let attrs = signer_attributes(&original, 0..original.len()).unwrap();
    let fields = children(&original[..attrs.end], body(&original, attrs.start));
    assert!(fields.len() >= 2);
    let mut mutated = original.clone();
    let joined = [
        original[fields[1].1.clone()].to_vec(),
        original[fields[0].1.clone()].to_vec(),
    ]
    .concat();
    mutated[fields[0].1.start..fields[1].1.end].copy_from_slice(&joined);
    let error = engine
        .verify_bytes(&mutated, &member, SipKind::FlatXml)
        .unwrap_err();
    assert!(format!("{error:#}").contains("canonical"));
    let mut damaged_member = member;
    damaged_member.push(b' ');
    assert!(
        engine
            .verify_bytes(&original, &damaged_member, SipKind::FlatXml)
            .is_err()
    );
}
