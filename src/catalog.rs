//! Bounded inspection of Microsoft PKCS#7 catalog CTLs. Parsing establishes no trust.
use der::{Decode, Reader, SliceReader, asn1::AnyRef};
use serde::Serialize;
use std::fmt;

const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const CTL: &str = "1.3.6.1.4.1.311.10.1";
const INDIRECT: &str = "1.3.6.1.4.1.311.2.1.4";

#[derive(Clone, Copy, Debug)]
pub struct CatalogLimits {
    pub max_bytes: usize,
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_members: usize,
}
impl Default for CatalogLimits {
    fn default() -> Self {
        Self {
            max_bytes: 32 * 1024 * 1024,
            max_nodes: 500_000,
            max_depth: 64,
            max_members: 100_000,
        }
    }
}
#[derive(Debug)]
pub enum CatalogError {
    Malformed(String),
    Unsupported(String),
    Limit(&'static str),
}
impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(s) => write!(f, "malformed catalog: {s}"),
            Self::Unsupported(s) => write!(f, "unsupported catalog: {s}"),
            Self::Limit(s) => write!(f, "catalog limit exceeded: {s}"),
        }
    }
}
impl std::error::Error for CatalogError {}
impl From<der::Error> for CatalogError {
    fn from(e: der::Error) -> Self {
        Self::Malformed(e.to_string())
    }
}
#[derive(Debug, Serialize)]
pub struct Catalog {
    pub content_type: String,
    pub digest_algorithms: Vec<String>,
    pub certificate_count: usize,
    pub signers: Vec<Signer>,
    pub ctl: CertificateTrustList,
    pub trust_established: bool,
}
#[derive(Debug, Serialize)]
pub struct Signer {
    pub digest_algorithm: String,
    pub signature_algorithm: String,
    pub signature_bytes: usize,
    pub signed_attributes: Vec<Attribute>,
    pub unsigned_attributes: Vec<Attribute>,
}
#[derive(Debug, Serialize)]
pub struct Attribute {
    pub oid: String,
    pub values_der_hex: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct CertificateTrustList {
    pub version: u64,
    pub subject_usage: Vec<String>,
    pub list_identifier_hex: Option<String>,
    pub sequence_number_hex: Option<String>,
    pub this_update: String,
    pub next_update: Option<String>,
    pub subject_algorithm: String,
    pub members: Vec<CatalogMember>,
    pub extensions_der_hex: Option<String>,
    /// Exact CTL DER encoding; legacy PKCS#7 signs its value octets, not a CMS OCTET STRING.
    pub encoded_hex: String,
}
#[derive(Debug, Serialize)]
pub struct CatalogMember {
    pub identifier_hex: String,
    pub attributes: Vec<Attribute>,
    pub indirect_data: Option<IndirectData>,
}
#[derive(Debug, Serialize)]
pub struct IndirectData {
    pub data_type: String,
    pub digest_algorithm: String,
    pub digest_hex: String,
}

#[derive(Clone, Copy)]
pub(crate) struct Node<'a> {
    pub(crate) tag: u8,
    pub(crate) full: &'a [u8],
    pub(crate) value: &'a [u8],
}
pub(crate) fn bad(message: &str) -> CatalogError {
    CatalogError::Malformed(message.into())
}
pub(crate) fn node(bytes: &[u8]) -> Result<(Node<'_>, usize), CatalogError> {
    let mut r = SliceReader::new(bytes)?;
    let a = AnyRef::decode(&mut r)?;
    let consumed = usize::try_from(r.position()).map_err(|_| bad("length overflow"))?;
    Ok((
        Node {
            tag: bytes[0],
            full: &bytes[..consumed],
            value: a.value(),
        },
        consumed,
    ))
}
pub(crate) fn children(n: Node<'_>) -> Result<Vec<Node<'_>>, CatalogError> {
    let mut bytes = n.value;
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (n, size) = node(bytes)?;
        out.push(n);
        bytes = &bytes[size..];
    }
    Ok(out)
}
pub(crate) fn tagged(n: Node<'_>, tag: u8) -> Result<Node<'_>, CatalogError> {
    if n.tag != tag {
        return Err(bad("unexpected ASN.1 tag"));
    }
    Ok(n)
}
pub(crate) fn field<'a>(items: &[Node<'a>], i: usize, tag: u8) -> Result<Node<'a>, CatalogError> {
    tagged(*items.get(i).ok_or_else(|| bad("missing field"))?, tag)
}
pub(crate) fn oid(n: Node<'_>) -> Result<String, CatalogError> {
    tagged(n, 6)?;
    Ok(AnyRef::from_der(n.full)?
        .decode_as::<der::asn1::ObjectIdentifier>()?
        .to_string())
}
pub(crate) fn algorithm(n: Node<'_>) -> Result<String, CatalogError> {
    let fields = children(tagged(n, 0x30)?)?;
    if fields.is_empty() || fields.len() > 2 {
        return Err(bad("invalid AlgorithmIdentifier"));
    }
    oid(fields[0])
}
pub(crate) fn integer(n: Node<'_>) -> Result<u64, CatalogError> {
    tagged(n, 2)?;
    Ok(AnyRef::from_der(n.full)?.decode_as::<u64>()?)
}
pub(crate) fn time(n: Node<'_>) -> Result<String, CatalogError> {
    match n.tag {
        0x17 => {
            AnyRef::from_der(n.full)?.decode_as::<der::asn1::UtcTime>()?;
        }
        0x18 => {
            AnyRef::from_der(n.full)?.decode_as::<der::asn1::GeneralizedTime>()?;
        }
        _ => return Err(bad("invalid CTL time")),
    };
    String::from_utf8(n.value.to_vec()).map_err(|_| bad("invalid time encoding"))
}
pub(crate) fn attributes(n: Node<'_>) -> Result<Vec<Attribute>, CatalogError> {
    children(n)?
        .into_iter()
        .map(|n| {
            let f = children(tagged(n, 0x30)?)?;
            if f.len() != 2 {
                return Err(bad("invalid attribute"));
            }
            let values = children(tagged(f[1], 0x31)?)?;
            if values.is_empty() {
                return Err(bad("empty attribute values"));
            }
            Ok(Attribute {
                oid: oid(f[0])?,
                values_der_hex: values.iter().map(|v| hex::encode(v.full)).collect(),
            })
        })
        .collect()
}
fn signer(n: Node<'_>) -> Result<Signer, CatalogError> {
    let f = children(tagged(n, 0x30)?)?;
    integer(field(&f, 0, 2)?)?;
    let sid = *f.get(1).ok_or_else(|| bad("missing signer identifier"))?;
    if !matches!(sid.tag, 0x30 | 0x80) {
        return Err(bad("invalid signer identifier"));
    }
    let digest_algorithm = algorithm(field(&f, 2, 0x30)?)?;
    let mut pos = 3;
    let signed_attributes = if f.get(pos).is_some_and(|n| n.tag == 0xa0) {
        let a = attributes(f[pos])?;
        pos += 1;
        a
    } else {
        Vec::new()
    };
    let signature_algorithm = algorithm(field(&f, pos, 0x30)?)?;
    pos += 1;
    let signature_bytes = field(&f, pos, 4)?.value.len();
    pos += 1;
    let unsigned_attributes = if f.get(pos).is_some_and(|n| n.tag == 0xa1) {
        let a = attributes(f[pos])?;
        pos += 1;
        a
    } else {
        Vec::new()
    };
    if pos != f.len() {
        return Err(bad("unexpected signer fields"));
    }
    Ok(Signer {
        digest_algorithm,
        signature_algorithm,
        signature_bytes,
        signed_attributes,
        unsigned_attributes,
    })
}
fn indirect(n: Node<'_>) -> Result<IndirectData, CatalogError> {
    let f = children(tagged(n, 0x30)?)?;
    if f.len() != 2 {
        return Err(bad("invalid indirect data"));
    }
    let data = children(tagged(f[0], 0x30)?)?;
    let data_type = oid(*data.first().ok_or_else(|| bad("missing data type"))?)?;
    if data.len() > 2 {
        return Err(bad("invalid indirect data type"));
    }
    let digest = children(tagged(f[1], 0x30)?)?;
    if digest.len() != 2 {
        return Err(bad("invalid DigestInfo"));
    }
    let digest_algorithm = algorithm(digest[0])?;
    let bytes = tagged(digest[1], 4)?.value;
    let expected = match digest_algorithm.as_str() {
        "1.3.14.3.2.26" => Some(20),
        "2.16.840.1.101.3.4.2.1" => Some(32),
        "2.16.840.1.101.3.4.2.2" => Some(48),
        "2.16.840.1.101.3.4.2.3" => Some(64),
        _ => None,
    };
    if expected.is_some_and(|len| len != bytes.len()) {
        return Err(bad("digest length does not match algorithm"));
    }
    Ok(IndirectData {
        data_type,
        digest_algorithm,
        digest_hex: hex::encode(bytes),
    })
}
fn ctl(n: Node<'_>, limits: CatalogLimits) -> Result<CertificateTrustList, CatalogError> {
    let f = children(tagged(n, 0x30)?)?;
    let mut pos = 0;
    let version = if f.first().is_some_and(|n| n.tag == 2) {
        pos += 1;
        integer(f[0])?
    } else {
        0
    };
    if version > 1 {
        return Err(CatalogError::Unsupported(format!("CTL version {version}")));
    }
    let subject_usage = children(field(&f, pos, 0x30)?)?
        .into_iter()
        .map(oid)
        .collect::<Result<Vec<_>, _>>()?;
    pos += 1;
    let list_identifier_hex = if f.get(pos).is_some_and(|n| n.tag == 4) {
        let s = hex::encode(f[pos].value);
        pos += 1;
        Some(s)
    } else {
        None
    };
    let sequence_number_hex = if f.get(pos).is_some_and(|n| n.tag == 2) {
        let s = hex::encode(f[pos].value);
        pos += 1;
        Some(s)
    } else {
        None
    };
    let this_update = time(*f.get(pos).ok_or_else(|| bad("missing CTL time"))?)?;
    pos += 1;
    let next_update = if f.get(pos).is_some_and(|n| matches!(n.tag, 0x17 | 0x18)) {
        let s = time(f[pos])?;
        pos += 1;
        Some(s)
    } else {
        None
    };
    let subject_algorithm = algorithm(field(&f, pos, 0x30)?)?;
    pos += 1;
    let mut members = Vec::new();
    let mut identifiers = std::collections::HashMap::new();
    if f.get(pos).is_some_and(|n| n.tag == 0x30) {
        let entries = children(f[pos])?;
        pos += 1;
        if entries.len() > limits.max_members {
            return Err(CatalogError::Limit("members"));
        }
        for member in entries {
            let m = children(tagged(member, 0x30)?)?;
            if m.len() != 2 {
                return Err(bad("invalid CTL member"));
            }
            let identifier_hex = hex::encode(tagged(m[0], 4)?.value);
            let attrs = attributes(tagged(m[1], 0x31)?)?;
            let raw = children(m[1])?;
            let mut indirect_data = None;
            let mut indirect_der = None;
            for attr in raw {
                let a = children(attr)?;
                if oid(a[0])? == INDIRECT {
                    if indirect_data.is_some() {
                        return Err(bad("duplicate indirect data"));
                    }
                    let vals = children(a[1])?;
                    if vals.len() != 1 {
                        return Err(bad("multiple indirect data values"));
                    }
                    indirect_data = Some(indirect(vals[0])?);
                    indirect_der = Some(vals[0].full);
                }
            }
            // A catalog can bind identical content to several authenticated Hint
            // names. Retain every signed row. Identical opaque rows remain
            // inspectable, but never supply SIP membership. Differing rows must
            // carry exactly the same supported SIP/digest DER; whole-row equality
            // would incorrectly reject differing member-info metadata.
            if let Some(previous) =
                identifiers.insert(identifier_hex.clone(), (member.full, indirect_der))
            {
                let supported = indirect_data.as_ref().is_some_and(|data| {
                    matches!(
                        data.data_type.as_str(),
                        "1.3.6.1.4.1.311.2.1.15"
                            | "1.3.6.1.4.1.311.2.1.18"
                            | "1.3.6.1.4.1.311.2.1.25"
                    ) && matches!(
                        data.digest_algorithm.as_str(),
                        "1.3.14.3.2.26"
                            | "2.16.840.1.101.3.4.2.1"
                            | "2.16.840.1.101.3.4.2.2"
                            | "2.16.840.1.101.3.4.2.3"
                    )
                });
                if previous.0 != member.full
                    && (!supported || indirect_der.is_none() || previous.1 != indirect_der)
                {
                    return Err(bad("conflicting duplicate CTL member identifier"));
                }
            }
            members.push(CatalogMember {
                identifier_hex,
                attributes: attrs,
                indirect_data,
            });
        }
    }
    let extensions_der_hex = if f.get(pos).is_some_and(|n| n.tag == 0xa0) {
        let s = hex::encode(f[pos].full);
        pos += 1;
        Some(s)
    } else {
        None
    };
    if pos != f.len() {
        return Err(bad("unexpected CTL fields"));
    }
    Ok(CertificateTrustList {
        version,
        subject_usage,
        list_identifier_hex,
        sequence_number_hex,
        this_update,
        next_update,
        subject_algorithm,
        members,
        extensions_der_hex,
        encoded_hex: hex::encode(n.full),
    })
}
pub(crate) fn preflight(
    root: Node<'_>,
    limits: CatalogLimits,
    count: &mut usize,
) -> Result<(), CatalogError> {
    let mut stack = vec![(root, 0)];
    while let Some((n, depth)) = stack.pop() {
        *count += 1;
        if *count > limits.max_nodes {
            return Err(CatalogError::Limit("nodes"));
        }
        if depth > limits.max_depth {
            return Err(CatalogError::Limit("depth"));
        }
        if n.tag & 0x20 != 0 {
            let mut rest = n.value;
            let mut previous: Option<&[u8]> = None;
            while !rest.is_empty() {
                let (child, size) = node(rest)?;
                if n.tag == 0x31 && previous.is_some_and(|p| p > child.full) {
                    return Err(bad("noncanonical SET OF order"));
                }
                previous = Some(child.full);
                stack.push((child, depth + 1));
                rest = &rest[size..];
                if stack.len() > limits.max_nodes {
                    return Err(CatalogError::Limit("nodes"));
                }
            }
        }
    }
    Ok(())
}
/// Inspect a strict DER catalog, retaining unknown attribute OIDs without assigning trust.
pub fn parse(bytes: &[u8], limits: CatalogLimits) -> Result<Catalog, CatalogError> {
    if bytes.len() > limits.max_bytes {
        return Err(CatalogError::Limit("bytes"));
    }
    // Preflight every constructed value before allocating output, including nested timestamp data.
    let (root, len) = node(bytes)?;
    if len != bytes.len() {
        return Err(bad("trailing bytes"));
    }
    let mut count = 0;
    preflight(root, limits, &mut count)?;
    let outer = children(tagged(root, 0x30)?)?;
    if outer.len() != 2 || oid(outer[0])? != SIGNED_DATA {
        return Err(CatalogError::Unsupported(
            "expected PKCS#7 SignedData".into(),
        ));
    }
    let wrapper = children(tagged(outer[1], 0xa0)?)?;
    if wrapper.len() != 1 {
        return Err(bad("invalid SignedData wrapper"));
    }
    let sd = children(tagged(wrapper[0], 0x30)?)?;
    integer(field(&sd, 0, 2)?)?;
    let digest_algorithms = children(field(&sd, 1, 0x31)?)?
        .into_iter()
        .map(algorithm)
        .collect::<Result<Vec<_>, _>>()?;
    let content = children(field(&sd, 2, 0x30)?)?;
    if content.len() != 2 {
        return Err(bad("detached or invalid catalog content"));
    }
    let content_type = oid(content[0])?;
    if content_type != CTL {
        return Err(CatalogError::Unsupported(format!(
            "content type {content_type}"
        )));
    }
    let encap = children(tagged(content[1], 0xa0)?)?;
    if encap.len() != 1 {
        return Err(bad("invalid CTL wrapper"));
    }
    let ctl_node = if encap[0].tag == 4 {
        let (n, len) = node(encap[0].value)?;
        if len != encap[0].value.len() {
            return Err(bad("trailing CTL bytes"));
        }
        preflight(n, limits, &mut count)?;
        n
    } else {
        encap[0]
    };
    let ctl = ctl(ctl_node, limits)?;
    let mut pos = 3;
    let certificate_count = if sd.get(pos).is_some_and(|n| n.tag == 0xa0) {
        let count = children(sd[pos])?.len();
        pos += 1;
        count
    } else {
        0
    };
    if sd.get(pos).is_some_and(|n| n.tag == 0xa1) {
        pos += 1;
    }
    let signers = children(field(&sd, pos, 0x31)?)?
        .into_iter()
        .map(signer)
        .collect::<Result<Vec<_>, _>>()?;
    pos += 1;
    if pos != sd.len() {
        return Err(bad("unexpected SignedData fields"));
    }
    Ok(Catalog {
        content_type,
        digest_algorithms,
        certificate_count,
        signers,
        ctl,
        trust_established: false,
    })
}

/// Match flat XML MUM/manifest bytes against parsed indirect-data digests.
/// This checks membership only; neither the catalog signature nor its signer is verified.
/// PE and other SIP-specific formats are deliberately excluded.
pub fn match_flat_xml_member(catalog: &Catalog, bytes: &[u8]) -> Result<Vec<usize>, CatalogError> {
    use sha2::Digest;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CatalogError::Unsupported("flat member must be UTF-8 XML".into()))?;
    let xml = roxmltree::Document::parse(text)
        .map_err(|_| CatalogError::Unsupported("flat member must be XML".into()))?;
    if xml.root_element().tag_name().name() != "assembly" {
        return Err(CatalogError::Unsupported(
            "flat member must be an assembly MUM/manifest".into(),
        ));
    }
    let sha1 = hex::encode(sha1::Sha1::digest(bytes));
    let sha256 = hex::encode(sha2::Sha256::digest(bytes));
    let mut matched = Vec::new();
    for (index, member) in catalog.ctl.members.iter().enumerate() {
        if let Some(indirect) = &member.indirect_data {
            if indirect.data_type != "1.3.6.1.4.1.311.2.1.25" {
                continue;
            }
            let digest = match indirect.digest_algorithm.as_str() {
                "1.3.14.3.2.26" => &sha1,
                "2.16.840.1.101.3.4.2.1" => &sha256,
                _ => continue,
            };
            if indirect.digest_hex == *digest {
                matched.push(index);
            }
        }
    }
    Ok(matched)
}
