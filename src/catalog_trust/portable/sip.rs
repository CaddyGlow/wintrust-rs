//! Portable, explicit catalog member hashing. Unknown SIP formats fail closed.
use crate::catalog::Catalog;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// Explicit member format; no extension-based or unknown-format fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SipKind {
    Pe,
    FlatXml,
    FlatRaw,
    Cab,
}
/// Supported digest identifiers; SHA-1 requires explicit compatibility policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}
impl DigestAlgorithm {
    pub fn from_oid(oid: &str) -> Result<Self> {
        match oid {
            "1.3.14.3.2.26" => Ok(Self::Sha1),
            "2.16.840.1.101.3.4.2.1" => Ok(Self::Sha256),
            "2.16.840.1.101.3.4.2.2" => Ok(Self::Sha384),
            "2.16.840.1.101.3.4.2.3" => Ok(Self::Sha512),
            _ => anyhow::bail!("unsupported member digest algorithm {oid}"),
        }
    }
    pub fn oid(self) -> &'static str {
        match self {
            Self::Sha1 => "1.3.14.3.2.26",
            Self::Sha256 => "2.16.840.1.101.3.4.2.1",
            Self::Sha384 => "2.16.840.1.101.3.4.2.2",
            Self::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }
}
/// Resource and legacy-algorithm policy, independent of signature trust.
#[derive(Debug, Clone)]
pub struct MemberHashPolicy {
    pub allow_sha1: bool,
    pub max_member_bytes: usize,
}
impl Default for MemberHashPolicy {
    fn default() -> Self {
        Self {
            allow_sha1: false,
            max_member_bytes: 256 * 1024 * 1024,
        }
    }
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    hexspell::utils::extract_u16(bytes, offset).context("truncated member field")
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    hexspell::utils::extract_u32(bytes, offset).context("truncated member field")
}
fn range(bytes: &[u8], start: usize, length: usize) -> Result<&[u8]> {
    bytes
        .get(start..start.checked_add(length).context("member range overflow")?)
        .context("member range outside file")
}

fn pe_chunks(bytes: &[u8]) -> Result<Vec<&[u8]>> {
    let parsed = hexspell::pe::view::PeHeaders::parse(bytes).context("invalid PE headers")?;
    let pe = parsed.nt;
    ensure!(pe >= 0x40, "invalid PE signature");
    let sections = usize::from(parsed.coff.number_of_sections.value);
    ensure!(sections <= 4096, "excessive PE section count");
    let optional_length = usize::from(parsed.coff.size_of_optional_header.value);
    let optional = parsed.optional;
    range(bytes, optional, optional_length)?;
    let directory = parsed
        .directory_offset()
        .context("unsupported PE optional header")?;
    let count_offset = directory - 4;
    ensure!(optional_length >= directory, "truncated PE optional header");
    let headers = u32_at(bytes, optional + 60)? as usize;
    let checksum = optional + 64;
    let count = u32_at(bytes, optional + count_offset)? as usize;
    ensure!(
        count <= (optional_length - directory) / 8,
        "PE directory count exceeds optional header"
    );
    let security = optional + directory + 4 * 8;
    let (certificate, certificate_size) = if count > 4 {
        let (offset, size) = parsed.directory_slot(4)?;
        (offset as usize, size as usize)
    } else {
        (0, 0)
    };
    ensure!(
        (certificate == 0) == (certificate_size == 0),
        "incomplete PE certificate table range"
    );
    let section_table = optional + optional_length;
    let section_table_end = section_table
        .checked_add(sections * 40)
        .context("PE section table overflow")?;
    ensure!(
        headers >= section_table_end && headers <= bytes.len(),
        "invalid PE header size"
    );
    ensure!(checksum + 4 <= headers, "PE checksum lies outside headers");
    let mut chunks = vec![range(bytes, 0, checksum)?];
    if count > 4 {
        ensure!(
            security >= checksum + 4 && security + 8 <= headers,
            "PE security directory lies outside headers"
        );
        chunks.push(range(bytes, checksum + 4, security - checksum - 4)?);
        chunks.push(range(bytes, security + 8, headers - security - 8)?);
    } else {
        chunks.push(range(bytes, checksum + 4, headers - checksum - 4)?);
    }
    let mut raw = Vec::new();
    for index in 0..sections {
        let section = parsed.section(index).context("invalid PE section header")?;
        let size = section.size_of_raw_data.value as usize;
        let start = section.pointer_to_raw_data.value as usize;
        if size > 0 {
            ensure!(start >= headers, "PE section overlaps headers");
            range(bytes, start, size)?;
            raw.push((start, size));
        }
    }
    raw.sort_unstable();
    let mut last = headers;
    let mut sum = headers;
    for (start, size) in raw {
        ensure!(start >= last, "overlapping PE raw sections");
        last = start.checked_add(size).context("PE section end overflow")?;
        sum = sum.checked_add(size).context("PE hashed size overflow")?;
        chunks.push(range(bytes, start, size)?);
    }
    let end = if certificate_size > 0 {
        ensure!(
            certificate % 8 == 0
                && certificate >= last
                && certificate.checked_add(certificate_size) == Some(bytes.len()),
            "unsupported nonterminal or overlapping PE certificate table"
        );
        let mut cursor = certificate;
        while cursor < bytes.len() {
            let length = u32_at(bytes, cursor)? as usize;
            ensure!(length >= 8, "invalid WIN_CERTIFICATE length");
            let rounded = length
                .checked_add(7)
                .context("certificate length overflow")?
                & !7;
            cursor = cursor
                .checked_add(rounded)
                .context("certificate offset overflow")?;
            ensure!(cursor <= bytes.len(), "truncated WIN_CERTIFICATE");
        }
        certificate
    } else {
        bytes.len()
    };
    // Authenticode's extra-data rule starts at SizeOfHeaders + sum(raw sizes),
    // not at the largest section end. This matters for gapped section layouts.
    ensure!(sum <= end, "PE sum of hashed bytes exceeds payload extent");
    if end > sum {
        chunks.push(range(bytes, sum, end - sum)?);
    }
    Ok(chunks)
}

fn flat_xml(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("flat XML member is not UTF-8")?;
    let xml = roxmltree::Document::parse(text).context("invalid flat XML member")?;
    ensure!(
        xml.root_element().tag_name().name() == "assembly",
        "flat XML member must be an assembly MUM/manifest"
    );
    Ok(())
}
fn flat_raw(bytes: &[u8]) -> Result<()> {
    for magic in [
        b"MZ".as_slice(),
        b"MSCF",
        b"PK\x03\x04",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        b"MSWIM\0\0\0",
    ] {
        ensure!(
            !bytes.starts_with(magic),
            "flat raw member resembles a format requiring a dedicated SIP"
        );
    }
    Ok(())
}

/// Compute a catalog-member digest. This does not verify a catalog signature.
pub fn member_hash(
    bytes: &[u8],
    kind: SipKind,
    algorithm: DigestAlgorithm,
    policy: &MemberHashPolicy,
) -> Result<String> {
    ensure!(
        bytes.len() <= policy.max_member_bytes,
        "catalog member exceeds byte limit"
    );
    ensure!(
        algorithm != DigestAlgorithm::Sha1 || policy.allow_sha1,
        "SHA-1 member digest requires explicit compatibility policy"
    );
    let chunks = match kind {
        SipKind::Pe => pe_chunks(bytes)?,
        SipKind::FlatXml => {
            flat_xml(bytes)?;
            vec![bytes]
        }
        SipKind::FlatRaw => {
            flat_raw(bytes)?;
            vec![bytes]
        }
        SipKind::Cab => cab_chunks(bytes)?,
    };
    macro_rules! hash {
        ($algorithm:ty) => {{
            let mut hash = <$algorithm>::new();
            for chunk in chunks {
                hash.update(chunk);
            }
            hex::encode(hash.finalize())
        }};
    }
    Ok(match algorithm {
        DigestAlgorithm::Sha1 => hash!(sha1::Sha1),
        DigestAlgorithm::Sha256 => hash!(sha2::Sha256),
        DigestAlgorithm::Sha384 => hash!(sha2::Sha384),
        DigestAlgorithm::Sha512 => hash!(sha2::Sha512),
    })
}

/// Return member indices whose declared data type and digest match this format.
/// Unknown algorithms/types are not treated as flat hashes.
pub fn match_catalog_member(
    catalog: &Catalog,
    bytes: &[u8],
    kind: SipKind,
    policy: &MemberHashPolicy,
) -> Result<Vec<usize>> {
    ensure!(
        bytes.len() <= policy.max_member_bytes,
        "catalog member exceeds byte limit"
    );
    let mut matched = Vec::new();
    let mut hashes: [Option<String>; 4] = [None, None, None, None];
    for (index, member) in catalog.ctl.members.iter().enumerate() {
        let Some(indirect) = &member.indirect_data else {
            continue;
        };
        let compatible = match kind {
            SipKind::Pe => indirect.data_type == "1.3.6.1.4.1.311.2.1.15",
            SipKind::FlatXml | SipKind::FlatRaw => matches!(
                indirect.data_type.as_str(),
                "1.3.6.1.4.1.311.2.1.18" | "1.3.6.1.4.1.311.2.1.25"
            ),
            SipKind::Cab => indirect.data_type == "1.3.6.1.4.1.311.2.1.25",
        };
        if !compatible {
            continue;
        }
        let Ok(algorithm) = DigestAlgorithm::from_oid(&indirect.digest_algorithm) else {
            continue;
        };
        if algorithm == DigestAlgorithm::Sha1 && !policy.allow_sha1 {
            continue;
        }
        let cache_index = match algorithm {
            DigestAlgorithm::Sha1 => 0,
            DigestAlgorithm::Sha256 => 1,
            DigestAlgorithm::Sha384 => 2,
            DigestAlgorithm::Sha512 => 3,
        };
        if hashes[cache_index].is_none() {
            hashes[cache_index] = Some(member_hash(bytes, kind, algorithm, policy)?);
        }
        if hashes[cache_index]
            .as_deref()
            .is_some_and(|hash| hash.eq_ignore_ascii_case(&indirect.digest_hex))
        {
            matched.push(index);
        }
    }
    Ok(matched)
}

fn cab_chunks(bytes: &[u8]) -> Result<Vec<&[u8]>> {
    ensure!(
        bytes.starts_with(b"MSCF") && bytes.len() >= 36,
        "invalid CAB signature/header"
    );
    ensure!(
        u32_at(bytes, 4)? == 0 && u32_at(bytes, 12)? == 0 && u32_at(bytes, 20)? == 0,
        "invalid CAB reserved fields"
    );
    ensure!(bytes[24] == 3 && bytes[25] == 1, "unsupported CAB version");
    let flags = u16_at(bytes, 30)?;
    ensure!(flags & !7 == 0, "unknown CAB flags");
    let cabinet_size = u32_at(bytes, 8)? as usize;
    let files_offset = u32_at(bytes, 16)? as usize;
    let folders = u16_at(bytes, 26)? as usize;
    let (header_end, payload_end, signed) = if flags & 4 != 0 {
        ensure!(
            u32_at(bytes, 36)? == 20 && u32_at(bytes, 40)? == 0x0010_0000,
            "unsupported CAB reserve/SIP layout"
        );
        let signature = u32_at(bytes, 44)? as usize;
        let signature_size = u32_at(bytes, 48)? as usize;
        ensure!(
            signature >= 60
                && signature == cabinet_size
                && signature_size > 0
                && signature.checked_add(signature_size) == Some(bytes.len()),
            "invalid signed CAB signature range"
        );
        (60, signature, true)
    } else {
        ensure!(
            cabinet_size == bytes.len(),
            "CAB size differs from file extent"
        );
        (36, bytes.len(), false)
    };
    let mut folder_start = header_end;
    for flag in [1, 2] {
        if flags & flag != 0 {
            for _ in 0..2 {
                let remaining = range(
                    bytes,
                    folder_start,
                    payload_end
                        .checked_sub(folder_start)
                        .context("CAB name outside payload")?,
                )?;
                let length = remaining
                    .iter()
                    .position(|byte| *byte == 0)
                    .context("unterminated CAB volume name")?
                    + 1;
                folder_start += length;
            }
        }
    }
    let folder_end = folder_start
        .checked_add(folders * 8)
        .context("CAB folder range overflow")?;
    ensure!(
        folder_end == files_offset && folder_end <= payload_end,
        "CAB file table does not follow folder table"
    );
    for folder in 0..folders {
        let data = u32_at(bytes, folder_start + folder * 8)? as usize;
        ensure!(
            data >= files_offset && data <= payload_end,
            "CAB folder data outside payload"
        );
    }
    if signed {
        Ok(vec![
            range(bytes, 0, 4)?,
            range(bytes, 8, 26)?,
            range(bytes, 56, payload_end - 56)?,
        ])
    } else {
        Ok(vec![range(bytes, 0, 4)?, range(bytes, 8, bytes.len() - 8)?])
    }
}
