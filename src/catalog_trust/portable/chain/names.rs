//! RFC 5280 name-constraint normalization and matching.
use crate::error::{Context, Error, Result, bail, ensure};
use alloc::{
    borrow::ToOwned,
    format,
    string::{String, ToString},
    vec::Vec,
};
use der::{Tag, Tagged};
use x509_cert::Certificate;

// RFC 5280 4.2.1.10/6.1: every issuer's permitted union is intersected
// with other issuers' unions; excluded subtrees take precedence. Evaluate the
// path-local descendants instead of merging heterogeneous subtree encodings.
pub(super) fn validate_name_constraints(
    value: &x509_cert::ext::pkix::NameConstraints,
) -> Result<()> {
    use x509_cert::ext::pkix::name::GeneralName;
    ensure!(
        value.permitted_subtrees.is_some() || value.excluded_subtrees.is_some(),
        Error::malformed("empty name constraints")
    );
    for subtrees in [&value.permitted_subtrees, &value.excluded_subtrees]
        .into_iter()
        .flatten()
    {
        ensure!(
            !subtrees.is_empty() && subtrees.len() <= 256,
            Error::resource_limit("name constraint subtree count limit")
        );
        for subtree in subtrees {
            // RFC 5280 4.2.1.10: other values must be processed or rejected. Level
            // distances are defined for domain names and distinguished names only.
            if subtree.minimum != 0 || subtree.maximum.is_some() {
                ensure!(
                    matches!(
                        subtree.base,
                        GeneralName::DnsName(_) | GeneralName::DirectoryName(_)
                    ),
                    Error::unsupported("unsupported name constraint minimum/maximum")
                );
                ensure!(
                    subtree.maximum.is_none_or(|max| max >= subtree.minimum),
                    "name constraint maximum below minimum"
                );
            }
            match &subtree.base {
                GeneralName::DnsName(name) | GeneralName::UniformResourceIdentifier(name) => {
                    validate_domain(name.as_str().strip_prefix('.').unwrap_or(name.as_str()))?;
                }
                GeneralName::Rfc822Name(name) => {
                    if name.as_str().contains('@') {
                        split_mailbox(name.as_str())?;
                    } else {
                        validate_domain(name.as_str().strip_prefix('.').unwrap_or(name.as_str()))?;
                    }
                }
                GeneralName::IpAddress(bytes) => {
                    let bytes = bytes.as_bytes();
                    ensure!(
                        matches!(bytes.len(), 8 | 32),
                        Error::malformed("invalid IP name constraint length")
                    );
                    let half = bytes.len() / 2;
                    let mut zero = false;
                    for byte in &bytes[half..] {
                        for bit in (0..8).rev() {
                            if byte & (1 << bit) == 0 {
                                zero = true;
                            } else {
                                ensure!(
                                    !zero,
                                    Error::unsupported(
                                        "unsupported non-contiguous IP constraint mask"
                                    )
                                );
                            }
                        }
                    }
                }
                GeneralName::DirectoryName(name) => {
                    ensure!(
                        !name.0.is_empty(),
                        Error::malformed("empty directory name constraint")
                    );
                    normalize_dn(name)?;
                }
                _ => bail!(Error::unsupported("unsupported name constraint form")),
            }
        }
    }
    Ok(())
}

fn validate_domain(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name.len() <= 253,
        Error::malformed("invalid constrained domain length")
    );
    for label in name.split('.') {
        ensure!(
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            Error::malformed("invalid constrained domain label")
        );
    }
    Ok(())
}

fn domain_matches(name: &str, constraint: &str, exact_host: bool) -> Result<bool> {
    validate_domain(name)?;
    let descendants_only = constraint.starts_with('.');
    let base = constraint.strip_prefix('.').unwrap_or(constraint);
    validate_domain(base)?;
    if name.eq_ignore_ascii_case(base) {
        return Ok(!descendants_only);
    }
    if exact_host && !descendants_only {
        return Ok(false);
    }
    Ok(name.len() > base.len()
        && name.as_bytes()[name.len() - base.len() - 1] == b'.'
        && name[name.len() - base.len()..].eq_ignore_ascii_case(base))
}

fn split_mailbox(mailbox: &str) -> Result<(&str, &str)> {
    let (local, host) = mailbox
        .split_once('@')
        .context("invalid constrained mailbox")?;
    ensure!(
        !local.is_empty()
            && local
                .bytes()
                .all(|byte| byte.is_ascii() && !byte.is_ascii_control() && byte != b'@'),
        Error::unsupported("unsupported constrained mailbox local part")
    );
    validate_domain(host)?;
    Ok((local, host))
}

/// The DNS host of a URI, or `None` when it has no authority or names an IP
/// address. Such URIs lie outside every domain subtree (RFC 5280 4.2.1.10), so
/// they can never satisfy a permitted URI constraint nor be excluded by one.
fn uri_host(uri: &str) -> Result<Option<&str>> {
    let (scheme, rest) = match uri.split_once(':') {
        Some(parts) => parts,
        None => bail!(Error::malformed("invalid URI")),
    };
    ensure!(
        !scheme.is_empty()
            && scheme.as_bytes()[0].is_ascii_alphabetic()
            && scheme
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')),
        Error::malformed("invalid URI scheme")
    );
    let Some(rest) = rest.strip_prefix("//") else {
        return Ok(None);
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if authority.starts_with('[') {
        let end = authority.find(']').context("invalid URI IP literal")?;
        let tail = &authority[end + 1..];
        ensure!(
            tail.is_empty()
                || tail
                    .strip_prefix(':')
                    .is_some_and(|port| port.bytes().all(|byte| byte.is_ascii_digit())),
            Error::malformed("invalid URI port")
        );
        return Ok(None);
    }
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if let Some(port) = port {
        ensure!(
            !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()),
            Error::malformed("invalid URI port")
        );
    }
    if host.parse::<core::net::Ipv4Addr>().is_ok() {
        return Ok(None);
    }
    validate_domain(host)?;
    Ok(Some(host))
}

/// RFC 4518 string preparation as profiled by RFC 5280 7.1 for case-ignore
/// matching: map, case fold, NFKC, prohibit and bidirectional checks, then
/// insignificant-space handling. Anything the profile prohibits is an error.
fn prepare_string(text: &str) -> Result<String> {
    let mut mapped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\u{9}'..='\u{d}'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}' => mapped.push(' '),
            '\u{0}'..='\u{8}'
            | '\u{e}'..='\u{1f}'
            | '\u{7f}'..='\u{84}'
            | '\u{86}'..='\u{9f}'
            | '\u{6dd}'
            | '\u{70f}'
            | '\u{180e}'
            | '\u{200c}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2063}'
            | '\u{206a}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffc}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}' => {}
            c => mapped.push(c),
        }
    }
    let folded = crate::stringprep::nameprep(&mapped).map_err(|error| {
        Error::policy(format!("prohibited directory string character: {error:?}"))
    })?;
    // Insignificant spaces: trim, collapse internal runs, and keep one space for an empty value.
    let collapsed = folded.split_whitespace().collect::<Vec<_>>().join(" ");
    Ok(if collapsed.is_empty() {
        " ".to_owned()
    } else {
        collapsed
    })
}

fn directory_string_text(value: &der::asn1::Any) -> Result<String> {
    let bytes = value.value();
    match value.tag() {
        Tag::Utf8String => Ok(core::str::from_utf8(bytes)?.to_owned()),
        Tag::PrintableString | Tag::Ia5String => {
            ensure!(bytes.is_ascii(), "non-ASCII restricted directory string");
            Ok(core::str::from_utf8(bytes)?.to_owned())
        }
        // TeletexString has no unambiguous mapping beyond ASCII; fail closed.
        Tag::TeletexString => {
            ensure!(
                bytes.is_ascii(),
                Error::unsupported("unsupported TeletexString repertoire")
            );
            Ok(core::str::from_utf8(bytes)?.to_owned())
        }
        Tag::BmpString => {
            ensure!(
                bytes.len().is_multiple_of(2),
                Error::malformed("invalid BMPString")
            );
            char::decode_utf16(
                bytes
                    .chunks_exact(2)
                    .map(|pair| u16::from_be_bytes([pair[0], pair[1]])),
            )
            .collect::<core::result::Result<String, _>>()
            .map_err(|_| Error::malformed("invalid BMPString"))
        }
        _ => bail!(Error::unsupported(
            "unsupported directory name attribute syntax"
        )),
    }
}

fn normalize_dn(name: &x509_cert::name::Name) -> Result<Vec<Vec<(String, String)>>> {
    name.0
        .iter()
        .map(|rdn| {
            let mut attributes = rdn
                .0
                .iter()
                .map(|attribute| {
                    let text = directory_string_text(&attribute.value)?;
                    let oid = attribute.oid.to_string();
                    let normalized = if oid == "1.2.840.113549.1.9.1" {
                        ensure!(
                            text.is_ascii(),
                            Error::unsupported("unsupported international email attribute")
                        );
                        let (local, host) = split_mailbox(&text)?;
                        format!("{local}@{}", host.to_ascii_lowercase())
                    } else {
                        ensure!(
                            matches!(
                                oid.as_str(),
                                "2.5.4.3"
                                    | "2.5.4.4"
                                    | "2.5.4.5"
                                    | "2.5.4.6"
                                    | "2.5.4.7"
                                    | "2.5.4.8"
                                    | "2.5.4.9"
                                    | "2.5.4.10"
                                    | "2.5.4.11"
                                    | "2.5.4.12"
                                    | "2.5.4.13"
                                    | "2.5.4.15"
                                    | "2.5.4.17"
                                    | "2.5.4.41"
                                    | "2.5.4.42"
                                    | "2.5.4.43"
                                    | "2.5.4.44"
                                    | "2.5.4.46"
                                    | "2.5.4.65"
                                    | "0.9.2342.19200300.100.1.25"
                            ),
                            Error::unsupported(format!(
                                "unsupported directory name attribute matching rule {oid}"
                            ))
                        );
                        prepare_string(&text)?
                    };
                    Ok((oid, normalized))
                })
                .collect::<Result<Vec<_>>>()?;
            attributes.sort();
            Ok(attributes)
        })
        .collect()
}

fn same_name_form(
    a: &x509_cert::ext::pkix::name::GeneralName,
    b: &x509_cert::ext::pkix::name::GeneralName,
) -> bool {
    core::mem::discriminant(a) == core::mem::discriminant(b)
}

/// Levels `name` lies below `base` (0 when equal), or `None` when it is not a
/// descendant. A leading dot on `base` excludes the base itself.
fn dns_depth(name: &str, constraint: &str) -> Result<Option<usize>> {
    validate_domain(name)?;
    let descendants_only = constraint.starts_with('.');
    let base = constraint.strip_prefix('.').unwrap_or(constraint);
    validate_domain(base)?;
    if name.eq_ignore_ascii_case(base) {
        return Ok((!descendants_only).then_some(0));
    }
    if name.len() > base.len()
        && name.as_bytes()[name.len() - base.len() - 1] == b'.'
        && name[name.len() - base.len()..].eq_ignore_ascii_case(base)
    {
        let prefix = &name[..name.len() - base.len() - 1];
        return Ok(Some(prefix.split('.').count()));
    }
    Ok(None)
}

fn within_levels(
    depth: Option<usize>,
    subtree: &x509_cert::ext::pkix::constraints::name::GeneralSubtree,
) -> bool {
    depth.is_some_and(|depth| {
        depth as u64 >= u64::from(subtree.minimum)
            && subtree
                .maximum
                .is_none_or(|max| depth as u64 <= u64::from(max))
    })
}

fn within_subtree(
    name: &x509_cert::ext::pkix::name::GeneralName,
    subtree: &x509_cert::ext::pkix::constraints::name::GeneralSubtree,
) -> Result<bool> {
    use x509_cert::ext::pkix::name::GeneralName;
    let base = &subtree.base;
    match (name, base) {
        (GeneralName::DnsName(name), GeneralName::DnsName(base)) => Ok(within_levels(
            dns_depth(name.as_str(), base.as_str())?,
            subtree,
        )),
        (GeneralName::Rfc822Name(name), GeneralName::Rfc822Name(base)) => {
            let (local, host) = split_mailbox(name.as_str())?;
            if base.as_str().contains('@') {
                let (expected_local, expected_host) = split_mailbox(base.as_str())?;
                Ok(local == expected_local && host.eq_ignore_ascii_case(expected_host))
            } else {
                domain_matches(host, base.as_str(), true)
            }
        }
        (
            GeneralName::UniformResourceIdentifier(name),
            GeneralName::UniformResourceIdentifier(base),
        ) => match uri_host(name.as_str())? {
            Some(host) => domain_matches(host, base.as_str(), true),
            None => Ok(false),
        },
        (GeneralName::IpAddress(name), GeneralName::IpAddress(base)) => {
            let (name, base) = (name.as_bytes(), base.as_bytes());
            ensure!(
                matches!(name.len(), 4 | 16),
                Error::malformed("invalid subject IP address length")
            );
            if base.len() != name.len() * 2 {
                return Ok(false);
            }
            Ok(name
                .iter()
                .zip(&base[..name.len()])
                .zip(&base[name.len()..])
                .all(|((name, address), mask)| name & mask == address & mask))
        }
        (GeneralName::DirectoryName(name), GeneralName::DirectoryName(base)) => {
            let (name, base) = (normalize_dn(name)?, normalize_dn(base)?);
            Ok(within_levels(
                name.starts_with(&base).then(|| name.len() - base.len()),
                subtree,
            ))
        }
        _ => Ok(false),
    }
}

pub(super) fn check_certificate_names(
    certificate: &Certificate,
    constraints: &x509_cert::ext::pkix::NameConstraints,
) -> Result<()> {
    use x509_cert::ext::pkix::{SubjectAltName, name::GeneralName};
    let subject = &certificate.tbs_certificate.subject;
    let san = certificate
        .tbs_certificate
        .get::<SubjectAltName>()
        .map_err(Error::malformed)?;
    let mut names = san
        .as_ref()
        .map_or_else(Vec::new, |(_, names)| names.0.clone());
    ensure!(
        names.len() <= 256,
        Error::resource_limit("subject alternative name count limit")
    );
    if !subject.0.is_empty() {
        names.push(GeneralName::DirectoryName(subject.clone()));
    }
    if san.is_none() {
        for rdn in &subject.0 {
            for attribute in rdn.0.iter() {
                if attribute.oid.to_string() == "1.2.840.113549.1.9.1" {
                    names.push(GeneralName::Rfc822Name(
                        attribute
                            .value
                            .decode_as::<der::asn1::Ia5String>()
                            .map_err(Error::malformed)?,
                    ));
                }
            }
        }
    }
    for name in names {
        for excluded in constraints.excluded_subtrees.iter().flatten() {
            if same_name_form(&name, &excluded.base) {
                ensure!(
                    !within_subtree(&name, excluded)?,
                    "certificate name is in excluded subtree"
                );
            }
        }
        let permitted = constraints
            .permitted_subtrees
            .iter()
            .flatten()
            .filter(|subtree| same_name_form(&name, &subtree.base))
            .collect::<Vec<_>>();
        if !permitted.is_empty() {
            let mut matched = false;
            for subtree in permitted {
                matched |= within_subtree(&name, subtree)?;
            }
            ensure!(matched, "certificate name outside permitted subtrees");
        }
    }
    Ok(())
}
