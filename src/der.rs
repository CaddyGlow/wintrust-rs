//! Shared bounded DER traversal; format-specific validation stays with callers.
use crate::catalog::{CatalogError, CatalogLimits, bad};
use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};
use der::{Decode, Reader, SliceReader, asn1::AnyRef};

#[derive(Clone, Copy)]
pub(crate) struct Node<'a> {
    pub(crate) tag: u8,
    pub(crate) full: &'a [u8],
    pub(crate) value: &'a [u8],
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
/// Callers preflight the complete tree before collecting format-specific fields.
pub(crate) fn children(n: Node<'_>) -> Result<Vec<Node<'_>>, CatalogError> {
    all(n.value, usize::MAX)
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
pub(crate) fn typed_oid(n: Node<'_>) -> Result<der::asn1::ObjectIdentifier, CatalogError> {
    tagged(n, 6)?;
    Ok(AnyRef::from_der(n.full)?.decode_as::<der::asn1::ObjectIdentifier>()?)
}
pub(crate) fn oid(n: Node<'_>) -> Result<String, CatalogError> {
    Ok(typed_oid(n)?.to_string())
}
pub(crate) fn all(bytes: &[u8], max_children: usize) -> Result<Vec<Node<'_>>, CatalogError> {
    let mut rest = bytes;
    let mut out = Vec::new();
    while !rest.is_empty() {
        if out.len() >= max_children {
            return Err(CatalogError::Limit("ASN.1 collection"));
        }
        let (n, size) = node(rest)?;
        out.push(n);
        rest = &rest[size..];
    }
    Ok(out)
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
