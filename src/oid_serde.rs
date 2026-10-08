//! Preserve dotted-decimal OID strings in serialized reports.
use alloc::{string::ToString, vec::Vec};
use der::asn1::ObjectIdentifier;
use serde::Serializer;

pub fn serialize<S: Serializer>(
    oid: &ObjectIdentifier,
    serializer: S,
) -> core::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&oid.to_string())
}
pub mod vec {
    use super::*;
    use serde::Serialize;
    pub fn serialize<S: Serializer>(
        oids: &[ObjectIdentifier],
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        oids.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
}
