use wintrust::catalog::{CatalogLimits, parse};
const CAT: &[u8] = include_bytes!("fixtures/ssu-19041.7714-shared.cat");
#[test]
fn genuine_shared_catalog_retains_rows_with_identical_digest_and_different_hints() {
    let catalog = parse(CAT, CatalogLimits::default()).unwrap();
    assert_eq!(catalog.ctl.members.len(), 410);
    let identifier = "1d4364761b7623d701e512c88e3f00608e4082d4d9c025dd4dca795663737c7e";
    let repeated: Vec<_> = catalog
        .ctl
        .members
        .iter()
        .filter(|row| row.identifier_hex == identifier)
        .collect();
    assert_eq!(repeated.len(), 2);
    assert_eq!(
        serde_json::to_value(&repeated[0].indirect_data).unwrap(),
        serde_json::to_value(&repeated[1].indirect_data).unwrap()
    );
    assert_ne!(
        serde_json::to_value(&repeated[0].attributes).unwrap(),
        serde_json::to_value(&repeated[1].attributes).unwrap()
    );
}
#[test]
fn repeated_identifier_with_changed_indirect_digest_is_rejected_before_trust() {
    let digest =
        hex::decode("1d4364761b7623d701e512c88e3f00608e4082d4d9c025dd4dca795663737c7e").unwrap();
    let offsets: Vec<_> = CAT
        .windows(digest.len())
        .enumerate()
        .filter(|(_, bytes)| *bytes == digest)
        .map(|(index, _)| index)
        .collect();
    assert_eq!(offsets.len(), 4);
    // Each row holds identifier then indirect-data digest; change only the last
    // indirect digest, preserving signed structure and the duplicated identifier.
    let mut changed = CAT.to_vec();
    changed[*offsets.last().unwrap()] ^= 1;
    let error = parse(&changed, CatalogLimits::default()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("conflicting duplicate CTL member identifier"),
        "{error}"
    );
}
