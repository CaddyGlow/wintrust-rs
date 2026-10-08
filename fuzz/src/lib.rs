use wintrust::catalog::{CatalogLimits, match_flat_xml_member, parse};
pub fn catalog(data: &[u8]) {
    if data.len() > 1 << 20 {
        return;
    }
    let limits = CatalogLimits {
        max_bytes: 1 << 20,
        max_nodes: 4096,
        max_depth: 32,
        max_members: 128,
    };
    if let Ok(catalog) = parse(data, limits) {
        let _ = match_flat_xml_member(&catalog, b"<assembly/>");
    }
}
pub fn run(target: &str, data: &[u8]) -> Result<(), &'static str> {
    match target {
        "catalog" => catalog(data),
        _ => return Err("unknown fuzz target"),
    }
    Ok(())
}
pub const TARGETS: &[&str] = &["catalog"];
pub fn seeds(target: &str) -> Vec<Vec<u8>> {
    match target {
        "catalog" => vec![
            include_bytes!("../fixtures/basic-en-us.cat").to_vec(),
            vec![],
        ],
        _ => vec![],
    }
}

#[cfg(test)]
mod smoke {
    #[test]
    fn corpus_and_truncations_exercise_owned_harnesses() {
        for target in super::TARGETS {
            for seed in super::seeds(target) {
                super::run(target, &seed).unwrap();
                for end in [0, seed.len() / 2, seed.len().saturating_sub(1)] {
                    super::run(target, &seed[..end]).unwrap();
                }
                for offset in (0..seed.len()).step_by((seed.len() / 16).max(1)) {
                    let mut mutation = seed.clone();
                    mutation[offset] ^= 0xff;
                    super::run(target, &mutation).unwrap();
                }
            }
        }
    }
}
