use wintrust::portable::{chain, signed, timestamp};

#[test]
fn timestamp_path_callback_runs_after_binding_and_can_reject_trusted_tsa() {
    let signed = signed::verify_signed_data(
        include_bytes!("fixtures/catalog.cat"),
        "1.3.6.1.4.1.311.10.1",
    )
    .unwrap();
    let roots = vec![include_bytes!("fixtures/root.der").to_vec()];
    let signer = &signed.signers[0];
    let mut calls = 0;
    let accepted = timestamp::verify_timestamps_with_path_policy(
        signer,
        &signed.certificates,
        &roots,
        1791117219,
        false,
        chain::PathLimits::default(),
        |path, time| {
            calls += 1;
            assert!(time <= 1791117219);
            assert!(path.chain_der.len() >= 2);
            Ok(())
        },
    )
    .unwrap()
    .unwrap();
    assert!(calls > 0);
    assert!(!accepted.chain_der.is_empty());
    assert!(
        timestamp::verify_timestamps_with_path_policy(
            signer,
            &signed.certificates,
            &roots,
            1791117219,
            false,
            chain::PathLimits::default(),
            |_, _| anyhow::bail!("TSA path revoked")
        )
        .is_err()
    );
    let mut forged = signer.clone();
    forged.signature[0] ^= 1;
    assert!(
        timestamp::verify_timestamps_with_path_policy(
            &forged,
            &signed.certificates,
            &roots,
            1791117219,
            false,
            chain::PathLimits::default(),
            |_, _| panic!("invalid binding must precede path callback")
        )
        .is_err()
    );
}
