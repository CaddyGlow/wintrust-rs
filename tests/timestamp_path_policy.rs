use wintrust::portable::{chain, signed, timestamp};

#[test]
fn timestamp_path_callback_runs_after_binding_and_can_reject_trusted_tsa() {
    let signed = signed::verify_signed_data(
        include_bytes!("fixtures/catalog.cat"),
        &signed::SignedDataOptions::new("1.3.6.1.4.1.311.10.1".parse().unwrap()),
    )
    .unwrap();
    let roots = vec![include_bytes!("fixtures/root.der").to_vec()];
    let signer = &signed.signers[0];
    let options = timestamp::TimestampOptions {
        issuer_candidates: (&signed.certificates).into(),
        ..timestamp::TimestampOptions::new((&roots).into(), 1791117219)
    };
    let mut calls = 0;
    let accepted = timestamp::verify_timestamps_with_path_policy(signer, &options, |path, time| {
        calls += 1;
        assert!(time <= 1791117219);
        assert!(path.chain_der.len() >= 2);
        Ok(())
    })
    .unwrap()
    .unwrap();
    assert!(calls > 0);
    assert!(!accepted.chain_der.is_empty());
    assert!(
        timestamp::verify_timestamps_with_path_policy(signer, &options, |_, _| Err(
            wintrust::Error::policy("TSA path revoked")
        ))
        .is_err()
    );
    let mut forged = signer.clone();
    forged.signature[0] ^= 1;
    assert!(
        timestamp::verify_timestamps_with_path_policy(&forged, &options, |_, _| panic!(
            "invalid binding must precede path callback"
        ))
        .is_err()
    );
}

#[test]
fn ordinary_and_callback_timestamp_verification_enforce_configured_path_limits() {
    let cms = signed::verify_signed_data(
        include_bytes!("fixtures/catalog.cat"),
        &signed::SignedDataOptions::new("1.3.6.1.4.1.311.10.1".parse().unwrap()),
    )
    .unwrap();
    let roots = vec![include_bytes!("fixtures/root.der").to_vec()];
    for path_limits in [
        chain::PathLimits {
            max_depth: 1,
            ..Default::default()
        },
        chain::PathLimits {
            max_signature_checks: 0,
            ..Default::default()
        },
        chain::PathLimits {
            max_store_bytes: 1,
            ..Default::default()
        },
    ] {
        let options = timestamp::TimestampOptions {
            issuer_candidates: (&cms.certificates).into(),
            path_limits,
            ..timestamp::TimestampOptions::new((&roots).into(), 1791117219)
        };
        assert!(timestamp::verify_timestamps(&cms.signers[0], &options).is_err());
        assert!(
            timestamp::verify_timestamps_with_path_policy(
                &cms.signers[0],
                &options,
                |_, _| panic!("excess work must fail before acceptance"),
            )
            .is_err()
        );
    }
}
