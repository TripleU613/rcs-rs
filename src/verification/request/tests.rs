use super::*;
use crate::consent::{Attestation, BuildInfo, CachedToken};
use std::time::SystemTime;
pub(super) const SESSION: &str = "00000000-0000-4000-8000-000000000000";
pub(super) const CARRIER: &str = "{\"ap2009\":{\"TemporaryToken\":\"synthetic-carrier-token\"},\"Vers\":{\"version\":1,\"validity\":3600}}";
pub(super) fn identity(cached: bool) -> ConsentRequest {
    ConsentRequest {
        iid_token: "synthetic-iid".into(),
        checkin_android_id: 123456,
        user_serial: 0,
        public_key_der: include_bytes!("../../../tests/fixtures/consent-public-key.der").to_vec(),
        build: BuildInfo {
            locale: "en_US".into(),
            gms_version_code: 263737035,
            gms_version_name: "26.37.37".into(),
            android_sdk: 37,
            model: "Generic".into(),
            manufacturer: "Example".into(),
            fingerprint: None,
        },
        attestation: if cached {
            Attestation::Cached(
                CachedToken::new(
                    "synthetic-cache".into(),
                    SystemTime::now() + Duration::from_secs(3600),
                )
                .unwrap(),
            )
        } else {
            Attestation::RawDroidGuard("synthetic-sync-proof".into())
        },
        policy: "upi-carrier-tos-ts43".into(),
        calling_package: "org.example.sms".into(),
    }
}
fn operator() -> OperatorInfo {
    OperatorInfo {
        country: "us".into(),
        code: "00101".into(),
        name: "Test".into(),
    }
}
pub(super) fn sim() -> InitialSync {
    InitialSync {
        session_id: SESSION.into(),
        caller_session_id: "11111111-1111-4111-8111-111111111111".into(),
        caller_certificate_sha1: [1; 20],
        imsi: "001010000000001".into(),
        number: Some("+15550000001".into()),
        iccid: Some("8901000000000000000".into()),
        slot_index: 0,
        subscription_id: 1,
        telephony: TelephonyInfo {
            phone_type: 1,
            gid1: "00".into(),
            sim_operator: operator(),
            network_operator: operator(),
            roaming: 2,
            phone_count: 1,
            max_subscriptions: 2,
        },
    }
}
#[test]
fn sync_binds_the_caller_nonce_to_real_sim_and_keeps_session_and_slot_fields() {
    let request = make_sync(&identity(false), &sim()).unwrap();
    assert_eq!(
        request.encode_to_vec(),
        include_bytes!("../../../tests/fixtures/sync-request.bin")
    );
}
#[test]
fn proceed_keeps_original_verification_and_context_and_full_carrier_json() {
    let response = SyncResponse::decode(Bytes::from_static(include_bytes!(
        "../../../tests/fixtures/verification-sync-pending.bin"
    )))
    .unwrap();
    let history = vec![
        "synthetic-actual-request-log".into(),
        "synthetic-actual-response-log".into(),
    ];
    let request = make_proceed(
        &identity(true),
        SESSION,
        response.results[0].verification.as_ref().unwrap(),
        CARRIER,
        &history,
    )
    .unwrap();
    assert_eq!(
        request.encode_to_vec(),
        include_bytes!("../../../tests/fixtures/proceed-request.bin")
    );
}

#[test]
fn rejects_invalid_sim_or_caller_facts_before_encoding() {
    for (imsi, caller, slot, sub) in [
        (
            "001010000000001\n",
            "11111111-1111-4111-8111-111111111111",
            0,
            1,
        ),
        (
            "００１０１０００００００００１",
            "11111111-1111-4111-8111-111111111111",
            0,
            1,
        ),
        ("001010000000001", "invalid", 0, 1),
        (
            "001010000000001",
            "11111111-1111-4111-8111-111111111111",
            -1,
            1,
        ),
        (
            "001010000000001",
            "11111111-1111-4111-8111-111111111111",
            0,
            -1,
        ),
    ] {
        let mut input = sim();
        input.imsi = imsi.into();
        input.caller_session_id = caller.into();
        input.slot_index = slot;
        input.subscription_id = sub;
        assert!(make_sync(&identity(false), &input).is_err());
    }
    let mut input = sim();
    input.telephony.network_operator.code = "00101\nprivate".into();
    assert!(make_sync(&identity(false), &input).is_err());
    let mut input = sim();
    input.number = Some("+15550000001\nprivate".into());
    assert!(make_sync(&identity(false), &input).is_err());
}

#[test]
fn proceed_requires_pending_state_and_refuses_unimplemented_key_authentication() {
    let bytes = Bytes::from_static(include_bytes!(
        "../../../tests/fixtures/verification-sync-pending.bin"
    ));
    let mut response = super::super::wire::SyncResponse::decode(bytes.clone()).unwrap();
    response.headers = vec![Bytes::from_static(&[10, 2, 8, 1])];
    let response = SyncResponse::decode(Bytes::from(response.encode_to_vec())).unwrap();
    assert!(
        make_proceed(
            &identity(true),
            SESSION,
            response.results[0].verification.as_ref().unwrap(),
            CARRIER,
            &[]
        )
        .is_err()
    );
    let response = SyncResponse::decode(bytes).unwrap();
    let mut value = super::super::wire::Verification::decode(
        response.results[0]
            .verification
            .as_ref()
            .unwrap()
            .raw
            .clone(),
    )
    .unwrap();
    value.states = vec![1];
    let value = Verification::decode(Bytes::from(value.encode_to_vec())).unwrap();
    assert!(make_proceed(&identity(true), SESSION, &value, CARRIER, &[]).is_err());
}

#[test]
fn rejects_incomplete_carrier_json_and_excessive_history() {
    let response = SyncResponse::decode(Bytes::from_static(include_bytes!(
        "../../../tests/fixtures/verification-sync-pending.bin"
    )))
    .unwrap();
    let pending = response.results[0].verification.as_ref().unwrap();
    for json in [
        "",
        "{",
        "{}",
        "[]",
        "{\"ap2009\":{\"TemporaryToken\":\"\"}}",
        "{\"ap2014\":{\"TemporaryToken\":\"synthetic-carrier-token\"}}",
    ] {
        assert!(make_proceed(&identity(true), SESSION, pending, json, &[]).is_err());
    }
    assert!(
        make_proceed(
            &identity(true),
            SESSION,
            pending,
            CARRIER,
            &vec!["synthetic-history".into(); 65]
        )
        .is_err()
    );
    assert!(
        make_proceed(
            &identity(true),
            SESSION,
            pending,
            &format!("{}{}", CARRIER, " ".repeat(65536)),
            &[]
        )
        .is_err()
    );
}

#[test]
fn diagnostics_omit_subscriber_and_proof_values_and_aggregate_payloads_are_bounded() {
    let input = sim();
    let identity = identity(false);
    let request = make_sync(&identity, &input).unwrap();
    for diagnostic in [
        format!("{input:?}"),
        format!("{:?}", input.telephony),
        format!("{request:?}"),
        format!("{:?}", request.verifications[0]),
    ] {
        for secret in [
            "001010000000001",
            "synthetic-sync-proof",
            "synthetic-iid",
            "8901000000000000000",
        ] {
            assert!(!diagnostic.contains(secret));
        }
    }
    let response = SyncResponse::decode(Bytes::from_static(include_bytes!(
        "../../../tests/fixtures/verification-sync-pending.bin"
    )))
    .unwrap();
    let history = vec!["x".repeat(8192); 16];
    assert!(
        make_proceed(
            &identity,
            SESSION,
            response.results[0].verification.as_ref().unwrap(),
            CARRIER,
            &history
        )
        .is_err()
    );
}
