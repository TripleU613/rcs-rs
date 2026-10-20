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
        mt_sms_token: Some(String::new()),
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
fn sync_only_supplies_mt_data_for_an_explicit_receiver() {
    let mut input = sim();
    input.mt_sms_token = None;
    assert!(
        make_sync(&identity(false), &input).unwrap().verifications[0]
            .methods
            .is_none()
    );
    input.mt_sms_token = Some("Abcd_efg-12".into());
    let request = make_sync(&identity(false), &input).unwrap();
    assert_eq!(
        request.verifications[0]
            .methods
            .as_ref()
            .unwrap()
            .mt
            .as_ref()
            .unwrap()
            .payload
            .as_deref(),
        Some("Abcd_efg-12")
    );
    for token in ["short", "Abcd_efg-12\n", "Abcd_efg/12", "Ａbcd_efg-12"] {
        input.mt_sms_token = Some(token.into());
        assert!(make_sync(&identity(false), &input).is_err());
    }
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

fn mt_pending() -> Verification {
    let raw =
        b"\x10\x02\x22\x20\x12\x1e\x10\x02\x32\x1a\x0a\x18synthetic-sms-signature!\x7a\x07unknown";
    Verification::decode(Bytes::from_static(raw)).unwrap()
}

#[test]
fn mt_proceed_keeps_original_pending_and_sends_full_matching_sms_body_and_sender() {
    let mut pending = mt_pending();
    let raw = pending.raw.clone();
    pending.method = Some(11);
    pending.mt_sms = None;
    let request = make_mt_proceed(
        &identity(true),
        SESSION,
        &pending,
        "prefix\nsynthetic-sms-signature!\nsuffix",
        "ExampleSender",
    )
    .unwrap();
    assert_eq!(request.verification, raw);
    for debug in [
        format!("{request:?}"),
        format!("{:?}", request.response.as_ref().unwrap()),
        format!(
            "{:?}",
            request.response.as_ref().unwrap().mt_sms.as_ref().unwrap()
        ),
    ] {
        assert!(!debug.contains("synthetic-sms-signature"));
        assert!(!debug.contains("ExampleSender"));
    }
    assert_eq!(
        request.response.unwrap().encode_to_vec(),
        b"\x0a\x37\x0a\x26prefix\nsynthetic-sms-signature!\nsuffix\x12\x0dExampleSender"
    );
    assert!(request.header.is_some());
}

#[test]
fn mt_proceed_rejects_unmatched_or_unbounded_sms_and_unsigned_key_updates() {
    let mut pending = mt_pending();
    for (body, sender) in [
        ("SYNTHETIC-SMS-SIGNATURE!".into(), "ExampleSender".into()),
        ("synthetic-sms-signature!".into(), "".into()),
        (
            "synthetic-sms-signature!".into(),
            "sender\r\nprivate".into(),
        ),
        (
            format!(
                "synthetic-sms-signature!{}",
                "x".repeat(super::super::MAX_TEXT)
            ),
            "ExampleSender".into(),
        ),
        (
            "synthetic-sms-signature!".into(),
            "x".repeat(super::super::MAX_TEXT + 1),
        ),
    ] {
        assert!(make_mt_proceed(&identity(true), SESSION, &pending, &body, &sender).is_err());
    }
    pending.key_status = Some(1);
    assert!(
        make_mt_proceed(
            &identity(true),
            SESSION,
            &pending,
            "synthetic-sms-signature!",
            "ExampleSender"
        )
        .is_err()
    );
    let mut raw = pending.raw.to_vec();
    raw[1] = 3;
    let wrong_state = Verification::decode(Bytes::from(raw)).unwrap();
    assert!(
        make_mt_proceed(
            &identity(true),
            SESSION,
            &wrong_state,
            "synthetic-sms-signature!",
            "ExampleSender"
        )
        .is_err()
    );
    let response = SyncResponse::decode(Bytes::from_static(include_bytes!(
        "../../../tests/fixtures/verification-sync-pending.bin"
    )))
    .unwrap();
    assert!(
        make_mt_proceed(
            &identity(true),
            SESSION,
            response.results[0].verification.as_ref().unwrap(),
            "synthetic-sms-signature!",
            "ExampleSender"
        )
        .is_err()
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
