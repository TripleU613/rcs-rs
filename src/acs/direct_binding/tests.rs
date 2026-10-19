use super::*;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};

const SALT: &str = "00000000-0000-4000-8000-000000000043";
fn parameters() -> DirectBindingParameters<'static> {
    DirectBindingParameters {
        application_package: "org.example.sms",
        caller_session_id: "00000000-0000-4000-8000-000000000042",
        imsi: "001010123456789",
        imei: "123456789012345",
        cookie_value: "synthetic-direct-cookie",
        carrier_temporary_token: "synthetic-carrier-token",
        challenge: "synthetic-direct-challenge",
    }
}
fn binding() -> DirectBindingV2<'static> {
    DirectBindingV2::with_salt(parameters(), SALT.into()).unwrap()
}

#[test]
fn map_matches_independent_sha384_vector() {
    let expected: BTreeMap<String, String> = serde_json::from_str(include_str!(
        "../../../tests/fixtures/direct-v2-inputs.json"
    ))
    .unwrap();
    let actual = binding().private_droidguard_inputs();
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 9);
    assert!(actual.values().all(|v| {
        v.len() == 96
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }));
    for absent in ["MSISDN", "MSISDN_TOKEN", "GMSCORE_IID_TOKEN"] {
        assert!(!actual.contains_key(absent));
    }
}

#[test]
fn unavailable_identifiers_are_omitted() {
    let mut p = parameters();
    p.imsi = "";
    p.imei = "";
    let actual = DirectBindingV2::with_salt(p, SALT.into())
        .unwrap()
        .private_droidguard_inputs();
    assert_eq!(actual.len(), 7);
    assert!(!actual.contains_key("IMSI") && !actual.contains_key("IMEI"));
}

#[test]
fn all_session_inputs_and_salt_are_bound() {
    let baseline = binding().private_droidguard_inputs();
    for (key, field) in [
        ("APP_NAME", 0),
        ("PROVISIONING_SESSION_ID", 1),
        ("JIBE_ACS_COOKIE", 2),
        ("SIM_AUTH_TEMP_TOKEN", 3),
        ("DROIDGUARD_CHALLENGE", 4),
    ] {
        let mut p = parameters();
        match field {
            0 => p.application_package = "org.example.other",
            1 => p.caller_session_id = "00000000-0000-4000-8000-000000000044",
            2 => p.cookie_value = "synthetic-other-cookie",
            3 => p.carrier_temporary_token = "synthetic-other-token",
            _ => p.challenge = "synthetic-other-challenge",
        }
        let changed = DirectBindingV2::with_salt(p, SALT.into())
            .unwrap()
            .private_droidguard_inputs();
        assert_ne!(baseline[key], changed[key]);
        assert_eq!(
            baseline.iter().filter(|(k, v)| changed[*k] != **v).count(),
            1
        );
    }
    let changed = DirectBindingV2::new(parameters())
        .unwrap()
        .private_droidguard_inputs();
    assert!(baseline.iter().all(|(k, v)| changed[k] != *v));
}

#[test]
fn result_has_two_distinct_base64_layers_and_only_three_fields() {
    let result = binding()
        .private_authenticity_result(&[0xfb, 0xff, 0xef])
        .unwrap();
    assert_eq!(
        result,
        include_str!("../../../tests/fixtures/direct-v2-result.txt").trim()
    );
    let bytes = STANDARD.decode(&result).unwrap();
    assert!(result.ends_with("=="));
    assert_eq!(&bytes[..8], &[8, 2, 18, 4, b'-', b'_', b'_', b'v']);
    assert_eq!(&bytes[8..10], &[26, 36]);
    assert_eq!(&bytes[10..], SALT.as_bytes());
    assert_eq!(
        URL_SAFE_NO_PAD.decode(&bytes[4..8]).unwrap(),
        [0xfb, 0xff, 0xef]
    );
}

#[test]
fn rejects_invalid_or_incomplete_direct_context() {
    for field in 0..9 {
        let mut p = parameters();
        match field {
            0 => p.application_package = "",
            1 => p.application_package = "org.example/other",
            2 => p.caller_session_id = "invalid-session",
            3 => p.cookie_value = "",
            4 => p.carrier_temporary_token = "",
            5 => p.challenge = "",
            6 => p.challenge = "synthetic\nchallenge",
            7 => p.imsi = "wrong-identifier",
            _ => p.imei = "wrong-identifier",
        }
        assert!(DirectBindingV2::new(p).is_err(), "invalid field {field}");
    }
    let long = "x".repeat(16 * 1024 + 1);
    let mut p = parameters();
    p.challenge = &long;
    assert!(DirectBindingV2::new(p).is_err());
    assert!(DirectBindingV2::with_salt(parameters(), "invalid-salt".into()).is_err());
}

#[test]
fn rejects_empty_error_or_oversized_snapshots() {
    for value in [
        Vec::new(),
        b"ERROR : synthetic".to_vec(),
        vec![0; 64 * 1024 + 1],
    ] {
        assert!(binding().private_authenticity_result(&value).is_err());
    }
}

#[test]
fn debug_does_not_expose_private_inputs() {
    let p = format!("{:?}", parameters());
    let b = format!("{:?}", binding());
    for secret in [
        SALT,
        "001010123456789",
        "123456789012345",
        "synthetic-direct-cookie",
        "synthetic-carrier-token",
        "synthetic-direct-challenge",
    ] {
        assert!(!p.contains(secret) && !b.contains(secret));
    }
}
