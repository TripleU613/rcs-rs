use super::*;

#[test]
fn rejects_duplicate_number_credentials_before_they_can_be_used_for_provisioning() {
    let param = [
        field(1, b"id_token"),
        field(2, b"synthetic-number-credential"),
    ]
    .concat();
    let record = [vec![16, 3], field(6, &param), field(6, &param)].concat();
    assert!(ProceedResponse::decode(Bytes::from(field(1, &record))).is_err());
}

#[test]
fn number_credential_comes_from_verification_params_and_keeps_original_bytes_private() {
    let token = b"synthetic-number-credential";
    let param = [field(1, b"id_token"), field(2, token)].concat();
    let verified = field(1, b"+15550000001");
    let record = [
        vec![16, 3],
        field(3, &verified),
        field(6, &param),
        field(15, b"future"),
    ]
    .concat();
    let response = ProceedResponse::decode(Bytes::from(field(1, &record))).unwrap();
    let v = response.verification.as_ref().unwrap();
    assert_eq!(v.private_id_token(), Some("synthetic-number-credential"));
    assert_eq!(v.raw_protobuf(), record);
    assert!(!format!("{response:?}").contains("synthetic-number-credential"));
    let sync = SyncResponse::decode(Bytes::from(field(1, &field(1, &record)))).unwrap();
    assert_eq!(
        sync.results[0]
            .verification
            .as_ref()
            .unwrap()
            .private_id_token(),
        Some("synthetic-number-credential")
    );

    let no_credential = [vec![16, 3], field(3, &verified)].concat();
    let root_restoration_token = field(1, token);
    let sync = SyncResponse::decode(Bytes::from(
        [
            field(1, &field(1, &no_credential)),
            field(5, &root_restoration_token),
        ]
        .concat(),
    ))
    .unwrap();
    assert_eq!(
        sync.results[0]
            .verification
            .as_ref()
            .unwrap()
            .private_id_token(),
        None
    );
}

#[test]
fn rejects_malformed_or_unbounded_number_credential_params() {
    for param in [
        field(1, b"id_token"),
        [field(1, b"id_token"), field(2, b"")].concat(),
        [field(1, b"id_token"), field(2, b"synthetic\r\nprivate")].concat(),
        [field(1, b"id_token"), field(2, &vec![b'x'; 16 * 1024 + 1])].concat(),
        [
            field(1, b"id_token"),
            field(1, b"id_token"),
            field(2, b"synthetic"),
        ]
        .concat(),
        [
            field(1, b"id_token"),
            field(2, b"synthetic"),
            field(2, b"other"),
        ]
        .concat(),
    ] {
        let record = [vec![16, 3], field(6, &param)].concat();
        assert!(ProceedResponse::decode(Bytes::from(field(1, &record))).is_err());
    }
    let param = [field(1, b"future"), field(2, b"synthetic")].concat();
    let record = field(6, &param).repeat(65);
    assert!(ProceedResponse::decode(Bytes::from(field(1, &record))).is_err());
}

#[test]
fn rejects_cached_proof_without_expiry_before_followup_can_use_it() {
    // Both services put cached DroidGuard in field4. An empty cache is unusable.
    assert!(SyncResponse::decode(Bytes::from_static(&[34, 0])).is_err());
    assert!(ProceedResponse::decode(Bytes::from_static(&[34, 0])).is_err());
}

#[test]
fn pending_ts43_keeps_exact_verification_context_and_per_record_status() {
    let bytes = Bytes::from_static(include_bytes!(
        "../../tests/fixtures/verification-sync-pending.bin"
    ));
    let response = SyncResponse::decode(bytes.clone()).ok().unwrap();
    assert_eq!(response.raw_protobuf(), bytes);
    assert_eq!(response.results.len(), 1);
    let result = &response.results[0];
    let verification = result.verification.as_ref().unwrap();
    assert_eq!(verification.state, Some(2));
    assert_eq!(verification.method, Some(11));
    assert_eq!(verification.unverified_reason, None);
    assert_eq!(
        verification.raw_protobuf(),
        include_bytes!("../../tests/fixtures/verification-pending.bin")
    );
    let challenge = verification.ts43.as_ref().unwrap();
    assert_eq!(challenge.private_context(), [8, 7, 18, 4, 0, 255, 128, 0]);
    assert_eq!(
        challenge.private_server_url(),
        "https://carrier.example.test/entitlement?opaque=synthetic-private"
    );
    let status = result.status.as_ref().unwrap();
    assert_eq!(status.code, Some(0));
    assert_eq!(status.private_message(), Some("synthetic-private-message"));
    assert!(
        status
            .raw_protobuf()
            .windows(7)
            .any(|bytes| bytes == b"generic")
    );
}

#[test]
fn proceed_failure_decodes_none_reason_without_treating_outer_success_as_verification() {
    let response = ProceedResponse::decode(Bytes::from_static(include_bytes!(
        "../../tests/fixtures/verification-proceed-failed.bin"
    )))
    .ok()
    .unwrap();
    let verification = response.verification.unwrap();
    assert_eq!(verification.state, Some(1));
    assert_eq!(verification.unverified_reason, Some(2));
    assert_eq!(verification.method, Some(11));
    assert!(verification.ts43.is_none());
}

#[test]
fn throttled_record_status_is_retained_inside_successful_sync_envelope() {
    let response = SyncResponse::decode(Bytes::from_static(include_bytes!(
        "../../tests/fixtures/verification-sync-throttled.bin"
    )))
    .ok()
    .unwrap();
    let result = &response.results[0];
    assert_eq!(result.verification.as_ref().unwrap().state, Some(1));
    assert_eq!(
        result.verification.as_ref().unwrap().unverified_reason,
        Some(1)
    );
    assert_eq!(result.status.as_ref().unwrap().code, Some(8));
}

#[test]
fn decodes_operation_and_all_parameter_kinds_with_redacted_default_diagnostics() {
    let response = SyncResponse::decode(Bytes::from_static(include_bytes!(
        "../../tests/fixtures/verification-sync-pending.bin"
    )))
    .unwrap();
    let result = &response.results[0];
    let verification = result.verification.as_ref().unwrap();
    let challenge = verification.ts43.as_ref().unwrap();
    assert_eq!(challenge.parameters.configuration_version, Some(1));
    assert_eq!(challenge.parameters.notification_action, Some(2));
    for (parameter, expected) in [
        (StringParameter::EntitlementVersion, "2.0"),
        (StringParameter::AuthenticationToken, "synthetic-auth"),
        (StringParameter::TemporaryToken, "synthetic-temporary"),
        (StringParameter::TerminalId, "<imei>"),
        (StringParameter::TerminalVendor, "Example"),
        (StringParameter::TerminalModel, "Generic"),
        (StringParameter::TerminalSoftwareVersion, "1"),
        (StringParameter::AppName, "ExampleApp"),
        (StringParameter::AppVersion, "1.0"),
        (StringParameter::NotificationToken, "synthetic-notification"),
        (StringParameter::AcceptContentType, "application/json"),
        (StringParameter::BoostType, "example-boost"),
        (StringParameter::Gid1, "synthetic-gid1"),
    ] {
        assert_eq!(
            challenge.parameters.private_string(parameter),
            Some(expected)
        );
    }
    assert_eq!(challenge.private_application_id(), Some("ap2009"));
    assert_eq!(challenge.private_nai_realm(), Some("example.realm"));
    let action = challenge.action.as_ref().unwrap();
    let Ts43Action::AcquireTemporaryToken(operation) = action else {
        panic!("expected acquire action");
    };
    assert_eq!(operation.private_name(), Some("AcquireTemporaryToken"));
    assert_eq!(operation.operation_type, Some(4));
    assert_eq!(operation.private_targets(), ["rcs"]);
    assert_eq!(operation.private_target_ids(), ["synthetic-target"]);
    assert!(
        operation
            .raw_protobuf()
            .ends_with(b"synthetic-operation-unknown")
    );
    for debug in [
        format!("{response:?}"),
        format!("{result:?}"),
        format!("{verification:?}"),
        format!("{challenge:?}"),
        format!("{:?}", challenge.parameters),
        format!("{action:?}"),
        format!("{operation:?}"),
    ] {
        for secret in [
            "synthetic-",
            "001010000000001",
            "<imei>",
            "carrier.example.test",
        ] {
            assert!(!debug.contains(secret));
        }
    }
}

// Independent test encoding of length-delimited fields; production uses only prost decoding.
fn field(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut output = vec![(tag << 3) | 2];
    let mut length = data.len();
    while length > 127 {
        output.push((length as u8 & 127) | 128);
        length >>= 7;
    }
    output.push(length as u8);
    output.extend(data);
    output
}

fn proceed_ts43(ts43: &[u8]) -> Bytes {
    let mut challenge = vec![16, 11];
    challenge.extend(field(12, ts43));
    let container = field(2, &challenge);
    let mut verification = vec![16, 2];
    verification.extend(field(4, &container));
    Bytes::from(field(1, &verification))
}

#[test]
fn rejects_malformed_or_conflicting_mt_sms_challenges() {
    let signature = field(1, b"synthetic-sms-signature");
    let mt = field(6, &signature);
    for challenge in [
        vec![16, 2],
        [vec![16, 2], field(6, &[])].concat(),
        [vec![16, 2], field(6, &field(1, b""))].concat(),
        [vec![16, 2], field(6, &signature.repeat(2))].concat(),
        [vec![16, 2], mt.repeat(2)].concat(),
        [vec![16, 2], mt.clone(), vec![16, 2]].concat(),
        [vec![16, 3], mt.clone()].concat(),
        [vec![16, 2], mt, field(12, &[])].concat(),
        [vec![16, 2], field(6, &field(1, &[0xff]))].concat(),
        [vec![16, 2], field(6, &field(1, b"synthetic\nprivate"))].concat(),
        [vec![16, 2], field(6, &field(1, &vec![b'x'; MAX_TEXT + 1]))].concat(),
    ] {
        let record = [vec![16, 2], field(4, &field(2, &challenge))].concat();
        assert!(
            ProceedResponse::decode(Bytes::from(field(1, &record))).is_err(),
            "malformed MT challenge was accepted"
        );
    }
}

#[test]
fn mt_sms_keeps_original_record_and_redacts_its_matching_signature() {
    let signature = b"synthetic-sms-signature";
    let challenge = [vec![16, 2], field(6, &field(1, signature))].concat();
    let record = [
        vec![16, 2],
        field(4, &field(2, &challenge)),
        field(15, b"synthetic-unknown-field"),
    ]
    .concat();
    let response = ProceedResponse::decode(Bytes::from(field(1, &record))).unwrap();
    let verification = response.verification.as_ref().unwrap();
    let mt = verification.mt_sms.as_ref().unwrap();
    assert_eq!(verification.method, Some(2));
    assert_eq!(mt.private_signature().as_bytes(), signature);
    assert_eq!(verification.raw_protobuf(), record);
    assert!(verification.ts43.is_none());
    for debug in [
        format!("{response:?}"),
        format!("{verification:?}"),
        format!("{mt:?}"),
    ] {
        assert!(!debug.contains("synthetic-"));
    }
}

fn minimal_ts43(url: &str) -> Vec<u8> {
    let mut payload = field(1, &[8, 7]);
    payload.extend(field(2, url.as_bytes()));
    payload.extend(field(3, &[]));
    payload
}

#[test]
fn preserves_missing_and_unknown_states_and_status_only_results() {
    let empty = ProceedResponse::decode(Bytes::new()).unwrap();
    assert!(empty.verification.is_none());
    for (state, bytes) in [(None, &[10, 0][..]), (Some(91), &[10, 2, 16, 91])] {
        let verification = ProceedResponse::decode(Bytes::copy_from_slice(bytes))
            .unwrap()
            .verification
            .unwrap();
        assert_eq!(verification.state, state);
        assert_eq!(verification.unverified_reason, None);
    }
    let response = SyncResponse::decode(Bytes::from_static(&[10, 4, 18, 2, 8, 8])).unwrap();
    assert!(response.results[0].verification.is_none());
    assert_eq!(response.results[0].status.as_ref().unwrap().code, Some(8));
    let response =
        ProceedResponse::decode(Bytes::from_static(&[10, 8, 16, 1, 74, 4, 8, 91, 24, 93])).unwrap();
    let verification = response.verification.unwrap();
    assert_eq!(verification.unverified_reason, Some(91));
    assert_eq!(verification.method, Some(93));
}

#[test]
fn rejects_malformed_oversize_and_ambiguous_records_or_state_payloads() {
    assert!(SyncResponse::decode(Bytes::from_static(&[10, 255])).is_err());
    assert!(ProceedResponse::decode(Bytes::from(vec![0; MAX_MESSAGE + 1])).is_err());
    assert!(SyncResponse::decode(Bytes::from([10, 0].repeat(MAX_RECORDS + 1))).is_err());
    let mut duplicate =
        include_bytes!("../../tests/fixtures/verification-sync-pending.bin").to_vec();
    duplicate.extend(include_bytes!(
        "../../tests/fixtures/verification-sync-pending.bin"
    ));
    assert!(SyncResponse::decode(Bytes::from(duplicate)).is_err());
    for bytes in [
        &[10, 4, 16, 1, 16, 2][..],
        &[10, 2, 16, 1, 10, 2, 16, 2],
        &[10, 6, 26, 0, 34, 0, 74, 0],
    ] {
        assert!(ProceedResponse::decode(Bytes::copy_from_slice(bytes)).is_err());
    }
    for url in [
        "http://carrier.example.test/",
        "https://user:private@carrier.example.test/",
        "https://carrier.example.test/#private",
        "https://carrier.example.test/\nprivate",
        "invalid",
    ] {
        assert!(ProceedResponse::decode(proceed_ts43(&minimal_ts43(url))).is_err());
    }
    let mut duplicate_url = minimal_ts43("https://carrier.example.test/");
    duplicate_url.extend(field(2, b"https://other.example.test/"));
    assert!(ProceedResponse::decode(proceed_ts43(&duplicate_url)).is_err());
    let mut ambiguous_action = minimal_ts43("https://carrier.example.test/");
    ambiguous_action.extend(field(4, &[]));
    ambiguous_action.extend(field(5, &[]));
    assert!(ProceedResponse::decode(proceed_ts43(&ambiguous_action)).is_err());
    let mut bad_context = field(1, &vec![1; 16 * 1024 + 1]);
    bad_context.extend(field(2, b"https://carrier.example.test/"));
    bad_context.extend(field(3, &[]));
    assert!(ProceedResponse::decode(proceed_ts43(&bad_context)).is_err());
    let mut duplicate_params = field(1, &[8, 7]);
    duplicate_params.extend(field(2, b"https://carrier.example.test/"));
    duplicate_params.extend(field(3, &[8, 1, 8, 2]));
    assert!(ProceedResponse::decode(proceed_ts43(&duplicate_params)).is_err());
}

#[test]
fn rejects_packed_wire_encoding_for_singular_integer_fields() {
    // State2 is a singular int32, not a packed repeated scalar.
    assert!(ProceedResponse::decode(Bytes::from_static(&[10, 3, 18, 1, 2])).is_err());
    // Custom Status.code1 is also singular int32.
    assert!(SyncResponse::decode(Bytes::from_static(&[10, 5, 18, 3, 10, 1, 8])).is_err());
    // TS43 params.configurationVersion1 must not accept a packed byte string.
    let mut ts43 = field(1, &[8, 7]);
    ts43.extend(field(2, b"https://carrier.example.test/"));
    ts43.extend(field(3, &[10, 1, 1]));
    assert!(ProceedResponse::decode(proceed_ts43(&ts43)).is_err());
}

#[test]
fn unknown_outer_fields_allow_bounded_large_capture_and_status_message_stays_lossless() {
    // Unknown field2 at the response level is preserved, including a large future extension.
    let bytes = Bytes::from(field(2, &vec![0; 128 * 1024]));
    let response = SyncResponse::decode(bytes.clone()).unwrap();
    assert!(response.results.is_empty());
    assert_eq!(response.raw_protobuf(), bytes);
    // Status.message is opaque UTF-8, including newlines. Debug does not reflect it.
    let mut status = vec![8, 8];
    status.extend(field(3, b"synthetic-private\nsecond line"));
    let response = SyncResponse::decode(Bytes::from(field(1, &field(2, &status)))).unwrap();
    assert_eq!(
        response.results[0]
            .status
            .as_ref()
            .unwrap()
            .private_message(),
        Some("synthetic-private\nsecond line")
    );
    assert!(!format!("{:?}", response.results[0]).contains("synthetic-private"));
}

#[test]
fn keeps_cached_proof_and_key_update_without_disclosing_private_values() {
    // Independent cache {token1:"synthetic-cache", expiry2:{seconds1:2000000000}}.
    let cache = [
        10, 15, 115, 121, 110, 116, 104, 101, 116, 105, 99, 45, 99, 97, 99, 104, 101, 18, 6, 8,
        128, 168, 214, 185, 7,
    ];
    let mut sync = include_bytes!("../../tests/fixtures/verification-sync-pending.bin").to_vec();
    sync.extend(field(4, &cache));
    let response = SyncResponse::decode(Bytes::from(sync)).unwrap();
    assert_eq!(response.public_key_status(), None);
    assert_eq!(
        response.cached_droidguard.as_ref().unwrap().value(),
        "synthetic-cache"
    );
    assert!(!format!("{response:?}").contains("synthetic-cache"));
    // Proceed header2 -> keyupdate1 -> status1=1.
    let response = ProceedResponse::decode(Bytes::from_static(&[18, 4, 10, 2, 8, 1])).unwrap();
    assert_eq!(response.public_key_status(), Some(1));
    assert!(SyncResponse::decode(Bytes::from_static(&[26, 4, 10, 2, 8, 1, 26, 0])).is_err());
}
