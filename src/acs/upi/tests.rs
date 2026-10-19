use super::*;
const SESSION: &str = "00000000-0000-4000-8000-000000000000";
const SALT: &str = "11111111-1111-4111-8111-111111111111";
fn parameters() -> UpiParameters<'static> {
    UpiParameters {
        client: ClientParameters {
            terminal_vendor: "Exam",
            terminal_model: "Test phone",
            terminal_sw_version: "17",
            client_vendor: "Exam",
            client_version: "1",
            rcs_profile: "UP_T",
            rcs_version: "5.1B",
        },
        application_package: "org.example.sms",
        caller_session_id: SESSION,
        imsi: "001010000000001",
        imei: "000000000000000",
        gid1: "00",
        number_credential: "synthetic-number-credential",
        gmscore_iid_token: Some("synthetic-gms-iid"),
        eligibility: 1,
        policy: "synthetic-upi-policy",
        user_agent: "Synthetic-client/1",
        language: "en-US",
        client_channel: "PUBLIC",
    }
}

#[tokio::test]
async fn an_initial_upi_get_cannot_reuse_an_older_post_path_cookie() {
    use crate::acs::tests::{mock_session, reply};
    let xml = include_str!("../../../tests/fixtures/clientauth.xml")
        .replace("goog-droidguard", "goog-mls-upi");
    let(s,server)=mock_session(vec![reply(200,"Content-Type: application/vnd.gsma.cfg-clientauth+xml\r\nSet-Cookie: JIBE_ACS_COOKIE=previous-cookie; Path=/provision\r\n",&xml),reply(200,"Content-Type: application/vnd.gsma.cfg-clientauth+xml\r\n",&xml)]).await;
    let p = parameters();
    let first = s.upi_challenge(&p).await.unwrap();
    drop(first);
    assert!(matches!(
        s.upi_challenge(&p).await,
        Err(Error::InvalidInput(
            "ACS challenge requires fresh cookie state"
        ))
    ));
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}
fn challenge<'a>(session: &'a AcsSession, parameters: &'a UpiParameters<'a>) -> UpiChallenge<'a> {
    session.cookies.add_cookie_str(
        "JIBE_ACS_COOKIE=synthetic-cookie; Path=/; Secure",
        &session.endpoint,
    );
    UpiChallenge {
        _exchange: session.begin_exchange().unwrap(),
        session,
        parameters,
        nonce: "synthetic-nonce".into(),
        cookie: "synthetic-cookie".into(),
        salt: SALT.into(),
    }
}
fn signature() -> (Vec<u8>, Vec<u8>) {
    use ring::signature::KeyPair;
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rng,
    )
    .unwrap();
    let key = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8.as_ref(),
        &rng,
    )
    .unwrap();
    let mut der = include_bytes!("../../../tests/fixtures/consent-public-key.der")[..26].to_vec();
    der.extend_from_slice(key.public_key().as_ref());
    let signature = key
        .sign(
            &rng,
            include_bytes!("../../../tests/fixtures/upi-mls-signing-input.bin"),
        )
        .unwrap();
    (der, signature.as_ref().to_vec())
}
#[test]
fn upi_initial_request_uses_its_own_method_policy_and_logical_session() {
    let session = AcsSession::new("https://acs.example.test/base").unwrap();
    let p = parameters();
    let request = session.upi_request(&p).unwrap();
    assert_eq!(request.method(), reqwest::Method::GET);
    assert_eq!(request.url().path(), "/base");
    let query: BTreeMap<_, _> = request
        .url()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(
        query.get("client_authenticity_support").unwrap(),
        "goog-mls-upi"
    );
    assert_eq!(query.get("IMSI").unwrap(), "001010000000001");
    assert!(!query.contains_key("SMS_port") && !query.contains_key("token"));
    assert_eq!(request.headers()["rcs_engine_session_id"], SESSION);
    assert_eq!(
        request.headers()["supported_provisioning_types"],
        "synthetic-upi-policy"
    );
    assert!(!request.headers().contains_key("rcs_msisdn_token"));
    assert!(!format!("{:?}", request.headers()).contains("synthetic-gms-iid"));
}
#[test]
fn version_one_binding_matches_independent_hashes_and_body_fixture() {
    let session = AcsSession::new("https://acs.example.test/").unwrap();
    let p = parameters();
    let c = challenge(&session, &p);
    let expected: BTreeMap<String, String> = serde_json::from_str(include_str!(
        "../../../tests/fixtures/upi-droidguard-inputs.json"
    ))
    .unwrap();
    assert_eq!(c.private_droidguard_inputs(), expected);
    assert_eq!(
        c.private_mls_signing_input(),
        include_bytes!("../../../tests/fixtures/upi-mls-signing-input.bin")
    );
    let body = c.body("synthetic-genuine-proof").unwrap();
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap(),
        include_bytes!("../../../tests/fixtures/upi-provision-body.bin")
    );
    assert!(!format!("{c:?} {p:?}").contains("synthetic"));
}
#[test]
fn upi_post_binds_the_exact_nonce_cookie_identity_and_credential() {
    let session = AcsSession::new("https://acs.example.test/base").unwrap();
    let p = parameters();
    let c = challenge(&session, &p);
    let (public, signature) = signature();
    let proof = MlsProof {
        public_key_der: &public,
        signature_der: &signature,
        home_kds: 2,
    };
    let request = c.make_request("synthetic-genuine-proof", &proof).unwrap();
    assert_eq!(request.method(), reqwest::Method::POST);
    assert_eq!(request.url().origin(), session.endpoint.origin());
    assert_eq!(request.url().path(), "/provision");
    assert_eq!(request.headers()["content-type"], "text/plain");
    assert_eq!(
        request.headers()["rcs_msisdn_token"],
        "synthetic-number-credential"
    );
    assert_eq!(
        request.headers()["cookie"],
        "JIBE_ACS_COOKIE=synthetic-cookie"
    );
    assert!(!format!("{:?}", request.headers()).contains("synthetic-number-credential"));
    let q: BTreeMap<_, _> = request.url().query_pairs().collect();
    assert!(!q.contains_key("client_authenticity_support") && !q.contains_key("as_temp_token"));
    assert_eq!(q.get("home_kds").unwrap(), "2");
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(q.get("participant_public_key").unwrap().as_bytes())
            .unwrap(),
        public
    );
    let body = request.body().unwrap().as_bytes().unwrap();
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap(),
        include_bytes!("../../../tests/fixtures/upi-provision-body.bin")
    );
}
#[test]
fn rejects_replaced_cookie_wrong_nonce_and_invalid_signature_before_post() {
    let session = AcsSession::new("https://acs.example.test/").unwrap();
    let p = parameters();
    let mut c = challenge(&session, &p);
    let (public, signature) = signature();
    let proof = MlsProof {
        public_key_der: &public,
        signature_der: &signature,
        home_kds: 2,
    };
    c.nonce = "different-nonce".into();
    assert!(c.make_request("synthetic-genuine-proof", &proof).is_err());
    c.nonce = "synthetic-nonce".into();
    session.cookies.add_cookie_str(
        "JIBE_ACS_COOKIE=replaced-cookie; Path=/; Secure",
        &session.endpoint,
    );
    assert!(c.make_request("synthetic-genuine-proof", &proof).is_err());
    drop(c);
    let c = challenge(&session, &p);
    let bad = MlsProof {
        public_key_der: &public,
        signature_der: b"invalid",
        home_kds: 2,
    };
    assert!(c.make_request("synthetic-genuine-proof", &bad).is_err());
}
#[test]
fn rejects_missing_identity_header_injection_and_invalid_eligibility() {
    let session = AcsSession::new("https://acs.example.test/").unwrap();
    for choice in 0..6 {
        let mut p = parameters();
        match choice {
            0 => p.imsi = "",
            1 => p.number_credential = "synthetic\r\nprivate",
            2 => p.policy = "bad\r\nheader",
            3 => p.eligibility = 4,
            4 => p.caller_session_id = "invalid",
            _ => p.imei = "not-an-imei",
        }
        assert!(session.upi_request(&p).is_err());
    }
    let p = parameters();
    let c = challenge(&session, &p);
    assert!(c.body("").is_err());
    assert!(c.body(&"x".repeat(64 * 1024 + 1)).is_err());
}
#[test]
fn mls_length_prefix_is_minimal_at_the_sixty_four_byte_boundary() {
    let session = AcsSession::new("https://acs.example.test/").unwrap();
    let p = parameters();
    let mut c = challenge(&session, &p);
    c.nonce = "n".repeat(64);
    let input = c.private_mls_signing_input();
    let label_len = b"MLS 1.0 ACS_Participant_Key_Proof".len();
    assert_eq!(&input[1 + label_len..3 + label_len], &[0x40, 0x40]);
}

#[tokio::test]
async fn sends_the_real_upi_get_then_post_with_origin_bound_cookies_and_opaque_wap_result() {
    use crate::acs::tests::{mock_session, reply};
    let xml = include_str!("../../../tests/fixtures/clientauth.xml")
        .replace("goog-droidguard", "goog-mls-upi");
    let wap = "<wap-provisioningdoc/>";
    let (session,server)=mock_session(vec![
        reply(200,"Content-Type: application/vnd.gsma.cfg-clientauth+xml\r\nSet-Cookie: JIBE_ACS_COOKIE=synthetic-cookie; Path=/; HttpOnly\r\n",&xml),
        reply(200,"Content-Type: application/vnd.wap.connectivity-xml\r\n",wap),
    ]).await;
    let p = parameters();
    let c = session.upi_challenge(&p).await.unwrap();
    assert!(uuid::Uuid::parse_str(&c.salt).is_ok());
    let (public, signature) = signature();
    let proof = MlsProof {
        public_key_der: &public,
        signature_der: &signature,
        home_kds: 2,
    };
    let response = c
        .provision("synthetic-genuine-proof", &proof)
        .await
        .unwrap();
    let Response::WapConfiguration(raw) = response else {
        panic!("expected opaque WAP bytes")
    };
    assert_eq!(raw.as_ref(), wap.as_bytes());
    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /?"));
    assert!(!requests[0].contains("synthetic-number-credential"));
    assert!(requests[1].starts_with("POST /provision?"));
    assert!(requests[1].contains("rcs_msisdn_token: synthetic-number-credential"));
    assert!(requests[1].contains("cookie: JIBE_ACS_COOKIE=synthetic-cookie"));
    assert!(
        session
            .cookies
            .cookies(&reqwest::Url::parse("https://different.example/").unwrap())
            .is_none()
    );
}

#[tokio::test]
async fn credential_post_never_follows_redirects_or_retries_service_failures() {
    use crate::acs::tests::{mock_session, reply};
    let xml = include_str!("../../../tests/fixtures/clientauth.xml")
        .replace("goog-droidguard", "goog-mls-upi");
    let sink = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let location = format!(
        "Location: http://{}/private\r\n",
        sink.local_addr().unwrap()
    );
    for (status, extra) in [(302, location.as_str()), (503, "Retry-After: 60\r\n")] {
        let (session,server)=mock_session(vec![
            reply(200,"Content-Type: application/vnd.gsma.cfg-clientauth+xml\r\nSet-Cookie: JIBE_ACS_COOKIE=synthetic-cookie; Path=/\r\n",&xml),
            reply(status,extra,"synthetic-private-error"),
        ]).await;
        let p = parameters();
        let c = session.upi_challenge(&p).await.unwrap();
        let (public, signature) = signature();
        let proof = MlsProof {
            public_key_der: &public,
            signature_der: &signature,
            home_kds: 2,
        };
        let error = c
            .provision("synthetic-genuine-proof", &proof)
            .await
            .unwrap_err();
        assert!(!format!("{error}").contains("synthetic"));
        match error {
            Error::Http {
                status: actual,
                retry_after,
            } => {
                assert_eq!(actual, status);
                if status == 503 {
                    assert_eq!(retry_after, Some(Duration::from_secs(60)));
                }
            }
            _ => panic!("expected HTTP rejection"),
        }
        assert_eq!(server.await.unwrap().len(), 2);
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), sink.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_nonce_without_usable_cookie_cannot_start_the_proof_flow() {
    use crate::acs::tests::{mock_session, reply};
    let xml = include_str!("../../../tests/fixtures/clientauth.xml")
        .replace("goog-droidguard", "goog-mls-upi");
    let (session, server) = mock_session(vec![
        reply(200, "Content-Type: application/vnd.gsma.cfg-clientauth+xml\r\n", &xml),
        reply(200, "Content-Type: application/vnd.gsma.cfg-clientauth+xml\r\nSet-Cookie: JIBE_ACS_COOKIE=synthetic-cookie; Path=/\r\n", &xml),
    ]).await;
    let p = parameters();
    assert!(session.upi_challenge(&p).await.is_err());
    drop(session.upi_challenge(&p).await.unwrap());
    assert_eq!(server.await.unwrap().len(), 2);
}

#[tokio::test]
async fn cookie_rotation_after_request_build_does_not_replace_the_bound_cookie_on_the_wire() {
    use crate::acs::tests::{mock_session, reply};
    let xml = include_str!("../../../tests/fixtures/clientauth.xml")
        .replace("goog-droidguard", "goog-mls-upi");
    let (session,server)=mock_session(vec![
        reply(200,"Content-Type: application/vnd.gsma.cfg-clientauth+xml\r\nSet-Cookie: JIBE_ACS_COOKIE=synthetic-cookie; Path=/\r\n",&xml),
        reply(200,"Content-Type: application/vnd.wap.connectivity-xml\r\n","<wap-provisioningdoc/>"),
    ]).await;
    let p = parameters();
    let c = session.upi_challenge(&p).await.unwrap();
    let (public, signature) = signature();
    let proof = MlsProof {
        public_key_der: &public,
        signature_der: &signature,
        home_kds: 2,
    };
    let request = c.make_request("synthetic-genuine-proof", &proof).unwrap();
    session
        .cookies
        .add_cookie_str("JIBE_ACS_COOKIE=rotated-cookie; Path=/", &session.endpoint);
    session.response_body(request).await.unwrap();
    let requests = server.await.unwrap();
    assert!(requests[1].contains("cookie: JIBE_ACS_COOKIE=synthetic-cookie"));
    assert!(!requests[1].contains("rotated-cookie"));
}

#[test]
fn unspecified_eligibility_is_preserved_and_optional_iid_is_not_invented() {
    let session = AcsSession::new("https://acs.example.test/").unwrap();
    let mut p = parameters();
    p.eligibility = 0;
    p.gmscore_iid_token = None;
    let c = challenge(&session, &p);
    let body = base64::engine::general_purpose::STANDARD
        .decode(c.body("synthetic-genuine-proof").unwrap())
        .unwrap();
    assert_eq!(&body[..2], &[8, 0]);
    assert!(
        !body
            .windows(b"synthetic-gms-iid".len())
            .any(|w| w == b"synthetic-gms-iid")
    );
    assert!(
        !c.private_droidguard_inputs()
            .contains_key("GMSCORE_IID_TOKEN")
    );
    assert!(
        !session
            .upi_request(&p)
            .unwrap()
            .headers()
            .contains_key("gmscore_instance_id_token")
    );
}

#[tokio::test]
async fn an_active_upi_context_excludes_cookie_mutating_challenges_until_dropped() {
    use crate::acs::tests::{mock_session, reply};
    let xml = include_str!("../../../tests/fixtures/clientauth.xml")
        .replace("goog-droidguard", "goog-mls-upi");
    let response = reply(
        200,
        "Content-Type: application/vnd.gsma.cfg-clientauth+xml\r\nSet-Cookie: JIBE_ACS_COOKIE=synthetic-cookie; Path=/\r\n",
        &xml,
    );
    let (session, server) = mock_session(vec![
        response,
        reply(
            200,
            "Content-Type: application/vnd.wap.connectivity-xml\r\n",
            "<wap-provisioningdoc/>",
        ),
    ])
    .await;
    let p = parameters();
    let c = session.upi_challenge(&p).await.unwrap();
    assert!(matches!(
        session.upi_challenge(&p).await,
        Err(Error::InvalidInput("ACS session exchange already active"))
    ));
    assert!(matches!(
        session.initial_challenge(&p.client, None).await,
        Err(Error::InvalidInput("ACS session exchange already active"))
    ));
    drop(c);
    assert!(matches!(
        session.upi_challenge(&p).await,
        Err(Error::InvalidInput(
            "ACS challenge requires fresh cookie state"
        ))
    ));
    assert!(matches!(
        session.initial_challenge(&p.client, None).await.unwrap(),
        Response::WapConfiguration(_)
    ));
    assert_eq!(server.await.unwrap().len(), 2);
}
