use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
const SESSION: &str = "00000000-0000-4000-8000-000000000000";
fn parameters() -> DirectParameters<'static> {
    DirectParameters {
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
        configuration_version: 0,
        rcs_state: 0,
        sms_port: 0,
        device_type: "phone",
        user_agent: "Synthetic-client/1",
        language: "en-US",
        client_channel: "PUBLIC",
    }
}
fn context<'a>(session: &'a AcsSession, p: &'a DirectParameters<'a>) -> DirectChallenge<'a> {
    session.cookies.add_cookie_str(
        "JIBE_ACS_COOKIE=synthetic-cookie; Path=/; Secure",
        &session.endpoint,
    );
    let (cookie, cookie_header) = session.cookie_for(&session.endpoint).unwrap();
    DirectChallenge {
        _exchange: session.begin_exchange().unwrap(),
        session,
        parameters: p,
        challenge: Challenge {
            method_id: "synthetic-method".into(),
            challenge: "synthetic-DG-challenge".into(),
            nonce: "synthetic-nonce".into(),
        },
        cookie,
        cookie_header,
    }
}
fn signature(input: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use ring::signature::KeyPair;
    let rng = ring::rand::SystemRandom::new();
    let key = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rng,
    )
    .unwrap();
    let key = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        key.as_ref(),
        &rng,
    )
    .unwrap();
    let mut public =
        include_bytes!("../../../tests/fixtures/consent-public-key.der")[..26].to_vec();
    public.extend_from_slice(key.public_key().as_ref());
    (public, key.sign(&rng, input).unwrap().as_ref().to_vec())
}
fn query(r: &reqwest::Request) -> BTreeMap<String, String> {
    r.url()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

#[test]
fn direct_request_preserves_configured_path_state_port_and_own_metadata() {
    let s = AcsSession::new("https://acs.example.test/configured/path/").unwrap();
    let mut p = parameters();
    p.configuration_version = 7;
    p.rcs_state = 2;
    p.sms_port = 37273;
    p.device_type = "wear";
    let r = s.direct_request(&p, true).unwrap();
    let q = query(&r);
    assert_eq!(r.url().path(), "/configured/path/");
    assert_eq!(r.method(), reqwest::Method::GET);
    assert_eq!(q.get("vers").unwrap(), "7");
    assert_eq!(q.get("rcs_state").unwrap(), "2");
    assert_eq!(q.get("SMS_port").unwrap(), "37273");
    assert_eq!(q.get("token").unwrap(), "");
    assert_eq!(q.get("device_type").unwrap(), "wear");
    assert_eq!(q.get("IMSI").unwrap(), p.imsi);
    assert_eq!(q.get("IMEI").unwrap(), p.imei);
    assert_eq!(q.get("GID1").unwrap(), p.gid1);
    assert_eq!(
        q.get("client_authenticity_support").unwrap(),
        "goog-droidguard"
    );
    assert_eq!(r.headers()["rcs_engine_session_id"], SESSION);
    assert_eq!(r.headers()["rcs-pe-version"], "3");
    assert_eq!(r.headers()["rcs-pe-location"], "3");
    for name in [
        "supported_provisioning_types",
        "rcs_msisdn_token",
        "gmscore_instance_id_token",
        "authorization",
    ] {
        assert!(!r.headers().contains_key(name));
    }
    for name in [
        "msisdn",
        "instance_id_token",
        "provision_id",
        "participant_public_key",
    ] {
        assert!(!q.contains_key(name));
    }
    assert!(r.body().is_none());
}
#[test]
fn omits_unavailable_identifiers_and_requires_valid_own_inputs_before_get() {
    let s = AcsSession::new("https://acs.example.test/").unwrap();
    let mut p = parameters();
    p.imsi = "";
    p.imei = "";
    p.gid1 = "";
    p.device_type = "";
    p.configuration_version = -1;
    let r = s.direct_request(&p, true).unwrap();
    let q = query(&r);
    assert_eq!(q.get("vers").unwrap(), "0");
    for n in ["IMSI", "IMEI", "GID1", "device_type"] {
        assert!(!q.contains_key(n));
    }
    for i in 0..6 {
        let mut p = parameters();
        match i {
            0 => p.application_package = "",
            1 => p.caller_session_id = "bad",
            2 => p.imsi = "bad",
            3 => p.user_agent = "bad\r\nheader",
            4 => p.client.rcs_version = "too-long",
            _ => p.client_channel = "",
        };
        assert!(s.direct_request(&p, true).is_err());
    }
}
#[test]
fn exact_two_part_body_binds_same_cookie_token_salt_and_owned_mls_nonce() {
    use prost::Message;
    let s = AcsSession::new("https://acs.example.test/base/").unwrap();
    let p = parameters();
    let c = context(&s, &p)
        .bind_carrier("synthetic-carrier-token")
        .unwrap();
    let input = c.private_mls_signing_input();
    assert_eq!(
        input,
        include_bytes!("../../../tests/fixtures/upi-mls-signing-input.bin")
    );
    let (public, sig) = signature(&input);
    let proof = MlsProof {
        public_key_der: &public,
        signature_der: &sig,
        home_kds: 2,
    };
    let r = c.make_request(b"synthetic-VM-bytes", &proof).unwrap();
    let q = query(&r);
    assert_eq!(r.method(), reqwest::Method::POST);
    assert_eq!(r.url().path(), "/base/");
    assert!(!q.contains_key("client_authenticity_support"));
    assert_eq!(q.get("home_kds").unwrap(), "2");
    assert_eq!(q.get("token").unwrap(), "");
    assert_eq!(r.headers()["cookie"], "JIBE_ACS_COOKIE=synthetic-cookie");
    let content = r.headers()["content-type"].to_str().unwrap();
    let boundary = content
        .strip_prefix("multipart/form-data; boundary=\"")
        .unwrap()
        .strip_suffix('"')
        .unwrap();
    let body = std::str::from_utf8(r.body().unwrap().as_bytes().unwrap()).unwrap();
    let parts: Vec<_> = body.split(&format!("--{boundary}")).collect();
    assert_eq!(parts.len(), 4);
    assert_eq!(parts[0], "");
    assert_eq!(parts[3], "--\r\n");
    assert_eq!(
        parts[1],
        "\r\nContent-Disposition: form-data; name=\"as_temp_token\"\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nsynthetic-carrier-token\r\n"
    );
    let proof_text=parts[2].strip_prefix("\r\nContent-Disposition: form-data; name=\"client_authenticity_result_synthetic-method\"\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n").unwrap().strip_suffix("\r\n").unwrap();
    #[derive(prost::Message)]
    struct Wire {
        #[prost(int32, tag = "1")]
        version: i32,
        #[prost(string, tag = "2")]
        snapshot: String,
        #[prost(string, tag = "3")]
        salt: String,
    }
    let wire = Wire::decode(STANDARD.decode(proof_text).unwrap().as_slice()).unwrap();
    assert_eq!(wire.version, 2);
    assert_eq!(wire.salt, c.private_droidguard_salt());
    assert_eq!(wire.snapshot, "c3ludGhldGljLVZNLWJ5dGVz");
    let map = c.private_droidguard_inputs().unwrap();
    let salt = c.private_droidguard_salt();
    for (key, value) in [
        ("APP_NAME", format!("{}{salt}", p.application_package)),
        (
            "PROVISIONING_SESSION_ID",
            format!("{}{salt}", p.caller_session_id),
        ),
        ("DROIDGUARD_SALT", salt.to_owned()),
        ("DROIDGUARD_CONTENT_BINDING_VERSION", format!("2{salt}")),
    ] {
        let digest = ring::digest::digest(&ring::digest::SHA384, value.as_bytes());
        let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(map[key], hex);
    }
    assert_eq!(map.len(), 9);
    assert!(!body.contains("filename="));
    assert!(!r.url().as_str().contains("synthetic-carrier-token"));
    assert!(!format!("{c:?}").contains("synthetic"));
}
#[test]
fn rejects_replaced_cookies_invalid_signature_and_unsafe_method_name() {
    let s = AcsSession::new("https://acs.example.test/").unwrap();
    let p = parameters();
    let c = context(&s, &p)
        .bind_carrier("synthetic-carrier-token")
        .unwrap();
    let (public, wrong) = signature(b"wrong-nonce");
    let proof = MlsProof {
        public_key_der: &public,
        signature_der: &wrong,
        home_kds: 2,
    };
    assert!(c.make_request(b"synthetic-VM-bytes", &proof).is_err());
    let (public, sig) = signature(&c.private_mls_signing_input());
    let proof = MlsProof {
        public_key_der: &public,
        signature_der: &sig,
        home_kds: 2,
    };
    for raw in [b"".as_slice(), b"ERROR : local failure"] {
        assert!(c.make_request(raw, &proof).is_err());
    }
    s.cookies.add_cookie_str(
        "JIBE_ACS_COOKIE=replaced-cookie; Path=/; Secure",
        &s.endpoint,
    );
    assert!(c.make_request(b"synthetic-VM-bytes", &proof).is_err());
    drop(c);
    for bad in ["bad\"name", "bad\\name", "bad\r\nname"] {
        let mut c = context(&s, &p);
        c.challenge.method_id = bad.into();
        assert!(c.bind_carrier("synthetic-carrier-token").is_err());
    }
    for token in ["", "bad\ntoken"] {
        assert!(context(&s, &p).bind_carrier(token).is_err());
    }
    let c = context(&s, &p)
        .bind_carrier("synthetic-carrier-token")
        .unwrap();
    let (public, sig) = signature(&c.private_mls_signing_input());
    s.cookies
        .add_cookie_str("EXTRA=changed; Path=/; Secure", &s.endpoint);
    assert!(
        c.make_request(
            b"synthetic-VM-bytes",
            &MlsProof {
                public_key_der: &public,
                signature_der: &sig,
                home_kds: 2
            }
        )
        .is_err()
    );
}

#[tokio::test]
async fn missing_or_ambiguous_cookie_stops_before_carrier_acquisition() {
    use crate::acs::tests::{mock_session, reply};
    for cookies in [
        "",
        "Set-Cookie: EXTRA=not-a-JIBE-cookie; Path=/\r\n",
        "Set-Cookie: JIBE_ACS_COOKIE=one; Path=/\r\nSet-Cookie: JIBE_ACS_COOKIE=two; Path=/base/\r\n",
    ] {
        let (s, server) = mock_session(vec![reply(
            200,
            &format!("Content-Type: application/vnd.gsma.cfg-clientauth+xml\r\n{cookies}"),
            include_str!("../../../tests/fixtures/clientauth.xml"),
        )])
        .await;
        let mut s = s;
        s.endpoint.set_path("/base/");
        let p = parameters();
        assert!(s.direct_challenge(&p).await.is_err());
        assert_eq!(server.await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn a_new_challenge_cannot_reuse_a_previous_get_cookie() {
    use crate::acs::tests::{mock_session, reply};
    let xml = include_str!("../../../tests/fixtures/clientauth.xml");
    let(s,server)=mock_session(vec![reply(200,"Content-Type: application/vnd.gsma.cfg-clientauth+xml\r\nSet-Cookie: JIBE_ACS_COOKIE=previous-cookie; Path=/\r\n",xml),reply(200,"Content-Type: application/vnd.gsma.cfg-clientauth+xml\r\n",xml)]).await;
    let p = parameters();
    let first = s.direct_challenge(&p).await.unwrap();
    assert!(matches!(first, DirectStart::Challenge(_)));
    drop(first);
    assert!(matches!(
        s.direct_challenge(&p).await,
        Err(Error::InvalidInput(
            "ACS challenge requires fresh cookie state"
        ))
    ));
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn credential_post_never_redirects_or_retries_service_rejections() {
    use crate::acs::tests::{mock_session, reply};
    let sink = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let location = format!(
        "Location: http://{}/private\r\n",
        sink.local_addr().unwrap()
    );
    for (status, extra) in [(302, location.as_str()), (503, "Retry-After: 60\r\n")] {
        let(s,server)=mock_session(vec![reply(200,"Content-Type: application/vnd.gsma.cfg-clientauth+xml\r\nSet-Cookie: JIBE_ACS_COOKIE=synthetic-cookie; Path=/\r\n",include_str!("../../../tests/fixtures/clientauth.xml")),reply(status,extra,"")]).await;
        let p = parameters();
        let DirectStart::Challenge(c) = s.direct_challenge(&p).await.unwrap() else {
            panic!("challenge")
        };
        let c = c.bind_carrier("synthetic-carrier-token").unwrap();
        let (public, sig) = signature(&c.private_mls_signing_input());
        let result = c
            .provision(
                b"synthetic-VM-bytes",
                &MlsProof {
                    public_key_der: &public,
                    signature_der: &sig,
                    home_kds: 2,
                },
            )
            .await;
        assert!(matches!(result,Err(Error::Http{status:s,..}) if s==status));
        assert_eq!(server.await.unwrap().len(), 2);
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), sink.accept())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn direct_exchange_preserves_nonce_rules_and_classifies_wap_without_proof() {
    use crate::acs::tests::{mock_session, reply};
    let xml = include_str!("../../../tests/fixtures/clientauth.xml")
        .replace("synthetic-nonce", " \n\t\u{a0}synthetic-nonce\u{a0}\t ")
        .replace("synthetic-challenge", "  synthetic-challenge  ");
    let (mut s,server)=mock_session(vec![reply(200,"Content-Type: application/vnd.gsma.cfg-clientauth+xml\r\nSet-Cookie: JIBE_ACS_COOKIE=synthetic-cookie; Path=/\r\nSet-Cookie: EXTRA=keep-me; Path=/\r\n",&xml),reply(200,"Content-Type: application/vnd.wap.connectivity-xml\r\n","<wap-provisioningdoc/>")]).await;
    s.endpoint.set_path("/configured/path/");
    let p = parameters();
    let DirectStart::Challenge(c) = s.direct_challenge(&p).await.unwrap() else {
        panic!("challenge")
    };
    assert_eq!(c.challenge.nonce(), "\u{a0}synthetic-nonce\u{a0}");
    assert_eq!(c.challenge.challenge(), "  synthetic-challenge  ");
    assert!(matches!(
        s.begin_exchange(),
        Err(Error::InvalidInput("ACS session exchange already active"))
    ));
    let c = c.bind_carrier("synthetic-carrier-token").unwrap();
    assert_eq!(c.private_mls_nonce(), "\u{a0}synthetic-nonce\u{a0}");
    let (public, sig) = signature(&c.private_mls_signing_input());
    let response = c
        .provision(
            b"synthetic-VM-bytes",
            &MlsProof {
                public_key_der: &public,
                signature_der: &sig,
                home_kds: 2,
            },
        )
        .await
        .unwrap();
    assert!(matches!(response, Response::WapConfiguration(_)));
    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /configured/path/?"));
    assert!(requests[1].starts_with("POST /configured/path/?"));
    assert!(requests[1].contains("EXTRA=keep-me"));
    let (s, server) = mock_session(vec![reply(
        200,
        "Content-Type: application/vnd.wap.connectivity-xml\r\n",
        "<wap-provisioningdoc/>",
    )])
    .await;
    let DirectStart::WapConfiguration(bytes) = s.direct_challenge(&p).await.unwrap() else {
        panic!("opaque WAP")
    };
    assert_eq!(bytes.as_ref(), b"<wap-provisioningdoc/>");
    assert_eq!(server.await.unwrap().len(), 1);
}
#[tokio::test]
async fn wait_header_on_success_status_stops_before_carrier_and_never_retries() {
    use crate::acs::tests::{mock_session, reply};
    for value in ["60", "", "Wed, 21 Oct 2026 07:28:00 GMT", "invalid"] {
        let (s, server) = mock_session(vec![reply(
            200,
            &format!(
                "Content-Type: application/vnd.gsma.cfg-clientauth+xml\r\nRetry-After: {value}\r\n"
            ),
            include_str!("../../../tests/fixtures/clientauth.xml"),
        )])
        .await;
        let p = parameters();
        assert!(matches!(
            s.direct_challenge(&p).await,
            Err(Error::Http { status: 200, .. })
        ));
        assert_eq!(server.await.unwrap().len(), 1);
    }
}
