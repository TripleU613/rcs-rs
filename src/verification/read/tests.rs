use super::*;
use std::time::{Duration, UNIX_EPOCH};

const SESSION: &str = "01234567-89ab-4cde-8fab-0123456789ab";
fn input() -> ReadNumbersRequest {
    ReadNumbersRequest {
        iid_token: "synthetic-read-iid".into(),
        signed_at: UNIX_EPOCH + Duration::new(1_700_000_000, 123_000_000),
        signature_der: vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
        caller_certificate_sha1: [0x01; 20],
        calling_package: "org.example.sms".into(),
        caller_nonce: "synthetic-caller-nonce".into(),
    }
}

#[test]
fn read_request_sends_signed_identity_and_rcs_caller_fields_at_original_tags() {
    let request = make_request(&input(), SESSION).unwrap();
    assert_eq!(
        request.encode_to_vec(),
        include_bytes!("../../../tests/fixtures/read-numbers-request.bin")
    );
    let diagnostic = format!("{:?} {:?}", input(), request);
    assert!(!diagnostic.contains("synthetic-read-iid"));
    assert!(!diagnostic.contains("synthetic-caller-nonce"));
}

#[test]
fn invalid_signing_identity_and_request_inputs_are_rejected() {
    for iid in ["".to_string(), "synthetic\nsecret".into(), "x".repeat(4097)] {
        assert!(read_numbers_signing_input(&iid, UNIX_EPOCH).is_err());
    }
    assert!(read_numbers_signing_input("iid", UNIX_EPOCH - Duration::from_secs(1)).is_err());
    for change in [
        |r: &mut ReadNumbersRequest| r.iid_token.clear(),
        |r: &mut ReadNumbersRequest| r.signature_der.clear(),
        |r: &mut ReadNumbersRequest| r.signature_der = vec![1; 129],
        |r: &mut ReadNumbersRequest| r.calling_package = "synthetic\nsecret".into(),
        |r: &mut ReadNumbersRequest| r.caller_nonce = "synthetic\nsecret".into(),
        |r: &mut ReadNumbersRequest| r.signed_at = UNIX_EPOCH - Duration::from_secs(1),
    ] {
        let mut r = input();
        change(&mut r);
        assert!(make_request(&r, SESSION).is_err());
    }
}

#[test]
fn signing_input_uses_exact_seconds_and_nanoseconds_without_rounding() {
    let at = UNIX_EPOCH + Duration::new(1_700_000_000, 123_000_000);
    assert_eq!(
        read_numbers_signing_input("synthetic-read-iid", at).unwrap(),
        b"synthetic-read-iid:1700000000:123000000"
    );
}

#[test]
fn empty_success_has_no_verified_records() {
    let result = ReadNumbersResponse::decode(Bytes::new()).unwrap();
    assert!(result.numbers.is_empty());
    assert!(result.raw_protobuf().is_empty());
}

#[test]
fn service_records_preserve_unknowns_and_redact_phone_and_credential() {
    let raw = Bytes::from_static(include_bytes!(
        "../../../tests/fixtures/read-numbers-response.bin"
    ));
    let result = ReadNumbersResponse::decode(raw.clone()).unwrap();
    assert_eq!(result.raw_protobuf(), raw);
    assert_eq!(result.numbers.len(), 1);
    let row = &result.numbers[0];
    assert_eq!(row.private_phone_number(), Some("+10000000000"));
    assert_eq!(row.private_id_token(), Some("synthetic-read-token"));
    assert_eq!(row.rcs_state, Some(99));
    assert!(row.raw_protobuf().ends_with(&[0x98, 6, 7]));
    let diagnostic = format!("{result:?} {row:?}");
    assert!(!diagnostic.contains("10000000000"));
    assert!(!diagnostic.contains("synthetic-read-token"));
}

#[test]
fn ambiguous_or_oversized_records_are_rejected_without_reflecting_data() {
    for bytes in [
        b"\x12\x06\x0a\x01a\x0a\x01b".to_vec(),
        b"\x12\x04\x20\x01\x20\x02".to_vec(),
        b"\x12\x03\x22\x01\x01".to_vec(),
        vec![0; 256 * 1024 + 1],
        b"\x12\x0f".to_vec(),
    ] {
        let error = ReadNumbersResponse::decode(bytes.into()).unwrap_err();
        assert!(!format!("{error:?}").contains("synthetic-read-token"));
    }
    let rows = b"\x12\x00".repeat(65);
    assert!(ReadNumbersResponse::decode(rows.into()).is_err());
}

#[test]
fn duplicate_credentials_and_unbounded_text_are_not_exposed_as_records() {
    let duplicate = b"\x12\x06\x1a\x01a\x1a\x01b";
    assert!(ReadNumbersResponse::decode(Bytes::from_static(duplicate)).is_err());
    let token = ReadNumberWire {
        phones: vec![],
        tokens: vec!["x".repeat(MAX_TEXT + 1)],
        states: vec![],
    };
    let response = ReadResponseWire {
        records: vec![token.encode_to_vec().into()],
    };
    assert!(ReadNumbersResponse::decode(response.encode_to_vec().into()).is_err());
}

#[tokio::test]
async fn invalid_request_is_rejected_before_connecting() {
    let mut request = input();
    request.signature_der.clear();
    let metadata = crate::ClientMetadata::new(
        "synthetic-key",
        "org.example.gms",
        "0101010101010101010101010101010101010101",
    )
    .unwrap();
    assert!(matches!(
        read_verified_numbers(&metadata, &request).await,
        Err(Error::InvalidInput(_))
    ));
}

mod transport {
    use super::*;
    use std::{
        convert::Infallible,
        future::Future,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };
    use tonic::{Request, Response, Status, body::Body, codegen::Service};

    #[derive(Clone)]
    struct Fixture {
        status: Option<Status>,
        calls: Arc<AtomicUsize>,
    }
    impl tonic::server::NamedService for Fixture {
        const NAME: &'static str =
            "google.internal.communications.phonedeviceverification.v1.PhoneNumber";
    }
    impl Service<http::Request<Body>> for Fixture {
        type Response = http::Response<Body>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, request: http::Request<Body>) -> Self::Future {
            assert_eq!(
                request.uri().path(),
                "/google.internal.communications.phonedeviceverification.v1.PhoneNumber/GetVerifiedPhoneNumbers"
            );
            let handler = self.clone();
            Box::pin(async move {
                let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                Ok(grpc.unary(handler, request).await)
            })
        }
    }
    impl tonic::server::UnaryService<ReadRequestWire> for Fixture {
        type Response = ReadResponseWire;
        type Future =
            Pin<Box<dyn Future<Output = Result<Response<Self::Response>, Status>> + Send>>;
        fn call(&mut self, request: Request<ReadRequestWire>) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            for (key, value) in [
                ("x-goog-api-key", "synthetic-api-key"),
                ("x-android-package", "org.example.gms"),
                ("x-android-cert", "0101010101010101010101010101010101010101"),
            ] {
                assert_eq!(request.metadata().get(key).unwrap(), value);
            }
            assert!(request.metadata().get("grpc-timeout").is_some());
            assert_eq!(
                request.into_inner().encode_to_vec(),
                include_bytes!("../../../tests/fixtures/read-numbers-request.bin")
            );
            let status = self.status.clone();
            Box::pin(async move {
                if let Some(status) = status {
                    Err(status)
                } else {
                    Ok(Response::new(ReadResponseWire { records: vec![] }))
                }
            })
        }
    }
    async fn run(status: Option<Status>) -> (Result<ReadNumbersResponse, Error>, usize) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let fixture = Fixture {
            status,
            calls: calls.clone(),
        };
        let (shutdown, receiver) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(fixture)
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = receiver.await;
                    },
                )
                .await
                .unwrap();
        });
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let metadata = crate::ClientMetadata::new(
            "synthetic-api-key",
            "org.example.gms",
            "0101010101010101010101010101010101010101",
        )
        .unwrap();
        let result = super::super::super::request::send_channel(
            channel,
            &metadata,
            make_request(&input(), SESSION).unwrap(),
            PATH,
        )
        .await
        .and_then(ReadNumbersResponse::decode);
        shutdown.send(()).unwrap();
        server.await.unwrap();
        (result, calls.load(Ordering::SeqCst))
    }
    #[tokio::test]
    async fn accepted_empty_query_remains_empty() {
        let (result, calls) = run(None).await;
        assert_eq!(calls, 1);
        assert!(result.unwrap().numbers.is_empty());
    }
    #[tokio::test]
    async fn project_quota_is_an_error_without_retry_or_private_error_text() {
        let mut status = Status::resource_exhausted("synthetic-private-server-message");
        status
            .metadata_mut()
            .insert("grpc-retry-pushback-ms", "5000".parse().unwrap());
        let (result, calls) = run(Some(status)).await;
        let error = result.unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(error.retry_after(), Some(Duration::from_secs(5)));
        assert!(!format!("{error:?}").contains("synthetic-private-server-message"));
    }
}
