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
#[derive(Clone, PartialEq, prost::Message)]
struct Incoming {
    #[prost(bytes = "bytes", tag = "2")]
    verification: Bytes,
    #[prost(bytes = "bytes", tag = "3")]
    data: Bytes,
    #[prost(bytes = "bytes", tag = "4")]
    header: Bytes,
}
#[derive(Clone, PartialEq, prost::Message)]
struct FutureResponse {
    #[prost(bytes = "bytes", tag = "1")]
    record: Bytes,
    #[prost(int32, tag = "99")]
    unknown: i32,
}
#[derive(Clone)]
struct Fixture {
    path: &'static str,
    expected: Vec<u8>,
    record: Bytes,
    status: Option<Status>,
    calls: Arc<AtomicUsize>,
}
impl tonic::server::NamedService for Fixture {
    const NAME: &'static str =
        "google.internal.communications.phonedeviceverification.v1.PhoneDeviceVerification";
}
impl Service<http::Request<Body>> for Fixture {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        assert_eq!(request.uri().path(), self.path);
        let handler = self.clone();
        Box::pin(async move {
            let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
            Ok(grpc.unary(handler, request).await)
        })
    }
}
impl tonic::server::UnaryService<Incoming> for Fixture {
    type Response = FutureResponse;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Self::Response>, Status>> + Send>>;
    fn call(&mut self, request: Request<Incoming>) -> Self::Future {
        self.calls.fetch_add(1, Ordering::SeqCst);
        for (key, value) in [
            ("x-goog-api-key", "synthetic-api-key"),
            ("x-android-package", "org.example.gms"),
            ("x-android-cert", "0123456789abcdef0123456789abcdef01234567"),
        ] {
            assert_eq!(request.metadata().get(key).unwrap(), value);
        }
        assert!(request.metadata().get("grpc-timeout").is_some());
        assert_eq!(request.into_inner().encode_to_vec(), self.expected);
        let reply = FutureResponse {
            record: self.record.clone(),
            unknown: 7,
        };
        let status = self.status.clone();
        Box::pin(async move {
            if let Some(status) = status {
                Err(status)
            } else {
                Ok(Response::new(reply))
            }
        })
    }
}
async fn run(proceed: bool, status: Option<Status>) -> (Result<Bytes, Error>, usize) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let (path, expected, record) = if proceed {
        let response = super::super::wire::ProceedResponse::decode(Bytes::from_static(
            include_bytes!("../../../tests/fixtures/verification-proceed-failed.bin"),
        ))
        .unwrap();
        (
            "/google.internal.communications.phonedeviceverification.v1.PhoneDeviceVerification/Proceed",
            include_bytes!("../../../tests/fixtures/proceed-request.bin").to_vec(),
            response.verifications[0].clone(),
        )
    } else {
        let response = super::super::wire::SyncResponse::decode(Bytes::from_static(
            include_bytes!("../../../tests/fixtures/verification-sync-throttled.bin"),
        ))
        .unwrap();
        (
            "/google.internal.communications.phonedeviceverification.v1.PhoneDeviceVerification/Sync",
            include_bytes!("../../../tests/fixtures/sync-request.bin").to_vec(),
            response.results[0].clone(),
        )
    };
    let fixture = Fixture {
        path,
        expected,
        record,
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
        "0123456789abcdef0123456789abcdef01234567",
    )
    .unwrap();
    let result = if proceed {
        let response = SyncResponse::decode(Bytes::from_static(include_bytes!(
            "../../../tests/fixtures/verification-sync-pending.bin"
        )))
        .unwrap();
        let history = vec![
            "synthetic-actual-request-log".into(),
            "synthetic-actual-response-log".into(),
        ];
        let message = make_proceed(
            &tests::identity(true),
            tests::SESSION,
            response.results[0].verification.as_ref().unwrap(),
            tests::CARRIER,
            &history,
        )
        .unwrap();
        send_channel(channel, &metadata, message, path).await
    } else {
        send_channel(
            channel,
            &metadata,
            make_sync(&tests::identity(false), &tests::sim()).unwrap(),
            path,
        )
        .await
    };
    shutdown.send(()).unwrap();
    server.await.unwrap();
    (result, calls.load(Ordering::SeqCst))
}
#[tokio::test]
async fn sync_keeps_per_record_throttle_even_when_grpc_succeeds() {
    let (result, calls) = run(false, None).await;
    assert_eq!(calls, 1);
    let bytes = result.unwrap();
    assert!(bytes.ends_with(&[0x98, 6, 7]));
    let out = SyncResponse::decode(bytes).unwrap();
    assert_eq!(out.results[0].status.as_ref().unwrap().code, Some(8));
    assert_eq!(
        out.results[0]
            .verification
            .as_ref()
            .unwrap()
            .unverified_reason,
        Some(1)
    );
}
#[tokio::test]
async fn proceed_keeps_verification_failure_in_successful_envelope() {
    let (result, calls) = run(true, None).await;
    assert_eq!(calls, 1);
    let out = ProceedResponse::decode(result.unwrap()).unwrap();
    assert_eq!(out.verification.as_ref().unwrap().state, Some(1));
    assert_eq!(
        out.verification.as_ref().unwrap().unverified_reason,
        Some(2)
    );
}
#[tokio::test]
async fn transport_reports_backoff_without_retrying_or_reflecting_server_secrets() {
    let mut status = Status::resource_exhausted("synthetic-secret-in-server-error");
    status
        .metadata_mut()
        .insert("grpc-retry-pushback-ms", "5000".parse().unwrap());
    let (result, calls) = run(false, Some(status)).await;
    assert_eq!(calls, 1);
    let error = result.unwrap_err();
    assert_eq!(error.retry_after(), Some(Duration::from_secs(5)));
    assert!(!format!("{error:?}").contains("synthetic-secret"));
}
