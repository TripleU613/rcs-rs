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

#[derive(Clone, PartialEq, prost::Message)]
struct FutureResponse {
    #[prost(message, optional, tag = "1")]
    legacy: Option<wire::Consent>,
    #[prost(message, repeated, tag = "8")]
    consumers: Vec<wire::ConsumerConsent>,
    #[prost(int32, tag = "99")]
    unknown: i32,
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
        assert_eq!(
            request.uri().path(),
            "/google.internal.communications.phonedeviceverification.v1.PhoneDeviceVerification/GetConsent"
        );
        let handler = self.clone();
        Box::pin(async move {
            let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
            Ok(grpc.unary(handler, request).await)
        })
    }
}

impl tonic::server::UnaryService<wire::GetConsentRequest> for Fixture {
    type Response = FutureResponse;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Self::Response>, Status>> + Send>>;
    fn call(&mut self, request: Request<wire::GetConsentRequest>) -> Self::Future {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            request.metadata().get("x-goog-api-key").unwrap(),
            "synthetic-api-key"
        );
        assert_eq!(
            request.metadata().get("x-android-package").unwrap(),
            "org.example.gms"
        );
        assert_eq!(
            request.metadata().get("x-android-cert").unwrap(),
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert!(request.metadata().get("grpc-timeout").is_some());
        let message = request.into_inner();
        assert_eq!(message.device.unwrap().device_android_id, 0);
        let info = message.header.unwrap().info.unwrap();
        assert_eq!(info.device.unwrap().user_android_id, 123456);
        assert_eq!(info.signals.unwrap().raw_droidguard.len(), 32 * 1024);
        let status = self.status.clone();
        Box::pin(async move {
            if let Some(status) = status {
                return Err(status);
            }
            Ok(Response::new(FutureResponse {
                legacy: Some(wire::Consent {
                    state: 0,
                    detail: 0,
                }),
                consumers: vec![wire::ConsumerConsent {
                    client: 2,
                    state: 1,
                    detail: 5,
                }],
                unknown: 7,
            }))
        })
    }
}

async fn run(status: Option<Status>) -> (Result<ConsentResponse, Error>, usize) {
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
        "0123456789abcdef0123456789abcdef01234567",
    )
    .unwrap();
    let mut input = tests::input();
    input.attestation = Attestation::RawDroidGuard("x".repeat(32 * 1024));
    let message = make_request(&input, "00000000-0000-4000-8000-000000000000").unwrap();
    let result = query_channel(channel, &metadata, message).await;
    let _ = shutdown.send(());
    server.await.unwrap();
    (result, calls.load(Ordering::SeqCst))
}

#[tokio::test]
async fn large_realistic_proof_fits_transport_and_retains_unknown_response_fields() {
    let (result, calls) = run(None).await;
    let response = result.unwrap();
    assert_eq!(response.rcs_state(), Some(1));
    assert!(response.raw_protobuf().ends_with(&[152, 6, 7]));
    assert_eq!(calls, 1);
}

#[tokio::test]
async fn grpc_trailers_preserve_error_backoff_without_secret_reflection_or_retry() {
    let mut status = Status::resource_exhausted("synthetic-private-server-detail");
    status
        .metadata_mut()
        .insert("grpc-retry-pushback-ms", "7000".parse().unwrap());
    let (result, calls) = run(Some(status)).await;
    let error = result.unwrap_err();
    assert_eq!(
        error.rpc_status().unwrap().code(),
        tonic::Code::ResourceExhausted
    );
    assert_eq!(error.retry_after(), Some(Duration::from_secs(7)));
    assert!(!format!("{error:?} {error}").contains("synthetic-private-server-detail"));
    assert_eq!(calls, 1);
}
