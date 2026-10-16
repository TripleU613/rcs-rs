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
    time::Duration,
};
use tonic::{Request, Response, Status, body::Body, codegen::Service};

#[derive(Clone)]
struct FixtureService {
    reply: Result<wire::GetConfigurationResponse, Status>,
    calls: Arc<AtomicUsize>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct FutureServerResponse {
    #[prost(message, repeated, tag = "1")]
    configurations: Vec<wire::Configuration>,
    #[prost(uint32, repeated, tag = "2")]
    experiment_ids: Vec<u32>,
    #[prost(uint32, tag = "99")]
    future_server_field: u32,
}

impl tonic::server::NamedService for FixtureService {
    const NAME: &'static str =
        "google.internal.communications.mobileconfiguration.v1.MobileConfigurationService";
}

type ServerFuture = Pin<Box<dyn Future<Output = Result<http::Response<Body>, Infallible>> + Send>>;

impl Service<http::Request<Body>> for FixtureService {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = ServerFuture;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        assert_eq!(
            request.uri().path(),
            "/google.internal.communications.mobileconfiguration.v1.MobileConfigurationService/GetConfiguration"
        );
        let handler = self.clone();
        Box::pin(async move {
            let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
            Ok(grpc.unary(handler, request).await)
        })
    }
}

impl tonic::server::UnaryService<wire::GetConfigurationRequest> for FixtureService {
    type Response = FutureServerResponse;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Self::Response>, Status>> + Send>>;

    fn call(&mut self, request: Request<wire::GetConfigurationRequest>) -> Self::Future {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            request.metadata().get("x-goog-api-key").unwrap(),
            "synthetic-secret"
        );
        assert_eq!(
            request.metadata().get("x-android-package").unwrap(),
            "org.example.sms"
        );
        assert_eq!(
            request.get_ref().context.as_ref().unwrap().gsf_android_id,
            0
        );
        assert_eq!(
            request.get_ref().parameters[0]
                .carrier
                .as_ref()
                .unwrap()
                .mcc,
            "001"
        );
        assert_eq!(
            request.get_ref().parameters[0]
                .carrier
                .as_ref()
                .unwrap()
                .mnc,
            "01"
        );
        let reply = self.reply.clone();
        Box::pin(async move {
            reply.map(|message| {
                Response::new(FutureServerResponse {
                    configurations: message.configurations,
                    experiment_ids: message.experiment_ids,
                    future_server_field: 7,
                })
            })
        })
    }
}

async fn run_query(
    reply: Result<wire::GetConfigurationResponse, Status>,
) -> (Result<Discovery, Error>, usize) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let service = FixtureService {
        reply,
        calls: calls.clone(),
    };
    let (shutdown, receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
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
    let metadata = ClientMetadata::new(
        "synthetic-secret",
        "org.example.sms",
        "0123456789abcdef0123456789abcdef01234567",
    )
    .unwrap();
    let probe = Probe::new(Carrier::new("001", "01").unwrap(), "generic", "Example", 1).unwrap();
    let result = query_channel(channel, &metadata, &probe).await;
    let _ = shutdown.send(());
    server.await.unwrap();
    (result, calls.load(Ordering::SeqCst))
}

#[tokio::test]
async fn http2_probe_sends_expected_request_and_returns_config() {
    let response = wire::GetConfigurationResponse::decode(
        include_bytes!("../tests/fixtures/onboarding.bin").as_slice(),
    )
    .unwrap();
    let (result, calls) = run_query(Ok(response)).await;
    let result = result.unwrap();
    assert_eq!(result.flags.rcs_enabled_state, 1);
    assert!(result.raw_protobuf().ends_with(&[0x98, 0x06, 0x07]));
    assert_eq!(calls, 1);
}

#[tokio::test]
async fn grpc_trailer_error_retains_backoff_without_retrying() {
    let mut status = Status::resource_exhausted("synthetic-secret server detail");
    status
        .metadata_mut()
        .insert("grpc-retry-pushback-ms", "1500".parse().unwrap());
    let (result, calls) = run_query(Err(status)).await;
    let error = result.expect_err("server rejected the RPC");
    assert_eq!(
        error.rpc_status().unwrap().code(),
        tonic::Code::ResourceExhausted
    );
    assert_eq!(error.retry_after(), Some(Duration::from_millis(1500)));
    assert_eq!(calls, 1);
    assert!(!format!("{error:?}").contains("synthetic-secret"));
}

#[test]
fn rpc_debug_redacts_server_details_and_metadata() {
    let error = Error::Rpc(Box::new(Status::unauthenticated("synthetic-secret")));
    assert!(!format!("{error:?}").contains("synthetic-secret"));
}
