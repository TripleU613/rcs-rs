//! Opt-in PDV experiment: RCS_PDV_HTTP_PROXY=IP:port. No direct fallback.
use std::{io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub(super) async fn connect(address: SocketAddr) -> io::Result<hyper_util::rt::TokioIo<TcpStream>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(b"CONNECT phonedeviceverification-pa.googleapis.com:443 HTTP/1.1\r\nHost: phonedeviceverification-pa.googleapis.com:443\r\n\r\n").await?;
        // Read only the header so no tunneled TLS bytes are consumed here.
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() == 8192 {
                return Err(io::Error::other("proxy response header too large"));
            }
            header.push(stream.read_u8().await?);
        }
        let line = header.split(|b| *b == b'\r').next().unwrap_or_default();
        let mut fields = line.split(|b| *b == b' ');
        if !matches!(fields.next(), Some(b"HTTP/1.1" | b"HTTP/1.0")) || fields.next() != Some(b"200") {
            return Err(io::Error::other("proxy refused CONNECT"));
        }
        // Tonic applies its usual origin TLS and hostname verification to this tunnel.
        Ok(hyper_util::rt::TokioIo::new(stream))
    }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy CONNECT timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "explicit public proxy TLS/HTTP2 connection check; sends no verification RPC"]
    async fn live_proxy_connects_with_origin_tls() {
        let address: SocketAddr = std::env::var("RCS_PDV_HTTP_PROXY")
            .unwrap()
            .parse()
            .unwrap();
        tonic::transport::Endpoint::from_static(
            "https://phonedeviceverification-pa.googleapis.com",
        )
        .tls_config(tonic::transport::ClientTlsConfig::new().with_native_roots())
        .unwrap()
        .connect_timeout(Duration::from_secs(10))
        .connect_with_connector(tower::service_fn(move |_| connect(address)))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn accepts_only_successful_bounded_connect() {
        for (reply, accepted) in [
            (
                b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec(),
                true,
            ),
            (
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".to_vec(),
                false,
            ),
            (b"HTTP/1.1 2000 Bad\r\n\r\n".to_vec(), false),
            (vec![b'x'; 8193], false),
            (b"HTTP/1.1 200".to_vec(), false),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(socket.read_u8().await.unwrap());
                }
                assert_eq!(request, b"CONNECT phonedeviceverification-pa.googleapis.com:443 HTTP/1.1\r\nHost: phonedeviceverification-pa.googleapis.com:443\r\n\r\n");
                let _ = socket.write_all(&reply).await;
            });
            assert_eq!(connect(address).await.is_ok(), accepted);
            server.await.unwrap();
        }
    }
}
