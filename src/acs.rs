//! ACS challenges and recovered UPI provisioning; no attestation generation or registration.
use bytes::Bytes;
use reqwest::cookie::{CookieStore, Jar};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

mod upi;
pub use upi::{MlsProof, UpiChallenge, UpiParameters};

const AUTH_MEDIA_TYPE: &str = "application/vnd.gsma.cfg-clientauth+xml";
const AUTH_NS: &str = "urn:gsma:params:xml:ns:cfg:clientauth:req";
const MAX_BODY: usize = 64 * 1024;

pub struct ClientParameters<'a> {
    pub terminal_vendor: &'a str,
    pub terminal_model: &'a str,
    pub terminal_sw_version: &'a str,
    pub client_vendor: &'a str,
    pub client_version: &'a str,
    pub rcs_profile: &'a str,
    pub rcs_version: &'a str,
}

pub struct AcsSession {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    cookies: Arc<Jar>,
    exchange_active: AtomicBool,
}

struct ExchangeLease<'a>(&'a AtomicBool);
impl Drop for ExchangeLease<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl fmt::Debug for AcsSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcsSession")
            .field("host", &self.endpoint.host_str())
            .field("cookies", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl AcsSession {
    pub fn new(endpoint: &str) -> Result<Self, Error> {
        let endpoint =
            reqwest::Url::parse(endpoint).map_err(|_| Error::InvalidInput("HTTPS endpoint"))?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(Error::InvalidInput("HTTPS endpoint"));
        }
        let cookies = Arc::new(Jar::default());
        let client = client_builder(cookies.clone())
            .build()
            .map_err(|e| Error::Transport(e.without_url()))?;
        Ok(Self {
            client,
            endpoint,
            cookies,
            exchange_active: AtomicBool::new(false),
        })
    }

    fn begin_exchange(&self) -> Result<ExchangeLease<'_>, Error> {
        self.exchange_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::InvalidInput("ACS session exchange already active"))?;
        Ok(ExchangeLease(&self.exchange_active))
    }

    pub fn host(&self) -> &str {
        self.endpoint.host_str().expect("validated HTTPS endpoint")
    }

    pub fn has_session_cookie(&self) -> bool {
        self.cookies
            .cookies(&self.endpoint)
            .and_then(|header| {
                header.to_str().ok().map(|value| {
                    value
                        .split(';')
                        .any(|part| part.trim_start().starts_with("JIBE_ACS_COOKIE="))
                })
            })
            .unwrap_or(false)
    }

    fn initial_request(
        &self,
        parameters: &ClientParameters<'_>,
    ) -> Result<reqwest::Request, Error> {
        let metadata = [
            ("terminal_vendor", parameters.terminal_vendor),
            ("terminal_model", parameters.terminal_model),
            ("terminal_sw_version", parameters.terminal_sw_version),
            ("client_vendor", parameters.client_vendor),
            ("client_version", parameters.client_version),
            ("rcs_profile", parameters.rcs_profile),
            ("rcs_version", parameters.rcs_version),
        ];
        for (name, value) in metadata {
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err(Error::InvalidInput(name));
            }
        }
        self.client
            .get(self.endpoint.clone())
            .query(&[
                ("vers", "0"),
                ("rcs_state", "0"),
                metadata[0],
                metadata[1],
                metadata[2],
                metadata[3],
                metadata[4],
                metadata[5],
                metadata[6],
                ("device_type", "phone"),
                ("token", ""),
                ("SMS_port", "0"),
                ("client_authenticity_support", "goog-droidguard"),
            ])
            .build()
            .map_err(|e| Error::Transport(e.without_url()))
    }

    /// One initial request, preserving origin-scoped cookies in this session. No automatic retries.
    pub async fn initial_challenge(
        &self,
        parameters: &ClientParameters<'_>,
    ) -> Result<Response, Error> {
        let _exchange = self.begin_exchange()?;
        let request = self.initial_request(parameters)?;
        let (content_type, body) = self.response_body(request).await?;
        parse_response(&content_type, &body)
    }

    async fn response_body(&self, request: reqwest::Request) -> Result<(String, Vec<u8>), Error> {
        let mut response = self
            .client
            .execute(request)
            .await
            .map_err(|e| Error::Transport(e.without_url()))?;
        if response.status() != reqwest::StatusCode::OK {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok())
                .map(Duration::from_secs);
            return Err(Error::Http {
                status: response.status().as_u16(),
                retry_after,
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BODY as u64)
        {
            return Err(Error::BodyTooLarge);
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| Error::Transport(e.without_url()))?
        {
            if chunk.len() > MAX_BODY - body.len() {
                return Err(Error::BodyTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok((content_type, body))
    }
}

fn client_builder(cookies: Arc<Jar>) -> reqwest::ClientBuilder {
    // Reuse the crate's existing ring provider; respect a provider installed by the host.
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    reqwest::Client::builder()
        .cookie_provider(cookies)
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
}

pub struct Challenge {
    method_id: String,
    challenge: String,
    nonce: String,
}

impl Challenge {
    pub fn method_id(&self) -> &str {
        &self.method_id
    }
    pub fn challenge(&self) -> &str {
        &self.challenge
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
}

impl fmt::Debug for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Challenge([REDACTED])")
    }
}

pub enum Response {
    Challenge(Challenge),
    /// Opaque server-labeled WAP configuration; not yet validated as provisioned.
    WapConfiguration(Bytes),
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Challenge(_) => "Response::Challenge([REDACTED])",
            Self::WapConfiguration(_) => "Response::WapConfiguration([REDACTED])",
        })
    }
}

pub enum Error {
    InvalidInput(&'static str),
    InvalidXml,
    InvalidChallenge(&'static str),
    UnsupportedMediaType,
    BodyTooLarge,
    Http {
        status: u16,
        retry_after: Option<Duration>,
    },
    Transport(reqwest::Error),
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(_) => f.write_str("Transport([REDACTED])"),
            Self::InvalidInput(reason) => f.debug_tuple("InvalidInput").field(reason).finish(),
            Self::InvalidChallenge(reason) => {
                f.debug_tuple("InvalidChallenge").field(reason).finish()
            }
            Self::InvalidXml => f.write_str("InvalidXml"),
            Self::UnsupportedMediaType => f.write_str("UnsupportedMediaType"),
            Self::BodyTooLarge => f.write_str("BodyTooLarge"),
            Self::Http {
                status,
                retry_after,
            } => f
                .debug_struct("Http")
                .field("status", status)
                .field("retry_after", retry_after)
                .finish(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ACS request failed: {self:?}")
    }
}
impl std::error::Error for Error {}

pub fn parse_response(content_type: &str, body: &[u8]) -> Result<Response, Error> {
    parse_response_for_method(content_type, body, "goog-droidguard")
}

fn parse_response_for_method(
    content_type: &str,
    body: &[u8],
    method_name: &str,
) -> Result<Response, Error> {
    if body.len() > MAX_BODY {
        return Err(Error::BodyTooLarge);
    }
    let media = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if matches!(
        media.as_str(),
        "application/vnd.wap.connectivity-xml" | "application/vnd.wap.connectivity-wbxml"
    ) {
        return Ok(Response::WapConfiguration(Bytes::copy_from_slice(body)));
    }
    if !matches!(
        media.as_str(),
        AUTH_MEDIA_TYPE | "application/xml" | "text/xml"
    ) {
        return Err(Error::UnsupportedMediaType);
    }
    let xml = std::str::from_utf8(body).map_err(|_| Error::InvalidXml)?;
    let document = roxmltree::Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: 256,
            entity_resolver: None,
        },
    )
    .map_err(|_| Error::InvalidXml)?;
    let root = document.root_element();
    if media != AUTH_MEDIA_TYPE && root.tag_name().name() == "wap-provisioningdoc" {
        return Ok(Response::WapConfiguration(Bytes::copy_from_slice(body)));
    }
    if media != AUTH_MEDIA_TYPE
        || root.tag_name().name() != "client-authenticity-request"
        || document
            .descendants()
            .filter(|n| n.is_element())
            .any(|n| n.tag_name().namespace() != Some(AUTH_NS))
    {
        return Err(Error::InvalidChallenge("root or namespace"));
    }
    let method = only_child(root, "method")?;
    let nonce = only_child(root, "nonce")?;
    if [root, method].iter().any(|node| {
        node.children()
            .any(|child| child.is_text() && !child.text().unwrap_or("").trim().is_empty())
    }) {
        return Err(Error::InvalidChallenge("unexpected mixed content"));
    }
    if root.children().filter(|n| n.is_element()).count() != 2
        || method.attribute("name") != Some(method_name)
    {
        return Err(Error::InvalidChallenge("method"));
    }
    let method_id = method
        .attribute("id")
        .filter(|value| !value.trim().is_empty())
        .ok_or(Error::InvalidChallenge("method id"))?
        .to_owned();
    let param = only_child(method, "param")?;
    if method.children().filter(|n| n.is_element()).count() != 1
        || param.attribute("name") != Some("challenge")
    {
        return Err(Error::InvalidChallenge("challenge parameter"));
    }
    Ok(Response::Challenge(Challenge {
        method_id,
        challenge: text_value(param)?,
        nonce: text_value(nonce)?,
    }))
}

fn only_child<'a, 'input>(
    parent: roxmltree::Node<'a, 'input>,
    name: &'static str,
) -> Result<roxmltree::Node<'a, 'input>, Error> {
    let mut found = parent
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == name);
    let node = found.next().ok_or(Error::InvalidChallenge(name))?;
    if found.next().is_some() {
        return Err(Error::InvalidChallenge(name));
    }
    Ok(node)
}

fn text_value(node: roxmltree::Node<'_, '_>) -> Result<String, Error> {
    if node.children().any(|n| n.is_element()) {
        return Err(Error::InvalidChallenge("nested value"));
    }
    let value: String = node
        .children()
        .filter(|n| n.is_text())
        .filter_map(|n| n.text())
        .collect();
    if value.trim().is_empty() {
        return Err(Error::InvalidChallenge("empty value"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    const XML: &str = include_str!("../tests/fixtures/clientauth.xml");

    #[test]
    fn upi_challenge_requires_the_selected_method_without_changing_the_legacy_parser() {
        let xml = XML.replace("goog-droidguard", "goog-mls-upi");
        let response =
            parse_response_for_method(AUTH_MEDIA_TYPE, xml.as_bytes(), "goog-mls-upi").unwrap();
        let Response::Challenge(challenge) = response else {
            panic!("expected UPI challenge")
        };
        assert_eq!(challenge.nonce(), "synthetic-nonce");
        assert!(parse_response(AUTH_MEDIA_TYPE, xml.as_bytes()).is_err());
    }

    fn parameters() -> ClientParameters<'static> {
        ClientParameters {
            terminal_vendor: "Example",
            terminal_model: "Test phone",
            terminal_sw_version: "17",
            client_vendor: "Example",
            client_version: "1",
            rcs_profile: "UP_T",
            rcs_version: "5.1B",
        }
    }

    pub(super) async fn mock_session(
        replies: Vec<String>,
    ) -> (AcsSession, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint =
            reqwest::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for reply in replies {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&request[..end]).unwrap();
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        assert!(length <= 256 * 1024);
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                    let mut chunk = [0; 1024];
                    let n = stream.read(&mut chunk).await.unwrap();
                    assert_ne!(n, 0);
                    request.extend_from_slice(&chunk[..n]);
                    assert!(request.len() <= 256 * 1024 + 8192);
                }
                requests.push(String::from_utf8(request).unwrap());
                let _ = stream.write_all(reply.as_bytes()).await;
            }
            requests
        });
        let cookies = Arc::new(Jar::default());
        // Only the loopback fixture relaxes HTTPS; all other production policies are reused.
        let client = client_builder(cookies.clone())
            .https_only(false)
            .http1_only()
            .build()
            .unwrap();
        (
            AcsSession {
                client,
                endpoint,
                cookies,
                exchange_active: AtomicBool::new(false),
            },
            server,
        )
    }

    pub(super) fn reply(status: u16, headers: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status} Test\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn retains_cookie_for_same_session_without_debug_exposure() {
        let (session, server) = mock_session(vec![
            reply(200, "Content-Type: application/vnd.gsma.cfg-clientauth+xml; charset=utf-8\r\nSet-Cookie: JIBE_ACS_COOKIE=synthetic-cookie; Path=/; HttpOnly\r\n", XML),
            reply(200, "Content-Type: application/vnd.gsma.cfg-clientauth+xml\r\n", XML),
        ]).await;
        assert!(matches!(
            session.initial_challenge(&parameters()).await.unwrap(),
            Response::Challenge(_)
        ));
        assert!(session.has_session_cookie());
        assert!(matches!(
            session.initial_challenge(&parameters()).await.unwrap(),
            Response::Challenge(_)
        ));
        let requests = server.await.unwrap();
        assert!(!requests[0].to_ascii_lowercase().contains("cookie:"));
        assert!(
            requests[1]
                .to_ascii_lowercase()
                .contains("cookie: jibe_acs_cookie=synthetic-cookie")
        );
        assert!(!format!("{session:?}").contains("synthetic-cookie"));
        assert!(
            session
                .cookies
                .cookies(&reqwest::Url::parse("https://other.example/").unwrap())
                .is_none()
        );
    }

    #[tokio::test]
    async fn rejects_redirect_and_exposes_status_backoff_without_retry() {
        for (status, headers) in [
            (302, "Location: http://127.0.0.1:1/private\r\n"),
            (503, "Retry-After: 60\r\n"),
        ] {
            let (session, server) =
                mock_session(vec![reply(status, headers, "not a challenge")]).await;
            let error = session
                .initial_challenge(&parameters())
                .await
                .expect_err("HTTP failure");
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
                other => panic!("wrong error: {other:?}"),
            }
            assert_eq!(server.await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn bounds_streamed_body_even_without_content_length() {
        let oversized = "x".repeat(MAX_BODY + 1);
        let reply = format!(
            "HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nContent-Type: application/vnd.gsma.cfg-clientauth+xml\r\n\r\n{:x}\r\n{oversized}\r\n0\r\n\r\n",
            oversized.len()
        );
        let (session, server) = mock_session(vec![reply]).await;
        assert!(matches!(
            session.initial_challenge(&parameters()).await,
            Err(Error::BodyTooLarge)
        ));
        server.await.unwrap();
    }

    #[test]
    fn rejects_non_https_endpoints_and_encodes_only_verified_initial_parameters() {
        for url in [
            "http://acs.example.test/",
            "https://secret@acs.example.test/",
            "https://acs.example.test/?token=secret",
            "https://acs.example.test/#secret",
        ] {
            assert!(AcsSession::new(url).is_err());
        }
        let session = AcsSession::new("https://acs.example.test/").unwrap();
        let request = session.initial_request(&parameters()).unwrap();
        let pairs: std::collections::BTreeMap<_, _> = request
            .url()
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            pairs,
            std::collections::BTreeMap::from([
                ("vers".into(), "0".into()),
                ("rcs_state".into(), "0".into()),
                ("terminal_vendor".into(), "Example".into()),
                ("terminal_model".into(), "Test phone".into()),
                ("terminal_sw_version".into(), "17".into()),
                ("client_vendor".into(), "Example".into()),
                ("client_version".into(), "1".into()),
                ("rcs_profile".into(), "UP_T".into()),
                ("rcs_version".into(), "5.1B".into()),
                ("device_type".into(), "phone".into()),
                ("token".into(), "".into()),
                ("SMS_port".into(), "0".into()),
                (
                    "client_authenticity_support".into(),
                    "goog-droidguard".into()
                ),
            ])
        );
        session.cookies.add_cookie_str(
            "JIBE_ACS_COOKIE=synthetic-cookie; Secure; Path=/",
            &session.endpoint,
        );
        assert!(session.has_session_cookie());
        assert!(!format!("{session:?}").contains("synthetic-cookie"));
    }

    #[test]
    fn parses_namespace_and_redacts_all_challenge_material() {
        let response = parse_response(
            "application/vnd.gsma.cfg-clientauth+xml; charset=utf-8",
            XML.as_bytes(),
        )
        .unwrap();
        let Response::Challenge(challenge) = response else {
            panic!("expected challenge")
        };
        assert_eq!(challenge.method_id(), "synthetic-method-id");
        assert_eq!(challenge.challenge(), "synthetic-challenge");
        assert_eq!(challenge.nonce(), "synthetic-nonce");
        assert!(!format!("{challenge:?}").contains("synthetic"));
    }

    #[test]
    fn accepts_prefix_namespace_and_unescapes_text() {
        let xml = XML
            .replace("xmlns=", "xmlns:a=")
            .replace("<client-", "<a:client-")
            .replace("</client-", "</a:client-")
            .replace("<method", "<a:method")
            .replace("</method", "</a:method")
            .replace("<param", "<a:param")
            .replace("</param", "</a:param")
            .replace("<nonce", "<a:nonce")
            .replace("</nonce", "</a:nonce")
            .replace("synthetic-challenge", "synthetic&amp;challenge");
        let Response::Challenge(challenge) =
            parse_response(AUTH_MEDIA_TYPE, xml.as_bytes()).unwrap()
        else {
            panic!("expected challenge")
        };
        assert_eq!(challenge.challenge(), "synthetic&challenge");
    }

    #[test]
    fn preserves_text_and_cdata_but_excludes_xml_comments() {
        let xml = XML.replace(
            "synthetic-challenge",
            "synthetic<!--ignored--><![CDATA[-challenge]]>",
        );
        let Response::Challenge(challenge) =
            parse_response(AUTH_MEDIA_TYPE, xml.as_bytes()).unwrap()
        else {
            panic!("expected challenge")
        };
        assert_eq!(challenge.challenge(), "synthetic-challenge");
    }

    #[test]
    fn rejects_wrong_namespace_duplicates_missing_and_empty_values() {
        for xml in [XML.replace(AUTH_NS, "urn:wrong"), XML.replace("<nonce>", "<nonce>duplicate</nonce><nonce>"), XML.replace("</method>", "</method><method name=\"goog-droidguard\" id=\"duplicate\"><param name=\"challenge\">duplicate</param></method>"), XML.replace("synthetic-method-id", ""), XML.replace("synthetic-nonce", " "), XML.replace("synthetic-challenge", ""), XML.replace("<nonce>synthetic-nonce</nonce>", ""), XML.replace("name=\"challenge\"", "name=\"unknown\""), XML.replace("goog-droidguard", "other-method"), "<!DOCTYPE x [<!ENTITY secret SYSTEM \"file:///etc/passwd\">]><x>&secret;</x>".to_owned()] {
            let error = parse_response(AUTH_MEDIA_TYPE, xml.as_bytes()).expect_err("invalid challenge");
            assert!(!format!("{error:?}").contains("synthetic"));
        }
    }

    #[test]
    fn distinguishes_wap_configuration_and_rejects_unbounded_or_html_body() {
        let response = parse_response(
            "application/vnd.wap.connectivity-xml",
            b"<wap-provisioningdoc/>",
        )
        .unwrap();
        assert!(matches!(response, Response::WapConfiguration(_)));
        assert!(matches!(
            parse_response("text/html", b"<html/>"),
            Err(Error::UnsupportedMediaType)
        ));
        assert!(matches!(
            parse_response(AUTH_MEDIA_TYPE, &vec![b'x'; MAX_BODY + 1]),
            Err(Error::BodyTooLarge)
        ));
    }

    #[test]
    fn rejects_mixed_structure_text_and_metadata_controls() {
        let xml = XML.replace("<method", "unexpected<method");
        assert!(parse_response(AUTH_MEDIA_TYPE, xml.as_bytes()).is_err());
        let session = AcsSession::new("https://acs.example.test/").unwrap();
        let mut metadata = parameters();
        metadata.terminal_model = "";
        assert!(session.initial_request(&metadata).is_err());
        metadata.terminal_model = "Test\nphone";
        assert!(session.initial_request(&metadata).is_err());
    }
}
