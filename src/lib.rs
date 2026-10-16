//! Experimental RCS bootstrap and verification decoding; no registration or messaging yet.

use bytes::Bytes;
use prost::Message;
use std::fmt;
use std::time::Duration;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

pub mod acs;
pub mod consent;
pub mod verification;
pub mod wire;

pub struct Discovery {
    pub flags: wire::OnboardingFlags,
    pub validity: Option<wire::Duration>,
    raw: Bytes,
}

impl fmt::Debug for Discovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Discovery")
            .field("rcs_enabled_state", &self.flags.rcs_enabled_state)
            .field("protobuf_bytes", &self.raw.len())
            .finish_non_exhaustive()
    }
}

impl Discovery {
    /// Decode one requested onboarding configuration, retaining the entire wire response.
    pub fn decode(raw: Bytes) -> Result<Self, Error> {
        let mut response = wire::GetConfigurationResponse::decode(raw.clone())
            .map_err(|_| Error::InvalidResponse("malformed protobuf"))?;
        if response.configurations.len() != 1 {
            return Err(Error::InvalidResponse("expected exactly one configuration"));
        }
        let configuration = response.configurations.remove(0);
        if configuration.correlation_id != "0" {
            return Err(Error::InvalidResponse("configuration correlation mismatch"));
        }
        let Some(wire::configuration::Data::Onboarding(flags)) = configuration.data else {
            return Err(Error::InvalidResponse("onboarding configuration missing"));
        };
        if flags.rcs_enabled_state == 1
            && !matches!(&flags.acs_location,
            Some(wire::onboarding_flags::AcsLocation::Direct(value) | wire::onboarding_flags::AcsLocation::MccFormat(value)) if !value.is_empty())
        {
            return Err(Error::InvalidResponse(
                "enabled configuration has no ACS location",
            ));
        }
        Ok(Self {
            flags,
            validity: configuration.validity,
            raw,
        })
    }

    /// Original protobuf bytes, including unknown fields. Keep captures private.
    pub fn raw_protobuf(&self) -> &[u8] {
        &self.raw
    }
}

pub struct Carrier {
    mcc: String,
    mnc: String,
}

impl Carrier {
    pub fn new(mcc: &str, mnc: &str) -> Result<Self, Error> {
        if mcc.len() != 3 || !mcc.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::InvalidInput("MCC"));
        }
        if !(2..=3).contains(&mnc.len()) || !mnc.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::InvalidInput("MNC"));
        }
        Ok(Self {
            mcc: mcc.into(),
            mnc: mnc.into(),
        })
    }
}

pub struct Probe {
    carrier: Carrier,
    device: String,
    manufacturer: String,
    package_version: i64,
    gms_version: Option<i64>,
}

impl Probe {
    /// Include the actual installed Play Services (or compatible implementation) version.
    /// Omitting this package can select different provisioning routes at discovery.
    pub fn with_gms_version(mut self, version: i64) -> Result<Self, Error> {
        if version <= 0 {
            return Err(Error::InvalidInput("GMS version"));
        }
        self.gms_version = Some(version);
        Ok(self)
    }

    pub fn new(
        carrier: Carrier,
        device: &str,
        manufacturer: &str,
        package_version: i64,
    ) -> Result<Self, Error> {
        if device.is_empty() || device.len() > 256 || device.chars().any(char::is_control) {
            return Err(Error::InvalidInput("device"));
        }
        if manufacturer.is_empty()
            || manufacturer.len() > 256
            || manufacturer.chars().any(char::is_control)
        {
            return Err(Error::InvalidInput("manufacturer"));
        }
        if package_version <= 0 {
            return Err(Error::InvalidInput("package version"));
        }
        Ok(Self {
            carrier,
            device: device.into(),
            manufacturer: manufacturer.into(),
            package_version,
            gms_version: None,
        })
    }
}

fn make_request(
    metadata: &ClientMetadata,
    probe: &Probe,
    uuid: &str,
) -> tonic::Request<wire::GetConfigurationRequest> {
    // shortcut: MCC/MNC only; add opt-in carrier fields when a verified carrier needs them.
    let mut packages = vec![wire::PackageVersion {
        package_name: metadata
            .package
            .to_str()
            .expect("validated ASCII package")
            .into(),
        version_code: probe.package_version,
    }];
    if let Some(version_code) = probe.gms_version {
        packages.push(wire::PackageVersion {
            package_name: "com.google.android.gms".into(),
            version_code,
        });
    }
    let message = wire::GetConfigurationRequest {
        context: Some(wire::RequestContext {
            request_uuid: uuid.into(),
            gsf_android_id: 0,
        }),
        parameters: vec![wire::Parameters {
            correlation_id: "0".into(),
            configuration_type: 1,
            device: Some(wire::Device {
                device: probe.device.clone(),
                manufacturer: probe.manufacturer.clone(),
                form_factor: 1,
            }),
            carrier: Some(wire::Carrier {
                mcc: probe.carrier.mcc.clone(),
                mnc: probe.carrier.mnc.clone(),
            }),
            packages,
        }],
    };
    let mut request = tonic::Request::new(message);
    metadata.apply_to(&mut request);
    request.set_timeout(std::time::Duration::from_secs(20));
    request
}

pub struct ClientMetadata {
    api_key: MetadataValue<Ascii>,
    package: MetadataValue<Ascii>,
    certificate_sha1: MetadataValue<Ascii>,
}

impl ClientMetadata {
    fn apply_to<T>(&self, request: &mut tonic::Request<T>) {
        request
            .metadata_mut()
            .insert("x-goog-api-key", self.api_key.clone());
        request
            .metadata_mut()
            .insert("x-android-package", self.package.clone());
        request
            .metadata_mut()
            .insert("x-android-cert", self.certificate_sha1.clone());
    }

    pub fn new(key: &str, package: &str, cert: &str) -> Result<Self, Error> {
        if key.is_empty() || key.len() > 4096 || !key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Error::InvalidInput("API key"));
        }
        if package.is_empty()
            || package.len() > 255
            || !package
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
        {
            return Err(Error::InvalidInput("application package"));
        }
        if cert.len() != 40 || !cert.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::InvalidInput("certificate SHA1"));
        }
        let mut api_key: MetadataValue<Ascii> =
            key.parse().map_err(|_| Error::InvalidInput("API key"))?;
        api_key.set_sensitive(true);
        Ok(Self {
            api_key,
            package: package
                .parse()
                .map_err(|_| Error::InvalidInput("application package"))?,
            certificate_sha1: cert
                .to_ascii_lowercase()
                .parse()
                .map_err(|_| Error::InvalidInput("certificate SHA1"))?,
        })
    }
}

impl fmt::Debug for ClientMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientMetadata([REDACTED])")
    }
}

pub enum Error {
    InvalidInput(&'static str),
    InvalidResponse(&'static str),
    Rpc(Box<tonic::Status>),
    Transport(tonic::transport::Error),
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(field) => write!(f, "invalid {field}"),
            Self::InvalidResponse(reason) => write!(f, "invalid bootstrap response: {reason}"),
            Self::Rpc(status) => write!(f, "bootstrap RPC failed: {:?}", status.code()),
            Self::Transport(_) => f.write_str("bootstrap TLS/HTTP2 transport failed"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Explicit access to server details; Display/Debug omit these to avoid reflecting secrets.
    pub fn rpc_status(&self) -> Option<&tonic::Status> {
        match self {
            Self::Rpc(status) => Some(status),
            _ => None,
        }
    }

    /// Suggested delay only. Negative retry pushback means no suggested retry.
    pub fn retry_after(&self) -> Option<std::time::Duration> {
        let metadata = self.rpc_status()?.metadata();
        if let Some(value) = metadata.get("grpc-retry-pushback-ms") {
            return value.to_str().ok()?.parse().ok().map(Duration::from_millis);
        }
        metadata
            .get("retry-after")?
            .to_str()
            .ok()?
            .parse()
            .ok()
            .map(Duration::from_secs)
    }
}

/// Make one TLS-protected bootstrap request. No automatic RPC retries.
/// Sends GSF Android ID zero and MCC/MNC only; never sends IMSI or a phone number.
/// The caller supplies application credentials; backend admission may restrict them.
pub async fn discover(metadata: &ClientMetadata, probe: &Probe) -> Result<Discovery, Error> {
    let channel = Endpoint::from_static("https://mobileconfiguration-pa.googleapis.com")
        .tls_config(ClientTlsConfig::new().with_native_roots())
        .map_err(Error::Transport)?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .connect()
        .await
        .map_err(Error::Transport)?;
    query_channel(channel, metadata, probe).await
}

async fn query_channel(
    channel: Channel,
    metadata: &ClientMetadata,
    probe: &Probe,
) -> Result<Discovery, Error> {
    let mut grpc = tonic::client::Grpc::new(channel)
        .max_decoding_message_size(256 * 1024)
        .max_encoding_message_size(16 * 1024);
    grpc.ready().await.map_err(Error::Transport)?;
    let request = make_request(metadata, probe, &uuid::Uuid::new_v4().to_string());
    let response = grpc.unary(request,
        http::uri::PathAndQuery::from_static("/google.internal.communications.mobileconfiguration.v1.MobileConfigurationService/GetConfiguration"),
        codec::PreservingCodec::<wire::GetConfigurationRequest>::default()).await.map_err(|status| Error::Rpc(Box::new(status)))?;
    Discovery::decode(response.into_inner())
}

mod codec;

#[cfg(test)]
mod transport_tests;

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn request_matches_independent_fixture_without_subscriber_identifiers() {
        let metadata =
            ClientMetadata::new("synthetic-secret", "org.example.sms", &CERT.to_uppercase())
                .unwrap();
        let probe =
            Probe::new(Carrier::new("001", "01").unwrap(), "generic", "Example", 1).unwrap();
        let request = make_request(&metadata, &probe, "00000000-0000-4000-8000-000000000000");
        assert_eq!(
            request.get_ref().encode_to_vec(),
            include_bytes!("../tests/fixtures/request.bin")
        );
        assert_eq!(
            request.metadata().get("x-android-package").unwrap(),
            "org.example.sms"
        );
        assert_eq!(request.metadata().get("x-android-cert").unwrap(), CERT);
        assert!(
            request
                .metadata()
                .get("x-goog-api-key")
                .unwrap()
                .is_sensitive()
        );
        assert!(!format!("{request:?}").contains("synthetic-secret"));
    }

    #[test]
    fn installed_gms_version_reaches_discovery_in_addition_to_the_calling_app() {
        let metadata = ClientMetadata::new("synthetic-secret", "org.example.sms", CERT).unwrap();
        let probe = Probe::new(Carrier::new("001", "01").unwrap(), "generic", "Example", 1)
            .unwrap()
            .with_gms_version(253_000_000)
            .unwrap();
        let request = make_request(&metadata, &probe, "00000000-0000-4000-8000-000000000000");
        assert_eq!(
            request.get_ref().encode_to_vec(),
            include_bytes!("../tests/fixtures/request-with-gms.bin")
        );
    }

    #[test]
    fn missing_or_invalid_gms_version_is_never_invented() {
        for version in [0, -1] {
            let probe =
                Probe::new(Carrier::new("001", "01").unwrap(), "generic", "Example", 1).unwrap();
            assert!(probe.with_gms_version(version).is_err());
        }
    }

    #[test]
    fn rejects_missing_device_and_invalid_package_versions() {
        for (device, manufacturer, version) in [
            ("", "Example", 1),
            ("generic", "", 1),
            ("generic", "Example\n", 1),
            ("generic", "Example", 0),
            ("generic", "Example", -1),
        ] {
            assert!(
                Probe::new(
                    Carrier::new("001", "01").unwrap(),
                    device,
                    manufacturer,
                    version
                )
                .is_err()
            );
        }
    }

    #[test]
    fn decodes_synthetic_config_and_preserves_unknown_wire_fields() {
        let fixture = Bytes::from_static(include_bytes!("../tests/fixtures/onboarding.bin"));
        let result = Discovery::decode(fixture.clone()).unwrap();
        assert_eq!(result.flags.rcs_enabled_state, 1);
        assert_eq!(
            result.flags.acs_location,
            Some(wire::onboarding_flags::AcsLocation::Direct(
                "rcs.example.test".into()
            ))
        );
        assert_eq!(result.flags.provisioning_imei_format, 4);
        assert_eq!(
            wire::PiiFormat::try_from(result.flags.provisioning_imsi_format),
            Ok(wire::PiiFormat::Ignored)
        );
        assert!(result.flags.enable_droidguard_with_http_get);
        assert_eq!(result.validity.as_ref().unwrap().seconds, 3600);
        assert_eq!(result.raw_protobuf(), fixture.as_ref());
    }

    #[test]
    fn disabled_configuration_can_have_no_acs() {
        let response = Discovery::decode(Bytes::from_static(include_bytes!(
            "../tests/fixtures/disabled.bin"
        )))
        .unwrap();
        assert_eq!(response.flags.rcs_enabled_state, 2);
        assert!(response.flags.acs_location.is_none());
    }

    #[test]
    fn direct_ts43_flag_is_independent_of_upi_number_verification() {
        // Independent wire literals: correlation "0", onboarding {UPI33, directTS43 55}.
        for (upi, direct) in [(1, false), (0, true)] {
            let bytes = Bytes::from(vec![
                10,
                11,
                10,
                1,
                b'0',
                26,
                6,
                0x88,
                2,
                upi,
                0xb8,
                3,
                u8::from(direct),
            ]);
            let discovery = Discovery::decode(bytes.clone()).unwrap();
            assert_eq!(discovery.flags.upi_enabled_state, i32::from(upi));
            assert_eq!(discovery.flags.ts43_supported, direct);
            assert_eq!(discovery.raw_protobuf(), bytes);
        }
    }

    #[test]
    fn rejects_missing_wrong_and_duplicate_configuration() {
        for fixture in [
            include_bytes!("../tests/fixtures/missing.bin").as_slice(),
            include_bytes!("../tests/fixtures/wrong-correlation.bin").as_slice(),
            include_bytes!("../tests/fixtures/duplicate.bin").as_slice(),
            include_bytes!("../tests/fixtures/missing-acs.bin").as_slice(),
            &[0xff],
        ] {
            assert!(Discovery::decode(Bytes::copy_from_slice(fixture)).is_err());
        }
    }

    #[test]
    fn carrier_accepts_ascii_widths_and_keeps_leading_zeroes() {
        let carrier = Carrier::new("001", "01").unwrap();
        assert_eq!(carrier.mcc, "001");
        assert_eq!(carrier.mnc, "01");
        assert!(Carrier::new("310", "240").is_ok());
    }

    #[test]
    fn carrier_rejects_non_ascii_digits_and_invalid_widths() {
        for (mcc, mnc) in [
            ("31", "240"),
            ("3100", "240"),
            ("310", "2"),
            ("310", "2400"),
            ("３１０", "240"),
            ("310", "2a"),
            ("310", " 24"),
        ] {
            assert!(Carrier::new(mcc, mnc).is_err());
        }
    }

    #[test]
    fn credentials_accept_valid_headers_but_never_debug_the_key() {
        let metadata = ClientMetadata::new("synthetic-secret", "org.example.sms", CERT).unwrap();
        assert!(!format!("{metadata:?}").contains("synthetic-secret"));
    }

    #[test]
    fn credentials_reject_header_injection_and_bad_certificates() {
        for (key, package, cert) in [
            ("", "org.example.sms", CERT),
            ("key\r\nleak", "org.example.sms", CERT),
            ("key", "org.example\nsms", CERT),
            ("key", "", CERT),
            ("key", "org.example.sms", "invalid"),
        ] {
            assert!(ClientMetadata::new(key, package, cert).is_err());
        }
    }

    #[test]
    fn rejects_oversized_identity_metadata_before_connecting() {
        assert!(ClientMetadata::new(&"x".repeat(4097), "org.example.sms", CERT).is_err());
        assert!(ClientMetadata::new("synthetic-key", &"x".repeat(256), CERT).is_err());
    }
}
