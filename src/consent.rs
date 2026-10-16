//! Consumer consent lookup only; a consent response does not verify a phone number.

use crate::Error;
use bytes::Bytes;
use prost::Message;
use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod wire;

pub struct ConsentResponse {
    pub legacy: Option<ConsentRecord>,
    pub consumers: Vec<ConsumerConsent>,
    pub cached_droidguard: Option<CachedToken>,
    raw: Bytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsentRecord {
    pub state: i32,
    pub detail: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsumerConsent {
    pub client: i32,
    pub state: i32,
    pub detail: i32,
}

impl ConsentResponse {
    /// Retains unknown fields verbatim. Raw captures may include private cached tokens.
    pub fn decode(raw: Bytes) -> Result<Self, Error> {
        if raw.len() > 256 * 1024 {
            return Err(Error::InvalidResponse("consent response too large"));
        }
        let response = wire::GetConsentResponse::decode(raw.clone())
            .map_err(|_| Error::InvalidResponse("malformed consent protobuf"))?;
        if response
            .consumers
            .iter()
            .filter(|row| row.client == 2)
            .count()
            > 1
        {
            return Err(Error::InvalidResponse("duplicate RCS consent rows"));
        }
        let cached_droidguard = response
            .cached_dg
            .map(|cache| {
                let expiry = cache
                    .expires
                    .ok_or(Error::InvalidResponse("cached token expiry missing"))?;
                if !(0..=253_402_300_799).contains(&expiry.seconds)
                    || !(0..1_000_000_000).contains(&expiry.nanos)
                {
                    return Err(Error::InvalidResponse("invalid cached token expiry"));
                }
                let expires_at = UNIX_EPOCH
                    .checked_add(Duration::new(expiry.seconds as u64, expiry.nanos as u32))
                    .ok_or(Error::InvalidResponse("invalid cached token expiry"))?;
                CachedToken::new(cache.token, expires_at)
                    .map_err(|_| Error::InvalidResponse("invalid cached token"))
            })
            .transpose()?;
        Ok(Self {
            legacy: response.consent.map(|record| ConsentRecord {
                state: record.state,
                detail: record.detail,
            }),
            consumers: response
                .consumers
                .into_iter()
                .map(|record| ConsumerConsent {
                    client: record.client,
                    state: record.state,
                    detail: record.detail,
                })
                .collect(),
            cached_droidguard,
            raw,
        })
    }
    /// Consumer-specific RCS state takes precedence over legacy consent, including state zero.
    /// Known states: unknown=0, consented=1, no-consent=2, expired=3. Unknown values are retained.
    /// This describes consent only, never phone-number verification or RCS registration.
    pub fn rcs_state(&self) -> Option<i32> {
        self.consumers
            .iter()
            .find(|row| row.client == 2)
            .map(|row| row.state)
            .or_else(|| self.legacy.map(|record| record.state))
    }
    /// Original protobuf bytes. Keep captures private.
    pub fn raw_protobuf(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for ConsentResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsentResponse")
            .field("rcs_state", &self.rcs_state())
            .field("consumer_count", &self.consumers.len())
            .field(
                "cached_droidguard_present",
                &self.cached_droidguard.is_some(),
            )
            .finish_non_exhaustive()
    }
}

/// A backend-issued token with its real expiry. Requests reject expired tokens.
pub struct CachedToken {
    token: String,
    expires_at: SystemTime,
}

impl CachedToken {
    pub fn new(token: String, expires_at: SystemTime) -> Result<Self, Error> {
        if token.is_empty()
            || token.len() > 64 * 1024
            || !token.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(Error::InvalidInput("cached DroidGuard token"));
        }
        if expires_at.duration_since(UNIX_EPOCH).is_err() {
            return Err(Error::InvalidInput("cached DroidGuard expiry"));
        }
        Ok(Self { token, expires_at })
    }
    /// Explicit private-token access for storage. Debug omits the token.
    pub fn value(&self) -> &str {
        &self.token
    }
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}

impl fmt::Debug for CachedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CachedToken([REDACTED])")
    }
}

/// Actual device/build values from the implementation producing the supplied proof.
#[derive(Clone, Debug)]
pub struct BuildInfo {
    pub locale: String,
    pub gms_version_code: i64,
    pub gms_version_name: String,
    pub android_sdk: i32,
    pub model: String,
    pub manufacturer: String,
    pub fingerprint: Option<String>,
}

/// A real `constellation_verify` result bound to this IID and `rpc=getConsent`,
/// or a backend-issued unexpired token. This module does not produce attestation.
pub enum Attestation {
    RawDroidGuard(String),
    Cached(CachedToken),
}

impl fmt::Debug for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Attestation([REDACTED])")
    }
}

/// Genuine full-flow IID, checkin identity, owned EC SPKI DER public key and device facts.
/// `checkin_android_id` preserves signed protobuf int64 bits, including negative Java longs.
/// Key ownership and proof provenance remain the caller's responsibility; DER is opaque here.
pub struct ConsentRequest {
    pub iid_token: String,
    pub checkin_android_id: i64,
    pub user_serial: i64,
    pub public_key_der: Vec<u8>,
    pub build: BuildInfo,
    pub attestation: Attestation,
    pub policy: String,
    pub calling_package: String,
}

impl fmt::Debug for ConsentRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsentRequest([REDACTED])")
    }
}

fn make_request(
    input: &ConsentRequest,
    session_id: &str,
) -> Result<wire::GetConsentRequest, Error> {
    fn text(value: &str, limit: usize, name: &'static str) -> Result<(), Error> {
        if value.is_empty() || value.len() > limit || value.chars().any(char::is_control) {
            return Err(Error::InvalidInput(name));
        }
        Ok(())
    }
    text(&input.iid_token, 4096, "IID token")?;
    if !input.iid_token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error::InvalidInput("IID token"));
    }
    if input.checkin_android_id == 0 || input.user_serial < 0 {
        return Err(Error::InvalidInput("checkin identity"));
    }
    if input.public_key_der.is_empty() || input.public_key_der.len() > 4096 {
        return Err(Error::InvalidInput("owned EC public key"));
    }
    let version = i32::try_from(input.build.gms_version_code / 1000)
        .ok()
        .filter(|v| *v > 0)
        .ok_or(Error::InvalidInput("GMS version code"))?;
    if !(1..=1000).contains(&input.build.android_sdk) {
        return Err(Error::InvalidInput("Android SDK"));
    }
    for (value, name) in [
        (&input.build.locale, "locale"),
        (&input.build.gms_version_name, "GMS version name"),
        (&input.build.model, "model"),
        (&input.build.manufacturer, "manufacturer"),
        (&input.policy, "consent policy"),
        (&input.calling_package, "calling package"),
    ] {
        text(value, 512, name)?;
    }
    if let Some(fingerprint) = &input.build.fingerprint {
        text(fingerprint, 4096, "build fingerprint")?;
    }
    if uuid::Uuid::parse_str(session_id).is_err() {
        return Err(Error::InvalidInput("session UUID"));
    }
    let signals = match &input.attestation {
        Attestation::RawDroidGuard(value) => {
            if value.is_empty()
                || value.len() > 64 * 1024
                || !value.bytes().all(|b| b.is_ascii_graphic())
            {
                return Err(Error::InvalidInput("DroidGuard result"));
            }
            wire::DroidGuardSignals {
                raw_droidguard: value.clone(),
                cached_token: String::new(),
            }
        }
        Attestation::Cached(cache) => {
            if cache.expires_at <= SystemTime::now() {
                return Err(Error::InvalidInput("expired DroidGuard token"));
            }
            wire::DroidGuardSignals {
                raw_droidguard: String::new(),
                cached_token: cache.token.clone(),
            }
        }
    };
    Ok(wire::GetConsentRequest {
        device: Some(wire::DeviceId {
            iid_token: input.iid_token.clone(),
            ..Default::default()
        }),
        header: Some(wire::RequestHeader {
            info: Some(wire::ClientInfo {
                device: Some(wire::DeviceId {
                    iid_token: input.iid_token.clone(),
                    device_android_id: input.checkin_android_id,
                    user_serial: input.user_serial,
                    user_android_id: input.checkin_android_id,
                }),
                public_key: input.public_key_der.clone(),
                locale: input.build.locale.clone(),
                version,
                version_name: input.build.gms_version_name.clone(),
                sdk: input.build.android_sdk,
                signals: Some(signals),
                model: input.build.model.clone(),
                manufacturer: input.build.manufacturer.clone(),
                fingerprint: input.build.fingerprint.clone().unwrap_or_default(),
            }),
            session_id: session_id.into(),
            trigger: Some(wire::Trigger { reason: 7 }),
        }),
        params: vec![
            wire::Param {
                name: "required_consumer_consent".into(),
                value: "RCS".into(),
            },
            wire::Param {
                name: "consent_type".into(),
                value: "RCS_DEFAULT_ON_LEGAL_FYI_IN_SETTINGS".into(),
            },
        ],
        client: 2,
        api: Some(wire::ApiInfo {
            policy: input.policy.clone(),
            calling_package: input.calling_package.clone(),
        }),
        request_consent: true,
    })
}

/// Make one TLS-protected GetConsent call using genuine caller-supplied inputs.
/// Does not start Sync/SIM verification, generate attestation, or retry server failures.
pub async fn get_consent(
    metadata: &crate::ClientMetadata,
    input: &ConsentRequest,
) -> Result<ConsentResponse, Error> {
    let message = make_request(input, &uuid::Uuid::new_v4().to_string())?;
    let channel = tonic::transport::Endpoint::from_static(
        "https://phonedeviceverification-pa.googleapis.com",
    )
    .tls_config(tonic::transport::ClientTlsConfig::new().with_native_roots())
    .map_err(Error::Transport)?
    .connect_timeout(Duration::from_secs(10))
    .timeout(Duration::from_secs(20))
    .connect()
    .await
    .map_err(Error::Transport)?;
    query_channel(channel, metadata, message).await
}

async fn query_channel(
    channel: tonic::transport::Channel,
    metadata: &crate::ClientMetadata,
    message: wire::GetConsentRequest,
) -> Result<ConsentResponse, Error> {
    let mut grpc = tonic::client::Grpc::new(channel)
        .max_decoding_message_size(256 * 1024)
        .max_encoding_message_size(128 * 1024);
    grpc.ready().await.map_err(Error::Transport)?;
    let mut request = tonic::Request::new(message);
    metadata.apply_to(&mut request);
    request.set_timeout(Duration::from_secs(20));
    let response = grpc.unary(request,
        http::uri::PathAndQuery::from_static("/google.internal.communications.phonedeviceverification.v1.PhoneDeviceVerification/GetConsent"),
        crate::codec::PreservingCodec::<wire::GetConsentRequest>::default()
    ).await.map_err(|status| Error::Rpc(Box::new(status)))?;
    ConsentResponse::decode(response.into_inner())
}

#[cfg(test)]
mod transport_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_legacy_state_field_two_and_explicit_rcs_state() {
        // Independent wire literals: legacy {2:1,3:1}, consumers {1:1}, {1:2,2:1,3:5}, unknown 99:7.
        let bytes = Bytes::from_static(include_bytes!("../tests/fixtures/consent-response.bin"));
        let result = ConsentResponse::decode(bytes.clone()).ok().unwrap();
        assert_eq!(
            result.legacy,
            Some(ConsentRecord {
                state: 1,
                detail: 1
            })
        );
        assert_eq!(result.rcs_state(), Some(1));
        assert_eq!(result.consumers[1].detail, 5);
        assert_eq!(result.raw_protobuf(), bytes);
    }

    #[test]
    fn explicit_rcs_overrides_unknown_legacy_without_claiming_verification() {
        let response = ConsentResponse::decode(Bytes::from_static(&[10, 0, 66, 4, 8, 2, 16, 1]))
            .ok()
            .unwrap();
        assert_eq!(response.legacy.unwrap().state, 0);
        assert_eq!(response.rcs_state(), Some(1));
        assert_eq!(
            ConsentResponse::decode(Bytes::new())
                .ok()
                .unwrap()
                .rcs_state(),
            None
        );
        for (state, bytes) in [
            (2, &[10, 2, 16, 2][..]),
            (3, &[10, 2, 16, 3]),
            (91, &[66, 4, 8, 2, 16, 91]),
        ] {
            assert_eq!(
                ConsentResponse::decode(Bytes::copy_from_slice(bytes))
                    .ok()
                    .unwrap()
                    .rcs_state(),
                Some(state)
            );
        }
    }

    #[test]
    fn malformed_or_ambiguous_consumer_response_is_rejected() {
        for bytes in [&[10, 99][..], &[66, 2, 8, 2, 66, 2, 8, 2]] {
            assert!(ConsentResponse::decode(Bytes::copy_from_slice(bytes)).is_err());
        }
    }

    pub(super) fn input() -> ConsentRequest {
        ConsentRequest {
            iid_token: "synthetic-iid".into(),
            checkin_android_id: 123_456,
            user_serial: 0,
            public_key_der: include_bytes!("../tests/fixtures/consent-public-key.der").to_vec(),
            build: BuildInfo {
                locale: "en_US".into(),
                gms_version_code: 263737035,
                gms_version_name: "26.37.37".into(),
                android_sdk: 37,
                model: "Generic".into(),
                manufacturer: "Example".into(),
                fingerprint: None,
            },
            attestation: Attestation::RawDroidGuard("synthetic-droidguard".into()),
            policy: "upi-carrier-tos-ts43".into(),
            calling_package: "org.example.sms".into(),
        }
    }

    #[test]
    fn request_wire_matches_independent_fixture_and_redacts_default_debug() {
        let input = input();
        let request = make_request(&input, "00000000-0000-4000-8000-000000000000").unwrap();
        assert_eq!(
            request.encode_to_vec(),
            include_bytes!("../tests/fixtures/consent-request.bin")
        );
        assert_eq!(request.device.as_ref().unwrap().device_android_id, 0);
        let header = request.header.as_ref().unwrap();
        assert_eq!(header.info.as_ref().unwrap().version, 263737);
        assert_eq!(
            header
                .info
                .as_ref()
                .unwrap()
                .device
                .as_ref()
                .unwrap()
                .user_android_id,
            123_456
        );
        assert_eq!(header.trigger.as_ref().unwrap().reason, 7);
        for debug in [
            format!("{input:?}"),
            format!("{request:?}"),
            format!("{:?}", input.attestation),
        ] {
            for secret in ["synthetic-iid", "synthetic-droidguard", "123456"] {
                assert!(!debug.contains(secret));
            }
        }
    }

    #[test]
    fn request_validation_rejects_missing_facts_expired_cache_and_oversize_proof() {
        let mut request = input();
        request.iid_token.clear();
        assert!(make_request(&request, "00000000-0000-4000-8000-000000000000").is_err());
        request = input();
        request.checkin_android_id = 0;
        assert!(make_request(&request, "00000000-0000-4000-8000-000000000000").is_err());
        request = input();
        request.user_serial = -1;
        assert!(make_request(&request, "00000000-0000-4000-8000-000000000000").is_err());
        request = input();
        request.public_key_der.clear();
        assert!(make_request(&request, "00000000-0000-4000-8000-000000000000").is_err());
        request = input();
        request.build.gms_version_code = 999;
        assert!(make_request(&request, "00000000-0000-4000-8000-000000000000").is_err());
        request = input();
        request.attestation = Attestation::RawDroidGuard("x".repeat(65537));
        assert!(make_request(&request, "00000000-0000-4000-8000-000000000000").is_err());
        request.attestation =
            Attestation::Cached(CachedToken::new("synthetic-cache".into(), UNIX_EPOCH).unwrap());
        assert!(make_request(&request, "00000000-0000-4000-8000-000000000000").is_err());
        request.attestation = Attestation::Cached(
            CachedToken::new(
                "synthetic-cache".into(),
                SystemTime::now() + Duration::from_secs(600),
            )
            .unwrap(),
        );
        let message = make_request(&request, "00000000-0000-4000-8000-000000000000").unwrap();
        let signals = message.header.unwrap().info.unwrap().signals.unwrap();
        assert!(signals.raw_droidguard.is_empty());
        assert_eq!(signals.cached_token, "synthetic-cache");
    }

    #[test]
    fn cache_response_preserves_expiry_without_disclosing_token() {
        // Independent wire literal: field9 {token1:"synthetic-cache", expiry2:{seconds1:2000000000}}.
        let bytes = Bytes::from_static(&[
            74, 25, 10, 15, 115, 121, 110, 116, 104, 101, 116, 105, 99, 45, 99, 97, 99, 104, 101,
            18, 6, 8, 128, 168, 214, 185, 7,
        ]);
        let response = ConsentResponse::decode(bytes).ok().unwrap();
        let cache = response.cached_droidguard.as_ref().unwrap();
        assert_eq!(cache.value(), "synthetic-cache");
        assert_eq!(
            cache.expires_at(),
            UNIX_EPOCH + Duration::from_secs(2_000_000_000)
        );
        assert!(!format!("{cache:?} {response:?}").contains("synthetic-cache"));
        assert!(ConsentResponse::decode(Bytes::from_static(&[74, 3, 10, 1, 120])).is_err());
    }
}
