//! One initial Sync and an unsigned AcquireTemporaryToken Proceed only.
use super::{ProceedResponse, SyncResponse, Verification};
use crate::{Error, consent::ConsentRequest};
use base64::Engine;
use bytes::Bytes;
use prost::Message;
use std::{fmt, time::Duration};
mod wire;

pub struct InitialSync {
    /// GMS/PDV RPC session, reused for its Proceed call.
    pub session_id: String,
    /// Logical client provisioning session, also used by ACS and its attestation.
    pub caller_session_id: String,
    pub caller_certificate_sha1: [u8; 20],
    pub imsi: String,
    pub number: Option<String>,
    pub iccid: Option<String>,
    pub slot_index: i32,
    pub subscription_id: i32,
    pub telephony: TelephonyInfo,
}
pub struct TelephonyInfo {
    pub phone_type: i32,
    pub gid1: String,
    pub sim_operator: OperatorInfo,
    pub network_operator: OperatorInfo,
    pub roaming: i32,
    pub phone_count: i32,
    pub max_subscriptions: i32,
}
pub struct OperatorInfo {
    pub country: String,
    pub code: String,
    pub name: String,
}

fn make_sync(identity: &ConsentRequest, input: &InitialSync) -> Result<wire::SyncRequest, Error> {
    validate_sim(input)?;
    let header = crate::consent::make_header(identity, &input.session_id)?;
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        format!("{}.{}", input.caller_session_id, input.imsi).as_bytes(),
    );
    let nonce: String = digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let operator = |value: &OperatorInfo| wire::Operator {
        country: value.country.clone(),
        code: value.code.clone(),
        name: value.name.clone(),
    };
    let message = wire::SyncRequest {
        verifications: vec![wire::Verification {
            association: Some(wire::Association {
                sim: Some(wire::SimAssociation {
                    info: Some(wire::SimInfo {
                        imsi: vec![input.imsi.clone()],
                        number: input.number.clone(),
                        iccid: input.iccid.clone(),
                    }),
                    slot: Some(wire::Slot {
                        index: Some(input.slot_index),
                        subscription: Some(input.subscription_id),
                    }),
                }),
            }),
            state: 1,
            telephony: Some(wire::Telephony {
                phone_type: Some(input.telephony.phone_type),
                gid1: input.telephony.gid1.clone(),
                sim_operator: Some(operator(&input.telephony.sim_operator)),
                network_operator: Some(operator(&input.telephony.network_operator)),
                roaming: Some(input.telephony.roaming),
                phone_count: Some(input.telephony.phone_count),
                max_subscriptions: Some(input.telephony.max_subscriptions),
            }),
            params: [
                ("session_id", input.caller_session_id.as_str()),
                ("required_consumer_consent", "RCS"),
                ("consent_type", "RCS_DEFAULT_ON_LEGAL_FYI_IN_SETTINGS"),
            ]
            .into_iter()
            .map(|(name, value)| crate::consent::wire::Param {
                name: name.into(),
                value: value.into(),
            })
            .collect(),
            methods: Some(wire::Methods {
                mt: Some(wire::MtData {
                    payload: Some(String::new()),
                }),
            }),
            api: Some(wire::ApiInfo {
                policy: identity.policy.clone(),
                timeout: Some(0),
                token: Some(wire::CallerToken {
                    certificate: base64::engine::general_purpose::STANDARD
                        .encode(input.caller_certificate_sha1),
                    nonce,
                }),
                package: identity.calling_package.clone(),
                imsi_requests: vec![wire::ImsiRequest {
                    imsi: input.imsi.clone(),
                    number: input.number.clone(),
                }],
            }),
        }],
        header: Some(header),
    };
    check_size(&message)?;
    Ok(message)
}
fn make_proceed(
    identity: &ConsentRequest,
    session: &str,
    verification: &Verification,
    json: &str,
    history: &[String],
) -> Result<wire::ProceedRequest, Error> {
    // shortcut: unsigned bootstrap only; implement ClientAuth before accepting key updates.
    if verification.key_status.is_some_and(|status| status != 0) {
        return Err(Error::InvalidInput(
            "unsigned Proceed after public-key update",
        ));
    }
    let original = Verification::decode(verification.raw.clone())?;
    if original.state != Some(2) || original.method != Some(11) {
        return Err(Error::InvalidInput("pending TS43 verification"));
    }
    let challenge = original
        .ts43
        .as_ref()
        .ok_or(Error::InvalidInput("pending TS43 challenge"))?;
    if !matches!(
        challenge.action,
        Some(super::Ts43Action::AcquireTemporaryToken(_))
    ) {
        return Err(Error::InvalidInput("AcquireTemporaryToken challenge"));
    }
    if json.is_empty()
        || json.len() > 64 * 1024
        || history.len() > 64
        || history.iter().any(|line| line.len() > 16 * 1024)
    {
        return Err(Error::InvalidInput("TS43 response size"));
    }
    let document: serde_json::Value =
        serde_json::from_str(json).map_err(|_| Error::InvalidInput("carrier JSON"))?;
    let app = challenge
        .app_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .ok_or(Error::InvalidInput("TS43 application ID"))?;
    if !document
        .get(app)
        .and_then(|app| app.get("TemporaryToken"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|token| !token.is_empty())
    {
        return Err(Error::InvalidInput("carrier temporary-token response"));
    }
    let message = wire::ProceedRequest {
        verification: verification.raw.clone(),
        response: Some(wire::ChallengeResponse {
            ts43: Some(wire::Ts43Response {
                context: challenge.context.clone(),
                temporary: Some(wire::TemporaryResponse {
                    full_json: json.into(),
                }),
                history: history.to_vec(),
            }),
        }),
        header: Some(crate::consent::make_header(identity, session)?),
    };
    check_size(&message)?;
    Ok(message)
}

fn check_size(message: &impl Message) -> Result<(), Error> {
    if message.encoded_len() > 128 * 1024 {
        return Err(Error::InvalidInput("verification request size"));
    }
    Ok(())
}
fn validate_sim(input: &InitialSync) -> Result<(), Error> {
    if !(5..=15).contains(&input.imsi.len()) || !input.imsi.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidInput("SIM IMSI"));
    }
    if uuid::Uuid::parse_str(&input.caller_session_id).is_err() {
        return Err(Error::InvalidInput("caller session UUID"));
    }
    if !(0..64).contains(&input.slot_index) || input.subscription_id < 0 {
        return Err(Error::InvalidInput("SIM slot/subscription"));
    }
    if let Some(number) = &input.number {
        let digits = number.strip_prefix('+').unwrap_or(number);
        if !(5..=15).contains(&digits.len()) || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::InvalidInput("SIM number"));
        }
    }
    if input.iccid.as_ref().is_some_and(|value| {
        !(10..=32).contains(&value.len()) || !value.bytes().all(|b| b.is_ascii_hexdigit())
    }) {
        return Err(Error::InvalidInput("SIM ICCID"));
    }
    let telephony = &input.telephony;
    if !(1..=64).contains(&telephony.phone_count)
        || !(1..=64).contains(&telephony.max_subscriptions)
        || telephony.phone_type < 0
        || telephony.roaming < 0
    {
        return Err(Error::InvalidInput("telephony counts/state"));
    }
    if telephony.gid1.len() > 128 || telephony.gid1.chars().any(char::is_control) {
        return Err(Error::InvalidInput("SIM GID1"));
    }
    for operator in [&telephony.sim_operator, &telephony.network_operator] {
        if (!operator.code.is_empty()
            && (!(5..=6).contains(&operator.code.len())
                || !operator.code.bytes().all(|b| b.is_ascii_digit())))
            || (!operator.country.is_empty()
                && (operator.country.len() != 2
                    || !operator.country.bytes().all(|b| b.is_ascii_alphabetic())))
            || operator.name.len() > 512
            || operator.name.chars().any(char::is_control)
        {
            return Err(Error::InvalidInput("operator facts"));
        }
    }
    Ok(())
}

macro_rules! redacted_debug {
    ($($name:ty),*) => { $(impl fmt::Debug for $name {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(concat!(stringify!($name), "([REDACTED])")) }
    })* }
}
redacted_debug!(InitialSync, TelephonyInfo, OperatorInfo);

#[cfg(test)]
mod tests;

/// One initial verification RPC using real caller/device facts from `identity`.
/// A raw `constellation_verify` proof must be bound to `rpc=sync`. No automatic retries.
pub async fn initial_sync(
    metadata: &crate::ClientMetadata,
    identity: &ConsentRequest,
    input: &InitialSync,
) -> Result<SyncResponse, Error> {
    let message = make_sync(identity, input)?;
    let response = rpc(
        metadata,
        message,
        "/google.internal.communications.phonedeviceverification.v1.PhoneDeviceVerification/Sync",
    )
    .await?;
    SyncResponse::decode(response)
}

/// Submit the complete genuine carrier response for an unsigned initial TS43 challenge.
/// Reuse the Sync session ID. Supply genuine HTTP history or an empty list.
/// Raw proof must use `rpc=proceed`; a valid backend cached token can be reused.
/// Key updates are rejected because signed ClientAuth is not implemented here.
pub async fn proceed_ts43_unsigned(
    metadata: &crate::ClientMetadata,
    identity: &ConsentRequest,
    session: &str,
    verification: &Verification,
    json: &str,
    history: &[String],
) -> Result<ProceedResponse, Error> {
    let message = make_proceed(identity, session, verification, json, history)?;
    let response=rpc(metadata,message,"/google.internal.communications.phonedeviceverification.v1.PhoneDeviceVerification/Proceed").await?;
    ProceedResponse::decode(response)
}

async fn rpc<T: Message + Default + 'static>(
    metadata: &crate::ClientMetadata,
    message: T,
    path: &'static str,
) -> Result<Bytes, Error> {
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
    send_channel(channel, metadata, message, path).await
}
async fn send_channel<T: Message + Default + 'static>(
    channel: tonic::transport::Channel,
    metadata: &crate::ClientMetadata,
    message: T,
    path: &'static str,
) -> Result<Bytes, Error> {
    let mut grpc = tonic::client::Grpc::new(channel)
        .max_decoding_message_size(256 * 1024)
        .max_encoding_message_size(128 * 1024);
    grpc.ready().await.map_err(Error::Transport)?;
    let mut request = tonic::Request::new(message);
    metadata.apply_to(&mut request);
    request.set_timeout(Duration::from_secs(20));
    let response = grpc
        .unary(
            request,
            http::uri::PathAndQuery::from_static(path),
            crate::codec::PreservingCodec::<T>::default(),
        )
        .await
        .map_err(|status| Error::Rpc(Box::new(status)))?;
    Ok(response.into_inner())
}
#[cfg(test)]
mod transport_tests;
