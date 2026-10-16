//! Signed read-only lookup of this client's existing RCS number records.
use super::*;
use base64::Engine;
use std::time::SystemTime;

const PATH: &str = "/google.internal.communications.phonedeviceverification.v1.PhoneNumber/GetVerifiedPhoneNumbers";

/// Uses the read API's project-specific IID and the client's own persisted EC key.
/// The caller signs `read_numbers_signing_input` and supplies the DER signature.
/// Signature ownership and freshness remain host responsibilities; only its size is checked.
pub struct ReadNumbersRequest {
    pub iid_token: String,
    pub signed_at: SystemTime,
    pub signature_der: Vec<u8>,
    pub caller_certificate_sha1: [u8; 20],
    pub calling_package: String,
    pub caller_nonce: String,
}
pub struct ReadNumbersResponse {
    pub numbers: Vec<ReadNumber>,
    raw: Bytes,
}
/// Unvalidated service data. A record is not an admitted RCS session.
pub struct ReadNumber {
    phone: Option<String>,
    id_token: Option<String>,
    pub rcs_state: Option<i32>,
    raw: Bytes,
}
impl fmt::Debug for ReadNumbersRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReadNumbersRequest([REDACTED])")
    }
}
impl fmt::Debug for ReadNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReadNumber([REDACTED])")
    }
}
impl fmt::Debug for ReadNumbersResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadNumbersResponse")
            .field("record_count", &self.numbers.len())
            .finish_non_exhaustive()
    }
}
impl ReadNumber {
    pub fn private_phone_number(&self) -> Option<&str> {
        self.phone.as_deref()
    }
    pub fn private_id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }
    /// Original record, including its verification timestamp and unknown fields.
    pub fn raw_protobuf(&self) -> &[u8] {
        &self.raw
    }
}
impl ReadNumbersResponse {
    pub fn decode(raw: Bytes) -> Result<Self, Error> {
        let response: ReadResponseWire = decode(&raw)?;
        if response.records.len() > MAX_RECORDS {
            return Err(Error::InvalidResponse("too many read number records"));
        }
        let mut numbers = Vec::with_capacity(response.records.len());
        for raw in response.records {
            // Reject packed data for a singular enum before the duplicate-detection view.
            let _: ReadNumberState = decode(&raw)?;
            let row: ReadNumberWire = decode(&raw)?;
            numbers.push(ReadNumber {
                phone: text(one(row.phones)?)?,
                id_token: text(one(row.tokens)?)?.filter(|s| !s.is_empty()),
                rcs_state: one(row.states)?,
                raw,
            });
        }
        Ok(Self { numbers, raw })
    }
    pub fn raw_protobuf(&self) -> &[u8] {
        &self.raw
    }
}
/// Private UTF-8 `iid_token:seconds:nanos`, for SHA256withECDSA using the owned key.
pub fn read_numbers_signing_input(iid: &str, at: SystemTime) -> Result<Vec<u8>, Error> {
    validate_iid(iid)?;
    let at = timestamp(at)?;
    Ok(format!("{iid}:{}:{}", at.seconds, at.nanos).into_bytes())
}

fn validate_iid(iid: &str) -> Result<(), Error> {
    if iid.is_empty() || iid.len() > 4096 || !iid.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error::InvalidInput("read API IID"));
    }
    Ok(())
}
fn timestamp(at: SystemTime) -> Result<crate::consent::wire::Timestamp, Error> {
    let duration = at
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidInput("read API signing time"))?;
    Ok(crate::consent::wire::Timestamp {
        seconds: duration
            .as_secs()
            .try_into()
            .map_err(|_| Error::InvalidInput("read API signing time"))?,
        nanos: duration.subsec_nanos() as i32,
    })
}
fn make_request(input: &ReadNumbersRequest, session: &str) -> Result<ReadRequestWire, Error> {
    validate_iid(&input.iid_token)?;
    if !(8..=128).contains(&input.signature_der.len()) {
        return Err(Error::InvalidInput("read API signature size"));
    }
    if input.calling_package.is_empty()
        || input.calling_package.len() > 255
        || !input
            .calling_package
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
    {
        return Err(Error::InvalidInput("read API caller package"));
    }
    if input.caller_nonce.is_empty()
        || input.caller_nonce.len() > MAX_TEXT
        || !input.caller_nonce.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(Error::InvalidInput("read API caller nonce"));
    }
    Ok(ReadRequestWire {
        session: session.into(),
        credentials: Some(ReadCredentialsWire {
            iid: input.iid_token.clone(),
            signature: input.signature_der.clone(),
            timestamp: Some(timestamp(input.signed_at)?),
        }),
        selection: vec![2],
        caller: Some(ReadCallerWire {
            certificate: base64::engine::general_purpose::STANDARD
                .encode(input.caller_certificate_sha1),
            package: input.calling_package.clone(),
            nonce: input.caller_nonce.clone(),
        }),
    })
}
/// One read-only RCS-record lookup; it does not initiate number verification or retry.
/// Default GMS read-API behavior signs the request and omits DroidGuard.
pub async fn read_verified_numbers(
    metadata: &crate::ClientMetadata,
    input: &ReadNumbersRequest,
) -> Result<ReadNumbersResponse, Error> {
    let request = make_request(input, &uuid::Uuid::new_v4().to_string())?;
    let raw = super::request::rpc(metadata, request, PATH).await?;
    ReadNumbersResponse::decode(raw)
}

#[derive(Clone, PartialEq, Message)]
#[prost(skip_debug)]
struct ReadRequestWire {
    #[prost(string, tag = "1")]
    session: String,
    #[prost(message, optional, tag = "2")]
    credentials: Option<ReadCredentialsWire>,
    #[prost(int32, repeated, tag = "3")]
    selection: Vec<i32>,
    #[prost(message, optional, tag = "4")]
    caller: Option<ReadCallerWire>,
}
#[derive(Clone, PartialEq, Message)]
#[prost(skip_debug)]
struct ReadCredentialsWire {
    #[prost(string, tag = "1")]
    iid: String,
    #[prost(bytes, tag = "2")]
    signature: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    timestamp: Option<crate::consent::wire::Timestamp>,
}
#[derive(Clone, PartialEq, Message)]
#[prost(skip_debug)]
struct ReadCallerWire {
    #[prost(string, tag = "1")]
    certificate: String,
    #[prost(string, tag = "2")]
    package: String,
    #[prost(string, tag = "3")]
    nonce: String,
}
#[derive(Clone, PartialEq, Message)]
#[prost(skip_debug)]
struct ReadResponseWire {
    #[prost(bytes = "bytes", repeated, tag = "2")]
    records: Vec<Bytes>,
}
#[derive(Clone, PartialEq, Message)]
#[prost(skip_debug)]
struct ReadNumberWire {
    #[prost(string, repeated, tag = "1")]
    phones: Vec<String>,
    #[prost(string, repeated, tag = "3")]
    tokens: Vec<String>,
    #[prost(int32, packed = "false", repeated, tag = "4")]
    states: Vec<i32>,
}
#[derive(Clone, PartialEq, Message)]
struct ReadNumberState {
    #[prost(int32, optional, tag = "4")]
    _state: Option<i32>,
}
macro_rules! redacted_wire_debug {
    ($($name:ty),*)=>{$(impl fmt::Debug for $name { fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result { f.write_str(concat!(stringify!($name),"([REDACTED])")) } })*}
}
redacted_wire_debug!(
    ReadRequestWire,
    ReadCredentialsWire,
    ReadCallerWire,
    ReadResponseWire,
    ReadNumberWire
);

#[cfg(test)]
mod tests;
