//! Decoder-only views of Sync/Proceed responses. No RPC, SIM authentication,
//! Proceed encoding, number verification, or token validation is performed.

use crate::Error;
use bytes::Bytes;
use prost::Message;
use std::{collections::HashSet, fmt};

mod wire;

const MAX_MESSAGE: usize = 256 * 1024;
const MAX_TEXT: usize = 16 * 1024;
const MAX_RECORDS: usize = 64;

/// Decoded records retain service-level failures even when the outer gRPC status is OK.
pub struct SyncResponse {
    pub results: Vec<VerificationResult>,
    raw: Bytes,
}
pub struct ProceedResponse {
    pub verification: Option<Verification>,
    raw: Bytes,
}
#[derive(Debug)]
pub struct VerificationResult {
    pub verification: Option<Verification>,
    pub status: Option<RecordStatus>,
}
pub struct Verification {
    /// Known values: NONE=1 and PENDING=2. Other values remain numeric, without inference.
    pub state: Option<i32>,
    /// Known examples: THROTTLED=1, FAILED=2. Unknown values remain numeric.
    pub unverified_reason: Option<i32>,
    /// Challenge.method2 or UnverifiedInfo.method3; TS43 is 11.
    pub method: Option<i32>,
    pub ts43: Option<Ts43Challenge>,
    raw: Bytes,
    association: Option<Bytes>,
}
/// Custom service status: code field1, message field3. Field2 remains opaque in raw bytes.
pub struct RecordStatus {
    pub code: Option<i32>,
    message: Option<String>,
    raw: Bytes,
}
pub struct Ts43Challenge {
    context: Bytes,
    server_url: String,
    pub parameters: Ts43Parameters,
    pub action: Option<Ts43Action>,
    app_id: Option<String>,
    nai_realm: Option<String>,
}

/// The decoder recognizes these payload kinds; it does not execute either operation.
pub enum Ts43Action {
    AcquireTemporaryToken(CarrierOperation),
    GetPhoneNumber,
}

pub struct CarrierOperation {
    pub operation_type: Option<i32>,
    name: Option<String>,
    targets: Vec<String>,
    target_ids: Vec<String>,
    raw: Bytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StringParameter {
    EntitlementVersion,
    AuthenticationToken,
    TemporaryToken,
    TerminalId,
    TerminalVendor,
    TerminalModel,
    TerminalSoftwareVersion,
    AppName,
    AppVersion,
    NotificationToken,
    AcceptContentType,
    BoostType,
    Gid1,
}

pub struct Ts43Parameters {
    pub configuration_version: Option<i32>,
    pub notification_action: Option<i32>,
    strings: Vec<(StringParameter, String)>,
}

impl SyncResponse {
    /// Decode bounded records and retain their original bytes. Duplicate association
    /// detection compares bytes only; reordered/unknown schemas are not normalized.
    pub fn decode(raw: Bytes) -> Result<Self, Error> {
        bounded(&raw, MAX_MESSAGE)?;
        let response: wire::SyncResponse = decode(&raw)?;
        if response.results.len() > MAX_RECORDS {
            return Err(Error::InvalidResponse("too many verification results"));
        }
        let mut results = Vec::with_capacity(response.results.len());
        let mut associations = HashSet::new();
        let mut verifications = HashSet::new();
        for bytes in response.results {
            let result: wire::Result = decode(&bytes)?;
            let verification = one(result.verifications)?
                .map(Verification::decode)
                .transpose()?;
            let status = one(result.statuses)?
                .map(RecordStatus::decode)
                .transpose()?;
            if verification.is_none() && status.is_none() {
                return Err(Error::InvalidResponse("empty verification result"));
            }
            if let Some(verification) = &verification {
                if !verifications.insert(verification.raw.clone()) {
                    return Err(Error::InvalidResponse("duplicate verification result"));
                }
                if let Some(association) = &verification.association
                    && !associations.insert(association.clone())
                {
                    return Err(Error::InvalidResponse("ambiguous verification association"));
                }
            }
            results.push(VerificationResult {
                verification,
                status,
            });
        }
        Ok(Self { results, raw })
    }
    /// Original response bytes, including private identifiers and unknown fields.
    pub fn raw_protobuf(&self) -> &[u8] {
        &self.raw
    }
}
impl ProceedResponse {
    pub fn decode(raw: Bytes) -> Result<Self, Error> {
        bounded(&raw, MAX_MESSAGE)?;
        let response: wire::ProceedResponse = decode(&raw)?;
        let verification = one(response.verifications)?
            .map(Verification::decode)
            .transpose()?;
        Ok(Self { verification, raw })
    }
    /// Original response bytes, including private identifiers and unknown fields.
    pub fn raw_protobuf(&self) -> &[u8] {
        &self.raw
    }
}
impl Verification {
    fn decode(raw: Bytes) -> Result<Self, Error> {
        let _: wire::Integer2 = decode(&raw)?;
        let message: wire::Verification = decode(&raw)?;
        let association = one(message.associations)?;
        let state = one(message.states)?;
        let verified = one(message.verified_infos)?;
        let challenge = one(message.challenges)?;
        let unverified = one(message.unverified_infos)?;
        if [
            verified.is_some(),
            challenge.is_some(),
            unverified.is_some(),
        ]
        .into_iter()
        .filter(|v| *v)
        .count()
            > 1
        {
            return Err(Error::InvalidResponse(
                "ambiguous verification state payload",
            ));
        }
        let mut method = None;
        let mut unverified_reason = None;
        let mut ts43 = None;
        if let Some(bytes) = unverified {
            let _: wire::Integer1 = decode(&bytes)?;
            let _: wire::Integer3 = decode(&bytes)?;
            let info: wire::UnverifiedInfo = decode(&bytes)?;
            unverified_reason = one(info.reasons)?;
            method = one(info.methods)?;
        }
        if let Some(bytes) = challenge {
            let container: wire::ChallengeContainer = decode(&bytes)?;
            if let Some(bytes) = one(container.challenges)? {
                let _: wire::Integer2 = decode(&bytes)?;
                let challenge: wire::Challenge = decode(&bytes)?;
                method = one(challenge.methods)?;
                let payload = one(challenge.ts43)?;
                match (method, payload) {
                    (Some(11), Some(bytes)) => ts43 = Some(Ts43Challenge::decode(&bytes)?),
                    (Some(11), None) | (_, Some(_)) => {
                        return Err(Error::InvalidResponse("TS43 method/payload mismatch"));
                    }
                    _ => {}
                }
            }
        }
        Ok(Self {
            state,
            unverified_reason,
            method,
            ts43,
            raw,
            association,
        })
    }
    /// Exact embedded Verification, including unknown fields and challenge bytes.
    /// Keep private; this is the original record needed by a future Proceed encoder.
    pub fn raw_protobuf(&self) -> &[u8] {
        &self.raw
    }
}
impl RecordStatus {
    fn decode(raw: Bytes) -> Result<Self, Error> {
        let _: wire::Integer1 = decode(&raw)?;
        let status: wire::Status = decode(&raw)?;
        let message = one(status.messages)?;
        if message.as_ref().is_some_and(|value| value.len() > MAX_TEXT) {
            return Err(Error::InvalidResponse(
                "verification status message exceeds size limit",
            ));
        }
        Ok(Self {
            code: one(status.codes)?,
            message,
            raw,
        })
    }
    pub fn private_message(&self) -> Option<&str> {
        self.message.as_deref()
    }
    pub fn raw_protobuf(&self) -> &[u8] {
        &self.raw
    }
}
impl Ts43Challenge {
    fn decode(raw: &[u8]) -> Result<Self, Error> {
        let challenge: wire::Ts43Challenge = decode(raw)?;
        let context = one(challenge.contexts)?
            .filter(|bytes| !bytes.is_empty())
            .ok_or(Error::InvalidResponse("TS43 context missing"))?;
        bounded(&context, 16 * 1024)?;
        let server_url =
            text(one(challenge.server_urls)?)?.ok_or(Error::InvalidResponse("TS43 URL missing"))?;
        let url = reqwest::Url::parse(&server_url)
            .map_err(|_| Error::InvalidResponse("invalid TS43 URL"))?;
        if server_url.len() > 8192
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::InvalidResponse("invalid TS43 HTTPS URL"));
        }
        let params =
            one(challenge.params)?.ok_or(Error::InvalidResponse("TS43 parameters missing"))?;
        let get_phone_number = one(challenge.get_phone_number)?;
        let acquire = one(challenge.acquire_temporary_token)?;
        if get_phone_number.is_some() && acquire.is_some() {
            return Err(Error::InvalidResponse("ambiguous TS43 action"));
        }
        let action = if let Some(bytes) = acquire {
            let wrapper: wire::AcquireTemporaryToken = decode(&bytes)?;
            let operation =
                one(wrapper.operations)?.ok_or(Error::InvalidResponse("TS43 operation missing"))?;
            Some(Ts43Action::AcquireTemporaryToken(CarrierOperation::decode(
                operation,
            )?))
        } else {
            get_phone_number.map(|_| Ts43Action::GetPhoneNumber)
        };
        Ok(Self {
            context,
            server_url,
            parameters: Ts43Parameters::decode(&params)?,
            action,
            app_id: text(one(challenge.app_ids)?)?,
            nai_realm: text(one(challenge.nai_realms)?)?,
        })
    }
    pub fn private_context(&self) -> &[u8] {
        &self.context
    }
    pub fn private_server_url(&self) -> &str {
        &self.server_url
    }
    pub fn private_application_id(&self) -> Option<&str> {
        self.app_id.as_deref()
    }
    pub fn private_nai_realm(&self) -> Option<&str> {
        self.nai_realm.as_deref()
    }
}

impl CarrierOperation {
    fn decode(raw: Bytes) -> Result<Self, Error> {
        let _: wire::Integer2 = decode(&raw)?;
        let operation: wire::Operation = decode(&raw)?;
        for values in [&operation.targets, &operation.target_ids] {
            if values.len() > MAX_RECORDS {
                return Err(Error::InvalidResponse("too many TS43 operation targets"));
            }
            for value in values {
                text(Some(value.clone()))?;
            }
        }
        Ok(Self {
            operation_type: one(operation.types)?,
            name: text(one(operation.names)?)?,
            targets: operation.targets,
            target_ids: operation.target_ids,
            raw,
        })
    }
    pub fn private_name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    pub fn private_targets(&self) -> &[String] {
        &self.targets
    }
    pub fn private_target_ids(&self) -> &[String] {
        &self.target_ids
    }
    /// Retains operation fields outside the typed subset, including companion/terminal identifiers.
    pub fn raw_protobuf(&self) -> &[u8] {
        &self.raw
    }
}

impl Ts43Parameters {
    fn decode(raw: &[u8]) -> Result<Self, Error> {
        let _: wire::Integer1 = decode(raw)?;
        let _: wire::Integer12 = decode(raw)?;
        let params: wire::Ts43Params = decode(raw)?;
        let mut strings = Vec::new();
        for (name, values) in [
            (
                StringParameter::EntitlementVersion,
                params.entitlement_versions,
            ),
            (
                StringParameter::AuthenticationToken,
                params.authentication_tokens,
            ),
            (StringParameter::TemporaryToken, params.temporary_tokens),
            (StringParameter::TerminalId, params.terminal_ids),
            (StringParameter::TerminalVendor, params.terminal_vendors),
            (StringParameter::TerminalModel, params.terminal_models),
            (
                StringParameter::TerminalSoftwareVersion,
                params.terminal_sw_versions,
            ),
            (StringParameter::AppName, params.app_names),
            (StringParameter::AppVersion, params.app_versions),
            (
                StringParameter::NotificationToken,
                params.notification_tokens,
            ),
            (StringParameter::AcceptContentType, params.accept_types),
            (StringParameter::BoostType, params.boost_types),
            (StringParameter::Gid1, params.gid1),
        ] {
            if let Some(value) = text(one(values)?)? {
                strings.push((name, value));
            }
        }
        Ok(Self {
            configuration_version: one(params.versions)?,
            notification_action: one(params.notification_actions)?,
            strings,
        })
    }
    pub fn private_string(&self, parameter: StringParameter) -> Option<&str> {
        self.strings
            .iter()
            .find(|(name, _)| *name == parameter)
            .map(|(_, value)| value.as_str())
    }
}

fn bounded(raw: &[u8], limit: usize) -> Result<(), Error> {
    if raw.len() > limit {
        return Err(Error::InvalidResponse(
            "verification response exceeds size limit",
        ));
    }
    Ok(())
}
fn decode<M: Message + Default>(raw: &[u8]) -> Result<M, Error> {
    bounded(raw, MAX_MESSAGE)?;
    M::decode(raw).map_err(|_| Error::InvalidResponse("malformed verification protobuf"))
}
fn one<T>(mut values: Vec<T>) -> Result<Option<T>, Error> {
    if values.len() > 1 {
        return Err(Error::InvalidResponse(
            "duplicate singular verification field",
        ));
    }
    Ok(values.pop())
}
fn text(value: Option<String>) -> Result<Option<String>, Error> {
    if value
        .as_ref()
        .is_some_and(|s| s.len() > MAX_TEXT || s.chars().any(char::is_control))
    {
        return Err(Error::InvalidResponse("invalid verification text field"));
    }
    Ok(value)
}

impl fmt::Debug for Verification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verification")
            .field("state", &self.state)
            .field("unverified_reason", &self.unverified_reason)
            .field("method", &self.method)
            .field("ts43_present", &self.ts43.is_some())
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for RecordStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordStatus")
            .field("code", &self.code)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for SyncResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncResponse")
            .field("record_count", &self.results.len())
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for ProceedResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProceedResponse")
            .field("verification", &self.verification)
            .finish_non_exhaustive()
    }
}
macro_rules! redacted_debug {
    ($($name:ty),* $(,)?) => { $(impl fmt::Debug for $name {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(concat!(stringify!($name), "([REDACTED])")) }
    })* }
}
redacted_debug!(Ts43Challenge, Ts43Action, CarrierOperation, Ts43Parameters);

#[cfg(test)]
mod tests;
