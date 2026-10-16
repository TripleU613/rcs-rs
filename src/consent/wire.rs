//! Independently reconstructed wire subset from original GMS 26.37.37 descriptors.
//! IDs are header-only; ClientAuth and SIM verification fields are intentionally absent.

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct DeviceId {
    #[prost(string, tag = "1")]
    pub iid_token: String,
    #[prost(int64, tag = "2")]
    pub device_android_id: i64,
    #[prost(int64, tag = "3")]
    pub user_serial: i64,
    #[prost(int64, tag = "4")]
    pub user_android_id: i64,
}

impl std::fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceId([REDACTED])")
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Trigger {
    #[prost(int32, tag = "1")]
    pub reason: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct DroidGuardSignals {
    #[prost(string, tag = "1")]
    pub raw_droidguard: String,
    #[prost(string, tag = "2")]
    pub cached_token: String,
}

impl std::fmt::Debug for DroidGuardSignals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DroidGuardSignals([REDACTED])")
    }
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct ClientInfo {
    #[prost(message, optional, tag = "1")]
    pub device: Option<DeviceId>,
    #[prost(bytes, tag = "2")]
    pub public_key: Vec<u8>,
    #[prost(string, tag = "3")]
    pub locale: String,
    #[prost(int32, tag = "4")]
    pub version: i32,
    #[prost(string, tag = "5")]
    pub version_name: String,
    #[prost(int32, tag = "6")]
    pub sdk: i32,
    #[prost(message, optional, tag = "8")]
    pub signals: Option<DroidGuardSignals>,
    #[prost(string, tag = "15")]
    pub model: String,
    #[prost(string, tag = "16")]
    pub manufacturer: String,
    #[prost(string, tag = "21")]
    pub fingerprint: String,
}

impl std::fmt::Debug for ClientInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientInfo([REDACTED])")
    }
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct RequestHeader {
    #[prost(message, optional, tag = "1")]
    pub info: Option<ClientInfo>,
    #[prost(string, tag = "3")]
    pub session_id: String,
    #[prost(message, optional, tag = "4")]
    pub trigger: Option<Trigger>,
}

impl std::fmt::Debug for RequestHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RequestHeader([REDACTED])")
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Param {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ApiInfo {
    #[prost(string, tag = "1")]
    pub policy: String,
    #[prost(string, tag = "4")]
    pub calling_package: String,
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct GetConsentRequest {
    #[prost(message, optional, tag = "1")]
    pub device: Option<DeviceId>,
    #[prost(message, optional, tag = "4")]
    pub header: Option<RequestHeader>,
    #[prost(message, repeated, tag = "5")]
    pub params: Vec<Param>,
    #[prost(int32, tag = "6")]
    pub client: i32,
    #[prost(message, optional, tag = "7")]
    pub api: Option<ApiInfo>,
    #[prost(bool, tag = "8")]
    pub request_consent: bool,
}

impl std::fmt::Debug for GetConsentRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GetConsentRequest([REDACTED])")
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Consent {
    #[prost(int32, tag = "2")]
    pub state: i32,
    #[prost(int32, tag = "3")]
    pub detail: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ConsumerConsent {
    #[prost(int32, tag = "1")]
    pub client: i32,
    #[prost(int32, tag = "2")]
    pub state: i32,
    #[prost(int32, tag = "3")]
    pub detail: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Timestamp {
    #[prost(int64, tag = "1")]
    pub seconds: i64,
    #[prost(int32, tag = "2")]
    pub nanos: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct DroidGuardCache {
    #[prost(string, tag = "1")]
    pub token: String,
    #[prost(message, optional, tag = "2")]
    pub expires: Option<Timestamp>,
}

impl std::fmt::Debug for DroidGuardCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DroidGuardCache([REDACTED])")
    }
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct GetConsentResponse {
    #[prost(message, optional, tag = "1")]
    pub consent: Option<Consent>,
    #[prost(message, repeated, tag = "8")]
    pub consumers: Vec<ConsumerConsent>,
    #[prost(message, optional, tag = "9")]
    pub cached_dg: Option<DroidGuardCache>,
}

impl std::fmt::Debug for GetConsentResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GetConsentResponse([REDACTED])")
    }
}
