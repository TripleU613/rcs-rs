use crate::consent::wire::{Param, RequestHeader};
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct Slot {
    #[prost(int32, optional, tag = "1")]
    pub index: Option<i32>,
    #[prost(int32, optional, tag = "2")]
    pub subscription: Option<i32>,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct SimInfo {
    #[prost(string, repeated, tag = "1")]
    pub imsi: Vec<String>,
    #[prost(string, optional, tag = "2")]
    pub number: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub iccid: Option<String>,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct SimAssociation {
    #[prost(message, optional, tag = "1")]
    pub info: Option<SimInfo>,
    #[prost(message, optional, tag = "4")]
    pub slot: Option<Slot>,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct Association {
    #[prost(message, optional, tag = "1")]
    pub sim: Option<SimAssociation>,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct Operator {
    #[prost(string, tag = "1")]
    pub country: String,
    #[prost(string, tag = "2")]
    pub code: String,
    #[prost(string, tag = "3")]
    pub name: String,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct Telephony {
    #[prost(int32, optional, tag = "1")]
    pub phone_type: Option<i32>,
    #[prost(string, tag = "2")]
    pub gid1: String,
    #[prost(message, optional, tag = "3")]
    pub sim_operator: Option<Operator>,
    #[prost(message, optional, tag = "4")]
    pub network_operator: Option<Operator>,
    #[prost(int32, optional, tag = "5")]
    pub roaming: Option<i32>,
    #[prost(int32, optional, tag = "8")]
    pub phone_count: Option<i32>,
    #[prost(int32, optional, tag = "9")]
    pub max_subscriptions: Option<i32>,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct MtData {
    #[prost(string, optional, tag = "2")]
    pub payload: Option<String>,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct Methods {
    #[prost(message, optional, tag = "2")]
    pub mt: Option<MtData>,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct CallerToken {
    #[prost(string, tag = "1")]
    pub certificate: String,
    #[prost(string, tag = "2")]
    pub nonce: String,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct ImsiRequest {
    #[prost(string, tag = "1")]
    pub imsi: String,
    #[prost(string, optional, tag = "2")]
    pub number: Option<String>,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct ApiInfo {
    #[prost(string, tag = "1")]
    pub policy: String,
    #[prost(int64, optional, tag = "2")]
    pub timeout: Option<i64>,
    #[prost(message, optional, tag = "3")]
    pub token: Option<CallerToken>,
    #[prost(string, tag = "4")]
    pub package: String,
    #[prost(message, repeated, tag = "5")]
    pub imsi_requests: Vec<ImsiRequest>,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct Verification {
    #[prost(message, optional, tag = "1")]
    pub association: Option<Association>,
    #[prost(int32, tag = "2")]
    pub state: i32,
    #[prost(message, optional, tag = "5")]
    pub telephony: Option<Telephony>,
    #[prost(message, repeated, tag = "6")]
    pub params: Vec<Param>,
    #[prost(message, optional, tag = "7")]
    pub methods: Option<Methods>,
    #[prost(message, optional, tag = "8")]
    pub api: Option<ApiInfo>,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct SyncRequest {
    #[prost(message, repeated, tag = "3")]
    pub verifications: Vec<Verification>,
    #[prost(message, optional, tag = "4")]
    pub header: Option<RequestHeader>,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct TemporaryResponse {
    #[prost(string, tag = "2")]
    pub full_json: String,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct Ts43Response {
    #[prost(bytes = "bytes", tag = "1")]
    pub context: bytes::Bytes,
    #[prost(message, optional, tag = "3")]
    pub temporary: Option<TemporaryResponse>,
    #[prost(string, repeated, tag = "5")]
    pub history: Vec<String>,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct MtSmsResponse {
    #[prost(string, tag = "1")]
    pub body: String,
    #[prost(string, tag = "2")]
    pub sender: String,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct ChallengeResponse {
    #[prost(message, optional, tag = "1")]
    pub mt_sms: Option<MtSmsResponse>,
    #[prost(message, optional, tag = "9")]
    pub ts43: Option<Ts43Response>,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct ProceedRequest {
    #[prost(bytes = "bytes", tag = "2")]
    pub verification: bytes::Bytes,
    #[prost(message, optional, tag = "3")]
    pub response: Option<ChallengeResponse>,
    #[prost(message, optional, tag = "4")]
    pub header: Option<RequestHeader>,
}
macro_rules! redacted { ($($name:ty),*) => {$(impl std::fmt::Debug for $name { fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.write_str(concat!(stringify!($name),"([REDACTED])"))}})*} }
redacted!(
    Slot,
    SimInfo,
    SimAssociation,
    Association,
    Operator,
    Telephony,
    MtData,
    Methods,
    CallerToken,
    ImsiRequest,
    ApiInfo,
    Verification,
    SyncRequest,
    TemporaryResponse,
    Ts43Response,
    MtSmsResponse,
    ChallengeResponse,
    ProceedRequest
);
