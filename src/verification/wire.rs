//! Private prost decode views. Singular slots are repeated only to detect duplicates.
//! Length-delimited messages use bytes where their original contents must survive.

// Repeated scalar views also accept packed encodings. A standard singular parse
// rejects that wrong wire type before the repeated view checks duplicates.
macro_rules! singular_integer {
    ($name:ident, $tag:literal) => {
        #[derive(Clone, PartialEq, prost::Message)]
        pub(super) struct $name {
            #[prost(int32, optional, tag=$tag)]
            value: Option<i32>,
        }
    };
}
singular_integer!(Integer1, "1");
singular_integer!(Integer2, "2");
singular_integer!(Integer3, "3");
singular_integer!(Integer12, "12");

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct SyncResponse {
    #[prost(bytes = "bytes", repeated, tag = "1")]
    pub results: Vec<bytes::Bytes>,
    #[prost(bytes = "bytes", repeated, tag = "3")]
    pub headers: Vec<bytes::Bytes>,
    #[prost(bytes = "bytes", repeated, tag = "4")]
    pub cached_tokens: Vec<bytes::Bytes>,
}
impl std::fmt::Debug for SyncResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyncResponse([REDACTED])")
    }
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct ProceedResponse {
    #[prost(bytes = "bytes", repeated, tag = "1")]
    pub verifications: Vec<bytes::Bytes>,
    #[prost(bytes = "bytes", repeated, tag = "2")]
    pub headers: Vec<bytes::Bytes>,
    #[prost(bytes = "bytes", repeated, tag = "4")]
    pub cached_tokens: Vec<bytes::Bytes>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct ResponseHeader {
    #[prost(bytes = "bytes", repeated, tag = "1")]
    pub updates: Vec<bytes::Bytes>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct ClientInfoUpdate {
    #[prost(int32, packed = "false", repeated, tag = "1")]
    pub statuses: Vec<i32>,
}
impl std::fmt::Debug for ProceedResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProceedResponse([REDACTED])")
    }
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct Result {
    #[prost(bytes = "bytes", repeated, tag = "1")]
    pub verifications: Vec<bytes::Bytes>,
    #[prost(bytes = "bytes", repeated, tag = "2")]
    pub statuses: Vec<bytes::Bytes>,
}
impl std::fmt::Debug for Result {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Result([REDACTED])")
    }
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct Verification {
    #[prost(bytes = "bytes", repeated, tag = "1")]
    pub associations: Vec<bytes::Bytes>,
    #[prost(int32, packed = "false", repeated, tag = "2")]
    pub states: Vec<i32>,
    #[prost(bytes = "bytes", repeated, tag = "3")]
    pub verified_infos: Vec<bytes::Bytes>,
    #[prost(bytes = "bytes", repeated, tag = "4")]
    pub challenges: Vec<bytes::Bytes>,
    #[prost(bytes = "bytes", repeated, tag = "9")]
    pub unverified_infos: Vec<bytes::Bytes>,
}
impl std::fmt::Debug for Verification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Verification([REDACTED])")
    }
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct Status {
    #[prost(int32, packed = "false", repeated, tag = "1")]
    pub codes: Vec<i32>,
    #[prost(string, repeated, tag = "3")]
    pub messages: Vec<String>,
}
impl std::fmt::Debug for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Status([REDACTED])")
    }
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct UnverifiedInfo {
    #[prost(int32, packed = "false", repeated, tag = "1")]
    pub reasons: Vec<i32>,
    #[prost(int32, packed = "false", repeated, tag = "3")]
    pub methods: Vec<i32>,
}
impl std::fmt::Debug for UnverifiedInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UnverifiedInfo([REDACTED])")
    }
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct ChallengeContainer {
    #[prost(bytes = "bytes", repeated, tag = "2")]
    pub challenges: Vec<bytes::Bytes>,
}
impl std::fmt::Debug for ChallengeContainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChallengeContainer([REDACTED])")
    }
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct Challenge {
    #[prost(int32, packed = "false", repeated, tag = "2")]
    pub methods: Vec<i32>,
    #[prost(bytes = "bytes", repeated, tag = "12")]
    pub ts43: Vec<bytes::Bytes>,
}
impl std::fmt::Debug for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Challenge([REDACTED])")
    }
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct Ts43Challenge {
    #[prost(bytes = "bytes", repeated, tag = "1")]
    pub contexts: Vec<bytes::Bytes>,
    #[prost(string, repeated, tag = "2")]
    pub server_urls: Vec<String>,
    #[prost(bytes = "bytes", repeated, tag = "3")]
    pub params: Vec<bytes::Bytes>,
    #[prost(bytes = "bytes", repeated, tag = "4")]
    pub get_phone_number: Vec<bytes::Bytes>,
    #[prost(bytes = "bytes", repeated, tag = "5")]
    pub acquire_temporary_token: Vec<bytes::Bytes>,
    #[prost(string, repeated, tag = "6")]
    pub app_ids: Vec<String>,
    #[prost(string, repeated, tag = "7")]
    pub nai_realms: Vec<String>,
}
impl std::fmt::Debug for Ts43Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ts43Challenge([REDACTED])")
    }
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct Ts43Params {
    #[prost(int32, packed = "false", repeated, tag = "1")]
    pub versions: Vec<i32>,
    #[prost(string, repeated, tag = "2")]
    pub entitlement_versions: Vec<String>,
    #[prost(string, repeated, tag = "3")]
    pub authentication_tokens: Vec<String>,
    #[prost(string, repeated, tag = "4")]
    pub temporary_tokens: Vec<String>,
    #[prost(string, repeated, tag = "5")]
    pub terminal_ids: Vec<String>,
    #[prost(string, repeated, tag = "6")]
    pub terminal_vendors: Vec<String>,
    #[prost(string, repeated, tag = "7")]
    pub terminal_models: Vec<String>,
    #[prost(string, repeated, tag = "8")]
    pub terminal_sw_versions: Vec<String>,
    #[prost(string, repeated, tag = "9")]
    pub app_names: Vec<String>,
    #[prost(string, repeated, tag = "10")]
    pub app_versions: Vec<String>,
    #[prost(string, repeated, tag = "11")]
    pub notification_tokens: Vec<String>,
    #[prost(int32, packed = "false", repeated, tag = "12")]
    pub notification_actions: Vec<i32>,
    #[prost(string, repeated, tag = "13")]
    pub accept_types: Vec<String>,
    #[prost(string, repeated, tag = "14")]
    pub boost_types: Vec<String>,
    #[prost(string, repeated, tag = "15")]
    pub gid1: Vec<String>,
}
impl std::fmt::Debug for Ts43Params {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ts43Params([REDACTED])")
    }
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct AcquireTemporaryToken {
    #[prost(bytes = "bytes", repeated, tag = "1")]
    pub operations: Vec<bytes::Bytes>,
}
impl std::fmt::Debug for AcquireTemporaryToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AcquireTemporaryToken([REDACTED])")
    }
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub(super) struct Operation {
    #[prost(string, repeated, tag = "1")]
    pub names: Vec<String>,
    #[prost(int32, packed = "false", repeated, tag = "2")]
    pub types: Vec<i32>,
    #[prost(string, repeated, tag = "3")]
    pub targets: Vec<String>,
    #[prost(string, repeated, tag = "15")]
    pub target_ids: Vec<String>,
}
impl std::fmt::Debug for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Operation([REDACTED])")
    }
}
