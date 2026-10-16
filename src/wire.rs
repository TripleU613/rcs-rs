//! Protocol field numbers reconstructed from Messages 324451063.
//! See docs/research/gapps-bootstrap.md for provenance. No Google implementation source is included.

#[derive(Clone, PartialEq, prost::Message)]
pub struct GetConfigurationRequest {
    #[prost(message, optional, tag = "1")]
    pub context: Option<RequestContext>,
    #[prost(message, repeated, tag = "2")]
    pub parameters: Vec<Parameters>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RequestContext {
    #[prost(string, tag = "1")]
    pub request_uuid: String,
    #[prost(int64, tag = "2")]
    pub gsf_android_id: i64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Parameters {
    #[prost(string, tag = "1")]
    pub correlation_id: String,
    #[prost(int32, tag = "2")]
    pub configuration_type: i32,
    #[prost(message, optional, tag = "3")]
    pub device: Option<Device>,
    #[prost(message, optional, tag = "4")]
    pub carrier: Option<Carrier>,
    #[prost(message, repeated, tag = "6")]
    pub packages: Vec<PackageVersion>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Device {
    #[prost(string, tag = "1")]
    pub device: String,
    #[prost(string, tag = "2")]
    pub manufacturer: String,
    #[prost(int32, tag = "3")]
    pub form_factor: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Carrier {
    #[prost(string, tag = "1")]
    pub mcc: String,
    #[prost(string, tag = "2")]
    pub mnc: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PackageVersion {
    #[prost(string, tag = "1")]
    pub package_name: String,
    #[prost(int64, tag = "2")]
    pub version_code: i64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct GetConfigurationResponse {
    #[prost(message, repeated, tag = "1")]
    pub configurations: Vec<Configuration>,
    #[prost(uint32, repeated, tag = "2")]
    pub experiment_ids: Vec<u32>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Configuration {
    #[prost(string, tag = "1")]
    pub correlation_id: String,
    #[prost(message, optional, tag = "2")]
    pub validity: Option<Duration>,
    #[prost(oneof = "configuration::Data", tags = "3, 4, 5, 6, 7, 8")]
    pub data: Option<configuration::Data>,
}

pub mod configuration {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Data {
        #[prost(message, tag = "3")]
        Onboarding(super::OnboardingFlags),
        #[prost(bytes, tag = "4")]
        Xms(Vec<u8>),
        #[prost(bytes, tag = "5")]
        Upi(Vec<u8>),
        #[prost(bytes, tag = "6")]
        Renumberings(Vec<u8>),
        #[prost(bytes, tag = "7")]
        Network(Vec<u8>),
        #[prost(bytes, tag = "8")]
        Satellite(Vec<u8>),
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Duration {
    #[prost(int64, tag = "1")]
    pub seconds: i64,
    #[prost(int32, tag = "2")]
    pub nanos: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct OnboardingFlags {
    #[prost(oneof = "onboarding_flags::AcsLocation", tags = "2, 3")]
    pub acs_location: Option<onboarding_flags::AcsLocation>,
    #[prost(string, tag = "14")]
    pub rcs_profile: String,
    #[prost(string, tag = "15")]
    pub rcs_version: String,
    #[prost(enumeration = "PiiFormat", tag = "17")]
    pub provisioning_imei_format: i32,
    #[prost(enumeration = "PiiFormat", tag = "18")]
    pub provisioning_imsi_format: i32,
    #[prost(int32, tag = "24")]
    pub rcs_enabled_state: i32,
    #[prost(bool, tag = "29")]
    pub skip_header_enrichment: bool,
    #[prost(int32, tag = "33")]
    pub upi_enabled_state: i32,
    #[prost(bool, tag = "44")]
    pub enable_droidguard_with_http_get: bool,
    /// Direct ACS TS43 provisioning; separate from TS43 inside UPI number verification.
    #[prost(bool, tag = "55")]
    pub ts43_supported: bool,
}

pub mod onboarding_flags {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum AcsLocation {
        #[prost(string, tag = "2")]
        Direct(String),
        #[prost(string, tag = "3")]
        MccFormat(String),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum PiiFormat {
    Undefined = 0,
    None = 1,
    Short = 2,
    Full = 3,
    Ignored = 4,
}
