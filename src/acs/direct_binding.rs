//! Direct-TS43 version-two proof binding; no VM, HTTP or attestation verification.
use super::Error;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use prost::Message;
use std::{collections::BTreeMap, fmt};

/// Exact values used by the matching direct-TS43 GET/POST, never another app's identity.
pub struct DirectBindingParameters<'a> {
    /// Actual Android Context package of the app that will run the VM.
    pub application_package: &'a str,
    /// Same own logical session UUID as the request's rcs_engine_session_id header.
    pub caller_session_id: &'a str,
    /// Selected subscription's configured request values; empty means unavailable/omitted.
    pub imsi: &'a str,
    pub imei: &'a str,
    /// Value of the same GET's unambiguous JIBE_ACS_COOKIE, without its name.
    pub cookie_value: &'a str,
    /// Genuine selected-SIM carrier credential, also sent as the as_temp_token part.
    pub carrier_temporary_token: &'a str,
    /// Same GET's goog-droidguard challenge parameter, distinct from the MLS nonce.
    pub challenge: &'a str,
}

/// Keeps a fresh binding salt associated with its map and proof wrapper.
/// This direct V2 route is distinct from UPI V1; neither proof provenance nor admission is verified here.
pub struct DirectBindingV2<'a> {
    parameters: DirectBindingParameters<'a>,
    salt: String,
}

impl fmt::Debug for DirectBindingParameters<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirectBindingParameters([REDACTED])")
    }
}
impl fmt::Debug for DirectBindingV2<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirectBindingV2([REDACTED])")
    }
}

impl<'a> DirectBindingV2<'a> {
    /// Prepare one own-client binding. This does not contact a service or generate attestation.
    pub fn new(parameters: DirectBindingParameters<'a>) -> Result<Self, Error> {
        Self::with_salt(parameters, uuid::Uuid::new_v4().to_string())
    }
    fn with_salt(parameters: DirectBindingParameters<'a>, salt: String) -> Result<Self, Error> {
        let p = &parameters;
        if p.application_package.is_empty()
            || p.application_package.len() > 256
            || !p
                .application_package
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
            || uuid::Uuid::parse_str(p.caller_session_id).is_err()
            || salt.len() != 36
            || uuid::Uuid::parse_str(&salt).is_err()
        {
            return Err(Error::InvalidInput(
                "direct binding application/session/salt",
            ));
        }
        for (value, min, max) in [(p.imsi, 5, 15), (p.imei, 14, 16)] {
            if !value.is_empty()
                && (!(min..=max).contains(&value.len())
                    || !value.bytes().all(|b| b.is_ascii_digit()))
            {
                return Err(Error::InvalidInput("direct binding identifiers"));
            }
        }
        for value in [p.cookie_value, p.carrier_temporary_token, p.challenge] {
            if value.is_empty() || value.len() > 16 * 1024 || value.chars().any(char::is_control) {
                return Err(Error::InvalidInput("direct binding credential/challenge"));
            }
        }
        Ok(Self { parameters, salt })
    }
    /// Private map for one genuine rcs_provisioning ss(Map) call in the own Android Context.
    /// Hashes still correlate sensitive inputs; do not log or reuse them across sessions.
    pub fn private_droidguard_inputs(&self) -> BTreeMap<String, String> {
        let p = &self.parameters;
        let mut inputs = BTreeMap::from([
            ("APP_NAME".into(), hash(p.application_package, &self.salt)),
            (
                "PROVISIONING_SESSION_ID".into(),
                hash(p.caller_session_id, &self.salt),
            ),
            ("DROIDGUARD_SALT".into(), hash(&self.salt, "")),
            (
                "DROIDGUARD_CONTENT_BINDING_VERSION".into(),
                hash("2", &self.salt),
            ),
        ]);
        for (name, value) in [
            ("IMSI", p.imsi),
            ("IMEI", p.imei),
            ("JIBE_ACS_COOKIE", p.cookie_value),
            ("SIM_AUTH_TEMP_TOKEN", p.carrier_temporary_token),
            ("DROIDGUARD_CHALLENGE", p.challenge),
        ] {
            if !value.is_empty() {
                inputs.insert(name.into(), hash(value, &self.salt));
            }
        }
        inputs
    }
    /// Encode raw bytes returned by that same VM/map as the multipart authenticity value.
    /// The caller supplies the same method ID in the part name and preserves GET cookies/session.
    /// Snapshots are bounded at 64 KiB; this is a host limit, not a recovered server limit.
    /// A nonempty opaque result does not establish a valid or accepted attestation.
    pub fn private_authenticity_result(&self, raw_snapshot: &[u8]) -> Result<String, Error> {
        if raw_snapshot.is_empty()
            || raw_snapshot.len() > 64 * 1024
            || raw_snapshot.starts_with(b"ERROR : ")
        {
            return Err(Error::InvalidInput("direct DroidGuard snapshot"));
        }
        let proof = ProofV2 {
            version: 2,
            snapshot: URL_SAFE_NO_PAD.encode(raw_snapshot),
            salt: self.salt.clone(),
        };
        Ok(STANDARD.encode(proof.encode_to_vec()))
    }
}

fn hash(value: &str, salt: &str) -> String {
    let mut digest = ring::digest::Context::new(&ring::digest::SHA384);
    digest.update(value.as_bytes());
    digest.update(salt.as_bytes());
    digest
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
struct ProofV2 {
    #[prost(int32, tag = "1")]
    version: i32,
    #[prost(string, tag = "2")]
    snapshot: String,
    #[prost(string, tag = "3")]
    salt: String,
}

#[cfg(test)]
mod tests;
