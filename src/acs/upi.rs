//! Recovered version-one UPI provisioning path. Caller supplies genuine platform proof.
use super::*;
use base64::Engine;
use std::collections::BTreeMap;

pub struct UpiParameters<'a> {
    /// Prepared carrier/client metadata; apply the selected configuration's formatting first.
    pub client: ClientParameters<'a>,
    pub application_package: &'a str,
    pub caller_session_id: &'a str,
    pub imsi: &'a str,
    pub imei: &'a str,
    pub gid1: &'a str,
    pub number_credential: &'a str,
    pub gmscore_iid_token: Option<&'a str>,
    /// Actual subscription eligibility: unspecified=0, eligible=1, ineligible=2, denied=3.
    pub eligibility: i32,
    pub policy: &'a str,
    pub user_agent: &'a str,
    pub language: &'a str,
    pub client_channel: &'a str,
}
pub struct MlsProof<'a> {
    pub public_key_der: &'a [u8],
    pub signature_der: &'a [u8],
    /// Explicit routing configuration. Reference build 324451063 defaults to 2;
    /// this is not an enrollment result or a universal server assignment.
    pub home_kds: u32,
}
pub struct UpiChallenge<'a> {
    _exchange: ExchangeLease<'a>,
    session: &'a AcsSession,
    parameters: &'a UpiParameters<'a>,
    nonce: String,
    cookie: String,
    salt: String,
}
macro_rules! redacted { ($($name:ty),*) => { $(impl fmt::Debug for $name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(concat!(stringify!($name), "([REDACTED])")) }
})* }; }
redacted!(UpiParameters<'_>, MlsProof<'_>, UpiChallenge<'_>);

pub(super) fn header(value: &str, name: &'static str) -> Result<http::HeaderValue, Error> {
    if value.is_empty()
        || value.len() > 64 * 1024
        || !value.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
    {
        return Err(Error::InvalidInput(name));
    }
    let mut value = http::HeaderValue::from_str(value).map_err(|_| Error::InvalidInput(name))?;
    value.set_sensitive(true);
    Ok(value)
}
impl UpiParameters<'_> {
    fn validate(&self) -> Result<(), Error> {
        if !(5..=15).contains(&self.imsi.len())
            || !self.imsi.bytes().all(|b| b.is_ascii_digit())
            || !(14..=16).contains(&self.imei.len())
            || !self.imei.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::InvalidInput("UPI SIM/device identifiers"));
        }
        if uuid::Uuid::parse_str(self.caller_session_id).is_err()
            || !(0..=3).contains(&self.eligibility)
        {
            return Err(Error::InvalidInput("UPI session or eligibility"));
        }
        if self.application_package.is_empty()
            || self.application_package.len() > 256
            || !self
                .application_package
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
            || self.gid1.len() > 128
            || self.gid1.chars().any(char::is_control)
        {
            return Err(Error::InvalidInput("UPI application or GID1"));
        }
        if self.number_credential.len() > 16 * 1024
            || !self.number_credential.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(Error::InvalidInput("UPI number credential"));
        }
        header(self.number_credential, "UPI number credential")?;
        for (name, value) in [
            ("UPI policy", self.policy),
            ("UPI user agent", self.user_agent),
            ("UPI language", self.language),
            ("UPI client channel", self.client_channel),
        ] {
            if value.len() > 512 {
                return Err(Error::InvalidInput(name));
            }
            header(value, name)?;
        }
        if let Some(iid) = self.gmscore_iid_token {
            header(iid, "UPI GMS IID")?;
        }
        Ok(())
    }
}
impl AcsSession {
    fn upi_request(&self, p: &UpiParameters<'_>) -> Result<reqwest::Request, Error> {
        p.validate()?;
        let mut request = self.initial_request(&p.client, None)?;
        let pairs: Vec<(String, String)> = request
            .url()
            .query_pairs()
            .filter(|(k, _)| {
                !matches!(
                    k.as_ref(),
                    "token" | "SMS_port" | "client_authenticity_support"
                )
            })
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        request.url_mut().set_query(None);
        request
            .url_mut()
            .query_pairs_mut()
            .extend_pairs(pairs)
            .append_pair("client_authenticity_support", "goog-mls-upi")
            .append_pair("IMSI", p.imsi)
            .append_pair("IMEI", p.imei);
        if !p.gid1.is_empty() {
            request
                .url_mut()
                .query_pairs_mut()
                .append_pair("GID1", p.gid1);
        }
        for (name, value) in [
            ("rcs_engine_session_id", p.caller_session_id),
            ("supported_provisioning_types", p.policy),
            ("user-agent", p.user_agent),
            ("accept-language", p.language),
            ("client_channel", p.client_channel),
            ("rcs-pe-version", "3"),
            ("rcs-pe-location", "3"),
        ] {
            request
                .headers_mut()
                .insert(name, header(value, "UPI request header")?);
        }
        if let Some(iid) = p.gmscore_iid_token {
            request
                .headers_mut()
                .insert("gmscore_instance_id_token", header(iid, "UPI GMS IID")?);
        }
        Ok(request)
    }
    fn upi_cookie(&self) -> Result<(String, http::HeaderValue), Error> {
        let mut url = self.endpoint.clone();
        url.set_path("/provision");
        self.cookie_for(&url)
    }
    /// Obtain a nonce/cookie for the recovered UPI route, after number verification.
    /// Caller supplies actual configured metadata, subscription eligibility and credential.
    /// Requires a fresh cookie jar for both the GET path and /provision.
    /// No automatic retries. The returned context borrows the identity/session inputs.
    pub async fn upi_challenge<'a>(
        &'a self,
        p: &'a UpiParameters<'a>,
    ) -> Result<UpiChallenge<'a>, Error> {
        let exchange = self.begin_exchange()?;
        let mut proof_url = self.endpoint.clone();
        proof_url.set_path("/provision");
        self.require_fresh_cookies(&proof_url)?;
        let (media, body) = self.response_body(self.upi_request(p)?).await?;
        let Response::Challenge(challenge) =
            parse_response_for_method(&media, &body, "goog-mls-upi")?
        else {
            return Err(Error::InvalidChallenge("UPI nonce challenge required"));
        };
        Ok(UpiChallenge {
            _exchange: exchange,
            session: self,
            parameters: p,
            nonce: challenge.nonce,
            cookie: self.upi_cookie()?.0,
            salt: uuid::Uuid::new_v4().to_string(),
        })
    }
}
impl UpiChallenge<'_> {
    /// Private input map for a genuine platform `rcs_provisioning` DroidGuard call.
    /// APP_NAME must describe the actual client; admission of arbitrary clients is unproven.
    pub fn private_droidguard_inputs(&self) -> BTreeMap<String, String> {
        let p = self.parameters;
        let mut inputs = BTreeMap::from([("APP_NAME".into(), p.application_package.into())]);
        for (name, value) in [
            ("IMSI", p.imsi),
            ("IMEI", p.imei),
            ("MSISDN_TOKEN", p.number_credential),
            ("JIBE_ACS_COOKIE", &self.cookie),
            ("GMSCORE_IID_TOKEN", p.gmscore_iid_token.unwrap_or("")),
            ("PROVISIONING_SESSION_ID", p.caller_session_id),
        ] {
            if !value.is_empty() {
                let digest = ring::digest::digest(
                    &ring::digest::SHA384,
                    format!("{value}{}", self.salt).as_bytes(),
                );
                let hash: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
                inputs.insert(name.into(), hash);
            }
        }
        inputs
    }
    /// MLS SignWithLabel bytes for an owned participant key. Sign using P-256/SHA-256,
    /// returning a DER ECDSA signature and the matching SPKI DER public key.
    pub fn private_mls_signing_input(&self) -> Vec<u8> {
        mls_signing_input(&self.nonce)
    }
    fn body(&self, dg: &str) -> Result<String, Error> {
        use prost::Message;
        if dg.is_empty() || dg.len() > 64 * 1024 || !dg.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Error::InvalidInput("UPI DroidGuard result"));
        }
        let p = self.parameters;
        let body = UpiEnvelope {
            eligibility: Some(p.eligibility),
            proof: Some(UpiProof {
                version: Some(1),
                droidguard: Some(dg.into()),
                salt: Some(self.salt.clone()),
                imsi: Some(p.imsi.into()),
                imei: Some(p.imei.into()),
                msisdn: None,
                credential: Some(p.number_credential.into()),
                cookie: Some(self.cookie.clone()),
                iid: p.gmscore_iid_token.map(String::from),
                session: Some(p.caller_session_id.into()),
            }),
        };
        if body.encoded_len() > 128 * 1024 {
            return Err(Error::InvalidInput("UPI request size"));
        }
        Ok(base64::engine::general_purpose::STANDARD.encode(body.encode_to_vec()))
    }
    fn make_request(&self, dg: &str, proof: &MlsProof<'_>) -> Result<reqwest::Request, Error> {
        let (cookie, cookie_header) = self.session.upi_cookie()?;
        if cookie != self.cookie {
            return Err(Error::InvalidInput(
                "UPI cookie changed; new attestation required",
            ));
        }
        proof.verify_nonce(&self.nonce)?;
        let body = self.body(dg)?;
        let mut request = self.session.upi_request(self.parameters)?;
        *request.method_mut() = reqwest::Method::POST;
        request.url_mut().set_path("/provision");
        let pairs: Vec<(String, String)> = request
            .url()
            .query_pairs()
            .filter(|(k, _)| k != "client_authenticity_support")
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        request.url_mut().set_query(None);
        request
            .url_mut()
            .query_pairs_mut()
            .extend_pairs(pairs)
            .append_pair(
                "participant_public_key",
                &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(proof.public_key_der),
            )
            .append_pair(
                "participant_key_signed_nonce",
                &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(proof.signature_der),
            )
            .append_pair("home_kds", &proof.home_kds.to_string());
        request
            .headers_mut()
            .insert("content-type", http::HeaderValue::from_static("text/plain"));
        // Freeze the cookie used by the proof; a concurrent challenge must not replace it.
        request.headers_mut().insert("cookie", cookie_header);
        request.headers_mut().insert(
            "rcs_msisdn_token",
            header(self.parameters.number_credential, "UPI number credential")?,
        );
        *request.body_mut() = Some(body.into());
        Ok(request)
    }
    /// Consume this challenge and send one credential-bearing request to the same HTTPS origin.
    /// The genuine DroidGuard result must use this context's private input map.
    /// Signature possession is checked locally; this does not validate DG provenance or the number JWT.
    /// Returned WAP bytes still require configuration validation, then registration.
    pub async fn provision(
        self,
        droidguard_result: &str,
        proof: &MlsProof<'_>,
    ) -> Result<Response, Error> {
        let request = self.make_request(droidguard_result, proof)?;
        let (media, body) = self.session.response_body(request).await?;
        parse_response(&media, &body)
    }
}

impl MlsProof<'_> {
    pub(super) fn verify_nonce(&self, nonce: &str) -> Result<(), Error> {
        verify_mls_participant_proof(nonce, self.public_key_der, self.signature_der)
    }
}

/// Verify an RFC9420 ACS participant proof independently of HTTP or routing configuration.
/// Uses the exact UTF-8 nonce without trimming; accepts 1..=65536 bytes. The public
/// key is P-256 SPKI DER and the signature is SHA-256/ECDSA DER. This checks key
/// possession only, not identity, enrollment, attestation provenance or admission.
pub fn verify_mls_participant_proof(
    nonce: &str,
    public_key_der: &[u8],
    signature_der: &[u8],
) -> Result<(), Error> {
    if nonce.is_empty()
        || nonce.len() > MAX_BODY
        || signature_der.is_empty()
        || signature_der.len() > 128
    {
        return Err(Error::InvalidInput("participant proof size"));
    }
    // shortcut: observed P-256 proof only; add other suites when their negotiated format is established.
    const PREFIX: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    let key = public_key_der
        .strip_prefix(PREFIX)
        .filter(|k| k.len() == 65)
        .ok_or(Error::InvalidInput("participant P-256 public key"))?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, key)
        .verify(&mls_signing_input(nonce), signature_der)
        .map_err(|_| Error::InvalidInput("participant signature does not match nonce"))
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
struct UpiEnvelope {
    #[prost(int32, optional, tag = "1")]
    eligibility: Option<i32>,
    #[prost(message, optional, tag = "2")]
    proof: Option<UpiProof>,
}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
struct UpiProof {
    #[prost(int32, optional, tag = "1")]
    version: Option<i32>,
    #[prost(string, optional, tag = "2")]
    droidguard: Option<String>,
    #[prost(string, optional, tag = "3")]
    salt: Option<String>,
    #[prost(string, optional, tag = "4")]
    imsi: Option<String>,
    #[prost(string, optional, tag = "5")]
    imei: Option<String>,
    #[prost(string, optional, tag = "6")]
    msisdn: Option<String>,
    #[prost(string, optional, tag = "7")]
    credential: Option<String>,
    #[prost(string, optional, tag = "8")]
    cookie: Option<String>,
    #[prost(string, optional, tag = "9")]
    iid: Option<String>,
    #[prost(string, optional, tag = "10")]
    session: Option<String>,
}
redacted!(UpiEnvelope, UpiProof);
#[cfg(test)]
mod tests;
