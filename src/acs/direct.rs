//! Recovered direct TS43 exchange. The host supplies its own carrier, VM and MLS proofs.
use super::upi::header;
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::collections::BTreeMap;

/// Actual selected configuration and already formatted own-client metadata.
/// This bounded route excludes optional instance_id_token/provision_id branches.
pub struct DirectParameters<'a> {
    pub client: ClientParameters<'a>,
    pub application_package: &'a str,
    pub caller_session_id: &'a str,
    pub imsi: &'a str,
    pub imei: &'a str,
    pub gid1: &'a str,
    pub configuration_version: i32,
    pub rcs_state: i32,
    pub sms_port: u16,
    pub device_type: &'a str,
    pub user_agent: &'a str,
    pub language: &'a str,
    pub client_channel: &'a str,
}
pub enum DirectStart<'a> {
    Challenge(DirectChallenge<'a>),
    /// Opaque configuration, including possible disabled/invalid configuration; never ready.
    WapConfiguration(Bytes),
}
pub struct DirectChallenge<'a> {
    _exchange: ExchangeLease<'a>,
    session: &'a AcsSession,
    parameters: &'a DirectParameters<'a>,
    challenge: Challenge,
    cookie: String,
    cookie_header: http::HeaderValue,
}
pub struct DirectBoundChallenge<'a> {
    context: DirectChallenge<'a>,
    token: String,
    salt: String,
}
macro_rules! redacted { ($($name:ty),*) => { $(impl fmt::Debug for $name {
    fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.write_str(concat!(stringify!($name),"([REDACTED])"))}
})* }; }
redacted!(
    DirectParameters<'_>,
    DirectStart<'_>,
    DirectChallenge<'_>,
    DirectBoundChallenge<'_>
);

impl AcsSession {
    fn direct_request(
        &self,
        p: &DirectParameters<'_>,
        initial: bool,
    ) -> Result<reqwest::Request, Error> {
        direct_binding::validate_identity(
            p.application_package,
            p.caller_session_id,
            p.imsi,
            p.imei,
        )?;
        for (value, cap) in [
            (p.client.terminal_vendor, 4),
            (p.client.terminal_sw_version, 10),
            (p.client.client_vendor, 4),
            (p.client.client_version, 15),
            (p.client.rcs_profile, 15),
            (p.client.rcs_version, 4),
        ] {
            if value.encode_utf16().count() > cap {
                return Err(Error::InvalidInput("direct formatted metadata"));
            }
        }
        if p.gid1.len() > 128
            || p.gid1.chars().any(char::is_control)
            || p.device_type.len() > 256
            || p.device_type.chars().any(char::is_control)
        {
            return Err(Error::InvalidInput("direct GID1/device type"));
        }
        let mut request =
            self.initial_request(&p.client, initial.then_some(ClientAuthenticity::DroidGuard))?;
        let pairs: Vec<(String, String)> = request
            .url()
            .query_pairs()
            .filter(|(k, _)| {
                !matches!(
                    k.as_ref(),
                    "vers" | "rcs_state" | "SMS_port" | "device_type"
                )
            })
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        request.url_mut().set_query(None);
        request
            .url_mut()
            .query_pairs_mut()
            .extend_pairs(pairs)
            .append_pair("vers", &p.configuration_version.max(0).to_string())
            .append_pair("rcs_state", &p.rcs_state.to_string())
            .append_pair("SMS_port", &p.sms_port.to_string());
        for (name, value) in [
            ("IMSI", p.imsi),
            ("IMEI", p.imei),
            ("GID1", p.gid1),
            ("device_type", p.device_type),
        ] {
            if !value.is_empty() {
                request.url_mut().query_pairs_mut().append_pair(name, value);
            }
        }
        for (name, value) in [
            ("rcs_engine_session_id", p.caller_session_id),
            ("user-agent", p.user_agent),
            ("accept-language", p.language),
            ("client_channel", p.client_channel),
            ("rcs-pe-version", "3"),
            ("rcs-pe-location", "3"),
        ] {
            if value.len() > 512 {
                return Err(Error::InvalidInput("direct request header"));
            }
            request
                .headers_mut()
                .insert(name, header(value, "direct request header")?);
        }
        Ok(request)
    }
    /// One GET to the configured HTTPS path, requiring no applicable pre-existing cookies.
    /// Use a fresh HTTP session for a newly authorized exchange; never revive an old cookie.
    /// A challenge excludes other exchanges until dropped.
    /// WAP bytes remain opaque; the caller must validate configuration, not infer readiness.
    pub async fn direct_challenge<'a>(
        &'a self,
        p: &'a DirectParameters<'a>,
    ) -> Result<DirectStart<'a>, Error> {
        let exchange = self.begin_exchange()?;
        self.require_fresh_cookies(&self.endpoint)?;
        let (media, body) = self.response_body(self.direct_request(p, true)?).await?;
        match parse_response(&media, &body)? {
            Response::WapConfiguration(bytes) => Ok(DirectStart::WapConfiguration(bytes)),
            Response::Challenge(mut challenge) => {
                challenge.nonce = challenge.nonce.trim_matches(|c| c <= '\u{20}').to_owned();
                validate_challenge(&challenge)?;
                let (cookie, cookie_header) = self.cookie_for(&self.endpoint)?;
                Ok(DirectStart::Challenge(DirectChallenge {
                    _exchange: exchange,
                    session: self,
                    parameters: p,
                    challenge,
                    cookie,
                    cookie_header,
                }))
            }
        }
    }
}
impl<'a> DirectChallenge<'a> {
    /// Attach the genuine selected-subscription credential after carrier authentication.
    /// Consumes the GET context; never creates or verifies a carrier credential itself.
    pub fn bind_carrier(self, token: &str) -> Result<DirectBoundChallenge<'a>, Error> {
        validate_challenge(&self.challenge)?;
        let bound = DirectBoundChallenge {
            context: self,
            token: token.into(),
            salt: uuid::Uuid::new_v4().to_string(),
        };
        bound.binding()?;
        Ok(bound)
    }
}
impl DirectBoundChallenge<'_> {
    fn binding(&self) -> Result<DirectBindingV2<'_>, Error> {
        let p = self.context.parameters;
        DirectBindingV2::with_salt(
            DirectBindingParameters {
                application_package: p.application_package,
                caller_session_id: p.caller_session_id,
                imsi: p.imsi,
                imei: p.imei,
                cookie_value: &self.context.cookie,
                carrier_temporary_token: &self.token,
                challenge: &self.context.challenge.challenge,
            },
            self.salt.clone(),
        )
    }
    /// Private inputs for a genuine VM call in this app's actual Android Context; never log.
    pub fn private_droidguard_inputs(&self) -> Result<BTreeMap<String, String>, Error> {
        Ok(self.binding()?.private_droidguard_inputs())
    }
    /// Java-style trimmed nonce for an own Android signer; distinct from the DG challenge.
    pub fn private_mls_nonce(&self) -> &str {
        &self.context.challenge.nonce
    }
    /// RFC9420 SignWithLabel bytes for the host's own P-256/SHA256 signer.
    pub fn private_mls_signing_input(&self) -> Vec<u8> {
        mls_signing_input(self.private_mls_nonce())
    }
    fn make_request(&self, raw: &[u8], proof: &MlsProof<'_>) -> Result<reqwest::Request, Error> {
        let c = &self.context;
        let (cookie, cookie_header) = c.session.cookie_for(&c.session.endpoint)?;
        if cookie != c.cookie || cookie_header != c.cookie_header {
            return Err(Error::InvalidInput(
                "direct cookie changed; new attestation required",
            ));
        }
        proof.verify_nonce(self.private_mls_nonce())?;
        let authenticity = self.binding()?.private_authenticity_result(raw)?;
        let mut request = c.session.direct_request(c.parameters, false)?;
        *request.method_mut() = reqwest::Method::POST;
        request
            .url_mut()
            .query_pairs_mut()
            .append_pair(
                "participant_public_key",
                &URL_SAFE_NO_PAD.encode(proof.public_key_der),
            )
            .append_pair(
                "participant_key_signed_nonce",
                &URL_SAFE_NO_PAD.encode(proof.signature_der),
            )
            .append_pair("home_kds", &proof.home_kds.to_string());
        let boundary = format!("==={}", uuid::Uuid::new_v4());
        if self.token.contains(&boundary) || authenticity.contains(&boundary) {
            return Err(Error::InvalidInput("direct multipart boundary collision"));
        }
        let mut body = String::new();
        for (name, value) in [
            ("as_temp_token".to_owned(), self.token.as_str()),
            (
                format!("client_authenticity_result_{}", c.challenge.method_id),
                authenticity.as_str(),
            ),
        ] {
            body.push_str(&format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{value}\r\n"));
        }
        body.push_str(&format!("--{boundary}--\r\n"));
        request.headers_mut().insert(
            "content-type",
            header(
                &format!("multipart/form-data; boundary=\"{boundary}\""),
                "direct multipart type",
            )?,
        );
        request
            .headers_mut()
            .insert("cookie", c.cookie_header.clone());
        *request.body_mut() = Some(body.into());
        Ok(request)
    }
    /// Consume this context for at most one POST. No VM or attestation provenance is inferred
    /// from supplied bytes. MLS possession is checked locally; returned WAP is still unvalidated.
    /// The host must preserve subscription binding and request journals; no automatic retry occurs.
    pub async fn provision(self, raw: &[u8], proof: &MlsProof<'_>) -> Result<Response, Error> {
        let request = self.make_request(raw, proof)?;
        let (media, body) = self.context.session.response_body(request).await?;
        parse_response(&media, &body)
    }
}

fn validate_challenge(c: &Challenge) -> Result<(), Error> {
    // Host bounds and safe quoted multipart names, not a recovered server ID grammar.
    if c.method_id.len() > 256
        || c.method_id.is_empty()
        || !c
            .method_id
            .bytes()
            .all(|b| (32..=126).contains(&b) && b != b'"' && b != b'\\')
        || c.challenge.is_empty()
        || c.challenge.len() > 16 * 1024
        || c.challenge.chars().any(char::is_control)
        || c.nonce.is_empty()
        || c.nonce.len() > 16 * 1024
        || c.nonce.chars().any(char::is_control)
    {
        return Err(Error::InvalidChallenge("direct method/challenge/nonce"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
