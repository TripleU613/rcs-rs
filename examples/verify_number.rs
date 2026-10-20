//! Explicit phone verification: `verify_number sync|proceed SESSION_JSON NEW_RESPONSE_PROTO`.
//! SESSION_JSON references identity_file (same format as get_consent), session_id,
//! caller_session_id, caller_certificate_sha1 (oldest caller cert, 40 hex digits),
//! imsi, number?, iccid?, slot_index, subscription_id and telephony:{phone_type,gid1,
//! sim_operator:{country,code,name},network_operator:{country,code,name},roaming,
//! phone_count,max_subscriptions}. Proceed additionally needs pending_response_file,
//! carrier_response_file and optional http_history_file (JSON string array).
//! Paths are relative to SESSION_JSON. Keep all inputs/captures outside the repo.
//! A response file is exclusively reserved before a request, and may be empty on error.
//! session_id is the PDV RPC session; carry caller_session_id into later ACS provisioning.
#[path = "support/pdv_input.rs"]
mod input;
use input::{invalid, read_bounded};
use rcs_rs::verification::{self, InitialSync, OperatorInfo, SyncResponse, TelephonyInfo};
use serde::Deserialize;
use std::{
    env,
    fs::{File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    identity_file: PathBuf,
    session_id: String,
    caller_session_id: String,
    caller_certificate_sha1: String,
    imsi: String,
    number: Option<String>,
    iccid: Option<String>,
    slot_index: i32,
    subscription_id: i32,
    telephony: Telephony,
    pending_response_file: Option<PathBuf>,
    carrier_response_file: Option<PathBuf>,
    http_history_file: Option<PathBuf>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Telephony {
    phone_type: i32,
    gid1: String,
    sim_operator: Operator,
    network_operator: Operator,
    roaming: i32,
    phone_count: i32,
    max_subscriptions: i32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Operator {
    country: String,
    code: String,
    name: String,
}
impl From<Operator> for OperatorInfo {
    fn from(v: Operator) -> Self {
        Self {
            country: v.country,
            code: v.code,
            name: v.name,
        }
    }
}
impl From<Telephony> for TelephonyInfo {
    fn from(v: Telephony) -> Self {
        Self {
            phone_type: v.phone_type,
            gid1: v.gid1,
            sim_operator: v.sim_operator.into(),
            network_operator: v.network_operator.into(),
            roaming: v.roaming,
            phone_count: v.phone_count,
            max_subscriptions: v.max_subscriptions,
        }
    }
}
fn certificate(value: &str) -> Result<[u8; 20], io::Error> {
    if value.len() != 40 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("invalid caller certificate SHA1"));
    }
    let mut digest = [0; 20];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| invalid("invalid caller certificate SHA1"))?;
    }
    Ok(digest)
}
fn output_file(path: &Path) -> Result<File, io::Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|_| invalid("cannot create new private response file"))
}
fn adopt_sync_cache(
    proof: &mut rcs_rs::consent::Attestation,
    cache: Option<rcs_rs::consent::CachedToken>,
) {
    if let Some(cache) = cache.filter(|cache| cache.expires_at() > std::time::SystemTime::now()) {
        *proof = rcs_rs::consent::Attestation::Cached(cache);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err(
            invalid("usage: verify_number sync|proceed SESSION_JSON NEW_RESPONSE_PROTO").into(),
        );
    }
    let mode = args[0]
        .to_str()
        .ok_or_else(|| invalid("invalid verification method"))?;
    if !matches!(mode, "sync" | "proceed") {
        return Err(invalid("invalid verification method").into());
    }
    let path = Path::new(&args[1]);
    let base = path.parent().unwrap_or(Path::new("."));
    let session: Session = serde_json::from_slice(&read_bounded(path, 32 * 1024)?)
        .map_err(|_| invalid("invalid session JSON"))?;
    let (metadata, mut identity) = input::load(&base.join(session.identity_file))?;
    let facts = InitialSync {
        session_id: session.session_id,
        caller_session_id: session.caller_session_id,
        caller_certificate_sha1: certificate(&session.caller_certificate_sha1)?,
        imsi: session.imsi,
        number: session.number,
        iccid: session.iccid,
        slot_index: session.slot_index,
        subscription_id: session.subscription_id,
        telephony: session.telephony.into(),
        mt_sms_token: None,
    };
    let mut output = output_file(Path::new(&args[2]))?;
    if mode == "sync" {
        let response = verification::initial_sync(&metadata, &identity, &facts).await?;
        output
            .write_all(response.raw_protobuf())
            .map_err(|_| invalid("cannot write private response"))?;
        for result in &response.results {
            println!(
                "Verification state: {:?}; reason: {:?}; record code: {:?}; number credential present: {}",
                result.verification.as_ref().and_then(|v| v.state),
                result
                    .verification
                    .as_ref()
                    .and_then(|v| v.unverified_reason),
                result.status.as_ref().and_then(|s| s.code),
                result
                    .verification
                    .as_ref()
                    .is_some_and(|v| v.private_id_token().is_some())
            );
        }
    } else {
        let pending = session
            .pending_response_file
            .ok_or_else(|| invalid("pending response file required"))?;
        let carrier = session
            .carrier_response_file
            .ok_or_else(|| invalid("carrier response file required"))?;
        let mut response =
            SyncResponse::decode(read_bounded(&base.join(pending), 256 * 1024)?.into())?;
        adopt_sync_cache(&mut identity.attestation, response.cached_droidguard.take());
        if response.results.len() != 1 {
            return Err(invalid("expected one pending verification").into());
        }
        let result = &response.results[0];
        if result
            .status
            .as_ref()
            .and_then(|s| s.code)
            .is_some_and(|code| code != 0)
        {
            return Err(invalid("pending response contains service failure").into());
        }
        let pending = result
            .verification
            .as_ref()
            .ok_or_else(|| invalid("pending verification missing"))?;
        let carrier = String::from_utf8(read_bounded(&base.join(carrier), 64 * 1024)?)
            .map_err(|_| invalid("carrier JSON is not UTF8"))?;
        let history: Vec<String> = match session.http_history_file {
            Some(path) => serde_json::from_slice(&read_bounded(&base.join(path), 1024 * 1024)?)
                .map_err(|_| invalid("invalid HTTP history JSON"))?,
            None => vec![],
        };
        let response = verification::proceed_ts43_unsigned(
            &metadata,
            &identity,
            &facts.session_id,
            pending,
            &carrier,
            &history,
        )
        .await?;
        output
            .write_all(response.raw_protobuf())
            .map_err(|_| invalid("cannot write private response"))?;
        println!(
            "Verification state: {:?}; reason: {:?}; number credential present: {}",
            response.verification.as_ref().and_then(|v| v.state),
            response
                .verification
                .as_ref()
                .and_then(|v| v.unverified_reason),
            response
                .verification
                .as_ref()
                .is_some_and(|v| v.private_id_token().is_some())
        );
    }
    output
        .flush()
        .map_err(|_| invalid("cannot flush private response"))?;
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expired_sync_cache_does_not_replace_a_fresh_proof() {
        use rcs_rs::consent::{Attestation, CachedToken};
        use std::time::{Duration, SystemTime};
        let mut proof = Attestation::RawDroidGuard("synthetic-fresh-proof".into());
        adopt_sync_cache(
            &mut proof,
            Some(
                CachedToken::new(
                    "synthetic-old-cache".into(),
                    SystemTime::now() - Duration::from_secs(60),
                )
                .unwrap(),
            ),
        );
        assert!(matches!(&proof, Attestation::RawDroidGuard(v) if v == "synthetic-fresh-proof"));
        adopt_sync_cache(
            &mut proof,
            Some(
                CachedToken::new(
                    "synthetic-valid-cache".into(),
                    SystemTime::now() + Duration::from_secs(3600),
                )
                .unwrap(),
            ),
        );
        assert!(matches!(&proof, Attestation::Cached(v) if v.value() == "synthetic-valid-cache"));
    }
    #[cfg(unix)]
    #[test]
    fn response_files_are_private_and_existing_captures_are_never_replaced() {
        use std::os::unix::fs::PermissionsExt;
        let dir = env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("capture.bin");
        let mut file = output_file(&path).unwrap();
        file.write_all(b"synthetic-private-capture").unwrap();
        drop(file);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(output_file(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"synthetic-private-capture");
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn certificate_rejects_malformed_input_without_echoing_it() {
        assert_eq!(
            certificate("synthetic-private-invalid")
                .unwrap_err()
                .to_string(),
            "invalid caller certificate SHA1"
        );
        assert_eq!(
            certificate("0101010101010101010101010101010101010101").unwrap(),
            [1; 20]
        );
    }
}
