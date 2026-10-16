//! One explicit GetConsent request: `cargo run --example get_consent -- /private/input.json`.
//! Keep JSON and every referenced file outside the repository, mode 600.
//! Required JSON fields (paths are relative to the JSON file):
//! api_key_file, application_package, certificate_sha1, iid_token_file,
//! checkin_android_id (signed int64), user_serial, public_key_der_file,
//! raw_droidguard_file OR cached_droidguard:{token_file,expires_unix_seconds,expires_nanos?},
//! policy, calling_package, build:{locale,gms_version_code,gms_version_name,
//! android_sdk,model,manufacturer,fingerprint?}.
//! Supply actual values and `constellation_verify` proof bound to `rpc=getConsent`.
//! Consent is not number verification. No Sync request is made.

use rcs_rs::{
    ClientMetadata,
    consent::{self, Attestation, BuildInfo, CachedToken, ConsentRequest},
};
use serde::Deserialize;
use std::{
    env,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    api_key_file: PathBuf,
    application_package: String,
    certificate_sha1: String,
    iid_token_file: PathBuf,
    checkin_android_id: i64,
    user_serial: i64,
    public_key_der_file: PathBuf,
    raw_droidguard_file: Option<PathBuf>,
    cached_droidguard: Option<Cache>,
    policy: String,
    calling_package: String,
    build: Build,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cache {
    token_file: PathBuf,
    expires_unix_seconds: u64,
    #[serde(default)]
    expires_nanos: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Build {
    locale: String,
    gms_version_code: i64,
    gms_version_name: String,
    android_sdk: i32,
    model: String,
    manufacturer: String,
    fingerprint: Option<String>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, io::Error> {
    let file = File::open(path).map_err(|_| invalid("cannot read private input file"))?;
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid("cannot read private input file"))?;
    if bytes.len() > limit {
        return Err(invalid("private input file too large"));
    }
    Ok(bytes)
}

fn read_text(base: &Path, path: &Path, limit: usize) -> Result<String, io::Error> {
    let text = String::from_utf8(read_bounded(&base.join(path), limit)?)
        .map_err(|_| invalid("private input file is not UTF-8"))?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

fn load(path: &Path) -> Result<(ClientMetadata, ConsentRequest), Box<dyn std::error::Error>> {
    let input: Input = serde_json::from_slice(&read_bounded(path, 32 * 1024)?)
        .map_err(|_| invalid("invalid private input JSON"))?;
    let base = path.parent().unwrap_or(Path::new("."));
    let metadata = ClientMetadata::new(
        &read_text(base, &input.api_key_file, 4096)?,
        &input.application_package,
        &input.certificate_sha1,
    )?;
    let attestation = match (input.raw_droidguard_file, input.cached_droidguard) {
        (Some(path), None) => Attestation::RawDroidGuard(read_text(base, &path, 64 * 1024)?),
        (None, Some(cache)) => {
            if cache.expires_nanos >= 1_000_000_000 {
                return Err(invalid("invalid cached token expiry").into());
            }
            let expires = UNIX_EPOCH
                .checked_add(Duration::new(
                    cache.expires_unix_seconds,
                    cache.expires_nanos,
                ))
                .ok_or_else(|| invalid("invalid cached token expiry"))?;
            Attestation::Cached(CachedToken::new(
                read_text(base, &cache.token_file, 64 * 1024)?,
                expires,
            )?)
        }
        _ => return Err(invalid("supply exactly one DroidGuard result or cached token").into()),
    };
    Ok((
        metadata,
        ConsentRequest {
            iid_token: read_text(base, &input.iid_token_file, 4096)?,
            checkin_android_id: input.checkin_android_id,
            user_serial: input.user_serial,
            public_key_der: read_bounded(&base.join(input.public_key_der_file), 4096)?,
            build: BuildInfo {
                locale: input.build.locale,
                gms_version_code: input.build.gms_version_code,
                gms_version_name: input.build.gms_version_name,
                android_sdk: input.build.android_sdk,
                model: input.build.model,
                manufacturer: input.build.manufacturer,
                fingerprint: input.build.fingerprint,
            },
            attestation,
            policy: input.policy,
            calling_package: input.calling_package,
        },
    ))
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    if arguments.len() != 1 {
        return Err(invalid("usage: get_consent /private/input.json").into());
    }
    let (metadata, input) = load(Path::new(&arguments[0]))?;
    let response = consent::get_consent(&metadata, &input).await?;
    println!("RCS consent state: {:?}", response.rcs_state());
    println!(
        "Cached DroidGuard token present: {}",
        response.cached_droidguard.is_some()
    );
    Ok(())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_json_and_unreadable_files_do_not_reflect_private_contents_or_paths() {
        let dir = env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("synthetic-private-path.json");
        std::fs::write(&path, b"{\"synthetic-private-value\":").unwrap();
        assert_eq!(
            load(&path).err().unwrap().to_string(),
            "invalid private input JSON"
        );
        assert_eq!(
            read_bounded(&dir.join("synthetic-private-path"), 10)
                .unwrap_err()
                .to_string(),
            "cannot read private input file"
        );
        std::fs::write(&path, b"01234567890").unwrap();
        assert_eq!(
            read_bounded(&path, 10).unwrap_err().to_string(),
            "private input file too large"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn loads_relative_private_files_and_rejects_ambiguous_proof_sources() {
        let dir = env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir(&dir).unwrap();
        for (name, text) in [
            ("key", "synthetic-key\n"),
            ("iid", "synthetic-iid\n"),
            ("dg", "synthetic-droidguard\n"),
        ] {
            std::fs::write(dir.join(name), text).unwrap();
        }
        std::fs::write(
            dir.join("public.der"),
            include_bytes!("../tests/fixtures/consent-public-key.der"),
        )
        .unwrap();
        let mut json = serde_json::json!({
            "api_key_file":"key", "application_package":"org.example.gms",
            "certificate_sha1":"0123456789abcdef0123456789abcdef01234567",
            "iid_token_file":"iid", "checkin_android_id":-1, "user_serial":0,
            "public_key_der_file":"public.der", "raw_droidguard_file":"dg",
            "policy":"upi-carrier-tos-ts43", "calling_package":"org.example.sms",
            "build":{"locale":"en_US", "gms_version_code":263737035, "gms_version_name":"26.37.37",
                "android_sdk":37, "model":"Generic", "manufacturer":"Example"}
        });
        let path = dir.join("input.json");
        std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        let (metadata, request) = load(&path).unwrap();
        assert_eq!(request.iid_token, "synthetic-iid");
        assert_eq!(request.checkin_android_id, -1);
        assert!(
            matches!(&request.attestation, Attestation::RawDroidGuard(value) if value == "synthetic-droidguard")
        );
        assert!(!format!("{metadata:?} {request:?}").contains("synthetic-"));
        json["cached_droidguard"] =
            serde_json::json!({"token_file":"dg", "expires_unix_seconds":2000000000});
        std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(
            load(&path).err().unwrap().to_string(),
            "supply exactly one DroidGuard result or cached token"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
