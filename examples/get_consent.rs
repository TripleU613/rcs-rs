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

#[path = "support/pdv_input.rs"]
mod input;
use input::{invalid, load};
use std::{env, path::Path};

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    if arguments.len() != 1 {
        return Err(invalid("usage: get_consent /private/input.json").into());
    }
    let (metadata, input) = load(Path::new(&arguments[0]))?;
    let response = rcs_rs::consent::get_consent(&metadata, &input).await?;
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
