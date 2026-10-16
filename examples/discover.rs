//! One explicit live request:
//! cargo run --example discover -- MCC MNC DEVICE MANUFACTURER PACKAGE_VERSION [GMS_VERSION]
//! Credentials: RCS_APP_PACKAGE, RCS_APP_CERT_SHA1, and RCS_API_KEY_FILE or RCS_API_KEY.
//! Optional RCS_GSF_ANDROID_ID: actual client-context GServices ID, signed decimal.
//! Keep application keys outside the repository. No subscriber identifiers are accepted.

use rcs_rs::{Carrier, ClientMetadata, Probe, wire::onboarding_flags::AcsLocation};
use std::{env, io};

fn safe_host(location: &Option<AcsLocation>) -> Option<String> {
    let Some(AcsLocation::Direct(value)) = location else {
        return None;
    };
    let value = if value.contains("://") {
        value.clone()
    } else {
        format!("https://{value}")
    };
    let uri: http::Uri = value.parse().ok()?;
    if !matches!(uri.scheme_str(), Some("https" | "http")) {
        return None;
    }
    let authority = uri.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    Some(authority.host().to_owned())
}

fn required_env(name: &str) -> Result<String, io::Error> {
    env::var(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("missing {name}")))
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    if !(5..=6).contains(&args.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: discover MCC MNC DEVICE MANUFACTURER PACKAGE_VERSION [GMS_VERSION]",
        )
        .into());
    }
    let key = if let Ok(path) = env::var("RCS_API_KEY_FILE") {
        std::fs::read_to_string(path)?
            .trim_end_matches(['\r', '\n'])
            .to_owned()
    } else {
        required_env("RCS_API_KEY")?
    };
    let metadata = ClientMetadata::new(
        &key,
        &required_env("RCS_APP_PACKAGE")?,
        &required_env("RCS_APP_CERT_SHA1")?,
    )?;
    let version = args[4]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid package version"))?;
    let mut probe = Probe::new(
        Carrier::new(&args[0], &args[1])?,
        &args[2],
        &args[3],
        version,
    )?;
    if let Some(value) = args.get(5) {
        let version = value
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid GMS version"))?;
        probe = probe.with_gms_version(version)?;
    }
    if let Some(value) = env::var_os("RCS_GSF_ANDROID_ID") {
        let id = value
            .to_str()
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid GServices ID"))?;
        probe = probe.with_gsf_android_id(id);
    }
    let discovery = rcs_rs::discover(&metadata, &probe).await?;
    println!("RCS enabled state: {}", discovery.flags.rcs_enabled_state);
    println!(
        "ACS host: {}",
        safe_host(&discovery.flags.acs_location)
            .as_deref()
            .unwrap_or("not a direct host")
    );
    println!(
        "Skip header enrichment: {}",
        discovery.flags.skip_header_enrichment
    );
    println!(
        "DroidGuard HTTP challenge: {}",
        discovery.flags.enable_droidguard_with_http_get
    );
    println!("UPI state: {}", discovery.flags.upi_enabled_state);
    println!(
        "Direct TS43 provisioning: {}",
        discovery.flags.ts43_supported
    );
    println!(
        "IMEI format: {:?}; IMSI format: {:?}",
        rcs_rs::wire::PiiFormat::try_from(discovery.flags.provisioning_imei_format),
        rcs_rs::wire::PiiFormat::try_from(discovery.flags.provisioning_imsi_format)
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
    fn prints_host_without_acs_paths_credentials_or_query_tokens() {
        for value in [
            "rcs.example.test",
            "https://rcs.example.test/path?token=synthetic-secret",
        ] {
            assert_eq!(
                safe_host(&Some(AcsLocation::Direct(value.into()))),
                Some("rcs.example.test".into())
            );
        }
        assert_eq!(
            safe_host(&Some(AcsLocation::MccFormat("synthetic-secret".into()))),
            None
        );
        assert_eq!(
            safe_host(&Some(AcsLocation::Direct(
                "rcs.example.test\nsynthetic-secret".into()
            ))),
            None
        );
    }
}
