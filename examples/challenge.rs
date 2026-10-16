//! One initial ACS challenge request, never an attestation or provisioning attempt.
//! challenge HTTPS_URL TERMINAL_VENDOR MODEL SW_VERSION CLIENT_VENDOR CLIENT_VERSION PROFILE RCS_VERSION
use rcs_rs::acs::{AcsSession, ClientParameters, Response};
use std::{env, io};

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
            "usage: challenge HTTPS_URL TERMINAL_VENDOR MODEL SW_VERSION CLIENT_VENDOR CLIENT_VERSION PROFILE RCS_VERSION").into());
    }
    let session = AcsSession::new(&args[0])?;
    let parameters = ClientParameters {
        terminal_vendor: &args[1],
        terminal_model: &args[2],
        terminal_sw_version: &args[3],
        client_vendor: &args[4],
        client_version: &args[5],
        rcs_profile: &args[6],
        rcs_version: &args[7],
    };
    let outcome = match session.initial_challenge(&parameters).await? {
        Response::Challenge(_) => "client-authenticity challenge",
        Response::WapConfiguration(_) => "opaque WAP configuration (unvalidated)",
    };
    println!("ACS host: {}", session.host());
    println!(
        "Outcome: {outcome}; session cookie retained: {}",
        session.has_session_cookie()
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
