//! One initial ACS challenge request, never an attestation or provisioning attempt.
//! challenge HTTPS_URL TERMINAL_VENDOR MODEL SW_VERSION CLIENT_VENDOR CLIENT_VERSION PROFILE RCS_VERSION [--droidguard]
use rcs_rs::acs::{AcsSession, ClientAuthenticity, ClientParameters, Response};
use std::{env, io};

fn authenticity(args: &[String]) -> Result<Option<ClientAuthenticity>, io::Error> {
    match args.len() {
        8 => Ok(None),
        9 if args[8] == "--droidguard" => Ok(Some(ClientAuthenticity::DroidGuard)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: challenge HTTPS_URL TERMINAL_VENDOR MODEL SW_VERSION CLIENT_VENDOR CLIENT_VERSION PROFILE RCS_VERSION [--droidguard]",
        )),
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    let authenticity = authenticity(&args)?;
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
    let outcome = match session.initial_challenge(&parameters, authenticity).await? {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_explicit_opt_in_to_advertise_droidguard() {
        let mut args = vec!["synthetic".to_owned(); 8];
        assert!(authenticity(&args).unwrap().is_none());
        args.push("--droidguard".into());
        assert!(matches!(
            authenticity(&args).unwrap(),
            Some(ClientAuthenticity::DroidGuard)
        ));
    }

    #[test]
    fn rejects_missing_arguments_or_unknown_flags_before_a_request() {
        for args in [
            vec![],
            vec!["synthetic".to_owned(); 7],
            vec!["synthetic".to_owned(); 9],
        ] {
            assert!(authenticity(&args).is_err());
        }
    }
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
