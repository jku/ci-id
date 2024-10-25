use std::process::exit;

use clap::Parser;
use ci_id::{detect_credentials, CIIDError};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Optional audience name
    audience: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    match detect_credentials(cli.audience.as_deref()) {
        Ok(token) => println!("{}", token),
        Err(CIIDError::EnvironmentNotDetected) => println!("No ambient OIDC tokens found"),
        Err(e) => {
            eprintln!("Error: {}", e);
            exit(1);
        }
    }
}
