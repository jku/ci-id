use ci_id::{detect_credentials, CIIDError};
use clap::Parser;
use std::process::exit;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Optional audience name
    audience: Option<String>,
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match detect_credentials(cli.audience.as_deref()) {
        Ok(token) => print!("{}", token),
        Err(CIIDError::EnvironmentNotDetected) => println!("No ambient OIDC tokens found"),
        Err(e) => {
            eprintln!("Error: {}", e);
            exit(1);
        }
    }
}
