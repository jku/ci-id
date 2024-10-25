// TODO
// * blocking?
// * handle errors?
// * less dependencies

use std::{collections::HashMap, env, fmt};
use serde::Deserialize;
pub type Result<T> = std::result::Result<T, CIIDError>;

#[derive(Debug, Clone)]
pub enum CIIDError{
    EnvironmentNotDetected,
    EnvironmentError,
}
impl fmt::Display for CIIDError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "credential detection failed")
    }
}

pub fn detect_credentials(audience: Option<&str>) -> Result<String> {
    // TODO dispatch here
    GitHub::detect(audience)
}

trait CredentialDetector {
    fn detect(audience: Option<&str>) -> Result<String>;
}


// Github implementation

#[derive(Deserialize)]
struct GitHubTokenResponse {
    value: String,
}


struct GitHub{
}

impl CredentialDetector for GitHub {
    
    fn detect(audience: Option<&str>) -> Result<String> {
        if let Err(_) = env::var("GITHUB_ACTIONS") {
            return Err(CIIDError::EnvironmentNotDetected);
        };

        let token_token = env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
            .expect("ACTIONS_ID_TOKEN_REQUEST_TOKEN env variable not found: is the id-token workflow permission set?");
        let token_url = env::var("ACTIONS_ID_TOKEN_REQUEST_URL").unwrap();
        let mut params = HashMap::new();
        if let Some(aud) = audience {
            params.insert("audience", aud);
        }

        let client = reqwest::blocking::Client::new();
        let token_response = client
            .get(token_url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("bearer {}", token_token),
            )
            .query(&params)
            .send()
            .unwrap()
            .json::<GitHubTokenResponse>()
            .unwrap();

        Ok(token_response.value)
    }
}