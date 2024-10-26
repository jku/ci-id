// TODO
// * blocking?
// * handle errors?
// * less dependencies

use std::{collections::HashMap, env, fmt};
use serde::Deserialize;
use regex::Regex;
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
    for detect in [
        GitHub::detect,
        GitLab::detect
    ] {
        match detect(audience) {
            Ok(token) => return Ok(token),
            Err(CIIDError::EnvironmentNotDetected) => {},
            Err(e) => return Err(e)
        }

    }

    Err(CIIDError::EnvironmentNotDetected)
}

trait CredentialDetector {
    fn detect(audience: Option<&str>) -> Result<String>;
}


// Github implementation

#[derive(Deserialize)]
struct GitHubTokenResponse {
    value: String,
}


struct GitHub;

impl CredentialDetector for GitHub {
    fn detect(audience: Option<&str>) -> Result<String> {
        log::debug!("Probing for GitHub Actions...");

        if let Err(_) = env::var("GITHUB_ACTIONS") {
            log::debug!("GitHub Actions environment not detected");
            return Err(CIIDError::EnvironmentNotDetected);
        };

        let token_token = env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
            .expect("ACTIONS_ID_TOKEN_REQUEST_TOKEN env variable not found: is the id-token workflow permission set?");
        let token_url = env::var("ACTIONS_ID_TOKEN_REQUEST_URL").unwrap();
        let mut params = HashMap::new();
        if let Some(aud) = audience {
            params.insert("audience", aud);
        }

        log::debug!("Requesting token");
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

struct GitLab;

impl CredentialDetector for GitLab {
    fn detect(audience: Option<&str>) -> Result<String> {
        // gitlab tokens can be in any environment variable: we require the variable name to be
        // * "ID_TOKEN" if no audience is argument is used or
        // * "<AUDIENCE>_ID_TOKEN" where <AUDIENCE> is the audience string.

        log::debug!("Probing for GitLab Pipelines...");

        if let Err(_) = env::var("GITLAB_CI") {
            log::debug!("GitLab Pipelines environment not detected");
            return Err(CIIDError::EnvironmentNotDetected);
        };

        let var_name = match audience {
            None => "ID_TOKEN".into(),
            Some(audience) => {
                let upper_audience = audience.to_uppercase();
                let re = Regex::new(r"[^A-Z0-9_]|^[^A-Z_]").unwrap();
                format!("{}_ID_TOKEN", re.replace_all(&upper_audience, "_"))
            }
        };
        log::debug!("Looking for token in {}", var_name);
        match env::var(var_name) {
            Ok(token) => Ok(token),
            Err(_) => Err(CIIDError::EnvironmentError),
        }
    }
}