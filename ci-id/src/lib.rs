// TODO
// * is blocking an issue?
// * less dependencies?
// * build library only with library deps -- maybe separate into two crates in a workspace?

use std::{collections::HashMap, env, fmt};
use serde::Deserialize;
use regex::Regex;
pub type Result<T> = std::result::Result<T, CIIDError>;

#[derive(Debug, Clone)]
pub enum CIIDError{
    EnvironmentNotDetected,
    EnvironmentError(String),
    MalformedToken,
}
impl fmt::Display for CIIDError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CIIDError::EnvironmentError(s) => write!(f, "credential detection failed: {}", s),
            _ => write!(f, "credential detection failed"),
        }
    }
}

type DetectFn = fn(Option<&str>) -> Result<String>;


fn validate_token(token: String) -> Result<String> {
    // very, very shallow validation: could this be a JWT token?
    match token.split(".").collect::<Vec<&str>>().len() {
        3 => Ok(token),
        _ => Err(CIIDError::MalformedToken)
    }
}

pub fn detect_credentials(audience: Option<&str>) -> Result<String> {
    for (name, detect) in [
        ("GitHub Actions", detect_github as DetectFn),
        ("GitLab Pipelines", detect_gitlab as DetectFn),
    ] {
        match detect(audience) {
            Ok(token) => {
                let token = validate_token(token)?;
                log::debug!("{}: Token found", name);
                return Ok(token)
            },
            Err(CIIDError::EnvironmentNotDetected) => {
                log::debug!("{}: Environment not detected", name);
            },
            Err(e) => return Err(e)
        }
    }

    Err(CIIDError::EnvironmentNotDetected)
}

// Github implementation

#[derive(Deserialize)]
struct GitHubTokenResponse {
    value: String,
}

fn detect_github(audience: Option<&str>) -> Result<String> {
    if let Err(_) = env::var("GITHUB_ACTIONS") {
        return Err(CIIDError::EnvironmentNotDetected);
    };

    let Ok(token_token) = env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN") else {
        return Err(CIIDError::EnvironmentError("GitHub Actions: ACTIONS_ID_TOKEN_REQUEST_TOKEN is not set".into()));
    };
    let Ok(token_url) = env::var("ACTIONS_ID_TOKEN_REQUEST_URL") else {
        return Err(CIIDError::EnvironmentError("GitHub Actions: ACTIONS_ID_TOKEN_REQUEST_URL is not set".into()));
    };
    let mut params = HashMap::new();
    if let Some(aud) = audience {
        params.insert("audience", aud);
    }

    log::debug!("GitHub Actions: Requesting token");
    let client = reqwest::blocking::Client::new();
    let http_response = match client
        .get(token_url)
        .header(
            reqwest::header::AUTHORIZATION,
            format!("bearer {}", token_token),
        )
        .query(&params)
        .send() {
        Ok(response) => response,
        Err(e) => {
            return Err(CIIDError::EnvironmentError(format!("GitHub Actions: Token request failed: {}", e)))
        }

    };
    match http_response.json::<GitHubTokenResponse>() {
        Ok(token_response) => Ok(token_response.value),
        Err(e) => {
            Err(CIIDError::EnvironmentError(format!("GitHub Actions: Failed to parse token reponse: {}", e)))
        }
    }
}

fn detect_gitlab(audience: Option<&str>) -> Result<String> {
    // gitlab tokens can be in any environment variable: we require the variable name to be
    // * "ID_TOKEN" if no audience is argument is used or
    // * "<AUDIENCE>_ID_TOKEN" where <AUDIENCE> is the audience string.

    if let Err(_) = env::var("GITLAB_CI") {
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
    log::debug!("GitLab Pipelines: Looking for token in {}", var_name);
    match env::var(&var_name) {
        Ok(token) => Ok(token),
        Err(_) => Err(CIIDError::EnvironmentError(format!("GitLab Pipelines: {} is not set", var_name))),
    }
}
