//! `ci-id` provides easy access to ambient OIDC credentials in CI systems like
//! GitHub Actions.
//!
//! ```
//! match ci_id::detect_credentials(Some("my-audience")) {
//!     Ok(token) => println!("{}", token),
//!     Err(e) => eprintln!("{}", e)
//! }
//! ```
//!
//! # Environment specific setup
//!
//! Typically the CI environment needs to allow OIDC identity access.
//!
//! ## GitHub Actions
//!
//! Workflow must be given the [permission](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect#adding-permissions-settings)
//! to use the workflow identity:
//!
//! ```yaml
//! permissions:
//!     id-token: write
//! ```
//!
//! ## GitLab Pipelines
//!
//! An [ID token](https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html)
//! must be defined in the pipeline:
//!
//! ```yaml
//! id_tokens:
//!     MY_AUDIENCE_ID_TOKEN:
//!         aud: my-audience
//! ```
//!
//! The ID token name must be based on the audience so
//! that token name is either
//! * `ID_TOKEN` for default audience
//! * `<AUD>_ID_TOKEN` where `<AUD>` is the audience string sanitized for environment variable names
//!   (uppercased and all characters outside of ascii letters and digits are replaced with "_")
//!
//! ## CircleCI
//!
//! No configuration is needed.

// TODO
// * is blocking an issue?
// * less dependencies?

use regex::Regex;
use serde::Deserialize;
use std::{collections::HashMap, env, fmt, process::Command};
pub type Result<T> = std::result::Result<T, CIIDError>;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

#[derive(Debug, Clone, PartialEq)]
pub enum CIIDError {
    /// No supported OIDC identity environment was detected
    EnvironmentNotDetected,
    /// Environment was found but there was a problem with acquiring the token
    EnvironmentError(String),
    /// Identity token was found but it does not look like JSON Web Token
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
        _ => Err(CIIDError::MalformedToken),
    }
}

/// Returns detected OIDC identity token.
///
/// The supported environments are probed in order, the identity token
/// for the first found environment is returned.
///
/// ```
/// match ci_id::detect_credentials(Some("my-audience")) {
///     Ok(token) => println!("{}", token),
///     Err(e) => eprintln!("{}", e)
/// }
/// ```
pub fn detect_credentials(audience: Option<&str>) -> Result<String> {
    for (name, detect) in [
        ("GitHub Actions", detect_github as DetectFn),
        ("GitLab Pipelines", detect_gitlab as DetectFn),
        ("CircleCI", detect_circleci as DetectFn),
        ("Buildkite", detect_buildkite as DetectFn),
    ] {
        match detect(audience) {
            Ok(token) => {
                let token = validate_token(token)?;
                log::debug!("{}: Token found", name);
                return Ok(token);
            }
            Err(CIIDError::EnvironmentNotDetected) => {
                log::debug!("{}: Environment not detected", name);
            }
            Err(e) => return Err(e),
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
    if env::var("GITHUB_ACTIONS").is_err() {
        return Err(CIIDError::EnvironmentNotDetected);
    };

    let Ok(token_token) = env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN") else {
        return Err(CIIDError::EnvironmentError(
            "GitHub Actions: ACTIONS_ID_TOKEN_REQUEST_TOKEN is not set. This could \
            imply that the job does not have 'id-token: write' permission"
                .into(),
        ));
    };
    let Ok(token_url) = env::var("ACTIONS_ID_TOKEN_REQUEST_URL") else {
        return Err(CIIDError::EnvironmentError(
            "GitHub Actions: ACTIONS_ID_TOKEN_REQUEST_URL is not set".into(),
        ));
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
        .send()
    {
        Ok(response) => response,
        Err(e) => {
            return Err(CIIDError::EnvironmentError(format!(
                "GitHub Actions: Token request failed: {}",
                e
            )))
        }
    };
    match http_response.json::<GitHubTokenResponse>() {
        Ok(token_response) => Ok(token_response.value),
        Err(e) => Err(CIIDError::EnvironmentError(format!(
            "GitHub Actions: Failed to parse token reponse: {}",
            e
        ))),
    }
}

fn detect_gitlab(audience: Option<&str>) -> Result<String> {
    // gitlab tokens can be in any environment variable: we require the variable name to be
    // * "ID_TOKEN" if no audience is argument is used or
    // * "<AUDIENCE>_ID_TOKEN" where <AUDIENCE> is the audience string.

    if env::var("GITLAB_CI").is_err() {
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
        Err(_) => Err(CIIDError::EnvironmentError(format!(
            "GitLab Pipelines: {} is not set. This could imply that the \
            pipeline does not define an id token with that name",
            var_name
        ))),
    }
}

fn detect_circleci(audience: Option<&str>) -> Result<String> {
    if env::var("CIRCLECI").is_err() {
        return Err(CIIDError::EnvironmentNotDetected);
    };
    let payload;
    match audience {
        None => match env::var("CIRCLE_OIDC_TOKEN_V2") {
            Ok(token) => Ok(token),
            Err(_) => Err(CIIDError::EnvironmentError(
                "CircleCI: CIRCLE_OIDC_TOKEN_V2 is not set.".into(),
            )),
        },
        Some(audience) => {
            // TODO Use serde here? the audience string could be anything...
            payload = format!("{{\"aud\":\"{}\"}}", audience);
            let args = ["run", "oidc", "get", "--claims", &payload];
            match Command::new("circleci").args(args).output() {
                Ok(output) => match String::from_utf8(output.stdout) {
                    Ok(token) => Ok(token),
                    Err(_) => Err(CIIDError::EnvironmentError(
                        "CircleCI; Failed to read token".into(),
                    )),
                },
                Err(e) => Err(CIIDError::EnvironmentError(format!(
                    "CircleCI: Call to circle CLI failed: {}",
                    e
                ))),
            }
        }
    }
}

fn detect_buildkite(audience: Option<&str>) -> Result<String> {
    if env::var("BUILDKITE").is_err() {
        return Err(CIIDError::EnvironmentNotDetected);
    };

    let args = match audience {
        Some(audience) => vec!["oidc", "request-token", "--audience", audience],
        None => vec!["oidc", "request-token"],
    };
    match Command::new("buildkite-agent").args(args).output() {
        Ok(output) => match String::from_utf8(output.stdout) {
            Ok(token) => Ok(token),
            Err(_) => Err(CIIDError::EnvironmentError(
                "Buildkite; Failed to read token".into(),
            )),
        },
        Err(e) => Err(CIIDError::EnvironmentError(format!(
            "Buildkite: Call to buildkite-agent failed: {}",
            e
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        fs::{self, File},
        io::Write,
        os::unix::fs::PermissionsExt,
        sync::{Mutex, MutexGuard},
    };

    const TOKEN: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxNjA2OGMzM2ZhMjg2OTZhZmI5YzM5YWI2OTMxMjY1ZDk0Y2I3NTUifQ.eyJpc3MiOiJodHRwczovL29hdXRoMi5zaWdzdG9yZS5kZXYvYXV0aCIsInN1YiI6IkNnVXpNVGc0T1JJbWFIUjBjSE02SlRKR0pUSkdaMmwwYUhWaUxtTnZiU1V5Um14dloybHVKVEpHYjJGMWRHZyIsImF1ZCI6InNpZ3N0b3JlIiwiZXhwIjoxNzI5NTEyOTMwLCJpYXQiOjE3Mjk1MTI4NzAsIm5vbmNlIjoiNTI3NjM3Y2UtN2Q2MS00MDA5LThkM2EtNGNjZGM3OGJiZDg1IiwiYXRfaGFzaCI6IktmMUNPTXB5TVJDTkdzWWp1QXczclEiLCJlbWFpbCI6ImprdUBnb3RvLmZpIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImZlZGVyYXRlZF9jbGFpbXMiOnsiY29ubmVjdG9yX2lkIjoiaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoIiwidXNlcl9pZCI6IjMxODg5In19.s27uZ3vpIzRS4eWdC3pM0FSsYkHNvScQoii_TcSRVZhtrcPAbA4D95Pw_R_UB-qRquMK1BHepKmeN1b1-CQ00jiFZgUOf9sDLC3Hy3oQejGJsYKb-7oeHs7amLz3SBzPwDwVd09e-7Yu1x9YV5k6aezqruLLt42C_kyOTsHeCIWWMEVmGp32105Jkj8YT5uEYXS-aOEvQFvAYsDfKgGuiJtGybUycVcJEfqyWI3cami7fkjU5PcCx8oFyP2E7YNRw4UeNWCTn7WFtL2onrgDm0oa2AqF3gtH4Q-9ByksVq3y6xQdoLj1ydzWcoCzsF43oZ6O6DkLmWk5fu3FxNyewg";

    // Mutex for all tests that modify environment variables
    lazy_static! {
        static ref ENV_MUTEX: Mutex<()> = Mutex::new(());
    }

    struct SavedEnv<'a> {
        old_env: HashMap<&'a str, Option<String>>,
        _guard: MutexGuard<'a, ()>,
    }

    impl<'a> SavedEnv<'a> {
        fn new<T>(test_env: T) -> Self
        where
            T: IntoIterator<Item = (&'a str, Option<&'a str>)>,
        {
            // Tests can panic: assume our lock is still fine
            let guard = match ENV_MUTEX.lock() {
                Ok(guard) => guard,
                Err(poison) => poison.into_inner(),
            };

            // Store current env values, set the test values as the environment
            let mut old_env = HashMap::new();
            for (key, val) in test_env {
                let old_val = env::var(key).ok();
                old_env.insert(key, old_val);
                match val {
                    Some(val) => env::set_var(key, val),
                    None => env::remove_var(key),
                }
            }

            Self {
                old_env,
                _guard: guard,
            }
        }
    }

    impl<'a> Drop for SavedEnv<'a> {
        fn drop(&mut self) {
            for (key, val) in self.old_env.drain() {
                match val {
                    Some(val) => env::set_var(key, val),
                    None => env::remove_var(key),
                }
            }
        }
    }

    fn run_with_env<'a, T, F>(test_env: T, f: F)
    where
        F: Fn(),
        T: IntoIterator<Item = (&'a str, Option<&'a str>)>,
    {
        // Prepares env variables according to `env`, runs the function, then returns environment
        // to old values
        let saved_env = SavedEnv::new(test_env);
        f();
        drop(saved_env);
    }

    #[test]
    fn circleci_not_detected() {
        run_with_env([("CIRCLECI", None)], || {
            assert_eq!(
                detect_circleci(None),
                Err(CIIDError::EnvironmentNotDetected)
            );
        });
    }

    #[test]
    fn circleci_env_failure() {
        run_with_env(
            // empty the path so that this does not accidentally succeed on CircleCI
            [("CIRCLECI", Some("1")), ("PATH", Some(""))],
            || {
                assert!(matches!(
                    detect_circleci("my-audience".into()).unwrap_err(),
                    CIIDError::EnvironmentError(_)
                ));
            },
        );

        run_with_env(
            // default audience uses specific env var
            [("CIRCLECI", Some("1")), ("CIRCLE_OIDC_TOKEN_V2", None)],
            || {
                assert!(matches!(
                    detect_circleci(None).unwrap_err(),
                    CIIDError::EnvironmentError(_)
                ));
            },
        );
    }

    #[test]
    fn circleci_success() {
        // create a fake 'circleci' executable
        let tmpdir = tempfile::tempdir().unwrap();
        let dir_path = tmpdir.into_path();
        let path = dir_path.join("circleci");
        let mut f = File::create(&path).unwrap();
        let script = format!("#!/bin/sh\necho -n {}\n", TOKEN);
        f.write_all(script.as_bytes()).unwrap();
        let mut permissions = f.metadata().unwrap().permissions();
        drop(f);
        permissions.set_mode(0o744);
        fs::set_permissions(path, permissions).unwrap();

        // Make sure the fake executable is in PATH, then test non-default audience
        run_with_env(
            // empty the path so that this does not accidentally succeed on CircleCI
            [
                ("CIRCLECI", Some("1")),
                ("PATH", Some(dir_path.to_str().unwrap())),
            ],
            || {
                assert_eq!(detect_circleci("my-audience".into()), Ok(TOKEN.into()));
            },
        );

        run_with_env(
            [
                ("CIRCLECI", Some("1")),
                ("CIRCLE_OIDC_TOKEN_V2", Some(TOKEN)),
            ],
            || {
                assert_eq!(detect_circleci(None), Ok(TOKEN.into()));
            },
        );
    }

    #[test]
    fn github_not_detected() {
        run_with_env([("GITHUB_ACTIONS", None)], || {
            assert_eq!(detect_github(None), Err(CIIDError::EnvironmentNotDetected));
        });
    }

    #[test]
    fn github_env_failure() {
        // Missing env variables
        run_with_env(
            [
                ("GITHUB_ACTIONS", Some("1")),
                ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", None),
            ],
            || {
                assert!(matches!(
                    detect_github(None).unwrap_err(),
                    CIIDError::EnvironmentError(_)
                ));
            },
        );
        run_with_env(
            [
                ("GITHUB_ACTIONS", Some("1")),
                ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", Some("token")),
                ("ACTIONS_ID_TOKEN_REQUEST_URL", None),
            ],
            || {
                assert!(matches!(
                    detect_github(None).unwrap_err(),
                    CIIDError::EnvironmentError(_)
                ));
            },
        );

        // request fails
        run_with_env(
            [
                ("GITHUB_ACTIONS", Some("1")),
                ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", Some("token")),
                ("ACTIONS_ID_TOKEN_REQUEST_URL", Some("http://invalid")),
            ],
            || {
                assert_eq!(
                    detect_github(None).unwrap_err(),
                    CIIDError::EnvironmentError("GitHub Actions: Token request failed: error sending request for url (http://invalid/)".into())
                );
            },
        );
    }

    // TODO This requires mocking reqwest response
    // fn github_success() { }

    #[test]
    fn gitlab_not_detected() {
        run_with_env([("GITLAB_CI", None)], || {
            assert_eq!(detect_gitlab(None), Err(CIIDError::EnvironmentNotDetected));
        });
    }

    #[test]
    fn gitlab_env_failure() {
        // Missing token variable for default audience
        run_with_env([("GITLAB_CI", Some("1")), ("ID_TOKEN", None)], || {
            assert!(matches!(
                detect_gitlab(None).unwrap_err(),
                CIIDError::EnvironmentError(_)
            ));
        });

        // Missing token variable for non-default audience
        run_with_env(
            [("GITLAB_CI", Some("1")), ("MY_AUD_ID_TOKEN", None)],
            || {
                assert!(matches!(
                    detect_gitlab(Some("my-aud")).unwrap_err(),
                    CIIDError::EnvironmentError(_)
                ));
            },
        );
    }

    #[test]
    fn gitlab_success() {
        run_with_env(
            [("GITLAB_CI", Some("1")), ("ID_TOKEN", Some(TOKEN))],
            || {
                assert_eq!(detect_gitlab(None), Ok(TOKEN.into()));
            },
        );

        run_with_env(
            [("GITLAB_CI", Some("1")), ("MY_AUD_ID_TOKEN", Some(TOKEN))],
            || {
                assert_eq!(detect_gitlab(Some("my-aud")), Ok(TOKEN.into()));
            },
        );
    }

    #[test]
    fn detect_credentials_no_environments() {
        run_with_env(
            [
                ("CIRCLECI", None),
                ("GITLAB_CI", None),
                ("GITHUB_ACTIONS", None),
            ],
            || {
                assert_eq!(
                    detect_credentials(None),
                    Err(CIIDError::EnvironmentNotDetected)
                );
            },
        );
    }

    #[test]
    fn detect_credentials_failure() {
        // Unexpected failure in any detector leads to detect_credentials failure.
        run_with_env(
            [
                ("GITHUB_ACTIONS", Some("1")),
                ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", None),
            ],
            || {
                assert!(matches!(
                    detect_credentials(None).unwrap_err(),
                    CIIDError::EnvironmentError(_)
                ));
            },
        );
    }

    #[test]
    fn detect_credentials_malformed_token() {
        // need to disable GitHub, otherwise we get a "false" positive on CI...
        run_with_env(
            [
                ("GITHUB_ACTIONS", None),
                ("GITLAB_CI", Some("1")),
                ("ID_TOKEN", Some("token value")),
            ],
            || {
                assert_eq!(detect_credentials(None), Err(CIIDError::MalformedToken));
            },
        );
    }

    #[test]
    fn detect_credentials_success() {
        // need to disable GitHub, otherwise we get a "false" positive on CI...
        run_with_env(
            [
                ("GITHUB_ACTIONS", None),
                ("GITLAB_CI", Some("1")),
                ("ID_TOKEN", Some(TOKEN)),
            ],
            || {
                assert_eq!(detect_credentials(None), Ok(TOKEN.into()));
            },
        );

        run_with_env(
            [
                ("GITHUB_ACTIONS", None),
                ("GITLAB_CI", Some("1")),
                ("MY_AUD_ID_TOKEN", Some(TOKEN)),
            ],
            || {
                assert_eq!(detect_credentials(Some("my-aud")), Ok(TOKEN.into()));
            },
        );
    }
}
