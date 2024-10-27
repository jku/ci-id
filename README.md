## ci-id -- Ambient credentials detection for CI systems

[![CI badge](https://github.com/jku/ci-id/actions/workflows/ci.yml/badge.svg)](https://github.com/jku/ci-id/actions/workflows/ci.yml)

`ci-id` provides easy access to ambient OIDC credentials in CI systems.


```rust
use ci_id::{detect_credentials, CIIDError};

fn main() -> Result<(), CIIDError>  {
    let token = detect_credentials(Some("myaudience"))?;
    print!("Ambient OIDC token detected: {}", token);
    Ok(())
}
```

A simple CLI application is included in the `ci-id-bin` crate: `ci-id [<AUDIENCE>]` prints the token in stdout.

ci-id is based on [id](https://github.com/di/id), a similar Python project.

### Supported environments

GitHub Actions and GitLab Pipelines are supported at the moment: more implementations are welcome.

#### GitHub Actions

Workflow must be given the permission to use the workflow identity: 

```yaml
permissions:
    id-token: write
```

#### GitLab Pipelines

An ID token must be defined in the pipeline. The ID token name must be based on the audience so
that token name is either
* `ID_TOKEN` for default audience
* `<AUD>_ID_TOKEN` where <AUD> is the audience string sanitized for environment variable names
  (uppercased and all characters outside of ascii letters and digits are replaced with "_")

```yaml
  id_tokens:
    MY_AUDIENCE_ID_TOKEN:
      aud: my-audience
```

### License

`ci-id` is licensed under the Apache 2.0 License.
