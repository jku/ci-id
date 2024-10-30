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

See [ci-id-bin](https://crates.io/crates/ci-id-bin) crate for a simple CLI wrapper.

ci-id is based on [id](https://github.com/di/id), a similar Python project.

### Supported environments

Currently supported environments are:
* GitHub Actions
* GitLab CI/CD
* CircleCI
* Buildkite

See [documentation](https://docs.rs/ci-id/latest/ci_id/) for details on what configuration each of these environments needs.

### License

`ci-id` is licensed under the Apache 2.0 License.
