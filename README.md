## Ambient credentials detection for CI systems

[![CI badge](https://github.com/jku/ci-id/actions/workflows/ci.yml/badge.svg)](https://github.com/jku/ci-id/actions/workflows/ci.yml)

`ci-id-bin` crate contains a small CLI application that enables easy access to ambient OIDC credentials in CI systems.

```bash
$ ci-id my-audience > token.txt
```

See [ci-id](https://crates.io/crates/ci-id) for the underlying library.

ci-id is based on [id](https://github.com/di/id), a similar Python project.

### Supported environments

Currently supported environments are:
* GitHub Actions
* GitLab CI/CD
* CircleCI

See See [ci-id API documentation](https://docs.rs/ci-id/latest/ci_id/) for details on what configuration each of these environments needs.

### License

`ci-id` is licensed under the Apache 2.0 License.
