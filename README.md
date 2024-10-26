## ci-id -- Ambient credentials detection for CI systems

ci-id provides easy access to ambient OIDC credentials in CI systems.


```
use ci_id::{detect_credentials, CIIDError};

fn main() -> Result<(), CIIDError>  {
    let token = detect_credentials(Some("myaudience"))?;
    print!("Ambient OIDC token detected: {}", token);
    Ok(())
}
```

There is a simple CLI application: `ci-id` prints the token in stdout. 

### Supported environments



#### GitHub Actions

Workflow must be given the permission to use the workflow identity: 

```
permissions:
    id-token: write
```

#### GitLab Pipelines

An ID token must be defined in the pipeline. The ID token name must be based on the audience so
that token name is either
* `ID_TOKEN` for default audience
* `<AUD>_ID_TOKEN` where <AUD> is the audience string sanitized for environment variable names
  (uppercased and all characters outside of ascii letters and digits are replaced with "_")

```
  id_tokens:
    MY_AUDIENCE_ID_TOKEN:
      aud: my-audience
```

