
use super::*;

// ── Identity grammar (the client-side mirror) ──

fn front(url: &str) -> ServerFront {
    ServerFront {
        url: url.to_string(),
    }
}

fn release_cfg() -> ReleaseConfig {
    ReleaseConfig {
        signing_key: Some(PathBuf::from("/keys/update.pub")),
        s3_endpoint: Some("https://s3.internal.example".into()),
        s3_bucket: Some("nau-tree".into()),
        s3_region: Some("us-east-1".into()),
        s3_access_key: Some("ak".into()),
        s3_secret_key: Some("sk".into()),
        tree_base: Some("https://tree.example/nau".into()),
    }
}

mod identity_validation;
