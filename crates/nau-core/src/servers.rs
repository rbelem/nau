//! The `servers` config value types (ADR-0052 Decision 6), placed beside
//! [`crate::worker_types`] per its precedent: the value types live DOWN
//! here so every consumer composes them (the chart's Lua extraction, the
//! pod declaration's override field, the submit client, the drain); the
//! Lua parsing stays with the chart, which re-exports the type.
//!
//! `servers` is an ORDERED list of server fronts. One front is the
//! public tree base URL — the same base `nau pull` consumes
//! (`<base>/manifests/<pkg>.json`) and the one the build-request path
//! POSTs to (`<base>/build-requests`, ADR-0052 Decision 4). The list is
//! tried in declaration order; a pod may override it with its own list
//! (pod override → system list in order → named error).

use serde::{Deserialize, Serialize};

/// One server front: the public base URL of the static tree the front
/// serves (rustfs behind Caddy, ADR-0052 Decision 5) — the submit path
/// POSTs `<url>/build-requests` against it, the pull lane fetches
/// `<url>/manifests/<pkg>.json` from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerFront {
    /// Public tree base, e.g. `https://download.example/nau` — scheme
    /// `http`/`https`, non-empty host, optional path. No trailing-slash
    /// normalization: the URL is joined as declared.
    pub url: String,
}

/// Validate one server-front URL (ADR-0052 Decision 6): `http://` or
/// `https://` scheme, non-empty authority, no whitespace anywhere, no
/// control characters. The path component is kept verbatim — a front may
/// serve the tree under a subpath.
pub fn validate_server_url(raw: &str) -> miette::Result<()> {
    if raw.is_empty() {
        miette::bail!("server url must not be empty");
    }
    if raw.chars().any(char::is_whitespace) || raw.chars().any(|c| c.is_control()) {
        miette::bail!("server url must not contain whitespace or control characters: '{raw}'");
    }
    let rest = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("http://"))
        .ok_or_else(|| {
            miette::miette!(
                "server url '{raw}' must start with http:// or https:// (the public tree base)"
            )
        })?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        miette::bail!("server url '{raw}' has an empty host");
    }
    if authority.starts_with('-') {
        miette::bail!("server url '{raw}' host must not start with '-'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_public_tree_shapes() {
        validate_server_url("https://download.example/nau").unwrap();
        validate_server_url("http://nuci.local:7780").unwrap();
        validate_server_url("https://mirror.example").unwrap();
        validate_server_url("http://[::1]:7780/nau").unwrap();
    }

    #[test]
    fn refuses_the_named_shapes() {
        assert!(validate_server_url("").is_err());
        assert!(validate_server_url("download.example").is_err());
        assert!(validate_server_url("ftp://mirror.example").is_err());
        assert!(validate_server_url("https://").is_err());
        assert!(validate_server_url("https://mirror with space").is_err());
        assert!(validate_server_url("https://mirror.example/path\n").is_err());
        assert!(validate_server_url("http://-host.example").is_err());
    }
}
