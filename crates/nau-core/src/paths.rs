//! On-disk location vocabulary (issue #326 PR 3, R4 down-move).
//!
//! The documented default roots the runtime store and the image state
//! layer both name. Plain `&'static str` constants — shared vocabulary
//! (ADR-0051 Decision 3), so the image crate consumes them from the
//! spine instead of the runtime domain. `RuntimeStore` re-exports them
//! from the root crate.
//!
//! Issue #326 PR 5 added the pod state-layout helpers (`DEFAULT_POD`,
//! `pod_dir`, `validate_pod_name`, `resolve_pod_dir_under`): the peer
//! crate composes pods from names + roots without importing the root
//! pod domain (the env-reading `pod_root` stays root).

use std::path::{Path, PathBuf};

/// Default state root for generations + the content store.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/nau";

/// Sysext link directory the extensions link dir defaults to.
pub const DEFAULT_EXTENSIONS_LINK_DIR: &str = "/var/lib/extensions";

/// On-device trust anchor embedded at image build time (ADR-0011 step
/// (d)); its siblings `trusted-keys/` and `revoked-keys` are consulted
/// beside it (see `nau_core::sign`). The runtime re-exports this.
pub const DEVICE_ANCHOR: &str = "/etc/nau/update-key.pub";

/// The serve address every default falls back to (issue #326 PR 5
/// down-move): loopback, because `/info` publishes the pod inventory to
/// everyone who can reach the socket — binding wider is an explicit
/// choice the operator types. `nau-chart`'s `node {}` handling
/// re-exports this.
pub const DEFAULT_SERVE_ADDRESS: &str = "127.0.0.1:7780";

/// The implicit pod when no `--name` is given (`nau pod <verb>`) — and
/// the pod `serve`/`export` default to. Moved DOWN from the root pod
/// module (issue #326 PR 5); the root re-exports it.
pub const DEFAULT_POD: &str = "default";

/// One pod's state directory: `<root>/<name>` (holding `pod.lua`, the
/// lockfile, and — in later tickets — generation links).
pub fn pod_dir(root: &Path, pod_name: &str) -> PathBuf {
    root.join(pod_name)
}

/// Validate a pod name: the name becomes a directory under the pod root
/// AND reaches generated unit file names and `Description=` lines
/// (ADR-0032 Decision 4), so besides being a single path-safe component
/// it must not carry control characters or quotes (a newline would
/// inject into the unit text; a quote breaks its quoting — issue #109
/// S5).
pub fn validate_pod_name(name: &str) -> miette::Result<()> {
    if name.is_empty() {
        miette::bail!("pod name must not be empty");
    }
    if name == "." || name == ".." {
        miette::bail!("pod name '{name}' is not allowed");
    }
    if name.chars().any(|c| c == '/' || c == '\\') {
        miette::bail!("pod name '{name}' must not contain path separators");
    }
    if name
        .chars()
        .any(|c| c.is_control() || c == '\'' || c == '"')
    {
        miette::bail!(
            "pod name '{name}' must not contain control characters or quotes — the \
             name reaches unit file names and unit descriptions verbatim"
        );
    }
    Ok(())
}

/// Resolve a `--pod` param to `(name, pod dir)` under an explicit pod
/// root — `default` when None, name validated per [`validate_pod_name`].
/// Moved DOWN from the root pod module (issue #326 PR 5), where it was
/// split from the env-reading `resolve_pod_dir` (still root) so tests
/// can point the root at a tempdir.
pub fn resolve_pod_dir_under(root: &Path, pod: Option<&str>) -> miette::Result<(String, PathBuf)> {
    let name = pod.unwrap_or(DEFAULT_POD);
    validate_pod_name(name)?;
    Ok((name.to_string(), pod_dir(root, name)))
}
