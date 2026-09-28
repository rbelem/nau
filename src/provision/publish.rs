//! The guest publish → coordinator receive surface (ADR-0045 amendment,
//! #295 sub-task 2): the guest generates its SSH host keypair locally on
//! first boot and publishes the PUBLIC half — plus the identity content
//! the future certificate principal binds — to the coordinator. This
//! module is the coordinator half: the one-time publish token, the
//! payload contract, and the persisted pending store that issuance
//! (#295 sub-task 3) consumes. No private half ever crosses this surface
//! — that is the amendment's whole point (ADR-0045 addendum: user-data is
//! served for the machine's lifetime and re-delivered on rebuild, so any
//! secret routed through it is recoverable forever; public material is
//! not a secret).
//!
//! ## Transport design (the simplest honest shape)
//!
//! - At create time the coordinator mints ONE one-time publish token per
//!   server (32 bytes from `/dev/urandom`, hex — the `sign.rs` direct
//!   read convention; 256 bits, no crate) bound to the server's machine
//!   identity, records it in the token registry, and rides it — with the
//!   callback URL — through the SAME user-data channel ADR-0045 D2
//!   already trusts (the provider's authenticated create-time channel).
//! - On first boot the guest POSTs one JSON payload
//!   (`{"machine_identity", "public_key", "instance_identity"}`) to the
//!   callback URL with `Authorization: Bearer <token>`. The URL is
//!   operator-supplied (`SHUTTLE_PUBLISH_URL`) — provider-independent,
//!   so one shape serves all five clouds. A TLS-terminating front that
//!   hands the payload + bearer token to [`crate::provision::workers_main`]'s
//!   `receive-publish` verb (payload on stdin, token in
//!   `SHUTTLE_PUBLISH_TOKEN`) completes the channel in front of the
//!   pending store; the in-tree listener is sub-task 3's surface (it must
//!   exist before issuance anyway, and the pending store decouples the
//!   fire-and-forget publish from issuance consumption).
//! - **Trust argument**: the channel authenticates by the one-time token;
//!   it carries PUBLIC material only. ADR-0045's residual class — the
//!   private half recoverable from the metadata service for the machine's
//!   lifetime and every rebuild — is gone BY CONSTRUCTION: nothing
//!   sensitive ships. What a leaked (unconsumed) token buys an attacker
//!   is one spoofed pending entry for one machine identity within the
//!   24h TTL — the same trust level ADR-0045 D2 already accepted (the
//!   provider credential can create machines with arbitrary
//!   `authorized_keys`), bounded further because the workers pin is the
//!   CA fingerprint (not the published key) and issuance binds the
//!   principal to the provider instance-identity content. If the
//!   operator fronts the callback with plain HTTP, the token crosses the
//!   wire in cleartext — name it, and front the URL with TLS.
//! - **Fail-closed refusals** (all named): malformed token, unknown
//!   token, replayed token, expired token, payload identity mismatch,
//!   malformed JSON, key-shape failure, empty instance identity. A
//!   refused publish stores NOTHING.
//!
//! ## Pending store (persisted; sub-task 3 consumes exactly this)
//!
//! - `<home>/.config/shuttle/ca/pending/` — 0700, under the CA's
//!   dedicated root (NEVER `keys/` — the sub-task-1 contract keeps the CA
//!   flow out of the manifest keychain): one
//!   `pending-<machine-identity>.json` entry per enrolled machine
//!   (public half + instance identity + receipt), the intake queue
//!   issuance signs from.
//! - `<home>/.config/shuttle/ca/pending/tokens.json` — 0600, the one-time
//!   token registry. Tokens are stored SHA-256-hashed (a leaked registry
//!   must not leak live bearers), each bound to its machine identity with
//!   issue/consume stamps; one-time-ness is enforced by the consume
//!   stamp, expiry by [`PUBLISH_TOKEN_TTL_SECS`].
//! - **INTERIM (by design)**: issuance is #295 sub-task 3 — until it
//!   lands the flow STOPS at this store, fail-closed. Pending identities
//!   accumulate, nothing signs, and a provisioned worker's pin is the CA
//!   fingerprint, which [`crate::ssh_exec`] still refuses at preflight
//!   (fingerprint-only) until sub-task 4 teaches the executor the
//!   `@cert-authority` shape. The fleet flow is intentionally incomplete
//!   in this window; every gap fails closed rather than open.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The one-time publish token's validity window, from issue: an older
/// token is refused even if never consumed — tokens leak through
/// user-data by design, so a stale bearer must not stay live forever
/// (the guest publishes within minutes of first boot; 24h is generous).
pub const PUBLISH_TOKEN_TTL_SECS: u64 = 86_400;

/// Token entropy: 32 bytes → 64 hex chars.
const TOKEN_BYTES: usize = 32;

/// The pending store root: `<home>/.config/shuttle/ca/pending/`.
pub fn pending_dir(home: &Path) -> PathBuf {
    crate::ca::ca_dir(home).join("pending")
}

/// The one-time token registry (token SHA-256 → identity + stamps).
fn registry_path(home: &Path) -> PathBuf {
    pending_dir(home).join("tokens.json")
}

/// One enrolled machine's pending entry, as the store persists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingIdentity {
    pub machine_identity: String,
    /// The guest's published PUBLIC host key line (full
    /// `<keytype> <base64> [comment]` — issuance consumes it verbatim).
    pub public_key: String,
    /// The cloud-init normalized instance-data document the guest read at
    /// `/run/cloud-init/instance-data.json` — the provider
    /// instance-identity content the certificate principal binds
    /// (ADR-0045 Decision 3's principal rule).
    pub instance_identity: Value,
    pub received_at_epoch: u64,
    /// SHA-256 of the consuming token — the receipt that ties the entry
    /// to the create-time issuance.
    pub token_sha256: String,
}

/// One registry record (token kept hashed at rest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TokenRecord {
    token_sha256: String,
    machine_identity: String,
    issued_at_epoch: u64,
    consumed_at_epoch: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Registry {
    tokens: Vec<TokenRecord>,
}

/// The coordinator side of the publish channel, resolved once at the CLI
/// boundary: the callback URL the guest POSTs to and the ceremony home
/// the registry + pending store live under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishChannel {
    pub url: String,
    pub home: PathBuf,
}

/// The machine-identity charset: provider server names are
/// coordinator-generated (`shuttle-worker-<hex>-NN`); anything outside
/// `[A-Za-z0-9._-]` is refused at BOTH ends (issue + receive), which
/// also makes the pending filename traversal-proof.
fn validate_machine_identity(identity: &str) -> miette::Result<()> {
    let ok = !identity.is_empty()
        && identity
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'));
    if ok {
        Ok(())
    } else {
        Err(miette::miette!(
            "machine identity '{identity}' is not a shuttle server name (expected \
             [A-Za-z0-9._-] only) — refusing to bind or store it"
        ))
    }
}

/// The callback URL shape rules: single-line http(s), no whitespace,
/// no quote characters, no controls — anything else would break the
/// template's single-quoted env file or invite header injection.
pub fn validate_publish_url(url: &str) -> miette::Result<()> {
    let scheme_ok = url.starts_with("https://") || url.starts_with("http://");
    let chars_ok = url
        .chars()
        .all(|c| !c.is_whitespace() && c != '\'' && c != '"' && !c.is_control());
    if scheme_ok && chars_ok {
        Ok(())
    } else {
        Err(miette::miette!(
            "SHUTTLE_PUBLISH_URL must be a single-line http(s):// URL with no whitespace or \
             quotes, got '{url}'"
        ))
    }
}

/// Resolve the publish channel from the environment: `SHUTTLE_PUBLISH_URL`
/// and `HOME`, read here at the CLI boundary like every other credential
/// source — the provider cores stay env-free under test.
pub fn resolve_publish_channel() -> miette::Result<PublishChannel> {
    let url = std::env::var("SHUTTLE_PUBLISH_URL")
        .ok()
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .ok_or_else(|| {
            miette::miette!(
                "provision: no publish callback URL — set SHUTTLE_PUBLISH_URL to the \
                 coordinator endpoint the guest publishes its public host half to \
                 (https-fronted; the one-time token authenticates each POST). A provision \
                 whose guest cannot publish can never be issued a certificate, so this is \
                 refused before any API call"
            )
        })?;
    validate_publish_url(&url)?;
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    Ok(PublishChannel {
        url,
        home: PathBuf::from(home),
    })
}

/// Mint one one-time publish token: 32 bytes from `/dev/urandom`, hex —
/// the `sign.rs` direct-read convention (Linux-only per project charter),
/// no new crates.
pub fn mint_publish_token() -> miette::Result<String> {
    let mut buf = [0u8; TOKEN_BYTES];
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| miette::miette!("provision: cannot open /dev/urandom: {e}"))?;
    // read_exact — /dev/urandom never EOFs, so read-to-end would block.
    f.read_exact(&mut buf)
        .map_err(|e| miette::miette!("provision: cannot read /dev/urandom: {e}"))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Registry key for a bearer token: its SHA-256 — the registry never
/// stores the live bearer.
fn token_fingerprint(token: &str) -> String {
    crate::oci::sha256_hex(token.as_bytes())
}

fn load_registry(home: &Path) -> miette::Result<Registry> {
    let path = registry_path(home);
    if !path.exists() {
        return Ok(Registry::default());
    }
    let text = std::fs::read_to_string(&path).map_err(|e| {
        miette::miette!(
            "publish: cannot read the token registry {}: {e}",
            path.display()
        )
    })?;
    serde_json::from_str(&text).map_err(|e| {
        miette::miette!(
            "publish: the token registry {} is corrupt: {e} — fix or move it; refusing to guess",
            path.display()
        )
    })
}

/// Atomically install `content` at `path`, 0600 (the config-rewrite
/// pattern): a crashed write never leaves a torn store.
fn atomic_write_0600(path: &Path, content: &str) -> miette::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| miette::miette!("publish: cannot stage {}: {e}", path.display()))?;
    use std::io::Write;
    tmp.write_all(content.as_bytes())
        .and_then(|_| tmp.flush())
        .map_err(|e| miette::miette!("publish: cannot write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| miette::miette!("publish: cannot chmod 0600 {}: {e}", path.display()))?;
    }
    tmp.persist(path)
        .map_err(|e| miette::miette!("publish: cannot install {}: {}", path.display(), e.error))?;
    Ok(())
}

/// Record one issuance: provision-side, BEFORE the create call — the
/// token must be enforceable by the time the guest's first boot
/// publishes. The registry file is created (0600, under the 0700 pending
/// dir) on the first issuance.
pub fn record_issue(
    home: &Path,
    token: &str,
    machine_identity: &str,
    issued_at_epoch: u64,
) -> miette::Result<()> {
    validate_machine_identity(machine_identity)?;
    if token.len() != TOKEN_BYTES * 2 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(miette::miette!(
            "publish: refusing to record a malformed publish token"
        ));
    }
    let mut registry = load_registry(home)?;
    registry.tokens.push(TokenRecord {
        token_sha256: token_fingerprint(token),
        machine_identity: machine_identity.to_string(),
        issued_at_epoch,
        consumed_at_epoch: None,
    });
    std::fs::create_dir_all(pending_dir(home)).map_err(|e| {
        miette::miette!(
            "publish: cannot create the pending store {}: {e}",
            pending_dir(home).display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(pending_dir(home), std::fs::Permissions::from_mode(0o700));
    }
    let text = serde_json::to_string_pretty(&registry)
        .map_err(|e| miette::miette!("publish: cannot serialize the registry: {e}"))?;
    atomic_write_0600(&registry_path(home), &format!("{text}\n"))
}

/// The parsed publish payload: exactly the three identity fields the
/// pending store keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishPayload {
    pub machine_identity: String,
    pub public_key: String,
    pub instance_identity: Value,
}

/// Parse + shape-check the guest's JSON payload. Fail-closed, named:
/// non-JSON, non-object, missing/mistyped fields, a fingerprint-shaped
/// "key" (useless for issuance), and an empty instance identity (a guest
/// that cannot read its metadata is not enrollable — the principal would
/// bind nothing).
pub fn parse_publish_payload(bytes: &[u8]) -> miette::Result<PublishPayload> {
    let v: Value = serde_json::from_slice(bytes)
        .map_err(|e| miette::miette!("publish: payload is not valid JSON: {e}"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| miette::miette!("publish: payload must be a JSON object"))?;
    let identity = obj
        .get("machine_identity")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            miette::miette!("publish: payload is missing 'machine_identity' (a non-empty string)")
        })?;
    validate_machine_identity(identity)?;
    let public_key = obj
        .get("public_key")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            miette::miette!("publish: payload is missing 'public_key' (the full public line)")
        })?;
    if public_key.starts_with("SHA256:") {
        return Err(miette::miette!(
            "publish: 'public_key' is a fingerprint, not a public-key line — issuance needs \
             the full `<keytype> <base64>` half"
        ));
    }
    crate::lua::validate_host_key(public_key)
        .map_err(|e| miette::miette!("publish: 'public_key' fails the host-key grammar: {e}"))?;
    let instance_identity = obj
        .get("instance_identity")
        .and_then(Value::as_object)
        .filter(|o| !o.is_empty())
        .ok_or_else(|| {
            miette::miette!(
                "publish: payload is missing 'instance_identity' (the cloud-init \
                 instance-data object) — the certificate principal would bind nothing; \
                 fail-closed"
            )
        })?;
    Ok(PublishPayload {
        machine_identity: identity.to_string(),
        public_key: public_key.trim().to_string(),
        instance_identity: Value::Object(instance_identity.clone()),
    })
}

/// The coordinator receive: validate the bearer (shape → registry →
/// one-time-ness → expiry), validate the payload, bind the token to its
/// machine identity, store the pending entry, then consume the token.
/// Returns the stored machine identity. The entry is written BEFORE the
/// consume stamp — a crash in between leaves the token unconsumed and a
/// re-publish idempotently rewrites the SAME entry, never a duplicate.
pub fn receive_publish(
    home: &Path,
    bearer: &str,
    payload_bytes: &[u8],
    now_epoch: u64,
) -> miette::Result<String> {
    let bearer = bearer.trim();
    if bearer.len() != TOKEN_BYTES * 2 || !bearer.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(miette::miette!(
            "publish: malformed publish token (expected 64 hex chars) — refusing"
        ));
    }
    let fingerprint = token_fingerprint(bearer);
    let mut registry = load_registry(home)?;
    let record = registry
        .tokens
        .iter_mut()
        .find(|t| t.token_sha256 == fingerprint)
        .ok_or_else(|| {
            miette::miette!(
                "publish: unknown publish token — never issued by this coordinator (or the \
                 registry moved); refusing"
            )
        })?;
    if record.consumed_at_epoch.is_some() {
        return Err(miette::miette!(
            "publish: replay refused — this one-time publish token was already consumed \
             (machine identity '{}')",
            record.machine_identity
        ));
    }
    if now_epoch.saturating_sub(record.issued_at_epoch) > PUBLISH_TOKEN_TTL_SECS {
        return Err(miette::miette!(
            "publish: expired publish token (issued for '{}' more than {PUBLISH_TOKEN_TTL_SECS}s \
             ago) — refusing",
            record.machine_identity
        ));
    }
    let payload = parse_publish_payload(payload_bytes)?;
    if payload.machine_identity != record.machine_identity {
        return Err(miette::miette!(
            "publish: token/identity mismatch — the token is bound to '{}' but the payload \
             claims '{}'; refusing",
            record.machine_identity,
            payload.machine_identity
        ));
    }

    let dir = pending_dir(home);
    std::fs::create_dir_all(&dir)
        .map_err(|e| miette::miette!("publish: cannot create {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let entry = PendingIdentity {
        machine_identity: payload.machine_identity.clone(),
        public_key: payload.public_key,
        instance_identity: payload.instance_identity,
        received_at_epoch: now_epoch,
        token_sha256: fingerprint,
    };
    let text = serde_json::to_string_pretty(&entry)
        .map_err(|e| miette::miette!("publish: cannot serialize the pending entry: {e}"))?;
    let entry_path = dir.join(format!("pending-{}.json", entry.machine_identity));
    atomic_write_0600(&entry_path, &format!("{text}\n"))?;

    // Entry durable → consume. Same-file replay now reads as a replay.
    record.consumed_at_epoch = Some(now_epoch);
    let reg_text = serde_json::to_string_pretty(&registry)
        .map_err(|e| miette::miette!("publish: cannot serialize the registry: {e}"))?;
    atomic_write_0600(&registry_path(home), &format!("{reg_text}\n"))?;
    Ok(entry.machine_identity)
}

/// The pending entries currently awaiting issuance — sub-task 3's read
/// side. Missing store → empty (nothing enrolled yet).
pub fn pending_identities(home: &Path) -> miette::Result<Vec<PendingIdentity>> {
    let dir = pending_dir(home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut names: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map_err(|e| miette::miette!("publish: cannot read {}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("pending-") && n.ends_with(".json"))
        })
        .collect();
    names.sort();
    for path in names {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| miette::miette!("publish: cannot read {}: {e}", path.display()))?;
        let entry: PendingIdentity = serde_json::from_str(&text).map_err(|e| {
            miette::miette!("publish: pending entry {} is corrupt: {e}", path.display())
        })?;
        out.push(entry);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkvsDFv9XrohqXsJvKK8dFbGFe5vN3fGcLgoW8cR3UxQ shuttle-worker-host-key";
    const IDENTITY: &str = "shuttle-worker-abc123-01";

    fn payload_bytes(identity: &str) -> Vec<u8> {
        serde_json::json!({
            "machine_identity": identity,
            "public_key": FIXTURE_PUB,
            "instance_identity": {
                "v1": { "instance_id": "i-123", "cloud_name": "hetzner", "region": "hel1" }
            }
        })
        .to_string()
        .into_bytes()
    }

    fn enrolled(home: &Path) -> String {
        let token = mint_publish_token().unwrap();
        record_issue(home, &token, IDENTITY, 1_000_000).unwrap();
        token
    }

    #[test]
    fn minted_tokens_are_64_hex_and_unique() {
        let a = mint_publish_token().unwrap();
        let b = mint_publish_token().unwrap();
        assert_eq!(a.len(), 64, "32 bytes hex");
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, b, "each machine gets its own bearer");
    }

    #[test]
    fn publish_urls_breaking_the_env_file_shape_are_named_refusals() {
        let bad = [
            "ftp://x",
            "https://a b",
            "https://a'b",
            "https://a\"b",
            "https://a\nb",
            "",
        ];
        for url in bad {
            let err = validate_publish_url(url).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("SHUTTLE_PUBLISH_URL"),
                "'{url}' must be a named refusal: {msg}"
            );
        }
        validate_publish_url("https://coordinator.example:8443/publish").unwrap();
        validate_publish_url("http://10.0.0.1:8080/publish?a=b&c=d").unwrap();
    }

    #[test]
    fn receive_stores_the_pending_entry_and_consumes_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let token = enrolled(home);

        let stored = receive_publish(home, &token, &payload_bytes(IDENTITY), 1_000_030).unwrap();
        assert_eq!(stored, IDENTITY);

        let entries = pending_identities(home).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].machine_identity, IDENTITY);
        assert_eq!(entries[0].public_key, FIXTURE_PUB);
        assert_eq!(entries[0].token_sha256, token_fingerprint(&token));
        assert!(
            entries[0].instance_identity.get("v1").is_some(),
            "instance identity content rides the entry"
        );
        assert!(pending_dir(home)
            .join(format!("pending-{IDENTITY}.json"))
            .exists());
    }

    #[test]
    fn replayed_tokens_are_named_refusals() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let token = enrolled(home);
        receive_publish(home, &token, &payload_bytes(IDENTITY), 1_000_030).unwrap();
        let err = receive_publish(home, &token, &payload_bytes(IDENTITY), 1_000_040).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("replay refused"), "{msg}");
        assert!(msg.contains("already consumed"), "{msg}");
        assert_eq!(
            pending_identities(home).unwrap().len(),
            1,
            "a replay never stores a second entry"
        );
    }

    #[test]
    fn unknown_and_malformed_tokens_are_named_refusals_storing_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let token = enrolled(home);
        let _ = token;

        for (i, bearer) in [
            "0".repeat(64),
            "zz".repeat(32),
            "abc".to_string(),
            String::new(),
        ]
        .into_iter()
        .enumerate()
        {
            let err =
                receive_publish(home, &bearer, &payload_bytes(IDENTITY), 1_000_030).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("malformed publish token") || msg.contains("unknown publish token"),
                "case {i} must be a named refusal: {msg}"
            );
        }
        assert!(
            pending_identities(home).unwrap().is_empty(),
            "a refused publish stores nothing"
        );
    }

    #[test]
    fn expired_tokens_are_refused_but_the_ttl_boundary_stays_open() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let stale = mint_publish_token().unwrap();
        record_issue(home, &stale, IDENTITY, 0).unwrap();
        let late = PUBLISH_TOKEN_TTL_SECS + 1;
        let err = receive_publish(home, &stale, &payload_bytes(IDENTITY), late).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("expired publish token"), "{msg}");
        assert!(pending_identities(home).unwrap().is_empty());

        // One second inside the window: the same payload is accepted for
        // a freshly issued token.
        let fresh = mint_publish_token().unwrap();
        record_issue(home, &fresh, IDENTITY, late - 1).unwrap();
        receive_publish(home, &fresh, &payload_bytes(IDENTITY), late).unwrap();
    }

    #[test]
    fn payload_shaped_like_another_machine_is_a_named_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let token = enrolled(home);
        let err = receive_publish(
            home,
            &token,
            &payload_bytes("shuttle-worker-abc123-02"),
            1_000_030,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("token/identity mismatch"), "{msg}");
        assert!(msg.contains(IDENTITY), "names the bound identity: {msg}");
        assert!(pending_identities(home).unwrap().is_empty());
    }

    #[test]
    fn malformed_payloads_are_named_refusals_storing_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let token = enrolled(home);

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("not json", b"{ not json".to_vec()),
            (
                "fingerprint key",
                serde_json::json!({
                    "machine_identity": IDENTITY,
                    "public_key": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "instance_identity": {"v1": {}}
                })
                .to_string()
                .into_bytes(),
            ),
            (
                "bad key grammar",
                serde_json::json!({
                    "machine_identity": IDENTITY,
                    "public_key": "not-a-key",
                    "instance_identity": {"v1": {}}
                })
                .to_string()
                .into_bytes(),
            ),
            (
                "empty instance identity",
                serde_json::json!({
                    "machine_identity": IDENTITY,
                    "public_key": FIXTURE_PUB,
                    "instance_identity": {}
                })
                .to_string()
                .into_bytes(),
            ),
            (
                "traversal identity",
                serde_json::json!({
                    "machine_identity": "../../etc/shuttle",
                    "public_key": FIXTURE_PUB,
                    "instance_identity": {"v1": {}}
                })
                .to_string()
                .into_bytes(),
            ),
        ];
        for (name, bytes) in cases {
            let err = receive_publish(home, &token, &bytes, 1_000_030).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("publish:")
                    || msg.contains("grammar")
                    || msg.contains("machine identity"),
                "{name} must be a named refusal: {msg}"
            );
        }
        assert!(
            pending_identities(home).unwrap().is_empty(),
            "no malformed payload ever lands"
        );
    }

    #[test]
    fn registry_is_hashed_at_rest_and_survives_process_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let token = enrolled(home);
        let reg_text = std::fs::read_to_string(registry_path(home)).unwrap();
        assert!(
            !reg_text.contains(&token),
            "the live bearer never sits in the registry"
        );
        assert!(reg_text.contains(&token_fingerprint(&token)));

        // A fresh load (the next process) still enforces one-time-ness.
        receive_publish(home, &token, &payload_bytes(IDENTITY), 1_000_030).unwrap();
        let err = receive_publish(home, &token, &payload_bytes(IDENTITY), 1_000_040).unwrap_err();
        assert!(format!("{err:#}").contains("replay refused"));
    }

    #[test]
    fn pending_identities_reads_an_empty_store_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(pending_identities(dir.path()).unwrap().is_empty());
    }
}
