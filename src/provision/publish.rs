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
//! - **Issuance + delivery back (#295 sub-task 3)**: the operator (or
//!   the provisioner loop) runs `shuttle workers issue` — the host CA
//!   signs a SHORT-LIVED certificate per pending entry behind the
//!   [`crate::command::CommandRunner`] seam (`ssh-keygen -s <ca> -h -I
//!   <identity> -n <principals> -V <validity>`), principals bind the
//!   machine identity PLUS the provider instance-identity content
//!   (Decision 3's rule; default validity [`HOST_CERT_VALIDITY_DEFAULT`],
//!   overridable at the verb), and the entry moves to
//!   `<home>/.config/shuttle/ca/issued/issued-<identity>.json` — the
//!   audit record, not a deletion. Delivery back is the pickup half of
//!   the SAME channel: the guest GETs the callback URL with the SAME
//!   one-time bearer and receives its certificate (`shuttle workers
//!   pickup` is the transport binding). **Trust argument**: a host
//!   certificate is PUBLIC material — sshd serves it to every client
//!   that connects — so the channel residual class (ADR-0045's
//!   recoverable secret) is gone by construction; the consumed token
//!   keeps authenticating the pickup (a leaked bearer buys a read of one
//!   public certificate, nothing more), and pickup stays inside the
//!   token TTL — after that the guest can no longer fetch and the TTL
//!   sweep reclaims the worker, fail-closed. The guest-side fetch and
//!   the sshd cert-serving config are #295 sub-task 4's.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::command::CommandRunner;

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

/// The machine-linkage store root:
/// `<home>/.config/shuttle/ca/machines/` — the provision-time record of
/// which machine identity each pinned workers address belongs to (#295
/// sub-task 4). The config entry carries only the address and the CA
/// fingerprint (the amendment's "same config shape"), so this
/// coordinator-side store is what lets the executor bind the pinned
/// `@cert-authority` line to the certificate principal: the principal
/// form is the machine identity, and the linkage is the only
/// address→identity map that exists.
pub fn machines_dir(home: &Path) -> PathBuf {
    crate::ca::ca_dir(home).join("machines")
}

/// The filesystem slug for an address's linkage record: the same
/// sha256-truncated form the executor's known_hosts files use, so both
/// sides derive the same name from the same address string.
fn machine_link_slug(address: &str) -> String {
    crate::oci::sha256_hex(address.as_bytes())[..16].to_string()
}

/// One provision-time machine linkage: the pinned workers address and
/// the machine identity (the provider-side server name) it was created
/// for — the identity the certificate principal binds first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineLink {
    pub address: String,
    pub machine_identity: String,
}

fn machine_link_path(home: &Path, address: &str) -> PathBuf {
    machines_dir(home).join(format!("machine-{}.json", machine_link_slug(address)))
}

/// Record one address→machine-identity linkage at provision time, next
/// to the config pin transaction (the executor cannot build a
/// `@cert-authority` connection without it). A malformed identity or
/// address refuses — a provision whose executor could never connect is
/// torn down, not pinned blind.
pub fn record_machine_link(
    home: &Path,
    machine_identity: &str,
    address: &str,
) -> miette::Result<PathBuf> {
    validate_machine_identity(machine_identity)?;
    if address.is_empty() || address.chars().any(char::is_whitespace) {
        return Err(miette::miette!(
            "publish: refusing to link machine identity '{machine_identity}' to the malformed \
             address '{address}'"
        ));
    }
    std::fs::create_dir_all(machines_dir(home)).map_err(|e| {
        miette::miette!(
            "publish: cannot create the machine-linkage store {}: {e}",
            machines_dir(home).display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ =
            std::fs::set_permissions(machines_dir(home), std::fs::Permissions::from_mode(0o700));
    }
    let link = MachineLink {
        address: address.to_string(),
        machine_identity: machine_identity.to_string(),
    };
    let text = serde_json::to_string_pretty(&link)
        .map_err(|e| miette::miette!("publish: cannot serialize the machine linkage: {e}"))?;
    let path = machine_link_path(home, address);
    atomic_write_0600(&path, &format!("{text}\n"))?;
    Ok(path)
}

/// The linkage recorded for `address`, `Ok(None)` when absent. A corrupt
/// record is a named refusal — the executor never guesses an identity.
pub fn machine_link(home: &Path, address: &str) -> miette::Result<Option<MachineLink>> {
    let path = machine_link_path(home, address);
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|e| {
        miette::miette!(
            "publish: cannot read the machine linkage {}: {e}",
            path.display()
        )
    })?;
    serde_json::from_str(&text).map(Some).map_err(|e| {
        miette::miette!(
            "publish: machine linkage {} is corrupt: {e} — fix or \
             re-provision; refusing to guess the machine identity",
            path.display()
        )
    })
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

/// One identity's pending entry, `Ok(None)` when absent — the
/// single-identity read `workers issue --identity` uses. A corrupt entry
/// is a named refusal (fail-closed; never sign from a guessed record).
pub fn pending_entry(home: &Path, identity: &str) -> miette::Result<Option<PendingIdentity>> {
    let path = pending_dir(home).join(format!("pending-{identity}.json"));
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| miette::miette!("publish: cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| miette::miette!("publish: pending entry {} is corrupt: {e}", path.display()))
}

// ── Certificate issuance (#295 sub-task 3) ──

/// Default host-certificate validity — the ssh-keygen relative `-V`
/// form, 48 hours. Short-lived certificates are the ADR-0045 amendment's
/// whole point: a compromised certificate must age out on its own (SSH
/// host certs have no revocation list in this design), so `forever` and
/// absolute windows are refused by [`parse_cert_validity`]. Workers are
/// TTL'd fleet members (provision `--ttl` default 4h, sweep-reclaimed),
/// so 48h covers any sane fleet TTL plus the gap between a rebuild and
/// its re-issue, while bounding every certificate to two days.
/// Overridable per invocation (`workers issue --validity`).
pub const HOST_CERT_VALIDITY_DEFAULT: &str = "+48h";

/// The instance-identity fields the certificate principal binds beyond
/// the machine identity (ADR-0045 Decision 3: the principal binds the
/// operator-assigned machine identity plus the provider's
/// instance-identity content). Fixed order → deterministic certificates;
/// a field absent from the guest's cloud-init instance-data document is
/// skipped; at least ONE must resolve or issuance refuses — a principal
/// binding nothing fails closed. `hostname`/`local_hostname` and friends
/// are deliberately NOT bound: they are addresses, not identity.
const INSTANCE_IDENTITY_PRINCIPAL_FIELDS: [&str; 4] =
    ["instance_id", "cloud_name", "region", "availability_zone"];

/// One issued identity: the pending entry's full audit content (who
/// published, when, under which token) plus the certificate material
/// issuance produced. Written when the identity leaves the pending
/// store — the audit trail, not a deletion. NOTE: an explicit
/// `--force` re-issue replaces this record; the previous certificate
/// remains valid until ITS expiry by SSH-cert design (rotation without
/// revocation — the ADR's accepted posture), so the replaced record is
/// superseded, not revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedIdentity {
    pub machine_identity: String,
    pub public_key: String,
    pub instance_identity: Value,
    pub received_at_epoch: u64,
    pub token_sha256: String,
    /// The ssh-keygen host certificate (the `-cert.pub` content) —
    /// public material; the guest installs it beside its host key.
    pub cert: String,
    /// The principal list the certificate binds, in binding order
    /// (machine identity first, then the instance-identity fields).
    pub principals: Vec<String>,
    /// The `-V` validity argument the certificate was signed with.
    pub validity: String,
    pub issued_at_epoch: u64,
    /// The signing CA's ssh-keygen fingerprint — which root vouches.
    pub ca_fingerprint: String,
}

/// The issued store root: `<home>/.config/shuttle/ca/issued/`.
pub fn issued_dir(home: &Path) -> PathBuf {
    crate::ca::ca_dir(home).join("issued")
}

fn issued_path(home: &Path, identity: &str) -> PathBuf {
    issued_dir(home).join(format!("issued-{identity}.json"))
}

/// The issued records, sorted by machine identity — the store's read
/// side. Missing store → empty.
pub fn issued_identities(home: &Path) -> miette::Result<Vec<IssuedIdentity>> {
    let dir = issued_dir(home);
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
                .is_some_and(|n| n.starts_with("issued-") && n.ends_with(".json"))
        })
        .collect();
    names.sort();
    for path in names {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| miette::miette!("publish: cannot read {}: {e}", path.display()))?;
        let entry: IssuedIdentity = serde_json::from_str(&text).map_err(|e| {
            miette::miette!("publish: issued record {} is corrupt: {e}", path.display())
        })?;
        out.push(entry);
    }
    Ok(out)
}

/// One identity's issued record, `Ok(None)` when not issued. A corrupt
/// record is a named refusal — pickup never serves a guessed cert.
pub fn issued_entry(home: &Path, identity: &str) -> miette::Result<Option<IssuedIdentity>> {
    let path = issued_path(home, identity);
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| miette::miette!("publish: cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| miette::miette!("publish: issued record {} is corrupt: {e}", path.display()))
}

/// The charset an SSH certificate principal may carry: known_hosts
/// matches principals as a comma-separated list, so each principal must
/// be a single `[A-Za-z0-9._-]` token — the same shape as machine
/// identities (which are themselves principals).
fn principal_charset_ok(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
}

/// Validate the certificate validity argument: the ssh-keygen RELATIVE
/// form only — `+` followed by one or more concatenated `<n><unit>`
/// groups (`+48h`, `+30m`, `+2d12h`), unit ∈ `s m h d w`, every n > 0.
/// Absolute dates and `always`/`forever` are named refusals: the
/// amendment's point is that certificates age out; a long-lived window
/// would quietly reintroduce the pin-forever posture it removed.
pub fn parse_cert_validity(raw: &str) -> miette::Result<String> {
    let v = raw.trim();
    let ok_shape = v.starts_with('+') && relative_groups_ok(&v[1..]);
    if ok_shape {
        Ok(v.to_string())
    } else {
        Err(miette::miette!(
            "publish: certificate validity must be short-lived and relative to now — \
             '+<n><s|m|h|d|w>' with optional concatenated groups (e.g. '+48h', '+2d12h'), \
             got '{raw}'; absolute dates and forever windows are refused (ADR-0045 amendment)"
        ))
    }
}

/// `<n><unit>` groups, concatenated: `48h`, `2d12h`.
fn relative_groups_ok(rest: &str) -> bool {
    if rest.is_empty() {
        return false;
    }
    let mut s = rest;
    while !s.is_empty() {
        let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            return false;
        }
        let n: u64 = match digits.parse() {
            Ok(n) => n,
            Err(_) => return false,
        };
        if n == 0 {
            return false;
        }
        s = &s[digits.len()..];
        match s.chars().next() {
            Some(u @ ('s' | 'm' | 'h' | 'd' | 'w')) => s = &s[u.len_utf8()..],
            _ => return false,
        }
    }
    true
}

/// Depth-first search for the first non-empty string value under `key`.
fn find_string_field(v: &Value, key: &str) -> Option<String> {
    match v {
        Value::Object(map) => {
            if let Some(Value::String(s)) = map.get(key) {
                if !s.is_empty() {
                    return Some(s.clone());
                }
            }
            map.values().find_map(|child| find_string_field(child, key))
        }
        Value::Array(items) => items.iter().find_map(|child| find_string_field(child, key)),
        _ => None,
    }
}

/// The principal list a pending identity's certificate binds (ADR-0045
/// Decision 3): the machine identity FIRST — the coordinator addresses
/// the worker by it — then the provider instance-identity content
/// ([`INSTANCE_IDENTITY_PRINCIPAL_FIELDS`], fixed order, deduplicated).
/// No instance-identity principal resolvable is a named refusal: a
/// certificate binding only the machine name would certify an
/// uncorroborated claim, and the publish path already refuses guests
/// that cannot read their instance data.
pub fn cert_principals(
    machine_identity: &str,
    instance_identity: &Value,
) -> miette::Result<Vec<String>> {
    if !principal_charset_ok(machine_identity) {
        return Err(miette::miette!(
            "publish: machine identity '{machine_identity}' is not a usable certificate \
             principal (expected [A-Za-z0-9._-] only)"
        ));
    }
    let mut principals = vec![machine_identity.to_string()];
    for field in INSTANCE_IDENTITY_PRINCIPAL_FIELDS {
        let Some(value) = find_string_field(instance_identity, field) else {
            continue;
        };
        if !principal_charset_ok(&value) {
            return Err(miette::miette!(
                "publish: instance-identity field '{field}' carries '{value}', which is not a \
                 usable certificate principal (expected [A-Za-z0-9._-] only) — refusing to bind it"
            ));
        }
        if !principals.contains(&value) {
            principals.push(value);
        }
    }
    if principals.len() == 1 {
        return Err(miette::miette!(
            "publish: no instance-identity content binds to a principal — the pending entry's \
             instance_identity document carries none of \
             [instance_id, cloud_name, region, availability_zone]; refusing to issue a \
             machine-identity-only certificate (ADR-0045 Decision 3)"
        ));
    }
    Ok(principals)
}

/// Sign ONE pending identity's short-lived host certificate: write the
/// published public half to a scratch file, run
/// `ssh-keygen -s <ca_secret> -h -I <identity> -n <principals> -V <validity>`
/// behind the command seam, read back the `-cert.pub` sibling, persist
/// the issued record, and remove the pending entry. Ordering is
/// crash-safe: the issued record lands BEFORE the pending entry is
/// removed — a crash in between leaves both, and the already-issued
/// guard (or `--force`) resolves the overlap; a pickup always finds a
/// durable certificate. Every refusal in here signs nothing and leaves
/// the pending entry untouched.
pub fn issue_certificate(
    runner: &dyn CommandRunner,
    home: &Path,
    entry: &PendingIdentity,
    validity: &str,
    now_epoch: u64,
) -> miette::Result<IssuedIdentity> {
    // The CA must exist with BOTH halves: issuance signs with the
    // private half; the fingerprint (which root vouches) rides the
    // issued record.
    let ca = crate::ca::inspect(runner, home)?.ok_or_else(|| {
        miette::miette!(
            "issue: no host CA at {} — run 'shuttle ca keygen' first; issuance signs with \
             its private half (ADR-0045 amendment)",
            crate::ca::ca_secret_path(home).display()
        )
    })?;
    if !ca.secret_present {
        return Err(miette::miette!(
            "issue: the host CA's private half {} is missing — its fingerprint is known but \
             nothing can be signed; restore the keypair or re-key with 'shuttle ca keygen --force'",
            crate::ca::ca_secret_path(home).display()
        ));
    }

    // Defense at the trust boundary: the pending store is on-disk state
    // a crash or tamper could have mangled — re-check the key grammar
    // before putting it in front of ssh-keygen.
    crate::lua::validate_host_key(&entry.public_key).map_err(|e| {
        miette::miette!(
            "issue: pending entry for '{}' carries a malformed public key — refusing to sign \
             it: {e}",
            entry.machine_identity
        )
    })?;
    let principals = cert_principals(&entry.machine_identity, &entry.instance_identity)?;
    let validity = parse_cert_validity(validity)?;

    // Scratch public-key file; ssh-keygen writes the certificate to the
    // `<input>-cert.pub` sibling. Both are cleaned up; the published
    // half is public material but never lingers coordinator-side.
    let tmp = tempfile::NamedTempFile::new()
        .map_err(|e| miette::miette!("issue: cannot stage the public key: {e}"))?;
    std::fs::write(tmp.path(), format!("{}\n", entry.public_key))
        .map_err(|e| miette::miette!("issue: cannot write {}: {e}", tmp.path().display()))?;
    let pub_str = tmp.path().to_string_lossy().into_owned();
    let cert_path = tmp
        .path()
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(
            "{}-cert.pub",
            tmp.path().file_name().unwrap_or_default().to_string_lossy()
        ));

    let argv = vec![
        "ssh-keygen".to_string(),
        "-s".to_string(),
        crate::ca::ca_secret_path(home)
            .to_string_lossy()
            .into_owned(),
        "-h".to_string(),
        "-I".to_string(),
        entry.machine_identity.clone(),
        "-n".to_string(),
        principals.join(","),
        "-V".to_string(),
        validity.clone(),
        pub_str,
    ];
    let out = runner.run(&argv).map_err(|e| {
        miette::miette!("issue: cannot run ssh-keygen (is openssh installed?): {e}")
    })?;
    if crate::command::exit_code(&out) != 0 {
        return Err(miette::miette!(
            "issue: ssh-keygen refused to sign '{}' (principals {}): {}",
            entry.machine_identity,
            principals.join(","),
            out.stderr.trim()
        ));
    }
    let cert = std::fs::read_to_string(&cert_path)
        .map_err(|e| {
            miette::miette!(
                "issue: ssh-keygen reported success but produced no certificate at {}: {e}",
                cert_path.display()
            )
        })?
        .trim()
        .to_string();
    let _ = std::fs::remove_file(&cert_path);

    let issued = IssuedIdentity {
        machine_identity: entry.machine_identity.clone(),
        public_key: entry.public_key.clone(),
        instance_identity: entry.instance_identity.clone(),
        received_at_epoch: entry.received_at_epoch,
        token_sha256: entry.token_sha256.clone(),
        cert,
        principals,
        validity,
        issued_at_epoch: now_epoch,
        ca_fingerprint: ca.fingerprint,
    };
    persist_issued(home, &issued)?;
    // Issued record durable → the pending entry leaves the intake queue.
    // Absent is fine (a --force re-issue runs from the issued record —
    // there is no pending entry anymore); present-but-unremovable is a
    // named error, because the overlap is state the operator must see.
    let pending_path = pending_dir(home).join(format!("pending-{}.json", entry.machine_identity));
    if pending_path.exists() {
        if let Err(e) = std::fs::remove_file(&pending_path) {
            return Err(miette::miette!(
                "issue: certificate for '{}' is issued and durable, but the pending entry {} \
                 could not be removed: {e}",
                entry.machine_identity,
                pending_path.display()
            ));
        }
    }
    Ok(issued)
}

/// Install an issued record: the 0700 `issued/` dir, the record 0600 —
/// the same hygiene as the pending store (the record is public material
/// plus audit content, but it lives under the CA's dedicated root).
fn persist_issued(home: &Path, issued: &IssuedIdentity) -> miette::Result<()> {
    let dir = issued_dir(home);
    std::fs::create_dir_all(&dir)
        .map_err(|e| miette::miette!("publish: cannot create {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let text = serde_json::to_string_pretty(issued)
        .map_err(|e| miette::miette!("publish: cannot serialize the issued record: {e}"))?;
    atomic_write_0600(
        &issued_path(home, &issued.machine_identity),
        &format!("{text}\n"),
    )
}

/// The outcome of one issuance run: what was signed, and what was
/// deliberately left alone (already issued, `--force` not given).
#[derive(Debug, Default)]
pub struct IssueReport {
    pub issued: Vec<IssuedIdentity>,
    pub skipped: Vec<String>,
}

/// Issue certificates for pending identities. With `identity`, exactly
/// that machine is processed (absent pending + absent issued → named
/// refusal; already issued → named refusal unless `force`). Without,
/// every pending entry is processed and already-issued ones are skipped
/// with a report — a batch never hard-fails on identities it was not
/// asked about.
pub fn issue_identities(
    runner: &dyn CommandRunner,
    home: &Path,
    identity: Option<&str>,
    validity: &str,
    force: bool,
    now_epoch: u64,
) -> miette::Result<IssueReport> {
    let mut report = IssueReport::default();
    let Some(name) = identity else {
        for entry in pending_identities(home)? {
            match issued_entry(home, &entry.machine_identity)? {
                Some(_) if !force => report.skipped.push(entry.machine_identity),
                _ => report.issued.push(issue_certificate(
                    runner, home, &entry, validity, now_epoch,
                )?),
            }
        }
        return Ok(report);
    };

    let entry = match pending_entry(home, name)? {
        Some(entry) => Some(entry),
        None => issued_entry(home, name)?.map(|rec| PendingIdentity {
            machine_identity: rec.machine_identity,
            public_key: rec.public_key,
            instance_identity: rec.instance_identity,
            received_at_epoch: rec.received_at_epoch,
            token_sha256: rec.token_sha256,
        }),
    };
    let Some(entry) = entry else {
        return Err(miette::miette!(
            "issue: no pending identity named '{name}' — nothing was published under that \
             machine identity (the pending store lists what issuance can sign)"
        ));
    };
    if !force && issued_entry(home, name)?.is_some() {
        return Err(miette::miette!(
            "issue: '{name}' is already issued — pickup serves its certificate; pass --force \
             to re-issue (the previous certificate stays valid until its own expiry: SSH host \
             certs have no revocation list)"
        ));
    }
    report.issued.push(issue_certificate(
        runner, home, &entry, validity, now_epoch,
    )?);
    Ok(report)
}

/// The pickup half of the publish channel: the guest GETs the callback
/// URL with the SAME one-time bearer it published under and receives its
/// host certificate (`shuttle workers pickup` is the transport binding
/// a TLS-terminating front drives, symmetric with `receive-publish`).
/// Pickup is an idempotent READ — the guest polls until the coordinator
/// signs — and it never mutates state: the one-time-ness of the PUBLISH
/// is untouched (the token was consumed at intake; replayed publishes
/// still refuse). A leaked bearer after pickup buys a read of one public
/// certificate — public material by definition — and stops working at
/// the token TTL.
pub fn pickup_certificate(
    home: &Path,
    bearer: &str,
    now_epoch: u64,
) -> miette::Result<IssuedIdentity> {
    let bearer = bearer.trim();
    if bearer.len() != TOKEN_BYTES * 2 || !bearer.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(miette::miette!(
            "pickup: malformed publish token (expected 64 hex chars) — refusing"
        ));
    }
    let fingerprint = token_fingerprint(bearer);
    let registry = load_registry(home)?;
    let record = registry
        .tokens
        .iter()
        .find(|t| t.token_sha256 == fingerprint)
        .ok_or_else(|| {
            miette::miette!(
                "pickup: unknown publish token — never issued by this coordinator; refusing"
            )
        })?;
    if now_epoch.saturating_sub(record.issued_at_epoch) > PUBLISH_TOKEN_TTL_SECS {
        return Err(miette::miette!(
            "pickup: expired publish token — the pickup window closed more than \
             {PUBLISH_TOKEN_TTL_SECS}s after issuance (machine identity '{}'); the guest can no \
             longer fetch its certificate and the TTL sweep reclaims the worker — fail-closed",
            record.machine_identity
        ));
    }
    if record.consumed_at_epoch.is_none() {
        return Err(miette::miette!(
            "pickup: nothing to pick up — this token never completed a publish (no pending \
             entry was stored); refusing"
        ));
    }
    let identity = &record.machine_identity;
    let issued = issued_entry(home, identity)?.ok_or_else(|| {
        miette::miette!(
            "pickup: '{identity}' has no issued certificate yet — the coordinator has not \
             signed it; the guest retries"
        )
    })?;
    if issued.token_sha256 != fingerprint {
        return Err(miette::miette!(
            "pickup: the issued record for '{identity}' does not match this token — refusing"
        ));
    }
    Ok(issued)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::RunnerOutput;
    use std::io;
    use std::sync::{Arc, Mutex};

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

    // ── Certificate issuance (sub-task 3) ──

    /// The CA halves as the fake harness sees them: the public half is a
    /// real-looking line on disk (`inspect` fingerprints it), the secret
    /// half just has to exist.
    const CA_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOrZfC0rKJdBX8mUJIKdClRNKdVKmShWU8rjHfDrBKUM shuttle-host-ca";
    const CA_FPR: &str = "SHA256:CAFAKE";

    fn ca_on_disk(home: &Path) {
        std::fs::create_dir_all(crate::ca::ca_dir(home)).unwrap();
        std::fs::write(crate::ca::ca_secret_path(home), "test-ca-secret").unwrap();
        std::fs::write(crate::ca::ca_public_path(home), format!("{CA_PUB}\n")).unwrap();
    }

    /// The full intake flow up to issuance: mint + record a token, then
    /// receive the fixture publish for `identity`.
    fn enrolled_and_published(home: &Path, identity: &str) -> String {
        let token = mint_publish_token().unwrap();
        record_issue(home, &token, identity, 1_000_000).unwrap();
        receive_publish(home, &token, &payload_bytes(identity), 1_000_030).unwrap();
        token
    }

    /// Plays `ssh-keygen` for issuance: answers `-lf` from the on-disk
    /// CA public half, plays `-s` by writing the `<input>-cert.pub`
    /// sibling with a per-call distinguishable certificate line, and
    /// records every argv.
    #[derive(Clone)]
    struct FakeSigner {
        calls: Arc<Mutex<Vec<Vec<String>>>>,
        sign_calls: Arc<Mutex<usize>>,
        fail_sign_at: Arc<Mutex<Option<usize>>>,
    }

    impl FakeSigner {
        fn new() -> Self {
            FakeSigner {
                calls: Arc::new(Mutex::new(Vec::new())),
                sign_calls: Arc::new(Mutex::new(0)),
                fail_sign_at: Arc::new(Mutex::new(None)),
            }
        }

        fn fail_sign_at(&self, n: usize) {
            *self.fail_sign_at.lock().unwrap() = Some(n);
        }

        fn argvs(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandRunner for FakeSigner {
        fn run(&self, argv: &[String]) -> io::Result<RunnerOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            if let Some(i) = argv.iter().position(|a| a == "-lf") {
                let text = std::fs::read_to_string(&argv[i + 1]).unwrap();
                let fpr = if text.contains("shuttle-host-ca") {
                    CA_FPR
                } else {
                    "SHA256:OTHER"
                };
                return Ok(ok_out(&format!("256 {fpr} shuttle-host-ca (ED25519)\n")));
            }
            if argv.iter().any(|a| a == "-s") {
                let mut n = self.sign_calls.lock().unwrap();
                let k = *n;
                *n += 1;
                drop(n);
                if self.fail_sign_at.lock().unwrap().is_some_and(|f| k >= f) {
                    return Ok(RunnerOutput {
                        code: 1,
                        stdout: vec![],
                        stderr: "scripted sign failure".into(),
                    });
                }
                let input = argv.last().unwrap();
                std::fs::write(
                    format!("{input}-cert.pub"),
                    format!("fake-cert-{}\n", k + 1),
                )
                .unwrap();
                return Ok(ok_out(""));
            }
            panic!("unexpected program in test: {argv:?}")
        }
    }

    /// A runner that must NEVER be called — refusal paths prove no
    /// subprocess runs before the trust checks pass.
    struct NeverRunner;
    impl CommandRunner for NeverRunner {
        fn run(&self, argv: &[String]) -> io::Result<RunnerOutput> {
            panic!("no subprocess may run on a refusal path: {argv:?}")
        }
    }

    fn ok_out(stdout: &str) -> RunnerOutput {
        RunnerOutput {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: String::new(),
        }
    }

    fn enroll_with_ca(home: &Path, identity: &str) -> String {
        ca_on_disk(home);
        enrolled_and_published(home, identity)
    }

    #[test]
    fn issue_signs_via_ssh_keygen_with_the_host_argv_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        enroll_with_ca(home, IDENTITY);
        let fake = FakeSigner::new();

        let report = issue_identities(&fake, home, None, "+48h", false, 1_000_100).unwrap();
        assert_eq!(report.issued.len(), 1);

        let argvs = fake.argvs();
        let sign = argvs
            .iter()
            .find(|a| a.contains(&"-s".to_string()))
            .expect("ssh-keygen -s ran");
        assert_eq!(sign[0], "ssh-keygen");
        assert!(sign.contains(&"-h".to_string()), "host cert: {sign:?}");
        assert!(sign.windows(2).any(|w| w == ["-I", IDENTITY]), "{sign:?}");
        assert!(
            sign.windows(2).any(|w| w == ["-V", "+48h"]),
            "validity rides -V: {sign:?}"
        );
        let i = sign.iter().position(|a| a == "-s").unwrap();
        assert_eq!(
            Path::new(&sign[i + 1]),
            crate::ca::ca_secret_path(home),
            "-s targets the contract CA secret"
        );
        // Principals: machine identity FIRST, then the fixture's
        // instance-identity content in fixed field order (hostname is
        // deliberately not bound).
        assert!(
            sign.windows(2)
                .any(|w| w == ["-n", "shuttle-worker-abc123-01,i-123,hetzner,hel1"]),
            "principal binding: {sign:?}"
        );
        let input = sign.last().unwrap();
        assert!(!Path::new(input).exists(), "scratch public half cleaned up");
        assert!(
            !Path::new(&format!("{input}-cert.pub")).exists(),
            "certificate sibling cleaned up"
        );
    }

    #[test]
    fn cert_principals_bind_machine_and_instance_identity_in_fixed_order() {
        let nested = serde_json::json!({
            "v1": {
                "instance_id": "i-9",
                "cloud_name": "aws",
                "region": "eu-central-1",
                "availability_zone": "eu-central-1a",
                "hostname": "ip-10-0-0-1",
                "local_hostname": "ip-10-0-0-1.internal",
            }
        });
        assert_eq!(
            cert_principals("shuttle-worker-x", &nested).unwrap(),
            vec![
                "shuttle-worker-x",
                "i-9",
                "aws",
                "eu-central-1",
                "eu-central-1a"
            ],
            "fixed field order; addresses are not identity"
        );
        // A flat document binds too, and a value equal to the machine
        // identity is deduplicated away.
        let flat = serde_json::json!({ "instance_id": "shuttle-worker-x", "region": "r1" });
        assert_eq!(
            cert_principals("shuttle-worker-x", &flat).unwrap(),
            vec!["shuttle-worker-x", "r1"]
        );
        // No instance-identity content at all → named refusal.
        let err = cert_principals("shuttle-worker-x", &serde_json::json!({"v1": {}})).unwrap_err();
        assert!(
            format!("{err:#}").contains("no instance-identity content"),
            "{err:#}"
        );
        // A principal-hostile value is refused, never bound.
        let err = cert_principals(
            "shuttle-worker-x",
            &serde_json::json!({"v1": {"region": "eu central"}}),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("not a usable certificate principal"),
            "{err:#}"
        );
    }

    #[test]
    fn issue_refuses_without_a_ca_and_signs_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        enrolled_and_published(home, IDENTITY);

        let err = issue_identities(&NeverRunner, home, None, "+48h", false, 1_000_100).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no host CA"), "{msg}");
        assert!(msg.contains("ca keygen"), "names the mint verb: {msg}");
        assert!(
            pending_entry(home, IDENTITY).unwrap().is_some(),
            "the pending entry survives a refusal"
        );
    }

    #[test]
    fn issue_refuses_with_only_the_ca_public_half() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        enroll_with_ca(home, IDENTITY);
        std::fs::remove_file(crate::ca::ca_secret_path(home)).unwrap();

        // inspect() fingerprints the public half (a legitimate -lf run);
        // the refusal must still fire BEFORE any signing (-s) happens.
        let fake = FakeSigner::new();
        let err = issue_identities(&fake, home, None, "+48h", false, 1_000_100).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("private half"), "{msg}");
        assert!(
            msg.contains(&crate::ca::ca_secret_path(home).display().to_string()),
            "names the missing half: {msg}"
        );
        assert!(
            !fake.argvs().iter().any(|a| a.contains(&"-s".to_string())),
            "nothing was signed"
        );
    }

    #[test]
    fn already_issued_identity_is_a_named_refusal_unless_forced() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        enroll_with_ca(home, IDENTITY);
        let fake = FakeSigner::new();
        issue_identities(&fake, home, Some(IDENTITY), "+48h", false, 1_000_100).unwrap();

        // Pending is gone but the issued record stands: a plain re-issue
        // is refused BY NAME (pickup serves the cert).
        let err = issue_identities(
            &FakeSigner::new(),
            home,
            Some(IDENTITY),
            "+48h",
            false,
            1_000_200,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("already issued"), "{msg}");
        assert!(msg.contains("--force"), "{msg}");
        assert!(msg.contains("pickup"), "{msg}");

        // --force re-signs the SAME published key (new cert, fresh
        // record).
        let report =
            issue_identities(&fake, home, Some(IDENTITY), "+48h", true, 1_000_200).unwrap();
        assert_eq!(report.issued.len(), 1);
        assert_eq!(report.issued[0].cert, "fake-cert-2", "a fresh signature");
    }

    #[test]
    fn force_reissues_from_the_issued_record_after_pending_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        enroll_with_ca(home, IDENTITY);
        let fake = FakeSigner::new();
        issue_identities(&fake, home, Some(IDENTITY), "+48h", false, 1_000_100).unwrap();
        assert!(pending_entry(home, IDENTITY).unwrap().is_none());

        // The re-issue consumes no pending entry — the audit record
        // carries the published key forward.
        let report =
            issue_identities(&fake, home, Some(IDENTITY), "+2d12h", true, 1_000_200).unwrap();
        assert_eq!(report.issued[0].validity, "+2d12h");
        assert_eq!(
            issued_entry(home, IDENTITY).unwrap().unwrap().public_key,
            FIXTURE_PUB,
            "same published key, new certificate"
        );
        assert!(pending_entry(home, IDENTITY).unwrap().is_none());
    }

    #[test]
    fn issue_refuses_a_corrupt_pending_entry() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        ca_on_disk(home);
        std::fs::create_dir_all(pending_dir(home)).unwrap();
        std::fs::write(
            pending_dir(home).join(format!("pending-{IDENTITY}.json")),
            "{ not json",
        )
        .unwrap();

        let err = issue_identities(
            &FakeSigner::new(),
            home,
            Some(IDENTITY),
            "+48h",
            false,
            1_000_100,
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("corrupt"),
            "named refusal: {err:#}"
        );
    }

    #[test]
    fn a_failed_sign_leaves_the_pending_entry_and_no_issued_record() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        enroll_with_ca(home, IDENTITY);
        let fake = FakeSigner::new();
        fake.fail_sign_at(0);

        let err = issue_identities(&fake, home, None, "+48h", false, 1_000_100).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("refused to sign"), "{msg}");
        assert!(
            msg.contains("scripted sign failure"),
            "carries stderr: {msg}"
        );
        assert!(
            pending_entry(home, IDENTITY).unwrap().is_some(),
            "the identity stays pending — the operator re-runs issue"
        );
        assert!(issued_entry(home, IDENTITY).unwrap().is_none());
    }

    #[test]
    fn validity_grammar_is_capped_to_short_lived_relative_forms() {
        for ok in ["+48h", "+30m", "+2d", "+1w", "+90s", "+2d12h"] {
            assert_eq!(
                parse_cert_validity(ok).unwrap().as_str(),
                ok,
                "{ok} is a legal short-lived window"
            );
        }
        for bad in [
            "48h", "forever", "always", "+0h", "+4x", "", "20260101", "+", "+h", "+1h+",
        ] {
            let err = parse_cert_validity(bad).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("short-lived") && msg.contains("relative"),
                "'{bad}' must be a named refusal: {msg}"
            );
        }
    }

    #[test]
    fn pending_to_issued_lifecycle_keeps_the_full_audit_trail() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let token = enroll_with_ca(home, IDENTITY);

        issue_identities(&FakeSigner::new(), home, None, "+48h", false, 1_000_100).unwrap();

        assert!(
            pending_identities(home).unwrap().is_empty(),
            "the issued identity leaves the intake queue"
        );
        let records = issued_identities(home).unwrap();
        assert_eq!(records.len(), 1);
        let rec = &records[0];
        assert_eq!(rec.machine_identity, IDENTITY);
        assert_eq!(rec.public_key, FIXTURE_PUB);
        assert!(rec.instance_identity.get("v1").is_some());
        assert_eq!(rec.received_at_epoch, 1_000_030, "intake time preserved");
        assert_eq!(rec.token_sha256, token_fingerprint(&token));
        assert_eq!(
            rec.principals,
            vec!["shuttle-worker-abc123-01", "i-123", "hetzner", "hel1"]
        );
        assert_eq!(rec.validity, "+48h");
        assert_eq!(rec.issued_at_epoch, 1_000_100);
        assert_eq!(rec.ca_fingerprint, CA_FPR, "which root vouches");
        assert_eq!(rec.cert, "fake-cert-1");

        let mode = std::fs::metadata(issued_dir(home))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "the issued store lives behind 0700");
        let mode = std::fs::metadata(issued_dir(home).join(format!("issued-{IDENTITY}.json")))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn pickup_serves_the_cert_under_the_same_token_and_stays_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let token = enroll_with_ca(home, IDENTITY);
        issue_identities(&FakeSigner::new(), home, None, "+48h", false, 1_000_100).unwrap();

        let got = pickup_certificate(home, &token, 1_000_110).unwrap();
        assert_eq!(got.cert, "fake-cert-1");
        assert_eq!(
            pickup_certificate(home, &token, 1_000_120).unwrap().cert,
            "fake-cert-1",
            "pickup is an idempotent read — the guest polls"
        );

        // Malformed and unknown bearers are named refusals.
        let err = pickup_certificate(home, "zz", 1_000_110).unwrap_err();
        assert!(
            format!("{err:#}").contains("malformed publish token"),
            "{err:#}"
        );
        let err = pickup_certificate(home, &"f".repeat(64), 1_000_110).unwrap_err();
        assert!(
            format!("{err:#}").contains("unknown publish token"),
            "{err:#}"
        );

        // A token that never completed a publish has nothing to pick up.
        let virgin = mint_publish_token().unwrap();
        record_issue(home, &virgin, "shuttle-worker-abc123-02", 1_000_000).unwrap();
        let err = pickup_certificate(home, &virgin, 1_000_110).unwrap_err();
        assert!(
            format!("{err:#}").contains("never completed a publish"),
            "{err:#}"
        );

        // Published but not yet signed → the retryable refusal.
        let token3 = enrolled_and_published(home, "shuttle-worker-abc123-02");
        let err = pickup_certificate(home, &token3, 1_000_110).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no issued certificate yet"), "{msg}");
        assert!(msg.contains("retries"), "{msg}");

        // Past the token TTL the pickup window closes too.
        let err =
            pickup_certificate(home, &token, 1_000_000 + PUBLISH_TOKEN_TTL_SECS + 1).unwrap_err();
        assert!(
            format!("{err:#}").contains("expired publish token"),
            "{err:#}"
        );
    }

    #[test]
    fn batch_issue_processes_every_pending_and_reports_skips() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        enroll_with_ca(home, "shuttle-worker-abc123-01");
        enroll_with_ca(home, "shuttle-worker-abc123-02");

        let report =
            issue_identities(&FakeSigner::new(), home, None, "+48h", false, 1_000_100).unwrap();
        assert_eq!(report.issued.len(), 2);
        assert!(report.skipped.is_empty());
        assert!(pending_identities(home).unwrap().is_empty());

        // Crash-window overlap: the pending entry re-appears while the
        // issued record already stands (the write-issued-then-remove-
        // pending ordering makes this the only possible torn state).
        let rec = issued_entry(home, "shuttle-worker-abc123-01")
            .unwrap()
            .unwrap();
        let torn = PendingIdentity {
            machine_identity: rec.machine_identity.clone(),
            public_key: rec.public_key.clone(),
            instance_identity: rec.instance_identity.clone(),
            received_at_epoch: rec.received_at_epoch,
            token_sha256: rec.token_sha256.clone(),
        };
        std::fs::create_dir_all(pending_dir(home)).unwrap();
        std::fs::write(
            pending_dir(home).join("pending-shuttle-worker-abc123-01.json"),
            serde_json::to_string_pretty(&torn).unwrap(),
        )
        .unwrap();

        // Without --force the batch SKIPS the issued one (never
        // re-signs behind the operator's back)…
        let report =
            issue_identities(&FakeSigner::new(), home, None, "+48h", false, 1_000_200).unwrap();
        assert!(report.issued.is_empty());
        assert_eq!(report.skipped, vec!["shuttle-worker-abc123-01"]);
        // …and --force re-issues it.
        let report =
            issue_identities(&FakeSigner::new(), home, None, "+48h", true, 1_000_200).unwrap();
        assert_eq!(report.issued.len(), 1);
        assert_eq!(
            report.issued[0].machine_identity,
            "shuttle-worker-abc123-01"
        );
        assert!(pending_identities(home).unwrap().is_empty());
    }
}

#[cfg(test)]
mod link_tests {
    use super::*;

    #[test]
    fn machine_link_round_trips_by_address_slug() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let address = "ssh://root@203.0.113.9";
        let path = record_machine_link(home, "shuttle-worker-x-01", address).unwrap();
        assert_eq!(
            path,
            machines_dir(home).join(format!(
                "machine-{}.json",
                crate::oci::sha256_hex(address.as_bytes())[..16].to_string()
            ))
        );
        let link = machine_link(home, address).unwrap().expect("linked");
        assert_eq!(link.machine_identity, "shuttle-worker-x-01");
        assert_eq!(link.address, address);
        // A differently-formed address is a different worker: no link.
        assert!(machine_link(home, "ssh://root@203.0.113.10")
            .unwrap()
            .is_none());
    }

    #[test]
    fn machine_link_refuses_malformed_identity_or_address() {
        let dir = tempfile::tempdir().unwrap();
        let err = record_machine_link(dir.path(), "bad identity!", "ssh://root@203.0.113.9")
            .unwrap_err()
            .to_string();
        assert!(err.contains("shuttle server name"), "{err}");
        let err = record_machine_link(dir.path(), "shuttle-worker-x-01", "ssh://ro ot@h")
            .unwrap_err()
            .to_string();
        assert!(err.contains("malformed address"), "{err}");
        // Nothing was written on refusal.
        assert!(!machines_dir(dir.path()).exists());
    }

    #[test]
    fn machine_link_corrupt_record_is_a_named_refusal_not_a_guess() {
        let dir = tempfile::tempdir().unwrap();
        let address = "ssh://root@203.0.113.9";
        record_machine_link(dir.path(), "shuttle-worker-x-01", address).unwrap();
        let path = machine_link_path(dir.path(), address);
        std::fs::write(&path, "{not json").unwrap();
        let err = machine_link(dir.path(), address).unwrap_err().to_string();
        assert!(err.contains("corrupt"), "{err}");
        assert!(err.contains("refusing to guess"), "{err}");
    }
}
