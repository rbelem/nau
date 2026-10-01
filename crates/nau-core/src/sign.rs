//! The signing keychain — generic trust machinery (issue #326 PR 3
//! down-move; ADR-0051's "sign" spine slice).
//!
//! Ed25519 key material, the on-disk key layout, the trust-anchor
//! keychain, the local revocation list, and the key-ceremony ledger:
//! every domain that signs or trusts names these (image verify, the pod
//! install gate, the chart manifest ceremony). The EVAL-manifest
//! ceremony (provenance envelopes, cosign/rotate/revoke over
//! `nau_chart::manifest::ImageManifest`) and the OpenPGP sysupdate half
//! stay in the root `sign` module, which re-exports everything here —
//! every pre-existing `crate::sign::` path keeps resolving.

use std::path::{Path, PathBuf};

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use miette::{IntoDiagnostic, WrapErr};

use crate::manifest_ir::ManifestInput;

/// The sysupdate pubring fragment for `key_id`, under the keys dir.
/// `pub` — the root sysupdate half reads/writes fragments too; the
/// local-revocation path removes it (both halves share the layout).
pub fn sysupdate_fragment_path(keys_dir: &Path, key_id: &str) -> PathBuf {
    keys_dir.join(format!("{key_id}.pgp"))
}

/// Untrusted-comment header on the secret key file.
const SECRET_COMMENT: &str = "untrusted comment: nau signing secret key (ed25519)";

/// Untrusted-comment header on embedded public keys.
pub const PUBLIC_COMMENT: &str = "untrusted comment: nau update public key (ed25519)";

/// Public key file embedded into image builds when signing is engaged.
pub const PUBKEY_EMBED_PATH: &str = "etc/nau/update-key.pub";

/// Trusted-key-set directory embedded into image builds (ADR-0024 §4).
/// Every `<key-id>.pub` in it is an anchor the device-side verify path
/// accepts. The current signing key is also copied to
/// [`PUBKEY_EMBED_PATH`] for backward compatibility with anchors that
/// predate the trust-set shape.
pub const TRUSTED_KEYS_EMBED_DIR: &str = "etc/nau/trusted-keys";

/// Revocation list embedded into image builds (ADR-0024 §4): one key id
/// per line. A device-side verifier consults it so "revoked" is
/// distinguishable from "never trusted".
pub const REVOKED_KEYS_EMBED_PATH: &str = "etc/nau/revoked-keys";

/// Secret key location under the user's home (`~/.config/nau/`).
pub fn secret_key_path(home: &Path) -> PathBuf {
    home.join(".config").join("nau").join("secret-key")
}

/// Rotation successor secret location under `home`
/// (`~/.config/nau/secret-key.new`, 0600): minted by rotation, moved
/// into place by promotion.
pub fn rotation_key_path(home: &Path) -> PathBuf {
    home.join(".config").join("nau").join("secret-key.new")
}

/// An Ed25519 signing key pair: the seed and its derived public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    pub seed: [u8; 32],
    pub public: [u8; 32],
}

impl KeyPair {
    /// Short public identifier for the signatures map — the first 16 hex
    /// chars of the public key.
    pub fn key_id(&self) -> String {
        to_hex(&self.public)[..16].to_string()
    }

    /// Lowercase hex of the public key (the on-disk pubkey payload).
    pub fn public_hex(&self) -> String {
        to_hex(&self.public)
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }
}

/// Sign `bytes` and return the base64 signature string stored in the
/// signatures map.
pub fn sign_bytes(bytes: &[u8], kp: &KeyPair) -> String {
    let sig = kp.signing_key().sign(bytes);
    base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
}

/// with a named error — rotation is step (e) ceremony, never an accident.
pub fn create_secret_key(home: &Path) -> miette::Result<KeyPair> {
    let path = secret_key_path(home);
    if path.exists() {
        return Err(miette::miette!(
            "signing key already exists at {} — refusing to overwrite (rotation is a \
             deliberate ceremony, not a side effect)",
            path.display()
        ));
    }
    let seed = read_urandom32()?;
    let kp = derive_pair(&seed);
    write_secret_key_at(&path, &kp)?;
    eprintln!("  ✓ signing key created: {}", path.display());
    Ok(kp)
}

/// Load the secret key under `home`. `Ok(None)` when absent — signing is
/// opt-in (step (d)); a present-but-unparseable key is a named error.
pub fn load_secret_key(home: &Path) -> miette::Result<Option<KeyPair>> {
    let path = secret_key_path(home);
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", path.display()))?;
    parse_secret_key(&text)
        .map(Some)
        .wrap_err_with(|| format!("parsing {}", path.display()))
}

/// Serialize the public key for embedding (`/etc/nau/update-key.pub`)
/// and for trust-anchor files (`~/.config/nau/keys/<key-id>.pub`).
pub fn public_key_file(kp: &KeyPair) -> String {
    format!("{}\n{}\n", PUBLIC_COMMENT, kp.public_hex())
}

// ── Key ceremony (ADR-0011 step (e)): keychain, rotation, revocation ──
//
// Paths (documented contract — `nau key keygen|rotate|promote|revoke|
// list|verify` is the operator surface, the device half consumes the
// embedded copies from the image build):
//
// - Secret key:            `~/.config/nau/secret-key`   (0600)
// - Rotation secret:       `~/.config/nau/secret-key.new` (0600)
// - Trusted public keys:   `~/.config/nau/keys/<key-id>.pub`
//   (every `*.pub` file is a trust anchor; same two-line format as the
//   embedded `/etc/nau/update-key.pub`).
// - Ceremony ledger:       `~/.config/nau/keys/ceremony.json` — the
//   audit trail (issue #51): created/rotated/revoked dates and the
//   generation chain (key id → replaced-by → date → window). The
//   ceremony as a first-class thing, not just the crypto.

/// Trusted public-key directory under the user's home:
/// `~/.config/nau/keys/`.
pub fn keys_dir(home: &Path) -> PathBuf {
    home.join(".config").join("nau").join("keys")
}

/// A set of trusted public keys (the verification trust anchors).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Keychain {
    /// (key id, public key) pairs, in file order — order-insensitive at
    /// verify time (ANY trusted signature verifies). `pub` because the
    /// root ceremony's multi-key verify walks the loaded chain (the
    /// envelope machinery stayed root with the provenance half).
    pub entries: Vec<(String, [u8; 32])>,
}

impl Keychain {
    /// Load every `*.pub` file in `dir` as a trust anchor. A missing
    /// directory is an empty chain (verify fails closed); a present but
    /// unparseable anchor is a named error — corrupt trust anchors are
    /// never silently skipped.
    pub fn load_dir(dir: &Path) -> miette::Result<Keychain> {
        let mut chain = Keychain::default();
        let Ok(read) = std::fs::read_dir(dir) else {
            return Ok(chain);
        };
        let mut paths: Vec<PathBuf> = Vec::new();
        for entry in read {
            let entry = entry
                .into_diagnostic()
                .wrap_err_with(|| format!("reading {}", dir.display()))?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "pub") {
                paths.push(path);
            }
        }
        paths.sort();
        for path in paths {
            let (key_id, public) = parse_pub_file(&path)?;
            chain.entries.push((key_id, public));
        }
        Ok(chain)
    }

    /// Load ONE public-key file as a trust anchor — the legacy
    /// single-anchor shape (`/etc/nau/update-key.pub`) that predates
    /// the trusted-keys directory. Anchor walkers treat `Err` as "no
    /// legacy anchor here" (the runtime's best-effort fallback), so the
    /// error is a miss, never a silent trust grant.
    pub fn load_pub_file(path: &Path) -> miette::Result<Keychain> {
        let (key_id, public) = parse_pub_file(path)?;
        Ok(Keychain {
            entries: vec![(key_id, public)],
        })
    }

    /// Merge `other`'s anchors into `self`: the anchor walk verifies
    /// over the UNION of the device image-baked set and the operator
    /// keychain, so one merged chain feeds one strict verifier.
    pub fn merge(&mut self, other: Keychain) {
        self.entries.extend(other.entries);
    }

    /// True when no trust anchors are loaded — verification under an
    /// empty chain always fails closed.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The trusted key ids.
    pub fn key_ids(&self) -> Vec<String> {
        self.entries.iter().map(|(id, _)| id.clone()).collect()
    }

    /// (key id, public key) pairs for callers that verify entry-by-entry
    /// outside [`verify_keychain`]'s all-or-nothing message (the device
    /// path tries the embedded set, the legacy anchor, then the operator
    /// keychain).
    pub fn entries_for_verify(&self) -> Vec<(String, [u8; 32])> {
        self.entries.clone()
    }
}

/// Parse one public-key file (the two-line anchor format: an optional
/// `untrusted comment:` line, then the 64-hex public key). The single
/// parser behind [`Keychain::load_dir`] and [`Keychain::load_pub_file`].
fn parse_pub_file(path: &Path) -> miette::Result<(String, [u8; 32])> {
    let text = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", path.display()))?;
    let public_hex = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
        .ok_or_else(|| {
            miette::miette!("public key file {} carries no key material", path.display())
        })?;
    let public = from_hex32(public_hex).wrap_err_with(|| format!("parsing {}", path.display()))?;
    Ok((to_hex(&public)[..16].to_string(), public))
}

/// Install a public key into `dir` as `<key-id>.pub` (the trust-anchor
/// ceremony step). Returns the written path.
pub fn install_public_key(kp: &KeyPair, dir: &Path) -> miette::Result<PathBuf> {
    std::fs::create_dir_all(dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", dir.display()))?;
    let path = dir.join(format!("{}.pub", kp.key_id()));
    std::fs::write(&path, public_key_file(kp))
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", path.display()))?;
    Ok(path)
}
pub fn revoke_local(dir: &Path, key_id: &str) -> miette::Result<()> {
    let pub_path = dir.join(format!("{key_id}.pub"));
    let listed = read_revoked_keys(dir)?.iter().any(|id| id == key_id);
    if !pub_path.exists() && !listed {
        return Err(miette::miette!(
            "cannot revoke {key_id}: no trust anchor at {} and it is not in the \
             revocation list",
            pub_path.display()
        ));
    }
    if pub_path.exists() {
        remove_anchor_and_fragment(dir, key_id)?;
    }
    if !listed {
        write_revoked_keys(dir, &{
            let mut ids = read_revoked_keys(dir)?;
            ids.push(key_id.to_string());
            ids
        })?;
    }
    eprintln!("  ✓ key {key_id} revoked: anchor removed, listed in revoked-keys");
    Ok(())
}

/// Remove a key's trust anchor and its sysupdate pubring fragment — a
/// revoked key never re-enters the trust set an image embeds (issue
/// #290). The fragment may be absent (pre-#290 keychains); the anchor
/// must exist (the caller checked).
fn remove_anchor_and_fragment(dir: &Path, key_id: &str) -> miette::Result<()> {
    let pub_path = dir.join(format!("{key_id}.pub"));
    std::fs::remove_file(&pub_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("removing {}", pub_path.display()))?;
    let fragment = sysupdate_fragment_path(dir, key_id);
    if fragment.exists() {
        std::fs::remove_file(&fragment)
            .into_diagnostic()
            .wrap_err_with(|| format!("removing {}", fragment.display()))?;
    }
    Ok(())
}

/// Read the `<dir>/revoked-keys` list (one key id per line). A missing
/// file is an empty list; malformed lines are named errors — a corrupt
/// revocation list must never be silently treated as empty.
pub fn read_revoked_keys(dir: &Path) -> miette::Result<Vec<String>> {
    let path = dir.join("revoked-keys");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(Vec::new());
    };
    let mut ids = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() != 16 || !line.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(miette::miette!(
                "revocation list {} line {} is not a 16-hex key id: {line:?}",
                path.display(),
                n + 1
            ));
        }
        ids.push(line.to_ascii_lowercase());
    }
    Ok(ids)
}

/// Write the `<dir>/revoked-keys` list, one key id per line, sorted and
/// deduplicated (deterministic for byte-stable images).
fn write_revoked_keys(dir: &Path, ids: &[String]) -> miette::Result<()> {
    std::fs::create_dir_all(dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", dir.display()))?;
    let mut ids: Vec<String> = ids.iter().map(|id| id.to_ascii_lowercase()).collect();
    ids.sort();
    ids.dedup();
    let body: String = ids.iter().map(|id| format!("{id}\n")).collect();
    let path = dir.join("revoked-keys");
    std::fs::write(&path, body)
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Reject a signature set made under any revoked key id. A signature
/// entry whose key id appears in `revoked` is a hard refusal BEFORE any
/// anchor check — "this key was trusted once and is trusted no longer"
/// must not be masked by a dual-signed manifest that a revoked key also
/// signed.
pub fn reject_revoked(
    signatures: &std::collections::BTreeMap<String, serde_json::Value>,
    revoked: &[String],
) -> miette::Result<()> {
    for key_id in revoked {
        if signatures.contains_key(key_id) {
            return Err(miette::miette!(
                "artifact carries a signature from REVOKED key id {key_id} — refusing to \
                 install (revoked keys are never trusted again)"
            ));
        }
    }
    Ok(())
}

// ── Ceremony ledger (issue #51, ADR-0011 §4e): the auditable key chain ──

/// Ceremony ledger schema version.
pub const CEREMONY_LEDGER_VERSION: u32 = 1;

/// Default overlap window, in days, recorded at rotation: how long a
/// rotated-out key's signatures stay first-class during the rollout of
/// its successor. Expired windows downgrade to a verify warning — the
/// artifact still verifies, the operator is told to re-sign.
pub const DEFAULT_WINDOW_DAYS: u32 = 30;

/// The ceremony ledger: `keys/ceremony.json` beside the trust anchors.
/// One entry per key the ceremony ever touched, carrying its dates and
/// its chain link (`replaced_by`), so a rotation/revocation is auditable
/// after the fact and [`verify_with_ledger`] can apply transition-window
/// policy. Every field is `#[serde(default)]`: ledgers written before a
/// field existed (and hand-minimal ones) keep parsing.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CeremonyLedger {
    #[serde(default)]
    pub version: u32,
    /// Key id → ceremony record, sorted for byte-stable rewrites.
    #[serde(default)]
    pub keys: std::collections::BTreeMap<String, LedgerEntry>,
}

/// One key's ceremony record (issue #51): when it was created, which key
/// replaced it and when (the generation chain), the overlap window that
/// rotation granted it, and when it was revoked. Absent fields are
/// genuinely unknown (e.g. revoking a key minted on another machine).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LedgerEntry {
    /// Lowercase hex of the public key (64 chars), when known. Load-time
    /// validation pins its 16-char prefix to the map key — a tampered
    /// entry whose material disagrees with its id is a named error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    /// RFC3339 UTC creation date (keygen).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// The successor key id this key was rotated out for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_by: Option<String>,

    /// RFC3339 UTC date the rotation was minted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<String>,

    /// Overlap window in days from `rotated_at`
    /// (default [`DEFAULT_WINDOW_DAYS`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_days: Option<u32>,

    /// RFC3339 UTC date the key was revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

/// The ledger file beside the trust anchors: `<keys-dir>/ceremony.json`.
pub fn ceremony_ledger_path(keys_dir: &Path) -> PathBuf {
    keys_dir.join("ceremony.json")
}

impl CeremonyLedger {
    /// Load `<keys-dir>/ceremony.json`. A missing file is an empty ledger
    /// (keychains predating the ceremony are valid state); anything
    /// present is validated — corrupt JSON, a bad date, a key-id
    /// prefix/material mismatch, a dangling chain link, or an unknown
    /// future version is a named error. Trust-adjacent bookkeeping fails
    /// closed, never silently skips.
    pub fn load(keys_dir: &Path) -> miette::Result<CeremonyLedger> {
        let path = ceremony_ledger_path(keys_dir);
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Ok(CeremonyLedger::default());
        };
        let ledger: CeremonyLedger = serde_json::from_str(&text).map_err(|e| {
            miette::miette!(
                "key ceremony ledger {} is corrupt: {e} — refusing to interpret it",
                path.display()
            )
        })?;
        ledger
            .validate()
            .wrap_err_with(|| format!("key ceremony ledger {}", path.display()))?;
        Ok(ledger)
    }

    /// Write the ledger back (sorted ids, deterministic bytes).
    pub fn save(&self, keys_dir: &Path) -> miette::Result<()> {
        std::fs::create_dir_all(keys_dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("creating {}", keys_dir.display()))?;
        let path = ceremony_ledger_path(keys_dir);
        let body = serde_json::to_string_pretty(self)
            .map_err(|e| miette::miette!("ledger serialization: {e}"))?;
        std::fs::write(&path, body + "\n")
            .into_diagnostic()
            .wrap_err_with(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    /// Record a freshly created key (keygen). An existing entry for the
    /// id is never overwritten — the first record of a key wins.
    pub fn record_created(&mut self, kp: &KeyPair, created: &str) {
        self.keys.entry(kp.key_id()).or_insert_with(|| LedgerEntry {
            public_key: Some(kp.public_hex()),
            created: Some(created.to_string()),
            ..LedgerEntry::default()
        });
        self.version = CEREMONY_LEDGER_VERSION;
    }

    /// Record the generation chain of a rotation: `old` was replaced by
    /// `successor` at `rotated_at`, with an overlap window of
    /// `window_days` days. `old`'s entry is created on the spot when the
    /// ledger never saw its keygen (pre-ceremony keychain).
    pub fn record_rotation(
        &mut self,
        old: &KeyPair,
        successor: &KeyPair,
        rotated_at: &str,
        window_days: u32,
    ) {
        let old_entry = self.keys.entry(old.key_id()).or_default();
        if old_entry.public_key.is_none() {
            old_entry.public_key = Some(old.public_hex());
        }
        if old_entry.created.is_none() {
            old_entry.created = Some(rotated_at.to_string());
        }
        old_entry.replaced_by = Some(successor.key_id());
        old_entry.rotated_at = Some(rotated_at.to_string());
        old_entry.window_days = Some(window_days);
        self.keys
            .entry(successor.key_id())
            .or_insert_with(|| LedgerEntry {
                public_key: Some(successor.public_hex()),
                created: Some(rotated_at.to_string()),
                ..LedgerEntry::default()
            });
        self.version = CEREMONY_LEDGER_VERSION;
    }

    /// Record a revocation (the date is the audit trail; the enforcement
    /// half — anchor removal + `revoked-keys` — is [`revoke_local`]'s).
    pub fn record_revocation(&mut self, key_id: &str, revoked_at: &str) {
        let entry = self.keys.entry(key_id.to_string()).or_default();
        entry.revoked_at = Some(revoked_at.to_string());
        self.version = CEREMONY_LEDGER_VERSION;
    }

    /// Key ids carrying a revocation date.
    pub fn revoked_ids(&self) -> Vec<String> {
        self.keys
            .iter()
            .filter(|(_, e)| e.revoked_at.is_some())
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// True when `key_id` was rotated out and its overlap window has
    /// passed by `now` (unix seconds). Keys without a recorded rotation
    /// are never stale; a recorded date that cannot parse is a named
    /// error — but [`CeremonyLedger::load`] validates dates up front, so
    /// this only fires for in-memory tampering.
    pub fn rotation_window_expired(&self, key_id: &str, now: i64) -> miette::Result<bool> {
        let Some(entry) = self.keys.get(key_id) else {
            return Ok(false);
        };
        let Some(rotated_at) = entry.rotated_at.as_deref() else {
            return Ok(false);
        };
        if entry.replaced_by.is_none() {
            return Ok(false);
        }
        let days = i64::from(entry.window_days.unwrap_or(DEFAULT_WINDOW_DAYS));
        let end = rfc3339_to_unix(rotated_at)? + days * 86_400;
        Ok(now > end)
    }

    /// Structural validation (see [`CeremonyLedger::load`]).
    fn validate(&self) -> miette::Result<()> {
        if self.version > CEREMONY_LEDGER_VERSION {
            return Err(miette::miette!(
                "ledger version {} is newer than this nau understands ({})",
                self.version,
                CEREMONY_LEDGER_VERSION
            ));
        }
        for (id, entry) in &self.keys {
            validate_entry(self, id, entry)?;
        }
        Ok(())
    }
}

/// Validate one ledger entry: key-id shape, material↔id agreement, date
/// parseability, and a chain link that resolves inside the ledger.
fn validate_entry(ledger: &CeremonyLedger, id: &str, entry: &LedgerEntry) -> miette::Result<()> {
    if !is_key_id(id) {
        return Err(miette::miette!(
            "entry key id {id:?} is not a 16-hex key id"
        ));
    }
    validate_entry_material(id, entry)?;
    validate_entry_dates(id, entry)?;
    validate_entry_chain(ledger, id, entry)
}

/// The recorded public key material must be 64-hex whose own id prefix is
/// the entry's map key — a tampered entry cannot move the material
/// without tripping this.
fn validate_entry_material(id: &str, entry: &LedgerEntry) -> miette::Result<()> {
    let Some(pk) = &entry.public_key else {
        return Ok(());
    };
    let agrees = match from_hex32(pk) {
        Ok(bytes) => to_hex(&bytes)[..16] == *id,
        Err(_) => false,
    };
    if agrees {
        return Ok(());
    }
    Err(miette::miette!(
        "entry {id} carries public key material that does not hash to its own id"
    ))
}

/// Every recorded date must parse as RFC3339 UTC.
fn validate_entry_dates(id: &str, entry: &LedgerEntry) -> miette::Result<()> {
    for (label, date) in [
        ("created", &entry.created),
        ("rotated_at", &entry.rotated_at),
        ("revoked_at", &entry.revoked_at),
    ] {
        if let Some(date) = date {
            rfc3339_to_unix(date)
                .map_err(|e| miette::miette!("entry {id} has a malformed {label} date: {e}"))?;
        }
    }
    Ok(())
}

/// A chain link must be a real key id with its own entry.
fn validate_entry_chain(
    ledger: &CeremonyLedger,
    id: &str,
    entry: &LedgerEntry,
) -> miette::Result<()> {
    let Some(succ) = &entry.replaced_by else {
        return Ok(());
    };
    if !is_key_id(succ) {
        return Err(miette::miette!(
            "entry {id} chains to {succ:?}, which is not a 16-hex key id"
        ));
    }
    if !ledger.keys.contains_key(succ) {
        return Err(miette::miette!(
            "entry {id} chains to successor {succ}, which has no ledger entry"
        ));
    }
    Ok(())
}

/// True when `s` is a well-formed 16-hex key id.
fn is_key_id(s: &str) -> bool {
    s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// The current time as unix seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The current time, RFC3339 UTC.
pub fn now_rfc3339() -> String {
    unix_to_rfc3339(now_unix())
}

/// Render unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (RFC3339 UTC). Civil
/// date from days via the standard era algorithm — no timestamp
/// dependency; the format is exactly what [`rfc3339_to_unix`] parses.
pub fn unix_to_rfc3339(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Parse our own `YYYY-MM-DDTHH:MM:SSZ` rendering back to unix seconds.
/// Strict shape first, then a round-trip re-render must reproduce the
/// input — which rejects impossible dates (Feb 30, month 13, hour 27)
/// without a calendar table.
pub fn rfc3339_to_unix(s: &str) -> miette::Result<i64> {
    let b = s.as_bytes();
    let shape_ok = b.len() == 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z'
        && b.iter()
            .enumerate()
            .all(|(i, c)| (0x30..=0x39).contains(c) || [4usize, 7, 10, 13, 16, 19].contains(&i));
    if !shape_ok {
        return Err(miette::miette!("expected YYYY-MM-DDTHH:MM:SSZ, got {s:?}"));
    }
    let num = |a: usize, z: usize| -> i64 {
        s[a..z].parse().expect("shape check made this ascii digits")
    };
    let (y, mo, d) = (num(0, 4), num(5, 7), num(8, 10));
    let (h, mi, sec) = (num(11, 13), num(14, 16), num(17, 19));
    let t = days_from_civil(y, mo as u32, d as u32) * 86_400 + h * 3600 + mi * 60 + sec;
    if unix_to_rfc3339(t) != s {
        return Err(miette::miette!("not a real UTC datetime: {s:?}"));
    }
    Ok(t)
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + u64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Write the secret-key file at an explicit path (0600).
/// `pub` — the root rotation ceremony writes `secret-key.new`.
pub fn write_secret_key_at(path: &Path, kp: &KeyPair) -> miette::Result<()> {
    let dir = path.parent().expect("secret key path has a parent");
    std::fs::create_dir_all(dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", dir.display()))?;
    std::fs::write(path, format!("{SECRET_COMMENT}\n{}\n", kp.seed_hex()))
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .into_diagnostic()
            .wrap_err_with(|| format!("chmod 0600 {}", path.display()))?;
    }
    Ok(())
}

/// Derive a keypair from a seed (deterministic; ceremony tests pin key
/// ids). `pub` — the root rotation ceremony mints successors.
pub fn derive_pair(seed: &[u8; 32]) -> KeyPair {
    let signing = SigningKey::from_bytes(seed);
    KeyPair {
        seed: *seed,
        public: signing.verifying_key().to_bytes(),
    }
}

/// Parse the on-disk secret-key file shape (comment line + hex seed).
/// `pub` — the root rotation ceremony re-parses `.new` before promoting.
pub fn parse_secret_key(text: &str) -> miette::Result<KeyPair> {
    let seed_hex = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
        .ok_or_else(|| miette::miette!("secret key file carries no key material"))?;
    let seed = from_hex32(seed_hex)?;
    Ok(derive_pair(&seed))
}

/// 32 entropy bytes from /dev/urandom.
/// `pub` — the root rotation ceremony mints successors.
pub fn read_urandom32() -> miette::Result<[u8; 32]> {
    use std::io::Read;
    // read_exact — /dev/urandom never EOFs, so read-to-end would block
    // forever.
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| miette::miette!("cannot open /dev/urandom: {e}"))?;
    let mut out = [0u8; 32];
    f.read_exact(&mut out)
        .map_err(|e| miette::miette!("cannot read 32 bytes from /dev/urandom: {e}"))?;
    Ok(out)
}

impl KeyPair {
    /// Lowercase hex of the seed (the on-disk secret-key payload).
    pub fn seed_hex(&self) -> String {
        to_hex(&self.seed)
    }
}

/// Lowercase hex encoding (key ids, pubkey files, ledger material).
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode 64 hex chars into a 32-byte key (secret and public files).
/// `pub` — the root verify path decodes operator-supplied keys.
pub fn from_hex32(s: &str) -> miette::Result<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(miette::miette!("expected 64 hex chars, got {s:?}"));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| miette::miette!("bad hex at byte {i}: {e}"))?;
    }
    Ok(out)
}

// ── Signature envelope + verify cluster (issue #326 PR 3, R2) ──

/// key `public_hex`. The entry is looked up by the key id derived from that
/// public key; a missing entry, undecodable signature, provenance that
/// does not bind the bytes, or failed Ed25519 check is a named error
/// (fail closed). Attested entries verify over body ++ provenance bytes
/// (issue #56); legacy bare entries over the body alone.
pub fn verify(
    manifest_bytes: &[u8],
    signatures: &std::collections::BTreeMap<String, serde_json::Value>,
    public_hex: &str,
) -> miette::Result<()> {
    let public = from_hex32(public_hex).wrap_err("update public key is not 64 hex chars")?;
    let key_id = to_hex(&public)[..16].to_string();
    let entry = signatures.get(&key_id).ok_or_else(|| {
        miette::miette!("manifest carries no signature for key id {key_id} — refusing to verify")
    })?;
    let (payload, raw) = entry_signed_payload(manifest_bytes, &key_id, entry)?;
    verify_one(&payload, &key_id, &raw, &public)
}

/// Canonical signature input for the EVAL manifest
/// ([`crate::manifest::ImageManifest`]): serialized with `signatures`
/// emptied (see the module docs — a signature never covers itself; the map
/// is deterministic, so the bytes are byte-stable).
///
/// Named `eval_manifest_…` deliberately (#266): the IMAGE manifest's
/// canonical bytes are a separate scheme —
/// [`crate::image::verify::image_manifest_canonical_bytes`] — and the
/// two must never be confused when signing/verifying.
///   bytes only (every manifest signed before issue #56).
/// - `Attested` — the signature over body bytes ++ provenance bytes,
///   with the SLSA-lite claims riding inside the entry (under the
///   signature, never in the canonical body). `provenance` is optional so
///   an envelope object without claims still verifies over the body.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SignatureEntry {
    Bare(String),
    Attested {
        signature: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provenance: Option<Provenance>,
    },
}

impl SignatureEntry {
    /// The attested claims, when the entry carries them.
    pub fn provenance(&self) -> Option<&Provenance> {
        match self {
            SignatureEntry::Bare(_) => None,
            SignatureEntry::Attested { provenance, .. } => provenance.as_ref(),
        }
    }
}

/// The eval invocation a provenance attests: the flags that shaped pin
/// resolution (and that are deliberately kept OUT of the canonical body —
/// they are builder facts, not definition facts).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Invocation {
    pub arch: String,
    pub channel: String,
    /// True when eval ran with `--offline` (resolution was forbidden to
    /// touch the network).
    pub offline: bool,
}

/// The attested output: the sha3-384 of the canonical body bytes. The
/// same content-address family the image snap pins use.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Subject {
    pub name: String,
    pub manifest_sha3_384: String,
}

/// SLSA-lite provenance, attached under a signature entry (issue #56).
/// What was built (subject), from which verified inputs (materials), by
/// which builder (builder id + invocation).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Provenance {
    pub version: u32,

    /// Builder identity — `nau:<CARGO_PKG_VERSION>`. Self-asserted
    /// under the signing key; there is no independent builder registry
    /// (the "lite").
    pub builder_id: String,

    /// The invocation flags of the eval that produced the manifest.
    pub invocation: Invocation,

    /// The definition's declared inputs at their lockfile pins — a mirror
    /// of `ImageManifest.inputs`. The full input inventory (including
    /// every image snap pin) is already inside the signed body; the
    /// materials claim re-asserts the source-input half so a verifier
    /// holding only the attestation can read it, and
    /// [`check_provenance`] refuses a mirror that diverges from the
    /// manifest it rides.
    pub materials: std::collections::BTreeMap<String, ManifestInput>,

    /// The output digest binding: sha3-384 over the canonical body bytes
    /// the signature covers. Enforced at verify time before the Ed25519
    /// check — an attestation that does not bind its bytes is refused.
    pub subject: Subject,
}

/// SHA3-384 hex over the canonical body bytes — the provenance subject
/// digest.
pub fn subject_digest(body: &[u8]) -> String {
    use sha3::Digest;
    to_hex(&sha3::Sha3_384::digest(body))
}

/// The deterministic bytes a provenance contributes to the signed
/// payload (appended after the canonical body bytes).
pub fn provenance_bytes(provenance: &Provenance) -> miette::Result<Vec<u8>> {
    serde_json::to_vec(provenance).map_err(|e| miette::miette!("provenance serialization: {e}"))
}

/// Ed25519 signature covers (issue #56): the canonical body bytes, plus
/// the entry's provenance bytes when the entry carries them. A provenance
/// whose subject digest does not bind `body` is a named error BEFORE the
/// Ed25519 check — an attestation detached from its bytes must not pass
/// even with a valid signature over the pair.
pub fn entry_signed_payload(
    body: &[u8],
    key_id: &str,
    entry: &serde_json::Value,
) -> miette::Result<(Vec<u8>, String)> {
    let parsed: SignatureEntry = serde_json::from_value(entry.clone()).map_err(|e| {
        miette::miette!("signature entry for {key_id} is not a valid signature envelope: {e}")
    })?;
    match parsed {
        SignatureEntry::Bare(raw) => Ok((body.to_vec(), raw)),
        SignatureEntry::Attested {
            signature,
            provenance,
        } => {
            let Some(provenance) = provenance else {
                return Ok((body.to_vec(), signature));
            };
            let actual = subject_digest(body);
            if actual != provenance.subject.manifest_sha3_384 {
                return Err(miette::miette!(
                    "provenance subject digest does not bind these manifest bytes \
                     (attested {}, actual {}) — refusing to verify",
                    provenance.subject.manifest_sha3_384,
                    actual
                ));
            }
            let mut payload = body.to_vec();
            payload.extend_from_slice(&provenance_bytes(&provenance)?);
            Ok((payload, signature))
        }
    }
}

/// Multi-key verify: accept when ANY signature whose key id is in the
/// trusted set verifies over `manifest_bytes`. Attested entries verify
/// over body ++ provenance bytes with the subject binding enforced
/// (issue #56); a malformed envelope counts as failed, not missing. An
/// empty chain fails closed; so does a chain where no trusted key has a
/// verifiable signature. Returns the key id that verified.
pub fn verify_keychain(
    manifest_bytes: &[u8],
    signatures: &std::collections::BTreeMap<String, serde_json::Value>,
    chain: &Keychain,
) -> miette::Result<String> {
    if chain.is_empty() {
        return Err(miette::miette!(
            "empty trust chain — no public keys loaded, refusing to verify (fail closed)"
        ));
    }
    let mut missing = Vec::new();
    let mut failed = Vec::new();
    for (key_id, public) in &chain.entries {
        let Some(entry) = signatures.get(key_id) else {
            missing.push(key_id.clone());
            continue;
        };
        let checked = entry_signed_payload(manifest_bytes, key_id, entry)
            .and_then(|(payload, raw)| verify_one(&payload, key_id, &raw, public));
        match checked {
            Ok(()) => return Ok(key_id.clone()),
            Err(_) => failed.push(key_id.clone()),
        }
    }
    Err(miette::miette!(
        "no trusted signature verifies: missing entries for {:?}, failed for {:?} \
         — refusing to verify",
        missing,
        failed
    ))
}

/// The device-side trust policy (ADR-0024 §4): a closed key set plus an
/// explicit revocation list.
///
/// - [`reject_revoked`] runs first: a signature under a revoked id is a
///   hard refusal even if another, still-trusted key also signed.
/// - Then [`verify_keychain`] over the trusted set: a signature under an
///   id absent from the set is "never trusted" and fails closed.
///
/// Both halves are needed for "revoked" to be distinguishable from
/// "never trusted": without the revocation list, stripping an anchor is
/// indistinguishable from never having carried it.
pub fn verify_trust_set(
    manifest_bytes: &[u8],
    signatures: &std::collections::BTreeMap<String, serde_json::Value>,
    chain: &Keychain,
    revoked: &[String],
) -> miette::Result<String> {
    reject_revoked(signatures, revoked)?;
    verify_keychain(manifest_bytes, signatures, chain)
}
/// Verify one base64 signature string under one public key (the single
/// entry path shared by [`verify`] and [`verify_keychain`]).
pub fn verify_one(
    manifest_bytes: &[u8],
    key_id: &str,
    raw: &str,
    public: &[u8; 32],
) -> miette::Result<()> {
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|e| miette::miette!("signature for {key_id} is not valid base64: {e}"))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| miette::miette!("signature for {key_id} is malformed: {e}"))?;
    let vk = VerifyingKey::from_bytes(public)
        .map_err(|e| miette::miette!("public key {key_id} is malformed: {e}"))?;
    vk.verify(manifest_bytes, &sig)
        .map_err(|_| miette::miette!("signature verification FAILED for key id {key_id}"))
}

// ── Device trust-anchor paths (issue #326 PR 4 down-move) ──
//
// The embedded-key-set walk the runtime install path and the peer pull
// lane share: the same anchor directory layout, the same unioned
// revocation view (ADR-0024 §4, ADR-0033 Decision 7).

/// The embedded-key-set directory beside a device anchor: for
/// `/etc/nau/update-key.pub` that is `/etc/nau/trusted-keys/`.
pub fn trusted_keys_dir(anchor: &Path) -> PathBuf {
    anchor
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("trusted-keys")
}

/// Read the device revocation list beside the anchor, unioned with the
/// operator list under the keychain dir. A missing file is an empty list;
/// the operator side is the local `revoked-keys` the key ceremony writes.
/// Shared with the peer verify path (ADR-0033 Decision 7) so both lanes
/// police the same unioned revocation set.
pub fn embedded_revoked_keys(anchor: &Path, keys: &Path) -> miette::Result<Vec<String>> {
    let mut revoked = Vec::new();
    let device = anchor
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("revoked-keys");
    if let Ok(text) = std::fs::read_to_string(&device) {
        revoked.extend(parse_revoked_keys(&text, &device)?);
    }
    revoked.extend(read_revoked_keys(keys)?);
    revoked.sort();
    revoked.dedup();
    Ok(revoked)
}

/// Parse a revocation list body: one 16-hex key id per line, `#` comments
/// and blanks skipped. Malformed lines are named errors — a corrupt
/// revocation list is never treated as empty (that would silently bless
/// revoked keys).
fn parse_revoked_keys(text: &str, path: &Path) -> miette::Result<Vec<String>> {
    let mut ids = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() != 16 || !line.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(miette::miette!(
                "revocation list {} line {} is not a 16-hex key id: {line:?}",
                path.display(),
                n + 1
            ));
        }
        ids.push(line.to_ascii_lowercase());
    }
    Ok(ids)
}
