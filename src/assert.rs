//! Snap Store assertion verification — ADR-0011 step (b).
//!
//! `StoreClient::resolve()` receives the sha3-384 digest and the download
//! URL from a single **unsigned** channel-map response. Trusting either
//! directly is trust-on-first-use (TOFU). This module closes that gap: the
//! digest must be backed by a signed `snap-revision` assertion whose
//! signature chain roots in Canonical's account key, which is hardcoded
//! here as the trust anchor (snapd `asserts/sysdb/trusted.go` parity).
//!
//! # Chain
//!
//! ```text
//! snap-revision assertion   (binds snap-sha3-384 → snap-id, revision, size)
//!   ← signed by store account key (sign-key-sha3-384 header)
//! account-key assertion     (binds the OpenPGP public key body → key id)
//!   ← signed by Canonical's root key
//! root account-key assertion — hardcoded below, trusted by construction
//! ```
//!
//! Verification fails closed: any parse failure, signature failure, key-id
//! mismatch, validity-window violation, or field cross-check mismatch is a
//! named [`AssertError::Untrusted`]. Only a clean transport failure (curl
//! could not obtain the assertion) yields [`AssertError::Network`], which
//! the caller may downgrade for pins that predate the resolve (see
//! `store.rs`).
//!
//! # Wire format (validated against the live store chain)
//!
//! An assertion is `HEADERS "\n\n" BODY "\n\n" SIGNATURE` where BODY is
//! optional base64. snapd's `asserts.Decode` signs/stores the content as
//! the **exact wire bytes up to the last `\n\n`** — headers plus the raw
//! base64 body text, *not* the decoded body. Signature blocks are the v1
//! envelope: base64 of `0x01 || OpenPGP packet(s)` (line-wrapped).
//! `public-key-sha3-384` / `sign-key-sha3-384` ids are URL-safe unpadded
//! base64 of SHA3-384 over the decoded body *including* the `0x01` byte.
//! Assertion digest values (`snap-sha3-384`) are URL-safe unpadded base64
//! of the digest bytes; channel-map digests are hex — canonicalize by
//! comparing decoded bytes, never strings across encodings.
//!
//! # Crypto
//!
//! OpenPGP v4 packets, RSA (4096/8192), SHA-512. We use `rpgp` (pure Rust,
//! no C backend) but verify via its low-level hash + [`VerifyingKey::verify`]
//! path instead of `Signature::verify()`: the latter enforces that the
//! signature's OpenPGP issuer-keyid subpacket matches the key. Snap
//! assertions carry a stale legacy issuer keyid (pre-rotation) and snapd
//! selects keys by the assertion-level `sign-key-sha3-384` id instead, so
//! the identity guard is wrong for this format. Validated empirically
//! against the live `hello-world` rev-29 chain.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use pgp::packet::{PacketHeader, PublicKey, Signature};
use pgp::types::VerifyingKey;
use sha3::Digest;

/// Snap Store API base (same service `store.rs` queries).
const STORE_API: &str = "https://api.snapcraft.io";

/// Canonical's root account key — the hardcoded trust anchor, byte-identical
/// to snapd's embedded `encodedCanonicalRootAccountKey`
/// (`asserts/sysdb/trusted.go`, revision 2). Self-referential
/// (`sign-key-sha3-384` == `public-key-sha3-384`); trusted by construction,
/// its signature is not verified.
const TRUSTED_ROOT_ACCOUNT_KEY: &str = include_str!("assertions/trusted-root-account-key.assert");

/// Digest name used in error messages and the store header.
const SHA3_384: &str = "sha3-384";

// ── Errors ──

/// Why assertion verification did not pass. The distinction matters for the
/// offline fallback in `store.rs`: only `Network` is downgradeable, and only
/// for pins that predate the resolve.
#[derive(Debug)]
pub enum AssertError {
    /// The store could not be reached — no evidence either way. Never
    /// produced after an assertion was obtained.
    Network { url: String, detail: String },
    /// An assertion was obtained but is malformed, badly signed, or
    /// contradicts the expected pin. Never downgradeable.
    Untrusted { name: String, detail: String },
}

impl std::fmt::Display for AssertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssertError::Network { url, detail } => {
                write!(f, "assertion store unreachable ({url}): {detail}")
            }
            AssertError::Untrusted { name, detail } => {
                write!(f, "untrusted store assertion for '{name}': {detail}")
            }
        }
    }
}

fn network(url: String, detail: String) -> AssertError {
    AssertError::Network { url, detail }
}

fn untrusted(name: &str, detail: String) -> AssertError {
    AssertError::Untrusted {
        name: name.to_string(),
        detail,
    }
}

// ── Assertion model ──

/// One parsed snap-store assertion.
struct Assertion {
    assertion_type: String,
    authority_id: String,
    sign_key_id: String,
    /// All headers as string key/value pairs (store assertion headers are
    /// all scalar strings).
    headers: BTreeMap<String, String>,
    /// Signed content: exact wire bytes from the start through the last
    /// `\n\n` separator (headers + base64 body text if any).
    content: Vec<u8>,
    /// Decoded body, including the v1-envelope `0x01` prefix byte. Empty
    /// when the assertion has no body (e.g. snap-revision).
    body: Vec<u8>,
    /// Decoded signature section with the `0x01` envelope byte stripped:
    /// OpenPGP packet(s) led by the signature packet.
    signature_packets: Vec<u8>,
}

impl Assertion {
    fn header(&self, key: &str) -> Option<&str> {
        self.headers.get(key).map(String::as_str)
    }

    fn required(&self, name: &str, key: &str) -> Result<&str, AssertError> {
        self.header(key).ok_or_else(|| {
            untrusted(
                name,
                format!("assertion is missing required header '{key}'"),
            )
        })
    }
}

/// Split a packet stream into `(tag, packet bytes)` ranges. Snap assertions
/// constrain OpenPGP data to new-format packets (snapd parity); anything
/// else is a parse failure.
fn split_packets(
    name: &str,
    data: &[u8],
    what: &str,
) -> Result<Vec<(u8, std::ops::Range<usize>)>, AssertError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let first = data[i];
        if first & 0x80 == 0 || first & 0x40 == 0 {
            return Err(untrusted(
                name,
                format!("{what}: unsupported OpenPGP packet header at byte {i}"),
            ));
        }
        let tag = first & 0x3f;
        let mut j = i + 1;
        let lb = *data
            .get(j)
            .ok_or_else(|| untrusted(name, format!("{what}: truncated OpenPGP packet header")))?;
        let len = if lb < 192 {
            j += 1;
            lb as usize
        } else if lb < 224 {
            let l = ((lb as usize - 192) << 8)
                + *data.get(j + 1).ok_or_else(|| {
                    untrusted(name, format!("{what}: truncated OpenPGP packet length"))
                })? as usize
                + 192;
            j += 2;
            l
        } else if lb == 255 {
            if data.len() < j + 5 {
                return Err(untrusted(
                    name,
                    format!("{what}: truncated OpenPGP packet length"),
                ));
            }
            let l =
                u32::from_be_bytes([data[j + 1], data[j + 2], data[j + 3], data[j + 4]]) as usize;
            j += 5;
            l
        } else {
            return Err(untrusted(
                name,
                format!("{what}: unsupported OpenPGP partial packet length"),
            ));
        };
        let end = j + len;
        if data.len() < end {
            return Err(untrusted(
                name,
                format!("{what}: truncated OpenPGP packet body"),
            ));
        }
        out.push((tag, i..end));
        i = end;
    }
    Ok(out)
}

/// Decode a v1 envelope: base64 text → bytes that must start with `0x01`;
/// return the packet stream after the version byte.
fn envelope_decode(name: &str, what: &str, b64_text: &str) -> Result<Vec<u8>, AssertError> {
    let joined: String = b64_text.split_whitespace().collect();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(joined.as_bytes())
        .map_err(|e| untrusted(name, format!("{what}: invalid base64: {e}")))?;
    match raw.split_first() {
        Some((0x01, rest)) if !rest.is_empty() => Ok(rest.to_vec()),
        Some((version, _)) => Err(untrusted(
            name,
            format!("{what}: unsupported envelope version {version:#04x}"),
        )),
        None => Err(untrusted(name, format!("{what}: empty envelope"))),
    }
}

/// URL-safe unpadded base64 decode (assertion digest/key-id encoding).
fn b64url_decode(name: &str, what: &str, s: &str) -> Result<Vec<u8>, AssertError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .or_else(|_| {
            // Tolerate standard-alphabet encodings of the same value.
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(s.as_bytes())
        })
        .map_err(|e| untrusted(name, format!("{what}: invalid base64 '{s}': {e}")))
}

fn hex_decode(name: &str, what: &str, s: &str) -> Result<Vec<u8>, AssertError> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(untrusted(name, format!("{what}: invalid hex '{s}'")));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| untrusted(name, format!("{what}: invalid hex '{s}': {e}")))
}

fn sha3_384(data: &[u8]) -> Vec<u8> {
    sha3::Sha3_384::digest(data).to_vec()
}

/// Parse the constrained RFC3339 subset the store emits
/// (`YYYY-MM-DDTHH:MM:SS[.frac]Z`) into epoch seconds.
fn parse_epoch(s: &str) -> Option<u64> {
    let (date, time) = s.strip_suffix('Z')?.split_once('T')?;
    let mut d = date.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: u32 = d.next()?.parse().ok()?;
    let day: u32 = d.next()?.parse().ok()?;
    let mut t = time.split(':');
    let hour: u64 = t.next()?.parse().ok()?;
    let minute: u64 = t.next()?.parse().ok()?;
    let second: u64 = t.next()?.split('.').next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Days-from-civil (Hinnant), proleptic Gregorian.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp as i64 + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some((days as u64) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Parse one assertion in wire format.
fn parse_assertion(name: &str, raw: &str) -> Result<Assertion, AssertError> {
    let raw = raw.trim_end_matches('\n');
    let (content, sig_text) = raw
        .rsplit_once("\n\n")
        .ok_or_else(|| untrusted(name, "content/signature separator not found".to_string()))?;

    let (head, body_text) = match content.split_once("\n\n") {
        Some((head, body)) if !body.is_empty() => (head, body),
        _ => (content, ""),
    };

    let mut headers = BTreeMap::new();
    for line in head.lines() {
        let (k, v) = line
            .split_once(": ")
            .ok_or_else(|| untrusted(name, format!("malformed assertion header line '{line}'")))?;
        headers.insert(k.to_string(), v.to_string());
    }

    let assertion_type = headers
        .get("type")
        .cloned()
        .ok_or_else(|| untrusted(name, "assertion is missing header 'type'".to_string()))?;
    let authority_id = headers.get("authority-id").cloned().ok_or_else(|| {
        untrusted(
            name,
            "assertion is missing header 'authority-id'".to_string(),
        )
    })?;
    let sign_key_id = headers.get("sign-key-sha3-384").cloned().ok_or_else(|| {
        untrusted(
            name,
            "assertion is missing header 'sign-key-sha3-384'".to_string(),
        )
    })?;

    let body = if body_text.is_empty() {
        Vec::new()
    } else {
        envelope_decode(name, "assertion body", body_text)?
    };
    let signature_packets = envelope_decode(name, "assertion signature", sig_text)?;

    Ok(Assertion {
        assertion_type,
        authority_id,
        sign_key_id,
        headers,
        content: content.as_bytes().to_vec(),
        body,
        signature_packets,
    })
}

/// Extract the OpenPGP public key from an account-key assertion body
/// (`0x01 || public-key packet`).
fn public_key_from_body(name: &str, what: &str, body: &[u8]) -> Result<PublicKey, AssertError> {
    let packets = split_packets(name, body, what)?;
    let (tag, range) = packets
        .first()
        .ok_or_else(|| untrusted(name, format!("{what}: no OpenPGP packets in body")))?;
    if *tag != 6 {
        return Err(untrusted(
            name,
            format!("{what}: expected a public-key packet, got tag {tag}"),
        ));
    }
    let mut reader = Cursor::new(&body[range.clone()]);
    let header = PacketHeader::try_from_reader(&mut reader)
        .map_err(|e| untrusted(name, format!("{what}: invalid packet header: {e}")))?;
    PublicKey::try_from_reader(header, &mut reader)
        .map_err(|e| untrusted(name, format!("{what}: invalid public key: {e}")))
}

/// Verify an assertion's OpenPGP signature over its wire content.
///
/// Deliberately bypasses rpgp's `Signature::verify` identity guard — see
/// the module docs (stale legacy issuer keyids; snapd selects keys by the
/// assertion-level `sign-key-sha3-384`).
fn verify_signature(
    name: &str,
    what: &str,
    assertion: &Assertion,
    key: &PublicKey,
) -> Result<(), AssertError> {
    let packets = split_packets(name, &assertion.signature_packets, what)?;
    let sig_packets: Vec<&std::ops::Range<usize>> = packets
        .iter()
        .filter(|(t, _)| *t == 2)
        .map(|(_, r)| r)
        .collect();
    let range = sig_packets
        .first()
        .ok_or_else(|| untrusted(name, format!("{what}: no signature packet")))?;
    let mut reader = Cursor::new(&assertion.signature_packets[(*range).clone()]);
    let header = PacketHeader::try_from_reader(&mut reader)
        .map_err(|e| untrusted(name, format!("{what}: invalid signature header: {e}")))?;
    let sig = Signature::try_from_reader(header, &mut reader)
        .map_err(|e| untrusted(name, format!("{what}: invalid signature packet: {e}")))?;

    let config = sig
        .config()
        .ok_or_else(|| untrusted(name, format!("{what}: unsupported signature version")))?;
    let Some(signed_hash_value) = sig.signed_hash_value() else {
        return Err(untrusted(
            name,
            format!("{what}: missing signed hash value"),
        ));
    };
    let Some(signature_bytes) = sig.signature() else {
        return Err(untrusted(name, format!("{what}: missing signature bytes")));
    };

    let mut hasher = config
        .hash_alg
        .new_hasher()
        .map_err(|e| untrusted(name, format!("{what}: unsupported hash algorithm: {e}")))?;
    config
        .hash_data_to_sign(&mut hasher, Cursor::new(&assertion.content))
        .map_err(|e| untrusted(name, format!("{what}: cannot hash content: {e}")))?;
    let hashed_len = config
        .hash_signature_data(&mut hasher)
        .map_err(|e| untrusted(name, format!("{what}: cannot hash signature: {e}")))?;
    let trailer = config
        .trailer(hashed_len)
        .map_err(|e| untrusted(name, format!("{what}: cannot build trailer: {e}")))?;
    hasher.update(&trailer);
    let hash = hasher.finalize();

    if signed_hash_value != hash[0..2] {
        return Err(untrusted(
            name,
            format!("{what}: signature does not cover this assertion content"),
        ));
    }
    key.verify(config.hash_alg, &hash, signature_bytes)
        .map_err(|e| untrusted(name, format!("{what}: signature verification failed: {e}")))
}

/// Check `key-id header == sha3-384(body)` for account-key assertions: the
/// id binds the exact key material, so a swapped body cannot pass. The hash
/// covers the decoded envelope bytes *including* the `0x01` version prefix
/// (snapd parity — verified against the live root key); `Assertion::body`
/// has the prefix stripped, so it is re-attached here.
fn check_key_material_binding(
    name: &str,
    what: &str,
    assertion: &Assertion,
) -> Result<(), AssertError> {
    let key_id = assertion.required(name, "public-key-sha3-384")?;
    let mut enveloped = Vec::with_capacity(assertion.body.len() + 1);
    enveloped.push(0x01);
    enveloped.extend_from_slice(&assertion.body);
    if b64url_decode(name, what, key_id)? != sha3_384(&enveloped) {
        return Err(untrusted(
            name,
            format!("{what}: public-key-sha3-384 does not match the key body"),
        ));
    }
    Ok(())
}

/// The account key must be alive now and must have been alive when it
/// signed the snap-revision assertion (snapd `CheckSigningKeyIsNotExpired`
/// + `CheckTimestampVsSigningKeyValidity`).
fn check_validity_window(
    name: &str,
    account_key: &Assertion,
    assertion_timestamp: Option<u64>,
) -> Result<(), AssertError> {
    let since = account_key
        .header("since")
        .and_then(parse_epoch)
        .ok_or_else(|| untrusted(name, "account key has no valid 'since'".to_string()))?;
    let until = account_key.header("until").and_then(parse_epoch);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now < since {
        return Err(untrusted(
            name,
            format!(
                "account key not valid yet (since {})",
                account_key.header("since").unwrap_or("?")
            ),
        ));
    }
    if let Some(until) = until {
        if now >= until {
            return Err(untrusted(name, "account key expired".to_string()));
        }
    }
    if let Some(ts) = assertion_timestamp {
        if ts < since || until.is_some_and(|u| ts >= u) {
            return Err(untrusted(
                name,
                "assertion timestamp outside the signing key's validity window".to_string(),
            ));
        }
    }
    Ok(())
}

/// Cross-check the snap-revision assertion's signed fields against the
/// pinned/expected values (snapd `CrossCheck` parity: digest, snap-id,
/// revision, size).
fn cross_check_fields(
    name: &str,
    assertion: &Assertion,
    expected_snap_id: Option<&str>,
    expected_revision: u32,
    expected_digest: &[u8],
    expected_size: Option<u64>,
) -> Result<(), AssertError> {
    let digest = assertion.required(name, "snap-sha3-384")?;
    if b64url_decode(name, SHA3_384, digest)? != expected_digest {
        return Err(untrusted(
            name,
            format!("{SHA3_384} mismatch: assertion binds {digest}, expected the pinned digest"),
        ));
    }
    if let Some(snap_id) = expected_snap_id {
        let asserted = assertion.required(name, "snap-id")?;
        if asserted != snap_id {
            return Err(untrusted(
                name,
                format!("snap id mismatch: assertion binds '{asserted}', expected '{snap_id}'"),
            ));
        }
    }
    let revision = assertion.required(name, "snap-revision")?;
    let asserted_revision: u32 = revision
        .parse()
        .map_err(|_| untrusted(name, format!("invalid snap-revision header '{revision}'")))?;
    if asserted_revision != expected_revision {
        return Err(untrusted(
            name,
            format!(
                "revision mismatch: assertion binds revision {asserted_revision}, expected {expected_revision}"
            ),
        ));
    }
    if let Some(size) = expected_size {
        let asserted_size: u64 = assertion
            .required(name, "snap-size")?
            .parse()
            .map_err(|_| untrusted(name, "invalid snap-size header".to_string()))?;
        if asserted_size != size {
            return Err(untrusted(
                name,
                format!("snap size mismatch: assertion binds {asserted_size}, expected {size}"),
            ));
        }
    }
    Ok(())
}

/// Verify the full snap-revision chain offline: fixtures provided by the
/// caller. Used directly by tests; [`verify_revision`] is the online
/// entry point.
fn verify_chain(
    name: &str,
    snap_revision_raw: &str,
    account_key_raw: &str,
    expected_snap_id: Option<&str>,
    expected_revision: u32,
    expected_digest: &[u8],
    expected_size: Option<u64>,
) -> Result<(), AssertError> {
    let root = parse_assertion(name, TRUSTED_ROOT_ACCOUNT_KEY)?;
    if root.assertion_type != "account-key" {
        return Err(untrusted(
            name,
            "trust anchor is not an account-key assertion".to_string(),
        ));
    }
    check_key_material_binding(name, "trust anchor", &root)?;
    let root_key = public_key_from_body(name, "trust anchor", &root.body)?;

    // The store account key must be signed by the trusted root.
    let account_key = parse_assertion(name, account_key_raw)?;
    if account_key.assertion_type != "account-key" {
        return Err(untrusted(
            name,
            "signing key assertion is not an account-key".to_string(),
        ));
    }
    if account_key.authority_id != root.authority_id {
        return Err(untrusted(
            name,
            format!(
                "account key authority '{}' does not match the trust anchor authority '{}'",
                account_key.authority_id, root.authority_id
            ),
        ));
    }
    verify_signature(name, "account key", &account_key, &root_key)?;

    // The snap-revision assertion must be signed by that account key.
    let snap_revision = parse_assertion(name, snap_revision_raw)?;
    if snap_revision.assertion_type != "snap-revision" {
        return Err(untrusted(
            name,
            "assertion is not a snap-revision".to_string(),
        ));
    }
    let asserted_key_id = account_key.required(name, "public-key-sha3-384")?;
    if b64url_decode(name, SHA3_384, &snap_revision.sign_key_id)?
        != b64url_decode(name, SHA3_384, asserted_key_id)?
    {
        return Err(untrusted(
            name,
            format!(
                "account key id '{}' does not match the assertion's sign-key-sha3-384",
                asserted_key_id
            ),
        ));
    }
    if snap_revision.authority_id != account_key.authority_id {
        return Err(untrusted(
            name,
            format!(
                "assertion authority '{}' does not match signing key account '{}'",
                snap_revision.authority_id, account_key.authority_id
            ),
        ));
    }
    check_key_material_binding(name, "account key", &account_key)?;
    let account_pub_key = public_key_from_body(name, "account key", &account_key.body)?;

    let assertion_timestamp = snap_revision.header("timestamp").and_then(parse_epoch);
    check_validity_window(name, &account_key, assertion_timestamp)?;
    verify_signature(name, "snap revision", &snap_revision, &account_pub_key)?;

    cross_check_fields(
        name,
        &snap_revision,
        expected_snap_id,
        expected_revision,
        expected_digest,
        expected_size,
    )
}

/// Fetch one raw assertion via curl (same transport pattern as
/// `store.rs::query_info`; `Accept` selects the raw signed format — the
/// default `*/*` returns JSON instead).
fn fetch_assertion(
    runner: &dyn crate::command::CommandRunner,
    _name: &str,
    url: &str,
) -> Result<String, AssertError> {
    let argv = vec![
        "curl".to_string(),
        "-sSf".to_string(),
        "--max-time".to_string(),
        "30".to_string(),
        "-H".to_string(),
        "Snap-Device-Series: 16".to_string(),
        "-H".to_string(),
        "Accept: application/x.ubuntu.assertion".to_string(),
        url.to_string(),
    ];
    let output = runner
        .run(&argv)
        .map_err(|e| network(url.to_string(), format!("curl not found: {e}")))?;

    if output.code != 0 {
        let detail = if output.stderr.is_empty() {
            format!("curl exited with {}", crate::command::exit_code(&output))
        } else {
            output.stderr.trim().to_string()
        };
        return Err(network(url.to_string(), detail));
    }
    if output.stdout.is_empty() {
        return Err(network(url.to_string(), "empty response".to_string()));
    }
    String::from_utf8(output.stdout)
        .map_err(|e| network(url.to_string(), format!("non-UTF-8 assertion body: {e}")))
}

/// Verify a store-resolved snap revision against its signed assertion
/// chain (ADR-0011 step (b)). Fails closed on any mismatch; transport
/// failures are [`AssertError::Network`].
///
/// `sha3_384_hex` is the channel-map digest (hex); it is compared to the
/// assertion by decoded bytes, so the two encodings never need to match
/// textually.
pub fn verify_revision(
    name: &str,
    snap_id: Option<&str>,
    revision: u32,
    sha3_384_hex: &str,
    size: Option<u64>,
) -> Result<(), AssertError> {
    verify_revision_with(
        &crate::command::RealRunner,
        name,
        snap_id,
        revision,
        sha3_384_hex,
        size,
    )
}

/// [`verify_revision`] with the host tool runner injected (the image
/// pipeline threads its own runner so assertion fetches are as injectable
/// as the rest of the build).
pub fn verify_revision_with(
    runner: &dyn crate::command::CommandRunner,
    name: &str,
    snap_id: Option<&str>,
    revision: u32,
    sha3_384_hex: &str,
    size: Option<u64>,
) -> Result<(), AssertError> {
    let digest_bytes = hex_decode(name, "store digest", sha3_384_hex)?;
    let digest_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest_bytes);
    let sr_url = format!("{STORE_API}/v2/assertions/snap-revision/{digest_b64}");
    let snap_revision_raw = fetch_assertion(runner, name, &sr_url)?;

    let key_id = parse_assertion(name, &snap_revision_raw)?.sign_key_id;
    let ak_url = format!("{STORE_API}/v2/assertions/account-key/{key_id}");
    let account_key_raw = fetch_assertion(runner, name, &ak_url)?;

    verify_chain(
        name,
        &snap_revision_raw,
        &account_key_raw,
        snap_id,
        revision,
        &digest_bytes,
        size,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real snap-revision + account-key assertions captured from the live
    /// store (hello-world rev 29, the smallest published snap). The tests
    /// exercise the exact production verification path offline and
    /// deterministically.
    const SNAP_REVISION: &str =
        include_str!("../tests/fixtures/assertions/hello-world-rev29.snap-revision.assert");
    const STORE_ACCOUNT_KEY: &str =
        include_str!("../tests/fixtures/assertions/store.account-key.assert");

    const HELLO_SNAP_ID: &str = "buPKUD3TKqCOgLEjjHx5kSiCpIs5cMuQ";
    const HELLO_DIGEST_HEX: &str = "b07bdb78e762c2e6020c75fafc92055b323a6f8da3ab42a3963da5ade386aba11f77e3c8f919b8aa23f3aa5c06c844f9";
    const HELLO_SIZE: u64 = 20480;

    fn chain(revision: u32) -> Result<(), AssertError> {
        verify_chain(
            "hello-world",
            SNAP_REVISION,
            STORE_ACCOUNT_KEY,
            Some(HELLO_SNAP_ID),
            revision,
            &hex_decode("hello-world", "digest", HELLO_DIGEST_HEX).unwrap(),
            Some(HELLO_SIZE),
        )
    }

    /// Flip one character of the base64 body block (part of the signed
    /// wire content) without breaking base64 validity.
    fn tamper_body_first_char(text: &str) -> String {
        let (head, rest) = text.split_once("\n\n").unwrap();
        let (body, sig) = rest.split_once("\n\n").unwrap();
        let mut c: Vec<char> = body.chars().collect();
        c[0] = if c[0] == 'A' { 'B' } else { 'A' };
        let body: String = c.into_iter().collect();
        format!("{head}\n\n{body}\n\n{sig}")
    }

    #[test]
    fn test_valid_chain_verifies() {
        chain(29).unwrap_or_else(|e| panic!("valid chain must verify: {e}"));
    }

    #[test]
    fn test_tampered_revision_header_fails_signature() {
        // Cross-checks are aligned with the tampered header, so only the
        // signature over the content can catch the flip.
        let tampered = SNAP_REVISION.replace("snap-revision: 29", "snap-revision: 28");
        let err = verify_chain(
            "hello-world",
            &tampered,
            STORE_ACCOUNT_KEY,
            Some(HELLO_SNAP_ID),
            28,
            &hex_decode("hello-world", "digest", HELLO_DIGEST_HEX).unwrap(),
            Some(HELLO_SIZE),
        )
        .unwrap_err();
        assert!(err.to_string().contains("signature"), "got: {err}");
    }

    #[test]
    fn test_tampered_account_key_body_fails() {
        let tampered = tamper_body_first_char(STORE_ACCOUNT_KEY);
        let err = chain_with(29, &tampered).unwrap_err();
        assert!(err.to_string().contains("untrusted"), "got: {err}");
    }

    fn chain_with(revision: u32, account_key: &str) -> Result<(), AssertError> {
        verify_chain(
            "hello-world",
            SNAP_REVISION,
            account_key,
            Some(HELLO_SNAP_ID),
            revision,
            &hex_decode("hello-world", "digest", HELLO_DIGEST_HEX).unwrap(),
            Some(HELLO_SIZE),
        )
    }

    #[test]
    fn test_wrong_revision_fails_cross_check() {
        let err = chain(28).unwrap_err();
        assert!(err.to_string().contains("revision"), "got: {err}");
    }

    #[test]
    fn test_wrong_digest_fails_cross_check() {
        let err = verify_chain(
            "hello-world",
            SNAP_REVISION,
            STORE_ACCOUNT_KEY,
            Some(HELLO_SNAP_ID),
            29,
            &hex_decode("hello-world", "digest", &"ab".repeat(48)).unwrap(),
            Some(HELLO_SIZE),
        )
        .unwrap_err();
        assert!(err.to_string().contains(SHA3_384), "got: {err}");
    }

    #[test]
    fn test_wrong_snap_id_fails_cross_check() {
        let err = verify_chain(
            "hello-world",
            SNAP_REVISION,
            STORE_ACCOUNT_KEY,
            Some("not-the-snap-id"),
            29,
            &hex_decode("hello-world", "digest", HELLO_DIGEST_HEX).unwrap(),
            Some(HELLO_SIZE),
        )
        .unwrap_err();
        assert!(err.to_string().contains("snap id"), "got: {err}");
    }

    #[test]
    fn test_wrong_size_fails_cross_check() {
        let err = verify_chain(
            "hello-world",
            SNAP_REVISION,
            STORE_ACCOUNT_KEY,
            Some(HELLO_SNAP_ID),
            29,
            &hex_decode("hello-world", "digest", HELLO_DIGEST_HEX).unwrap(),
            Some(HELLO_SIZE + 1),
        )
        .unwrap_err();
        assert!(err.to_string().contains("size"), "got: {err}");
    }

    #[test]
    fn test_unbound_account_key_fails() {
        // The root key is a valid account-key assertion, but the
        // snap-revision was signed by the store key — the id binding must
        // refuse it.
        let err = chain_with(29, TRUSTED_ROOT_ACCOUNT_KEY).unwrap_err();
        assert!(err.to_string().contains("sign-key-sha3-384"), "got: {err}");
    }

    #[test]
    fn test_digest_encoding_canonicalization() {
        // The store channel-map digest is hex; the assertion binds the same
        // bytes URL-safe-base64 encoded. Byte comparison must accept that.
        let hex = hex_decode("hello-world", "digest", HELLO_DIGEST_HEX).unwrap();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&hex);
        let asserted = parse_assertion("hello-world", SNAP_REVISION).unwrap();
        assert_eq!(
            b64,
            asserted.header("snap-sha3-384").unwrap(),
            "same bytes, different encodings"
        );
    }

    #[test]
    fn test_parse_epoch() {
        assert_eq!(parse_epoch("2016-04-01T00:00:00.0Z"), Some(1_459_468_800));
        assert_eq!(
            parse_epoch("2019-04-17T16:44:02.929465Z"),
            Some(1_555_519_442)
        );
        assert_eq!(parse_epoch("nonsense"), None);
    }
}
