//! Ubuntu Core seed / role-model support (issue #32).
//!
//! Ubuntu Core (UC20+, via `snap-initramfs-mounts` and `snap-bootstrap`)
//! boots a gadget/seed image model, not the simplified self-contained
//! verity-root layout. On first boot `snap-bootstrap initramfs-mounts`
//! mounts the partitions the UC initrd's `90-ubuntu-core-partitions.rules`
//! selects **by GPT partition name** (`ubuntu-seed` / `ubuntu-boot` /
//! `ubuntu-data` / `ubuntu-save`), and — in install mode, driven by the
//! kernel cmdline the gadget's grub config supplies (`snapd_recovery_mode=
//! install snapd_recovery_system=<label>`) — loads the seed off
//! `ubuntu-seed` and seeds `ubuntu-data`. Without those pieces the initrd
//! stops upstream of switch-root at:
//!
//! ```text
//! snap-bootstrap: cannot detect mode nor recovery system to use
//! ```
//!
//! This module emits everything the seed side of that first boot consumes,
//! every item verified against the pinned snapd snap's snap-bootstrap
//! (2.77.x, amd64) rather than recalled:
//!
//! 1. **Partition roles** — the gadget.yaml role names (`system-seed` …)
//!    mapped to the exact GPT PARTLABELs the udev rule matches.
//! 2. **The recovery system** — `systems/<label>/` carrying the signed
//!    model assertion, `seed.yaml`, the seed snap payloads, the kernel
//!    snap's `kernel.efi` UKI, and a grubenv pointing grub's first-boot
//!    config at it.
//! 3. **The model assertion** — a UC `type: model` assertion in snapd's
//!    real wire format (headers only, `series: 16`, `body-length` when a
//!    body exists, base64url sha3-384 key id, OpenPGP v4 RSA-SHA512
//!    signature), self-signed through a bootstrapped account chain
//!    (`account-key` carrying the public key as its BODY + `account`,
//!    staged under the recovery system's `assertions/` dir — the same
//!    trust-anchor mechanism snapd's seed loader ReadDirs). The model
//!    carries `grade: dangerous` — a QEMU boot has no TPM and no secure
//!    boot, and the dangerous grade is the documented non-secboot path.
//!
//!    The signature machinery is snapd's own, not an approximation:
//!    snapd's assertion crypto implements ONLY OpenPGP v4 RSA
//!    (`asserts/crypto.go` — `golang.org/x/crypto/openpgp`; there is no
//!    ed25519 anywhere in the codebase), so this module:
//!    - signs assertions with an RSA-4096 key (PKCS#8-persisted at
//!      `~/.config/shuttle/assertion-key.pem`),
//!    - wraps signature bytes as `base64(0x01 ‖ OpenPGP signature packet)`
//!      in 76-column lines (x/crypto's `encodeV1`),
//!    - carries the account-key's public key as its assertion BODY in the
//!      same envelope (`0x01 ‖ public-key packet`), with a `body-length`
//!      header — the stream decoder reads bodies ONLY on that header,
//!    - derives the key id exactly as snapd does:
//!      `base64url(SHA3-384(0x01 ‖ x/crypto-serialized public-key
//!      packet))`.
//!
//!    Every byte of this contract is boot-verified against snap-bootstrap
//!    (2.77, amd64) — the wrong variants fail the seed load with named
//!    errors (`assertion account: "validation" header is mandatory`,
//!    `assertion account: "timestamp" header is not a RFC3339 date`,
//!    `assertion account-key: cannot decode public key: no data`).
//! 4. **The first-boot grub config** — snapd's own `Snapd-Boot-Config-
//!    Edition: 2` recovery config, byte-for-byte the template snapd
//!    installs, staged at `EFI/ubuntu/grub.cfg` (+ `.conf`) on
//!    `ubuntu-seed` — which for the pc gadget IS the ESP, so the firmware
//!    finds it on the bootloader's own path and the `/systems/*` glob sees
//!    the recovery systems.
//!
//! Like [`crate::sign`] (optional post-pass over canonical bytes), this is
//! deliberately a separate module from the painting/staging in
//! [`crate::image`] — the seed emit is pure IR construction + filesystem
//! staging over resolved inputs, unit-testable against fixture trees
//! without running `mkfs`/`parted`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Cursor;
use std::path::Path;

use base64::Engine as _;
use miette::{IntoDiagnostic, WrapErr};

use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::{PublicKey, SecretKey, SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::types::{Password, Timestamp};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::traits::PublicKeyParts;

use crate::image::{base_track, ImageDeclaration};

// ── UC partition role names ──
//
// These become GPT PARTLABELs (via the `name`→PARTLABEL wiring in
// [`crate::image`]) and are matched by the UC initrd's
// `90-ubuntu-core-partitions.rules` as `ID_PART_ENTRY_NAME`. The rule file
// is the source of truth: `ENV{ID_PART_ENTRY_NAME}=="ubuntu-seed"` etc.

/// `ubuntu-seed` — carries the seed (recovery systems + the ESP boot
/// assets for the pc gadget, whose `ubuntu-seed` doubles as the ESP).
pub const UC_SEED_PART: &str = "ubuntu-seed";
/// `ubuntu-boot` — carries `device/modeenv` and the run-mode boot assets.
pub const UC_BOOT_PART: &str = "ubuntu-boot";
/// `ubuntu-data` — the system-data writable snap-bootstrap seeds.
pub const UC_DATA_PART: &str = "ubuntu-data";
/// `ubuntu-save` — the small per-device save writable (UC20+).
pub const UC_SAVE_PART: &str = "ubuntu-save";

// ── Gadget role names (gadget.yaml `structure[].role`) ──
//
// The image DSL partition `role` opt maps to these; they select the UC
// PARTLABEL and the populate routing in the image builder.

pub const ROLE_SEED: &str = "system-seed";
pub const ROLE_BOOT: &str = "system-boot";
pub const ROLE_DATA: &str = "system-data";
pub const ROLE_SAVE: &str = "system-save";

/// Shuttle DSL-only role for a UC gap partition: a structure the gadget
/// declares (the pc gadget's `BIOS Boot`, say) that must EXIST on disk for
/// snapd's gadget validation but is deliberately left unformatted — the
/// build neither mounts nor populates it. Not a gadget.yaml role; the UC
/// PARTLABEL mapping does not apply.
pub const ROLE_GAP: &str = "gap";

/// The UC PARTLABEL a gadget role maps to (gadget.yaml role → partition
/// name). Returns `None` for a non-UC role (or an unimplemented one).
pub fn role_partlabel(role: &str) -> Option<&'static str> {
    match role {
        ROLE_SEED => Some(UC_SEED_PART),
        ROLE_BOOT => Some(UC_BOOT_PART),
        ROLE_DATA => Some(UC_DATA_PART),
        ROLE_SAVE => Some(UC_SAVE_PART),
        _ => None,
    }
}

/// True when the image base is an Ubuntu Core base (a `coreN` snap that
/// selects the UC gadget/seed model). Non-numeric bases (`core`, custom
/// bases) are NOT UC and leave the simplified image path untouched.
pub fn is_uc_base(base_name: &str) -> bool {
    base_track(base_name).is_some()
}

/// True when the UC path must activate for this build: a coreN base AND a
/// layout that marks at least one partition with a UC gadget role. This is
/// the early predicate the builder gates verity/UKI emission on — before
/// any staging runs — so a UC build never assembles a systemd-boot UKI the
/// gadget-proper chain would not boot.
pub fn uc_requested(image: &ImageDeclaration, layout: Option<&crate::image::DiskLayout>) -> bool {
    if !is_uc_base(&image.base.name) {
        return false;
    }
    layout.is_some_and(|d| {
        d.partitions
            .iter()
            .any(|p| crate::image::partition_uc_role(p).is_some())
    })
}

/// `series` header for UC model assertions. NOT the base track — snapd's
/// assertion series has been 16 since snappy and every store model
/// assertion (the embedded generic model included) carries `series: 16`.
pub const MODEL_SERIES: &str = "16";

// ── snapd assertion wire format ──
//
// Verified against the real assertion bytes snapd itself embeds (the
// generic classic model carried by snap-bootstrap):
//
// ```text
// type: model
// authority-id: generic
// series: 16
// ...
// sign-key-sha3-384: d-JcZF9nD9eBw7bwMnH61x-bklnQOhQud1Is6o_cn2wTj8EYDi9musrIT9z2MdAa
// <blank>
// <base64 signature>
// ```
//
// - The key id is the **base64url (unpadded) encoding of the sha3-384
//   digest of the public key** — 64 chars, not hex.
// - The signature covers the full header block **including the
//   sign-key-sha3-384 header**, ending at its newline; the blank line is
//   the wire separator before the signature.
// - Ed25519 signatures encode as base64 of `[SignatureTypeEd25519=1] ++
//   64-byte signature`.

// <blank>
// <base64 signature>
// ```
//
// - The key id is the **base64url (unpadded) encoding of the sha3-384
//   digest of `0x01 ‖ x/crypto-serialized public-key packet`** — 64
//   chars, not hex (asserts/crypto.go `newOpenPGPPubKey`).
// - Assertions without a body sign their header block ONLY (the content
//   ends at the last header's newline — snapd's writer emits no blank
//   line before the signature); assertions WITH a body (account-key)
//   sign headers + blank separator + body, and carry a `body-length`
//   header, without which the stream decoder never reads the body.
// - Signature and key envelopes are x/crypto `encodeV1`:
//   `base64(0x01 ‖ OpenPGP packet)`, wrapped at 76 columns.

/// The snapd assertion signing key: RSA-4096 (the only algorithm snapd's
/// assertion crypto implements), with the x/crypto serialization of its
/// v4 public-key packet and the sha3-384 key id snapd derives from it.
#[derive(Clone)]
pub struct SnapdAssertionKey {
    /// RSA private key (signing).
    secret: rsa::RsaPrivateKey,
    /// The v4 public-key packet in x/crypto `PublicKey.Serialize` form:
    /// new-format header (0x99 + RFC4880 length) + version/created/algo +
    /// MPI n + MPI e. The ID is derived over exactly these bytes.
    public_packet: Vec<u8>,
    /// RFC3339 creation timestamp (the seed epoch pin) for assertion
    /// headers and the packet's creation-time field.
    pub created_rfc3339: String,
}

impl SnapdAssertionKey {
    /// Load the persisted assertion key, or generate one (RSA-4096) on
    /// first use. Stored as PKCS#8 PEM at `~/.config/shuttle/
    /// assertion-key.pem` (mode 0600), like [`crate::sign`]'s manifest
    /// key but a SEPARATE key — the manifest chain keeps its Ed25519
    /// substrate (ADR-0011).
    pub fn load_or_create(home: &Path) -> miette::Result<Self> {
        let dir = home.join(".config").join("shuttle");
        let path = dir.join("assertion-key.pem");
        if path.is_file() {
            let pem = std::fs::read_to_string(&path)
                .into_diagnostic()
                .wrap_err_with(|| format!("reading {}", path.display()))?;
            let secret = rsa::RsaPrivateKey::from_pkcs8_pem(&pem)
                .map_err(|e| miette::miette!("parsing {}: {e}", path.display()))?;
            return Self::from_secret(secret);
        }
        eprintln!("  generating snapd assertion key (RSA-4096, one-time)…");
        let mut rng = rand::thread_rng();
        let secret = rsa::RsaPrivateKey::new(&mut rng, 4096)
            .map_err(|e| miette::miette!("generating the RSA assertion key: {e}"))?;
        let key = Self::from_secret(secret)?;
        std::fs::create_dir_all(&dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("creating {}", dir.display()))?;
        let pem = key
            .secret
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| miette::miette!("encoding the assertion key: {e}"))?;
        std::fs::write(&path, pem.as_bytes())
            .into_diagnostic()
            .wrap_err_with(|| format!("writing {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .into_diagnostic()
                .wrap_err_with(|| format!("restricting {}", path.display()))?;
        }
        Ok(key)
    }

    fn from_secret(secret: rsa::RsaPrivateKey) -> miette::Result<Self> {
        // The public-key packet's creation time is snapd's OWN
        // v1FixedTimestamp (2016-01-01): `RSAPublicKey()` rebuilds every
        // decoded key with that constant before computing the sha3-384
        // id, discarding whatever creation time the body carried. Using
        // anything else makes the id header mismatch snapd's
        // recomputation (`public key does not match provided key id`,
        // boot-observed). It is also a constant, so two builds serialize
        // byte-identical packets (#48 discipline).
        const SNAPD_V1_FIXED_TIMESTAMP_SECS: u32 = 1_451_606_400; // 2016-01-01Z
        let created_rfc3339 = seed_timestamp();
        let public_packet = xcrypto_public_key_packet(&secret, SNAPD_V1_FIXED_TIMESTAMP_SECS);
        Ok(Self {
            secret,
            public_packet,
            created_rfc3339,
        })
    }

    /// The `sign-key-sha3-384` / `public-key-sha3-384` key id: base64url
    /// (unpadded) of the sha3-384 digest over `0x01 ‖ public-key packet`
    /// — byte-for-byte snapd's `newOpenPGPPubKey` derivation.
    pub fn key_id(&self) -> String {
        use sha3::Digest;
        let mut hashed = Vec::with_capacity(self.public_packet.len() + 1);
        hashed.push(1u8);
        hashed.extend_from_slice(&self.public_packet);
        let digest = sha3::Sha3_384::digest(&hashed);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    }

    /// The raw x/crypto-serialized public-key packet (test + verification
    /// handle).
    #[cfg(test)]
    pub fn public_packet_bytes(&self) -> &[u8] {
        &self.public_packet
    }

    /// The public-key packet parsed back (verification handle — the same
    /// object snapd's decoder would hold).
    pub(crate) fn public_key(&self) -> miette::Result<PublicKey> {
        let mut reader = Cursor::new(&self.public_packet);
        let header = pgp::packet::PacketHeader::try_from_reader(&mut reader)
            .map_err(|e| miette::miette!("public-key packet header: {e}"))?;
        PublicKey::try_from_reader(header, &mut reader)
            .map_err(|e| miette::miette!("public-key packet: {e}"))
    }
}

/// Serialize the RSA public key as x/crypto's `PublicKey.Serialize` does:
/// new-format packet header (0x80|0x40|tag=0x99) with the RFC4880 length
/// encoding, then a v4 body — version 4, creation time, algorithm 1
/// (RSA), MPI n, MPI e. snapd re-serializes the DECODED key through this
/// exact code to derive the key id, so byte-exactness here is what makes
/// our id header match snapd's recomputation.
fn xcrypto_public_key_packet(secret: &rsa::RsaPrivateKey, created: u32) -> Vec<u8> {
    let pubkey = rsa::RsaPublicKey::from(secret);
    let mut body = Vec::with_capacity(6 + 2 + 512 + 2 + 3);
    body.push(4); // version
    body.extend_from_slice(&created.to_be_bytes());
    body.push(1); // PubKeyAlgoRSA
    body.extend_from_slice(&mpi(pubkey.n()));
    body.extend_from_slice(&mpi(pubkey.e()));
    let mut out = vec![0x80 | 0x40 | 6]; // new-format packet header, tag 6
    out.extend_from_slice(&rfc4880_length(body.len()));
    out.extend_from_slice(&body);
    out
}

/// An MPI: 2-byte big-endian bit count + minimal big-endian bytes
/// (x/crypto `writeMPI` over a big.Int with leading zeros stripped).
fn mpi(n: &rsa::BigUint) -> Vec<u8> {
    let bytes = n.to_bytes_be();
    let mut out = Vec::with_capacity(bytes.len() + 2);
    out.extend_from_slice(&(n.bits() as u16).to_be_bytes());
    out.extend_from_slice(&bytes);
    out
}

/// RFC4880 §4.2.2 new-format length encoding, exactly x/crypto's
/// `serializeHeader` length branches.
fn rfc4880_length(length: usize) -> Vec<u8> {
    let length = length as u32;
    if length < 192 {
        vec![length as u8]
    } else if length < 8384 {
        let l = length - 192;
        vec![192 + (l >> 8) as u8, l as u8]
    } else {
        vec![
            255,
            (length >> 24) as u8,
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
        ]
    }
}

/// x/crypto `encodeV1`: base64 of `[0x01] ++ data`, wrapped at 76 columns
/// with newlines BETWEEN chunks (none after the last).
fn encode_v1_wrapped(data: &[u8]) -> String {
    let mut raw = Vec::with_capacity(data.len() + 1);
    raw.push(1u8);
    raw.extend_from_slice(data);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
    let mut out = String::with_capacity(b64.len() + b64.len() / 76 + 1);
    for (i, chunk) in b64.as_bytes().chunks(76).enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(std::str::from_utf8(chunk).expect("base64 is utf8"));
    }
    out
}

/// Sign assertion content the way snapd verifies: an OpenPGP v4
/// RSA-SHA512 signature packet over the content bytes, wrapped as
/// `encodeV1` (base64 of `0x01 ‖ packet`, 76-column lines). The
/// creation-time subpacket is pinned to the seed epoch — the RSA
/// computation itself is deterministic (PKCS#1 v1.5), so two builds sign
/// identical bytes (#48).
fn snapd_sign(content: &[u8], key: &SnapdAssertionKey) -> miette::Result<String> {
    let packet_key = packet_secret_key(key)?;
    let created =
        Timestamp::try_from(std::time::UNIX_EPOCH + std::time::Duration::from_secs(seed_epoch().0))
            .map_err(|e| miette::miette!("seed epoch out of range: {e}"))?;
    let mut config = SignatureConfig::v4(
        SignatureType::Binary,
        PublicKeyAlgorithm::RSA,
        HashAlgorithm::Sha512,
    );
    config.hashed_subpackets =
        vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(created))
                .map_err(|e| miette::miette!("creation-time subpacket: {e}"))?,
        ];
    config.unhashed_subpackets = vec![];
    let sig = config
        .sign(&packet_key, &Password::empty(), Cursor::new(content))
        .map_err(|e| miette::miette!("signing the assertion: {e}"))?;
    // rpgp's `Serialize::to_bytes` writes the packet BODY only; the
    // envelope needs the full packet: new-format header (0x80|0x40|tag 2)
    // + RFC4880 length — byte-for-byte what x/crypto's Serialize emits
    // and what the store's own assertion signatures carry.
    let sig_body = pgp::ser::Serialize::to_bytes(&sig)
        .map_err(|e| miette::miette!("serializing the signature packet: {e}"))?;
    let mut packet_bytes = Vec::with_capacity(sig_body.len() + 6);
    packet_bytes.push(0x80 | 0x40 | 2); // new-format packet header, tag 2
    packet_bytes.extend_from_slice(&rfc4880_length(sig_body.len()));
    packet_bytes.extend_from_slice(&sig_body);
    Ok(encode_v1_wrapped(&packet_bytes))
}

/// The rpgp secret-key packet handle the signer needs, parsed back from
/// our own x/crypto-exact public-key packet bytes (the same bytes
/// snapd's decoder sees).
fn packet_secret_key(key: &SnapdAssertionKey) -> miette::Result<SecretKey> {
    let details = key.public_key()?;
    let secret_params = pgp::types::SecretParams::Plain(pgp::types::PlainSecretParams::RSA(
        pgp::crypto::rsa::SecretKey::from(key.secret.clone()),
    ));
    SecretKey::new(details, secret_params)
        .map_err(|e| miette::miette!("assembling the secret key packet: {e}"))
}

/// One snap entry in the model assertion `snaps:` header list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSnap {
    pub name: String,
    /// The store snap-id — every seed snap must be identified (the initrd
    /// cross-checks seed.yaml against the model by name + id).
    pub snap_id: String,
    pub snap_type: String, // "base" | "gadget" | "kernel" | "snapd" | "app"
    pub default_channel: String,
}

/// A UC `type: model` assertion in the snapd wire shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelAssertion {
    /// Assertion series — always [`MODEL_SERIES`] (`16`), not the base track.
    pub series: String,
    pub brand_id: String,
    pub model: String,
    pub architecture: String,
    pub base: String,
    pub grade: String,
    pub storage_safety: String,
    /// RFC3339 timestamp with the `.0` fractional form store assertions use.
    pub timestamp: String,
    pub snaps: Vec<ModelSnap>,
    pub sign_key_sha3_384: String,
}

/// Sanitize an image name into a snap account-id-shaped brand id: the
/// assertion DB accepts `[-a-z0-9]{2,28}` names (the store's 32-char ids
/// are the other accepted shape, reserved to real accounts).
pub fn brand_id_for(image_name: &str) -> String {
    let cleaned: String = image_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let trimmed: String = cleaned
        .trim_matches('-')
        .chars()
        .take(28)
        .collect::<String>()
        .to_lowercase();
    if trimmed.chars().count() < 2 {
        "shuttle".to_string()
    } else {
        trimmed
    }
}

impl ModelAssertion {
    /// Build the model assertion for an image, deriving the snaps list from
    /// the image declaration + resolved snap-ids. `snap_ids` maps store
    /// name → snap-id; every snap that lands in the seed must have one —
    /// a missing entry is a named, fail-closed error.
    pub fn from_image(
        image: &ImageDeclaration,
        arch: &str,
        snap_ids: &BTreeMap<String, String>,
    ) -> miette::Result<Self> {
        if !is_uc_base(&image.base.name) {
            return Err(miette::miette!(
                "cannot build a UC model assertion for base '{}' — not a coreN base",
                image.base.name
            ));
        }
        let need = |name: &str| -> miette::Result<String> {
            snap_ids.get(name).cloned().ok_or_else(|| {
                miette::miette!(
                    "snap '{name}' has no store snap-id — the UC seed identifies every \
                     system snap by snap-id; resolve the image against the store (or set \
                     SHUTTLE_SNAP_IDS='{name}=<snap-id>')"
                )
            })
        };
        let mut snaps = Vec::new();
        snaps.push(ModelSnap {
            name: image.base.name.clone(),
            snap_id: need(&image.base.name)?,
            snap_type: "base".into(),
            default_channel: derive_track_channel(base_track(&image.base.name)),
        });
        snaps.push(ModelSnap {
            name: "snapd".into(),
            snap_id: need("snapd")?,
            snap_type: "snapd".into(),
            default_channel: derive_track_channel(base_track(&image.base.name)),
        });
        if let Some(ref k) = image.kernel {
            snaps.push(ModelSnap {
                name: k.snap.name.clone(),
                snap_id: need(&k.snap.name)?,
                snap_type: "kernel".into(),
                default_channel: explicit_or_derived(&k.channel, base_track(&image.base.name)),
            });
        } else {
            return Err(miette::miette!(
                "the UC seed requires a kernel snap — snapd's first boot cannot seed \
                 a model without one"
            ));
        }
        if let Some(ref g) = image.gadget {
            snaps.push(ModelSnap {
                name: g.name.clone(),
                snap_id: need(&g.name)?,
                snap_type: "gadget".into(),
                default_channel: explicit_or_derived(
                    &image.gadget_channel,
                    base_track(&image.base.name),
                ),
            });
        } else {
            return Err(miette::miette!(
                "the UC seed requires a gadget snap — the gadget defines the boot \
                 chain snap-bootstrap drives (model requires system-seed structure)"
            ));
        }
        for s in &image.extra_snaps {
            // The essentials (base, snapd, kernel, gadget) are already
            // listed — a declaration that names one again (an explicit
            // snapd, say) must not duplicate it: snapd's model check
            // rejects `cannot list the same snap … multiple times`.
            if snaps.iter().any(|m| m.name == s.name) {
                continue;
            }
            snaps.push(ModelSnap {
                name: s.name.clone(),
                snap_id: need(&s.name)?,
                snap_type: "app".into(),
                default_channel: derive_track_channel(base_track(&image.base.name)),
            });
        }
        Ok(Self {
            series: MODEL_SERIES.into(),
            brand_id: brand_id_for(&image.name),
            model: image.name.clone(),
            architecture: arch.to_string(),
            base: image.base.name.clone(),
            // grade: dangerous — the QEMU boot has no TPM/secure boot; the
            // dangerous grade is snapd's documented non-secboot path.
            grade: "dangerous".into(),
            storage_safety: "prefer-unencrypted".into(),
            timestamp: seed_timestamp(),
            snaps,
            sign_key_sha3_384: String::new(),
        })
    }

    /// The canonical header block (including the `sign-key-sha3-384`
    /// header, ending at its newline): exactly the bytes the signature
    /// covers. Deterministic — same header order, same snap order.
    pub fn headers(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "type: model");
        let _ = writeln!(s, "authority-id: {}", self.brand_id);
        let _ = writeln!(s, "series: {}", self.series);
        let _ = writeln!(s, "brand-id: {}", self.brand_id);
        let _ = writeln!(s, "model: {}", self.model);
        let _ = writeln!(s, "architecture: {}", self.architecture);
        let _ = writeln!(s, "base: {}", self.base);
        let _ = writeln!(s, "grade: {}", self.grade);
        let _ = writeln!(s, "storage-safety: {}", self.storage_safety);
        let _ = writeln!(s, "timestamp: {}", self.timestamp);
        // List-of-maps items use a BARE `-` line with the map nested at
        // four spaces: snapd's assertion header parser treats
        // `- name: x` as a scalar item and then rejects the nested keys
        // as top-level headers (`invalid header name: "    id"`,
        // boot-observed). Matches snapd's own model fixtures.
        let _ = writeln!(s, "snaps:");
        for snap in &self.snaps {
            let _ = writeln!(s, "  -");
            let _ = writeln!(s, "    name: {}", snap.name);
            let _ = writeln!(s, "    id: {}", snap.snap_id);
            let _ = writeln!(s, "    type: {}", snap.snap_type);
            let _ = writeln!(s, "    default-channel: {}", snap.default_channel);
        }
        let _ = writeln!(s, "sign-key-sha3-384: {}", self.sign_key_sha3_384);
        s
    }

    /// The full assertion wire text (no body): headers, blank separator,
    /// base64 signature. The signed CONTENT ends at the last header's
    /// VALUE — snapd's writer emits headers each terminated by a newline,
    /// and the content/signature separator supplies the final one, so the
    /// content carries no trailing newline (asserts snap_declaration_test
    /// wire sample). The key id is stamped into the headers first.
    pub fn to_assert(&self, key: &SnapdAssertionKey) -> miette::Result<String> {
        let mut stamped = self.clone();
        stamped.sign_key_sha3_384 = key.key_id();
        let headers = stamped.headers();
        let content = strip_last_newline(headers);
        let mut out = content.clone();
        out.push_str("\n\n");
        out.push_str(&snapd_sign(content.as_bytes(), key)?);
        out.push('\n');
        Ok(out)
    }
}

/// Drop the final newline of a headers block — the content/signature
/// separator (`\n\n` before the signature) supplies it on the wire.
fn strip_last_newline(headers: String) -> String {
    let mut s = headers;
    if s.ends_with('\n') {
        s.pop();
    }
    s
}

/// Recover the effective default channel for a model snap entry: an
/// author-pinned channel wins, otherwise the base's track
/// (`core26` → `26/stable`), ADR-0019 semantics.
fn explicit_or_derived(explicit: &Option<String>, track: Option<&str>) -> String {
    if let Some(ref c) = explicit {
        return c.clone();
    }
    derive_track_channel(track)
}

fn derive_track_channel(track: Option<&str>) -> String {
    match track {
        Some(t) => format!("{t}/stable"),
        None => "latest/stable".into(),
    }
}

// ── Trust anchor: account + account-key assertions ──
//
// snapd's assertion DB bootstraps brand trust from the seed's
// `assertions/database/` directory: an `account-key` assertion is
// self-signed by the key it declares (that IS the onboarding mechanism —
// the key itself carries the proof), the `account` assertion is then
// signed by that key, and the model signed by the same key verifies.

/// The `type: account-key` assertion binding the shuttle Ed25519 public
/// key to the image's brand account. Self-signed by the declared key.
/// The account-key assertion BODY: the public key in snapd's wire encoding
/// — base64 over `format-id byte ++ key bytes` (ed25519 format id is 1),
/// exactly mirroring the `[1u8] ++ sig` signature encoding snapd already
/// accepts from us. Boot-verified: an EMPTY body fails the seed load with
/// `assertion account-key: cannot decode public key: no data`.
/// The account-key assertion BODY: the public key in snapd's wire encoding
/// — x/crypto `encodeV1`: base64 (76-column lines) over
/// `0x01 ‖ public-key packet`. Boot-verified: an EMPTY body fails the
/// seed load with `assertion account-key: cannot decode public key: no
/// data`.
fn snapd_public_key_body(key: &SnapdAssertionKey) -> String {
    encode_v1_wrapped(&key.public_packet)
}

pub fn account_key_assertion(
    key: &SnapdAssertionKey,
    brand_id: &str,
    timestamp: &str,
) -> miette::Result<String> {
    let key_id = key.key_id();
    let body = snapd_public_key_body(key);
    // `body-length` is MANDATORY for a body: the assertion stream decoder
    // reads the body ONLY on that header (`readExact(length)`); without it
    // the body text is consumed as the signature and the parsed body is
    // empty. It counts the RAW body bytes including the line wraps.
    let mut headers = String::new();
    let _ = writeln!(headers, "type: account-key");
    let _ = writeln!(headers, "authority-id: {brand_id}");
    let _ = writeln!(headers, "account-id: {brand_id}");
    let _ = writeln!(headers, "public-key-sha3-384: {key_id}");
    let _ = writeln!(headers, "name: shuttle-image-signing");
    let _ = writeln!(headers, "since: {timestamp}");
    let _ = writeln!(headers, "timestamp: {timestamp}");
    let _ = writeln!(headers, "body-length: {}", body.len());
    let _ = writeln!(headers, "sign-key-sha3-384: {key_id}");
    // The signed content ends at the LAST HEADER'S VALUE (no trailing
    // newline — the content/signature separator supplies it), then the
    // body follows after the separator: content = headers ‖ "\n\n" ‖ body,
    // byte-for-byte snapd's assembleAndSign construction.
    let headers = headers.strip_suffix('\n').unwrap_or(&headers);
    let content = format!("{headers}\n\n{body}");
    let mut out = content.clone();
    out.push_str("\n\n");
    out.push_str(&snapd_sign(content.as_bytes(), key)?);
    out.push('\n');
    Ok(out)
}

/// The `type: account` assertion naming the brand account, signed by the
/// account's key (the chain the model signature verifies through).
pub fn account_assertion(
    key: &SnapdAssertionKey,
    brand_id: &str,
    timestamp: &str,
) -> miette::Result<String> {
    let key_id = key.key_id();
    let mut headers = String::new();
    let _ = writeln!(headers, "type: account");
    let _ = writeln!(headers, "authority-id: {brand_id}");
    let _ = writeln!(headers, "account-id: {brand_id}");
    let _ = writeln!(headers, "display-name: Shuttle image signing account");
    // Mandatory per snapd's account assertion checks (boot-verified: seed
    // load fails with `assertion account: "validation" header is mandatory`
    // without it) — `certified` is what the store's own account carries.
    let _ = writeln!(headers, "validation: certified");
    let _ = writeln!(headers, "timestamp: {timestamp}");
    let _ = writeln!(headers, "sign-key-sha3-384: {key_id}");
    // No body: the signed content ends at the last header's VALUE (no
    // trailing newline — see `strip_last_newline`).
    let headers = headers.strip_suffix('\n').unwrap_or(&headers);
    let mut out = headers.to_string();
    out.push_str("\n\n");
    out.push_str(&snapd_sign(headers.as_bytes(), key)?);
    out.push('\n');
    Ok(out)
}

// ── Seed epoch + recovery-system label ──

/// The build epoch the seed identities derive from: `SOURCE_DATE_EPOCH`
/// when set (reproducible-builds convention), else a fixed default so the
/// same declaration produces byte-identical seeds (#48 discipline).
/// Returns (epoch_secs, YYYYMMDD date string).
pub fn seed_epoch() -> (u64, String) {
    let secs: u64 = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(1_767_225_600); // 2026-01-01T00:00:00Z
    (secs, ts_to_date(secs))
}

/// The recovery-system label for an image: a date-based label (the UC
/// convention) disambiguated by the image version so two images built the
/// same day cannot collide. Deterministic under the seed epoch. The
/// character set is constrained by snapd's own grub config, which matches
/// system labels with `[a-z0-9](-?[a-z0-9])*` — digits and single dashes
/// only, so version dots become dashes.
pub fn recovery_label(image: &ImageDeclaration) -> String {
    let (_, date) = seed_epoch();
    let version: String = image
        .version
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("{date}-{version}")
}

/// RFC3339 timestamp (`.0` fractional form, as store assertions use) for
/// the seed epoch. The DATE PART is RFC3339 (`YYYY-MM-DD`) — snapd parses
/// assertion timestamps with a strict RFC3339 layout and rejects the
/// compact `YYYYMMDD` form the recovery-system LABEL uses (boot-observed:
/// `assertion account: "timestamp" header is not a RFC3339 date`).
pub fn seed_timestamp() -> String {
    let (secs, _) = seed_epoch();
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    format!("{y:04}-{m:02}-{d:02}T00:00:00.0Z")
}

fn ts_to_date(secs: u64) -> String {
    // Minimal civil-date conversion (days since epoch → YYYYMMDD). Avoids a
    // chrono dependency for a derived-serial ID.
    let days = secs / 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}{m:02}{d:02}")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    // Howard Hinnant's days-from-civil inverse algorithm.
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    ((if m <= 2 { y + 1 } else { y }), m, d)
}

// ── seed.yaml ──

/// One staged snap payload for the recovery system.
#[derive(Debug, Clone)]
pub struct SeedSnapFile {
    /// Store snap name (also the seed.yaml `name`).
    pub name: String,
    /// Store snap-id (seed.yaml `snap-id`).
    pub snap_id: String,
    /// Resolved revision.
    pub revision: u32,
    /// Channel the snap resolved from (seed.yaml `channel`).
    pub channel: String,
    /// Snap type (base/gadget/kernel/snapd/app).
    pub snap_type: String,
    /// The local snap file to stage (cache path).
    pub path: std::path::PathBuf,
}

/// Emit a recovery-system `seed.yaml`. This is snapd's seed20 meta
/// (version + label + model + per-snap entries with `file` names), NOT a
/// free-form index — the initrd cross-checks it against the model
/// assertion by name, snap-id, type and revision, then opens every `file`.
pub fn seed_yaml(label: &str, snaps: &[SeedSnapFile]) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "version: 1");
    let _ = writeln!(s, "label: {label}");
    let _ = writeln!(s, "model: model");
    let _ = writeln!(s, "snaps:");
    for snap in snaps {
        let _ = writeln!(s, "  - name: {}", snap.name);
        let _ = writeln!(s, "    snap-id: {}", snap.snap_id);
        let _ = writeln!(s, "    type: {}", snap.snap_type);
        let _ = writeln!(s, "    revision: {}", snap.revision);
        let _ = writeln!(s, "    channel: {}", snap.channel);
        let _ = writeln!(s, "    file: snaps/{}_{}.snap", snap.name, snap.revision);
    }
    s
}

/// A VALID EMPTY GRUB environment block: the signature line, `#` padding,
/// trailing newline — byte-for-byte what `grub-editenv create` emits. The
/// seed's `/EFI/ubuntu/grubenv` must be well-formed because BOTH consumers
/// parse it strictly: grub's `load_env` (an invalid block is the boot-time
/// `error: invalid environment block.`) and snapd's own grubenv reader,
/// which the install completion drives to set `snapd_recovery_mode=run`.
pub fn empty_grubenv() -> [u8; 1024] {
    let mut out = [b'#'; 1024];
    out[..GRUBENV_SIG.len()].copy_from_slice(GRUBENV_SIG);
    out[1023] = b'\n';
    out
}

const GRUBENV_SIG: &[u8] = b"# GRUB Environment Block\n";

/// The `grubenv` content snapd's first-boot grub config consumes
/// (`load_env --file /systems/$label/grubenv snapd_recovery_kernel
/// snapd_extra_cmdline_args snapd_full_cmdline_args`). A grubenv file is
/// EXACTLY 1024 bytes (snapd's writer enforces the same bound); the layout
/// is the environment block format: the signature line, key=value entries,
/// `#` padding, and a trailing newline as the final byte.
pub fn grubenv(recovery_kernel: &str, extra_cmdline: &str) -> [u8; 1024] {
    let mut buf = String::new();
    let _ = writeln!(buf, "# GRUB Environment Block");
    let _ = writeln!(buf, "snapd_recovery_kernel={recovery_kernel}");
    if !extra_cmdline.is_empty() {
        let _ = writeln!(buf, "snapd_extra_cmdline_args={extra_cmdline}");
    }
    let mut out = [b'#'; 1024];
    let n = buf.len().min(1023); // the last byte is the format's newline
    out[..n].copy_from_slice(&buf.as_bytes()[..n]);
    out[1023] = b'\n';
    out
}

// ── The first-boot grub config ──

/// snapd's recovery/first-boot grub config (`Snapd-Boot-Config-Edition:
/// 2`), byte-identical to the template snap-bootstrap carries and installs.
/// Default mode is **install** when the seed's `/EFI/ubuntu/grubenv` carries
/// no mode — the first boot of a shuttle UC image; each `/systems/*` entry
/// is loopback-mounted and chainloaded as `kernel.efi` with the
/// `snapd_recovery_mode`/`snapd_recovery_system` cmdline snap-bootstrap's
/// mode detection consumes.
pub const GRUB_RECOVERY_CFG: &str = r#"# Snapd-Boot-Config-Edition: 2

set default=0
set timeout=3
set timeout_style=hidden

if [ -e /EFI/ubuntu/grubenv ]; then
   load_env --file /EFI/ubuntu/grubenv snapd_recovery_mode snapd_recovery_system
fi

# standard cmdline params
set snapd_static_cmdline_args='panic=-1'

# if no default boot mode set, pick one
if [ -z "$snapd_recovery_mode" ]; then
    set snapd_recovery_mode=install
fi

if [ "$snapd_recovery_mode" = "run" ]; then
    default="run"
elif [ -n "$snapd_recovery_system" ]; then
    default=$snapd_recovery_mode-$snapd_recovery_system
fi

search --no-floppy --set=boot_fs --label ubuntu-boot

if [ "$grub_cpu" = "x86_64" ]; then
    set snapd_static_cmdline_args='console=ttyS0 console=tty1 panic=-1'
    grub_binary="grubx64.efi"
elif [ "$grub_cpu" = "arm64" ]; then
    grub_binary="grubaa64.efi"
else
    echo "$grub_cpu" "is not supported"
    grub_binary="none"
fi

if [ -n "$boot_fs" ]; then
    menuentry "Continue to run mode" --hotkey=n --id=run {
        set root=($boot_fs)
        chainloader ($boot_fs)/EFI/boot/"$grub_binary"
    }
fi

# globbing in grub does not sort
for label in /systems/*; do
    # match the system labels generated by snapd, which are usually just
    # numbers. eg. 20210706, but can be hyphen separated numbers and letters
    if ! regexp --set 1:label "/([a-z0-9](-?[a-z0-9])*)\$" "$label"; then
        continue
    fi
    # yes, you need to backslash that less-than
    if [ -z "$best" -o "$label" \< "$best" ]; then
        set best="$label"
    fi
    # if grubenv did not pick mode-system, use best one
    if [ -z "$snapd_recovery_system" ]; then
        default=$snapd_recovery_mode-$best
    fi
    set snapd_recovery_kernel=
    load_env --file /systems/$label/grubenv snapd_recovery_kernel snapd_extra_cmdline_args snapd_full_cmdline_args
    set cmdline_args="$snapd_static_cmdline_args $snapd_extra_cmdline_args"
    if [ -n "$snapd_full_cmdline_args" ]; then
       set cmdline_args="$snapd_full_cmdline_args"
    fi

    # We could "source /systems/$snapd_recovery_system/grub.cfg" here as well
    menuentry "Recover using $label" --hotkey=r --id=recover-$label $snapd_recovery_kernel recover $label {
        loopback loop $2
        chainloader (loop)/kernel.efi snapd_recovery_mode=$3 snapd_recovery_system=$4 $cmdline_args
    }
    menuentry "Install using $label" --hotkey=i --id=install-$label $snapd_recovery_kernel install $label {
        loopback loop $2
        chainloader (loop)/kernel.efi snapd_recovery_mode=$3 snapd_recovery_system=$4 $cmdline_args
    }
    menuentry "Factory reset using $label" --hotkey=i --id=factory-reset-$label $snapd_recovery_kernel factory-reset $label {
        loopback loop $2
        chainloader (loop)/kernel.efi snapd_recovery_mode=$3 snapd_recovery_system=$4 $cmdline_args
    }
done

menuentry 'UEFI Firmware Settings' --hotkey=f 'uefi-firmware' {
    fwsetup
}
"#;

// ── Staging ──

/// The gadget snap's EFI boot assets, mapped to their on-seed targets
/// (gadget.yaml `structure[].content` for the pc gadget's `ubuntu-seed`).
#[derive(Debug, Clone)]
pub struct GadgetEfiAssets {
    /// `(gadget-relative source file, seed-relative target)` pairs.
    pub mappings: Vec<(std::path::PathBuf, String)>,
}

/// The pc gadget's `ubuntu-seed` content mapping (gadget.yaml, rev 227):
/// shim + grub under `EFI/ubuntu` (the path the firmware's bootloader
/// search and the `.csv` fallback agree on) plus the removable-media
/// fallback pair under `EFI/boot`.
pub fn pc_gadget_efi_assets() -> GadgetEfiAssets {
    GadgetEfiAssets {
        mappings: vec![
            ("grubx64.efi".into(), "EFI/ubuntu/grubx64.efi".into()),
            ("shim.efi.signed".into(), "EFI/ubuntu/shimx64.efi".into()),
            ("boot.csv".into(), "EFI/ubuntu/bootx64.csv".into()),
            ("fb.efi".into(), "EFI/boot/fbx64.efi".into()),
            ("shim.efi.signed".into(), "EFI/boot/bootx64.efi".into()),
        ],
    }
}

/// Inputs for [`stage_seed_tree`] — everything one recovery system needs,
/// resolved by the caller (which owns the runner for gadget extraction).
pub struct SeedStageInputs<'a> {
    pub label: &'a str,
    /// The extracted GADGET snap tree (the EFI assets come from it).
    pub gadget_tree: &'a Path,
    pub gadget_assets: &'a GadgetEfiAssets,
    /// The kernel snap's `kernel.efi` UKI (the first-boot chainloader).
    pub kernel_efi: &'a Path,
    /// Kernel cmdline extras (declared `kernel.params`) written into the
    /// system grubenv as `snapd_extra_cmdline_args` so the serial console
    /// reaches both the initrd and the installed system.
    pub extra_cmdline: &'a str,
    pub model: &'a ModelAssertion,
    pub snaps: &'a [SeedSnapFile],
    /// The snapd assertion signing key (RSA/OpenPGP — what snap-bootstrap
    /// verifies).
    pub key: &'a SnapdAssertionKey,
}

/// Write the full `ubuntu-seed` tree into a staging directory:
///
/// ```text
/// <seed_stage>/
///   EFI/ubuntu/{grub.cfg,grub.conf,grubx64.efi,shimx64.efi,bootx64.csv}
///   EFI/boot/{bootx64.efi,fbx64.efi}
///   EFI/ubuntu/grubenv          (empty — grub defaults the mode to install)
///   assertions/database/{account,account-key}
///   systems/<label>/
///     model                     (signed model assertion)
///     seed.yaml
///     grubenv                   (snapd_recovery_kernel + extra cmdline)
///     kernel.efi                (kernel snap UKI)
///     snaps/<name>_<rev>.snap   (every seed payload)
/// ```
pub fn stage_seed_tree(seed_stage: &Path, inputs: &SeedStageInputs<'_>) -> miette::Result<()> {
    std::fs::create_dir_all(seed_stage)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", seed_stage.display()))?;

    // 1. Gadget EFI boot assets (fail closed — the chain needs all of them).
    for (source, target) in &inputs.gadget_assets.mappings {
        let src = inputs.gadget_tree.join(source);
        if !src.is_file() {
            return Err(miette::miette!(
                "gadget snap lacks boot asset '{}' — the UC seed stages the \
                 gadget's own chain (gadget.yaml content); refusing to build a seed \
                 the firmware cannot boot",
                source.display()
            ));
        }
        let dst = seed_stage.join(target);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)
                .into_diagnostic()
                .wrap_err_with(|| format!("creating {}", parent.display()))?;
        }
        std::fs::copy(&src, &dst)
            .into_diagnostic()
            .wrap_err_with(|| format!("staging {} → {}", src.display(), dst.display()))?;
    }

    // 2. First-boot grub config — both names snapd's tooling uses, so the
    //    firmware path (grub.cfg) and snapd's managed name (grub.conf) agree.
    for name in ["EFI/ubuntu/grub.cfg", "EFI/ubuntu/grub.conf"] {
        let dst = seed_stage.join(name);
        std::fs::write(&dst, GRUB_RECOVERY_CFG)
            .into_diagnostic()
            .wrap_err_with(|| format!("writing {}", dst.display()))?;
    }
    // The seed-level grubenv stays a VALID EMPTY environment block: grub's
    // `load_env` parses it silently and the Edition-2 config defaults the
    // mode to `install` (the first-boot behavior we need); snapd's install
    // completion later writes `snapd_recovery_mode=run` into this exact
    // file through its own signature-checking grubenv reader.
    std::fs::write(seed_stage.join("EFI/ubuntu/grubenv"), empty_grubenv())
        .into_diagnostic()
        .wrap_err("writing the seed grubenv")?;

    // 3. The trust anchor — account-key + account as FLAT assertion files
    //    under the RECOVERY SYSTEM's assertions/ dir. The seed loader
    //    (seed/helpers loadAssertions) ReadDir's that dir and parses every
    //    entry as an assertion stream — no zips, no database subdir.
    let ts = seed_timestamp();
    let adb = seed_stage
        .join("systems")
        .join(inputs.label)
        .join("assertions");
    std::fs::create_dir_all(&adb)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", adb.display()))?;
    std::fs::write(
        adb.join("account-key"),
        account_key_assertion(inputs.key, &inputs.model.brand_id, &ts)?,
    )
    .into_diagnostic()
    .wrap_err("writing assertions/account-key")?;
    std::fs::write(
        adb.join("account"),
        account_assertion(inputs.key, &inputs.model.brand_id, &ts)?,
    )
    .into_diagnostic()
    .wrap_err("writing assertions/account")?;

    // 4. The recovery system.
    let sys_dir = seed_stage.join("systems").join(inputs.label);
    std::fs::create_dir_all(sys_dir.join("snaps"))
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", sys_dir.display()))?;
    std::fs::write(sys_dir.join("model"), inputs.model.to_assert(inputs.key)?)
        .into_diagnostic()
        .wrap_err("writing systems/<label>/model")?;
    std::fs::write(
        sys_dir.join("seed.yaml"),
        seed_yaml(inputs.label, inputs.snaps),
    )
    .into_diagnostic()
    .wrap_err("writing systems/<label>/seed.yaml")?;
    std::fs::write(
        sys_dir.join("grubenv"),
        grubenv(
            &format!("/systems/{}/kernel.efi", inputs.label),
            inputs.extra_cmdline,
        ),
    )
    .into_diagnostic()
    .wrap_err("writing systems/<label>/grubenv")?;
    if !inputs.kernel_efi.is_file() {
        return Err(miette::miette!(
            "the kernel snap carries no kernel.efi — snapd's grub chain bootstraps \
             the recovery system through it (loopback + chainloader); refusing to \
             build a seed the first boot cannot start"
        ));
    }
    std::fs::copy(inputs.kernel_efi, sys_dir.join("kernel.efi"))
        .into_diagnostic()
        .wrap_err("staging systems/<label>/kernel.efi")?;
    for snap in inputs.snaps {
        if !snap.path.is_file() {
            return Err(miette::miette!(
                "seed snap '{}' not staged in the cache at {} — refusing to build a \
                 seed with a missing essential payload",
                snap.name,
                snap.path.display()
            ));
        }
        let dst = sys_dir
            .join("snaps")
            .join(format!("{}_{}.snap", snap.name, snap.revision));
        std::fs::copy(&snap.path, &dst)
            .into_diagnostic()
            .wrap_err_with(|| format!("staging {}", dst.display()))?;
    }
    Ok(())
}

// ── modeenv ──

/// The `ubuntu-boot/device/modeenv` content. `mode=run` plus the seed,
/// kernel, gadget and recovery-system references snap-bootstrap's mode
/// detection reads to avoid `cannot detect mode nor recovery system to use`.
///
/// `recovery_label` is the system label under `ubuntu-seed/systems/<label>/`
/// that carries this image's model + seed. `kernel_name`/`gadget_name` are
/// snap names (`pc-kernel`, `pc`) formatted to the `_<rev>` seed filename
/// convention; `base_name` likewise.
///
/// No `bootloader` key is emitted, deliberately (issue #72): snapd's modeenv
/// parser (`boot.Modeenv`, verified against snapd 2.76.3) defines no such
/// key — unknown keys are carried in `extrakeys` and never read — and the
/// bootloader names snap-bootstrap does implement are `grub`, `u-boot`,
/// `android-boot`, `piboot` and `lk` (gadget.yaml validation), not
/// `systemd-boot`. The bootloader identity is recorded in the image
/// manifest instead.
pub fn modeenv(
    recovery_label: &str,
    kernel_name: Option<&str>,
    base_name: &str,
    gadget_name: Option<&str>,
) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "mode=run");
    let _ = writeln!(s, "ubuntu_boot=ubuntu-boot");
    let _ = writeln!(s, "ubuntu_seed=ubuntu-seed");
    let _ = writeln!(s, "ubuntu_save=ubuntu-save");
    let _ = writeln!(s, "kernel_status=none");
    if let Some(k) = kernel_name {
        let _ = writeln!(s, "snap_kernel={k}_1.snap");
    }
    let _ = writeln!(s, "snap_core={base_name}_1.snap");
    if let Some(g) = gadget_name {
        let _ = writeln!(s, "snap_gadget={g}_1.snap");
    }
    let _ = writeln!(s, "snap_recovery_system={recovery_label}");
    // No `bootloader=` line: snapd's modeenv defines no such key; anything
    // written here is dead data to snap-bootstrap (see doc comment, #72).
    s
}

/// Write `ubuntu-boot/device/modeenv` into a staging directory.
pub fn emit_modeenv(
    boot_stage: &Path,
    recovery_label: &str,
    kernel_name: Option<&str>,
    base_name: &str,
    gadget_name: Option<&str>,
) -> miette::Result<()> {
    let device_dir = boot_stage.join("device");
    std::fs::create_dir_all(&device_dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", device_dir.display()))?;
    std::fs::write(
        device_dir.join("modeenv"),
        modeenv(recovery_label, kernel_name, base_name, gadget_name),
    )
    .into_diagnostic()
    .wrap_err("writing device/modeenv")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixture image declaration: the UC26 chain #28 builds.
    fn sample_image() -> ImageDeclaration {
        crate::image::test_support::sample_image()
    }

    fn snap_ids() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("core24".into(), "CQaUVdoKPUs8ekLmXsVwYGbTqUuDnyt2".into()),
            ("snapd".into(), "PMrrV4nl8Bewqvd2qJfWq0rkGODW30if".into()),
            (
                "pc-kernel".into(),
                "DjYcoStxHLAaZ86Rln_XYVbYwLr0S2mZ".into(),
            ),
            ("pc".into(), "99T7MUlRhtI3U0QFgl5mXXESAiSwt776".into()),
            (
                "network-manager".into(),
                "B9B7uy4iTkTVp9Sxr4HbLK0UXDTKsJwN".into(),
            ),
        ])
    }

    #[test]
    fn is_uc_base_detects_core_n() {
        assert!(is_uc_base("core22"));
        assert!(is_uc_base("core26"));
        assert!(!is_uc_base("core"));
        assert!(!is_uc_base("my-base"));
    }

    #[test]
    fn role_partlabel_maps_uc_roles() {
        assert_eq!(role_partlabel(ROLE_SEED), Some(UC_SEED_PART));
        assert_eq!(role_partlabel(ROLE_BOOT), Some(UC_BOOT_PART));
        assert_eq!(role_partlabel(ROLE_DATA), Some(UC_DATA_PART));
        assert_eq!(role_partlabel(ROLE_SAVE), Some(UC_SAVE_PART));
        assert_eq!(role_partlabel("other"), None);
    }

    #[test]
    fn brand_ids_fit_the_assertion_db_shape() {
        assert_eq!(
            brand_id_for("ubuntu-core-uc26-seed"),
            "ubuntu-core-uc26-seed"
        );
        assert_eq!(brand_id_for("My_Weird.Image!"), "my-weird-image");
        assert_eq!(brand_id_for("x"), "shuttle");
        // ≤28 chars, [-a-z0-9] only.
        let long = brand_id_for("a-very-long-image-name-that-keeps-going");
        assert!(long.len() <= 28);
        assert!(long
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
    }

    #[test]
    fn model_assertion_carries_the_real_wire_shape() {
        let image = sample_image();
        let model = ModelAssertion::from_image(&image, "amd64", &snap_ids()).unwrap();
        // snapd assertion series is 16 — not the base track.
        assert_eq!(model.series, "16");
        assert_eq!(model.grade, "dangerous");
        assert_eq!(model.base, "core24");
        assert_eq!(model.brand_id, "test-uc");
        assert!(model.timestamp.ends_with("00:00:00.0Z"));
        // RFC3339 date part WITH dashes — snapd's assertion parser rejects
        // the compact YYYYMMDD label form (boot-observed first-boot
        // failure).
        assert!(
            model.timestamp.contains("-"),
            "timestamp {:?} is not RFC3339 (missing date dashes)",
            model.timestamp
        );
        assert_eq!(model.timestamp.len(), "YYYY-MM-DDTHH:MM:SS.0Z".len());
        // kernel + gadget + base + snapd all identified.
        let names: Vec<&str> = model.snaps.iter().map(|s| s.name.as_str()).collect();
        for n in ["core24", "snapd", "pc-kernel", "pc"] {
            assert!(names.contains(&n), "model snaps lack {n}");
        }
        let headers = model.headers();
        // Headers only — no blank line inside (the body is empty).
        assert!(!headers.contains("\n\n"));
        assert!(headers.starts_with("type: model\n"));
        assert!(headers.contains("authority-id: test-uc\n"));
        // Every snap entry carries its store id + type.
        assert!(headers.contains(
            "  -\n    name: core24\n    id: CQaUVdoKPUs8ekLmXsVwYGbTqUuDnyt2\n    type: base\n"
        ));
        assert!(headers.contains(
            "  -\n    name: pc-kernel\n    id: DjYcoStxHLAaZ86Rln_XYVbYwLr0S2mZ\n    type: kernel\n"
        ));
        assert!(headers.contains("    type: gadget\n"));
        assert!(headers.contains("    type: snapd\n"));
        assert!(headers.ends_with("sign-key-sha3-384: \n")); // empty until stamped
                                                             // The fixture declares base, kernel, gadget (+ snapd implied) —
                                                             // exactly one of each essential type.
        for t in ["base", "kernel", "gadget", "snapd"] {
            assert_eq!(
                headers.matches(&format!("    type: {t}\n")).count(),
                1,
                "exactly one {t}"
            );
        }
    }

    /// A fast RSA fixture key for assertion-emission tests (2048 bits —
    /// snapd's decoder imposes no minimum, and the production loader
    /// generates 4096).
    fn test_key() -> SnapdAssertionKey {
        let mut rng = rand::thread_rng();
        let secret = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        SnapdAssertionKey::from_secret(secret).unwrap()
    }

    #[test]
    fn signed_assertion_matches_the_snapd_wire_format() {
        let key = test_key();
        let image = sample_image();
        let model = ModelAssertion::from_image(&image, "amd64", &snap_ids()).unwrap();
        let assert_text = model.to_assert(&key).unwrap();

        // Split at the LAST header's newline + the blank separator.
        let key_id = key.key_id();
        let header_tail = format!("sign-key-sha3-384: {key_id}\n");
        let pos = assert_text
            .find(&header_tail)
            .expect("stamped key id header present");
        let headers_end = pos + header_tail.len();
        // No body: the signed content ends at the LAST HEADER'S VALUE —
        // the separator after it supplies the final newline (snapd's
        // writer convention, matches the store's own wire samples).
        let content = &assert_text[..headers_end - 1];
        let rest = &assert_text[headers_end - 1..];
        assert!(
            rest.starts_with("\n\n"),
            "the blank separator completes the content/signature split"
        );

        // Envelope: base64( [0x01] ++ OpenPGP v4 RSA-SHA512 signature
        // packet ), verified with the public key — snapd's exact verify
        // path (content hash + signature trailer + RSA). assert.rs's
        // parser can't handle the model's multi-line `snaps:` list header
        // (store assertions have none), so assemble the verifier input
        // directly: content bytes + 0x01-stripped OpenPGP packets.
        let sig_text = rest[1..].trim_end();
        let joined: String = sig_text.split_whitespace().collect();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(joined.as_bytes())
            .unwrap();
        assert_eq!(raw[0], 1, "x/crypto v1 envelope prefix");
        let assertion = crate::assert::Assertion {
            assertion_type: "model".into(),
            authority_id: model.brand_id.clone(),
            sign_key_id: key_id,
            headers: BTreeMap::new(),
            content: content.as_bytes().to_vec(),
            body: Vec::new(),
            signature_packets: raw[1..].to_vec(),
        };
        crate::assert::verify_signature("model", "model", &assertion, &key.public_key().unwrap())
            .unwrap();
    }

    #[test]
    fn snapd_key_id_is_base64url_sha3_384_of_the_public_key() {
        let key = test_key();
        let id = key.key_id();
        use sha3::Digest;
        let mut hashed = Vec::new();
        hashed.push(1u8);
        hashed.extend_from_slice(&key.public_packet_bytes());
        let digest = sha3::Sha3_384::digest(&hashed);
        let expect = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        assert_eq!(id, expect);
        // 48 bytes → 64 unpadded base64url chars, like the generic model's id.
        assert_eq!(id.len(), 64);
        assert!(!id.contains('='));
        assert!(id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn account_chain_bootstraps_the_brand_trust() {
        let key = test_key();
        let brand = "test-brand";
        let ts = "2026-01-01T00:00:00.0Z";
        let ak = account_key_assertion(&key, brand, ts).unwrap();
        let acc = account_assertion(&key, brand, ts).unwrap();
        // Drive OUR OWN snapd-grammar verifier over the emitted bytes —
        // the same parse + envelope + OpenPGP verification assert.rs runs
        // against Store assertions.
        let ak_parsed = crate::assert::parse_assertion("account-key", &ak).unwrap();
        assert_eq!(ak_parsed.assertion_type, "account-key");
        // The body carries the public key packet (0x01 ‖ packet).
        assert!(!ak_parsed.body.is_empty(), "account-key body present");
        let pk =
            crate::assert::public_key_from_body("account-key", "body", &ak_parsed.body).unwrap();
        crate::assert::verify_signature("account-key", "self", &ak_parsed, &pk).unwrap();
        // The account-key id header matches snapd's derivation over the body key.
        assert!(ak.contains(&format!("public-key-sha3-384: {}\n", key.key_id())));
        assert!(ak.contains("body-length: "));

        // The account is signed by the SAME key and verifies against it.
        let acc_parsed = crate::assert::parse_assertion("account", &acc).unwrap();
        assert!(acc.contains("validation: certified\n"));
        crate::assert::verify_signature("account", "account", &acc_parsed, &pk).unwrap();
    }

    #[test]
    fn model_fails_closed_without_snap_ids_or_essentials() {
        let image = sample_image();
        // No ids at all → the first lookup fails by name.
        let err = ModelAssertion::from_image(&image, "amd64", &BTreeMap::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("no store snap-id"), "{err}");
        // A kernel-free image is refused outright.
        let mut no_kernel = image.clone();
        no_kernel.kernel = None;
        let err = ModelAssertion::from_image(&no_kernel, "amd64", &snap_ids())
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires a kernel snap"), "{err}");
        let mut no_gadget = image.clone();
        no_gadget.gadget = None;
        let err = ModelAssertion::from_image(&no_gadget, "amd64", &snap_ids())
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires a gadget snap"), "{err}");
    }

    #[test]
    fn seed_yaml_is_the_snapd_seed20_shape() {
        let snaps = vec![SeedSnapFile {
            name: "pc".into(),
            snap_id: "99T7MUlRhtI3U0QFgl5mXXESAiSwt776".into(),
            revision: 227,
            channel: "26/stable".into(),
            snap_type: "gadget".into(),
            path: "unused".into(),
        }];
        let yaml = seed_yaml("20260101_26_04", &snaps);
        assert!(yaml.starts_with("version: 1\n"));
        assert!(yaml.contains("label: 20260101_26_04\n"));
        assert!(yaml.contains("model: model\n"));
        assert!(yaml.contains("    snap-id: 99T7MUlRhtI3U0QFgl5mXXESAiSwt776\n"));
        assert!(yaml.contains("    revision: 227\n"));
        assert!(yaml.contains("    file: snaps/pc_227.snap\n"));
    }

    #[test]
    fn grubenv_is_exactly_1024_bytes_with_the_recovery_kernel() {
        let env = grubenv("/systems/20260101_26_04/kernel.efi", "console=ttyS0");
        assert_eq!(env.len(), 1024);
        let text = String::from_utf8_lossy(&env);
        assert!(text.contains("# GRUB Environment Block\n"));
        assert!(text.contains("snapd_recovery_kernel=/systems/20260101_26_04/kernel.efi\n"));
        assert!(text.contains("snapd_extra_cmdline_args=console=ttyS0\n"));
        // The tail is '#' filler (grub's environment block padding) with
        // the format's trailing newline as the FINAL byte — snapd's writer
        // ends every env block exactly this way.
        assert!(env.iter().rev().take(10).skip(1).all(|&b| b == b'#'));
        assert_eq!(env[1023], b'\n');
    }

    #[test]
    fn empty_grubenv_is_a_valid_environment_block() {
        let env = empty_grubenv();
        assert_eq!(env.len(), 1024);
        // Signature line first — grub's load_env and snapd's grubenv reader
        // both hard-fail without it (`invalid environment block`).
        assert!(env.starts_with(b"# GRUB Environment Block\n"));
        // No entries between the signature and the padding: no mode var is
        // preselected, so the Edition-2 grub config defaults to install.
        assert_eq!(&env[25..1023], &[b'#'; 998]);
        assert_eq!(env[1023], b'\n');
    }

    #[test]
    fn modeenv_references_run_mode_and_seed_gadget_core() {
        let text = modeenv("20260909_1_0_0", Some("pc-kernel"), "core26", Some("pc"));
        assert!(text.starts_with("mode=run\n"));
        assert!(text.contains("snap_core=core26_1.snap"));
        assert!(text.contains("snap_kernel=pc-kernel_1.snap"));
        assert!(text.contains("snap_gadget=pc_1.snap"));
        assert!(text.contains("snap_recovery_system=20260909_1_0_0"));
        // Deliberate spec change (#72): modeenv carries no `bootloader` key —
        // snapd's parser (snapd 2.76.3, boot.Modeenv) has no such key, and
        // `systemd-boot` is not a name snap-bootstrap implements.
        assert!(!text.contains("bootloader="));
    }

    #[test]
    fn recovery_label_is_deterministic_and_grub_safe() {
        let image = sample_image();
        let a = recovery_label(&image);
        let b = recovery_label(&image);
        assert_eq!(
            a, b,
            "same declaration → same label (SOURCE_DATE_EPOCH pin)"
        );
        // snapd's grub config matches system labels with
        // [a-z0-9](-?[a-z0-9])* — a label outside that set gets skipped by
        // the /systems/* loop and nothing boots.
        assert!(a.chars().next().unwrap().is_ascii_digit(), "{a}");
        assert!(
            a.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "{a}"
        );
        assert!(!a.contains("--"), "{a}");
    }

    /// A fixture seed tree: tiny fake payloads + the pc gadget EFI layout.
    /// Leaks the fixture dirs so the inputs can borrow 'static (test-only).
    fn fixture_inputs() -> SeedStageInputs<'static> {
        let fixture = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let gadget = fixture.path().join("gadget");
        std::fs::create_dir_all(&gadget).unwrap();
        for f in ["grubx64.efi", "shim.efi.signed", "boot.csv", "fb.efi"] {
            std::fs::write(gadget.join(f), format!("fake-{f}")).unwrap();
        }
        let kernel_efi = fixture.path().join("kernel.efi");
        std::fs::write(&kernel_efi, b"fake-uki").unwrap();
        let snap = fixture.path().join("core26_462.snap");
        std::fs::write(&snap, b"fake-base-snap").unwrap();
        let snaps = vec![SeedSnapFile {
            name: "core26".into(),
            snap_id: "CQaUVdoKPUs8ekLmXsVwYGbTqUuDnyt2".into(),
            revision: 462,
            channel: "latest/stable".into(),
            snap_type: "base".into(),
            path: snap,
        }];
        let model = ModelAssertion {
            series: MODEL_SERIES.into(),
            brand_id: "fixture".into(),
            model: "fixture-img".into(),
            architecture: "amd64".into(),
            base: "core26".into(),
            grade: "dangerous".into(),
            storage_safety: "prefer-unencrypted".into(),
            timestamp: "2026-01-01T00:00:00.0Z".into(),
            snaps: vec![],
            sign_key_sha3_384: String::new(),
        };
        SeedStageInputs {
            label: "20260101_26_04",
            gadget_tree: Box::leak(Box::new(gadget)),
            gadget_assets: Box::leak(Box::new(pc_gadget_efi_assets())),
            kernel_efi: Box::leak(Box::new(kernel_efi)),
            extra_cmdline: "console=ttyS0",
            model: Box::leak(Box::new(model)),
            snaps: Box::leak(Box::new(snaps)),
            key: Box::leak(Box::new(test_key())),
        }
    }

    #[test]
    fn stage_seed_tree_writes_the_full_recovery_layout() {
        let home = tempfile::tempdir().unwrap();
        let inputs = fixture_inputs();
        let stage = home.path().join("seed");
        stage_seed_tree(&stage, &inputs).unwrap();

        // Gadget EFI chain at the firmware's paths.
        for p in [
            "EFI/ubuntu/grubx64.efi",
            "EFI/ubuntu/shimx64.efi",
            "EFI/ubuntu/bootx64.csv",
            "EFI/boot/fbx64.efi",
            "EFI/boot/bootx64.efi",
        ] {
            assert!(stage.join(p).is_file(), "missing {p}");
        }
        // First-boot grub config in both spellings + the (empty) seed grubenv.
        for p in ["EFI/ubuntu/grub.cfg", "EFI/ubuntu/grub.conf"] {
            let text = std::fs::read_to_string(stage.join(p)).unwrap();
            assert!(text.starts_with("# Snapd-Boot-Config-Edition: 2\n"), "{p}");
            assert!(text.contains("set snapd_recovery_mode=install"));
        }
        assert_eq!(
            std::fs::metadata(stage.join("EFI/ubuntu/grubenv"))
                .unwrap()
                .len(),
            1024
        );
        // Trust anchor: the recovery system's assertions dir carries flat
        // assertion files (seed loadAssertions ReadDir + AddStream).
        let adb = stage.join("systems/20260101_26_04/assertions");
        let ak = std::fs::read_to_string(adb.join("account-key")).unwrap();
        let acc = std::fs::read_to_string(adb.join("account")).unwrap();
        assert!(ak.starts_with("type: account-key\n"));
        assert!(ak.contains("\nsign-key-sha3-384: "));
        // The public key rides the assertion BODY (x/crypto encodeV1:
        // base64 of 0x01 ‖ public-key packet) with a mandatory
        // `body-length` header — an empty/undeclared body fails the seed
        // load (`cannot decode public key: no data`).
        assert!(ak.contains("\nbody-length: "));
        let body = ak.split("\n\n").nth(1).unwrap_or("");
        let body_main = body.split_once("\n\n").map(|(b, _)| b).unwrap_or(body);
        assert!(
            !body_main.trim().is_empty(),
            "account-key body must carry the public key"
        );
        let joined: String = body_main.split_whitespace().collect();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&joined)
                .unwrap()
                .first(),
            Some(&1u8),
            "account-key body must start with the v1 envelope prefix"
        );
        assert!(acc.starts_with("type: account\n"));
        // The validation header is mandatory per snapd's account checks —
        // its absence fails the seed load on the first boot (observed:
        // `assertion account: "validation" header is mandatory`).
        assert!(acc.contains("\nvalidation: certified\n"));
        // The recovery system.
        let sys = stage.join("systems/20260101_26_04");
        assert!(sys.join("model").is_file());
        assert!(sys.join("seed.yaml").is_file());
        assert!(sys.join("kernel.efi").is_file());
        assert_eq!(std::fs::read(sys.join("kernel.efi")).unwrap(), b"fake-uki");
        assert!(sys.join("snaps/core26_462.snap").is_file());
        let env = std::fs::read(sys.join("grubenv")).unwrap();
        assert_eq!(env.len(), 1024);
        assert!(String::from_utf8_lossy(&env)
            .contains("snapd_recovery_kernel=/systems/20260101_26_04/kernel.efi"));
        // Exactly one recovery system staged.
        let labels: Vec<_> = std::fs::read_dir(stage.join("systems"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(labels.len(), 1);
    }

    #[test]
    fn stage_seed_tree_fails_closed_on_missing_gadget_assets_or_kernel() {
        let home = tempfile::tempdir().unwrap();
        let mut inputs = fixture_inputs();
        // Drop a gadget asset: the seed would not boot — refuse.
        let broken_gadget = tempfile::tempdir().unwrap();
        std::fs::write(broken_gadget.path().join("grubx64.efi"), b"x").unwrap();
        inputs.gadget_tree = Box::leak(Box::new(broken_gadget.path().to_path_buf()));
        let stage = home.path().join("seed1");
        let err = stage_seed_tree(&stage, &inputs).unwrap_err().to_string();
        assert!(err.contains("lacks boot asset 'shim.efi.signed'"), "{err}");
        // The failing asset never landed.
        assert!(!stage.join("EFI/ubuntu/shimx64.efi").exists());

        // And a kernel snap without kernel.efi is refused too.
        let mut inputs2 = fixture_inputs();
        let no_uki = home.path().join("nope.efi");
        inputs2.kernel_efi = Box::leak(Box::new(no_uki));
        let stage2 = home.path().join("seed2");
        let err = stage_seed_tree(&stage2, &inputs2).unwrap_err().to_string();
        assert!(err.contains("carries no kernel.efi"), "{err}");
    }

    #[test]
    fn grub_recovery_cfg_defaults_to_install_and_loops_the_system_kernel() {
        let cfg = GRUB_RECOVERY_CFG;
        assert!(cfg.contains("# Snapd-Boot-Config-Edition: 2\n"));
        // Default mode = install (the first-boot behavior).
        assert!(cfg.contains("if [ -z \"$snapd_recovery_mode\" ]; then"));
        assert!(cfg.contains("set snapd_recovery_mode=install"));
        // The run-mode continuation searches ubuntu-boot (snapd manages it).
        assert!(cfg.contains("search --no-floppy --set=boot_fs --label ubuntu-boot"));
        // The install entry loopback-mounts the system kernel and passes the
        // mode + label snap-bootstrap detects.
        assert!(cfg.contains("loopback loop $2"));
        assert!(cfg.contains("chainloader (loop)/kernel.efi snapd_recovery_mode=$3 snapd_recovery_system=$4 $cmdline_args"));
        // Per-system grubenv drives the kernel choice.
        assert!(cfg.contains("load_env --file /systems/$label/grubenv snapd_recovery_kernel"));
    }
}
