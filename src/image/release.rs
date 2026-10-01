//! `nau image --release` — the deterministic mission-media
//! publication path (ADR-0044 Decisions 5 + 8, issue #266).
//!
//! Cassini ships named artifacts, not ad-hoc builds. One release run
//! builds ONE declared disk image with `SOURCE_DATE_EPOCH` pinned (the
//! CLI refuses to release without a pinned epoch) and emits the media
//! set into the ADR-0033 Decision 10 export tree — a plain directory any
//! static web server can serve:
//!
//! - `nau-<mission>-<version>-<arch>.img` — the whole-disk GPT mission
//!   image (ADR-0013 vocabulary: `nau` + the release-level mission
//!   codename, NOT the declaration's `name`; the identity matrix #263
//!   pinned in [`super::boot`]).
//! - `nau-<mission>-<version>-<arch>.manifest.json` — the SIGNED image
//!   manifest: the build's authoritative boot-facts manifest (roothash,
//!   cmdline, UKI, ESP identity) with the operator's Ed25519 signature
//!   attached.
//! - the sysupdate transfer payloads (#274, images with an
//!   `update_source`) — `root_<version>_<data-partuuid>.img`,
//!   `verity-hash_<version>_<hash-partuuid>.img`, `<name>_<version>.efi`:
//!   the build's own root/verity extents and staged UKI, copied under the
//!   exact names the emitted transfers fetch (`@u` expands to the
//!   roothash-derived PARTUUID). Every byte is a build output; nothing is
//!   recomputed.
//! - `SHA256SUMS` — coreutils-format (`<sha256>␠␠<name>`), one line per
//!   published file (media set + payloads), deterministic order.
//! - `SHA256SUMS.gpg` (#267) — the detached OpenPGP signature over the
//!   SHA256SUMS manifest, signed by the ceremony key's sysupdate
//!   identity: what systemd-sysupdate's `Verify=yes` checks at update
//!   time against the base rootfs's embedded
//!   `/usr/lib/systemd/import-pubring.pgp`.
//!
//! # The signature scheme (must interoperate with `nau verify-image`)
//!
//! The signed body is [`super::verify::image_manifest_canonical_bytes`] —
//! the typed image manifest serialized with the signatures map emptied —
//! NEVER the eval manifest's [`crate::sign::eval_manifest_canonical_bytes`]
//! (a different type, a different scheme; the eval signer is named for
//! what it signs so this sentence can be checked mechanically). The
//! signature is a bare base64 Ed25519 entry under the operator key's id,
//! and [`super::verify::verify_manifest_signature_at`] accepts it under
//! the ADR-0024 §4 anchor policy (revoked-first, then ANY of `--key` +
//! `~/.config/nau/keys/*.pub`). Tests pin the sign→verify round-trip
//! through that exact seam.
//!
//! The SHA256SUMS signature is deliberately NOT part of that scheme
//! family: systemd-sysupdate enforces it itself (OpenPGP, raw bytes — no
//! canonicalization), via [`crate::sign::sign_sysupdate_manifest`].
//!
//! # The baked-in release checklist (ADR-0044 D8)
//!
//! The verify advice this flow used to only print is now EXECUTED: before
//! the media set is reported, the release self-check runs in-process over
//! the published set ([`self_check`]) — the same device policy
//! `nau verify-image` applies, plus the device-side SHA256SUMS
//! signature round-trip (#293 item 4). Two steps CANNOT run in-process
//! and stay BLOCKING on the operator, printed with the media set, never
//! silently skipped, never faked by this flow:
//!
//! - `examples/rebuild-compare.sh` byte-identity across two machines
//!   BEFORE the media set is distributed;
//! - the ADR-0013 trademark pre-release sweep.
//!
//! No transport/upload happens here (ADR-0044: publication lanes are
//! #274's territory) — the release ends at a servable directory.

use std::path::{Path, PathBuf};

use super::*;

/// Arguments of one `nau image --release` invocation (gathered by the
/// CLI in [`crate::cli`]; the library entry takes the struct so tests
/// drive the same path the binary does).
#[derive(Debug, Clone)]
pub struct ReleaseArgs {
    /// The ADR-0033 D10 export tree root the media set lands in. The
    /// directory is created when missing; existing files with media-set
    /// names are overwritten (a release re-run republishes in place).
    pub dir: PathBuf,
}

/// The release media stem: `nau-<mission>-<version>-<arch>` (ADR-0044 D5,
/// ADR-0013 vocabulary). The mission codename is the release-level
/// constant [`super::boot::DISTRO_CODENAME`] — a future mission bump is a
/// one-constant change, exactly as #263 recorded.
pub fn release_stem(version: &str, arch: &str) -> String {
    format!(
        "{}-{}-{}-{}",
        super::boot::DISTRO_ID,
        super::boot::DISTRO_CODENAME.to_lowercase(),
        version,
        arch
    )
}

/// The published media-set filenames for one release, in SHA256SUMS order
/// (sorted — the deterministic order [`std::collections::BTreeMap`]
/// gives).
pub fn media_set(version: &str, arch: &str) -> [String; 2] {
    let stem = release_stem(version, arch);
    [format!("{stem}.img"), format!("{stem}.manifest.json")]
}

/// One per-partition update payload the release publishes (#274): an
/// already-built artifact copied into the release directory under the
/// name its sysupdate transfer fetches.
#[derive(Debug, Clone)]
pub struct ReleasePayload {
    /// The transient build artifact — the populated+verity-formatted root
    /// extent file, its verity-hash extent file, or the staged UKI.
    pub src: PathBuf,
    /// The published file name — the transfer's Source `MatchPattern`
    /// with `@v`/`@u` expanded (version + roothash-derived PARTUUID).
    pub name: String,
}

/// The payload set for a verity A/B build (#274): the populated+verity-
/// formatted root extent, its verity-hash extent, and the staged UKI —
/// every byte already built, nothing recomputed. The names follow the
/// emitted transfers' Source MatchPatterns verbatim (`root_@v_@u.img`,
/// `verity-hash_@v_@u.img`, `{name}_@v.efi`), with `@u` = the
/// roothash-derived PARTUUID the build pinned on its slots
/// ([`super::generation_guids_from_roothash`]) — the substitution
/// systemd-sysupdate performs at update time. The consumer-side contract
/// test below parses the actual drop-ins and refuses any divergence from
/// the published sums.
pub(crate) fn update_payloads(
    image_name: &str,
    version: &str,
    root_extent: &Path,
    hash_extent: &Path,
    data_guid: &str,
    hash_guid: &str,
    uki_stage: &Path,
) -> Vec<ReleasePayload> {
    vec![
        ReleasePayload {
            src: root_extent.to_path_buf(),
            name: format!("root_{version}_{data_guid}.img"),
        },
        ReleasePayload {
            src: hash_extent.to_path_buf(),
            name: format!("verity-hash_{version}_{hash_guid}.img"),
        },
        ReleasePayload {
            src: uki_stage.to_path_buf(),
            name: format!("{image_name}_{version}.efi"),
        },
    ]
}

/// Attach the operator's Ed25519 signature to an image manifest over its
/// CANONICAL BODY — [`super::verify::image_manifest_canonical_bytes`], the
/// typed manifest with the signatures map emptied. This is the exact
/// scheme `nau verify-image` checks; the round-trip test below drives
/// the verify side's own seam to pin the interop.
///
/// Prior signatures keep verifying (the canonical bytes never include the
/// map), so re-signing under a successor key is a plain second call.
pub fn sign_image_manifest(
    manifest: &mut ImageManifest,
    kp: &crate::sign::KeyPair,
) -> miette::Result<()> {
    let canonical = super::verify::image_manifest_canonical_bytes(manifest)?;
    let signature = crate::sign::sign_bytes(&canonical, kp);
    manifest
        .signatures
        .insert(kp.key_id(), serde_json::Value::String(signature));
    Ok(())
}

/// Publish the release media set: sign a copy of the build's
/// authoritative manifest, write it beside the (already release-named)
/// image, persist the sysupdate transfer payloads beside it (#274), write
/// `SHA256SUMS` + its signature over everything, then EXECUTE the release
/// self-check in-process over the published set (#293 item 4) before
/// printing the media set with the blocking checklist.
///
/// Trust paths resolve through the central fail-closed HOME helper
/// ([`super::verify::operator_home`], #285/#293 item 8) — an unset HOME
/// refuses instead of anchoring trust from the CWD.
pub fn publish(
    runner: &dyn crate::command::CommandRunner,
    img: &Path,
    manifest: &ImageManifest,
    arch: &str,
    args: &ReleaseArgs,
    payloads: &[ReleasePayload],
) -> miette::Result<()> {
    let home = super::verify::operator_home()?;
    let (dir, img_name, manifest_name, kp) =
        publish_with(&home, img, manifest, arch, args, payloads)?;
    // The printed verify advice, executed (#293 item 4): the published
    // set must pass the SAME device policy verify-image applies — under
    // the keychain this release signed with — before anyone can call it a
    // release. The checklist print below is only what CANNOT run here.
    self_check(
        runner,
        &dir,
        &img_name,
        &manifest_name,
        &crate::sign::keys_dir(&home),
        super::verity::find_veritysetup().as_deref(),
        super::verity::find_host_tool("mcopy").as_deref(),
        &kp,
    )?;
    report_media_set(&dir, &img_name, &manifest_name, payloads, &kp);
    Ok(())
}

/// The in-process release self-check over the PUBLISHED media set (#293
/// item 4): what the checklist used to only advertise, executed. Two
/// halves, both device-shaped:
///
/// 1. [`super::verify::verify_device_at`] over the published image +
///    published signed manifest under the release's OWN keychain — the
///    GPT identity, slot resolution, truncation, ESP UKI digest (#284),
///    and dm-verity recompute `nau verify-image` runs, minus the
///    HOME dependency (the release signs and proves under the same
///    keychain).
/// 2. The update-night round-trip: the published `SHA256SUMS` verifies
///    under its published signature against the pubring the build embeds
///    at `/usr/lib/systemd/import-pubring.pgp` — in-process, the exact
///    check the guest's `Verify=yes` gpg subprocess performs.
///
/// The operator-side checklist items (rebuild-compare, trademark) cannot
/// run here and stay printed as BLOCKING. Costs one region-extract pass
/// over the image (the verify-image price) — the release is not in a
/// hurry; a set that cannot verify its own bytes is not a release.
#[allow(clippy::too_many_arguments)]
pub(crate) fn self_check(
    runner: &dyn crate::command::CommandRunner,
    dir: &Path,
    img_name: &str,
    manifest_name: &str,
    keys_dir: &Path,
    veritysetup: Option<&Path>,
    mcopy: Option<&Path>,
    kp: &crate::sign::KeyPair,
) -> miette::Result<()> {
    let args = super::VerifyImageArgs {
        device: dir.join(img_name),
        manifest: dir.join(manifest_name),
        key: None,
        slot: super::SlotSelector::Auto,
    };
    let outcome = super::verify::verify_device_at(runner, &args, veritysetup, mcopy, keys_dir)?;
    let sums = std::fs::read(dir.join("SHA256SUMS"))
        .into_diagnostic()
        .wrap_err("reading the published SHA256SUMS")?;
    let sig = std::fs::read(dir.join(crate::sign::SYSUPDATE_MANIFEST_SIGNATURE_NAME))
        .into_diagnostic()
        .wrap_err("reading the published SHA256SUMS signature")?;
    let pubring = crate::sign::import_pubring_pgp(kp)?;
    crate::sign::verify_sysupdate_manifest_signature(&pubring, &sums, &sig)?;
    eprintln!(
        "  ✓ release self-check passed in-process: verify-image device policy \
         over the published set (slot {}, roothash {}…) and the device-side \
         SHA256SUMS.gpg round-trip (#293)",
        outcome.slot,
        &outcome.roothash[..8.min(outcome.roothash.len())]
    );
    Ok(())
}

/// [`publish`] with the key home explicit — the test seam (mirrors
/// [`super::verify::verify_manifest_signature_at`]'s split). Writes the whole
/// media set and returns `(release dir, image file name, manifest file
/// name, signing key)`; the report and the self-check are the caller's
/// (the tests drive the write path on toy bytes no real verify could
/// pass).
pub(crate) fn publish_with(
    home: &Path,
    img: &Path,
    manifest: &ImageManifest,
    arch: &str,
    args: &ReleaseArgs,
    payloads: &[ReleasePayload],
) -> miette::Result<(PathBuf, String, String, crate::sign::KeyPair)> {
    // The signing key is the same ceremony key the build already demanded
    // for update_source images: load fail-closed, never mint.
    let kp = super::load_signing_key_fail_closed(home)?;

    let dir = &args.dir;
    std::fs::create_dir_all(dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating release export tree {}", dir.display()))?;

    // The staged-rootfs copy of the manifest stays UNSIGNED (byte-stable
    // doctrine: the build's own artifact must not change); signatures ride
    // the PUBLISHED copy only.
    let stem = release_stem(&manifest.version, arch);
    let manifest_name = format!("{stem}.manifest.json");
    let manifest_json = write_published_manifest(dir, manifest, &kp, &manifest_name)?;

    // The per-partition payloads land BEFORE the sums, so the sums only
    // ever name files the directory actually serves.
    publish_payloads(dir, payloads)?;

    // The media file name for the report + the sums body (the file name
    // must exist — the sums cover the image bytes).
    let img_name = media_file_name(img)?;
    write_sums_and_signature(
        dir,
        img,
        &img_name,
        manifest_json.as_bytes(),
        &manifest_name,
        payloads,
        &kp,
    )?;

    Ok((dir.clone(), img_name, manifest_name, kp))
}

/// The published image's media-set file name (the sums cover it by this
/// exact name).
fn media_file_name(img: &Path) -> miette::Result<String> {
    img.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| miette::miette!("release image {} has no file name", img.display()))
}

/// Persist the build's per-partition payloads into the release directory
/// under their `@u`-PARTUUID names (#274). Fail-closed: a missing
/// artifact refuses BEFORE any sums are written — a release that names a
/// payload it cannot serve is not a release.
fn publish_payloads(dir: &Path, payloads: &[ReleasePayload]) -> miette::Result<()> {
    for payload in payloads {
        let dst = dir.join(&payload.name);
        std::fs::copy(&payload.src, &dst)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "publishing update payload {} from {}",
                    payload.name,
                    payload.src.display()
                )
            })?;
        eprintln!("  ✓ update payload: {} (carved, not rebuilt)", payload.name);
    }
    Ok(())
}

/// Write `SHA256SUMS` + its detached OpenPGP signature
/// ([`crate::sign::SYSUPDATE_MANIFEST_SIGNATURE_NAME`], #267) under
/// `dir`, returning the sums body the signature covers.
fn write_sums_and_signature(
    dir: &Path,
    img: &Path,
    img_name: &str,
    manifest_json: &[u8],
    manifest_name: &str,
    payloads: &[ReleasePayload],
    kp: &crate::sign::KeyPair,
) -> miette::Result<String> {
    let sums_body = sha256sums_body(img, img_name, manifest_json, manifest_name, payloads)?;
    let sums_path = dir.join("SHA256SUMS");
    std::fs::write(&sums_path, &sums_body)
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", sums_path.display()))?;
    let sums_sig = crate::sign::sign_sysupdate_manifest(kp, sums_body.as_bytes())?;
    let sums_sig_path = dir.join(crate::sign::SYSUPDATE_MANIFEST_SIGNATURE_NAME);
    std::fs::write(&sums_sig_path, &sums_sig)
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", sums_sig_path.display()))?;
    Ok(sums_body)
}

/// Write the SIGNED published manifest (a clone of the build's
/// authoritative one — the staged-rootfs copy stays unsigned) and return
/// its exact bytes.
fn write_published_manifest(
    dir: &Path,
    manifest: &ImageManifest,
    kp: &crate::sign::KeyPair,
    manifest_name: &str,
) -> miette::Result<String> {
    let mut published = manifest.clone();
    sign_image_manifest(&mut published, kp)?;
    let manifest_json = serde_json::to_string_pretty(&published)
        .map_err(|e| miette::miette!("release manifest serialization: {e}"))?;
    let manifest_path = dir.join(manifest_name);
    std::fs::write(&manifest_path, &manifest_json)
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", manifest_path.display()))?;
    Ok(manifest_json)
}

/// The coreutils-format SHA256SUMS body: one `<hash>␠␠<name>` line per
/// published file — the image, the signed manifest, and every sysupdate
/// transfer payload (#274; never the sums themselves) — names sorted by
/// the BTreeMap for a byte-stable file.
fn sha256sums_body(
    img: &Path,
    img_name: &str,
    manifest_json: &[u8],
    manifest_name: &str,
    payloads: &[ReleasePayload],
) -> miette::Result<String> {
    let mut sums = std::collections::BTreeMap::new();
    sums.insert(img_name.to_string(), sha256_file(img)?);
    sums.insert(manifest_name.to_string(), sha256_bytes(manifest_json));
    for payload in payloads {
        sums.insert(payload.name.clone(), sha256_file(&payload.src)?);
    }
    Ok(sums
        .iter()
        .map(|(name, hash)| format!("{hash}  {name}\n"))
        .collect())
}

/// The operator-facing media-set report plus the BLOCKING checklist items
/// this flow deliberately does not run for you (ADR-0044 D8).
fn report_media_set(
    dir: &Path,
    img_name: &str,
    manifest_name: &str,
    payloads: &[ReleasePayload],
    kp: &crate::sign::KeyPair,
) {
    let epoch = std::env::var("SOURCE_DATE_EPOCH").unwrap_or_else(|_| "<unset>".into());
    eprintln!(
        "  ✓ release media set in {} (SOURCE_DATE_EPOCH={epoch}):",
        dir.display()
    );
    eprintln!("      {img_name}");
    eprintln!("      {manifest_name}  (signed, key {})", kp.key_id());
    for payload in payloads {
        eprintln!("      {}  (sysupdate transfer payload)", payload.name);
    }
    eprintln!("      SHA256SUMS");
    eprintln!(
        "      {}  (Verify=yes anchor: import-pubring.pgp in the base rootfs)",
        crate::sign::SYSUPDATE_MANIFEST_SIGNATURE_NAME
    );
    if !payloads.is_empty() {
        eprintln!(
            "  ℹ update serving (sysupdate Path= semantics): the transfer payloads \
             above and SHA256SUMS/{} are SIBLINGS — url-file transfers resolve \
             SHA256SUMS and every MatchPattern name RELATIVE to the transfer's \
             Path= (the update_source URL), so this directory is the served \
             update root (#274).",
            crate::sign::SYSUPDATE_MANIFEST_SIGNATURE_NAME
        );
    }
    eprintln!(
        "  ℹ release checklist (ADR-0044 D8) — BLOCKING before distribution: run \
         examples/rebuild-compare.sh for two-machine byte-identity; the ADR-0013 \
         trademark sweep remains blocking. The verify pass itself ran in-process \
         above (#293): anchors still travel OUT-OF-BAND (ADR-0033 D7) — any --key \
         is a copy from the ceremony keychain, NEVER a file served beside this \
         media set; a --key fetched with the download is a self-bless. Procedure: \
         docs/nau-ops-runbook.md §7."
    );
}

fn sha256_bytes(bytes: &[u8]) -> String {
    use sha2::Digest;
    to_lower_hex(&sha2::Sha256::digest(bytes))
}

/// The read chunk for [`sha256_file`]: 1 MiB — large enough that a
/// multi-GB image hashes in few syscalls, small enough that the buffer is
/// noise next to the media it digests.
const SHA256_STREAM_CHUNK: usize = 1024 * 1024;

/// SHA-256 of a file, STREAMED in fixed chunks. A release image is
/// multi-GB; buffering it whole with `std::fs::read` OOMed release hosts
/// (#293 item 5). The digest is identical to the one-shot form — pinned
/// by `sha256_file_matches_the_one_shot_digest_across_chunks`.
fn sha256_file(path: &Path) -> miette::Result<String> {
    let file = std::fs::File::open(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("hashing {}", path.display()))?;
    let mut reader = std::io::BufReader::with_capacity(SHA256_STREAM_CHUNK, file);
    let mut hasher = sha2::Sha256::new();
    std::io::copy(&mut reader, &mut hasher)
        .into_diagnostic()
        .wrap_err_with(|| format!("hashing {}", path.display()))?;
    use sha2::Digest;
    Ok(to_lower_hex(&hasher.finalize()))
}

fn to_lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOTHASH: &str = "1111111122222222333333334444444455555555666666667777777788888888";

    /// The canonical test keypair (deterministic seed) — the same helper
    /// verify.rs's tests use, so both sides of the round-trip share one
    /// key shape.
    fn test_kp(seed_byte: u8) -> crate::sign::KeyPair {
        let seed = [seed_byte; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        crate::sign::KeyPair {
            seed,
            public: sk.verifying_key().to_bytes(),
        }
    }

    fn manifest() -> ImageManifest {
        ImageManifest {
            name: "nau-demo".into(),
            version: "1.0.0".into(),
            arch: "amd64".into(),
            snaps: vec![],
            kernel_version: Some("6.11.0".into()),
            cmdline: Some("root=PARTUUID=... quiet".into()),
            uki: Some(FIXTURE_UKI_NAME.into()),
            uki_sha3_384: Some(fixture_uki_sha3()),
            esp_partuuid: None,
            roothash: Some(ROOTHASH.into()),
            signatures: Default::default(),
        }
    }

    /// The UKI filename the fixture manifest pins (the build's
    /// `{name}_{version}.efi` shape).
    const FIXTURE_UKI_NAME: &str = "nau-demo_1.0.0.efi";

    /// The UKI bytes the FakeTools' mcopy materializes — the "factory"
    /// boot content the fixture manifest pins (same helper shape as
    /// verify.rs's tests, so both sides of the round-trip share one key
    /// and content shape).
    fn fixture_uki() -> Vec<u8> {
        b"UKI-PE-284-FACTORY-BYTES".to_vec()
    }

    fn fixture_uki_sha3() -> String {
        use sha3::Digest;
        let mut hasher = sha3::Sha3_384::new();
        hasher.update(fixture_uki());
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn temp_home(tag: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join(tag);
        std::fs::create_dir_all(&home).unwrap();
        // The ceremony key lives at <home>/.config/nau/secret-key.
        let keys = crate::sign::secret_key_path(&home);
        std::fs::create_dir_all(keys.parent().unwrap()).unwrap();
        (dir, home)
    }

    fn write_secret_key(home: &Path, kp: &crate::sign::KeyPair) {
        let path = crate::sign::secret_key_path(home);
        std::fs::write(
            &path,
            format!(
                "untrusted comment: nau signing secret key (ed25519)\n{}\n",
                hex_encode(&kp.seed)
            ),
        )
        .unwrap();
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // ── Naming ──

    #[test]
    fn release_stem_uses_the_adr0013_vocabulary() {
        assert_eq!(release_stem("1.0.0", "amd64"), "nau-cassini-1.0.0-amd64");
        assert_eq!(release_stem("2.1", "arm64"), "nau-cassini-2.1-arm64");
        // Media names derive from the DISTRO constants, never the
        // declaration's name — the #263 release-level fact.
        assert_eq!(
            media_set("1.0.0", "amd64")[0],
            "nau-cassini-1.0.0-amd64.img"
        );
        assert_eq!(
            media_set("1.0.0", "amd64")[1],
            "nau-cassini-1.0.0-amd64.manifest.json"
        );
    }

    // ── The sign↔verify interop pin ──

    #[test]
    fn release_signature_verifies_through_the_verify_side_seam() {
        let (_guard, home) = temp_home("home");
        let keys_dir = crate::sign::keys_dir(&home);
        let kp = test_kp(7);
        crate::sign::install_public_key(&kp, &keys_dir).unwrap();

        let mut m = manifest();
        sign_image_manifest(&mut m, &kp).unwrap();
        assert_eq!(m.signatures.len(), 1);

        // The EXACT device policy verify-image applies: unsigned refuses,
        // revoked-first, then ANY-anchor over the IMAGE canonical bytes.
        let key_id = super::verify::verify_manifest_signature_at(&m, None, &keys_dir).unwrap();
        assert_eq!(key_id, kp.key_id());
    }

    #[test]
    fn release_signature_covers_the_canonical_body_tamper_refuses() {
        let (_guard, home) = temp_home("home");
        let keys_dir = crate::sign::keys_dir(&home);
        let kp = test_kp(7);
        crate::sign::install_public_key(&kp, &keys_dir).unwrap();

        let mut m = manifest();
        sign_image_manifest(&mut m, &kp).unwrap();

        // Any body mutation — here the roothash, the manifest's most
        // security-relevant field — invalidates the signature.
        let mut tampered = m.clone();
        tampered.roothash = Some("f".repeat(64));
        assert!(super::verify::verify_manifest_signature_at(&tampered, None, &keys_dir).is_err());

        // The untampered manifest still verifies (the map never covers
        // itself, and the refused attempt above never mutated `m`).
        assert!(super::verify::verify_manifest_signature_at(&m, None, &keys_dir).is_ok());
    }

    #[test]
    fn foreign_anchor_refuses_a_release_signature() {
        let (_guard, home) = temp_home("home");
        let keys_dir = crate::sign::keys_dir(&home);
        // Anchored on a DIFFERENT operator key than the signer.
        crate::sign::install_public_key(&test_kp(9), &keys_dir).unwrap();

        let mut m = manifest();
        sign_image_manifest(&mut m, &test_kp(7)).unwrap();
        assert!(super::verify::verify_manifest_signature_at(&m, None, &keys_dir).is_err());
    }

    #[test]
    fn revoked_signer_refuses_before_any_anchor_check() {
        let (_guard, home) = temp_home("home");
        let keys_dir = crate::sign::keys_dir(&home);
        let kp = test_kp(7);
        crate::sign::install_public_key(&kp, &keys_dir).unwrap();
        // ADR-0024 §4: the revocation list outranks the anchor set.
        std::fs::write(keys_dir.join("revoked-keys"), format!("{}\n", kp.key_id())).unwrap();

        let mut m = manifest();
        sign_image_manifest(&mut m, &kp).unwrap();
        let err = super::verify::verify_manifest_signature_at(&m, None, &keys_dir)
            .expect_err("a revoked signer must refuse");
        assert!(
            format!("{err:#}").contains("REVOKED"),
            "refusal must name the revocation: {err:#}"
        );
    }

    #[test]
    fn unsigned_body_never_verifies_even_with_anchors() {
        let (_guard, home) = temp_home("home");
        let keys_dir = crate::sign::keys_dir(&home);
        crate::sign::install_public_key(&test_kp(7), &keys_dir).unwrap();
        assert!(super::verify::verify_manifest_signature_at(&manifest(), None, &keys_dir).is_err());
    }

    // ── Publish: determinism + SHA256SUMS ──

    /// The release fixture's image identity — the same name/version the
    /// drop-ins in the contract test are generated from, so the fixture
    /// and the transfer emitters cannot drift apart unnoticed.
    const FIXTURE_IMAGE_NAME: &str = "nau-demo";
    const FIXTURE_VERSION: &str = "1.0.0";

    fn publish_fixture(
        tag: &str,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        ReleaseArgs,
        Vec<String>,
    ) {
        let (_home_guard, home) = temp_home("home");
        let kp = test_kp(7);
        write_secret_key(&home, &kp);

        let work = tempfile::tempdir().unwrap();
        let dir = work.path().join(tag);
        std::fs::create_dir_all(&dir).unwrap();
        // The real flow builds the image INTO the release dir (cmd_image
        // points output_dir at the export tree) — mirror that.
        let img = dir.join("nau-cassini-1.0.0-amd64.img");
        std::fs::write(&img, b"whole-disk-bytes").unwrap();
        // The build's transient per-partition artifacts (#274): the
        // verity-formatted root extent, its hash extent, the staged UKI —
        // deterministic bytes a republish reproduces.
        let build = work.path().join("build");
        std::fs::create_dir_all(&build).unwrap();
        let root_extent = build.join("root.img");
        std::fs::write(&root_extent, b"verity-formatted-root-extent").unwrap();
        let hash_extent = build.join("verity-hash.img");
        std::fs::write(&hash_extent, b"verity-hash-extent").unwrap();
        let uki_stage = build.join(format!("{FIXTURE_IMAGE_NAME}_{FIXTURE_VERSION}.efi"));
        std::fs::write(&uki_stage, b"uki-pe-bytes").unwrap();
        // Payload names come from the REAL producer, never hand-rolled —
        // the contract test pins them against the drop-ins.
        let (data_guid, hash_guid) = super::generation_guids_from_roothash(ROOTHASH).unwrap();
        let payloads = update_payloads(
            FIXTURE_IMAGE_NAME,
            FIXTURE_VERSION,
            &root_extent,
            &hash_extent,
            &data_guid,
            &hash_guid,
            &uki_stage,
        );
        let args = ReleaseArgs { dir: dir.clone() };
        publish_with(&home, &img, &manifest(), "amd64", &args, &payloads).unwrap();
        let names = payloads.iter().map(|p| p.name.clone()).collect();
        (work, home, dir, args, names)
    }

    /// The ticket's unit verify at the release layer: the same build
    /// output published twice lands a BYTE-IDENTICAL media set — image,
    /// signed manifest, SHA256SUMS, its detached signature (#267), and
    /// the carved transfer payloads (#274; two builds at the same epoch
    /// produce identical build bytes by the build's own determinism; the
    /// release layer must not add variance).
    #[test]
    fn two_publishes_of_the_same_build_are_byte_identical() {
        let (_g1, _h1, dir1, _a1, _p1) = publish_fixture("release-a");
        let (_g2, _h2, dir2, _a2, _p2) = publish_fixture("release-b");
        let (data_guid, hash_guid) = super::generation_guids_from_roothash(ROOTHASH).unwrap();
        for name in [
            "nau-cassini-1.0.0-amd64.manifest.json".to_string(),
            "SHA256SUMS".to_string(),
            crate::sign::SYSUPDATE_MANIFEST_SIGNATURE_NAME.to_string(),
            format!("root_{FIXTURE_VERSION}_{data_guid}.img"),
            format!("verity-hash_{FIXTURE_VERSION}_{hash_guid}.img"),
            format!("{FIXTURE_IMAGE_NAME}_{FIXTURE_VERSION}.efi"),
        ] {
            let a = std::fs::read(dir1.join(&name)).unwrap();
            let b = std::fs::read(dir2.join(&name)).unwrap();
            assert_eq!(a, b, "{name} must be byte-identical across publishes");
        }
    }

    #[test]
    fn publish_signs_the_sysupdate_manifest_for_the_verify_yes_layer() {
        // #267: SHA256SUMS.gpg exists beside SHA256SUMS and verifies the
        // published sums bytes against the pubring the SAME ceremony key
        // anchors into the rootfs — the sign↔verify round-trip the device
        // will run (systemd-sysupdate Verify=yes), driven here through
        // the exact release output.
        let (_g, _h, dir, _a, _payload_names) = publish_fixture("release");
        let sums = std::fs::read(dir.join("SHA256SUMS")).unwrap();
        let sig = std::fs::read(dir.join(crate::sign::SYSUPDATE_MANIFEST_SIGNATURE_NAME)).unwrap();
        assert!(!sig.is_empty(), "a published release carries a signature");
        let pubring = crate::sign::import_pubring_pgp(&test_kp(7)).unwrap();
        crate::sign::verify_sysupdate_manifest_signature(&pubring, &sums, &sig)
            .expect("the published SHA256SUMS.gpg verifies under the ceremony anchor");

        // A tampered SHA256SUMS refuses BY NAME.
        let mut tampered = sums.clone();
        let last = tampered.len() - 2;
        tampered[last] ^= 0x01;
        let err = crate::sign::verify_sysupdate_manifest_signature(&pubring, &tampered, &sig)
            .expect_err("tampered sysupdate manifest must refuse");
        assert!(
            format!("{err:#}").contains("SHA256SUMS"),
            "the refusal names the manifest: {err:#}"
        );
    }

    #[test]
    fn sums_cover_exactly_the_release_files_in_coreutils_format() {
        let (_g, _h, dir, _a, _payload_names) = publish_fixture("release");
        let body = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 5, "media set + payloads: {body}");
        // Sorted (BTreeMap) order — the manifest line sorts before the
        // image line, the payloads slot in by name.
        let (data_guid, hash_guid) = super::generation_guids_from_roothash(ROOTHASH).unwrap();
        let mut names = Vec::new();
        for line in &lines {
            let (hash, name) = line.split_once("  ").expect("two-space separator");
            assert_eq!(hash.len(), 64, "sha256 hex: {line}");
            assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
            names.push(name.to_string());
        }
        names.sort();
        assert_eq!(
            names,
            vec![
                "nau-cassini-1.0.0-amd64.img".to_string(),
                "nau-cassini-1.0.0-amd64.manifest.json".to_string(),
                format!("{FIXTURE_IMAGE_NAME}_{FIXTURE_VERSION}.efi"),
                format!("root_{FIXTURE_VERSION}_{data_guid}.img"),
                format!("verity-hash_{FIXTURE_VERSION}_{hash_guid}.img"),
            ]
        );
        // The sums are the real digests of the PUBLISHED files,
        // independently recomputed.
        for line in &lines {
            let (hash, name) = line.split_once("  ").unwrap();
            let bytes = std::fs::read(dir.join(name)).unwrap();
            let expect = {
                use sha2::Digest;
                let d = sha2::Sha256::digest(&bytes);
                d.iter().map(|b| format!("{b:02x}")).collect::<String>()
            };
            assert_eq!(hash, expect, "{name} digest");
        }
    }

    #[test]
    fn release_without_transfer_payloads_sums_only_the_media_set() {
        // Non-sysupdate images (no A/B, no update_source) keep today's
        // shape: an empty payload set publishes exactly the media set.
        let (_home_guard, home) = temp_home("home");
        write_secret_key(&home, &test_kp(7));
        let work = tempfile::tempdir().unwrap();
        let dir = work.path().join("release");
        std::fs::create_dir_all(&dir).unwrap();
        let img = dir.join("nau-cassini-1.0.0-amd64.img");
        std::fs::write(&img, b"whole-disk-bytes").unwrap();
        let args = ReleaseArgs { dir: dir.clone() };
        publish_with(&home, &img, &manifest(), "amd64", &args, &[]).unwrap();
        let body = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
        assert_eq!(body.lines().count(), 2, "media-only sums: {body}");
    }

    /// THE contract (#274, council H2): every Source MatchPattern the
    /// emitted sysupdate drop-ins carry must resolve to a file listed in
    /// the SIGNED SHA256SUMS — and every payload the sums list must be
    /// fetchable by some transfer. The drop-ins are generated by the same
    /// emitters the build uses (never copied constants) and parsed the
    /// way a device reads them, so a rename on EITHER side fails this
    /// test instead of a fleet's update night.
    #[test]
    fn sysupdate_matchpatterns_are_all_listed_in_the_signed_sums() {
        let (_g, _h, dir, _a, payload_names) = publish_fixture("release");

        // The signed sums body — read from the published file its .gpg
        // covers, signature verified against the ceremony anchor first.
        let sums = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
        let sig = std::fs::read(dir.join(crate::sign::SYSUPDATE_MANIFEST_SIGNATURE_NAME)).unwrap();
        let pubring = crate::sign::import_pubring_pgp(&test_kp(7)).unwrap();
        crate::sign::verify_sysupdate_manifest_signature(&pubring, sums.as_bytes(), &sig)
            .expect("the sums carrying the MatchPattern contract are the signed ones");
        let names: Vec<&str> = sums
            .lines()
            .map(|l| l.split_once("  ").expect("two-space separator").1)
            .collect();

        // The exact drop-ins the build emits, from the emitters
        // themselves.
        let base_url = "https://download.example/missions/cassini/";
        let drop_ins = [
            super::root_transfer(FIXTURE_IMAGE_NAME, base_url),
            super::hash_transfer(FIXTURE_IMAGE_NAME, base_url),
            super::uki_transfer(FIXTURE_IMAGE_NAME, base_url),
        ];

        // @u expands to a roothash-derived PARTUUID — try both derived
        // guids the build may have pinned, exactly what a device
        // substitutes for its target slot.
        let (data_guid, hash_guid) = super::generation_guids_from_roothash(ROOTHASH).unwrap();
        let mut patterns = Vec::new();
        for drop_in in &drop_ins {
            for pattern in source_matchpatterns(drop_in) {
                let mut expansions = vec![pattern.replace("@v", FIXTURE_VERSION)];
                for guid in [&data_guid, &hash_guid] {
                    expansions.push(pattern.replace("@v", FIXTURE_VERSION).replace("@u", guid));
                }
                assert!(
                    expansions.iter().any(|e| names.contains(&e.as_str())),
                    "drop-in MatchPattern {pattern:?} matches no file in the \
                     signed SHA256SUMS ({names:?}) — the update channel would \
                     refuse this transfer"
                );
                patterns.push(pattern);
            }
        }
        assert_eq!(patterns.len(), 3, "one source pattern per transfer");

        // Reverse direction: every PAYLOAD the release published is
        // fetchable by some transfer — no un-downloadable strays. (The
        // media set is installer territory: served beside the channel,
        // never fetched by a transfer.)
        for name in &payload_names {
            let hit = patterns.iter().any(|p| {
                let mut expansions = vec![p.replace("@v", FIXTURE_VERSION)];
                for guid in [&data_guid, &hash_guid] {
                    expansions.push(p.replace("@v", FIXTURE_VERSION).replace("@u", guid));
                }
                expansions.iter().any(|e| e == name)
            });
            assert!(
                hit,
                "published payload {name:?} is matched by no transfer's \
                 MatchPattern — the channel cannot serve it"
            );
        }
    }

    /// Parse the `[Source]`-section `MatchPattern=` entries of a sysupdate
    /// drop-in the way sysupdate.d(5) defines them: whitespace-separated
    /// glob patterns, matched against the SHA256SUMS file names.
    fn source_matchpatterns(drop_in: &str) -> Vec<String> {
        let mut in_source = false;
        let mut patterns = Vec::new();
        for line in drop_in.lines() {
            match line.trim() {
                "[Source]" => in_source = true,
                "[Target]" => in_source = false,
                _ if in_source => {
                    if let Some(value) = line.trim().strip_prefix("MatchPattern=") {
                        patterns.extend(value.split_whitespace().map(str::to_string));
                    }
                }
                _ => {}
            }
        }
        patterns
    }

    #[test]
    fn publish_refuses_a_missing_payload_before_any_sums_land() {
        let (_home_guard, home) = temp_home("home");
        write_secret_key(&home, &test_kp(7));
        let work = tempfile::tempdir().unwrap();
        let dir = work.path().join("release");
        std::fs::create_dir_all(&dir).unwrap();
        let img = dir.join("nau-cassini-1.0.0-amd64.img");
        std::fs::write(&img, b"whole-disk-bytes").unwrap();
        let args = ReleaseArgs { dir: dir.clone() };
        let payloads = vec![ReleasePayload {
            src: work.path().join("absent-root.img"),
            name: "root_1.0.0_deadbeef.img".into(),
        }];
        let err = publish_with(&home, &img, &manifest(), "amd64", &args, &payloads)
            .expect_err("a missing payload must refuse");
        let flat: String = format!("{err:#}").chars().filter(|c| *c != '\n').collect();
        assert!(
            flat.contains("root_1.0.0_deadbeef.img"),
            "the refusal names the payload: {err:#}"
        );
        assert!(
            !args.dir.join("SHA256SUMS").exists(),
            "a refused release writes no sums"
        );
    }

    #[test]
    fn published_manifest_parses_back_with_the_signature() {
        let (_g, _h, dir, _a, _payload_names) = publish_fixture("release");
        let text =
            std::fs::read_to_string(dir.join("nau-cassini-1.0.0-amd64.manifest.json")).unwrap();
        let parsed: ImageManifest = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed.signatures.len(), 1, "published manifest is signed");
        assert_eq!(parsed.roothash.as_deref(), Some(ROOTHASH));
    }

    #[test]
    fn publish_refuses_without_a_signing_key() {
        let home = tempfile::tempdir().unwrap(); // no .config/nau/secret-key
        let work = tempfile::tempdir().unwrap();
        let img = work.path().join("nau-cassini-1.0.0-amd64.img");
        std::fs::write(&img, b"bytes").unwrap();
        let args = ReleaseArgs {
            dir: work.path().join("release"),
        };
        let err = publish_with(home.path(), &img, &manifest(), "amd64", &args, &[])
            .expect_err("no key must refuse");
        let flat: String = format!("{err:#}").chars().filter(|c| *c != '\n').collect();
        assert!(
            flat.contains("nau key keygen"),
            "refusal names the ceremony: {err:#}"
        );
        assert!(
            !args.dir.join("SHA256SUMS").exists(),
            "a refused release publishes nothing"
        );
    }

    #[test]
    fn prior_signatures_survive_a_release_resign() {
        let mut m = manifest();
        let old = test_kp(3);
        sign_image_manifest(&mut m, &old).unwrap();
        let new = test_kp(4);
        sign_image_manifest(&mut m, &new).unwrap();
        assert_eq!(m.signatures.len(), 2, "DUAL-signature shape");

        let (_guard, home) = temp_home("home");
        let keys_dir = crate::sign::keys_dir(&home);
        crate::sign::install_public_key(&new, &keys_dir).unwrap();
        // ANY-anchor: the successor key alone satisfies the device policy.
        let key_id = super::verify::verify_manifest_signature_at(&m, None, &keys_dir).unwrap();
        assert_eq!(key_id, new.key_id());
    }

    // ── #293 item 5: the digest streams, it does not buffer ──

    #[test]
    fn sha256_file_matches_the_one_shot_digest_across_chunks() {
        // 2.5 MiB of deterministic bytes — crosses the 1 MiB read chunk
        // twice and ends mid-chunk, the shapes a chunked reader gets wrong.
        let len = 5 * SHA256_STREAM_CHUNK / 2;
        let mut pattern = vec![0u8; len];
        for (i, b) in pattern.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.img");
        std::fs::write(&path, &pattern).unwrap();
        assert_eq!(sha256_file(&path).unwrap(), sha256_bytes(&pattern));
    }

    #[test]
    fn sha256_file_hashes_the_empty_file_to_the_known_digest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.img");
        std::fs::write(&path, b"").unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // ── #293 item 4: the self-check EXECUTES the printed advice ──

    /// A runner answering `sfdisk -J` with `body`, `veritysetup` with
    /// `verity_code`, and the mtools calls with the fixture ESP shape
    /// (recording every argv — the verify.rs FakeTools shape, extended
    /// for #284: the self-check now drives the ESP content check too).
    struct FakeTools {
        sfdisk_body: String,
        verity_code: i32,
        /// Names `mdir -b` reports for `EFI/Linux` (covered default: the
        /// fixture UKI; the extraction materializes [`fixture_uki`]).
        mdir_listing: Vec<String>,
        mdir_code: i32,
        mcopy_payload: Option<Vec<u8>>,
        calls: std::sync::Mutex<Vec<Vec<String>>>,
    }

    impl FakeTools {
        fn new(sfdisk_body: String, verity_code: i32) -> FakeTools {
            FakeTools {
                sfdisk_body,
                verity_code,
                mdir_listing: vec![FIXTURE_UKI_NAME.to_string()],
                mdir_code: 0,
                mcopy_payload: Some(fixture_uki()),
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        /// True when some recorded call invoked `tool`.
        fn called(&self, tool: &str) -> bool {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .any(|argv| argv.first().is_some_and(|t| t.ends_with(tool)))
        }

        /// Snapshot of every recorded argv (the verify.rs FakeTools
        /// seam — the ESP assertions read the mtools calls).
        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl crate::command::CommandRunner for FakeTools {
        fn run(&self, argv: &[String]) -> std::io::Result<crate::command::RunnerOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            let tool = argv.first().map(String::as_str).unwrap_or("");
            let out = if tool.ends_with("veritysetup") {
                crate::command::RunnerOutput {
                    code: self.verity_code,
                    stdout: Vec::new(),
                    stderr: "hash mismatch".to_string(),
                }
            } else if tool.ends_with("mdir") {
                let stdout = self
                    .mdir_listing
                    .iter()
                    .map(|n| format!("::/EFI/Linux/{n}\n"))
                    .collect::<String>();
                crate::command::RunnerOutput {
                    code: self.mdir_code,
                    stdout: stdout.into_bytes(),
                    stderr: if self.mdir_code == 0 {
                        String::new()
                    } else {
                        "no such directory".to_string()
                    },
                }
            } else if tool.ends_with("mcopy") {
                match &self.mcopy_payload {
                    Some(bytes) => {
                        std::fs::write(argv.last().expect("mcopy target"), bytes)
                            .expect("fake mcopy write");
                        crate::command::RunnerOutput {
                            code: 0,
                            stdout: Vec::new(),
                            stderr: String::new(),
                        }
                    }
                    None => crate::command::RunnerOutput {
                        code: 1,
                        stdout: Vec::new(),
                        stderr: "File \"::/EFI/Linux/…\" not found".to_string(),
                    },
                }
            } else {
                crate::command::RunnerOutput {
                    code: 0,
                    stdout: self.sfdisk_body.clone().into_bytes(),
                    stderr: String::new(),
                }
            };
            Ok(out)
        }
    }

    /// The published fixture's single-slot GPT table: ESP + root + hash,
    /// with root/hash carrying the roothash-derived PARTUUID identity the
    /// manifest pins (512-byte sectors; the manifest's `esp_partuuid` is
    /// None, so the ESP is located as the single ESP-typed partition —
    /// #284's content check runs against it).
    fn golden_gpt_json() -> String {
        let (data, hash) = super::generation_guids_from_roothash(ROOTHASH).unwrap();
        let (data_up, hash_up) = (data.to_ascii_uppercase(), hash.to_ascii_uppercase());
        format!(
            r#"{{"partitiontable": {{"label": "gpt", "sectorsize": 512, "partitions": [
                {{"start": 2048, "size": 2048, "type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "uuid": "AABBCCDD-0011-2233-4455-667788990011", "name": "ESP"}},
                {{"start": 4096, "size": 4096, "type": "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709", "uuid": "{data_up}", "name": "nau-demo_1.0.0_a"}},
                {{"start": 8192, "size": 256, "type": "2C7357ED-EBD2-46D9-AEC1-23D437EC2BF5", "uuid": "{hash_up}", "name": "nau-demo_1.0.0_hash_a"}}
            ]}}}}"#
        )
    }

    const FIXTURE_IMG_NAME: &str = "nau-cassini-1.0.0-amd64.img";
    const FIXTURE_MANIFEST_NAME: &str = "nau-cassini-1.0.0-amd64.manifest.json";

    /// A published media set shaped like the real one: release-named sparse
    /// image, SIGNED published manifest, sums + detached signature, and the
    /// keychain the release signed under. Returns (work guard, release dir,
    /// keychain dir, signing key).
    fn self_check_fixture(
        tag: &str,
    ) -> (tempfile::TempDir, PathBuf, PathBuf, crate::sign::KeyPair) {
        let work = tempfile::tempdir().unwrap();
        let release = work.path().join(tag);
        std::fs::create_dir_all(&release).unwrap();
        let kp = test_kp(7);
        // The published image: a sparse medium big enough for the fixture
        // extents (the verity recompute is runner-faked; only the size and
        // the GPT answers matter).
        let img = release.join(FIXTURE_IMG_NAME);
        let f = std::fs::File::create(&img).unwrap();
        f.set_len(5 * 1024 * 1024).unwrap();
        drop(f);
        // The published manifest: the release-signed form.
        let mut m = manifest();
        sign_image_manifest(&mut m, &kp).unwrap();
        std::fs::write(
            release.join(FIXTURE_MANIFEST_NAME),
            serde_json::to_string_pretty(&m).unwrap(),
        )
        .unwrap();
        // The published sums + their detached signature (the release shape).
        let sums = "deadbeefdeadbeef  some-file\n";
        std::fs::write(release.join("SHA256SUMS"), sums).unwrap();
        let sig = crate::sign::sign_sysupdate_manifest(&kp, sums.as_bytes()).unwrap();
        std::fs::write(
            release.join(crate::sign::SYSUPDATE_MANIFEST_SIGNATURE_NAME),
            sig,
        )
        .unwrap();
        // The keychain the release signed under — anchors installed.
        let keys_home = work.path().join("keys-home");
        std::fs::create_dir_all(&keys_home).unwrap();
        let keys = crate::sign::keys_dir(&keys_home);
        crate::sign::install_public_key(&kp, &keys).unwrap();
        (work, release, keys, kp)
    }

    #[test]
    fn release_self_check_executes_the_device_verify_in_process() {
        let (_work, release, keys, kp) = self_check_fixture("release");
        let runner = FakeTools::new(golden_gpt_json(), 0);
        self_check(
            &runner,
            &release,
            FIXTURE_IMG_NAME,
            FIXTURE_MANIFEST_NAME,
            &keys,
            Some(Path::new("veritysetup")),
            Some(Path::new("mcopy")),
            &kp,
        )
        .expect("the published set must pass its own self-check");
        // The advice is EXECUTED, not printed: the runner really invoked
        // sfdisk (GPT read), mcopy (the #284 ESP UKI extraction), and
        // veritysetup (dm-verity recompute).
        assert!(runner.called("sfdisk"), "the GPT was read in-process");
        assert!(
            runner.called("mcopy"),
            "the ESP UKI was pulled off the published image in-process"
        );
        assert!(
            runner.called("veritysetup"),
            "the dm-verity recompute ran in-process"
        );
    }

    #[test]
    fn release_self_check_covers_the_esp_uki_digest() {
        // #284 at the release layer: the self-check proves the published
        // image's ESP carries the UKI the SIGNED manifest pins — pulling
        // the named file out of the published image and hashing it.
        let (_work, release, keys, kp) = self_check_fixture("release");
        let runner = FakeTools::new(golden_gpt_json(), 0);
        self_check(
            &runner,
            &release,
            FIXTURE_IMG_NAME,
            FIXTURE_MANIFEST_NAME,
            &keys,
            Some(Path::new("veritysetup")),
            Some(Path::new("mcopy")),
            &kp,
        )
        .expect("a covered ESP passes the self-check");
        let mcopy = runner
            .calls()
            .into_iter()
            .find(|c| c.first().is_some_and(|t| t.ends_with("mcopy")))
            .expect("mcopy ran");
        assert_eq!(
            mcopy[3],
            format!("::EFI/Linux/{FIXTURE_UKI_NAME}"),
            "the manifest's UKI name, verbatim"
        );
    }

    #[test]
    fn release_self_check_refuses_a_tampered_esp_uki() {
        // The published image's ESP carries UKI bytes that do not match
        // the signed digest: the release must refuse to publish that set.
        let (_work, release, keys, kp) = self_check_fixture("release");
        let mut runner = FakeTools::new(golden_gpt_json(), 0);
        let mut tampered = fixture_uki();
        tampered[7] ^= 0x01;
        runner.mcopy_payload = Some(tampered);
        let err = self_check(
            &runner,
            &release,
            FIXTURE_IMG_NAME,
            FIXTURE_MANIFEST_NAME,
            &keys,
            Some(Path::new("veritysetup")),
            Some(Path::new("mcopy")),
            &kp,
        )
        .expect_err("a tampered ESP UKI must refuse the release");
        assert!(
            format!("{err:#}").contains("ESP content mismatch"),
            "the refusal names the ESP region: {err:#}"
        );
    }

    #[test]
    fn release_self_check_refuses_a_verity_mismatch() {
        let (_work, release, keys, kp) = self_check_fixture("release");
        let runner = FakeTools::new(golden_gpt_json(), 1);
        let err = self_check(
            &runner,
            &release,
            FIXTURE_IMG_NAME,
            FIXTURE_MANIFEST_NAME,
            &keys,
            Some(Path::new("veritysetup")),
            Some(Path::new("mcopy")),
            &kp,
        )
        .expect_err("a verity-mismatching medium must refuse the release");
        assert!(
            format!("{err:#}").contains("veritysetup"),
            "the refusal names the failing region/tool: {err:#}"
        );
    }

    #[test]
    fn release_self_check_refuses_tampered_sums_by_name() {
        let (_work, release, keys, kp) = self_check_fixture("release");
        // Rewrite the sums AFTER their signature landed — the device's
        // update-night check must refuse through the self-check.
        std::fs::write(release.join("SHA256SUMS"), "tampered  file\n").unwrap();
        let runner = FakeTools::new(golden_gpt_json(), 0);
        let err = self_check(
            &runner,
            &release,
            FIXTURE_IMG_NAME,
            FIXTURE_MANIFEST_NAME,
            &keys,
            Some(Path::new("veritysetup")),
            Some(Path::new("mcopy")),
            &kp,
        )
        .expect_err("tampered sums must refuse");
        assert!(
            format!("{err:#}").contains("SHA256SUMS"),
            "the refusal names the manifest: {err:#}"
        );
    }

    #[test]
    fn release_self_check_refuses_a_foreign_keychain() {
        let (_work, release, _keys, _kp) = self_check_fixture("release");
        // A keychain anchoring a DIFFERENT key than the manifest signer —
        // the device policy (revoked-first, then ANY-anchor) refuses.
        let foreign = test_kp(9);
        let foreign_home = _work.path().join("foreign-home");
        std::fs::create_dir_all(&foreign_home).unwrap();
        let foreign_keys = crate::sign::keys_dir(&foreign_home);
        crate::sign::install_public_key(&foreign, &foreign_keys).unwrap();
        let runner = FakeTools::new(golden_gpt_json(), 0);
        assert!(
            self_check(
                &runner,
                &release,
                FIXTURE_IMG_NAME,
                FIXTURE_MANIFEST_NAME,
                &foreign_keys,
                Some(Path::new("veritysetup")),
                Some(Path::new("mcopy")),
                &test_kp(7),
            )
            .is_err(),
            "a release must refuse to self-check under a foreign keychain"
        );
    }
}
