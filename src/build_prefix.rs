//! Merged build prefix — payload visibility for source builds (ADR-0018,
//! issue #17).
//!
//! A source package's `requires` + `build_deps` entries name pool packages
//! whose built `.snap` payloads carry the headers, link libraries, and
//! pkg-config metadata a build needs (`./configure`, `pkg-config`, the
//! compiler). The build sandbox is hermetic (ADR-0004): none of that is
//! visible today, which is why `htop` cannot find pool ncurses.
//!
//! The fix (ADR-0018 Decision 2) materializes the payloads of every entry
//! into ONE `/usr`-like prefix tree and binds it read-only into the build
//! sandbox ([`crate::snap::SANDBOX_BUILD_PREFIX`]). Per-package directories
//! with hand-rolled `-I`/`-L` flags are rejected by the ADR — a single
//! consumable prefix is the whole mechanism.
//!
//! Merge semantics: the same relative path with identical content merges
//! fine (deduplicated); the same path with differing content is a hard
//! build error naming both source packages. Payloads never overlap → no
//! conflicts → the merge is a no-op beyond copying.
//!
//! The payloads come from the existing build machinery: a dependency's
//! `.snap` (built by `shuttle build` into the output dir or fetched from
//! the binary cache) is data-only unpacked with `unsquashfs` — never
//! executed, never mounted.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

/// One dependency payload to merge: the source package name (for conflict
/// messages) and its built `.snap` file.
pub struct Payload {
    pub pkg: String,
    pub snap: PathBuf,
}

/// The materialized merged prefix: owns the tempdir backing the tree and
/// exposes the `/usr`-like prefix path the build sandbox binds (the tempdir
/// also holds the per-payload unpack dirs, which live BESIDE the prefix, not
/// inside it).
#[derive(Debug)]
pub struct MergedPrefix {
    /// Held for its `Drop` (removes the tree when the build finishes) —
    /// never read directly.
    #[allow(dead_code)]
    work: tempfile::TempDir,
    path: PathBuf,
}

impl MergedPrefix {
    /// The `/usr`-like prefix tree to bind into the build sandbox.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Every payload's file basenames (recursive — sonames live in
    /// `usr/lib`), keyed by source package name — the leak scan's
    /// resolution data (ADR-0018 Decision 3): a DT_NEEDED soname must
    /// resolve into a runtime payload, not a build-only one.
    ///
    /// Returns the per-package basenames at every depth under the unpacked
    /// payload. The merged tree is read here; the per-package unpack dirs
    /// live beside it.
    pub fn payload_files(&self) -> BTreeMap<String, BTreeSet<String>> {
        let mut out = BTreeMap::new();
        let Ok(payloads) = std::fs::read_dir(self.work.path().join("payloads")) else {
            return out;
        };
        for entry in payloads.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let pkg = entry.file_name().to_string_lossy().into_owned();
            let mut names = BTreeSet::new();
            collect_basenames(&entry.path(), &mut names);
            out.insert(pkg, names);
        }
        out
    }
}

/// Recursively collect the basenames of every entry (files, dirs,
/// symlinks) below `dir`.
fn collect_basenames(dir: &Path, out: &mut BTreeSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        out.insert(name.clone());
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            collect_basenames(&entry.path(), out);
        }
    }
}

/// The snapd packaging subtree every payload carries (`snap.yaml`, hooks,
/// gui icons) — per-package by definition and never consumed by a build
/// (`./configure`, `pkg-config`, compilers read the `usr/` prefix). Always
/// excluded from the merge: including it would hard-error every pair of
/// packages on their differing `meta/snap.yaml`.
const META_SUBTREE: &str = "meta";

/// The GNU info directory index. Every autotools `make install` regenerates
/// it through install-info, so any two packages shipping info files carry
/// byte-different copies — it is a per-host generated index, not package
/// content (Debian ships no `dir` in packages; dpkg triggers build it).
/// No build reads it, so it never enters the prefix: merging glibc and gcc
/// (the toolchain metas) would otherwise hard-error on it.
const INFO_DIR_FILE: &str = "usr/share/info/dir";

/// Materialize the merged `/usr`-like build prefix from `payloads`.
///
/// Returns the [`MergedPrefix`] — the caller must keep it alive for as long
/// as the build runs and bind [`MergedPrefix::path`] into the sandbox;
/// dropping it removes the tree. An empty `payloads` list yields an empty
/// prefix (callers usually skip materializing instead).
///
/// Wrapper-aware (issue #90): a payload built by the pod path carries the
/// build-time launcher wrappers (issues #9/#10/#13) authored for the POD
/// runtime layout. Those wrappers cannot resolve inside the prefix — see
/// [`rewrite_prefix_wrappers`], which re-points them at the prefix layout
/// after the merge and fails closed on one whose interpreter resolves to
/// neither the payloads nor a declared `requires`.
pub fn materialize_merged_prefix(payloads: &[Payload]) -> miette::Result<MergedPrefix> {
    let work = tempfile::tempdir().map_err(|e| miette::miette!("tempdir: {e}"))?;
    let path = work.path().join("prefix");
    std::fs::create_dir_all(&path).map_err(|e| miette::miette!("create prefix dir: {e}"))?;

    // rel path → the package that contributed it, so a conflict can name
    // both source packages.
    let mut owners: HashMap<String, String> = HashMap::new();
    for payload in payloads {
        let unpack_dir = work.path().join("payloads").join(&payload.pkg);
        // unsquashfs requires the destination's parent to exist.
        std::fs::create_dir_all(&unpack_dir)
            .map_err(|e| miette::miette!("creating unpack dir for '{}': {e}", payload.pkg))?;
        unpack_snap(&payload.snap, &unpack_dir)?;
        merge_tree(&unpack_dir, &payload.pkg, &path, &mut owners)?;
    }
    rewrite_prefix_wrappers(&path, payloads, &owners)?;
    Ok(MergedPrefix { work, path })
}

/// Resolve a floor tool (issue #101) through the tools module — per-tool
/// precedence (provisioned-first, curl PATH-first) with PATH fallback.
fn floor_tool(name: crate::tools::ToolName) -> miette::Result<PathBuf> {
    let resolved =
        crate::tools::resolve(name).map_err(|e| miette::miette!("resolve {name}: {e}"))?;
    Ok(match resolved {
        crate::tools::ResolvedTool::Provisioned { path, .. }
        | crate::tools::ResolvedTool::Path { path, .. } => path,
    })
}

/// Data-only unpack of a `.snap` (squashfs) into `dest` with `unsquashfs`.
/// The payload is never executed — files are just extracted.
fn unpack_snap(snap: &Path, dest: &Path) -> miette::Result<()> {
    let unsquashfs = floor_tool(crate::tools::ToolName::Unsquashfs)?;
    let output = std::process::Command::new(&unsquashfs)
        .arg("-no-progress")
        .arg("-d")
        .arg(dest)
        .arg(snap)
        .output()
        .map_err(|e| {
            miette::miette!(
                "unsquashfs not found (needed to unpack dependency payloads \
                 for the merged build prefix): {e}"
            )
        })?;
    if !output.status.success() {
        return Err(miette::miette!(
            "failed to unpack {} for the merged build prefix: {}",
            snap.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// The pod-runtime extension-tree segment our build-time wrappers embed
/// (`$PODROOT/active/extensions/<pkg>/usr/<payload-rel-path>`). Inside the
/// merged prefix the payload root IS the prefix root, so the whole segment
/// is dropped: the reference becomes `$PODROOT/<payload-rel-path>` — the
/// `usr/usr` doubling untangled (issue #90).
const EXTENSION_SEGMENT: &str = "active/extensions/";

/// The `#!/bin/sh` launcher wrappers [`crate::snap::emit_build_wrappers`]
/// authors derive their pod root from their own store-blob path with two
/// dirname shapes; both fingerprints identify a wrapper of ours.
const TREE_PODROOT_LINE: &str = "PODROOT=\"$(dirname \"$(dirname \"$(dirname \"$SCRIPT\")\")\")\"";
const LIB_PODROOT_LINE: &str = "PODROOT=\"$(dirname \"$(dirname \"$BLODIR\")\")\"";

/// Rewrite pod-runtime launcher wrappers staged into the merged prefix so
/// they resolve inside the prefix (issue #90).
///
/// The pod build path wraps toolchain payloads for the FARM: a wrapper execs
/// `$PODROOT/active/extensions/<pkg>/usr/<rel>` (the extension tree nests the
/// payload under a further `usr/`, hence the observed `usr/usr/bin/python3.real`
/// doubling) or a pod content-store blob (`<podroot>/store/<aa>/<hash>`). The
/// merged prefix has neither layout — the payload root merges at the prefix
/// root and the `.real` sibling the wrapper preserved sits right beside it.
/// Three deterministic rewrites, applied to files matching our wrapper
/// fingerprints only (never to an upstream script):
///
/// 1. every `active/extensions/<pkg>/usr` segment is dropped, re-pointing
///    the reference at the prefix root;
/// 2. an `exec` argument that is an absolute pod-store blob path is replaced
///    by an exec of the wrapper's `.real` sibling, resolved from the
///    wrapper's own directory;
/// 3. the python tree wrapper's `PYTHONPATH` scrub (farm isolation, snap.rs
///    `emit_tree_elf_wrapper`) is re-pointed to preserve the caller's
///    value: build tools hand python inputs through `PYTHONPATH` — meson
///    passes build-time generators the source root exactly that way
///    (xkeyboard-config 2.48 `rules.generator`, observed as a silent
///    status-1) — and inside the hermetic sandbox the host-PYTHONPATH
///    threat the scrub exists for does not apply;
/// 4. (verification, fail closed) every rewritten reference must resolve:
///    the exec target and `LD_LIBRARY_PATH` dirs must exist in the prefix,
///    and a bare-name interpreter must be provided by one of the merged
///    payloads — i.e. the payload itself or a declared `requires`. A wrapper
///    whose interpreter resolves to neither is a hard error naming the
///    wrapper, not a silently broken artifact.
fn rewrite_prefix_wrappers(
    prefix: &Path,
    payloads: &[Payload],
    owners: &HashMap<String, String>,
) -> miette::Result<()> {
    rewrite_dir(prefix, prefix, "", payloads, owners)
}

fn rewrite_dir(
    prefix: &Path,
    dir: &Path,
    rel: &str,
    payloads: &[Payload],
    owners: &HashMap<String, String>,
) -> miette::Result<()> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| miette::miette!("reading prefix dir '{rel}': {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| miette::miette!("reading prefix dir '{rel}': {e}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let child_rel = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        let ft = entry
            .file_type()
            .map_err(|e| miette::miette!("reading prefix entry '{child_rel}': {e}"))?;
        if ft.is_dir() {
            rewrite_dir(prefix, &entry.path(), &child_rel, payloads, owners)?;
        } else if ft.is_file() {
            rewrite_file(prefix, &child_rel, payloads, owners)?;
        }
    }
    Ok(())
}

/// Which of our build-time wrapper shapes a staged file matches.
#[derive(Debug, PartialEq)]
enum WrapperShape {
    /// Interpreter-script or native-ELF tree wrapper (issues #13/#10 B):
    /// execs `$PODROOT/active/extensions/<pkg>/usr/<rel>`.
    Tree,
    /// Native-ELF runtime-lib wrapper (issue #10 B): execs a pod-store blob.
    Lib,
    /// Flat interpreter wrapper (issue #9): execs a bare interpreter name
    /// plus a pod-store blob path.
    Flat,
}

fn rewrite_file(
    prefix: &Path,
    rel: &str,
    payloads: &[Payload],
    owners: &HashMap<String, String>,
) -> miette::Result<()> {
    let path = prefix.join(rel);
    let Some(text) = read_if_our_wrapper(&path) else {
        return Ok(());
    };
    let Some(shape) = classify_wrapper(&text) else {
        return Ok(());
    };
    // The PODROOT preamble derives the pod root from the wrapper's own path
    // three dirnames up — exact for the farm's store/<aa>/<hash> blob and,
    // in the prefix, exact for the usr/bin (or usr/sbin) command depth every
    // app uses. Any other placement derives a wrong root: fail closed
    // instead of rewriting into a silent lie.
    if rel.split('/').count() != 3 || !rel.starts_with("usr/") {
        return Err(unresolvable(
            rel,
            owners
                .get(rel)
                .map(String::as_str)
                .unwrap_or("an earlier payload"),
            "wrapper placement is not usr/<dir>/<name>; the prefix-root \
             derivation does not hold there",
        ));
    }
    let pkg = owners.get(rel).cloned().unwrap_or_default();

    // 1. Drop the extension-tree segment wherever it appears (exec targets,
    //    LD_LIBRARY_PATH entries, PKGROOT site-packages derivation).
    let rewritten = strip_extension_segments(&text);

    // 2. Replace absolute pod-store blob exec arguments with an exec of the
    //    wrapper's preserved `.real` sibling.
    let file_name = rel.rsplit('/').next().unwrap_or(rel);
    let real = crate::snap::real_sibling_name(file_name);
    let rewritten = rewrite_blob_execs(&rewritten, &real);

    // 3. Preserve the caller's PYTHONPATH behind the SHUTTLE_PYTHONPATH
    //    channel (farm scrub → prefix append; see the fn doc).
    let rewritten = preserve_caller_pythonpath(&rewritten);

    if rewritten != text {
        std::fs::write(&path, &rewritten)
            .map_err(|e| miette::miette!("rewriting wrapper '{rel}': {e}"))?;
    }

    // 4. Fail-closed resolution: every reference the wrapper makes must
    //    resolve into the merged prefix (the payload set) here.
    verify_resolution(prefix, rel, &pkg, shape, &rewritten, &real, payloads)
}

/// Read `path` as text if it starts with the `#!/bin/sh` magic our wrappers
/// carry; `None` leaves ELFs, data, and upstream scripts untouched.
fn read_if_our_wrapper(path: &Path) -> Option<String> {
    let mut head = [0u8; 10];
    let mut f = std::fs::File::open(path).ok()?;
    use std::io::Read;
    let n = f.read(&mut head).unwrap_or(0);
    if &head[..n] != b"#!/bin/sh\n" {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Match one of our wrapper fingerprints, else `None` (an upstream
/// `#!/bin/sh` script — meson's launcher, say — is never ours to rewrite).
fn classify_wrapper(text: &str) -> Option<WrapperShape> {
    if text.contains(TREE_PODROOT_LINE) {
        return Some(WrapperShape::Tree);
    }
    if text.contains(LIB_PODROOT_LINE) {
        return Some(WrapperShape::Lib);
    }
    if is_flat_script_wrapper(text) {
        return Some(WrapperShape::Flat);
    }
    None
}

/// Drop every `/active/extensions/<pkg>/usr` occurrence, re-joining the cut
/// edges so `$PODROOT/active/extensions/<pkg>/usr/<rest>` becomes
/// `$PODROOT/<rest>`. Malformed occurrences (no `/usr` right after the
/// package segment) are left as-is — they are not our wrappers' shape.
fn strip_extension_segments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(idx) = rest.find(EXTENSION_SEGMENT) {
        let after = &rest[idx + EXTENSION_SEGMENT.len()..];
        match extension_pkg_usr_len(after) {
            Some(skip) => {
                // Cut the segment together with its leading '/' (the one
                // after `$PODROOT`); the `<pkg>/usr` cut leaves `<rest>`
                // starting with its own '/', so the join carries exactly one
                // separator: `$PODROOT` + `/usr/bin/...`.
                let seg_start = if idx > 0 && rest.as_bytes()[idx - 1] == b'/' {
                    idx - 1
                } else {
                    idx
                };
                out.push_str(&rest[..seg_start]);
                rest = &after[skip..];
            }
            // Not our shape: copy the segment through and keep scanning.
            None => {
                out.push_str(&rest[..idx + EXTENSION_SEGMENT.len()]);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Re-point the python tree wrapper's `PYTHONPATH` scrub for the prefix.
/// The farm wrapper replaces `PYTHONPATH` with the `SHUTTLE_PYTHONPATH`
/// channel (a host PYTHONPATH would shadow the pod's site-packages). In
/// the merged build prefix the caller IS the build system: meson hands
/// build-time generators the source root through `PYTHONPATH`, and the
/// scrub turned that into a silent ModuleNotFoundError. Append the
/// caller's value behind the channel instead of replacing it; an empty
/// caller value expands to today's behavior exactly.
fn preserve_caller_pythonpath(text: &str) -> String {
    text.replace(
        "PYTHONPATH=\"${SHUTTLE_PYTHONPATH:-}\"\n",
        "PYTHONPATH=\"${SHUTTLE_PYTHONPATH:-}${PYTHONPATH:+:$PYTHONPATH}\"\n",
    )
}

/// Given the text right after `active/extensions/`, the number of bytes of
/// the well-formed `<pkg>/usr` that follows, else `None`.
fn extension_pkg_usr_len(after: &str) -> Option<usize> {
    let slash = after.find('/')?;
    if !after[slash..].starts_with("/usr") {
        return None;
    }
    Some(slash + "/usr".len())
}

/// True for the two-line flat interpreter wrapper (`emit_script_wrapper`,
/// issue #9): `#!/bin/sh` then `exec "<interpreter>" "<blob>" "$@"`.
fn is_flat_script_wrapper(text: &str) -> bool {
    let mut lines = text.lines();
    if lines.next() != Some("#!/bin/sh") {
        return false;
    }
    let Some(second) = lines.next() else {
        return false;
    };
    let args = second.strip_prefix("exec ").unwrap_or(second);
    matches!(quoted_tokens(args)[..], [_, blob, "$@"]
        if blob.starts_with('/') && blob.contains("/store/"))
}

/// Split a leading sequence of quoted tokens (`"a" "b" ...`) into their
/// contents; stops at the first gap that is not a single space.
fn quoted_tokens(args: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut rest = args;
    while let Some(after_open) = rest.strip_prefix('"') {
        let Some(close) = after_open.find('"') else {
            break;
        };
        tokens.push(&after_open[..close]);
        match after_open[close + 1..].strip_prefix(' ') {
            Some(tail) => rest = tail,
            None => break,
        }
    }
    tokens
}

/// Replace quoted exec arguments that are absolute pod-store blob paths with
/// an exec of `real_sibling`, resolved from the wrapper's own directory
/// (readlink resolves the farm symlink chain; dirname keeps the wrapper
/// depth-agnostic inside the prefix).
fn rewrite_blob_execs(text: &str, real_sibling: &str) -> String {
    if !text.contains("/store/") {
        return text.to_string();
    }
    let selfdir = "$(dirname \"$(readlink -f \"$0\")\")";
    let mut out = String::with_capacity(text.len() + 64);
    for line in text.split_inclusive('\n') {
        match line.strip_suffix('\n') {
            Some(body) => {
                out.push_str(&rewrite_exec_body(body, selfdir, real_sibling));
                out.push('\n');
            }
            None => out.push_str(&rewrite_exec_body(line, selfdir, real_sibling)),
        }
    }
    out
}

/// Rewrite one `exec` line (no terminator): quoted arguments that are
/// store-blob paths become `<selfdir>/<real_sibling>`; everything else is
/// copied verbatim.
fn rewrite_exec_body(body: &str, selfdir: &str, real_sibling: &str) -> String {
    let Some(args) = body.strip_prefix("exec ") else {
        return body.to_string();
    };
    let mut out = String::from("exec ");
    let mut rest = args;
    while let Some(after_open) = rest.strip_prefix('"') {
        let Some(close) = after_open.find('"') else {
            break;
        };
        let token = &after_open[..close];
        out.push('"');
        if token.starts_with('/') && token.contains("/store/") {
            out.push_str(selfdir);
            out.push('/');
            out.push_str(real_sibling);
        } else {
            out.push_str(token);
        }
        out.push('"');
        match after_open[close + 1..].strip_prefix(' ') {
            Some(tail) => {
                out.push(' ');
                rest = tail;
            }
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out
}
/// Fail-closed resolution check over the rewritten wrapper text (issue #90):
/// every reference the wrapper makes must resolve into the merged prefix —
/// `$PODROOT/...` exec targets and `LD_LIBRARY_PATH` dirs as prefix paths,
/// the preserved `.real` sibling beside the wrapper, and a bare-name
/// interpreter as a file one of the merged payloads (the payload itself or a
/// declared `requires`) provides. A wrapper that cannot resolve here would
/// be a silently broken artifact; it is a hard build error instead.
fn verify_resolution(
    prefix: &Path,
    rel: &str,
    pkg: &str,
    shape: WrapperShape,
    text: &str,
    real_sibling: &str,
    payloads: &[Payload],
) -> miette::Result<()> {
    let mut failures: BTreeSet<String> = BTreeSet::new();

    // The `.real` sibling the wrapper family preserves must have survived
    // the merge (Lib/Flat exec it directly; Tree execs it by extension path).
    if matches!(shape, WrapperShape::Lib | WrapperShape::Flat) {
        let sibling = prefix
            .join(rel)
            .parent()
            .map(|d| d.join(real_sibling))
            .unwrap_or_else(|| prefix.join(real_sibling));
        if !sibling.exists() {
            failures.insert(format!(
                "preserved sibling '{real_sibling}' is missing from the prefix"
            ));
        }
    }

    for line in text.lines() {
        check_exec_line(prefix, line, payloads, &mut failures);
        check_podroot_refs(prefix, line, &mut failures);
    }

    let Some(first) = failures.iter().next() else {
        return Ok(());
    };
    Err(unresolvable(rel, pkg, first))
}

/// One rewritten line's checks: on an `exec` line, the bare-name interpreter
/// must be provided by the payload set (a `usr/bin/<name>` in the prefix).
fn check_exec_line(
    prefix: &Path,
    line: &str,
    payloads: &[Payload],
    failures: &mut BTreeSet<String>,
) {
    let Some(args) = line.strip_prefix("exec ") else {
        return;
    };
    let Some(first) = quoted_tokens(args).first().copied() else {
        return;
    };
    if first.starts_with('$') || first.starts_with('/') || first == "$@" {
        return; // $PODROOT target, selfdir sibling, or the args passthrough
    }
    let interp_rel = format!("usr/bin/{first}");
    if !prefix.join(&interp_rel).exists() {
        failures.insert(format!(
            "interpreter '{first}' resolves to neither the merged payloads ({}) \
             nor a declared requires — no '{interp_rel}' in the prefix",
            payload_names(payloads),
        ));
    }
}

/// One rewritten line's checks: every `$PODROOT/<rest>` reference (exec
/// targets, colon-separated LD_LIBRARY_PATH dirs) must exist in the prefix.
/// Shell globs are skipped — they are expansion patterns, not paths.
fn check_podroot_refs(prefix: &Path, line: &str, failures: &mut BTreeSet<String>) {
    for part in quoted_tokens_after_prefix(line) {
        for piece in part.split(':') {
            let Some(rest) = piece.strip_prefix("$PODROOT/") else {
                continue;
            };
            // Shell-expansion fragments (the `${LD_LIBRARY_PATH:+…}`
            // prepend idiom) and globs are expansion patterns, not
            // literal paths.
            if rest.is_empty() || rest.contains('*') || rest.contains("${") {
                continue;
            }
            if !prefix.join(rest).exists() {
                failures.insert(format!(
                    "exec/library target '{rest}' is missing from the prefix"
                ));
            }
        }
    }
}

/// Payload names for the fail-closed message.
fn payload_names(payloads: &[Payload]) -> String {
    let mut names: Vec<&str> = payloads.iter().map(|p| p.pkg.as_str()).collect();
    names.sort_unstable();
    names.join(", ")
}

/// Collect every quoted token in `line` that references `$PODROOT/...`
/// (exec targets, LD_LIBRARY_PATH entries), including colon-separated
/// multi-dir values.
fn quoted_tokens_after_prefix(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut rest = line;
    while let Some((_, tail)) = rest.split_once('"') {
        let Some(close) = tail.find('"') else {
            break;
        };
        let token = &tail[..close];
        if token.contains("$PODROOT/") {
            tokens.push(token.to_string());
        }
        rest = &tail[close + 1..];
    }
    tokens
}

/// The issue #90 fail-closed error: a staged wrapper cannot be made to
/// resolve inside the prefix, so shipping it would be silent breakage.
fn unresolvable(rel: &str, pkg: &str, reason: &str) -> miette::Error {
    miette::miette!(
        "build prefix: refusing launcher wrapper '{rel}' (from payload '{pkg}'): \
         {reason} — the wrapper must resolve to the payload set or a declared \
         requires; shipping it broken is not an option (issue #90)"
    )
}

fn merge_tree(
    src: &Path,
    pkg: &str,
    prefix: &Path,
    owners: &mut HashMap<String, String>,
) -> miette::Result<()> {
    merge_dir(src, pkg, prefix, "", owners)
}

fn merge_dir(
    src: &Path,
    pkg: &str,
    prefix: &Path,
    rel: &str,
    owners: &mut HashMap<String, String>,
) -> miette::Result<()> {
    let entries =
        std::fs::read_dir(src).map_err(|e| miette::miette!("reading payload of '{pkg}': {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| miette::miette!("reading payload of '{pkg}': {e}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let child_rel = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{}", entry.file_name().to_string_lossy())
        };
        if excluded(rel, &name, &child_rel) {
            continue;
        }
        // No symlink following: the payload tree is what the package staged.
        let ft = entry
            .file_type()
            .map_err(|e| miette::miette!("reading payload of '{pkg}': {e}"))?;
        merge_entry(&entry.path(), ft, pkg, prefix, &child_rel, owners)?;
        owners.entry(child_rel).or_insert_with(|| pkg.to_string());
    }
    Ok(())
}

/// True when one payload entry never enters the prefix: per-package
/// packaging metadata (`meta/` at the payload root) and the shared
/// generated info index — both per-package by nature, consumed by no
/// build, and guaranteed conflict generators otherwise.
fn excluded(rel: &str, name: &str, child_rel: &str) -> bool {
    (rel.is_empty() && name == META_SUBTREE) || child_rel == INFO_DIR_FILE
}

/// Merge one payload entry into the prefix at `child_rel`.
fn merge_entry(
    src: &Path,
    ft: std::fs::FileType,
    pkg: &str,
    prefix: &Path,
    child_rel: &str,
    owners: &mut HashMap<String, String>,
) -> miette::Result<()> {
    let dst = prefix.join(child_rel);
    if ft.is_dir() {
        merge_dir_entry(src, pkg, prefix, child_rel, &dst, owners)
    } else if ft.is_symlink() {
        merge_symlink(src, pkg, child_rel, &dst, owners)
    } else {
        merge_file(src, pkg, child_rel, &dst, owners)
    }
}

/// Directory entry: recurse, merging subtree into the existing dir.
fn merge_dir_entry(
    src: &Path,
    pkg: &str,
    prefix: &Path,
    child_rel: &str,
    dst: &Path,
    owners: &mut HashMap<String, String>,
) -> miette::Result<()> {
    if !dst.is_dir() && dst.symlink_metadata().is_ok() {
        return Err(conflict(child_rel, owners, pkg));
    }
    std::fs::create_dir_all(dst)
        .map_err(|e| miette::miette!("merging payload dir '{child_rel}': {e}"))?;
    merge_dir(src, pkg, prefix, child_rel, owners)
}

/// Symlink entry: identical target dedupes, differing target conflicts.
fn merge_symlink(
    src: &Path,
    pkg: &str,
    child_rel: &str,
    dst: &Path,
    owners: &mut HashMap<String, String>,
) -> miette::Result<()> {
    let target = std::fs::read_link(src)
        .map_err(|e| miette::miette!("reading payload link '{child_rel}': {e}"))?;
    if dst.symlink_metadata().is_ok() {
        let same = std::fs::read_link(dst)
            .map(|t| t == target)
            .unwrap_or(false);
        if !same {
            return Err(conflict(child_rel, owners, pkg));
        }
        return Ok(());
    }
    std::os::unix::fs::symlink(&target, dst)
        .map_err(|e| miette::miette!("merging payload link '{child_rel}': {e}"))
}

/// Regular-file entry: identical content dedupes, differing content is a
/// hard error naming both packages.
fn merge_file(
    src: &Path,
    pkg: &str,
    child_rel: &str,
    dst: &Path,
    owners: &mut HashMap<String, String>,
) -> miette::Result<()> {
    if dst.symlink_metadata().is_ok() {
        // A regular file never merges with a symlink at the same path.
        if dst.is_file() && is_same_file_content(src, dst) {
            return Ok(());
        }
        return Err(conflict(child_rel, owners, pkg));
    }
    std::fs::copy(src, dst)
        .map_err(|e| miette::miette!("merging payload file '{child_rel}': {e}"))?;
    Ok(())
}

/// The hard build error for a same-path/different-content collision,
/// naming both source packages (ADR-0018 merge semantics).
fn conflict(rel: &str, owners: &HashMap<String, String>, incoming: &str) -> miette::Error {
    let existing = owners
        .get(rel)
        .cloned()
        .unwrap_or_else(|| "an earlier payload".to_string());
    miette::miette!(
        "build prefix conflict: '{rel}' differs between '{existing}' and '{incoming}' — \
         the merged build prefix requires identical content at shared paths"
    )
}

/// Byte-identical regular files (size short-circuit, then stream compare).
fn is_same_file_content(a: &Path, b: &Path) -> bool {
    let (ma, mb) = match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return false,
    };
    if !ma.is_file() || !mb.is_file() || ma.len() != mb.len() {
        return false;
    }
    use std::io::Read;
    let (mut fa, mut fb) = match (std::fs::File::open(a), std::fs::File::open(b)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return false,
    };
    let (mut ba, mut bb) = ([0u8; 65536], [0u8; 65536]);
    loop {
        let (na, nb) = match (fa.read(&mut ba), fb.read(&mut bb)) {
            (Ok(na), Ok(nb)) => (na, nb),
            _ => return false,
        };
        if na != nb {
            return false;
        }
        if na == 0 {
            return true;
        }
        if ba[..na] != bb[..nb] {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Skip gate for tests that shell out to squashfs tools (repo convention:
    /// integration-ish tests skip when the tools are unavailable).
    fn squashfs_tools_available() -> bool {
        crate::tools::resolve(crate::tools::ToolName::Mksquashfs).is_ok()
            && crate::tools::resolve(crate::tools::ToolName::Unsquashfs).is_ok()
    }

    /// Build a `.snap` whose payload contains the given rel-path → content
    /// files (plus a symlink: rel → target).
    fn make_snap(dir: &Path, files: &[(&str, &str)], links: &[(&str, &str)]) -> PathBuf {
        let payload = dir.join("payload");
        for (rel, content) in files {
            let p = payload.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, content).unwrap();
        }
        for (rel, target) in links {
            let p = payload.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(target, &p).unwrap();
        }
        let snap = dir.join("test.snap");
        let _ = std::fs::remove_file(&snap);
        let mksquashfs =
            floor_tool(crate::tools::ToolName::Mksquashfs).expect("mksquashfs should be available");
        let status = std::process::Command::new(&mksquashfs)
            .arg(&payload)
            .arg(&snap)
            .arg("-no-progress")
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "mksquashfs failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        snap
    }

    #[test]
    fn merge_disjoint_payloads_and_dedupes_identical() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let snap_a = make_snap(
            &tmp.path().join("a"),
            &[
                ("usr/include/ah.h", "a-header\n"),
                ("usr/share/common", "shared\n"),
            ],
            &[("usr/lib/liba.so", "liba.so.1")],
        );
        let snap_b = make_snap(
            &tmp.path().join("b"),
            &[
                ("usr/include/bh.h", "b-header\n"),
                ("usr/share/common", "shared\n"),
            ],
            &[],
        );

        let merged = materialize_merged_prefix(&[
            Payload {
                pkg: "pkg-a".into(),
                snap: snap_a,
            },
            Payload {
                pkg: "pkg-b".into(),
                snap: snap_b,
            },
        ])
        .unwrap();
        let prefix = merged.path().to_path_buf();
        assert_eq!(
            std::fs::read_to_string(prefix.join("usr/include/ah.h")).unwrap(),
            "a-header\n"
        );
        assert_eq!(
            std::fs::read_to_string(prefix.join("usr/include/bh.h")).unwrap(),
            "b-header\n"
        );
        // Identical content at the same path: merged fine.
        assert_eq!(
            std::fs::read_to_string(prefix.join("usr/share/common")).unwrap(),
            "shared\n"
        );
        // Symlinks survive the merge.
        assert_eq!(
            std::fs::read_link(prefix.join("usr/lib/liba.so")).unwrap(),
            Path::new("liba.so.1")
        );
    }

    #[test]
    fn merge_conflicting_content_is_a_hard_error_naming_both() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let snap_a = make_snap(&tmp.path().join("a"), &[("usr/share/x", "from-a\n")], &[]);
        let snap_b = make_snap(&tmp.path().join("b"), &[("usr/share/x", "from-b\n")], &[]);

        let err = materialize_merged_prefix(&[
            Payload {
                pkg: "pkg-a".into(),
                snap: snap_a,
            },
            Payload {
                pkg: "pkg-b".into(),
                snap: snap_b,
            },
        ])
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("usr/share/x"), "names the path: {msg}");
        assert!(
            msg.contains("pkg-a") && msg.contains("pkg-b"),
            "names both packages: {msg}"
        );
    }

    #[test]
    fn meta_packaging_subtree_is_excluded_from_the_merge() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
            return;
        }
        // Every payload ships its own meta/snap.yaml — differing content is
        // normal packaging metadata, never a build-prefix conflict.
        let tmp = tempfile::tempdir().unwrap();
        let snap_a = make_snap(
            &tmp.path().join("a"),
            &[
                ("meta/snap.yaml", "name: a\n"),
                ("usr/share/data", "shared\n"),
            ],
            &[],
        );
        let snap_b = make_snap(
            &tmp.path().join("b"),
            &[
                ("meta/snap.yaml", "name: b\n"),
                ("usr/share/data", "shared\n"),
            ],
            &[],
        );

        let merged = materialize_merged_prefix(&[
            Payload {
                pkg: "pkg-a".into(),
                snap: snap_a,
            },
            Payload {
                pkg: "pkg-b".into(),
                snap: snap_b,
            },
        ])
        .expect("differing meta/ subtrees must not conflict");
        let prefix = merged.path().to_path_buf();
        assert!(!prefix.join("meta").exists(), "meta/ must be excluded");
        assert_eq!(
            std::fs::read_to_string(prefix.join("usr/share/data")).unwrap(),
            "shared\n"
        );
    }

    #[test]
    fn info_dir_index_is_excluded_from_the_merge() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
            return;
        }
        // Every autotools install regenerates usr/share/info/dir through
        // install-info, so packages shipping info files carry
        // byte-different copies of the shared generated index. It is
        // never a build input — excluded like meta/ instead of
        // hard-erroring every toolchain-sized merge.
        let tmp = tempfile::tempdir().unwrap();
        let snap_a = make_snap(
            &tmp.path().join("a"),
            &[
                ("usr/share/info/dir", "glibc-dir-entries\n"),
                ("usr/share/info/libc.info", "libc\n"),
            ],
            &[],
        );
        let snap_b = make_snap(
            &tmp.path().join("b"),
            &[
                ("usr/share/info/dir", "gcc-dir-entries\n"),
                ("usr/share/info/gcc.info", "gcc\n"),
            ],
            &[],
        );

        let merged = materialize_merged_prefix(&[
            Payload {
                pkg: "glibc".into(),
                snap: snap_a,
            },
            Payload {
                pkg: "gcc".into(),
                snap: snap_b,
            },
        ])
        .expect("differing info dir indexes must not conflict");
        let prefix = merged.path().to_path_buf();
        assert!(
            !prefix.join("usr/share/info/dir").exists(),
            "the shared info index must be excluded"
        );
        // The actual docs still merge.
        assert_eq!(
            std::fs::read_to_string(prefix.join("usr/share/info/libc.info")).unwrap(),
            "libc\n"
        );
        assert_eq!(
            std::fs::read_to_string(prefix.join("usr/share/info/gcc.info")).unwrap(),
            "gcc\n"
        );
    }
    #[test]
    fn empty_payload_list_yields_empty_prefix() {
        let merged = materialize_merged_prefix(&[]).unwrap();
        assert!(merged.path().is_dir());
    }

    /// payload_files lists every basename at every depth — the leak scan's
    /// resolution data (ADR-0018 Decision 3). A soname lives in usr/lib, a
    /// layer below the payload root.
    #[test]
    fn payload_files_lists_recursive_basenames() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let snap = make_snap(
            &tmp.path().join("libfoo"),
            &[("usr/lib/libfoo.so.1", "x"), ("usr/include/libfoo.h", "h")],
            &[("usr/lib/libfoo.so", "libfoo.so.1")],
        );
        let merged = materialize_merged_prefix(&[Payload {
            pkg: "libfoo".into(),
            snap,
        }])
        .unwrap();
        let files = merged.payload_files();
        let libfoo = files.get("libfoo").expect("libfoo payload listed");
        assert!(libfoo.contains("libfoo.so.1"), "soname basename listed");
        assert!(libfoo.contains("libfoo.so"), "symlink basename listed");
        assert!(libfoo.contains("libfoo.h"), "header basename listed");
    }

    // ---- Wrapper-aware staging (issue #90) ----

    /// The native-ELF tree wrapper `emit_elf_tree_wrapper` authors for the
    /// python app: the exec target carries the pod extension layout —
    /// `active/extensions/<pkg>/usr/` + the payload's own `usr/bin/...`
    /// rel path, i.e. the `usr/usr/bin/python3.real` doubling that broke
    /// every cold meson-family build. Staging must re-point it at the
    /// prefix root, where the payload root merges.
    fn elf_tree_wrapper_text(pkg: &str, real_rel: &str) -> String {
        format!(
            "#!/bin/sh\n\
             SCRIPT=\"$(readlink -f \"$0\")\"\n\
             PODROOT=\"$(dirname \"$(dirname \"$(dirname \"$SCRIPT\")\")\")\"\n\
             PYTHONPATH=\"${{SHUTTLE_PYTHONPATH:-}}\"\n\
             export PYTHONPATH\n\
             exec \"$PODROOT/active/extensions/{pkg}/usr/{real_rel}\" \"$@\"\n"
        )
    }

    #[test]
    fn elf_tree_wrapper_usr_usr_doubling_is_repointed_at_the_prefix() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let wrapper = elf_tree_wrapper_text("python", "usr/bin/python3.real");
        let snap = make_snap(
            &tmp.path().join("python"),
            &[
                ("usr/bin/python3", wrapper.as_str()),
                ("usr/bin/python3.real", "ELF-bytes"),
            ],
            &[],
        );
        let merged = materialize_merged_prefix(&[Payload {
            pkg: "python".into(),
            snap,
        }])
        .expect("the doubled wrapper must stage");
        let rewritten = std::fs::read_to_string(merged.path().join("usr/bin/python3")).unwrap();
        assert!(
            !rewritten.contains("active/extensions"),
            "the extension-tree segment must be gone: {rewritten}"
        );
        assert!(
            rewritten.contains("exec \"$PODROOT/usr/bin/python3.real\" \"$@\"\n"),
            "the exec target must resolve at the prefix root: {rewritten}"
        );
        assert!(
            merged.path().join("usr/bin/python3.real").is_file(),
            "the .real sibling must survive staging"
        );
    }

    /// The script tree wrapper (`emit_script_tree_wrapper`, issue #13) also
    /// derives site-packages dirs from the doubled layout — the PKGROOT
    /// assignment must collapse to the prefix root as well.
    #[test]
    fn script_tree_wrapper_pkgroot_pythonpath_block_is_repointed() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let wrapper = format!(
            "#!/bin/sh\n\
             SCRIPT=\"$(readlink -f \"$0\")\"\n\
             PODROOT=\"$(dirname \"$(dirname \"$(dirname \"$SCRIPT\")\")\")\"\n\
             TREE=\"$PODROOT/active/extensions/cli/usr/usr/bin/cli.real\"\n\
             [ -f \"$TREE\" ] || TREE=\"$(dirname \"$(dirname \"$SCRIPT\")\")/usr/bin/cli.real\"\n\
             \x20        PKGROOT=\"$PODROOT/active/extensions/cli/usr\"\n\
             \x20        PYTHONPATH=\"\"\n\
             \x20        for sp in \"$PKGROOT\"/usr/lib/python3.*/site-packages; do\n\
             \x20         [ -d \"$sp\" ] && PYTHONPATH=\"${{PYTHONPATH:+$PYTHONPATH:$sp}}\"\n\
             \x20        done\n\
             \x20        export PYTHONPATH\n\
             exec \"python3\" \"$TREE\" \"$@\"\n"
        );
        let snap = make_snap(
            &tmp.path().join("cli"),
            &[
                ("usr/bin/cli", wrapper.as_str()),
                ("usr/bin/cli.real", "#!/usr/bin/env node\n"),
            ],
            &[],
        );
        let python = make_snap(
            &tmp.path().join("python"),
            &[("usr/bin/python3", "ELF")],
            &[],
        );
        let merged = materialize_merged_prefix(&[
            Payload {
                pkg: "cli".into(),
                snap,
            },
            Payload {
                pkg: "python".into(),
                snap: python,
            },
        ])
        .expect("the wrapper must stage against a requires-provided interpreter");
        let rewritten = std::fs::read_to_string(merged.path().join("usr/bin/cli")).unwrap();
        assert!(
            rewritten.contains("PKGROOT=\"$PODROOT\""),
            "PKGROOT must collapse to the prefix root: {rewritten}"
        );
        assert!(
            rewritten.contains("TREE=\"$PODROOT/usr/bin/cli.real\""),
            "the #210 tree target must resolve at the prefix root: {rewritten}"
        );
        assert!(
            rewritten.contains("exec \"python3\" \"$TREE\" \"$@\"\n"),
            "exec must point at the resolved tree target with the bare \
             interpreter: {rewritten}"
        );
    }

    /// The python tree wrapper scrubs inherited `PYTHONPATH` for the farm;
    /// in the prefix the caller's value must survive behind the
    /// `SHUTTLE_PYTHONPATH` channel (xkeyboard-config `rules.generator`
    /// died on this: meson hands build-time generators the source root
    /// through `PYTHONPATH`, the wrapper dropped it, `-m` import failed).
    #[test]
    fn python_tree_wrapper_pythonpath_scrub_preserves_the_caller_value() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let wrapper = elf_tree_wrapper_text("python", "usr/bin/python3.real");
        let snap = make_snap(
            &tmp.path().join("python"),
            &[
                ("usr/bin/python3", wrapper.as_str()),
                ("usr/bin/python3.real", "ELF-bytes"),
            ],
            &[],
        );
        let merged = materialize_merged_prefix(&[Payload {
            pkg: "python".into(),
            snap,
        }])
        .expect("the python wrapper must stage");
        let rewritten = std::fs::read_to_string(merged.path().join("usr/bin/python3")).unwrap();
        assert!(
            rewritten
                .contains("PYTHONPATH=\"${SHUTTLE_PYTHONPATH:-}${PYTHONPATH:+:$PYTHONPATH}\"\n"),
            "the scrub must append the caller's PYTHONPATH: {rewritten}"
        );
        assert!(
            !rewritten.contains("PYTHONPATH=\"${SHUTTLE_PYTHONPATH:-}\"\n"),
            "the bare scrub must not survive prefix staging: {rewritten}"
        );
    }

    /// The native-ELF lib wrapper (`emit_elf_lib_wrapper`, issue #10 B)
    /// execs an absolute pod-store blob path — meaningless in the prefix.
    /// The rewrite execs the preserved `.real` sibling from the wrapper's
    /// own directory; the LD_LIBRARY_PATH entries re-point at the prefix.
    #[test]
    fn elf_lib_wrapper_store_blob_exec_rewrites_to_the_real_sibling() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let wrapper = "#!/bin/sh\n\
             SCRIPT=\"$(readlink -f \"$0\")\"\n\
             BLODIR=\"$(dirname \"$SCRIPT\")\"\n\
             PODROOT=\"$(dirname \"$(dirname \"$BLODIR\")\")\"\n\
             export LD_LIBRARY_PATH=\"$PODROOT/active/extensions/jq/usr/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\"\n\
             exec \"/home/u/pods/daily/store/aa/deadbeef\" \"$@\"\n";
        let snap = make_snap(
            &tmp.path().join("jq"),
            &[
                ("usr/bin/jq", wrapper),
                ("usr/bin/jq.real", "ELF-bytes"),
                ("usr/lib/libjq.so.1", "ELF-lib"),
            ],
            &[],
        );
        let merged = materialize_merged_prefix(&[Payload {
            pkg: "jq".into(),
            snap,
        }])
        .expect("the lib wrapper must stage");
        let rewritten = std::fs::read_to_string(merged.path().join("usr/bin/jq")).unwrap();
        assert!(
            rewritten.contains("exec \"$(dirname \"$(readlink -f \"$0\")\")/jq.real\" \"$@\"\n"),
            "the store-blob exec must become a sibling exec: {rewritten}"
        );
        assert!(
            rewritten.contains(
                "LD_LIBRARY_PATH=\"$PODROOT/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\""
            ),
            "LD entries must re-point at the prefix root and keep the caller-prepend \
             idiom (the shellenv compose, #94): {rewritten}"
        );
    }

    /// The perl module-tree wrapper (the issue #90 PERL5LIB shape) sweeps
    /// every payload's extension tree with a `*` package glob; staging must
    /// re-point the whole sweep at the prefix root.
    #[test]
    fn perl_module_tree_wrapper_sweep_is_repointed_at_the_prefix() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let wrapper = "#!/bin/sh\n\
             SCRIPT=\"$(readlink -f \"$0\")\"\n\
             PODROOT=\"$(dirname \"$(dirname \"$(dirname \"$SCRIPT\")\")\")\"\n\
             TREE=\"$PODROOT/active/extensions/perltidy/usr/usr/bin/perltidy.real\"\n\
             [ -f \"$TREE\" ] || TREE=\"$(dirname \"$(dirname \"$SCRIPT\")\")/usr/bin/perltidy.real\"\n\
             \x20        PERL5LIB=\"\"\n\
             \x20        for d in \"$PODROOT\"/active/extensions/*/usr/usr/lib/perl5/*/ \"$PODROOT\"/active/extensions/*/usr/usr/lib/perl5/*/*/ \"$PODROOT\"/active/extensions/*/usr/usr/lib/perl5/*/*/*/; do\n\
             \x20         [ -d \"$d\" ] && PERL5LIB=\"${{PERL5LIB:+$PERL5LIB:}}$d\"\n\
             \x20        done\n\
             \x20        export PERL5LIB\n\
             exec \"perl\" \"$TREE\" \"$@\"\n";
        let app = make_snap(
            &tmp.path().join("perltidy"),
            &[
                ("usr/bin/perltidy", wrapper),
                ("usr/bin/perltidy.real", "#!/usr/bin/perl\n"),
            ],
            &[],
        );
        let perl = make_snap(&tmp.path().join("perl"), &[("usr/bin/perl", "ELF")], &[]);
        let merged = materialize_merged_prefix(&[
            Payload {
                pkg: "perltidy".into(),
                snap: app,
            },
            Payload {
                pkg: "perl".into(),
                snap: perl,
            },
        ])
        .expect("the perl tree wrapper must stage");
        let rewritten = std::fs::read_to_string(merged.path().join("usr/bin/perltidy")).unwrap();
        assert!(
            rewritten.contains("\"$PODROOT\"/usr/lib/perl5/*/"),
            "the closure-wide sweep must re-point at the prefix root: {rewritten}"
        );
        assert!(
            !rewritten.contains("active/extensions"),
            "no extension segment may survive: {rewritten}"
        );
        assert!(
            rewritten.contains("TREE=\"$PODROOT/usr/bin/perltidy.real\""),
            "the #210 tree target must resolve at the prefix root: {rewritten}"
        );
        assert!(
            rewritten.contains("exec \"perl\" \"$TREE\" \"$@\"\n"),
            "exec must point at the resolved tree target: {rewritten}"
        );
    }

    /// The flat interpreter wrapper (`emit_script_wrapper`, issue #9): the
    /// bare interpreter resolves through the prefix PATH (a declared
    /// requires provides it), the blob path becomes the `.real` sibling.
    #[test]
    fn flat_script_wrapper_rewrites_and_resolves_the_interpreter() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let wrapper = "#!/bin/sh\nexec \"perl\" \"/home/u/pods/daily/store/aa/cafe\" \"$@\"\n";
        let app = make_snap(
            &tmp.path().join("tool"),
            &[("usr/bin/tool", wrapper), ("usr/bin/tool.real", "script")],
            &[],
        );
        let perl = make_snap(&tmp.path().join("perl"), &[("usr/bin/perl", "ELF")], &[]);
        let merged = materialize_merged_prefix(&[
            Payload {
                pkg: "tool".into(),
                snap: app,
            },
            Payload {
                pkg: "perl".into(),
                snap: perl,
            },
        ])
        .expect("a requires-provided interpreter resolves");
        let rewritten = std::fs::read_to_string(merged.path().join("usr/bin/tool")).unwrap();
        assert!(
            rewritten.contains(
                "exec \"perl\" \"$(dirname \"$(readlink -f \"$0\")\")/tool.real\" \"$@\"\n"
            ),
            "blob path must become the sibling, interpreter kept: {rewritten}"
        );
    }

    /// Fail closed: a flat wrapper whose bare interpreter resolves to
    /// neither the payload set nor a declared requires is a hard error.
    #[test]
    fn flat_wrapper_with_unresolvable_interpreter_fails_closed() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let wrapper = "#!/bin/sh\nexec \"nosuchlang\" \"/p/store/aa/cafe\" \"$@\"\n";
        let app = make_snap(
            &tmp.path().join("tool"),
            &[("usr/bin/tool", wrapper), ("usr/bin/tool.real", "script")],
            &[],
        );
        let err = materialize_merged_prefix(&[Payload {
            pkg: "tool".into(),
            snap: app,
        }])
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("nosuchlang"), "names the interpreter: {msg}");
        assert!(
            msg.contains("neither the merged payloads"),
            "states the fail-closed condition: {msg}"
        );
        assert!(msg.contains("usr/bin/tool"), "names the wrapper: {msg}");
    }

    /// Fail closed: a tree wrapper whose doubled exec target has no
    /// counterpart in the merged prefix (the `.real` never staged).
    #[test]
    fn tree_wrapper_with_missing_exec_target_fails_closed() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let wrapper = elf_tree_wrapper_text("python", "usr/bin/python3.real");
        let snap = make_snap(
            &tmp.path().join("python"),
            // No python3.real: the wrapper's target cannot resolve.
            &[("usr/bin/python3", wrapper.as_str())],
            &[],
        );
        let err = materialize_merged_prefix(&[Payload {
            pkg: "python".into(),
            snap,
        }])
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("usr/bin/python3.real"),
            "names the unresolvable target: {msg}"
        );
        assert!(msg.contains("python"), "names the owning payload: {msg}");
    }

    /// Upstream scripts staged by a payload (meson's launcher, a shebang
    /// script like perltidy's) are never ours to rewrite: they stage
    /// byte-identical.
    #[test]
    fn upstream_scripts_stage_byte_identical() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let meson_launcher = "#!/bin/sh\nexec python3 -m mesonbuild.mesonmain \"$@\"\n";
        let perltidy_like = "#!/usr/bin/perl\nprint \"perltidy\\n\";\n";
        let snap = make_snap(
            &tmp.path().join("meson"),
            &[
                ("usr/bin/meson", meson_launcher),
                ("usr/bin/perltidy", perltidy_like),
            ],
            &[],
        );
        let merged = materialize_merged_prefix(&[Payload {
            pkg: "meson".into(),
            snap,
        }])
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(merged.path().join("usr/bin/meson")).unwrap(),
            meson_launcher
        );
        assert_eq!(
            std::fs::read_to_string(merged.path().join("usr/bin/perltidy")).unwrap(),
            perltidy_like
        );
    }
}
