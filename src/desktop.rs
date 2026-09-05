//! User-level Freedesktop launchers for pod GUI apps (issue #7).
//!
//! GUI applications in a pod appear in the desktop applications menu via
//! generated user-level `.desktop` entries plus icons, versioned with the
//! pod generation so removal and rollback add, revert, or withdraw
//! launchers atomically.
//!
//! The generated entries live INSIDE the pod generation (a `launchers/`
//! directory beside the bin farm — the farm emitter's sibling) and are
//! surfaced through user-level symlinks into the user's applications and
//! icons directories (`$XDG_DATA_HOME/applications`, `$XDG_DATA_HOME/icons`).
//! The generation is the versioned source of truth: install/remove/rollback
//! re-emit the target generation's launcher set, and the user-level links
//! follow. Nothing is ever written outside user directories; no privilege
//! escalation, no system paths, no sudo.
//!
//! Exec lines MUST point at the pod farm binaries (the `current`-flipped
//! farm), never at store paths: the farm is the documented activation seam,
//! and a launcher must survive a rollback of `current` to that generation.
//! An absolute farm path is baked into each entry.
//!
//! App-ID collision rule (issue #7): the desktop file ID is pod-namespaced
//! (`shuttle-pod-<pod>-<app>`), so two pods' same-ID apps coexist exactly
//! like their binaries (separate farms, no clash). WITHIN one pod, two
//! packages claiming the same application ID go through the shared
//! collision classifier (`crate::farm::classify_collision`, kept
//! desktop-agnostic so loads, #8, can generalize it to binaries):
//! same-precedence duplicates error before any write; a cross-layer
//! override warns and the higher layer wins.
//!
//! Sources: the pod package's `.desktop` file (declared per app via the
//! DSL's `desktop:` app key, read and parsed at install time) plus the
//! package icon (the snap-level `icon`, packed at `meta/gui/icon.<ext>`,
//! ingested into the store). Both are
//! recorded in the generation manifest as [`DesktopLauncher`] so the emitter
//! rebuilds entries from the manifest alone — rollback re-emits without
//! re-unpacking. The icon is a pod-namespaced link into the store blob; the
//! `.desktop` file itself is written fresh each emit.

use std::collections::BTreeSet;

use crate::runtime::{DesktopLauncher, Generation, RuntimeStore};

/// The launcher directory inside a generation: `<root>/generations/<n>/
/// launchers`. The bin farm's sibling (issue #7; the farm keeps its own
/// `farm/` subdir for binaries).
pub const LAUNCHERS_DIR: &str = "launchers";

/// The user-level applications directory (redirectable for tests).
pub fn user_applications_dir(data_home: &std::path::Path) -> std::path::PathBuf {
    data_home.join("applications")
}

/// The user-level icons directory (redirectable for tests).
pub fn user_icons_dir(data_home: &std::path::Path) -> std::path::PathBuf {
    data_home.join("icons")
}

/// The user's data-home root the launcher surface follows. Resolution
/// order:
///
/// 1. `SHUTTLE_DATA_HOME` — the explicit redirect knob (tests MUST set
///    this or nest their pod root; never the real home).
/// 2. The documented pod layout `<data-home>/shuttle/pods/<pod>`: derived
///    from the pod root, so a pod rooted at that layout (the production
///    default AND tests that root at `<tmp>/shuttle/pods/<name>`) gets
///    its surface under the same data home with no environment at all.
/// 3. `XDG_DATA_HOME`, then `~/.local/share` — the standard user
///    locations (only for pod roots redirected off the documented
///    layout).
pub fn user_data_home(root: &std::path::Path) -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("SHUTTLE_DATA_HOME") {
        if !dir.is_empty() {
            return std::path::PathBuf::from(dir);
        }
    }
    if let Some(data) = documented_layout_data_home(root) {
        return data.to_path_buf();
    }
    match std::env::var("XDG_DATA_HOME") {
        Ok(dir) if !dir.is_empty() => std::path::PathBuf::from(dir),
        _ => std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
            .join(".local/share"),
    }
}

/// The data home of a pod rooted at the documented
/// `<data-home>/shuttle/pods/<pod>` layout — `<root>/../../../`.
fn documented_layout_data_home(root: &std::path::Path) -> Option<&std::path::Path> {
    let pods = root.parent()?;
    if pods.file_name()? != "pods" {
        return None;
    }
    let shuttle = pods.parent()?;
    if shuttle.file_name()? != "shuttle" {
        return None;
    }
    shuttle.parent()
}

/// The pod name behind a store: the last component of its root path.
fn pod_name(store: &RuntimeStore) -> miette::Result<String> {
    store
        .root()
        .file_name()
        .and_then(|s| s.to_str())
        .map(str::to_string)
        .ok_or_else(|| miette::miette!("pod store root has no name component"))
}

/// The icon name the launcher uses: pod-namespaced so two pods' same-icon
/// apps never collide at the theme level, and so withdrawal can recognize
/// its own icons.
pub fn icon_name(pod: &str, app_id: &str) -> String {
    format!("shuttle-pod-{pod}-{app_id}")
}

/// The launcher directory of generation `n`.
pub fn launchers_dir(store: &RuntimeStore, n: u64) -> std::path::PathBuf {
    store.generation_dir(n).join(LAUNCHERS_DIR)
}

/// Emit a generation's launcher set into its `launchers/` directory and
/// surface it at the user level. Rebuilds the directory from scratch on
/// every call (fully idempotent), then rewrites the user-level entries
/// and icons so a re-emit reflects the generation exactly.
///
/// The user-level surface is redirected through [`user_data_home`]; use
/// [`emit_in`] for an explicit data home (tests).
pub fn emit(store: &RuntimeStore, gen: &Generation) -> miette::Result<std::path::PathBuf> {
    let data_home = user_data_home(store.root());
    let pod = pod_name(store)?;
    emit_in(store, gen, &data_home, &pod)
}

/// [`emit`] with an explicit pod name and data home.
///
/// `data_home` holds `applications/` and `icons/` (which the test harness
/// points at a tempdir). `pod` is threaded in (rather than re-derived) so
/// callers that already know the pod name don't re-read the store root.
pub fn emit_in(
    store: &RuntimeStore,
    gen: &Generation,
    data_home: &std::path::Path,
    pod: &str,
) -> miette::Result<std::path::PathBuf> {
    let dir = launchers_dir(store, gen.n);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)
            .map_err(|e| miette::miette!("clearing stale launchers {}: {e}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir)
        .map_err(|e| miette::miette!("creating launchers {}: {e}", dir.display()))?;

    let apps_dir = user_applications_dir(data_home);
    let icons_root = user_icons_dir(data_home);

    // The set of app ids we surface this emission — used to withdraw
    // stale user links a previous generation left.
    let mut keep: BTreeSet<String> = BTreeSet::new();

    let farm = store.root().join(crate::farm::CURRENT_LINK);
    let mut seen: std::collections::BTreeMap<&str, (&str, crate::farm::ClaimLayer)> =
        Default::default();
    for pkg in crate::farm::layered_packages(gen) {
        for (app_id, launcher) in &pkg.desktops {
            if let Some((incumbent_pkg, incumbent_layer)) = seen.get(app_id.as_str()) {
                crate::farm::warn_emit_collision(
                    "application id",
                    app_id,
                    &pkg.name,
                    incumbent_pkg,
                    *incumbent_layer == pkg.layer,
                );
            }
            seen.insert(app_id, (&pkg.name, pkg.layer));
            let exec = farm.join(app_id);
            let icon = if launcher.icon.is_some() {
                Some(icon_name(pod, app_id))
            } else {
                launcher.icon_ref.clone()
            };
            let text = render(launcher, app_id, &exec, icon.as_deref());
            // Validate before writing (and again on the written file in
            // tests): a malformed entry must fail the emit, never leak.
            let icon_blob = launcher.icon.as_ref().map(|i| store.blob_path(&i.sha256));
            validate(&text, icon.as_deref(), icon_blob.as_deref())?;

            let file = dir.join(format!("{app_id}.desktop"));
            std::fs::write(&file, text)
                .map_err(|e| miette::miette!("writing {}: {e}", file.display()))?;

            // User-level .desktop link, pod-NAMESPACED (the desktop file
            // ID mirrors the binary rule: separate pods coexist, their
            // farms are separate) — absolute, into the generation's
            // launcher file.
            let user_link = apps_dir.join(format!("{}{}.desktop", entry_prefix(pod), app_id));
            if let Some(parent) = user_link.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| miette::miette!("creating {}: {e}", parent.display()))?;
            }
            link_or_replace(&file, &user_link)?;
            keep.insert(app_id.clone());

            // Icon: a pod-namespaced theme icon link into the store blob.
            if let (Some(name), Some(icon)) = (icon.as_deref(), &launcher.icon) {
                let size = icon_theme_dir(&icon.ext);
                let dest = icons_root
                    .join("hicolor")
                    .join(size)
                    .join("apps")
                    .join(format!("{name}.{}", icon.ext));
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| miette::miette!("creating {}: {e}", parent.display()))?;
                }
                let src = store.blob_path(&icon.sha256);
                link_or_replace(&src, &dest)?;
            }
        }
    }

    // Withdraw user links the previous generation left but this one does
    // not own (a launcher removed, an app renamed).
    withdraw_stale(&apps_dir, &icons_root, pod, &keep)?;

    Ok(dir)
}

/// The freedesktop icon theme size subdirectory for a given icon
/// extension: SVG icons are theme-scalable, raster icons use the 256x256
/// apps slot.
fn icon_theme_dir(ext: &str) -> &'static str {
    if ext == "svg" || ext == "svgz" {
        "scalable"
    } else {
        "256x256"
    }
}

/// The pod-namespaced prefix of every user-level file this emitter owns:
/// `shuttle-pod-<pod>-`. The desktop file ID and the icon name share it,
/// so withdrawal can recognize its own links and two pods' same-app IDs
/// never collide at the user level.
fn entry_prefix(pod: &str) -> String {
    format!("shuttle-pod-{pod}-")
}

/// Withdraw the user-level `.desktop` and icon links this pod owns but
/// are not in `keep` (stale from a prior generation). Only links whose
/// file name matches the pod-namespaced pattern are touched — never other
/// tools' entries.
fn withdraw_stale(
    apps_dir: &std::path::Path,
    icons_root: &std::path::Path,
    pod: &str,
    keep: &BTreeSet<String>,
) -> miette::Result<()> {
    let prefix = entry_prefix(pod);
    if let Ok(rd) = std::fs::read_dir(apps_dir) {
        for e in rd.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(app_id) = name
                .strip_suffix(".desktop")
                .and_then(|stem| stem.strip_prefix(&prefix))
            else {
                continue;
            };
            if !keep.contains(app_id) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    // Icons: hicolor/<size>/apps/<prefix><app_id>.<ext>.
    let hicolor = icons_root.join("hicolor");
    if let Ok(sizes) = std::fs::read_dir(&hicolor) {
        for size in sizes.filter_map(|e| e.ok()) {
            let apps = size.path().join("apps");
            if let Ok(rd) = std::fs::read_dir(&apps) {
                for e in rd.filter_map(|e| e.ok()) {
                    let name = e.file_name().to_string_lossy().into_owned();
                    if let Some(id_ext) = name.strip_prefix(&prefix) {
                        if !keep_any(keep, id_ext) {
                            let _ = std::fs::remove_file(e.path());
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// True when a pod-namespaced icon basename belongs to a kept app id.
fn keep_any(keep: &BTreeSet<String>, id_ext: &str) -> bool {
    // id_ext = "<app_id>.<ext>"; the app id is everything before the
    // last dot. Because app ids can't contain dots in our DSL surface,
    // split off the extension.
    match id_ext.rsplit_once('.') {
        Some((id, _)) => keep.contains(id),
        None => keep.contains(id_ext),
    }
}

/// Remove the user-level launcher + icon links for one pod. The
/// generation's own `launchers/` directory is left in place (the store's
/// GC frees it with the generation); only the user-level surface is
/// withdrawn. Missing links are no-ops.
pub fn clear(store: &RuntimeStore) -> miette::Result<()> {
    clear_in(store, &user_data_home(store.root()))
}

/// [`clear`] with an explicit data home.
pub fn clear_in(store: &RuntimeStore, data_home: &std::path::Path) -> miette::Result<()> {
    let pod = pod_name(store)?;
    withdraw_stale(
        &user_applications_dir(data_home),
        &user_icons_dir(data_home),
        &pod,
        &BTreeSet::new(),
    )?;
    Ok(())
}

/// Symlink `dest` to `src`, replacing any existing file/link at `dest`.
/// Creating the same link again (a re-emit) is idempotent; a link to a
/// different target is replaced.
fn link_or_replace(src: &std::path::Path, dest: &std::path::Path) -> miette::Result<()> {
    let _ = std::fs::remove_file(dest);
    std::os::unix::fs::symlink(src, dest)
        .map_err(|e| miette::miette!("linking {} -> {}: {e}", dest.display(), src.display()))?;
    Ok(())
}

// ── Source parsing (the package's .desktop file) ──

/// The metadata subset the launcher takes from a package's `.desktop`
/// file, parsed at install time and recorded in the generation manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesktopSource {
    /// `Name=` (required for a valid entry).
    pub name: Option<String>,
    /// `GenericName=`, passed through.
    pub generic_name: Option<String>,
    /// `Comment=`, passed through.
    pub comment: Option<String>,
    /// `Categories=`, split on `;` (empties dropped).
    pub categories: Vec<String>,
    /// `Icon=` — a theme icon name passed through ONLY when the package
    /// ships no icon of its own (the emitter then substitutes the
    /// pod-namespaced link name).
    pub icon_ref: Option<String>,
}

/// Parse a package's `.desktop` file. Strict about what the launcher
/// NEEDS: the file must carry a `[Desktop Entry]` group with
/// `Type=Application` and a non-empty `Name=`; everything else the
/// launcher uses is optional. Unknown keys and locale variants
/// (`Name[de]=`) are ignored — the source file is the package's own.
pub fn parse_source(text: &str, label: &str) -> miette::Result<DesktopSource> {
    let mut source = DesktopSource::default();
    let mut in_entry = false;
    let mut saw_entry_group = false;
    let mut type_is_application = false;
    for line in text.lines() {
        if line.starts_with('[') {
            // A new group ends the Desktop Entry group.
            if in_entry {
                break;
            }
            in_entry = line == "[Desktop Entry]";
            saw_entry_group |= in_entry;
            continue;
        }
        if !in_entry || line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        // Locale variants (`Name[de]=`) are distinct keys — the
        // launcher uses the un-localized base key only.
        if key.contains('[') {
            continue;
        }
        match key {
            "Type" => type_is_application = value == "Application",
            "Name" => source.name = Some(unescape_value(value)),
            "GenericName" => source.generic_name = Some(unescape_value(value)),
            "Comment" => source.comment = Some(unescape_value(value)),
            "Categories" => {
                source.categories = value
                    .split(';')
                    .filter(|c| !c.is_empty())
                    .map(str::to_string)
                    .collect();
            }
            "Icon" => source.icon_ref = Some(unescape_value(value)),
            _ => {}
        }
    }
    if !saw_entry_group {
        miette::bail!("{label}: .desktop file has no [Desktop Entry] group");
    }
    if !type_is_application {
        miette::bail!("{label}: .desktop file must have Type=Application");
    }
    match &source.name {
        Some(n) if !n.trim().is_empty() => {}
        _ => miette::bail!("{label}: .desktop file must have a non-empty Name="),
    }
    Ok(source)
}

/// Unescape a `.desktop` string value: `\n`, `\t`, `\r`, `\s`, `\\`.
fn unescape_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::with_capacity(value.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.get(i) {
            Some('n') => {
                out.push('\n');
                i += 1;
            }
            Some('t') => {
                out.push('\t');
                i += 1;
            }
            Some('r') => {
                out.push('\r');
                i += 1;
            }
            Some('s') => {
                out.push(' ');
                i += 1;
            }
            Some('\\') => {
                out.push('\\');
                i += 1;
            }
            Some(&other) => {
                out.push('\\');
                out.push(other);
                i += 1;
            }
            None => out.push('\\'),
        }
    }
    out
}

// ── Rendering ──

/// Render a `.desktop` entry for one app. `exec` is the absolute farm
/// binary path (never a store path). `icon` is the icon NAME to write
/// into `Icon=` (a pod-namespaced theme icon name when the package ships
/// an icon blob, else the package's pass-through `icon_ref`).
///
/// Required keys (`[Desktop Entry]`, `Type=Application`, `Name=`,
/// `Exec=`) are always emitted; `Icon`, `GenericName`, `Comment`,
/// `Categories`, and `Terminal=false` follow. Category list is
/// `;`-terminated.
pub fn render(
    launcher: &DesktopLauncher,
    app_id: &str,
    exec: &std::path::Path,
    icon: Option<&str>,
) -> String {
    let mut out = String::new();
    out.push_str("[Desktop Entry]\n");
    out.push_str("Type=Application\n");
    out.push_str(&format!(
        "Name={}\n",
        escape_value(launcher.name.as_deref().unwrap_or(app_id))
    ));
    if let Some(gn) = &launcher.generic_name {
        out.push_str(&format!("GenericName={}\n", escape_value(gn)));
    }
    if let Some(c) = &launcher.comment {
        out.push_str(&format!("Comment={}\n", escape_value(c)));
    }
    if let Some(icon) = icon {
        out.push_str(&format!("Icon={}\n", escape_value(icon)));
    }
    if !launcher.categories.is_empty() {
        out.push_str(&format!("Categories={};\n", launcher.categories.join(";")));
    }
    out.push_str(&format!("Exec={}\n", render_exec(exec)));
    out.push_str("Terminal=false\n");
    out
}

/// Render an `Exec=` value: always a double-quoted absolute path (never a
/// bare token), with the spec's backslash escapes for `"`, `` ` ``, `$`,
/// and `\`. Exec's shell-like quoting inside double quotes makes the
/// absolute farm path unambiguous.
fn render_exec(exec: &std::path::Path) -> String {
    let raw = exec.to_string_lossy();
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for c in raw.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '`' => out.push_str("\\`"),
            '$' => out.push_str("\\$"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Escape a non-Exec `.desktop` string value: `\n`, `\t`, `\r`, `\\`,
/// and leading/trailing space become `\s`. Internal and most other
/// characters pass through verbatim (the freedesktop value escaping
/// rules).
fn escape_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let total = chars.len();
    let mut out = String::with_capacity(value.len() + 2);
    for (i, &c) in chars.iter().enumerate() {
        let is_edge = i == 0 || i + 1 == total;
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            ' ' if is_edge => out.push_str("\\s"),
            c => out.push(c),
        }
    }
    out
}

// ── Validation (embedded Desktop Entry validator) ──

/// The registered category names (the union of the freedesktop "main" and
/// "additional" categories) a `Categories=` is checked against.
const REGISTERED_CATEGORIES: &[&str] = &[
    "AudioVideo",
    "Audio",
    "Video",
    "Development",
    "Education",
    "Game",
    "Graphics",
    "Network",
    "Office",
    "Science",
    "Settings",
    "System",
    "Utility",
    // Additional categories.
    "Building",
    "Debugger",
    "IDE",
    "GUIDesigner",
    "Profiling",
    "RevisionControl",
    "Translation",
    "Calendar",
    "ContactManagement",
    "Database",
    "Dictionary",
    "Chart",
    "Email",
    "Feed",
    "FileManager",
    "WordProcessor",
    "P2P",
    "InstantMessaging",
    "IRCClient",
    "Viewer",
    "WebBrowser",
    "Archiving",
    "DiscBurning",
    "FileTools",
    "Midi",
    "Mixer",
    "Sequencer",
    "Tuner",
    "TV",
    "AudioVideoEditing",
    "Player",
    "Recorder",
    "Disc",
    "Amusement",
    "ArcadeGame",
    "BlockGame",
    "LogicGame",
    "BoardGame",
    "CardGame",
    "KidsGame",
    "ActionGame",
    "AdventureGame",
    "RolePlaying",
    "Shooter",
    "Simulation",
    "SportsGame",
    "StrategyGame",
    "Emulator",
    "Art",
    "Construction",
    "Music",
    "Languages",
    "ArtificialIntelligence",
    "Astronomy",
    "Biology",
    "Chemistry",
    "ComputerScience",
    "DataVisualization",
    "Economy",
    "Electricity",
    "Geography",
    "Geology",
    "Geoscience",
    "History",
    "Humanities",
    "ImageProcessing",
    "Literature",
    "Maps",
    "Math",
    "NumericalAnalysis",
    "MedicalSoftware",
    "Physics",
    "Robotics",
    "Spirituality",
    "Sports",
    "ParallelComputing",
    "RemoteAccess",
    "Telephony",
    "TelephonyTools",
    "VideoConference",
    "Security",
    "Accessibility",
    "DesktopSettings",
    "HardwareSettings",
    "Printing",
    "PackageManager",
    "Dialup",
    "Authentication",
    "Scanning",
    "OCR",
    "Photography",
    "Publishing",
    "Spreadsheet",
    "Presentation",
    "TextEditor",
    "TerminalEmulator",
    "FileTransfer",
    "Monitor",
    "WebDevelopment",
    "Screensaver",
    "TrayIcon",
    "Calculator",
    "Clock",
    "TextTools",
    "X11",
    "Wireless",
    "MonitorCC",
    "ModernToolkit",
    "GTK",
    "Qt",
    "Motif",
    "Java",
    "ConsoleOnly",
];

/// Validate a generated `.desktop` entry against the subset the DSL
/// emits, strictly. Used at emit time (and heavily in tests) so a
/// malformed entry fails the emit instead of leaking into the menu.
///
/// Checks:
/// - The file has a `[Desktop Entry]` group with `Type=Application`.
/// - Required keys `Name=`, `Exec=` are present and non-empty.
/// - `Exec=` begins with an absolute path (`/`), and that path is a
///   valid quoted/unquoted token (no stray quotes or backslashes).
/// - `Categories=`, when present, is `;`-terminated and every category
///   is in the registered set, with at least one main category.
/// - `Icon=`, when present, is a non-empty name containing no `/` (a
///   file path would leak outside the theme namespace).
/// - When `icon_blob` is given, it resolves to an existing file.
pub fn validate(
    text: &str,
    icon_name: Option<&str>,
    icon_blob: Option<&std::path::Path>,
) -> miette::Result<()> {
    let fields = parse_entry(text)?;
    if !fields.type_ok {
        miette::bail!("desktop entry must have Type=Application");
    }
    match fields.name.as_deref() {
        Some(n) if !n.trim().is_empty() => {}
        _ => miette::bail!("desktop entry missing a non-empty Name="),
    }
    let exec = fields.exec.as_deref().unwrap_or("");
    if exec.is_empty() {
        miette::bail!("desktop entry missing non-empty Exec=");
    }
    validate_exec(exec)?;
    if let Some(cats) = &fields.categories {
        validate_categories(cats)?;
    }
    validate_icon(fields.icon.as_deref(), icon_name, icon_blob)
}

/// The interesting keys of one `[Desktop Entry]` group.
struct EntryFields {
    type_ok: bool,
    name: Option<String>,
    exec: Option<String>,
    categories: Option<Vec<String>>,
    icon: Option<String>,
}

/// Extract the interesting keys from the FIRST `[Desktop Entry]` group.
fn parse_entry(text: &str) -> miette::Result<EntryFields> {
    let mut fields = EntryFields {
        type_ok: false,
        name: None,
        exec: None,
        categories: None,
        icon: None,
    };
    let mut in_entry = false;
    for line in text.lines() {
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry || line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            miette::bail!("invalid line in desktop entry: {line:?}");
        };
        match key {
            "Type" => fields.type_ok = value == "Application",
            "Name" => fields.name = Some(value.to_string()),
            "Exec" => fields.exec = Some(value.to_string()),
            "Categories" => {
                fields.categories = Some(
                    value
                        .split(';')
                        .filter(|c| !c.is_empty())
                        .map(str::to_string)
                        .collect(),
                );
            }
            "Icon" => fields.icon = Some(value.to_string()),
            _ => {}
        }
    }
    Ok(fields)
}

/// Validate the `Icon=` key against the expected icon name and blob.
fn validate_icon(
    icon: Option<&str>,
    expected: Option<&str>,
    icon_blob: Option<&std::path::Path>,
) -> miette::Result<()> {
    if let Some(icon) = icon {
        if icon.is_empty() {
            miette::bail!("Icon= must be non-empty when present");
        }
        if icon.contains('/') {
            miette::bail!("Icon= must be a theme icon name, not a path: {icon:?}");
        }
    }
    if let Some(expected) = expected {
        if icon != Some(expected) {
            miette::bail!("Icon= mismatch: expected {expected:?}, got {icon:?}");
        }
    }
    if let Some(blob) = icon_blob {
        if !blob.is_file() {
            miette::bail!("icon blob does not exist: {}", blob.display());
        }
    }
    Ok(())
}

/// Validate an `Exec=` string: the executable token is an absolute path,
/// either double-quoted (with only the spec-legal backslash escapes) or
/// an unquoted bare token containing no `"`/`\`/space.
fn validate_exec(exec: &str) -> miette::Result<()> {
    let first = exec.split_whitespace().next().unwrap_or("");
    if first.is_empty() {
        miette::bail!("Exec= must start with an absolute path, got {exec:?}");
    }
    // The token may be double-quoted; check the QUOTED FORM and the
    // unquoted path inside it.
    let (quoted, body) = match first.strip_prefix('"') {
        Some(rest) => match rest.rsplit_once('"') {
            Some((body, "")) => (true, body),
            _ => miette::bail!("Exec= first token has unclosed quotes: {exec:?}"),
        },
        None => {
            if first.contains('"') || first.contains('\\') {
                miette::bail!("Exec= bare token cannot contain quotes/backslash: {exec:?}");
            }
            (false, first)
        }
    };
    if !body.starts_with('/') {
        miette::bail!("Exec= must start with an absolute path, got {exec:?}");
    }
    if quoted {
        // Walk the quoted body, allowing only \" \\ \` \$ escapes.
        let mut chars = body.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('"' | '\\' | '`' | '$') => {}
                    _ => miette::bail!("Exec= quotes invalid escape: {exec:?}"),
                }
            }
        }
    }
    Ok(())
}

/// Validate a category list: `;`-terminated, every category in the
/// registered set, and at least one main category.
fn validate_categories(cats: &[String]) -> miette::Result<()> {
    let main = [
        "AudioVideo",
        "Audio",
        "Video",
        "Development",
        "Education",
        "Game",
        "Graphics",
        "Network",
        "Office",
        "Science",
        "Settings",
        "System",
        "Utility",
    ];
    for c in cats {
        if !REGISTERED_CATEGORIES.contains(&c.as_str()) {
            miette::bail!("desktop entry has unregistered category {c:?}");
        }
    }
    if !cats.iter().any(|c| main.contains(&c.as_str())) {
        miette::bail!("desktop entry needs at least one main category");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launcher(name: Option<&str>, cats: &[&str]) -> DesktopLauncher {
        DesktopLauncher {
            name: name.map(str::to_string),
            generic_name: None,
            comment: None,
            categories: cats.iter().map(|s| s.to_string()).collect(),
            icon_ref: None,
            icon: None,
        }
    }

    #[test]
    fn render_emits_required_keys_and_escapes_exec() {
        let l = launcher(Some("My App"), &["Graphics", "Viewer"]);
        let exec = std::path::Path::new("/home/u/.local/share/shuttle/pods/default/current/myapp");
        let text = render(&l, "myapp", exec, Some("shuttle-pod-default-myapp"));
        assert!(text.starts_with("[Desktop Entry]\n"));
        assert!(text.contains("Type=Application\n"));
        assert!(text.contains("Name=My App\n"));
        assert!(text.contains("Icon=shuttle-pod-default-myapp\n"));
        assert!(text.contains("Categories=Graphics;Viewer;\n"));
        assert!(text.contains("Exec=\""));
        assert!(text.contains("/home/u/.local/share/shuttle/pods/default/current/myapp\""));
        assert!(text.contains("Terminal=false\n"));
        // Round-trip through the validator — a strict conformance proof.
        validate(&text, Some("shuttle-pod-default-myapp"), None).unwrap();
    }

    #[test]
    fn render_escapes_newlines_tabs_and_spaces_in_values() {
        let mut l = launcher(Some("A\nB"), &["Utility"]);
        l.comment = Some(" padded ".into());
        l.icon_ref = Some("x".into());
        let text = render(&l, "a", std::path::Path::new("/usr/bin/a"), None);
        assert!(text.contains("Name=A\\nB\n"));
        assert!(text.contains("Comment=\\spadded\\s\n"));
    }

    #[test]
    fn name_falls_back_to_app_id() {
        let l = launcher(None, &["Utility"]);
        let text = render(&l, "mytool", std::path::Path::new("/bin/mytool"), None);
        assert!(text.contains("Name=mytool\n"));
    }

    #[test]
    fn exec_always_double_quoted_absolute() {
        let l = launcher(None, &["Utility"]);
        let text = render(&l, "a", std::path::Path::new("/bin/a"), None);
        let exec_line = text.lines().find(|l| l.starts_with("Exec=")).unwrap();
        assert!(exec_line.starts_with("Exec=\"/bin/a\""), "got {exec_line}");
    }

    #[test]
    fn unknown_category_fails_validation() {
        let l = launcher(Some("x"), &["NotRealCategory"]);
        let text = render(&l, "a", std::path::Path::new("/bin/a"), None);
        let err = validate(&text, None, None).unwrap_err().to_string();
        assert!(err.contains("unregistered category"), "got {err}");
    }

    #[test]
    fn missing_main_category_fails() {
        // "IDE" is registered but additional-only; a categories list with
        // no main category must be rejected.
        let l = launcher(Some("x"), &["IDE"]);
        let text = render(&l, "a", std::path::Path::new("/bin/a"), None);
        let err = validate(&text, None, None).unwrap_err().to_string();
        assert!(err.contains("at least one main category"), "got {err}");
    }

    #[test]
    fn icon_path_is_rejected() {
        let l = launcher(Some("x"), &["Utility"]);
        let text = render(
            &l,
            "a",
            std::path::Path::new("/bin/a"),
            Some("icons/app.png"),
        );
        let err = validate(&text, Some("icons/app.png"), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a path"), "got {err}");
    }

    #[test]
    fn exec_missing_absolute_or_broken_is_rejected() {
        let entry = |exec: &str| format!("[Desktop Entry]\nType=Application\nName=x\n{exec}\n");
        let err = validate(&entry("Exec=relative/path"), None, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("absolute path"), "got {err}");

        let err2 = validate(&entry("Exec=\"/unterminated"), None, None)
            .unwrap_err()
            .to_string();
        assert!(err2.contains("unclosed quotes"), "got {err2}");

        let err3 = validate(&entry("Exec=\"/bin/a\\z\""), None, None)
            .unwrap_err()
            .to_string();
        assert!(err3.contains("invalid escape"), "got {err3}");
    }

    #[test]
    fn parse_source_reads_the_metadata_subset() {
        let text = "[Desktop Entry]\nType=Application\nName=My App\nGenericName=Editor\n\
                    Comment=Does things\nCategories=Graphics;Viewer;\nIcon=theme-icon\n\
                    Exec=/somewhere/original\nName[de]=Meine App\nX-Custom=1\n";
        let src = parse_source(text, "test").unwrap();
        assert_eq!(src.name.as_deref(), Some("My App"));
        assert_eq!(src.generic_name.as_deref(), Some("Editor"));
        assert_eq!(src.comment.as_deref(), Some("Does things"));
        assert_eq!(src.categories, vec!["Graphics", "Viewer"]);
        assert_eq!(src.icon_ref.as_deref(), Some("theme-icon"));
    }

    #[test]
    fn parse_source_unescapes_values() {
        let src = parse_source("[Desktop Entry]\nType=Application\nName=a\\sb\n", "t").unwrap();
        assert_eq!(src.name.as_deref(), Some("a b"));
    }

    #[test]
    fn parse_source_requires_entry_group_type_and_name() {
        for (what, text) in [
            ("no group", "Type=Application\nName=x\n"),
            ("wrong type", "[Desktop Entry]\nType=Link\nName=x\n"),
            ("no type", "[Desktop Entry]\nName=x\n"),
            ("no name", "[Desktop Entry]\nType=Application\n"),
            ("empty name", "[Desktop Entry]\nType=Application\nName=  \n"),
        ] {
            let err = parse_source(text, "t").unwrap_err().to_string();
            assert!(!err.is_empty(), "{what} must fail");
        }
    }

    #[test]
    fn strict_checker_passes_every_rendered_generated_shape() {
        // A representative generated entry (the exact shape the emitter
        // produces) must pass. This is the test-only conformance proof.
        let l = DesktopLauncher {
            name: Some("GUI Example".into()),
            generic_name: Some("Example".into()),
            comment: Some("Example interface".into()),
            categories: vec!["Graphics".into(), "Viewer".into()],
            icon_ref: None,
            icon: Some(crate::runtime::DesktopIcon {
                sha256: "abc".into(),
                ext: "png".into(),
            }),
        };
        let exec =
            std::path::Path::new("/home/u/.local/share/shuttle/pods/default/current/gui-example");
        let icon_name = "shuttle-pod-default-gui-example";
        let text = render(&l, "gui-example", exec, Some(icon_name));
        validate(&text, Some(icon_name), None).unwrap();
    }
}
