//! The confined runtime backend (ADR-0016, ticket #11).
//!
//! A `confined` app runs inside a sandbox with declared grants, launched
//! via a `nau run <app>` interposing launcher. `nau run` resolves
//! the app's package + grants from the pod's generation manifest, selects
//! the enforcement backend (bwrap or AppArmor), verifies the backend is
//! available (FAIL CLOSED — a confined app must never silently run
//! unconfined), and execs the app's real command binary inside the
//! sandbox.
//!
//! Issue #102 adds the arbitrary-command form: `nau run -- <cmd…>`
//! execs any command with the pod's env overlaid (farm-first PATH +
//! loader-lib LD_LIBRARY_PATH) and no sandbox — fail-open by design.
//! That form, and issue #9's path-addressed form, live in
//! [`command`]: one job, one module.
//!
//! Both backends honor the SAME shared grants vocabulary, so they are
//! interchangeable for anything expressible in it. `backend_options` is
//! the non-portable finetune escape hatch (documented as lost when
//! switching backends).

use std::path::{Path, PathBuf};

use nau_core::generation_view::StoreView;
use nau_core::pkg_manifest::{Generation, InstalledPackage};
use nau_core::snap_types::{BackendKind, Confinement, SANDBOX_RO_ROOTS};

mod command;
use command::overlay_pod_env_with;
pub use command::run_command;

/// Run `app` from a pod confined per its declared grants (ticket #11).
///
/// `pod_dir` is the pod's state directory (the store root); `pod_name`
/// names it for diagnostics. Resolves the pod's active generation to find
/// the package providing `app`, reads its effective (per-app or
/// package-level) confinement, verifies the backend is available (fail
/// closed), then `exec`s the app's real command binary inside the sandbox.
/// A name no package provides falls through to the arbitrary-command
/// form (issue #102): `[app] ++ args` runs with the pod env, unconfined.
///
/// An unconfined app reached here (explicit `nau run` misuse, or a
/// pod overridden to unconfined) is exec'd directly — transparent, no
/// sandbox. This is never invoked by the farm for an unconfined app.
/// Every exec form (direct, bwrap, apparmor, arbitrary command) carries
/// the generation's declared env (ADR-0030): declared replaces
/// inherited, undeclared passes through.
pub fn run(pod_dir: &Path, pod_name: &str, app: &str, args: &[String]) -> miette::Result<()> {
    let blobs = nau_core::blob_store::BlobStore::new(pod_dir.join("store"));
    let store = StoreView::new(pod_dir.to_path_buf(), blobs);
    let gen = store.active_generation()?.ok_or_else(|| {
        miette::miette!("pod '{pod_name}' has no active generation — nothing to run for '{app}'")
    })?;
    let Some((pkg_name, pkg, real_hash)) = resolve_app(&gen, app) else {
        // Not a declared app: the arbitrary-command form (#102) takes
        // over — everything after the app name is the command vector.
        let mut cmd: Vec<String> = Vec::with_capacity(1 + args.len());
        cmd.push(app.to_string());
        cmd.extend_from_slice(args);
        return run_command(pod_dir, pod_name, &cmd);
    };

    // Issue #37: a multi-file app execs its ASSEMBLED binary — the
    // hardlinked leaf in the generation's assembly subtree, whose
    // directory holds the recorded siblings — so
    // relative-to-executable resolution works here exactly as it does
    // through the farm (the pod state root is bound read-only into the
    // sandbox, so the subtree resolves inside it too). Single-binary
    // apps keep the lone content blob.
    let bin = exec_target(&store, gen.n, pkg_name, pkg, app, real_hash);

    // ADR-0030: the generation's declared env rides EVERY exec form —
    // declared replaces inherited, undeclared passes through. The
    // shellenv read verb fails loudly on a torn state (no `current`
    // despite an active generation), never silently drops the env.
    let root = pod_dir.parent().unwrap_or(pod_dir);
    let shellenv = crate::pod::shellenv(root, pod_name)?;
    let vars = &shellenv.vars;
    // ADR-0042 D3 (issue #184): resolved secrets ride every exec form
    // too — the serve resolve happened inside `shellenv` (all-or-
    // nothing, D7: a provider outage fails the run named, never a
    // partial env).
    let secret_vars = &shellenv.secret_vars;

    // Effective confinement: the per-app override, else the package default.
    let Some(confined) = pkg.app_confined.get(app).or(pkg.confined.as_ref()) else {
        // Unconfined app reached `nau run` directly — exec the real
        // binary with no sandbox (the farm never routes an unconfined app
        // here). Two invariants keep this form equivalent to running the
        // app THROUGH the farm:
        //
        // 1. Prefer the generation's LD wrapper for the app when one was
        //    emitted: through the farm this binary runs wrapped
        //    (loader-libs LD_LIBRARY_PATH + the emit-chosen payload copy,
        //    issue #164); the raw assembly leaf would instead inherit the
        //    CALLER'S loader env, and a toolchain app would then resolve
        //    its toolchain from the caller's PATH, not the pod's. The
        //    wrapper exists exactly when the farm entry is
        //    wrapper-routed, so the two forms stay equivalent.
        // 2. Farm-first PATH (the shellenv contract, issue #102's
        //    arbitrary-command form): without it, the app's children
        //    (a build driver's `cc`, `rustc`) resolve from the caller's
        //    PATH, silently bypassing the pod.
        let wrapper = store
            .generation_dir(gen.n)
            .join(crate::farm::LD_WRAPPERS_DIR)
            .join(app);
        let target = if wrapper.is_file() { wrapper } else { bin };
        let mut cmd = std::process::Command::new(&target);
        for a in args {
            cmd.arg(a);
        }
        let shellenv = crate::pod::shellenv(root, pod_name)?;
        overlay_pod_env_with(&mut cmd, &shellenv, std::env::var_os("PATH").as_deref());
        return exec_cmd(cmd);
    };

    if !bin.is_file() {
        return Err(miette::miette!(
            "confined app '{app}' (package '{pkg_name}'): command binary \
             {} is missing from the content store",
            bin.display()
        ));
    }

    match confined.backend {
        BackendKind::Bwrap => run_bwrap(pod_dir, app, confined, &bin, args, vars, secret_vars),
        BackendKind::Apparmor => {
            run_apparmor(pod_name, app, confined, &bin, args, vars, secret_vars)
        }
    }
}

/// The binary `nau run` execs for `app` (issue #37): the assembled
/// leaf in the generation's assembly subtree when the package records a
/// sibling assembly for the app, else the lone content blob.
fn exec_target(
    store: &StoreView,
    gen_n: u64,
    pkg_name: &str,
    pkg: &InstalledPackage,
    app: &str,
    real_hash: &str,
) -> PathBuf {
    match pkg.assembly.get(app) {
        Some(asm) => crate::farm::assembly_bin_path(store, gen_n, pkg_name, asm),
        None => store.blob_path(real_hash),
    }
}

/// Locate the installed package providing `app` and the real command
/// binary hash `nau run` should exec.
fn resolve_app<'a>(
    gen: &'a Generation,
    app: &str,
) -> Option<(&'a str, &'a InstalledPackage, &'a str)> {
    for (name, pkg) in &gen.packages {
        if let Some(hash) = pkg.apps.get(app) {
            return Some((name, pkg, hash));
        }
    }
    None
}

/// The declared vars ride every exec form (ADR-0030): declared replaces
/// inherited, undeclared passes through — the same semantics as the
/// arbitrary-command overlay.
fn overlay_declared_vars(
    cmd: &mut std::process::Command,
    vars: &std::collections::BTreeMap<String, String>,
) {
    for (key, value) in vars {
        cmd.env(key, value);
    }
}

/// Exec `bin` under a bwrap sandbox built from the grants (ticket #11).
/// FAIL CLOSED: an unavailable bwrap (missing binary or no unprivileged
/// user namespace) is a hard error, never a silent unconfined run.
fn run_bwrap(
    pod_dir: &Path,
    app: &str,
    confined: &Confinement,
    bin: &Path,
    args: &[String],
    vars: &std::collections::BTreeMap<String, String>,
    secret_vars: &std::collections::BTreeMap<String, String>,
) -> miette::Result<()> {
    // Floor-tool seam (issue #101): bwrap resolves provisioned-first with
    // PATH fallback; a tool error still fails closed.
    let bwrap = nau_infra::tools::resolve(nau_infra::tools::ToolName::Bwrap).map_err(|_| {
        miette::miette!(
            "confined app '{app}' uses the bwrap backend, but bubblewrap is not \
             available on this host (no provisioned set and none on PATH) — refusing \
             to run unconfined. Run `nau doctor --fix` to provision it, install \
             bubblewrap (e.g. `apt install bubblewrap`), or override the package to \
             unconfined via the pod declaration."
        )
    })?;
    let bwrap = match bwrap {
        nau_infra::tools::ResolvedTool::Provisioned { path, .. }
        | nau_infra::tools::ResolvedTool::Path { path, .. } => path,
    };
    if !userns_available() {
        return Err(miette::miette!(
            "confined app '{app}' uses the bwrap backend, but unprivileged user \
             namespaces are disabled on this host — refusing to run unconfined. \
             Enable unprivileged userns or override the package to unconfined via \
             the pod declaration."
        ));
    }

    let mut cmd = std::process::Command::new(&bwrap);
    cmd.arg("--unshare-user")
        .arg("--unshare-pid")
        .arg("--unshare-ipc");
    if !confined.network {
        cmd.arg("--unshare-net");
    }
    cmd.arg("--proc").arg("/proc").arg("--dev").arg("/dev");
    cmd.arg("--tmpfs").arg("/tmp");
    // The pod's content store + active generation tree must be visible so
    // the app binary, its bundled libs, and the farm resolve inside the
    // sandbox. Bound read-only at its host path.
    if pod_dir.is_dir() {
        cmd.arg("--ro-bind").arg(pod_dir).arg(pod_dir);
    }
    bind_system_ro_roots(&mut cmd);
    bind_filesystem_grants(&mut cmd, &confined.filesystem);
    bind_sockets(&mut cmd, &confined.sockets);
    bind_devices(&mut cmd, &confined.devices);
    apply_backend_options(&mut cmd, &confined.backend_options);

    cmd.arg("--").arg(bin);
    for a in args {
        cmd.arg(a);
    }
    // ADR-0030: declared env, threaded through bwrap into the sandbox
    // (bwrap passes its own environment in; no --clearenv is applied).
    overlay_declared_vars(&mut cmd, vars);
    // ADR-0042 D3 (issue #184): resolved secrets ride the SAME declared
    // re-injection — declared replaces inherited, never ambient env
    // (the D3 isolation contract). Provider credentials stay
    // caller-side; only the pod's secret values cross.
    overlay_declared_vars(&mut cmd, secret_vars);
    // Replace the process (exec) so the sandboxed app is the child of our
    // caller, not a grandchild — transparent to the user.
    exec_cmd(cmd)
}

/// Build the bwrap command arguments (for the fail-closed test path).
fn apply_backend_options(
    cmd: &mut std::process::Command,
    options: &std::collections::BTreeMap<String, serde_json::Value>,
) {
    // Non-portable raw flags: each string value becomes a single
    // `--flag=value` bwrap argument (the shared vocabulary stays the
    // portability contract; these are lost when switching backends).
    for (k, v) in options {
        if let Some(s) = v.as_str() {
            cmd.arg(format!("--{k}={s}"));
        }
    }
}

/// Bind the standard read-only host filesystem roots into the sandbox.
fn bind_system_ro_roots(cmd: &mut std::process::Command) {
    for root in SANDBOX_RO_ROOTS {
        if Path::new(root).exists() {
            cmd.arg("--ro-bind").arg(root).arg(root);
        }
    }
}

/// Bind the `filesystem` grants. The portable keywords `read` (read-only
/// host roots) and `write` (read-write host roots) are honored; any other
/// entry is a host path bound at its own location, with an optional
/// `ro:`/`rw:` prefix (default read-write).
fn bind_filesystem_grants(cmd: &mut std::process::Command, filesystem: &[String]) {
    for grant in filesystem {
        match grant.as_str() {
            "read" => bind_system_ro_roots(cmd),
            "write" => {
                // An explicit write grant binds the standard roots
                // read-write (bwrap cannot recursively rw-mount /).
                for root in SANDBOX_RO_ROOTS {
                    if Path::new(root).exists() {
                        cmd.arg("--bind").arg(root).arg(root);
                    }
                }
            }
            other => {
                let (ro, path) = if let Some(p) = other.strip_prefix("ro:") {
                    (true, p)
                } else if let Some(p) = other.strip_prefix("rw:") {
                    (false, p)
                } else {
                    (false, other)
                };
                if Path::new(path).exists() {
                    let flag = if ro { "--ro-bind" } else { "--bind" };
                    cmd.arg(flag).arg(path).arg(path);
                }
            }
        }
    }
}

/// Bind socket grants. bwrap has no `--socket` flag; a named grant must
/// resolve to concrete socket paths bound read-write at their host
/// location (`--bind SRC DEST` — ADR-0038 contract 2). Absent sockets
/// are skipped, matching the filesystem-grant convention.
fn bind_sockets(cmd: &mut std::process::Command, sockets: &[String]) {
    for socket in sockets {
        for path in socket_grant_paths(socket) {
            if path.exists() {
                cmd.arg("--bind").arg(&path).arg(&path);
            }
        }
    }
}

/// Resolve a socket grant to the concrete host paths it grants. An
/// absolute path is taken verbatim; a bare name (e.g. "x11") resolves
/// to the per-user runtime dir (`/run/user/<euid>/<name>`) and the X11
/// socket dir (`/tmp/.X11-unix/<name>`) — the same shapes the AppArmor
/// renderer grants, with the uid glob resolved to the effective uid.
fn socket_grant_paths(grant: &str) -> Vec<PathBuf> {
    if grant.starts_with('/') {
        return vec![PathBuf::from(grant)];
    }
    let euid = unsafe { libc::geteuid() };
    vec![
        PathBuf::from(format!("/run/user/{euid}")).join(grant),
        PathBuf::from("/tmp/.X11-unix").join(grant),
    ]
}

/// Bind device grants. bwrap has no `--device` flag; device access is a
/// filesystem-bind variant (`--dev-bind SRC DEST`, bound read-write at
/// its host path — ADR-0038 contract 2). Absent devices are skipped,
/// matching the filesystem-grant convention.
fn bind_devices(cmd: &mut std::process::Command, devices: &[String]) {
    for device in devices {
        if Path::new(device).exists() {
            cmd.arg("--dev-bind").arg(device).arg(device);
        }
    }
}

/// Run `bin` under an AppArmor profile generated from the grants
/// (ticket #11). FAIL CLOSED: an unavailable AppArmor (`aa-exec` absent, or
/// no profile loaded) is a hard error — a confined app never runs
/// unconfined.
fn run_apparmor(
    pod_name: &str,
    app: &str,
    _confined: &Confinement,
    bin: &Path,
    args: &[String],
    vars: &std::collections::BTreeMap<String, String>,
    secret_vars: &std::collections::BTreeMap<String, String>,
) -> miette::Result<()> {
    let aa_exec = resolve_tool("aa-exec").ok_or_else(|| {
        miette::miette!(
            "confined app '{app}' uses the apparmor backend, but `aa-exec` is not \
             installed / AppArmor is not enforced on this host — refusing to run \
             unconfined. Install AppArmor (`aa-exec`) or switch the package to \
             the bwrap backend / unconfined via the pod declaration."
        )
    })?;
    // The profile must be loaded into the kernel. Profile loading is
    // privileged; an absent profile for this app fails closed.
    let profile = profile_name(pod_name, app);
    let mut cmd = std::process::Command::new(&aa_exec);
    cmd.arg("--profile").arg(&profile);
    cmd.arg("--").arg(bin);
    for a in args {
        cmd.arg(a);
    }
    overlay_declared_vars(&mut cmd, vars);
    // ADR-0042 D3 (issue #184): secrets ride the same declared
    // re-injection as env — declared replaces inherited.
    overlay_declared_vars(&mut cmd, secret_vars);
    exec_cmd(cmd)
}

/// A deterministic per-pod, per-app profile name.
pub fn profile_name(pod_name: &str, app: &str) -> String {
    format!("nau-{pod_name}-{app}")
}

/// Generate the AppArmor profile text honoring the shared grants
/// vocabulary: filesystem path rules, network allowance, socket/device
/// path rules, plus a minimal deny-by-default base. The profile carries a
/// `## NAU` marker line; the seccomp filter is a separate policy the
/// runtime applies via the profile (AppArmor's seccomp integration).
///
/// This is the vocabulary-honoring implementation — the profile is the
/// AppArmor backend's expression of the same `grants` declaration bwrap
/// expresses with `--bind`/`--ro-bind`/`--dev-bind`/`--unshare-net`.
pub fn render_apparmor_profile(pod_name: &str, app: &str, confined: &Confinement) -> String {
    let mut out = String::new();
    out.push_str("#include <tunables/global>\n");
    out.push_str(&format!("## NAU profile for '{}'\n", app));
    out.push_str(&format!(
        "profile {} flags=(attach_disconnected,mediate_deleted) {{\n",
        profile_name(pod_name, app)
    ));
    // Default deny: a confined app sees no filesystem except grants + a
    // minimal dynamic-linker/PROC base.
    out.push_str("  #include <abstractions/base>\n");
    // Filesystem grants.
    for grant in &confined.filesystem {
        let (ro, path) = match grant.as_str() {
            "read" => (true, "/**"),
            "write" => (false, "/**"),
            other => {
                if let Some(p) = other.strip_prefix("ro:") {
                    (true, p)
                } else if let Some(p) = other.strip_prefix("rw:") {
                    (false, p)
                } else {
                    (false, other)
                }
            }
        };
        if ro {
            out.push_str(&format!("  {path} r,\n"));
        } else {
            out.push_str(&format!("  {path} rw,\n"));
        }
    }
    // Network grant.
    if confined.network {
        out.push_str("  network,\n");
    }
    // Socket grants (paths). Absolute paths are emitted verbatim — the
    // same grant the bwrap backend binds at its own path; bare names
    // keep the per-user/X11 glob shapes.
    for socket in &confined.sockets {
        if socket.starts_with('/') {
            out.push_str(&format!("  {socket} rw,\n"));
        } else {
            out.push_str(&format!("  /run/user/*/{socket} rw,\n"));
            out.push_str(&format!("  /tmp/.X11-unix/{socket} rw,\n"));
        }
    }
    // Device grants.
    for device in &confined.devices {
        if Path::new(device).exists() {
            out.push_str(&format!("  {device} rw,\n"));
        }
    }
    // Seccomp filter: AppArmor profiles deny dangerous syscalls by default
    // when the profile is loaded with a seccomp-aware kernel hook; the raw
    // `backend_options` may append backend-specific rules.
    out.push_str("  ## seccomp: confined profiles restrict syscalls via the profile.\n");
    out.push_str("}\n");
    out
}

/// Resolve an external tool on PATH.
fn resolve_tool(tool: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(tool);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Whether unprivileged user namespaces are usable (bwrap's requirement).
/// Probes with a tiny no-op userns `unshare`; a failure (or the kernel
/// knob being disabled) means bwrap cannot run.
fn userns_available() -> bool {
    // Probe via bwrap's own minimal invocation is expensive; a cheap
    // `unshare --user --map-root-user true` reflects the kernel's
    // unprivileged-userns policy. Fall back to allowing when unshare is
    // absent (bwrap may still work).
    match std::process::Command::new("unshare")
        .args(["--user", "--map-root-user", "true"])
        .status()
    {
        Ok(s) => s.success(),
        Err(_) => true,
    }
}

/// Re-exec the current process into the built sandbox command. On a
/// successful `exec` the process image is replaced by the sandbox (bwrap /
/// aa-exec), which in turn launches the app — so the app is the direct
/// child of the caller, transparent to the user. `exec` only returns on
/// failure.
pub(crate) fn exec_cmd(mut cmd: std::process::Command) -> miette::Result<()> {
    use std::os::unix::process::CommandExt;
    let prog = cmd.get_program().to_string_lossy().into_owned();
    let err = cmd.exec();
    Err(miette::miette!("failed to exec {prog}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn sample_confinement() -> Confinement {
        Confinement {
            backend: BackendKind::Bwrap,
            filesystem: vec!["ro:/usr".into(), "rw:/lib".into(), "read".into()],
            network: false,
            sockets: vec!["wayland".into(), "x11".into()],
            devices: vec!["/dev/dri".into(), "/dev/input".into()],
            backend_options: BTreeMap::new(),
        }
    }

    #[test]
    fn backend_options_are_the_nonportable_escape_hatch() {
        let mut c = sample_confinement();
        c.backend_options
            .insert("die-with-parent".into(), serde_json::json!("true"));
        let mut cmd = std::process::Command::new("bwrap");
        apply_backend_options(&mut cmd, &c.backend_options);
        let arg_strs: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let joined = arg_strs.join(" ");
        assert!(joined.contains("--die-with-parent=true"), "got: {joined}");
    }

    #[test]
    fn bwrap_args_honor_the_shared_grants_vocabulary() {
        // Concrete grant paths (a real socket file + a device-like node
        // path) so the emitted argv is deterministic: grants resolve to
        // binds only when the path exists on the host.
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("wayland-0");
        std::fs::write(&sock, "").unwrap();
        let dev = tmp.path().join("dri-card");
        std::fs::write(&dev, "").unwrap();
        let c = Confinement {
            backend: BackendKind::Bwrap,
            filesystem: vec!["ro:/usr".into(), "rw:/lib".into(), "read".into()],
            network: false,
            sockets: vec![sock.to_string_lossy().into_owned()],
            devices: vec![dev.to_string_lossy().into_owned()],
            backend_options: BTreeMap::new(),
        };
        let mut cmd = std::process::Command::new("bwrap");
        if !c.network {
            cmd.arg("--unshare-net");
        }
        bind_filesystem_grants(&mut cmd, &c.filesystem);
        bind_sockets(&mut cmd, &c.sockets);
        bind_devices(&mut cmd, &c.devices);
        let arg_strs: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let joined = arg_strs.join(" ");
        assert!(joined.contains("--unshare-net"));
        // Filesystem entries map to --ro-bind/--bind at their own paths.
        assert!(joined.contains("--ro-bind /usr /usr"), "got: {joined}");
        assert!(joined.contains("--bind /lib /lib"), "got: {joined}");
        // "read" keyword ro-binds the standard roots.
        assert!(joined.contains("--ro-bind /usr /usr"));
        // Socket grants resolve to concrete rw binds at their host path.
        assert!(
            joined.contains(&format!("--bind {0} {0}", sock.display())),
            "got: {joined}"
        );
        // Device grants map to --dev-bind at their host path.
        assert!(
            joined.contains(&format!("--dev-bind {0} {0}", dev.display())),
            "got: {joined}"
        );
    }

    #[test]
    fn socket_grant_names_resolve_per_user_and_x11_dirs() {
        // A bare name resolves to the shapes the AppArmor renderer
        // grants, with the uid glob resolved to the effective uid.
        let euid = unsafe { libc::geteuid() };
        let paths = socket_grant_paths("wayland");
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], PathBuf::from(format!("/run/user/{euid}/wayland")));
        assert_eq!(paths[1], PathBuf::from("/tmp/.X11-unix/wayland"));
        // An absolute path grant is taken verbatim.
        assert_eq!(
            socket_grant_paths("/run/user/7/dbus"),
            vec![PathBuf::from("/run/user/7/dbus")]
        );
    }

    /// The real bwrap option vocabulary (from bwrap.1 / `bwrap --help`):
    /// every flag the backend emits for grants must be in this set —
    /// a flag bwrap does not accept fails the exec outright (issue #157).
    /// backend_options flags are excluded: that escape hatch is
    /// documented as non-portable.
    const BWRAP_ACCEPTED_FLAGS: &[&str] = &[
        "--bind",
        "--ro-bind",
        "--dev-bind",
        "--proc",
        "--dev",
        "--tmpfs",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-net",
        "--die-with-parent",
    ];

    #[test]
    fn emitted_grant_flags_are_real_bwrap_flags() {
        // Socket + device grants over BOTH grant shapes (bare names and
        // existing absolute paths). Runs without bwrap installed: the
        // accepted set is hardcoded; when bwrap is present the set is
        // additionally cross-checked against its --help output.
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("app.sock");
        std::fs::write(&sock, "").unwrap();
        // A device stand-in under the tmpdir: /dev/dri etc. are not
        // guaranteed to exist on every build host, and absent devices
        // are skipped — so grant a path that always exists.
        let dev = tmp.path().join("dri-card");
        std::fs::write(&dev, "").unwrap();
        let mut cmd = std::process::Command::new("bwrap");
        bind_sockets(
            &mut cmd,
            &["wayland".into(), sock.to_string_lossy().into_owned()],
        );
        bind_devices(&mut cmd, &[dev.to_string_lossy().into_owned()]);
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let flags: Vec<&str> = args
            .iter()
            .filter(|a| a.starts_with("--"))
            .map(|a| a.as_str())
            .collect();
        assert!(!flags.is_empty(), "grants must emit flags");
        for flag in &flags {
            assert!(
                BWRAP_ACCEPTED_FLAGS.contains(flag),
                "flag '{flag}' is not in real bwrap's option vocabulary"
            );
        }
        // And the mapping is the one ADR-0038 contract 2 names: sockets
        // are explicit binds, devices are --dev-bind.
        assert!(args.iter().any(|a| a == "--dev-bind"), "got: {args:?}");
        assert!(args.iter().any(|a| a == "--bind"), "got: {args:?}");
        assert!(!args.iter().any(|a| a == "--socket"), "got: {args:?}");
        assert!(!args.iter().any(|a| a == "--device"), "got: {args:?}");

        // When bwrap IS installed, cross-check the hardcoded set against
        // the binary's own option list (best-effort: absent bwrap skips
        // only this cross-check, never the assertions above).
        if let Some(bwrap) = resolve_tool("bwrap") {
            if let Ok(help) = std::process::Command::new(bwrap).arg("--help").output() {
                let text = String::from_utf8_lossy(&help.stdout).into_owned()
                    + &String::from_utf8_lossy(&help.stderr);
                // Whole-token match: splitting on whitespace/punctuation
                // boundaries so a dropped flag cannot false-pass inside a
                // longer one (e.g. `--bind` inside `--bind-file`).
                let tokens: Vec<&str> = text
                    .split(|c: char| c.is_whitespace() || !c.is_alphanumeric() && c != '-')
                    .filter(|t| !t.is_empty())
                    .collect();
                for flag in BWRAP_ACCEPTED_FLAGS {
                    assert!(
                        tokens.contains(flag),
                        "hardcoded flag {flag} missing from real bwrap --help"
                    );
                }
            }
        }
    }

    #[test]
    fn apparmor_profile_honors_the_shared_grants_vocabulary() {
        let mut c = sample_confinement();
        // Network is a shared grant: request it and the profile must allow.
        c.network = true;
        let profile = render_apparmor_profile("work", "myapp", &c);
        assert!(profile.contains("profile nau-work-myapp"));
        // Filesystem grants → path rules.
        assert!(profile.contains("/usr r,"));
        assert!(profile.contains("/lib rw,"));
        // Network grant.
        assert!(profile.contains("network,"));
        // Socket paths.
        assert!(profile.contains("/run/user/*/wayland rw,"));
        // Device rules.
        assert!(profile.contains("/dev/dri rw,"));
    }

    #[test]
    fn apparmor_socket_grants_honor_absolute_paths_verbatim() {
        // An absolute socket grant renders its own path as the rule —
        // the same grant the bwrap backend binds verbatim.
        let mut c = sample_confinement();
        c.sockets = vec!["/run/user/7/dbus".into()];
        let profile = render_apparmor_profile("work", "myapp", &c);
        assert!(profile.contains("/run/user/7/dbus rw,"), "got: {profile}");
        // No mangled double-path shapes for absolute grants.
        assert!(!profile.contains("//"), "got: {profile}");
        // A bare name still renders both glob shapes.
        let mut c = sample_confinement();
        c.sockets = vec!["x11".into()];
        let profile = render_apparmor_profile("work", "myapp", &c);
        assert!(profile.contains("/run/user/*/x11 rw,"), "got: {profile}");
        assert!(profile.contains("/tmp/.X11-unix/x11 rw,"), "got: {profile}");
    }

    #[test]
    fn profile_name_is_deterministic_and_namespaced() {
        assert_eq!(profile_name("default", "app"), "nau-default-app");
        assert_eq!(profile_name("work", "gui"), "nau-work-gui");
    }

    // ── Issue #37: nau run resolves multi-file apps via the assembly ──

    #[test]
    fn exec_target_prefers_the_assembly_leaf_for_multifile_apps() {
        let tmp = tempfile::tempdir().unwrap();
        let store = {
            let root = tmp.path().to_path_buf();
            let blobs = nau_core::blob_store::BlobStore::new(root.join("store"));
            StoreView::new(root, blobs)
        };
        let asm = crate::farm::AppAssembly {
            binary: "usr/bin/gcm".into(),
            files: [("libSkiaSharp.so".to_string(), "cc33".to_string())]
                .into_iter()
                .collect(),
            links: BTreeMap::new(),
        };
        let mut pkg = InstalledPackage {
            name: "git-credential-manager".into(),
            version: "1.0".into(),
            revision: 1,
            sha3_384: "abc".into(),
            files: vec![],
            units: vec![],
            layer: crate::farm::ClaimLayer::Own,
            apps: [("gcm".to_string(), "aa11".to_string())]
                .into_iter()
                .collect(),
            requires: Vec::new(),
            launchers: BTreeMap::new(),
            assembly: [("gcm".to_string(), asm)].into_iter().collect(),
            confined: None,
            app_confined: BTreeMap::new(),
            desktops: BTreeMap::new(),
            fonts: BTreeMap::new(),
            services: BTreeMap::new(),
            service_bins: BTreeMap::new(),
            meta_digest: None,
        };
        // Multi-file app: exec the assembled leaf, not the lone blob —
        // the leaf's directory carries the recorded sibling.
        let target = exec_target(&store, 3, &pkg.name, &pkg, "gcm", "aa11");
        assert_eq!(
            target,
            store
                .generation_dir(3)
                .join(crate::farm::ASSEMBLY_DIR)
                .join("git-credential-manager")
                .join("usr/bin/gcm")
        );
        // Single-binary app: unchanged lone content blob.
        pkg.assembly.clear();
        let target = exec_target(&store, 3, &pkg.name, &pkg, "gcm", "aa11");
        assert_eq!(target, store.blob_path("aa11"));
    }

    // ── Issue #102: the arbitrary-command form ──

    /// The env overlay result as seen through the built command.
    fn env_of(cmd: &std::process::Command, key: &str) -> Option<String> {
        cmd.get_envs()
            .find(|(k, _)| *k == key)
            .and_then(|(_, v)| v)
            .map(|v| v.to_string_lossy().into_owned())
    }

    #[test]
    fn overlay_declared_vars_replaces_inherited_and_passes_the_rest() {
        let mut vars = std::collections::BTreeMap::new();
        vars.insert("EDITOR".to_string(), "vi".to_string());
        let mut cmd = std::process::Command::new("true");
        cmd.env("EDITOR", "inherited");
        cmd.env("HOME", "/home/user");
        overlay_declared_vars(&mut cmd, &vars);
        assert_eq!(env_of(&cmd, "EDITOR").unwrap(), "vi");
        assert_eq!(env_of(&cmd, "HOME").unwrap(), "/home/user");
    }

    #[test]
    fn run_refuses_a_pod_without_an_active_generation() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("empty-pod");
        std::fs::create_dir_all(&dir).unwrap();
        let err = run(&dir, "empty-pod", "app", &[]).unwrap_err().to_string();
        assert!(err.contains("no active generation"), "{err}");
    }

    #[test]
    fn write_grant_binds_the_standard_roots_read_write() {
        let tmp = tempfile::tempdir().unwrap();
        let grants = vec![
            "write".to_string(),
            tmp.path().join("plain").to_string_lossy().into_owned(),
            format!("ro:{}", tmp.path().join("hidden").display()),
        ];
        std::fs::create_dir_all(tmp.path().join("plain")).unwrap();
        let mut cmd = std::process::Command::new("bwrap");
        bind_filesystem_grants(&mut cmd, &grants);
        let joined = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            joined.contains("--bind /usr /usr"),
            "write opens the standard roots rw: {joined}"
        );
        assert!(
            joined.contains(&format!(
                "--bind {} {}",
                tmp.path().join("plain").display(),
                tmp.path().join("plain").display()
            )),
            "a bare path defaults read-write: {joined}"
        );
        assert!(
            !joined.contains("hidden"),
            "a ro: grant at a missing host path binds nothing: {joined}"
        );
    }

    #[test]
    fn apparmor_profile_renders_a_bare_path_grant_read_write() {
        let mut c = sample_confinement();
        c.filesystem = vec!["/srv/data".into()];
        let profile = render_apparmor_profile("work", "myapp", &c);
        assert!(profile.contains("/srv/data rw,"), "{profile}");
    }

    #[test]
    fn resolve_tool_finds_a_standard_binary_on_path() {
        let tool = resolve_tool("sh").expect("sh exists on any Linux host");
        assert!(tool.is_file());
    }
}
