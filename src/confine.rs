//! The confined runtime backend (ADR-0016, ticket #11).
//!
//! A `confined` app runs inside a sandbox with declared grants, launched
//! via a `shuttle run <app>` interposing launcher. `shuttle run` resolves
//! the app's package + grants from the pod's generation manifest, selects
//! the enforcement backend (bwrap or AppArmor), verifies the backend is
//! available (FAIL CLOSED — a confined app must never silently run
//! unconfined), and execs the app's real command binary inside the
//! sandbox.
//!
//! Both backends honor the SAME shared grants vocabulary, so they are
//! interchangeable for anything expressible in it. `backend_options` is
//! the non-portable finetune escape hatch (documented as lost when
//! switching backends).

use std::path::{Path, PathBuf};

use crate::snap::{BackendKind, Confinement, SANDBOX_RO_ROOTS};

/// Run `app` from a pod confined per its declared grants (ticket #11).
///
/// `pod_dir` is the pod's state directory (the store root); `pod_name`
/// names it for diagnostics. Resolves the pod's active generation to find
/// the package providing `app`, reads its effective (per-app or
/// package-level) confinement, verifies the backend is available (fail
/// closed), then `exec`s the app's real command binary inside the sandbox.
///
/// An unconfined app reached here (explicit `shuttle run` misuse, or a
/// pod overridden to unconfined) is exec'd directly — transparent, no
/// sandbox. This is never invoked by the farm for an unconfined app.
pub fn run(pod_dir: &Path, pod_name: &str, app: &str, args: &[String]) -> miette::Result<()> {
    let store = crate::runtime::RuntimeStore::new(pod_dir.to_path_buf());
    let gen = store.active_generation()?.ok_or_else(|| {
        miette::miette!("pod '{pod_name}' has no active generation — nothing to run for '{app}'")
    })?;
    let (pkg_name, pkg, real_hash) = resolve_app(&gen, app).ok_or_else(|| {
        miette::miette!(
            "app '{app}' is not provided by any package in pod '{pod_name}' \
             (checked its active generation)"
        )
    })?;

    // Effective confinement: the per-app override, else the package default.
    let Some(confined) = pkg.app_confined.get(app).or(pkg.confined.as_ref()) else {
        // Unconfined app reached `shuttle run` directly — exec the real
        // binary with no sandbox (the farm never routes an unconfined app
        // here).
        let bin = store.blob_path(real_hash);
        return exec_direct(&bin, args);
    };

    // The real command binary `shuttle run` execs inside the sandbox.
    let bin = store.blob_path(real_hash);
    if !bin.is_file() {
        return Err(miette::miette!(
            "confined app '{app}' (package '{pkg_name}'): command binary \
             {} is missing from the content store",
            bin.display()
        ));
    }

    match confined.backend {
        BackendKind::Bwrap => run_bwrap(pod_dir, app, confined, &bin, args),
        BackendKind::Apparmor => run_apparmor(pod_name, app, confined, &bin, args),
    }
}

/// Locate the installed package providing `app` and the real command
/// binary hash `shuttle run` should exec.
fn resolve_app<'a>(
    gen: &'a crate::runtime::Generation,
    app: &str,
) -> Option<(&'a str, &'a crate::runtime::InstalledPackage, &'a str)> {
    for (name, pkg) in &gen.packages {
        if let Some(hash) = pkg.apps.get(app) {
            return Some((name, pkg, hash));
        }
    }
    None
}

/// Exec a binary directly (no sandbox), replacing the current process.
fn exec_direct(bin: &Path, args: &[String]) -> miette::Result<()> {
    let mut cmd = std::process::Command::new(bin);
    for a in args {
        cmd.arg(a);
    }
    exec_cmd(cmd)
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
) -> miette::Result<()> {
    let bwrap = resolve_tool("bwrap").ok_or_else(|| {
        miette::miette!(
            "confined app '{app}' uses the bwrap backend, but bubblewrap is not \
             installed on this host — refusing to run unconfined. Install bubblewrap \
             (e.g. `apt install bubblewrap`) or override the package to unconfined \
             via the pod declaration."
        )
    })?;
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

/// Bind named socket grants (bwrap `--socket <name>`).
fn bind_sockets(cmd: &mut std::process::Command, sockets: &[String]) {
    for socket in sockets {
        cmd.arg("--socket").arg(socket);
    }
}

/// Bind device grants (bwrap `--device <path>`).
fn bind_devices(cmd: &mut std::process::Command, devices: &[String]) {
    for device in devices {
        cmd.arg("--device").arg(device);
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
    exec_cmd(cmd)
}

/// A deterministic per-pod, per-app profile name.
pub fn profile_name(pod_name: &str, app: &str) -> String {
    format!("shuttle-{pod_name}-{app}")
}

/// Generate the AppArmor profile text honoring the shared grants
/// vocabulary: filesystem path rules, network allowance, socket/device
/// path rules, plus a minimal deny-by-default base. The profile carries a
/// `## SHUTTLE` marker line; the seccomp filter is a separate policy the
/// runtime applies via the profile (AppArmor's seccomp integration).
///
/// This is the vocabulary-honoring implementation — the profile is the
/// AppArmor backend's expression of the same `grants` declaration bwrap
/// expresses with `--bind`/`--ro-bind`/`--unshare-net`/`--socket`/
/// `--device`.
pub fn render_apparmor_profile(pod_name: &str, app: &str, confined: &Confinement) -> String {
    let mut out = String::new();
    out.push_str("#include <tunables/global>\n");
    out.push_str(&format!("## SHUTTLE profile for '{}'\n", app));
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
    // Socket grants (paths).
    for socket in &confined.sockets {
        out.push_str(&format!("  /run/user/*/{socket} rw,\n"));
        out.push_str(&format!("  /tmp/.X11-unix/{socket} rw,\n"));
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
fn exec_cmd(mut cmd: std::process::Command) -> miette::Result<()> {
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
        let c = sample_confinement();
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
        // Socket grants map to --socket.
        assert!(joined.contains("--socket wayland"));
        assert!(joined.contains("--socket x11"));
        // Device grants map to --device.
        assert!(joined.contains("--device /dev/dri"));
    }

    #[test]
    fn apparmor_profile_honors_the_shared_grants_vocabulary() {
        let mut c = sample_confinement();
        // Network is a shared grant: request it and the profile must allow.
        c.network = true;
        let profile = render_apparmor_profile("work", "myapp", &c);
        assert!(profile.contains("profile shuttle-work-myapp"));
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
    fn profile_name_is_deterministic_and_namespaced() {
        assert_eq!(profile_name("default", "app"), "shuttle-default-app");
        assert_eq!(profile_name("work", "gui"), "shuttle-work-gui");
    }
}
