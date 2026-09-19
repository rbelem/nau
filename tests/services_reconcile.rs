//! The pod-services reconcile tail (ADR-0032 Decision 8, issue #107).
//!
//! Two harnesses, one file:
//!
//! - Seeded-store tests (ungated): a pod's generations + applied state
//!   are written directly under a tempdir (the store layout is a plain
//!   directory contract), and `pod rollback` drives the flip + reconcile
//!   tail through the REAL binary with a PATH-shim dir of fake systemd
//!   tools (the `pod_deps.rs` injected-tools pattern). The shims log
//!   their argv, so call ORDER is assertable; the disable shim also
//!   records whether the unit link still existed at stop time — the
//!   stop-then-withdraw guarantee, observed directly.
//! - Sync-tail tests (gated on mksquashfs/unsquashfs/curl/tar): the
//!   same acceptance chain as `pod_services.rs`, with the shim dir
//!   PREPENDED to the host PATH so the reconcile tail runs the fakes
//!   while the build chain stays real.
//!
//! All state lives in tempdirs — never the real home, never the host bus.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;

use shuttle::farm::ClaimLayer;
use shuttle::runtime::{Generation, InstalledPackage};
use shuttle::services::ServiceUnit;
use shuttle::snap::ServiceDaemon;

// ── Fake systemd tools (pod_deps.rs pattern) ──

/// A fake systemd tool: logs its argv (one `$*` per line), runs
/// `extra` (the disable shim records whether `$SVC_LINK` still exists —
/// the stop-then-withdraw witness), then exits `exit_code`.
fn fake_systemd_tool(dir: &Path, name: &str, marker: &Path, exit_code: i32, extra: &str) {
    let path = dir.join(name);
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{argv}'\n{extra}\n: > '{marker}'\nexit \
             {exit_code}\n",
            argv = marker.with_extension("argv").display(),
            marker = marker.display(),
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn tools_bin_with(markers: &Path) -> PathBuf {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    // Leak the tempdir: the shim dir must outlive the spawned children.
    std::mem::forget(dir);
    fake_systemd_tool(
        &path,
        "systemctl",
        &markers.join("systemctl.marker"),
        0,
        "if [ \"$2\" = disable ] && [ -n \"$SVC_LINK\" ]; then\n  if [ -e \"$SVC_LINK\" ]; then \
         printf 'disable:link-present\\n' >> \"$SVC_ARGV\"\n  else printf \
         'disable:link-absent\\n' >> \"$SVC_ARGV\"; fi\nfi",
    );
    fake_systemd_tool(
        &path,
        "systemd-sysext",
        &markers.join("sysext.marker"),
        0,
        "",
    );
    path
}

/// The argv log the systemctl shim writes (`marker.with_extension` of
/// `systemctl.marker`).
fn argv_path(markers: &Path) -> PathBuf {
    markers.join("systemctl.argv")
}

fn argv_lines(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

// ── Seeded-store fixtures ──

fn service_unit(name: &str, enabled: bool, hash: &str, args: &[&str]) -> ServiceUnit {
    ServiceUnit {
        name: name.into(),
        pkg: "svc-a".into(),
        layer: ClaimLayer::Own,
        daemon: ServiceDaemon::Simple,
        enabled,
        exec: "current/valkey".into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        environment: Default::default(),
        after: vec![],
        text: format!(
            "[Unit]\nDescription=seeded {name}\n\n[Service]\nType=simple\n\n[Install]\n\
             WantedBy=default.target\n"
        ),
        hash: hash.into(),
    }
}

/// Seed one generation: minimal manifest + sysext tree, and when the
/// generation carries units, its `services/` dir with the unit
/// artifacts + `units.json` (the reconcile's only inputs).
fn seed_generation(pod: &Path, n: u64, units: &[ServiceUnit]) {
    let mut packages = std::collections::BTreeMap::new();
    packages.insert(
        "svc-a".to_string(),
        InstalledPackage {
            name: "svc-a".into(),
            version: "1.0".into(),
            revision: n as u32,
            sha3_384: format!("{n:0>96}"),
            files: Vec::new(),
            units: Vec::new(),
            layer: ClaimLayer::Own,
            apps: Default::default(),
            launchers: Default::default(),
            assembly: Default::default(),
            confined: None,
            app_confined: Default::default(),
            desktops: Default::default(),
            fonts: Default::default(),
            services: Default::default(),
            service_bins: Default::default(),
        },
    );
    let gen = Generation {
        n,
        base_version: "24.04".into(),
        packages,
        created_epoch: 0,
        boot_entry: None,
    };
    let gen_dir = pod.join("generations").join(n.to_string());
    std::fs::create_dir_all(gen_dir.join("extensions").join("svc-a")).unwrap();
    std::fs::write(
        gen_dir
            .join("extensions")
            .join("svc-a")
            .join("release.svc-a"),
        "ID=_any\n",
    )
    .unwrap();
    std::fs::write(
        gen_dir.join("manifest.json"),
        serde_json::to_string(&gen).unwrap(),
    )
    .unwrap();
    if units.is_empty() {
        return;
    }
    let svc_dir = gen_dir.join("services");
    std::fs::create_dir_all(&svc_dir).unwrap();
    let pod_name = pod.file_name().unwrap().to_string_lossy().into_owned();
    for u in units {
        std::fs::write(
            svc_dir.join(format!("shuttle-pod-{pod_name}-{}.service", u.name)),
            &u.text,
        )
        .unwrap();
    }
    std::fs::write(
        svc_dir.join("units.json"),
        serde_json::to_vec(&serde_json::json!({ "units": units })).unwrap(),
    )
    .unwrap();
}

/// Seed the applied-state record: (unit, hash, enabled) triples.
fn seed_state(pod: &Path, entries: &[(&str, &str, bool)]) {
    let units: serde_json::Map<String, serde_json::Value> = entries
        .iter()
        .map(|(n, h, e)| {
            (
                n.to_string(),
                serde_json::json!({ "hash": h, "enabled": e }),
            )
        })
        .collect();
    std::fs::write(
        pod.join("services-state.json"),
        serde_json::to_vec(&serde_json::json!({ "units": units })).unwrap(),
    )
    .unwrap();
}

fn state_of(pod: &Path) -> serde_json::Value {
    serde_json::from_str(
        &std::fs::read_to_string(pod.join("services-state.json")).unwrap_or_default(),
    )
    .unwrap_or(serde_json::json!({}))
}

fn set_active(pod: &Path, n: u64) {
    let _ = std::fs::remove_file(pod.join("active"));
    std::os::unix::fs::symlink(format!("generations/{n}"), pod.join("active")).unwrap();
}

fn unit_link(config_home: &Path, pod: &str, svc: &str) -> PathBuf {
    config_home
        .join("systemd")
        .join("user")
        .join(format!("shuttle-pod-{pod}-{svc}.service"))
}

fn seed_link(config_home: &Path, pod: &str, svc: &str, target: &Path) {
    let link = unit_link(config_home, pod, svc);
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(target, link).unwrap();
}

struct RollbackRig {
    root: tempfile::TempDir,
    markers: tempfile::TempDir,
}

impl RollbackRig {
    fn new() -> RollbackRig {
        RollbackRig {
            root: tempfile::tempdir().unwrap(),
            markers: tempfile::tempdir().unwrap(),
        }
    }

    fn pod(&self, name: &str) -> PathBuf {
        let pod = self.root.path().join(name);
        std::fs::create_dir_all(&pod).unwrap();
        pod
    }

    fn config_home(&self) -> PathBuf {
        self.root.path().join("config-home")
    }

    /// Run `shuttle pod [--name <pod>] rollback <target>` through the
    /// real binary with the fake tools dir as the ONLY PATH entry (the
    /// rollback path spawns nothing else; every shim is a /bin/sh script
    /// with an absolute shebang).
    fn run(&self, pod: &str, target: &str) -> (Option<i32>, String, String, PathBuf) {
        let tools_bin = tools_bin_with(self.markers.path());
        // Each invocation gets a fresh log; the link-check witness
        // writes into the same log.
        let argv = argv_path(self.markers.path());
        let _ = std::fs::remove_file(&argv);
        let svc_link = unit_link(&self.config_home(), "alpha", "valkey");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
        cmd.args(["pod", "rollback", target, "--root"])
            .arg(self.root.path())
            .current_dir(self.root.path());
        cmd.env("SHUTTLE_SYSTEMD", "on");
        cmd.env("SHUTTLE_POD_TOOLS", "");
        cmd.env("SHUTTLE_SERVICE_BACKEND", "systemd");
        cmd.env("XDG_CONFIG_HOME", self.config_home());
        cmd.env("PATH", &tools_bin);
        cmd.env("SVC_ARGV", &argv);
        cmd.env("SVC_LINK", &svc_link);
        if !pod.is_empty() {
            cmd.arg("--name").arg(pod);
        }
        let out = cmd.output().expect("failed to spawn shuttle pod rollback");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            argv,
        )
    }
}

fn link_of(rig: &RollbackRig, pod: &str, svc: &str) -> PathBuf {
    unit_link(&rig.config_home(), pod, svc)
}

// ── Ungated: the rollback flip carries the reconcile tail ──

#[test]
fn rollback_restarts_changed_service_on_the_flip() {
    let rig = RollbackRig::new();
    let pod = rig.pod("alpha");
    let gen1 = service_unit("valkey", true, "hash-a", &["--port", "6379"]);
    let gen2 = service_unit("valkey", true, "hash-b", &["--port", "6380"]);
    seed_generation(&pod, 1, &[gen1]);
    seed_generation(&pod, 2, &[gen2]);
    set_active(&pod, 2);
    seed_state(&pod, &[("valkey", "hash-b", true)]);
    seed_link(
        &rig.config_home(),
        "alpha",
        "valkey",
        &pod.join("generations/2/services/shuttle-pod-alpha-valkey.service"),
    );

    let (code, stdout, stderr, argv) = rig.run("alpha", "1");
    assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");

    // daemon-reload BEFORE restart; no enable for the changed unit.
    let lines = argv_lines(&argv);
    let reload = lines
        .iter()
        .position(|l| l.contains("daemon-reload"))
        .unwrap();
    let restart = lines
        .iter()
        .position(|l| l.contains("restart shuttle-pod-alpha-valkey"))
        .unwrap();
    assert!(reload < restart, "reload must precede restart: {lines:?}");
    assert!(
        !lines.iter().any(|l| l.contains("enable --now")),
        "a changed unit restarts, never re-enables: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("disable")),
        "nothing withdraws on this flip: {lines:?}"
    );

    // Applied state follows the flip; the link re-points at gen 1.
    let state = state_of(&pod);
    assert_eq!(state["units"]["valkey"]["hash"], "hash-a", "{state}");
    assert_eq!(state["units"]["valkey"]["enabled"], true);
    let link_target = std::fs::read_link(link_of(&rig, "alpha", "valkey")).unwrap();
    assert!(link_target.to_string_lossy().contains("generations/1"));
    // The rollback printer surfaces the restart.
    assert!(stderr.contains("services restarted"), "stderr: {stderr}");
}

#[test]
fn rollback_activates_newly_enabled_unit_reload_before_enable() {
    let rig = RollbackRig::new();
    let pod = rig.pod("alpha");
    let gen1 = service_unit("valkey", true, "hash-a", &["--port", "6379"]);
    seed_generation(&pod, 1, &[gen1]);
    seed_generation(&pod, 2, &[]);
    set_active(&pod, 2);
    // The applied record remembers the unit DISABLED: the flip to gen 1
    // (enabled there) is a NEWLY-ENABLED activation.
    seed_state(&pod, &[("valkey", "hash-a", false)]);

    let (code, stdout, stderr, argv) = rig.run("alpha", "1");
    assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");

    let lines = argv_lines(&argv);
    let reload = lines
        .iter()
        .position(|l| l.contains("daemon-reload"))
        .unwrap_or_else(|| panic!("no daemon-reload in log: {lines:?}"));
    let enable = lines
        .iter()
        .position(|l| l.contains("enable --now shuttle-pod-alpha-valkey"))
        .unwrap_or_else(|| panic!("no enable --now in log: {lines:?}"));
    assert!(reload < enable, "reload must precede enable: {lines:?}");
    assert!(link_of(&rig, "alpha", "valkey").exists());
    let state = state_of(&pod);
    assert_eq!(state["units"]["valkey"]["hash"], "hash-a", "{state}");
    assert_eq!(state["units"]["valkey"]["enabled"], true, "{state}");
    // No loginctl in the shim PATH → the linger probe stays silent.
    assert!(
        !stderr.contains("lingering"),
        "no loginctl → no linger warning: {stderr}"
    );
}

#[test]
fn linger_warning_when_loginctl_reports_no() {
    let rig = RollbackRig::new();
    let pod = rig.pod("alpha");
    seed_generation(&pod, 1, &[service_unit("valkey", true, "hash-a", &[])]);
    seed_generation(&pod, 2, &[]);
    set_active(&pod, 2);
    seed_state(&pod, &[("valkey", "hash-a", false)]);

    // A loginctl shim answering `Linger=no` → the warning, exactly once.
    let tools_bin = tools_bin_with(rig.markers.path());
    fake_systemd_tool(
        &tools_bin,
        "loginctl",
        &rig.markers.path().join("loginctl.marker"),
        0,
        "echo Linger=no",
    );
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.args(["pod", "--name", "alpha", "rollback", "1", "--root"])
        .arg(rig.root.path())
        .current_dir(rig.root.path());
    cmd.env("SHUTTLE_SYSTEMD", "on");
    cmd.env("SHUTTLE_POD_TOOLS", "");
    cmd.env("SHUTTLE_SERVICE_BACKEND", "systemd");
    cmd.env("XDG_CONFIG_HOME", rig.config_home());
    cmd.env("PATH", &tools_bin);
    let out = cmd.output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        stderr.matches("lingering is off").count(),
        1,
        "the linger warning is emitted once: {stderr}"
    );
    assert!(
        stderr.contains("sudo loginctl enable-linger"),
        "the warning documents the manual host step: {stderr}"
    );

    // `Linger=yes` → silent.
    let rig2 = RollbackRig::new();
    let pod2 = rig2.pod("alpha");
    seed_generation(&pod2, 1, &[service_unit("valkey", true, "hash-a", &[])]);
    seed_generation(&pod2, 2, &[]);
    set_active(&pod2, 2);
    seed_state(&pod2, &[("valkey", "hash-a", false)]);
    let tools_bin2 = tools_bin_with(rig2.markers.path());
    fake_systemd_tool(
        &tools_bin2,
        "loginctl",
        &rig2.markers.path().join("loginctl.marker"),
        0,
        "echo Linger=yes",
    );
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.args(["pod", "--name", "alpha", "rollback", "1", "--root"])
        .arg(rig2.root.path())
        .current_dir(rig2.root.path());
    cmd.env("SHUTTLE_SYSTEMD", "on");
    cmd.env("SHUTTLE_POD_TOOLS", "");
    cmd.env("SHUTTLE_SERVICE_BACKEND", "systemd");
    cmd.env("XDG_CONFIG_HOME", rig2.config_home());
    cmd.env("PATH", &tools_bin2);
    let out = cmd.output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        !stderr.contains("lingering"),
        "lingering on → silent: {stderr}"
    );
}

#[test]
fn rollback_withdraws_with_stop_before_unlink() {
    let rig = RollbackRig::new();
    let pod = rig.pod("alpha");
    let gen1 = service_unit("valkey", true, "hash-a", &["--port", "6379"]);
    seed_generation(&pod, 1, &[gen1]);
    seed_generation(&pod, 2, &[]);
    set_active(&pod, 1);
    seed_state(&pod, &[("valkey", "hash-a", true)]);
    let gen1_artifact = pod.join("generations/1/services/shuttle-pod-alpha-valkey.service");
    seed_link(&rig.config_home(), "alpha", "valkey", &gen1_artifact);

    // Roll forward to the service-less generation: withdrawn.
    let (code, stdout, stderr, argv) = rig.run("alpha", "2");
    assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");

    let lines = argv_lines(&argv);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("disable --now shuttle-pod-alpha-valkey")),
        "the withdrawal must disable --now: {lines:?}"
    );
    // The stop-then-withdraw witness recorded by the shim: at disable
    // time the registration (link) still existed.
    let svc_lines = argv_lines(&argv).join("\n");
    assert!(
        svc_lines.contains("disable:link-present"),
        "disable must run while the link exists: {svc_lines}"
    );
    // ... and afterwards the link is gone and the state emptied.
    assert!(!link_of(&rig, "alpha", "valkey").exists());
    let state = state_of(&pod);
    assert!(
        state["units"]
            .as_object()
            .map(|u| u.is_empty())
            .unwrap_or(true),
        "{state}"
    );
    assert!(stderr.contains("services deactivated"), "stderr: {stderr}");
}

#[test]
fn rollback_disables_newly_disabled_and_removes_the_link() {
    let rig = RollbackRig::new();
    let pod = rig.pod("alpha");
    let gen1 = service_unit("valkey", false, "hash-a", &["--port", "6379"]);
    let gen2 = service_unit("valkey", true, "hash-b", &["--port", "6379"]);
    seed_generation(&pod, 1, &[gen1]);
    seed_generation(&pod, 2, &[gen2]);
    set_active(&pod, 2);
    seed_state(&pod, &[("valkey", "hash-b", true)]);
    seed_link(
        &rig.config_home(),
        "alpha",
        "valkey",
        &pod.join("generations/2/services/shuttle-pod-alpha-valkey.service"),
    );

    let (code, stdout, stderr, argv) = rig.run("alpha", "1");
    assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");

    let lines = argv_lines(&argv);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("disable --now shuttle-pod-alpha-valkey")),
        "newly-disabled stops + disables: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("restart")),
        "a disabled unit never restarts: {lines:?}"
    );
    assert!(
        argv_lines(&argv)
            .iter()
            .any(|l| l.contains("disable:link-present")),
        "disable runs while the registration exists"
    );
    // The gen-1 unit is disabled → the link is withheld.
    assert!(!link_of(&rig, "alpha", "valkey").exists());
    let state = state_of(&pod);
    assert_eq!(state["units"]["valkey"]["enabled"], false, "{state}");
    assert_eq!(state["units"]["valkey"]["hash"], "hash-a");
}

#[test]
fn absent_tools_skip_bus_steps_but_files_still_reconcile() {
    let rig = RollbackRig::new();
    let pod = rig.pod("alpha");
    let gen1 = service_unit("valkey", true, "hash-a", &["--port", "6379"]);
    let gen2 = service_unit("valkey", true, "hash-b", &["--port", "6380"]);
    seed_generation(&pod, 1, &[gen1]);
    seed_generation(&pod, 2, &[gen2]);
    set_active(&pod, 2);
    seed_state(&pod, &[("valkey", "hash-b", true)]);
    seed_link(
        &rig.config_home(),
        "alpha",
        "valkey",
        &pod.join("generations/2/services/shuttle-pod-alpha-valkey.service"),
    );

    // SHUTTLE_POD_TOOLS=absent: every tool is None — the suite stays
    // off the real bus, the verb succeeds, and the FILE truth (links +
    // state) still reconciles.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.args(["pod", "--name", "alpha", "rollback", "1", "--root"])
        .arg(rig.root.path())
        .current_dir(rig.root.path());
    cmd.env("SHUTTLE_POD_TOOLS", "absent");
    cmd.env("SHUTTLE_SERVICE_BACKEND", "systemd");
    cmd.env("XDG_CONFIG_HOME", rig.config_home());
    let out = cmd.output().unwrap();
    let code = out.status.code();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(code, Some(0), "{combined}");
    assert!(
        combined.contains("systemctl unavailable"),
        "every skipped bus step is named: {combined}"
    );
    assert!(
        !rig.markers.path().join("systemctl.argv").exists(),
        "no systemctl call may happen (no shim was even on PATH)"
    );
    let state = state_of(&pod);
    assert_eq!(state["units"]["valkey"]["hash"], "hash-a", "{state}");
    let link_target = std::fs::read_link(link_of(&rig, "alpha", "valkey")).unwrap();
    assert!(link_target.to_string_lossy().contains("generations/1"));
}

#[test]
fn cross_pod_same_endpoint_collides_without_bus_calls() {
    let rig = RollbackRig::new();
    for name in ["alpha", "beta"] {
        let pod = rig.pod(name);
        let unit = service_unit("valkey", true, "hash-a", &["--port", "6379"]);
        seed_generation(&pod, 1, &[unit.clone()]);
        seed_generation(&pod, 2, &[unit]);
        set_active(&pod, 2);
    }

    let (code, stdout, stderr, argv) = rig.run("alpha", "1");
    assert_eq!(
        code,
        Some(1),
        "same endpoint across pods must hard-error: {stderr}{stdout}"
    );
    assert!(
        stderr.contains("alpha")
            && stderr.contains("beta")
            && stderr.contains("valkey")
            && stderr.contains("--port")
            && stderr.contains("6379"),
        "the error names both pods, the services, the endpoint: {stderr}"
    );
    assert!(
        stderr.contains("Decision 9") && stderr.contains("enabled = false"),
        "the error carries the resolution: {stderr}"
    );
    // The collision is a compare-first hard error: no SERVICE
    // registration call happens (the store's own activation reload is
    // not the service tail).
    assert!(
        !argv_lines(&argv)
            .iter()
            .any(|l| l.contains("shuttle-pod-alpha-valkey")),
        "no service unit may be touched: {stdout}{stderr}"
    );
}

#[test]
fn cross_pod_same_endpoint_with_one_disabled_coexists() {
    let rig = RollbackRig::new();
    let alpha = rig.pod("alpha");
    let unit = service_unit("valkey", true, "hash-a", &["--port", "6379"]);
    seed_generation(&alpha, 1, &[unit.clone()]);
    seed_generation(&alpha, 2, &[unit]);
    set_active(&alpha, 2);
    let beta = rig.pod("beta");
    let disabled = service_unit("valkey", false, "hash-a", &["--port", "6379"]);
    seed_generation(&beta, 1, &[disabled.clone()]);
    seed_generation(&beta, 2, &[disabled]);
    set_active(&beta, 2);

    let (code, stdout, stderr, _) = rig.run("alpha", "1");
    assert_eq!(
        code,
        Some(0),
        "a disabled consumer pod never collides: {stderr}{stdout}"
    );
}

// ── Gated sync-tail tests (full build chain + shim prepended to PATH) ──

fn has_tool(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some()
}

fn chain_available() -> bool {
    ["mksquashfs", "unsquashfs", "curl", "tar"]
        .iter()
        .all(|t| has_tool(t))
}

macro_rules! gated_test {
    ($fn_name:ident, $($body:tt)*) => {
        #[test]
        fn $fn_name() {
            if !chain_available() {
                eprintln!("skipping: mksquashfs/unsquashfs/curl/tar unavailable");
                return;
            }
            $($body)*
        }
    };
}

// ── Loopback source server (pod_services.rs pattern) ──

fn serve_dir(dir: &Path) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let root = dir.to_path_buf();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            if serve_one(&mut stream, &root).is_err() {
                continue;
            }
        }
    });
    port
}

fn serve_one(stream: &mut TcpStream, root: &Path) -> std::io::Result<()> {
    let mut buf = [0u8; 4096];
    let mut data = Vec::new();
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        if data.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let req = String::from_utf8_lossy(&data);
    let path = req.split_whitespace().nth(1).unwrap_or("/");
    let file = root.join(path.trim_start_matches('/'));
    let (status, body) = match std::fs::read(&file) {
        Ok(b) => ("200 OK", b),
        Err(_) => ("404 Not Found", b"not found".to_vec()),
    };
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()
}

fn make_tarball_at(server_dir: &Path, name: &str, rel: &str) {
    let pkg = server_dir.join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(pkg.join("README"), "fixture source\n").unwrap();
    let dest = server_dir.join(rel);
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    let status = Command::new("tar")
        .args(["czf", dest.to_str().unwrap(), name])
        .current_dir(server_dir)
        .status()
        .unwrap();
    assert!(status.success(), "tar failed");
}

/// A package that builds a marker binary AND declares the service
/// `valkey` (dormant by default, `--port`-endpoint args).
fn write_service_pkg(project: &Path, name: &str, marker: &str, port: u16, src_rel: &str) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
    source = "http://127.0.0.1:{port}/{src_rel}",
    build = "mkdir -p $STAGE/bin && echo '#!/bin/sh' > $STAGE/bin/{name} && echo 'echo {marker}' >> $STAGE/bin/{name} && chmod +x $STAGE/bin/{name}",
    apps = {{ ["{name}"] = {{ command = "bin/{name}" }} }},
    services = {{
        ["valkey"] = {{
            command = "bin/{name}",
            args = {{ "--port", "${{port}}" }},
            options = {{ enabled = false, port = 7001 }},
        }},
    }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

struct SyncRig {
    project: tempfile::TempDir,
    root: tempfile::TempDir,
    server: tempfile::TempDir,
    port: u16,
    markers: tempfile::TempDir,
}

impl SyncRig {
    fn new() -> SyncRig {
        let server = tempfile::tempdir().unwrap();
        let port = serve_dir(server.path());
        SyncRig {
            project: tempfile::tempdir().unwrap(),
            root: tempfile::tempdir().unwrap(),
            server,
            port,
            markers: tempfile::tempdir().unwrap(),
        }
    }

    fn pod(&self) -> PathBuf {
        self.root.path().join("default")
    }

    fn config_home(&self) -> PathBuf {
        self.root.path().join("config-home")
    }

    /// Run a pod verb with the fake systemd tools PREPENDED to the host
    /// PATH (the build chain stays real; the reconcile tail runs the
    /// shims). `systemd` opt-in so for_pod_runtime keeps the tools.
    fn run(&self, pod: &str, args: &[&str]) -> (Option<i32>, String, String) {
        let tools_bin = tools_bin_with(self.markers.path());
        // Each invocation gets a fresh log.
        let _ = std::fs::remove_file(argv_path(self.markers.path()));
        let host_path = std::env::var("PATH").unwrap_or_default();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
        cmd.arg("pod");
        if !pod.is_empty() {
            cmd.arg("--name").arg(pod);
        }
        cmd.args(args)
            .arg("--root")
            .arg(self.root.path())
            .current_dir(self.project.path());
        cmd.env("SHUTTLE_DATA_HOME", self.root.path().join("data-home"));
        cmd.env("SHUTTLE_SERVICE_BACKEND", "systemd");
        cmd.env("XDG_CONFIG_HOME", self.config_home());
        cmd.env("SHUTTLE_SYSTEMD", "on");
        cmd.env("SHUTTLE_POD_TOOLS", "");
        cmd.env("SVC_ARGV", argv_path(self.markers.path()));
        cmd.env("SVC_LINK", link_of_sync(self, "valkey"));
        cmd.env("PATH", format!("{}:{}", tools_bin.display(), host_path));
        let out = cmd.output().expect("failed to spawn shuttle pod");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// The same, but with the suite-default env (`SHUTTLE_SYSTEMD=off`):
    /// no tools resolve, the tail skips with named entries.
    fn run_default_env(&self, pod: &str, args: &[&str]) -> (Option<i32>, String, String) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
        cmd.arg("pod");
        if !pod.is_empty() {
            cmd.arg("--name").arg(pod);
        }
        cmd.args(args)
            .arg("--root")
            .arg(self.root.path())
            .current_dir(self.project.path());
        cmd.env("SHUTTLE_DATA_HOME", self.root.path().join("data-home"));
        cmd.env("SHUTTLE_SERVICE_BACKEND", "systemd");
        cmd.env("XDG_CONFIG_HOME", self.config_home());
        cmd.env("SHUTTLE_SYSTEMD", "off");
        let out = cmd.output().expect("failed to spawn shuttle pod");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn argv(&self) -> Vec<String> {
        argv_lines(&argv_path(self.markers.path()))
    }
}

/// Replace (or insert fresh) the pod declaration's `services` override
/// block — idempotent across edits, and `""` clears it (a removal must
/// not leave overrides for services no package declares anymore).
fn set_override(rig: &SyncRig, override_lua: &str) {
    let decl_path = rig.pod().join("pod.lua");
    let decl = std::fs::read_to_string(&decl_path).unwrap();
    let base = decl
        .lines()
        .filter(|l| !l.trim_start().starts_with("services = {"))
        .collect::<Vec<_>>()
        .join("\n");
    let edited = base.replace(
        "packages = { \"svc-a\" },",
        &format!("packages = {{ \"svc-a\" }},\n    services = {{ {override_lua} }},"),
    );
    assert_ne!(edited, base, "fixture must match");
    std::fs::write(&decl_path, &edited).unwrap();
}

fn link_of_sync(rig: &SyncRig, svc: &str) -> PathBuf {
    unit_link(&rig.config_home(), "default", svc)
}

gated_test!(sync_enable_runs_reload_then_enable_now, {
    let rig = SyncRig::new();
    write_service_pkg(
        rig.project.path(),
        "svc-a",
        "a-ran",
        rig.port,
        "svc-a.tar.gz",
    );
    make_tarball_at(rig.server.path(), "svc-a", "svc-a.tar.gz");
    let (code, _, stderr) = rig.run("default", &["add", "svc-a"]);
    assert_eq!(code, Some(0), "add failed: {stderr}");
    assert!(
        !link_of_sync(&rig, "valkey").exists(),
        "dormant default: no link"
    );

    set_override(&rig, "[\"valkey\"] = { enabled = true }");
    let (code, _, stderr) = rig.run("default", &["sync"]);
    assert_eq!(code, Some(0), "sync failed: {stderr}");

    let lines = rig.argv();
    let reload = lines
        .iter()
        .position(|l| l.contains("daemon-reload"))
        .unwrap();
    let enable = lines
        .iter()
        .position(|l| l.contains("enable --now shuttle-pod-default-valkey"))
        .unwrap();
    assert!(reload < enable, "reload must precede enable: {lines:?}");
    assert!(link_of_sync(&rig, "valkey").exists());
    let state = state_of(&rig.pod());
    assert_eq!(state["units"]["valkey"]["enabled"], true, "{state}");
    assert!(stderr.contains("services activated"), "stderr: {stderr}");
});

gated_test!(sync_option_change_restarts_the_service, {
    let rig = SyncRig::new();
    write_service_pkg(
        rig.project.path(),
        "svc-a",
        "a-ran",
        rig.port,
        "svc-a.tar.gz",
    );
    make_tarball_at(rig.server.path(), "svc-a", "svc-a.tar.gz");
    let (code, _, stderr) = rig.run("default", &["add", "svc-a"]);
    assert_eq!(code, Some(0), "add failed: {stderr}");
    set_override(&rig, "[\"valkey\"] = { enabled = true }");
    let (code, _, stderr) = rig.run("default", &["sync"]);
    assert_eq!(code, Some(0), "enable sync failed: {stderr}");

    // Option change (same binary): the hash moves → restart, not enable.
    set_override(&rig, "[\"valkey\"] = { enabled = true, port = 7003 }");
    let (code, _, stderr) = rig.run("default", &["sync"]);
    assert_eq!(code, Some(0), "option sync failed: {stderr}");
    let lines = rig.argv();
    assert!(
        lines
            .iter()
            .any(|l| l.contains("restart shuttle-pod-default-valkey")),
        "an option change restarts: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("enable --now")),
        "an already-enabled unit never re-enables: {lines:?}"
    );
});

gated_test!(sync_version_bump_restarts_the_service, {
    let rig = SyncRig::new();
    write_service_pkg(
        rig.project.path(),
        "svc-a",
        "v1-ran",
        rig.port,
        "v1/svc-a.tar.gz",
    );
    make_tarball_at(rig.server.path(), "svc-a", "v1/svc-a.tar.gz");
    let (code, _, stderr) = rig.run("default", &["add", "svc-a"]);
    assert_eq!(code, Some(0), "add failed: {stderr}");
    set_override(&rig, "[\"valkey\"] = { enabled = true }");
    let (code, _, stderr) = rig.run("default", &["sync"]);
    assert_eq!(code, Some(0), "enable sync failed: {stderr}");

    // Version bump at the SAME options: the package digest moved, the
    // hash covers it → the restart happens on the sync flip itself.
    write_service_pkg(
        rig.project.path(),
        "svc-a",
        "v2-ran",
        rig.port,
        "v2/svc-a.tar.gz",
    );
    make_tarball_at(rig.server.path(), "svc-a", "v2/svc-a.tar.gz");
    let (code, _, stderr) = rig.run("default", &["sync"]);
    assert_eq!(code, Some(0), "bump sync failed: {stderr}");
    let lines = rig.argv();
    assert!(
        lines
            .iter()
            .any(|l| l.contains("restart shuttle-pod-default-valkey")),
        "a binary-only upgrade restarts (hash covers the package digest): {lines:?}"
    );
});

gated_test!(remove_withdraws_with_stop_before_unlink, {
    let rig = SyncRig::new();
    write_service_pkg(
        rig.project.path(),
        "svc-a",
        "a-ran",
        rig.port,
        "svc-a.tar.gz",
    );
    make_tarball_at(rig.server.path(), "svc-a", "svc-a.tar.gz");
    let (code, _, stderr) = rig.run("default", &["add", "svc-a"]);
    assert_eq!(code, Some(0), "add failed: {stderr}");
    set_override(&rig, "[\"valkey\"] = { enabled = true }");
    let (code, _, stderr) = rig.run("default", &["sync"]);
    assert_eq!(code, Some(0), "enable sync failed: {stderr}");
    assert!(link_of_sync(&rig, "valkey").exists());

    // The service override goes with the package (an override for a
    // service no package declares fails validation), then remove.
    set_override(&rig, "");
    let (code, _, stderr) = rig.run("default", &["remove", "svc-a"]);
    assert_eq!(code, Some(0), "remove failed: {stderr}");
    let lines = rig.argv();
    assert!(
        lines
            .iter()
            .any(|l| l.contains("disable --now shuttle-pod-default-valkey")),
        "the removal withdraws with disable --now: {lines:?}"
    );
    assert!(
        argv_lines(&argv_path(rig.markers.path()))
            .iter()
            .any(|l| l.contains("disable:link-present")),
        "stop runs while the registration still exists"
    );
    assert!(
        !link_of_sync(&rig, "valkey").exists(),
        "the link is withdrawn"
    );
    let state = state_of(&rig.pod());
    assert!(
        state["units"]
            .as_object()
            .map(|u| u.is_empty())
            .unwrap_or(true),
        "{state}"
    );
});

gated_test!(sync_without_systemctl_skips_but_reconciles_links, {
    let rig = SyncRig::new();
    write_service_pkg(
        rig.project.path(),
        "svc-a",
        "a-ran",
        rig.port,
        "svc-a.tar.gz",
    );
    make_tarball_at(rig.server.path(), "svc-a", "svc-a.tar.gz");
    let (code, _, stderr) = rig.run_default_env("default", &["add", "svc-a"]);
    assert_eq!(code, Some(0), "add failed: {stderr}");

    // No systemctl on this surface: the enable still converges the
    // file-level truth (link + state) and names every skip.
    set_override(&rig, "[\"valkey\"] = { enabled = true }");
    let (code, _, stderr) = rig.run_default_env("default", &["sync"]);
    assert_eq!(code, Some(0), "sync without tools must succeed: {stderr}");
    assert!(
        stderr.contains("systemctl unavailable"),
        "skips are named, never silent: {stderr}"
    );
    assert!(
        link_of_sync(&rig, "valkey").exists(),
        "links still reconcile"
    );
    let state = state_of(&rig.pod());
    assert_eq!(state["units"]["valkey"]["enabled"], true, "{state}");
});
