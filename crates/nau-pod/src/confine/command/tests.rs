//! The arbitrary-command form's tests (issue #102) and the
//! path-addressed form's tests (issue #9).

use super::*;
use nau_core::pkg_manifest::Generation;
use std::collections::BTreeMap;
use std::path::Path;

/// Seed a pod with an active generation the way the production
/// mechanisms do: a manifest-bearing generation dir (the store's
/// `active` source of truth) plus a farm and the `current` link
/// (the pod flip), as pod.rs's `seed_active_pod` does. Returns the
/// pod dir. Executables are added by each test.
fn seed_command_pod(root: &Path, pod: &str, generation: u64) -> PathBuf {
    let dir = root.join(pod);
    let gen_dir = dir.join("generations").join(generation.to_string());
    let farm = gen_dir.join("farm");
    std::fs::create_dir_all(&farm).unwrap();
    let gen = Generation {
        n: generation,
        base_version: "24.04".into(),
        packages: BTreeMap::new(),
        created_epoch: 0,
        boot_entry: None,
    };
    std::fs::write(
        gen_dir.join("manifest.json"),
        serde_json::to_vec(&gen).unwrap(),
    )
    .unwrap();
    std::os::unix::fs::symlink(format!("generations/{generation}"), dir.join("active")).unwrap();
    crate::farm::flip_current(&dir, generation).unwrap();
    dir
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn sample_command_env(farm: &Path) -> PodShellenv {
    PodShellenv {
        pod: "work".into(),
        farm: farm.display().to_string(),
        generation: Some(1),
        vars: Default::default(),
        secret_vars: Default::default(),
        secrets: Default::default(),
    }
}

/// The env overlay result as seen through the built command.
fn env_of(cmd: &std::process::Command, key: &str) -> Option<String> {
    cmd.get_envs()
        .find(|(k, _)| *k == key)
        .and_then(|(_, v)| v)
        .map(|v| v.to_string_lossy().into_owned())
}

#[test]
fn resolve_command_prefers_the_farm_over_path() {
    let tmp = tempfile::tempdir().unwrap();
    let farm = tmp.path().join("farm");
    std::fs::create_dir_all(&farm).unwrap();
    make_executable(&farm.join("tool"));
    let pathdir = tmp.path().join("onpath");
    std::fs::create_dir_all(&pathdir).unwrap();
    make_executable(&pathdir.join("tool"));
    let entries = vec![farm.clone(), pathdir.clone()];
    assert_eq!(
        resolve_command_in("tool", &entries).unwrap(),
        farm.join("tool")
    );
}

#[test]
fn resolve_command_falls_through_to_path() {
    let tmp = tempfile::tempdir().unwrap();
    let farm = tmp.path().join("farm"); // exists, lacks the name
    std::fs::create_dir_all(&farm).unwrap();
    let pathdir = tmp.path().join("onpath");
    std::fs::create_dir_all(&pathdir).unwrap();
    make_executable(&pathdir.join("tool"));
    let entries = vec![farm, pathdir.clone()];
    assert_eq!(
        resolve_command_in("tool", &entries).unwrap(),
        pathdir.join("tool")
    );
}

#[test]
fn resolve_command_passes_explicit_paths_through_verbatim() {
    // A name containing '/' is a path, not a lookup — no entries
    // consulted (even bogus ones, proving no resolution ran).
    let entries = vec![PathBuf::from("/nonexistent-farm")];
    assert_eq!(
        resolve_command_in("./scripts/deploy.sh", &entries).unwrap(),
        PathBuf::from("./scripts/deploy.sh")
    );
    assert_eq!(
        resolve_command_in("/usr/bin/env", &entries).unwrap(),
        PathBuf::from("/usr/bin/env")
    );
}

#[test]
fn resolve_command_miss_names_the_command_and_path() {
    let tmp = tempfile::tempdir().unwrap();
    let farm = tmp.path().join("farm");
    std::fs::create_dir_all(&farm).unwrap();
    let pathdir = tmp.path().join("onpath");
    std::fs::create_dir_all(&pathdir).unwrap();
    let entries = vec![farm.clone(), pathdir];
    let err = resolve_command_in("nosuchcmd", &entries)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("nosuchcmd") && err.contains("PATH"),
        "error must name the command and the fix surface: {err}"
    );
    assert!(
        err.contains(&farm.display().to_string()),
        "error must name the farm searched: {err}"
    );
}

#[test]
fn overlay_pod_env_is_farm_first_and_never_touches_the_loader_path() {
    let tmp = tempfile::tempdir().unwrap();
    let farm = tmp.path().join("current");
    let env = sample_command_env(&farm);
    let mut cmd = std::process::Command::new("true");
    overlay_pod_env_with(&mut cmd, &env, Some(std::ffi::OsStr::new("/usr/bin:/bin")));
    assert_eq!(
        env_of(&cmd, "PATH").unwrap(),
        format!("{}:/usr/bin:/bin", farm.display()),
        "farm must precede the caller's PATH"
    );
    assert!(
        env_of(&cmd, "LD_LIBRARY_PATH").is_none(),
        "the pod must never export loader libs into a child (issue #110)"
    );
}

#[test]
fn overlay_pod_env_exports_the_farm_alone_for_unset_or_empty_path() {
    let tmp = tempfile::tempdir().unwrap();
    let farm = tmp.path().join("current");
    let env = sample_command_env(&farm);
    for existing in [None, Some(std::ffi::OsStr::new(""))] {
        let mut cmd = std::process::Command::new("true");
        overlay_pod_env_with(&mut cmd, &env, existing);
        assert_eq!(
            env_of(&cmd, "PATH").unwrap(),
            farm.display().to_string(),
            "unset/empty caller PATH must export just the farm (input: {existing:?})"
        );
    }
}

#[test]
fn overlay_pod_env_does_not_wipe_an_inherited_loader_path() {
    // The overlay never SETS LD_LIBRARY_PATH — but it also never
    // wipes the caller's own value: the wrapper (not this overlay)
    // owns the loader path inside pod processes (#110).
    let tmp = tempfile::tempdir().unwrap();
    let farm = tmp.path().join("current");
    let env = sample_command_env(&farm);
    let mut cmd = std::process::Command::new("true");
    cmd.env("LD_LIBRARY_PATH", "/opt/legacy");
    overlay_pod_env_with(&mut cmd, &env, Some(std::ffi::OsStr::new("/bin")));
    assert_eq!(
        env_of(&cmd, "LD_LIBRARY_PATH").unwrap(),
        "/opt/legacy",
        "an inherited LD_LIBRARY_PATH passes through untouched"
    );
}

#[test]
fn overlay_pod_env_declared_vars_replace_inherited_values() {
    let tmp = tempfile::tempdir().unwrap();
    let farm = tmp.path().join("current");
    let mut env = sample_command_env(&farm);
    env.vars.insert("EDITOR".to_string(), "vi".to_string());
    env.vars.insert("MODE".to_string(), "pod".to_string());
    let mut cmd = std::process::Command::new("true");
    cmd.env("MODE", "inherited");
    cmd.env("HOME", "/home/user");
    overlay_pod_env_with(&mut cmd, &env, Some(std::ffi::OsStr::new("/bin")));
    assert_eq!(
        env_of(&cmd, "EDITOR").unwrap(),
        "vi",
        "a declared var is set even when the caller has none"
    );
    assert_eq!(
        env_of(&cmd, "MODE").unwrap(),
        "pod",
        "a declared var replaces the inherited value (devbox env: semantics)"
    );
    assert_eq!(
        env_of(&cmd, "HOME").unwrap(),
        "/home/user",
        "undeclared vars pass through untouched"
    );
}

#[test]
fn overlay_pod_env_applies_secret_vars_with_the_declared_rule() {
    // ADR-0042 D3 (issue #184): resolved secrets ride the SAME
    // overlay as declared env — declared replaces inherited, the
    // caller's ambient value never wins.
    let tmp = tempfile::tempdir().unwrap();
    let mut env = sample_command_env(&tmp.path().join("current"));
    env.secret_vars.insert(
        "API_TOKEN".to_string(),
        "s3cr3t with spaces and 'quotes'".to_string(),
    );
    let mut cmd = std::process::Command::new("true");
    cmd.env("API_TOKEN", "ambient-must-lose");
    cmd.env("UNRELATED", "keep");
    overlay_pod_env_with(&mut cmd, &env, Some(std::ffi::OsStr::new("/bin")));
    assert_eq!(
        env_of(&cmd, "API_TOKEN").unwrap(),
        "s3cr3t with spaces and 'quotes'",
        "the secret value replaces the inherited one, verbatim"
    );
    assert_eq!(
        env_of(&cmd, "UNRELATED").unwrap(),
        "keep",
        "undeclared vars still pass through"
    );
}

#[test]
fn overlay_pod_env_prepends_the_farm_to_the_caller_path() {
    let tmp = tempfile::tempdir().unwrap();
    let env = sample_command_env(&tmp.path().join("farm"));
    let mut cmd = std::process::Command::new("true");
    overlay_pod_env(&mut cmd, &env);
    let path = env_of(&cmd, "PATH").unwrap();
    assert!(
        path.starts_with(&format!("{}", tmp.path().join("farm").display())),
        "farm must lead the exported PATH: {path}"
    );
}

#[test]
fn run_falls_through_to_the_command_form_for_undeclared_apps() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = seed_command_pod(tmp.path(), "default", 1);
    // The farm lacks the name and no package provides it: the
    // failure must be the command-form resolution miss (against the
    // caller's real PATH too — the name is unique enough to miss
    // everywhere), proving the command form was entered, not the old
    // "not provided by any package" error.
    let missing = "nau-102-definitely-missing-zz7f3a9b";
    let err = crate::confine::run(&dir, "default", missing, &[])
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(missing) && err.contains("PATH"),
        "expected the command-form resolution miss: {err}"
    );
    assert!(
        !err.contains("not provided by any package"),
        "the old declared-app error must be gone: {err}"
    );
}

#[test]
fn run_command_rejects_an_empty_command_vector() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = seed_command_pod(tmp.path(), "default", 1);
    let err = run_command(&dir, "default", &[]).unwrap_err().to_string();
    assert!(err.contains("empty command"), "{err}");
}

// ── Issue #9: a path-addressed command ──

/// A pod rootfs with one owned path, as the emit's gather builds it.
/// Returns the rootfs dir; the tempdir keeps it alive.
fn pod_rootfs_fixture() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().join("generations/1/rootfs");
    std::fs::create_dir_all(rootfs.join("lib64")).unwrap();
    std::fs::write(rootfs.join("lib64/ld-linux-x86-64.so.2"), b"loader").unwrap();
    (tmp, rootfs)
}

#[test]
fn a_pod_owned_absolute_path_resolves_to_the_pod_copy() {
    let (_tmp, rootfs) = pod_rootfs_fixture();
    let target = resolve_path_target(&rootfs, "/lib64/ld-linux-x86-64.so.2", "work");
    match target {
        PathTarget::Pod { target } => {
            assert!(
                target.starts_with(&rootfs),
                "the pod's own copy, not the host path: {}",
                target.display()
            );
            assert_eq!(target, rootfs.join("lib64/ld-linux-x86-64.so.2"));
        }
        PathTarget::Host { note } => panic!("the pod owns the path: {note}"),
    }
}

#[test]
fn a_path_the_pod_does_not_own_stays_on_the_host_and_says_why() {
    let (_tmp, rootfs) = pod_rootfs_fixture();
    let prog = "/usr/bin/env";
    match resolve_path_target(&rootfs, prog, "work") {
        PathTarget::Host { note } => {
            assert!(note.contains(prog), "the note names the path: {note}");
            assert!(
                note.contains("namespace"),
                "the note names the cause: {note}"
            );
            // The host branch runs the path as written — the same
            // verbatim rule an explicit path always had.
            let program = resolve_command(prog, Path::new("/nonexistent-farm")).unwrap();
            assert_eq!(program, PathBuf::from(prog));
        }
        PathTarget::Pod { target } => {
            panic!("the pod does not own {prog}: {}", target.display())
        }
    }
}

#[test]
fn the_namespace_command_carries_the_pod_loader_and_the_pod_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let gen_dir = tmp.path().join("generations/1");
    let target = gen_dir.join("rootfs/lib64/ld-linux-x86-64.so.2");
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    std::fs::write(&target, b"loader").unwrap();
    // A fake bwrap prints its argv: the namespace invocation is
    // proved without a real namespace, and without bwrap installed.
    let fake = tmp.path().join("bwrap");
    std::fs::write(
        &fake,
        "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let plan = crate::rootfs::PodRootfs {
        positions: vec!["lib64".into(), "usr/lib".into()],
        loader_rel: "extensions/glibc/usr/lib64/ld-linux-x86-64.so.2".into(),
    };
    let env = sample_command_env(&tmp.path().join("current"));
    let mut cmd = namespace_command(
        &fake,
        &plan,
        &gen_dir,
        &target,
        &["--version".to_string()],
        &["extensions/glibc/usr/lib64".to_string()],
        &env,
    );
    // The pod's env overlay still applies.
    assert!(
        env_of(&cmd, "PATH").is_some(),
        "the pod's PATH overlay applies"
    );
    // bwrap's own process starts without the pod's libs on its
    // loader path — they ride the namespace's --setenv instead.
    assert!(
        env_of(&cmd, "LD_LIBRARY_PATH").is_none(),
        "bwrap's own process must not carry a loader path"
    );
    let out = cmd.output().expect("the fake bwrap runs");
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("--bind\n/\n/"), "{text}");
    assert!(text.contains("--tmpfs\n/usr"), "{text}");
    // The pod's loader answers the interpreter slot.
    assert!(text.contains("/lib64/ld-linux-x86-64.so.2"), "{text}");
    // The pod's own copy is the command.
    assert!(
        text.contains(&target.display().to_string()),
        "the pod's own copy is the command: {text}"
    );
    // The pod's libraries ride inside the namespace.
    assert!(text.contains("--setenv\nLD_LIBRARY_PATH"), "{text}");
    assert!(
        text.contains(
            &gen_dir
                .join("extensions/glibc/usr/lib64")
                .display()
                .to_string()
        ),
        "{text}"
    );
    // The command's own args ride along.
    assert!(text.lines().any(|l| l == "--version"), "{text}");
}

#[test]
fn a_loader_carrying_generation_without_bubblewrap_refuses_to_run() {
    let err = namespace_backend("work", Path::new("/lib64/ld-linux-x86-64.so.2"), None)
        .unwrap_err()
        .to_string();
    assert!(err.contains("bubblewrap"), "{err}");
    assert!(err.contains("refusing"), "{err}");
}
