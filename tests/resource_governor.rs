use std::fs;
use std::io;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use nau_core::resource_limit::{CpuMax, ResourceLimit};
use nau_infra::governor::{self, ConfigGuard};
use syn::visit::Visit;
use syn::{Attribute, ExprMethodCall, ImplItemFn, ItemFn, ItemImpl, ItemMod, Meta, Type};

const CHILD_SLEEP_ENV: &str = "NAU_RESOURCE_GOVERNOR_TEST_SLEEP_MS";
const CHILD_LIMIT_ENV: &str = "NAU_RESOURCE_GOVERNOR_TEST_LIMIT";

static LIVE_TEST_LOCK: Mutex<()> = Mutex::new(());

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn resource_governor_joins_spawned_processes_and_writes_the_live_quota() {
    let _lock = live_test_lock();
    let Some(_guard) = live_governor() else {
        return;
    };
    let mut child = governed_test_child(None, Duration::from_secs(30));
    let cgroup = child_cgroup(child.0.id()).expect("child cgroup is readable");
    assert_eq!(
        cgroup.file_name().and_then(|name| name.to_str()),
        Some("nau-build")
    );
    assert_cpu_max_matches_claims(&cgroup);
    let stat = fs::read_to_string(cgroup.join("cpu.stat")).expect("cpu.stat is readable");
    assert!(stat.lines().any(|line| line.starts_with("usage_usec ")));
    child.0.kill().unwrap();
    child.0.wait().unwrap();
}

#[test]
fn resource_governor_clamps_jobs_to_the_live_quota() {
    let _lock = live_test_lock();
    let Some(_guard) = live_governor() else {
        return;
    };
    let mut child = governed_test_child(None, Duration::from_secs(30));
    let cgroup = child_cgroup(child.0.id()).expect("child cgroup is readable");
    let quota = fs::read_to_string(cgroup.join("cpu.max")).unwrap();
    let mut fields = quota.split_whitespace();
    let quota_us = fields.next().unwrap().parse::<usize>().unwrap();
    let period_us = fields.next().unwrap().parse::<usize>().unwrap();
    assert_eq!(period_us, CpuMax::PERIOD_US as usize);
    let quota_cores = NonZeroUsize::new((quota_us / period_us).max(1)).unwrap();
    let online = NonZeroUsize::new(online_cpus().get() as usize).unwrap();
    assert_eq!(governor::clamp_jobs(online), online.min(quota_cores));
    assert_eq!(governor::clamp_jobs(NonZeroUsize::new(1).unwrap()).get(), 1);
    child.0.kill().unwrap();
    child.0.wait().unwrap();
}

#[test]
fn resource_governor_reconciles_two_live_process_claims() {
    let _lock = live_test_lock();
    let Some(_guard) = live_governor() else {
        return;
    };
    let mut probe = governed_test_child(None, Duration::from_secs(30));
    let cgroup = child_cgroup(probe.0.id()).expect("child cgroup is readable");
    probe.0.kill().unwrap();
    probe.0.wait().unwrap();
    assert_cpu_max_matches_claims(&cgroup);

    let mut peer = ungoverned_test_child(Some("100"), Duration::from_millis(500));
    wait_for_claim(peer.0.id(), true);
    assert_cpu_max_matches_claims(&cgroup);
    assert!(peer.0.wait().unwrap().success());
    wait_for_claim(peer.0.id(), false);
    assert_cpu_max_matches_claims(&cgroup);
}

#[test]
fn resource_governor_sweeps_a_crashed_process_claim() {
    let _lock = live_test_lock();
    let Some(_guard) = live_governor() else {
        return;
    };
    let mut probe = governed_test_child(None, Duration::from_secs(30));
    let cgroup = child_cgroup(probe.0.id()).expect("child cgroup is readable");
    probe.0.kill().unwrap();
    probe.0.wait().unwrap();

    let mut peer = ungoverned_test_child(Some("100"), Duration::from_secs(30));
    wait_for_claim(peer.0.id(), true);
    peer.0.kill().unwrap();
    peer.0.wait().unwrap();
    assert!(claim_path(peer.0.id()).exists(), "crash leaves its claim");

    let _replacement = governor::configure(ResourceLimit::DEFAULT);
    wait_for_claim(peer.0.id(), false);
    assert_cpu_max_matches_claims(&cgroup);
}

#[test]
fn resource_governor_child_waits_when_started_as_a_probe() {
    let Ok(milliseconds) = std::env::var(CHILD_SLEEP_ENV) else {
        return;
    };
    if let Ok(limit) = std::env::var(CHILD_LIMIT_ENV) {
        let limit = ResourceLimit::resolve(Some(&limit), None).expect("helper limit parses");
        let _guard = governor::configure(limit);
        thread::sleep(Duration::from_millis(milliseconds.parse().unwrap()));
    } else {
        thread::sleep(Duration::from_millis(milliseconds.parse().unwrap()));
    }
}

#[test]
fn raw_build_and_infra_process_calls_use_governor_seams() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for directory in [
        root.join("crates/nau-build/src"),
        root.join("crates/nau-infra/src"),
    ] {
        collect_rust_files(&directory, &mut files).unwrap();
    }
    let mut violations = Vec::new();
    for path in files {
        let source = fs::read_to_string(&path).unwrap();
        let syntax = syn::parse_file(&source)
            .unwrap_or_else(|error| panic!("{} does not parse: {error}", path.display()));
        if is_test_only(&syntax.attrs) {
            continue;
        }
        let relative = path.strip_prefix(root).unwrap().display().to_string();
        let mut visitor = ProcessCallVisitor {
            path: relative,
            function: None,
            in_real_runner: false,
            violations: Vec::new(),
        };
        visitor.visit_file(&syntax);
        violations.extend(visitor.violations);
    }
    assert!(
        violations.is_empty(),
        "raw process calls remain:\n{}",
        violations.join("\n")
    );
    let image = fs::read_to_string(root.join("crates/nau-image/src/image/mod.rs")).unwrap();
    assert!(image.contains("RealRunner as ImageTools"));
    assert!(image.contains("runner: &dyn CommandRunner"));
    assert!(image.contains("build_image_with(\n        &ImageTools,"));
}

fn live_test_lock() -> MutexGuard<'static, ()> {
    LIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

fn live_governor() -> Option<ConfigGuard> {
    if let Some(reason) = governor::degrade_reason() {
        eprintln!("skipping: resource governor unavailable ({reason:?})");
        return None;
    }
    let guard = governor::configure(ResourceLimit::DEFAULT);
    if let Some(reason) = governor::degrade_reason() {
        eprintln!("skipping: resource governor unavailable ({reason:?})");
        drop(guard);
        return None;
    }
    Some(guard)
}

fn governed_test_child(limit: Option<&str>, duration: Duration) -> KillOnDrop {
    let command = test_child_command(limit, duration);
    KillOnDrop(governor::spawn(command).expect("governor starts the test child"))
}

fn ungoverned_test_child(limit: Option<&str>, duration: Duration) -> KillOnDrop {
    let mut command = test_child_command(limit, duration);
    KillOnDrop(command.spawn().expect("starts the peer test process"))
}

fn test_child_command(limit: Option<&str>, duration: Duration) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test binary path is available"));
    command
        .args([
            "--exact",
            "resource_governor_child_waits_when_started_as_a_probe",
            "--nocapture",
        ])
        .env(CHILD_SLEEP_ENV, duration.as_millis().to_string());
    if let Some(limit) = limit {
        command.env(CHILD_LIMIT_ENV, limit);
    }
    command
}

fn child_cgroup(pid: u32) -> Option<PathBuf> {
    let body = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let relative = body.lines().find_map(|line| line.strip_prefix("0::"))?;
    Some(Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/')))
}

fn claim_directory() -> PathBuf {
    let uid = unsafe { libc::getuid() };
    if uid == 0 {
        return PathBuf::from("/run/nau/governors");
    }
    let runtime = PathBuf::from(format!("/run/user/{uid}"));
    if fs::metadata(&runtime).is_ok() {
        runtime.join("nau/governors")
    } else {
        PathBuf::from(format!("/tmp/nau-governors-{uid}"))
    }
}

fn claim_path(pid: u32) -> PathBuf {
    claim_directory().join(pid.to_string())
}

fn wait_for_claim(pid: u32, expected: bool) {
    let path = claim_path(pid);
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if path.exists() == expected {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(path.exists(), expected, "claim state at {}", path.display());
}

fn assert_cpu_max_matches_claims(cgroup: &Path) {
    let effective = fs::read_dir(claim_directory())
        .expect("claim directory is readable")
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
                .and_then(|_| fs::read_to_string(entry.path()).ok())
        })
        .filter_map(|body| body.split_whitespace().next()?.parse::<u8>().ok())
        .min()
        .expect("at least one live claim exists");
    let limit = ResourceLimit::resolve(Some(&effective.to_string()), None).unwrap();
    let percent = limit.percent().expect("claim stores a percentage");
    assert_eq!(
        fs::read_to_string(cgroup.join("cpu.max")).unwrap().trim(),
        CpuMax::from_machine(percent, online_cpus()).file_text()
    );
}

fn online_cpus() -> NonZeroU32 {
    let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    NonZeroU32::new(u32::try_from(count).expect("online CPU count fits u32"))
        .expect("online CPU count is positive")
}

fn collect_rust_files(directory: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "tests") {
                continue;
            }
            collect_rust_files(&path, files)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

struct ProcessCallVisitor {
    path: String,
    function: Option<String>,
    in_real_runner: bool,
    violations: Vec<String>,
}

impl ProcessCallVisitor {
    fn is_allowed(&self, method: &str) -> bool {
        if self
            .path
            .ends_with("crates/nau-infra/src/governor/process.rs")
        {
            return matches!(
                (self.function.as_deref(), method),
                (Some("spawn"), "spawn") | (Some("status"), "status") | (Some("output"), "output")
            );
        }
        if self.path.ends_with("crates/nau-infra/src/command.rs") && self.in_real_runner {
            return method == "output";
        }
        self.path.ends_with("crates/nau-build/src/snap.rs")
            && self.function.as_deref() == Some("detect_bwrap")
            && method == "output"
    }

    fn visit_function(&mut self, name: String, visit: impl FnOnce(&mut Self)) {
        let previous = self.function.replace(name);
        visit(self);
        self.function = previous;
    }
}

impl<'ast> Visit<'ast> for ProcessCallVisitor {
    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        if !is_test_only(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        if !is_test_only(&item.attrs) {
            self.visit_function(item.sig.ident.to_string(), |visitor| {
                syn::visit::visit_item_fn(visitor, item)
            });
        }
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        if is_test_only(&item.attrs) {
            return;
        }
        let previous = self.in_real_runner;
        self.in_real_runner |= matches!(
            &*item.self_ty,
            Type::Path(path)
                if path.path.segments.last().is_some_and(|segment| segment.ident == "RealRunner")
        );
        syn::visit::visit_item_impl(self, item);
        self.in_real_runner = previous;
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        if !is_test_only(&item.attrs) {
            self.visit_function(item.sig.ident.to_string(), |visitor| {
                syn::visit::visit_impl_item_fn(visitor, item)
            });
        }
    }

    fn visit_expr_method_call(&mut self, expression: &'ast ExprMethodCall) {
        let method = expression.method.to_string();
        if matches!(method.as_str(), "spawn" | "status" | "output") && !self.is_allowed(&method) {
            self.violations
                .push(format!("{}: raw .{method}()", self.path));
        }
        syn::visit::visit_expr_method_call(self, expression);
    }
}

fn is_test_only(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        matches!(
            &attribute.meta,
            Meta::List(list) if list.path.is_ident("cfg") && list.tokens.to_string() == "test"
        )
    })
}
