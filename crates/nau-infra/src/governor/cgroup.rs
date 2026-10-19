use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::num::{NonZeroU32, NonZeroUsize};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use nau_core::resource_limit::{CpuMax, DegradeReason, MachinePercent, ResourceLimit};

use super::state::Configured;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CLAIM_SUBDIR: &str = "nau/governors";
const CHILD_CGROUP: &str = "nau-build";

static WARNED_DEGRADE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static WARNED_OFF: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(super) struct Placement {
    pub(super) parent: PathBuf,
    pub(super) online_cpus: NonZeroU32,
}

pub(super) struct ReconcileError {
    pub(super) reason: DegradeReason,
    pub(super) cgroup: Option<PathBuf>,
}

struct Claim {
    pid: u32,
    starttime: u64,
    percent: MachinePercent,
}

struct ClaimLock(File);

impl ClaimLock {
    fn acquire(directory: &Path) -> io::Result<Self> {
        let file = File::open(directory)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(file))
    }
}

impl Drop for ClaimLock {
    fn drop(&mut self) {
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub(super) fn warn_degraded(limit: ResourceLimit, reason: DegradeReason) {
    if WARNED_DEGRADE.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let percent = limit.percent().map_or(0, MachinePercent::get);
    eprintln!(
        "resource limit {percent}% not applied ({}); this build is uncapped",
        degrade_description(reason)
    );
}

pub(super) fn warn_off() {
    if !WARNED_OFF.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!("resource limit is off; build children are uncapped");
    }
}

pub(super) fn degrade(mut configured: Configured, reason: DegradeReason) -> Configured {
    configured.degrade = Some(reason);
    configured
}

pub(super) fn prepare_claim_directory() -> io::Result<PathBuf> {
    let uid = unsafe { libc::getuid() };
    let directory = if uid == 0 {
        PathBuf::from("/run/nau/governors")
    } else {
        let runtime = PathBuf::from(format!("/run/user/{uid}"));
        match fs::metadata(&runtime) {
            Ok(metadata) if metadata.is_dir() => runtime.join(CLAIM_SUBDIR),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    runtime.display().to_string(),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                PathBuf::from(format!("/tmp/nau-governors-{uid}"))
            }
            Err(error) => return Err(error),
        }
    };
    fs::create_dir_all(&directory)?;
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "claim directory must be owned by this uid",
        ));
    }
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    Ok(directory)
}

pub(super) fn write_claim(
    directory: &Path,
    pid: u32,
    starttime: u64,
    percent: MachinePercent,
    generation: u64,
) -> io::Result<()> {
    let temporary = directory.join(format!(".{pid}.{starttime}.{generation}.tmp"));
    let final_path = directory.join(pid.to_string());
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        writeln!(file, "{}\n{starttime}", percent.get())?;
        fs::rename(&temporary, &final_path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

pub(super) fn discover_placement() -> Result<Placement, DegradeReason> {
    let cgroup_file =
        fs::read_to_string("/proc/self/cgroup").map_err(|_| DegradeReason::NoCgroupV2)?;
    let path = cgroup_file
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or(DegradeReason::NoCgroupV2)?;
    let relative = Path::new(path.trim_start_matches('/'));
    if relative
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(DegradeReason::NoCgroupV2);
    }
    let root = Path::new(CGROUP_ROOT);
    let current = root.join(relative);
    let controllers = fs::read_to_string(current.join("cgroup.controllers"))
        .map_err(|_| DegradeReason::NoCpuController)?;
    if !has_controller(&controllers, "cpu") {
        return Err(DegradeReason::NoCpuController);
    }
    let online_cpus = online_cpu_count().ok_or(DegradeReason::CpuCountUnknown)?;
    let mut ancestors = Vec::new();
    let mut ancestor = current.as_path();
    while ancestor.starts_with(root) {
        ancestors.push(ancestor.to_path_buf());
        let Some(parent) = ancestor.parent() else {
            break;
        };
        ancestor = parent;
    }
    ancestors.reverse();
    ancestors
        .into_iter()
        .find(|parent| {
            fs::read_to_string(parent.join("cgroup.subtree_control"))
                .is_ok_and(|enabled| has_controller(&enabled, "cpu"))
                && can_create_child(parent)
        })
        .map(|parent| Placement {
            parent,
            online_cpus,
        })
        .ok_or(DegradeReason::NoWritableParent)
}

fn has_controller(controllers: &str, expected: &str) -> bool {
    controllers
        .split_whitespace()
        .any(|controller| controller.trim_start_matches('+') == expected)
}

fn can_create_child(path: &Path) -> bool {
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::W_OK | libc::X_OK,
            libc::AT_EACCESS,
        ) == 0
    }
}

fn online_cpu_count() -> Option<NonZeroU32> {
    let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    NonZeroU32::new(u32::try_from(count).ok()?)
}

fn create_child_cgroup(parent: &Path) -> io::Result<PathBuf> {
    let child = parent.join(CHILD_CGROUP);
    match fs::create_dir(&child) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(&child)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "nau-build cgroup path is not a directory",
        ));
    }
    Ok(child)
}

pub(super) fn process_starttime(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat_fields(&stat)?.1
}

fn process_parent(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    Some(stat_fields(&stat)?.0)
}

fn stat_fields(stat: &str) -> Option<(u32, Option<u64>)> {
    let (_, fields) = stat.rsplit_once(')')?;
    let fields = fields.split_whitespace().collect::<Vec<_>>();
    let parent = fields.get(1)?.parse().ok()?;
    let starttime = fields.get(19)?.parse().ok();
    Some((parent, starttime))
}

fn read_claim(path: &Path, pid: u32) -> Option<Claim> {
    let body = fs::read_to_string(path).ok()?;
    let mut fields = body.split_whitespace();
    let limit = ResourceLimit::resolve(Some(fields.next()?), None).ok()?;
    let percent = limit.percent()?;
    let starttime = fields.next()?.parse().ok()?;
    if fields.next().is_some() {
        return None;
    }
    Some(Claim {
        pid,
        starttime,
        percent,
    })
}

fn sweep_claims(directory: &Path) -> io::Result<(Vec<Claim>, usize)> {
    let mut live = Vec::new();
    let mut removed = 0;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            if name.starts_with('.') {
                // A crash between create and rename can leave a temp behind.
                let _ = fs::remove_file(entry.path());
            }
            continue;
        };
        let path = entry.path();
        let claim = read_claim(&path, pid);
        if let Some(claim) = claim.filter(|claim| process_starttime(pid) == Some(claim.starttime)) {
            live.push(claim);
        } else {
            match fs::remove_file(path) {
                Ok(()) => removed += 1,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok((live, removed))
}

pub(super) fn reconcile_added_claim(
    directory: &Path,
    parent: &Path,
    online_cpus: NonZeroU32,
    pid: u32,
    starttime: u64,
) -> Result<(PathBuf, bool), ReconcileError> {
    let _lock = ClaimLock::acquire(directory).map_err(|_| ReconcileError {
        reason: DegradeReason::NoWritableParent,
        cgroup: None,
    })?;
    let (claims, removed) = sweep_claims(directory).map_err(|_| ReconcileError {
        reason: DegradeReason::NoWritableParent,
        cgroup: None,
    })?;
    if !claims
        .iter()
        .any(|claim| claim.pid == pid && claim.starttime == starttime)
    {
        return Err(ReconcileError {
            reason: DegradeReason::NoWritableParent,
            cgroup: None,
        });
    }
    let recovered = removed > 0 && claims.iter().all(|claim| claim.pid == pid);
    let percent = minimum_percent(&claims).ok_or(ReconcileError {
        reason: DegradeReason::NoWritableParent,
        cgroup: None,
    })?;
    let cgroup = create_child_cgroup(parent).map_err(|_| ReconcileError {
        reason: DegradeReason::NoWritableParent,
        cgroup: None,
    })?;
    write_cpu_max(&cgroup, CpuMax::from_machine(percent, online_cpus)).map_err(|_| {
        ReconcileError {
            reason: DegradeReason::NoWritableParent,
            cgroup: Some(cgroup.clone()),
        }
    })?;
    Ok((cgroup, recovered))
}

fn minimum_percent(claims: &[Claim]) -> Option<MachinePercent> {
    claims
        .iter()
        .map(|claim| claim.percent)
        .min_by_key(|p| p.get())
}

fn write_cpu_max(cgroup: &Path, cpu_max: CpuMax) -> io::Result<()> {
    fs::write(cgroup.join("cpu.max"), format!("{}\n", cpu_max.file_text()))
}

pub(super) fn warn_previous_processes(cgroup: &Path) {
    if let Ok(pids) = read_cgroup_procs(cgroup) {
        if !pids.is_empty() {
            eprintln!(
                "nau-build still holds {} processes from a previous run; they share this run's quota",
                pids.len()
            );
        }
    }
}

pub(super) fn release_config(configured: Configured) {
    let Some(directory) = configured.claim_directory else {
        return;
    };
    let cgroup = configured.cgroup;
    let online_cpus = configured.online_cpus;
    let pid = std::process::id();
    let result = (|| {
        let _lock = ClaimLock::acquire(&directory)?;
        match fs::remove_file(directory.join(pid.to_string())) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let (claims, _) = sweep_claims(&directory)?;
        let Some(cgroup) = cgroup else {
            return Ok(());
        };
        if let Some(percent) = minimum_percent(&claims) {
            if let Some(online_cpus) = online_cpus {
                write_cpu_max(&cgroup, CpuMax::from_machine(percent, online_cpus))?;
            }
        } else {
            remove_empty_cgroup(&cgroup, pid)?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("resource governor cleanup failed: {error}");
    }
}

fn remove_empty_cgroup(cgroup: &Path, pid: u32) -> io::Result<()> {
    let pids = read_cgroup_procs(cgroup)?;
    if pids.is_empty() {
        match fs::remove_dir(cgroup) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        return Ok(());
    }
    let own_children = pids
        .iter()
        .filter(|child| process_parent(**child) == Some(pid))
        .count();
    let previous = pids.len() - own_children;
    if previous > 0 {
        eprintln!(
            "nau-build still holds {previous} processes from a previous run; leaving the cgroup in place"
        );
    }
    if own_children > 0 {
        eprintln!(
            "nau-build still holds {own_children} child processes at drop; leaving the cgroup in place"
        );
    }
    Ok(())
}

fn read_cgroup_procs(cgroup: &Path) -> io::Result<Vec<u32>> {
    fs::read_to_string(cgroup.join("cgroup.procs"))?
        .lines()
        .map(|line| {
            line.parse::<u32>()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
        })
        .collect()
}

pub(super) fn read_quota_cores(path: &Path) -> Option<NonZeroUsize> {
    let text = fs::read_to_string(path).ok()?;
    let mut fields = text.split_whitespace();
    let quota = fields.next()?;
    if quota == "max" {
        return None;
    }
    let quota = quota.parse::<u64>().ok()?;
    let period = fields.next()?.parse::<u64>().ok()?;
    if period == 0 {
        return None;
    }
    let cores = usize::try_from((quota / period).max(1)).ok()?;
    NonZeroUsize::new(cores)
}

pub(super) fn degrade_description(reason: DegradeReason) -> &'static str {
    match reason {
        DegradeReason::NoCgroupV2 => "cgroup v2 is unavailable",
        DegradeReason::NoCpuController => "the cpu controller is unavailable",
        DegradeReason::NoWritableParent => "no writable cpu cgroup parent exists",
        DegradeReason::CpuCountUnknown => "the online cpu count is unknown",
    }
}
