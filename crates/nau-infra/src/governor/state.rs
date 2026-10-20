use std::io;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::{Mutex, MutexGuard};

use nau_core::resource_limit::{DegradeReason, MachinePercent, ResourceLimit};

use super::cgroup;

static PROCESS: Mutex<ProcessState> = Mutex::new(ProcessState::new());

pub(super) struct ProcessState {
    generation: u64,
    pub(super) configured: Option<Configured>,
    worker_job: bool,
    auto_attempted: bool,
    auto_error: Option<String>,
}

impl ProcessState {
    const fn new() -> Self {
        Self {
            generation: 0,
            configured: None,
            worker_job: false,
            auto_attempted: false,
            auto_error: None,
        }
    }
}

pub(super) struct Configured {
    pub(super) limit: ResourceLimit,
    pub(super) claim_directory: Option<std::path::PathBuf>,
    pub(super) cgroup: Option<std::path::PathBuf>,
    pub(super) online_cpus: Option<NonZeroU32>,
    pub(super) degrade: Option<DegradeReason>,
}

impl Configured {
    fn without_claim(limit: ResourceLimit) -> Self {
        Self {
            limit,
            claim_directory: None,
            cgroup: None,
            online_cpus: None,
            degrade: None,
        }
    }
}

#[must_use]
pub struct ConfigGuard {
    generation: u64,
}

impl Drop for ConfigGuard {
    fn drop(&mut self) {
        let mut state = process_state();
        if state.generation != self.generation {
            return;
        }
        if let Some(configured) = state.configured.take() {
            cgroup::release_config(configured);
        }
    }
}

pub fn configure(limit: ResourceLimit) -> ConfigGuard {
    let mut state = process_state();
    state.auto_attempted = false;
    state.auto_error = None;
    let generation = configure_locked(&mut state, limit);
    ConfigGuard { generation }
}

pub fn enter_worker_job() {
    let mut state = process_state();
    state.worker_job = true;
    state.auto_attempted = false;
    state.auto_error = None;
}

pub fn configured_limit() -> Option<ResourceLimit> {
    process_state()
        .configured
        .as_ref()
        .map(|configured| configured.limit)
}

pub fn clamp_jobs(jobs: NonZeroUsize) -> NonZeroUsize {
    let _ = ensure_auto_configured();
    let state = process_state();
    let Some(configured) = state.configured.as_ref() else {
        return jobs;
    };
    if configured.degrade.is_some() || configured.limit == ResourceLimit::Off {
        return jobs;
    }
    let Some(cgroup) = configured.cgroup.as_ref() else {
        return jobs;
    };
    cgroup::read_quota_cores(&cgroup.join("cpu.max")).map_or(jobs, |limit| jobs.min(limit))
}

pub fn degrade_reason() -> Option<DegradeReason> {
    let state = process_state();
    if let Some(configured) = state.configured.as_ref() {
        return configured.degrade;
    }
    drop(state);
    cgroup::discover_placement().err()
}

pub(super) fn process_state() -> MutexGuard<'static, ProcessState> {
    PROCESS.lock().unwrap_or_else(|error| error.into_inner())
}

pub(super) fn ensure_auto_configured() -> io::Result<()> {
    let mut state = process_state();
    if state.configured.is_some() {
        return Ok(());
    }
    if state.auto_attempted {
        return state
            .auto_error
            .as_ref()
            .map(|error| io::Error::new(io::ErrorKind::InvalidInput, error.clone()))
            .map_or(Ok(()), Err);
    }
    state.auto_attempted = true;
    let env = if state.worker_job {
        None
    } else {
        std::env::var("NAU_RESOURCE_LIMIT").ok()
    };
    let limit = match ResourceLimit::resolve(None, env.as_deref()) {
        Ok(limit) => limit,
        Err(error) => {
            let message = error.to_string();
            state.auto_error = Some(message.clone());
            return Err(io::Error::new(io::ErrorKind::InvalidInput, message));
        }
    };
    configure_locked(&mut state, limit);
    Ok(())
}

fn configure_locked(state: &mut ProcessState, limit: ResourceLimit) -> u64 {
    state.generation = state.generation.wrapping_add(1);
    let generation = state.generation;
    let previous = state.configured.take();
    let configured = match limit {
        ResourceLimit::Off => {
            if let Some(previous) = previous {
                cgroup::release_config(previous);
            }
            cgroup::warn_off();
            Configured::without_claim(limit)
        }
        ResourceLimit::Percent(percent) => {
            let configured = configure_percent(limit, percent, generation);
            if previous
                .as_ref()
                .and_then(|value| value.claim_directory.as_ref())
                != configured.claim_directory.as_ref()
            {
                if let Some(previous) = previous {
                    cgroup::release_config(previous);
                }
            }
            if let Some(reason) = configured.degrade {
                cgroup::warn_degraded(limit, reason);
            }
            configured
        }
    };
    state.configured = Some(configured);
    generation
}

fn configure_percent(limit: ResourceLimit, percent: MachinePercent, generation: u64) -> Configured {
    let mut configured = Configured::without_claim(limit);
    let directory = match cgroup::prepare_claim_directory() {
        Ok(directory) => directory,
        Err(_) => return cgroup::degrade(configured, DegradeReason::NoWritableParent),
    };
    configured.claim_directory = Some(directory.clone());
    let pid = std::process::id();
    let starttime = match cgroup::process_starttime(pid) {
        Some(starttime) => starttime,
        None => return cgroup::degrade(configured, DegradeReason::NoWritableParent),
    };
    if cgroup::write_claim(&directory, pid, starttime, percent, generation).is_err() {
        return cgroup::degrade(configured, DegradeReason::NoWritableParent);
    }
    let placement = match cgroup::discover_placement() {
        Ok(placement) => placement,
        Err(reason) => return cgroup::degrade(configured, reason),
    };
    configured.online_cpus = Some(placement.online_cpus);
    match cgroup::reconcile_added_claim(
        &directory,
        &placement.parent,
        placement.online_cpus,
        pid,
        starttime,
    ) {
        Ok((cgroup_path, recovered)) => {
            configured.cgroup = Some(cgroup_path.clone());
            if recovered {
                cgroup::warn_previous_processes(&cgroup_path);
            }
            configured
        }
        Err(error) => {
            configured.cgroup = error.cgroup;
            cgroup::degrade(configured, error.reason)
        }
    }
}
