mod cgroup;
mod process;
mod state;

pub(crate) use process::attach_if_configured;
pub use process::{output, spawn, status};
pub use state::{
    clamp_jobs, configure, configured_limit, degrade_reason, enter_worker_job, ConfigGuard,
};
