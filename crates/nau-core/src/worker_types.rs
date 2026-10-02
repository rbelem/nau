//! The `workers` config value types (ADR-0040 Decision 3), moved DOWN
//! from `nau-chart::lua` (issue #326 PR 9): the pool domain's ssh_exec
//! and build_sched consume them, and a domain crate must not depend on
//! the chart. The Lua extraction (`FromLua`-style parsing) stays with
//! the chart, which re-exports both types.

use serde::{Deserialize, Serialize};

/// The `workers` config surface (ADR-0040 Decision 3): the coordinator's
/// own slot count plus the Worker entries, declared as one global table
/// in `nau.lua` — the array part holds the entries, the
/// `local_jobs` hash key holds the slot count. Absent entirely means
/// zero behavior change: no SSH, no sockets, no new code paths.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkersConfig {
    /// The coordinator's own build slots (today's
    /// `build_sched::MAX_PARALLEL_BUILD_WORKERS`, now config-driven).
    #[serde(default = "default_local_jobs")]
    pub local_jobs: u32,
    /// The Worker entries, in declaration order.
    #[serde(default)]
    pub workers: Vec<WorkerConfig>,
}

/// One Worker entry: where to reach it, how many concurrent jobs it
/// takes, and the arch override when the preflight probe must not be
/// trusted to match (ADR-0040 Decision 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerConfig {
    /// `ssh://[user@]host[:port]`.
    pub address: String,
    /// Max concurrent jobs on this machine (default 2).
    #[serde(default = "default_worker_jobs")]
    pub jobs: u32,
    /// GNU triplet override; probed via `__worker-cap` at preflight
    /// when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// The pinned SSH host identity (ADR-0045 Decision 4, as amended by
    /// #295): the host CA's `SHA256:` fingerprint (the `nau ca list`
    /// form) — the only pin form. The executor builds a nau-managed
    /// `@cert-authority` known_hosts entry from the ceremony CA whose
    /// fingerprint matches, scoped to the worker's certificate principals
    /// and connected under the provisioned machine identity. Pins are
    /// never learned: `StrictHostKeyChecking=yes` against the managed
    /// known_hosts, and preflight refuses a worker whose pin cannot be
    /// enforced by name. The retired mint-and-inject pin (a full
    /// public-key line) refuses at parse with the re-pin remedy. No
    /// `ssh-keyscan` path exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key: Option<String>,
    /// The client identity ssh presents to this worker (#298): the path
    /// of a private key, pinned so ambient `~/.ssh/config` cannot
    /// substitute its own `IdentityFile`. Absent = resolution falls to
    /// `NAU_SSH_IDENTITY`, then the operator's default key halves —
    /// the executor's resolution order, never ssh_config's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}

fn default_local_jobs() -> u32 {
    crate::MAX_PARALLEL_BUILD_WORKERS as u32
}

/// The default per-worker job count. Pub (unusual for a serde default)
/// because the chart's Lua-entry parser seeds the same default before
/// field overrides — one literal, two surfaces.
pub fn default_worker_jobs() -> u32 {
    2
}

impl Default for WorkersConfig {
    fn default() -> Self {
        WorkersConfig {
            local_jobs: default_local_jobs(),
            workers: Vec::new(),
        }
    }
}
