//! The root CLI shim over the pool domain's provisioning lane (issue
//! #326 PR 9). The verb BODIES — providers, the publish/issue/pickup
//! ceremony, the burst window, the managed-block machinery, the
//! shared user-data template — moved to [`nau_pool::provision`]; this
//! file keeps the clap-typed dispatch (`workers_main`, called by
//! `main.rs` with an unchanged signature) and the burst-count
//! resolution glue, which stays root because its `--count auto` arm
//! reads the wrapped build through the root's
//! [`crate::farm_dispatch`]. Everything the library and the
//! integration tests reference is re-exported unchanged, so every
//! `crate::provision::` and `nau::provision::` path keeps resolving.

// The whole pool provision surface: the verb bodies, the provider
// modules, the publish ceremony, the wire-stable pins, and the request/
// plan vocabulary. A glob (not a list) so the re-export can never
// silently lag the moved surface the tests exercise.
pub use nau_pool::provision::*;

use crate::cli::{
    WorkersBurstArgs, WorkersCommand, WorkersDestroyArgs, WorkersDownArgs, WorkersIssueArgs,
    WorkersPickupArgs, WorkersProvisionArgs,
};

/// CLI entry for `nau workers provision` / `nau workers destroy` /
/// `nau workers receive-publish`. The clap grammar stays root; every arm
/// forwards its scalars to the pool verb body. Burst sizing (#304) calls
/// the library's own wrapped-build helper — since #313 the orchestration
/// lives in the library, so there is nothing left to inject.
pub fn workers_main(command: WorkersCommand) -> miette::Result<()> {
    match command {
        WorkersCommand::Provision(args) => {
            let WorkersProvisionArgs {
                provider,
                server_type,
                location,
                count,
                ttl,
                spot,
                max_price,
                preemptible,
                dry_run,
                file,
            } = args;
            nau_pool::provision::provision_verb(
                &provider,
                server_type,
                location,
                count,
                &ttl,
                spot,
                preemptible,
                max_price,
                dry_run,
                &file,
            )
        }
        WorkersCommand::Destroy(args) => {
            let WorkersDestroyArgs {
                provider,
                name,
                file,
            } = args;
            nau_pool::provision::destroy_verb(&provider, &name, &file)
        }
        WorkersCommand::ReceivePublish => nau_pool::provision::receive_publish_main(),
        WorkersCommand::Issue(args) => {
            let WorkersIssueArgs {
                home,
                identity,
                validity,
                force,
                json,
                wait,
                timeout,
            } = args;
            nau_pool::provision::issue_main(
                home,
                identity.as_deref(),
                &validity,
                force,
                json,
                wait,
                timeout,
            )
        }
        WorkersCommand::Pickup(args) => {
            let WorkersPickupArgs { home } = args;
            nau_pool::provision::pickup_main(home)
        }
        WorkersCommand::Burst(args) => {
            let WorkersBurstArgs {
                provider,
                server_type,
                location,
                count,
                max,
                ttl,
                timeout,
                keep,
                file,
                command,
            } = args;
            let count = resolve_burst_count(count, max, &command)?;
            nau_pool::provision::burst_main(
                &provider,
                server_type,
                location,
                count,
                &ttl,
                timeout,
                keep,
                &file,
                command,
            )
        }
        WorkersCommand::Down(args) => {
            let WorkersDownArgs { provider, file, .. } = args;
            nau_pool::provision::down_all_managed_main(&provider, &file)
        }
    }
}

/// The burst's worker count (#304): an explicit `--count` keeps the
/// `--max` guard; `auto` sizes from the wrapped build's pending jobs.
/// Both land BEFORE any API call — a refused burst must never
/// provision, never pin, never bill. This glue stays root because the
/// Auto arm reads the wrapped build through the root's
/// [`crate::farm_dispatch`]; the arithmetic halves
/// ([`refuse_burst_above_max`], [`burst_auto_count`]) are pool
/// re-exports.
fn resolve_burst_count(
    count: crate::cli::BurstCount,
    max: u32,
    command: &[String],
) -> miette::Result<u32> {
    match count {
        crate::cli::BurstCount::Fixed(n) => {
            refuse_burst_above_max(n, max)?;
            Ok(n)
        }
        crate::cli::BurstCount::Auto => {
            let (pending, jobs_per_worker) =
                crate::farm_dispatch::wrapped_build_pending_jobs(command)?;
            burst_auto_count(pending, jobs_per_worker, max)
        }
    }
}
