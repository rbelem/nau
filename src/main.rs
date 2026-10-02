//! The `nau` binary entry (#313): parse the CLI and dispatch to the
//! library. Orchestration lives in library modules (`nau::build_orch`,
//! `nau::farm_dispatch`, `nau::commands`) — this file is a thin match
//! over the CLI enum (ADR-0051 sequencing, #313).

use clap::Parser;
use nau::cli::{
    normalize_domain, AuditArgs, CheckArgs, Cli, Command, DepsCommand, EvalArgs, ExportArgs,
    ImageArgs, LintArgs, LockArgs, PeersArgs, PullArgs, PushArgs, RunArgs, SearchArgs, ServeArgs,
    TestArgs, VerifyImageArgs, VersionsArgs,
};

fn main() -> miette::Result<()> {
    let cli = Cli::parse();

    match normalize_domain(cli.command) {
        Command::Build { args, .. } => nau::commands::build_command(args),

        Command::Image {
            args:
                ImageArgs {
                    file,
                    output,
                    arch,
                    channel,
                    cache,
                    cache_max_size,
                    output_name,
                    source_date_epoch,
                    release,
                    lockfile: lockfile_path,
                    json,
                },
            ..
        } => {
            nau::output::set_mode(json);
            let r = nau::commands::cmd_image(
                file,
                output,
                arch,
                channel,
                cache,
                cache_max_size,
                output_name,
                source_date_epoch,
                release,
                lockfile_path,
                json,
            );
            nau::output::flush_json("image");
            r
        }

        Command::VerifyImage(VerifyImageArgs {
            device,
            manifest,
            key,
            slot,
            json,
        }) => {
            nau::output::set_mode(json);
            nau::commands::cmd_verify_image(&device, &manifest, key.as_deref(), slot, json)
        }

        Command::Deps(sub) => match sub {
            DepsCommand::Show {
                package,
                recursive,
                tree,
                flat,
                json,
            } => {
                nau::output::set_mode(json);
                let r = nau::commands::cmd_deps(package, recursive, tree, flat, json);
                nau::output::flush_json("deps");
                r
            }
            DepsCommand::Fetch {
                name,
                root,
                latest,
                json,
            } => {
                nau::output::set_mode(json);
                let r = nau::commands::cmd_deps_fetch(name.as_deref(), root.as_deref(), latest);
                nau::output::flush_json("deps");
                r
            }
        },

        Command::Search(SearchArgs { query, json }) => {
            nau::output::set_mode(json);
            nau::commands::cmd_search(&query, json);
            Ok(())
        }

        Command::Index(sub) => nau::commands::cmd_index(sub),

        Command::Doctor {
            pod,
            fix,
            from,
            verify,
        } => nau::commands::cmd_doctor(pod, fix, from.as_deref(), verify),

        Command::Check(CheckArgs { file, json }) => {
            nau::output::set_mode(json);
            nau::commands::cmd_check(&file, json)
        }

        Command::Lint(LintArgs {
            file,
            pod,
            channel,
            json,
        }) => nau::commands::cmd_lint(file, pod, channel, json),

        Command::Audit(AuditArgs {
            file,
            lockfile,
            update,
            json,
        }) => nau::commands::cmd_audit(file, lockfile, update, json),

        Command::Lock(LockArgs {
            file,
            lockfile,
            json,
        }) => {
            nau::output::set_mode(json);
            nau::commands::cmd_lock(file, lockfile)
        }

        Command::Eval(EvalArgs {
            file,
            output,
            output_name,
            arch,
            channel,
            lockfile: lockfile_path,
            offline,
            json,
        }) => {
            nau::output::set_mode(json);
            if offline {
                std::env::set_var("NAU_OFFLINE", "1");
            }
            nau::commands::cmd_eval(
                file,
                output,
                output_name,
                arch,
                channel,
                lockfile_path,
                offline,
            )
        }

        Command::Versions(VersionsArgs { file, output, json }) => {
            nau::commands::cmd_versions(&file, output.as_deref(), json)
        }

        Command::Completion { shell } => nau::commands::cmd_completion(shell),

        Command::Cache(sub) => nau::commands::cmd_cache(sub),

        Command::Key(sub) => nau::commands::cmd_key(sub),

        Command::Ca(sub) => nau::commands::cmd_ca(sub),

        Command::Runtime(sub) => nau::commands::cmd_runtime(sub),

        Command::Pod { name, command } => nau::commands::cmd_pod(name.as_deref(), command),

        Command::Run {
            args:
                RunArgs {
                    app,
                    pod,
                    root,
                    app_args,
                },
        } => nau::commands::cmd_run(pod.as_deref(), root.as_deref(), app.as_deref(), &app_args),

        Command::Test(TestArgs {
            image,
            timeout,
            accel,
            log,
            require,
            firmware_dir,
            runs,
            expect_counter_seq,
            allow_no_completion,
            qemu_args,
            json,
        }) => {
            nau::output::set_mode(json);
            nau::commands::cmd_test(
                image,
                timeout,
                accel,
                log,
                require,
                firmware_dir,
                runs,
                expect_counter_seq,
                allow_no_completion,
                qemu_args,
                json,
            )
        }

        Command::Push(PushArgs {
            reference,
            dir,
            snap,
            image,
            tag,
            username,
            password_stdin,
            insecure_http,
            mount_from,
            record,
            json,
        }) => {
            nau::output::set_mode(json);
            nau::commands::cmd_push(
                &reference,
                &dir,
                &snap,
                &image,
                tag.as_deref(),
                username.as_deref(),
                password_stdin,
                insecure_http,
                mount_from.as_deref(),
                record.as_deref(),
            )
        }

        Command::Pull(PullArgs {
            reference,
            out_dir,
            username,
            password_stdin,
            insecure_http,
            expect,
            install,
            state_dir,
            pod,
            allow_downgrade,
            json,
        }) => {
            nau::output::set_mode(json);
            nau::commands::run_pull(
                &reference,
                out_dir,
                username.as_deref(),
                password_stdin,
                insecure_http,
                expect.as_deref(),
                install,
                state_dir,
                pod.as_deref(),
                allow_downgrade,
            )
        }

        Command::Serve(ServeArgs {
            address,
            port,
            announce,
            pod,
            token_file,
            queue_dir,
        }) => nau::commands::cmd_serve(
            address.as_deref(),
            port,
            announce,
            pod.as_deref(),
            token_file.as_deref(),
            queue_dir.as_deref(),
        ),

        Command::BuildRequest { command } => match command {
            nau::cli::BuildRequestCommand::Submit(args) => {
                nau::commands::cmd_build_request_submit(&args)
            }
            nau::cli::BuildRequestCommand::Run(args) => nau::commands::cmd_build_request_run(&args),
        },

        Command::Peers(PeersArgs { secs, json }) => {
            nau::output::set_mode(json);
            nau::commands::cmd_peers(secs)
        }

        Command::Export(ExportArgs {
            out,
            pod,
            mission,
            file,
        }) => nau::commands::cmd_export(&out, pod.as_deref(), mission.as_deref(), file.as_deref()),

        Command::EvalWorker => nau::isolate::worker_main(),

        Command::CheckWorker => nau::isolate::check_worker_main(),

        Command::WorkerCap => nau::worker::cap_main(),

        Command::WorkerJob { job_file } => nau::worker::job_main(&job_file),

        Command::Workers { command } => nau::provision::workers_main(command),

        // External fallthrough (ADR-0049 Decision 5): reachable only
        // when no real variant matched — run_external validates the
        // verb charset and resolves `nau-<verb>` (exe-dir sibling,
        // then PATH) before exec'ing it.
        Command::External(argv) => nau::cli::run_external(&argv),

        // Unreachable: normalize_domain folds every ADR-0049 namespace
        // group onto the legacy variants above. Kept for match
        // exhaustiveness.
        Command::Chart { .. }
        | Command::Ship { .. }
        | Command::Peer { .. }
        | Command::Trust { .. }
        | Command::Pool { .. } => unreachable!("normalize_domain folds the namespace groups"),
    }
}
