use super::*;

    /// Diamond a→(b,c)→d: d must start only after BOTH b and c finished,
    /// and b/c (ready together) must actually overlap.
    #[test]
    fn ready_set_wakes_dependents_on_completion() {
        let log = Log::new();
        let g = graph(&[("a", &[]), ("b", &["a"]), ("c", &["a"]), ("d", &["b", "c"])]);
        let l = log.clone();
        run_ready_set(&g, &HashSet::new(), 3, move |name| {
            l.start(name);
            match name {
                "b" | "c" => sleep_ms(120),
                _ => sleep_ms(10),
            }
            l.end(name);
            Ok(())
        })
        .expect("diamond builds clean");

        let events = log.events();
        // b and c overlapped (two jobs in flight while the cap is 3).
        assert!(
            log.max_inflight.load(Ordering::SeqCst) >= 2,
            "ready siblings must overlap: {events:?}"
        );
        // d wakes only after both siblings end.
        let d_start = log.position("start:d");
        assert!(log.position("end:b") < d_start, "{events:?}");
        assert!(log.position("end:c") < d_start, "{events:?}");
    }

    /// Linear chain: every node starts strictly after its dep ends.
    #[test]
    fn ready_set_orders_linear_chain() {
        let log = Log::new();
        let g = graph(&[("a", &[]), ("b", &["a"]), ("c", &["b"])]);
        let l = log.clone();
        run_ready_set(&g, &HashSet::new(), 3, move |name| {
            l.start(name);
            sleep_ms(30);
            l.end(name);
            Ok(())
        })
        .expect("chain builds clean");
        assert!(log.position("end:a") < log.position("start:b"));
        assert!(log.position("end:b") < log.position("start:c"));
    }

    /// Worker cap: 6 independent jobs on 2 workers — never more than 2 in
    /// flight, and really 2 (not a serialized queue).
    #[test]
    fn worker_cap_bounds_concurrency() {
        let log = Log::new();
        let g = graph(&[
            ("j1", &[]),
            ("j2", &[]),
            ("j3", &[]),
            ("j4", &[]),
            ("j5", &[]),
            ("j6", &[]),
        ]);
        let l = log.clone();
        run_ready_set(&g, &HashSet::new(), 2, move |name| {
            l.start(name);
            sleep_ms(60);
            l.end(name);
            Ok(())
        })
        .expect("independent jobs build clean");
        assert_eq!(log.max_inflight.load(Ordering::SeqCst), 2);
    }

    /// A failed node fails its dependents fast: they never start, the
    /// failed set is named with its error, and unrelated completed nodes
    /// are not reported as skipped.
    #[test]
    fn failure_never_starts_dependents() {
        let log = Log::new();
        let g = graph(&[("a", &[]), ("b", &["a"]), ("c", &["b"]), ("solo", &[])]);
        let l = log.clone();
        let out = run_ready_set(&g, &HashSet::new(), 3, move |name| {
            l.start(name);
            sleep_ms(30);
            if name == "a" {
                // "a" fails without recording a clean end.
                return Err("a exploded".to_string());
            }
            l.end(name);
            Ok(())
        });
        let err = out.expect_err("failed root must fail the run");
        assert_eq!(
            err.failed,
            vec![("a".to_string(), "a exploded".to_string())]
        );
        // Dependents never started; unrelated "solo" is done, not skipped.
        let events = log.events();
        assert!(!events.iter().any(|e| e == "start:b"), "{events:?}");
        assert!(!events.iter().any(|e| e == "start:c"), "{events:?}");
        assert!(events.iter().any(|e| e == "end:solo"), "{events:?}");
        assert_eq!(err.skipped, vec!["b".to_string(), "c".to_string()]);
    }

    /// Stop-the-world: with 1 worker and an early failure, ready-but-
    /// unstarted nodes are skipped, not built.
    #[test]
    fn failure_stops_unstarted_ready_work() {
        let log = Log::new();
        let g = graph(&[("j1", &[]), ("j2", &[]), ("j3", &[]), ("j4", &[])]);
        let l = log.clone();
        let out = run_ready_set(&g, &HashSet::new(), 1, move |name| {
            l.start(name);
            if name == "j1" {
                return Err("j1 exploded".to_string());
            }
            l.end(name);
            Ok(())
        });
        let err = out.expect_err("first failure must fail the run");
        assert_eq!(err.failed.len(), 1);
        assert_eq!(err.skipped, vec!["j2", "j3", "j4"]);
        // Exactly one job ever started.
        assert_eq!(
            log.events()
                .iter()
                .filter(|e| e.starts_with("start:"))
                .count(),
            1
        );
    }

    /// Pre-done (cached) nodes complete before scheduling and release
    /// their dependents immediately.
    #[test]
    fn pre_done_releases_dependents_immediately() {
        let log = Log::new();
        let g = graph(&[("a", &[]), ("b", &["a"]), ("c", &["b"])]);
        let pre: HashSet<String> = ["a".to_string(), "b".to_string()].into();
        let l = log.clone();
        run_ready_set(&g, &pre, 3, move |name| {
            l.start(name);
            l.end(name);
            Ok(())
        })
        .expect("pre-done cascade builds clean");
        let events = log.events();
        assert_eq!(events, vec!["start:c".to_string(), "end:c".to_string()]);
    }

    /// Edges to unknown targets and duplicate/self edges are ignored, and
    /// a cycle is reported as unschedulable instead of hanging.
    #[test]
    fn unknown_and_self_edges_are_dropped_and_cycles_are_named() {
        let log = Log::new();
        let g = graph(&[("a", &["a", "ghost", "a", "b"]), ("b", &["b", "a"])]);
        let l = log.clone();
        let out = run_ready_set(&g, &HashSet::new(), 2, move |name| {
            l.start(name);
            l.end(name);
            Ok(())
        });
        let err = out.expect_err("a cycle cannot be scheduled");
        assert!(err.failed.is_empty());
        assert_eq!(err.skipped, vec!["a".to_string(), "b".to_string()]);
    }

    /// The loss/build class keys on the typed ChannelLoss payload found
    /// through the error chain — never on message wording (#193 review
    /// F3). Pinned here beside [`classify_transport`]:
    ///
    /// * the exact leaf shape `run_ssh` emits for a dead channel, under
    ///   the contexts `dispatch` wraps it in, classifies LOST;
    /// * a build refusal whose text MIMICS the old channel-death wording
    ///   (remote-controlled result error — the injection the previous
    ///   string match allowed) stays BUILD;
    /// * a capability preflight refusal stays BUILD.
    #[test]
    fn transport_class_keys_on_the_typed_channel_loss_not_wording() {
        let dead_channel = miette::Error::new(crate::ssh_exec::ChannelLoss(
            "ssh to 'nuci.local' failed (code 255): Connection closed by remote host".to_string(),
        ))
        .wrap_err("preflight reachability")
        .wrap_err("dispatch failed on worker 'nuci.local' for job jm1_dead");
        assert!(
            matches!(classify_transport(&dead_channel), JobFailure::Lost(_)),
            "a typed channel death classifies LOST: {dead_channel:#}"
        );

        let injected = miette::miette!(
            "job jm1_x failed on worker 'evil': ssh to 'evil' failed (code 255): \
             not actually a channel death"
        );
        assert!(
            matches!(classify_transport(&injected), JobFailure::Build(_)),
            "wording alone cannot fake a channel death: {injected:#}"
        );

        let build_refusal = miette::miette!(
            "dispatch: worker 'nuci.local' declares arch arm64 but the job targets amd64 — \
             the entry's arch override and the job target disagree"
        );
        assert!(matches!(
            classify_transport(&build_refusal),
            JobFailure::Build(_)
        ));
    }
