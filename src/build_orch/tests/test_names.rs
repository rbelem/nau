use super::*;

    #[test]
    fn test_names_default_stage_matches_spellings() {
        // Any spelling of the default — existing or not — must match:
        // a lock-holder's wipe window is exactly the existing case.
        assert!(names_default_stage(Path::new("./stage")));
        assert!(names_default_stage(Path::new("./stage/")));
        assert!(names_default_stage(Path::new("stage")));
        assert!(names_default_stage(Path::new("stage/.")));
        // Sibling names stay user-owned explicit stages.
        assert!(!names_default_stage(Path::new("./stage2")));
        assert!(!names_default_stage(Path::new("staging")));
        assert!(!names_default_stage(Path::new("/tmp/stage")));
    }

    #[test]
    fn test_resolve_stage_refuses_default_stage_spelling() {
        let err = resolve_stage(Some("./stage".to_string())).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("default stage"),
            "conflict with the default must be loud: {msg}"
        );
        assert!(
            msg.contains("--stage"),
            "error must point at the explicit-stage escape: {msg}"
        );

        // A distinct directory is still a fine explicit stage.
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("stage2");
        let (path, policy, lock) =
            resolve_stage(Some(other.to_string_lossy().into_owned())).unwrap();
        assert_eq!(path, other);
        assert_eq!(policy, crate::snap::StagePolicy::Explicit);
        assert!(lock.is_none(), "an explicit stage is never locked");
    }

    #[test]
    fn test_resolve_stage_explicit_takes_no_lock() {
        let dir = tempfile::tempdir().unwrap();
        let stage = dir.path().join("stg");
        std::fs::create_dir_all(&stage).unwrap();

        let (path, policy, lock) =
            resolve_stage(Some(stage.to_string_lossy().into_owned())).unwrap();
        assert_eq!(policy, crate::snap::StagePolicy::Explicit);
        assert_eq!(path, stage);
        // An explicit --stage is user-owned: no cross-process lock, and no
        // lock file appears next to it.
        assert!(lock.is_none());
        assert!(!dir.path().join("stg.lock").exists());
    }

    #[test]
    fn test_resolve_stage_default_pins_against_concurrent_build() {
        // Runs against the repo's ./stage/ (the real default): the lock
        // file it creates is gitignored. Only this test touches it.
        let (path, policy, lock) = resolve_stage(None).unwrap();
        assert_eq!(policy, crate::snap::StagePolicy::Default);
        assert_eq!(path, std::path::Path::new("./stage/"));
        assert!(lock.is_some(), "default stage must be pinned by a lock");

        // A second concurrent default-stage build refuses loudly instead
        // of silently sharing the stage (gate-pod gap 6).
        let err = resolve_stage(None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("held by another nau build"),
            "conflict must be loud: {msg}"
        );
        assert!(
            msg.contains("--stage"),
            "conflict must point at the escape hatch: {msg}"
        );

        // Release on drop: the next build proceeds. A bounded re-acquire,
        // per the fork(2) window nau-build's StageLock tests document: a
        // concurrent test's forked-not-yet-exec'd child (the pod fixture
        // builds spawn tools) can pin the inherited lock fd for a few
        // microseconds past our close. The contract stays fail-loud; only
        // this release assertion tolerates that scheduling window.
        drop(lock);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let again = loop {
            match resolve_stage(None) {
                Ok((_, _, lock)) => break lock,
                Err(err) if std::time::Instant::now() < deadline => {
                    assert!(
                        format!("{err:#}").contains("held by another nau build"),
                        "re-acquire must fail only on the documented contention: {err:#}"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(err) => panic!("stage lock never released after drop: {err:#}"),
            }
        };
        assert!(again.is_some());
    }

    // ── #310: stage-only deps pack the run's resolved stage ──

    /// The stage SELECTION: a stage-only recipe packs the run's stage
    /// (its content IS the declaration); anything with a build phase
    /// keeps a private scratch — the shared stage must never be a
    /// build's wipe target.
    #[test]
    fn resolve_dep_stage_shares_the_run_stage_only_for_stage_only_deps() {
        let run = tempfile::tempdir().unwrap();
        match resolve_dep_stage(&dep_fixture_meta("meta-dep"), run.path()).unwrap() {
            DepStage::Shared(p) => assert_eq!(p, run.path()),
            DepStage::Private(_) => panic!("a stage-only dep must pack the run stage"),
        }
        let mut built = dep_fixture_meta("built-dep");
        built.build = Some("true".into());
        match resolve_dep_stage(&built, run.path()).unwrap() {
            DepStage::Private(t) => assert_ne!(t.path(), run.path()),
            DepStage::Shared(_) => panic!("a build-bearing dep must keep its private scratch"),
        }
    }

    /// The whole local dep leg: a stage-only dep builds a snap carrying
    /// the pre-staged content (the #310 bug built a meta-only shell),
    /// and the shared stage survives the build untouched.
    #[test]
    fn stage_only_dep_build_packs_the_run_stage_content() {
        if !tool_on_path("mksquashfs") {
            eprintln!("skipping: mksquashfs unavailable");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let run_stage = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(run_stage.path().join("usr/share")).unwrap();
        std::fs::write(
            run_stage.path().join("usr/share/dep-payload.txt"),
            b"declared content\n",
        )
        .unwrap();
        let output_dir = tmp.path().join("out");
        std::fs::create_dir_all(&output_dir).unwrap();

        build_dep_archs(
            "stage-dep",
            &dep_fixture_meta("stage-dep"),
            &["amd64".to_string()],
            &output_dir,
            None,
            None,
            &LockFile::empty(),
            false,
            true,
            run_stage.path(),
            crate::snap::StagePolicy::Default,
        )
        .expect("the stage-only dep builds");

        let snap = output_dir.join("stage-dep_1.0_amd64.snap");
        assert!(
            snap.is_file(),
            "the dep snap exists in {}",
            output_dir.display()
        );

        // The declared content rides the snap — a payload, not a shell.
        // The extraction spawns through the tools seam (#101 AC-1):
        // resolution IS the availability check (provisioned set,
        // NAU_TOOL_ override, PATH fallback), so a miss skips the check.
        let unsquashfs = match crate::tools::resolve(crate::tools::ToolName::Unsquashfs) {
            Ok(
                crate::tools::ResolvedTool::Provisioned { path, .. }
                | crate::tools::ResolvedTool::Path { path, .. },
            ) => path,
            Err(_) => {
                eprintln!("skipping content check: unsquashfs unavailable");
                return;
            }
        };
        let extract = tempfile::tempdir().unwrap();
        let status = std::process::Command::new(&unsquashfs)
            .args(["-f", "-d"])
            .arg(extract.path())
            .arg(&snap)
            .status()
            .unwrap();
        assert!(status.success(), "unsquashfs failed");
        let carried = std::fs::read(extract.path().join("usr/share/dep-payload.txt"))
            .expect("the staged payload is inside the snap");
        assert_eq!(carried, b"declared content\n");

        // The collision guard holds: the shared stage was read, never
        // wiped or consumed.
        assert_eq!(
            std::fs::read(run_stage.path().join("usr/share/dep-payload.txt")).unwrap(),
            b"declared content\n",
        );
    }
