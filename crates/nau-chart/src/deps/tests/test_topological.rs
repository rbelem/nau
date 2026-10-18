use super::*;

    #[test]
    fn test_topological_sort_simple() {
        let nodes = vec![
            DepNode {
                name: "gcc".into(),
                requires: vec!["gmp".into(), "mpfr".into()],
                build_deps: vec![],
            },
            DepNode {
                name: "mpfr".into(),
                requires: vec!["gmp".into()],
                build_deps: vec![],
            },
            DepNode {
                name: "gmp".into(),
                requires: vec![],
                build_deps: vec![],
            },
        ];

        let sorted = topological_sort(&nodes);
        let names: Vec<&str> = sorted.iter().map(|n| n.name.as_str()).collect();

        // gmp should come before mpfr, mpfr before gcc
        let gmp_pos = names.iter().position(|&n| n == "gmp").unwrap();
        let mpfr_pos = names.iter().position(|&n| n == "mpfr").unwrap();
        let gcc_pos = names.iter().position(|&n| n == "gcc").unwrap();

        assert!(gmp_pos < mpfr_pos, "gmp should be before mpfr");
        assert!(mpfr_pos < gcc_pos, "mpfr should be before gcc");
    }

    #[test]
    fn test_resolve_path() {
        // Package name -> pkgs/<letter>/<name>.lua (single file), pinned
        // through an input source: cargo runs the test binary with the
        // crate dir as cwd (crates/nau-chart), so the repo-root `pkgs/`
        // tree the local probe would find pre-extraction is invisible
        // here — the source seam carries the same name->path mapping
        // without a cwd assumption.
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("pkgs/g")).unwrap();
        std::fs::write(src.path().join("pkgs/g/gcc.lua"), "-- recipe body").unwrap();
        let _guard = INPUTS_LOCK.lock().unwrap();
        init_local_input_source(src.path());
        let p = resolve_path("gcc");
        assert!(p.to_string_lossy().ends_with("pkgs/g/gcc.lua"));

        // File path -> raw path
        let p = resolve_path("examples/full-system/system-base/nau.lua");
        assert!(p
            .to_string_lossy()
            .ends_with("examples/full-system/system-base/nau.lua"));
    }

    #[test]
    fn test_topological_sort_linear() {
        let nodes = vec![
            DepNode {
                name: "d".into(),
                requires: vec!["c".into()],
                build_deps: vec![],
            },
            DepNode {
                name: "c".into(),
                requires: vec!["b".into()],
                build_deps: vec![],
            },
            DepNode {
                name: "b".into(),
                requires: vec!["a".into()],
                build_deps: vec![],
            },
            DepNode {
                name: "a".into(),
                requires: vec![],
                build_deps: vec![],
            },
        ];

        let sorted = topological_sort(&nodes);
        let names: Vec<&str> = sorted.iter().map(|n| n.name.as_str()).collect();

        // All deps before dependents
        for &n in &["a", "b", "c", "d"] {
            assert!(names.contains(&n), "missing {}", n);
        }
        let a = names.iter().position(|&n| n == "a").unwrap();
        let b = names.iter().position(|&n| n == "b").unwrap();
        let c = names.iter().position(|&n| n == "c").unwrap();
        let d = names.iter().position(|&n| n == "d").unwrap();
        assert!(a < b);
        assert!(b < c);
        assert!(c < d);
    }

    #[test]
    fn build_dep_seeds_drop_self_referenced_payloads() {
        // Self-host marker (issue #33): a requires entry naming the
        // package itself declares the package builds that payload — it
        // must not seed the merged build prefix (pool headers would
        // shadow its own build tree). Regular deps pass through.
        let meta = seeds_meta("glibc", &["glibc", "linux-headers"], &["glibc", "make"]);
        assert_eq!(build_dep_seeds(&meta), vec!["linux-headers", "make"]);
    }

    /// Build_deps edges order a build exactly like requires edges: a
    /// build-time dependency must be built before whatever consumes it
    /// (ADR-0018, issue #17).
    #[test]
    fn test_topological_sort_build_deps_order() {
        let nodes = vec![
            DepNode {
                name: "app".into(),
                requires: vec![],
                build_deps: vec!["libdev".into()],
            },
            DepNode {
                name: "libdev".into(),
                requires: vec![],
                build_deps: vec![],
            },
        ];

        let sorted = topological_sort(&nodes);
        let names: Vec<&str> = sorted.iter().map(|n| n.name.as_str()).collect();
        let libdev = names.iter().position(|&n| n == "libdev").unwrap();
        let app = names.iter().position(|&n| n == "app").unwrap();
        assert!(libdev < app, "build_deps must build before their consumer");
    }

    /// all_deps merges both edge kinds, deduplicated.
    #[test]
    fn test_all_deps_dedupes() {
        let node = DepNode {
            name: "app".into(),
            requires: vec!["glibc".into(), "ncurses".into()],
            build_deps: vec!["ncurses".into()],
        };
        assert_eq!(node.all_deps(), vec!["glibc", "ncurses"]);
    }

    // ── topological sort branches (pure) ──

    #[test]
    fn topological_sort_treats_outside_graph_deps_as_leaves() {
        let nodes = vec![DepNode {
            name: "app".into(),
            requires: vec!["glibc".into()],
            build_deps: vec![],
        }];
        let names: Vec<String> = topological_sort(&nodes)
            .iter()
            .map(|n| n.name.clone())
            .collect();
        assert_eq!(names, vec!["app"]);
    }

    #[test]
    fn topological_sort_appends_nodes_trapped_in_cycles() {
        let nodes = vec![
            DepNode {
                name: "a".into(),
                requires: vec!["b".into()],
                build_deps: vec![],
            },
            DepNode {
                name: "b".into(),
                requires: vec!["a".into()],
                build_deps: vec![],
            },
            DepNode {
                name: "c".into(),
                requires: vec![],
                build_deps: vec![],
            },
        ];
        let names: Vec<String> = topological_sort(&nodes)
            .iter()
            .map(|n| n.name.clone())
            .collect();
        assert_eq!(names.len(), 3, "cycle members are not dropped: {names:?}");
        assert_eq!(names[0], "c", "free node sorts first");
    }

    // ── requires-edge constraints (ADR-0047) ──

    #[test]
    fn split_dep_spec_parses_name_and_constraint() {
        assert_eq!(split_dep_spec("glibc").unwrap(), ("glibc", None));
        assert_eq!(split_dep_spec("node@22").unwrap(), ("node", Some("22")));
        assert_eq!(split_dep_spec("node@22.2").unwrap(), ("node", Some("22.2")));
        // A path is never split, even when it contains '@'.
        assert_eq!(
            split_dep_spec("examples/x@1/pkg.lua").unwrap(),
            ("examples/x@1/pkg.lua", None)
        );
        // Malformed edges error.
        assert!(split_dep_spec("node@").is_err());
        assert!(split_dep_spec("node@2 2").is_err());
    }

    #[test]
    fn effective_constraints_pick_the_single_line() {
        let map = HashMap::from([
            ("glibc".to_string(), Vec::new()),
            ("node".to_string(), vec!["22".to_string()]),
        ]);
        let eff = effective_constraints(&map).unwrap();
        assert_eq!(eff["glibc"], None);
        assert_eq!(eff["node"].as_deref(), Some("22"));
    }

    #[test]
    fn effective_constraints_refuse_conflicting_lines() {
        // Two edges naming one package with different constraints: one
        // pod holds one version of a name (ADR-0047 D2) — the walk
        // refuses instead of letting edge order pick the winner.
        let map = HashMap::from([("node".to_string(), vec!["22".to_string(), "26".to_string()])]);
        let err = effective_constraints(&map).expect_err("conflicting lines must refuse");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("conflicting version lines for 'node'")
                && msg.contains("@22")
                && msg.contains("@26"),
            "refusal must name the package and both lines: {msg}"
        );
    }

    #[test]
    fn effective_constraints_compose_bare_and_constrained_edges() {
        // A bare edge imposes no constraint: bare + @22 of one name is
        // one node at line 22, not a conflict.
        let map = HashMap::from([("node".to_string(), vec!["22".to_string()])]);
        let eff = effective_constraints(&map).unwrap();
        assert_eq!(eff["node"].as_deref(), Some("22"));
    }

    // ── input-source resolution (no eval; process-global state, serialized) ──
    //
    // load_meta/format_tree evaluate recipes through the eval worker
    // subprocess, which re-executes argv[0] — under the test harness that
    // is the test binary, so the worker protocol breaks ("running 0
    // tests"). Those paths stay with the eval_* integration suites; only
    // the resolution seam is exercised here.

    #[test]
    fn recipe_dir_is_the_recipe_file_parent_through_input_sources() {
        let src = tempfile::tempdir().unwrap();
        let pkg = src.path().join("pkgs/b");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("bpkg.lua"), "-- recipe body").unwrap();
        let _guard = INPUTS_LOCK.lock().unwrap();
        init_local_input_source(src.path());
        assert_eq!(recipe_dir("bpkg"), Some(src.path().join("pkgs/b")));
        assert_eq!(recipe_dir("missing-pkg"), None);
    }
