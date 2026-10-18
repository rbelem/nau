use super::*;

    #[test]
    fn test_parse_pod_package() {
        let plain = parse_pod_package("jq").unwrap();
        assert_eq!(plain.name, "jq");
        assert_eq!(plain.constraint, None);

        let constrained = parse_pod_package("ripgrep@14").unwrap();
        assert_eq!(constrained.name, "ripgrep");
        assert_eq!(constrained.constraint.as_deref(), Some("14"));

        assert!(parse_pod_package("@14").is_err());
        assert!(parse_pod_package("jq@").is_err());
        assert!(parse_pod_package("").is_err());
        assert!(parse_pod_package("two words").is_err());
    }

    #[test]
    fn render_round_trips_the_servers_override() {
        // ADR-0052 Decision 6: the pod-level servers override must
        // survive `nau pod add/remove`/`declare` re-renders like every
        // other declared field.
        let decl = PodDeclaration {
            packages: vec!["jq".into()],
            servers: vec![
                "https://primary.example/nau".into(),
                "http://backup.example:7780".into(),
            ],
            ..Default::default()
        };
        let source = render_pod_source(&decl);
        assert!(
            source.contains(
                "servers = { \"https://primary.example/nau\", \
                             \"http://backup.example:7780\" }"
            ),
            "the override renders in declaration order: {source}"
        );
        // Absent servers render nothing (zero behavior change).
        let bare = render_pod_source(&PodDeclaration::default());
        assert!(!bare.contains("servers"), "{bare}");
    }

    #[test]
    fn test_render_shellenv_is_eval_safe_under_nounset() {
        let _lock = crate::test_env::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let env = PodShellenv {
            pod: "default".into(),
            farm: "/root/default/current".into(),
            generation: Some(1),
            vars: BTreeMap::new(),
            secret_vars: BTreeMap::new(),
            secrets: BTreeMap::new(),
        };
        let script = render_shellenv(&env);
        assert_eq!(
            script,
            "export PATH=\"/root/default/current:$PATH\"\n\
             unset LD_LIBRARY_PATH LIBRARY_PATH CPATH COMPILER_PATH\n"
        );

        // The real proof: eval the script under `set -u` with each
        // loader var unset, set, and empty. Issue #110 moved the seam
        // into the emit's per-app wrappers; issue #311 makes the eval
        // actively clear what it inherited, so a stale pre-#110
        // ancestor's poisoned value cannot reach this shell's children
        // in any case.
        let eval = |pre: Option<&str>| {
            let mut cmd = std::process::Command::new("sh");
            cmd.arg("-c").arg(format!(
                "set -u\n{script}\nprintf '%s' \"${{LD_LIBRARY_PATH-__UNSET__}},\
                 ${{LIBRARY_PATH-__UNSET__}},${{CPATH-__UNSET__}},${{COMPILER_PATH-__UNSET__}}\""
            ));
            match pre {
                Some(v) => {
                    for k in ["LD_LIBRARY_PATH", "LIBRARY_PATH", "CPATH", "COMPILER_PATH"] {
                        cmd.env(k, v);
                    }
                }
                None => {
                    for k in ["LD_LIBRARY_PATH", "LIBRARY_PATH", "CPATH", "COMPILER_PATH"] {
                        cmd.env_remove(k);
                    }
                }
            };
            let out = cmd.output().unwrap();
            assert!(
                out.status.success(),
                "stderr: {:?}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };
        assert_eq!(eval(None), "__UNSET__,__UNSET__,__UNSET__,__UNSET__");
        assert_eq!(
            eval(Some("keep")),
            "__UNSET__,__UNSET__,__UNSET__,__UNSET__"
        );
        assert_eq!(eval(Some("")), "__UNSET__,__UNSET__,__UNSET__,__UNSET__");
    }

    #[test]
    fn test_render_shellenv_exports_declared_vars_eval_safe() {
        let _lock = crate::test_env::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut vars = BTreeMap::new();
        vars.insert("EDITOR".to_string(), "vi".to_string());
        vars.insert(
            "GREETING".to_string(),
            "it's $fine, 'quoted' with spaces".to_string(),
        );
        vars.insert("EMPTY".to_string(), String::new());
        vars.insert("A_FIRST".to_string(), "sorted".to_string());
        let env = PodShellenv {
            pod: "default".into(),
            farm: "/root/default/current".into(),
            generation: Some(1),
            vars,
            secret_vars: BTreeMap::new(),
            secrets: BTreeMap::new(),
        };
        let script = render_shellenv(&env);
        // Sorted keys, POSIX single-quote escaping (`'` → `'\''`),
        // and the #311 loader strip right after the PATH prepend.
        assert_eq!(
            script,
            "export PATH=\"/root/default/current:$PATH\"\n\
             unset LD_LIBRARY_PATH LIBRARY_PATH CPATH COMPILER_PATH\n\
             export A_FIRST='sorted'\n\
             export EDITOR='vi'\n\
             export EMPTY=''\n\
             export GREETING='it'\\''s $fine, '\\''quoted'\\'' with spaces'\n"
        );

        // The real proof: eval under `set -u` and read the values back —
        // including the empty one, which must still count as SET.
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "set -u\n{script}\nprintf '%s|%s|%s|%s' \
                 \"$A_FIRST\" \"$EDITOR\" \"$EMPTY\" \"$GREETING\""
            ))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "stderr: {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            "sorted|vi||it's $fine, 'quoted' with spaces"
        );

        // JSON carries the map when present, omits it when empty.
        let with = serde_json::to_value(&env).unwrap();
        assert_eq!(with["vars"]["EDITOR"], "vi");
        let bare = PodShellenv {
            vars: BTreeMap::new(),
            ..env
        };
        assert!(!serde_json::to_value(&bare)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("vars"));
    }
