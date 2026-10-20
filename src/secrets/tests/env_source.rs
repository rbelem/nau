use super::*;

#[test]
fn env_source_resolves_the_caller_var() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("NAU_SECRETS_TEST_OK", SENTINEL);
    let refs = BTreeMap::from([("K".to_string(), env_ref("NAU_SECRETS_TEST_OK"))]);
    let values = resolve_references(
        tmp.path(),
        "p",
        3,
        &refs,
        Some(tmp.path().join("cache").as_path()),
    )
    .unwrap();
    std::env::remove_var("NAU_SECRETS_TEST_OK");
    assert_eq!(values.get("K").map(String::as_str), Some(SENTINEL));
}

#[test]
fn env_source_missing_var_fails_named_and_leaks_nothing() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("NAU_SECRETS_TEST_MISSING");
    let refs = BTreeMap::from([("API_TOKEN".to_string(), env_ref("NAU_SECRETS_TEST_MISSING"))]);
    let err = format!(
        "{}",
        resolve_references(Path::new("/nonexistent-pod"), "p", 3, &refs, None).unwrap_err()
    );
    assert!(err.contains("secret 'API_TOKEN'"), "{err}");
    assert!(err.contains("source 'env'"), "{err}");
    assert!(err.contains("NAU_SECRETS_TEST_MISSING"), "{err}");
    assert!(!err.contains(SENTINEL), "value leaked into error: {err}");
}

// ── exec source ──

#[test]
fn exec_source_runs_no_shell_and_trims_edges_only() {
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let path = script(tmp.path(), "pem-provider", "printf 'line1\nline2\n'\n");
    let refs = BTreeMap::from([(
        "PEM_KEY".to_string(),
        SecretSource::Exec {
            command: vec![path],
        },
    )]);
    let values = resolve_references(
        &pod,
        "p",
        3,
        &refs,
        Some(tmp.path().join("cache").as_path()),
    )
    .unwrap();
    assert_eq!(
        values.get("PEM_KEY").map(String::as_str),
        Some("line1\nline2"),
        "interior newline survives; only the edges are trimmed"
    );
}

#[test]
fn exec_cache_hit_makes_zero_provider_calls() {
    // The counting provider shells out to `cat` (an EXTERNAL command
    // resolved via PATH), so the spawn window must exclude every
    // env-mutating test (PATH swaps) — same ENV_LOCK discipline.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    let counter = tmp.path().join("calls");
    let pod = pod_state_root(tmp.path());
    let path = counting_script(tmp.path(), &counter);
    let refs = BTreeMap::from([(
        "K".to_string(),
        SecretSource::Exec {
            command: vec![path],
        },
    )]);
    let once = resolve_references(&pod, "p", 3, &refs, Some(&cache)).unwrap();
    assert_eq!(once.get("K").map(String::as_str), Some(SENTINEL));
    assert_eq!(calls(&counter), 1);
    // Same references → same decl-hash → the cache answers, the
    // provider never runs again (D3).
    let twice = resolve_references(&pod, "p", 3, &refs, Some(&cache)).unwrap();
    assert_eq!(twice.get("K").map(String::as_str), Some(SENTINEL));
    assert_eq!(calls(&counter), 1);
    // ANY reference change → different hash → fresh fetch.
    let changed = BTreeMap::from([(
        "K".to_string(),
        SecretSource::Exec {
            command: vec![counting_script(tmp.path(), &counter), "extra".to_string()],
        },
    )]);
    resolve_references(&pod, "p", 3, &changed, Some(&cache)).unwrap();
    assert_eq!(calls(&counter), 2);
}

#[test]
fn exec_nonzero_exit_fails_naming_key_and_program() {
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let path = script(tmp.path(), "broken-provider", "exit 3\n");
    let refs = BTreeMap::from([(
        "API_TOKEN".to_string(),
        SecretSource::Exec {
            command: vec![path],
        },
    )]);
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path())
        )
        .unwrap_err()
    );
    assert!(err.contains("secret 'API_TOKEN'"), "{err}");
    assert!(err.contains("source 'exec'"), "{err}");
    assert!(err.contains("broken-provider"), "{err}");
    assert!(err.contains("3"), "exit status not named: {err}");
}

#[test]
fn exec_empty_output_fails_loud_never_an_empty_value() {
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let path = script(tmp.path(), "silent-provider", "true\n");
    let refs = BTreeMap::from([(
        "K".to_string(),
        SecretSource::Exec {
            command: vec![path],
        },
    )]);
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path())
        )
        .unwrap_err()
    );
    assert!(err.contains("no output"), "{err}");
}

// ── D4: argv[0] host-PATH scrub ──

#[test]
fn exec_argv0_ignores_pod_farm_and_uses_the_host_path_winner() {
    let tmp = tempfile::tempdir().unwrap();
    let pod = tmp.path().join("work");
    // A "farm" (and anything else) under the pod state root shipping
    // the same program name must lose the search.
    std::fs::create_dir_all(pod.join("current")).unwrap();
    script(&pod.join("current"), "shadow", "printf 'FROM-FARM\n'");
    let host = tmp.path().join("hostbin");
    std::fs::create_dir_all(&host).unwrap();
    let host_tool = script(&host, "shadow", "printf 'FROM-HOST\n'");
    let raw_path = format!("{}:{}", pod.join("current").display(), host.display());
    let dirs = host_path_dirs(&pod, &raw_path);
    assert_eq!(
        dirs,
        vec![host.clone()],
        "the pod-rooted PATH entry must be scrubbed"
    );
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved_path = std::env::var("PATH").ok();
    std::env::set_var("PATH", &raw_path);
    let resolved = resolve_exec_program(&pod, "K", "exec", "shadow");
    match saved_path {
        Some(p) => std::env::set_var("PATH", p),
        None => std::env::remove_var("PATH"),
    }
    assert_eq!(resolved.unwrap(), PathBuf::from(&host_tool));
}

#[test]
fn exec_program_resolving_inside_the_pod_root_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let pod = tmp.path().join("work");
    let farm = pod.join("current");
    std::fs::create_dir_all(&farm).unwrap();
    let tool = script(&farm, "bws", "printf 'x\n'");
    // (a) The search form: the farm is the ONLY holder of the name,
    // but the D4 scrub removes pod-rooted PATH entries before the
    // search, so the honest answer is "not found on the host PATH".
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved_path = std::env::var("PATH").ok();
    std::env::set_var("PATH", &farm);
    let err = format!(
        "{}",
        resolve_exec_program(&pod, "BW_ITEM", "exec", "bws").unwrap_err()
    );
    // (b) The symlink-escape form: an OUTSIDE PATH entry whose
    // binary links back into the pod root. The scrub passes the
    // entry; the post-search canonicalization catches it.
    let outside = tmp.path().join("outside-bin");
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&tool, outside.join("bws")).unwrap();
    std::env::set_var("PATH", &outside);
    let err2 = format!(
        "{}",
        resolve_exec_program(&pod, "BW_ITEM", "exec", "bws").unwrap_err()
    );
    // (c) The absolute-path form hits the refusal directly.
    let err3 = format!(
        "{}",
        resolve_exec_program(&pod, "BW_ITEM", "exec", &tool).unwrap_err()
    );
    match saved_path {
        Some(p) => std::env::set_var("PATH", p),
        None => std::env::remove_var("PATH"),
    }
    assert!(err.contains("not found on the host PATH"), "{err}");
    assert!(err2.contains("inside the pod state root"), "{err2}");
    assert!(err2.contains("bws"), "{err2}");
    assert!(err3.contains("inside the pod state root"), "{err3}");
}

#[test]
fn exec_program_not_on_host_path_fails_named() {
    let tmp = tempfile::tempdir().unwrap();
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved_path = std::env::var("PATH").ok();
    std::env::set_var("PATH", tmp.path());
    let err = format!(
        "{}",
        resolve_exec_program(tmp.path(), "K", "exec", "definitely-not-on-path-183").unwrap_err()
    );
    match saved_path {
        Some(p) => std::env::set_var("PATH", p),
        None => std::env::remove_var("PATH"),
    }
    assert!(err.contains("not found on the host PATH"), "{err}");
    assert!(err.contains("definitely-not-on-path-183"), "{err}");
}

// ── cache shape ──

#[test]
fn cache_entry_is_0600_atomically_placed_and_generation_stamped() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    let pod = pod_state_root(tmp.path());
    let path = script(tmp.path(), "provider", &format!("printf '{SENTINEL}\\n'\n"));
    let refs = BTreeMap::from([(
        "K".to_string(),
        SecretSource::Exec {
            command: vec![path],
        },
    )]);
    resolve_references(&pod, "work", 7, &refs, Some(&cache)).unwrap();
    let hash = decl_hash(&refs).unwrap();
    let entry_path = pod_cache_entry_path(&cache, "work", &hash);
    assert_eq!(file_mode(&entry_path), 0o600, "entry must be 0600");
    let entries: Vec<_> = std::fs::read_dir(pod_cache_dir(&cache, "work"))
        .unwrap()
        .collect();
    assert_eq!(entries.len(), 1, "no temp leftovers on the success path");
    let entry = read_cache_entry(&entry_path).unwrap().unwrap();
    assert_eq!(entry.generation, 7, "generation rides inside the body");
    assert_eq!(entry.values.get("K").map(String::as_str), Some(SENTINEL));
}

#[test]
fn decl_hash_is_stable_and_moves_on_any_reference_change() {
    let a = BTreeMap::from([
        ("A".to_string(), env_ref("VAR_ONE")),
        (
            "B".to_string(),
            SecretSource::Exec {
                command: vec!["op".to_string(), "read".to_string(), "x".to_string()],
            },
        ),
    ]);
    assert_eq!(decl_hash(&a).unwrap(), decl_hash(&a).unwrap());
    let same_map_other_order = BTreeMap::from([
        (
            "B".to_string(),
            SecretSource::Exec {
                command: vec!["op".to_string(), "read".to_string(), "x".to_string()],
            },
        ),
        ("A".to_string(), env_ref("VAR_ONE")),
    ]);
    assert_eq!(
        decl_hash(&a).unwrap(),
        decl_hash(&same_map_other_order).unwrap(),
        "serialization is canonical (sorted keys)"
    );
    let variants = [
        BTreeMap::from([("A".to_string(), env_ref("VAR_TWO"))]),
        BTreeMap::from([("A2".to_string(), env_ref("VAR_ONE"))]),
        BTreeMap::from([(
            "A".to_string(),
            SecretSource::Bitwarden {
                id: "8848".to_string(),
            },
        )]),
    ];
    for changed in variants {
        assert_ne!(
            decl_hash(&a).unwrap(),
            decl_hash(&changed).unwrap(),
            "any reference change must move the hash"
        );
    }
}

// ── refresh + prune lifecycle ──

#[test]
fn refresh_busts_the_cache_and_rewrites_the_entry() {
    // The counting provider shells out to `cat` (external, found
    // via PATH) — hold ENV_LOCK so concurrent PATH swaps cannot
    // break the provider spawn.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    let counter = tmp.path().join("calls");
    let provider = counting_script(tmp.path(), &counter);
    seed_pod(
        tmp.path(),
        "work",
        &format!(
            r#"pod {{
    secrets = {{ K = {{ source = "exec", command = {{ "{provider}" }} }} }},
}}
"#
        ),
    );
    activate(tmp.path(), "work");
    let first = refresh_pod(
        tmp.path(),
        "work",
        Some(&cache),
        &crate::runtime::RuntimeTools::default(),
    )
    .unwrap();
    assert_eq!(first.resolved, 1);
    assert_eq!(first.sources.get("exec"), Some(&1));
    assert_eq!(calls(&counter), 1);
    // A plain resolve between refreshes is a cache hit (zero calls).
    let pod_dir = tmp.path().join("work");
    let decl = crate::pod::load_declaration(tmp.path(), "work").unwrap();
    let refs = crate::pod::resolve_pod_secrets(tmp.path(), "work", &decl).unwrap();
    resolve_references(&pod_dir, "work", 3, &refs, Some(&cache)).unwrap();
    assert_eq!(calls(&counter), 1);
    // Refresh busts it: the provider runs again.
    let second = refresh_pod(
        tmp.path(),
        "work",
        Some(&cache),
        &crate::runtime::RuntimeTools::default(),
    )
    .unwrap();
    assert_eq!(second.purged, 1);
    assert_eq!(calls(&counter), 2);
    // The rewritten entry serves the ACTIVE generation.
    let hash = decl_hash(&refs).unwrap();
    let entry = read_cache_entry(&pod_cache_entry_path(&cache, "work", &hash))
        .unwrap()
        .unwrap();
    assert_eq!(entry.generation, 3);
}

#[test]
fn prune_drops_entries_whose_generation_is_no_longer_active() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    for (hash, generation) in [("aaa", 1), ("bbb", 2)] {
        write_cache_entry(
            &pod_cache_entry_path(&cache, "work", hash),
            &CacheEntry {
                generation,
                values: BTreeMap::new(),
            },
        )
        .unwrap();
    }
    assert_eq!(prune_stale_cache_entries(&cache, "work", 2), 1);
    assert!(pod_cache_entry_path(&cache, "work", "bbb").is_file());
    assert!(!pod_cache_entry_path(&cache, "work", "aaa").exists());
    // Idempotent: nothing left to prune at the same generation.
    assert_eq!(prune_stale_cache_entries(&cache, "work", 2), 0);
}

#[test]
fn reconcile_prune_targets_the_active_generation_and_purges_when_cold() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    for (hash, generation) in [("aaa", 1), ("bbb", 2)] {
        write_cache_entry(
            &pod_cache_entry_path(&cache, "work", hash),
            &CacheEntry {
                generation,
                values: BTreeMap::new(),
            },
        )
        .unwrap();
    }
    reconcile_cache_prune("work", Some(2), Some(&cache));
    assert!(pod_cache_entry_path(&cache, "work", "bbb").is_file());
    assert!(!pod_cache_entry_path(&cache, "work", "aaa").exists());
    reconcile_cache_prune("work", None, Some(&cache));
    assert!(!cache.join("work").exists(), "cold pod purges its subtree");
    // Best-effort by construction: unknown pods and missing bases
    // are silent no-ops.
    reconcile_cache_prune("ghost", Some(1), Some(&cache));
}

// ── rotate-restart (ADR-0042 D3, issue #224) ──

#[test]
fn digest_diff_selection_restarts_only_changed_consumers() {
    let web = "nau-pod-work-web.service".to_string();
    let side = "nau-pod-work-side.service".to_string();
    let both = vec![web.clone(), side.clone()];
    // Changed digest: every current consumer restarts…
    assert_eq!(
        restart_on_digest_change(Some("old"), Some("new"), &both),
        both
    );
    // …including a NEWLY-added consumer, and NOT a removed one.
    assert_eq!(
        restart_on_digest_change(Some("old"), Some("new"), std::slice::from_ref(&web)),
        vec![web.clone()]
    );
    // Unchanged digest: nothing restarts, whatever the set.
    assert!(restart_on_digest_change(Some("same"), Some("same"), &both).is_empty());
    assert!(
        restart_on_digest_change(Some("same"), Some("same"), std::slice::from_ref(&web)).is_empty()
    );
    // Missing before (the envfile was gone — the D3 boot story):
    // every consumer is stale by construction.
    assert_eq!(restart_on_digest_change(None, Some("new"), &both), both);
}
