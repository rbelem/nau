use super::*;

#[test]
fn envfile_digest_tracks_bytes_and_missing_files() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("f.env");
    assert_eq!(envfile_digest(&file), None, "missing file, no digest");
    std::fs::write(&file, b"K=\"v1\"\n").unwrap();
    let first = envfile_digest(&file).unwrap();
    std::fs::write(&file, b"K=\"v1\"\n").unwrap();
    assert_eq!(envfile_digest(&file).unwrap(), first, "same bytes");
    std::fs::write(&file, b"K=\"v2\"\n").unwrap();
    assert_ne!(envfile_digest(&file).unwrap(), first, "moved bytes");
}

#[test]
fn refresh_restarts_exactly_the_changed_digest_consumers() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    let valuefile = tmp.path().join("value.txt");
    std::fs::write(&valuefile, "v1\n").unwrap();
    let provider = valuefile_provider(tmp.path(), &valuefile);
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
    let decl = crate::pod::load_declaration(tmp.path(), "work").unwrap();
    let refs = crate::pod::resolve_pod_secrets(tmp.path(), "work", &decl).unwrap();
    let hash = decl_hash(&refs).unwrap();
    let envfile = pod_envfile_path(&cache, "work", &hash);
    // One consumer ("web") and one non-consumer ("side").
    seed_units(
        &tmp.path().join("work"),
        3,
        &[
            (
                "web",
                format!(
                    "ExecStart=/bin/true\nEnvironmentFile=\"{}\"\n",
                    envfile.display()
                ),
            ),
            ("side", "ExecStart=/bin/true\n".to_string()),
        ],
    );
    let log = tmp.path().join("systemctl.log");
    let tools = fake_systemctl(tmp.path(), &log, 0);

    // First refresh: no envfile existed, so the consumer is stale by
    // construction (the D3 boot story) — exactly "web" restarts.
    let first = refresh_pod(tmp.path(), "work", Some(&cache), &tools).unwrap();
    assert_eq!(
        first.restarted,
        vec!["nau-pod-work-web.service".to_string()]
    );
    assert!(first.unchanged.is_empty());

    // Second refresh, same value: the bytes are identical, so
    // nothing restarts — the consumer is reported unchanged.
    let second = refresh_pod(tmp.path(), "work", Some(&cache), &tools).unwrap();
    assert!(second.restarted.is_empty());
    assert_eq!(
        second.unchanged,
        vec!["nau-pod-work-web.service".to_string()]
    );

    // Rotate the value: the digest moves and "web" restarts again.
    std::fs::write(&valuefile, "v2\n").unwrap();
    let third = refresh_pod(tmp.path(), "work", Some(&cache), &tools).unwrap();
    assert_eq!(
        third.restarted,
        vec!["nau-pod-work-web.service".to_string()]
    );

    // The fake ran `--user restart <consumer>` exactly twice and
    // NEVER touched the non-consumer.
    let ran = std::fs::read_to_string(&log).unwrap();
    assert_eq!(ran.matches("nau-pod-work-web.service").count(), 2);
    assert!(!ran.contains("nau-pod-work-side.service"));
    assert!(ran.contains("--user"));
    assert!(ran.contains("restart"));
}

#[test]
fn refresh_without_systemctl_skips_the_restart_named() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    let provider = valuefile_provider(tmp.path(), &tmp.path().join("value.txt"));
    std::fs::write(tmp.path().join("value.txt"), "v1\n").unwrap();
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
    let decl = crate::pod::load_declaration(tmp.path(), "work").unwrap();
    let refs = crate::pod::resolve_pod_secrets(tmp.path(), "work", &decl).unwrap();
    let envfile = pod_envfile_path(&cache, "work", &decl_hash(&refs).unwrap());
    seed_units(
        &tmp.path().join("work"),
        3,
        &[(
            "web",
            format!("EnvironmentFile=\"{}\"\n", envfile.display()),
        )],
    );
    // Tools absent (RuntimeTools::default()): the restart is a named
    // skip — never a silent no-op, never a failure.
    let report = refresh_pod(
        tmp.path(),
        "work",
        Some(&cache),
        &crate::runtime::RuntimeTools::default(),
    )
    .unwrap();
    assert!(report.restarted.is_empty());
    assert_eq!(report.skipped, vec!["nau-pod-work-web.service".to_string()]);
}

#[test]
fn refresh_fails_loud_naming_a_unit_the_restart_cannot_move() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    let valuefile = tmp.path().join("value.txt");
    std::fs::write(&valuefile, "v1\n").unwrap();
    let provider = valuefile_provider(tmp.path(), &valuefile);
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
    let decl = crate::pod::load_declaration(tmp.path(), "work").unwrap();
    let refs = crate::pod::resolve_pod_secrets(tmp.path(), "work", &decl).unwrap();
    let envfile = pod_envfile_path(&cache, "work", &decl_hash(&refs).unwrap());
    seed_units(
        &tmp.path().join("work"),
        3,
        &[(
            "web",
            format!("EnvironmentFile=\"{}\"\n", envfile.display()),
        )],
    );
    // The fake exists but FAILS: refresh exits naming the unit (D7),
    // after the envfile write landed (the write half is done).
    let log = tmp.path().join("systemctl.log");
    let tools = fake_systemctl(tmp.path(), &log, 7);
    let err = refresh_pod(tmp.path(), "work", Some(&cache), &tools).unwrap_err();
    let err = format!("{err:#}");
    assert!(
        err.contains("nau-pod-work-web.service"),
        "the error must name the unit: {err}"
    );
    assert!(
        envfile.is_file(),
        "the envfile write half completed before the failed restart"
    );
}

// ── serve step + envfile (issue #184) ──

#[test]
fn serve_pod_resolves_and_materializes_the_envfile_0600() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    let pod = pod_state_root(tmp.path());
    let counter = tmp.path().join("calls");
    let path = counting_script(tmp.path(), &counter);
    let refs = BTreeMap::from([
        ("A_KEY".to_string(), env_ref("NAU_SECRETS_TEST_SERVE")),
        (
            "B_KEY".to_string(),
            SecretSource::Exec {
                command: vec![path],
            },
        ),
    ]);
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("NAU_SECRETS_TEST_SERVE", "plain");
    let served = serve_pod(&pod, "p", 5, &refs, Some(&cache)).unwrap();
    std::env::remove_var("NAU_SECRETS_TEST_SERVE");
    assert_eq!(calls(&counter), 1, "cold resolve calls the provider");
    assert_eq!(
        served.values.get("B_KEY").map(String::as_str),
        Some(SENTINEL)
    );
    let envfile = served.envfile.clone().unwrap();
    let hash = decl_hash(&refs).unwrap();
    let cache_entry = pod_cache_entry_path(&cache, "p", &hash);
    assert_eq!(
        envfile,
        cache_entry.with_extension("env"),
        "the envfile is the cache entry's .env sibling"
    );
    assert_eq!(file_mode(&envfile), 0o600);
    let body = std::fs::read_to_string(&envfile).unwrap();
    assert_eq!(
        body,
        format!("A_KEY=\"plain\"\nB_KEY=\"{SENTINEL}\"\n"),
        "sorted KEY=value lines, systemd double-quote wrapping"
    );
    // A warm serve: zero provider calls, envfile refreshed anyway.
    std::fs::remove_file(&envfile).unwrap();
    let again = serve_pod(&pod, "p", 5, &refs, Some(&cache)).unwrap();
    assert_eq!(calls(&counter), 1, "cache hit = zero provider calls");
    assert!(envfile.is_file(), "the serve re-materializes the envfile");
    assert_eq!(again.meta.get("B_KEY").unwrap().cache, "hit");
    assert_eq!(again.meta.get("B_KEY").unwrap().source, "exec");
    assert_eq!(again.meta.get("A_KEY").unwrap().source, "env");
}

#[test]
fn envfile_escapes_systemd_c_sequences_verbatim_backslashes_included() {
    let tmp = tempfile::tempdir().unwrap();
    let refs = BTreeMap::from([(
        "K".to_string(),
        SecretSource::Exec {
            command: vec![script(
                tmp.path(),
                "nasty-provider",
                nasty_provider_script(),
            )],
        },
    )]);
    let pod = pod_state_root(tmp.path());
    let served = serve_pod(
        &pod,
        "p",
        1,
        &refs,
        Some(tmp.path().join("cache").as_path()),
    )
    .unwrap();
    let body = std::fs::read_to_string(served.envfile.unwrap()).unwrap();
    assert_eq!(
        body,
        expected_envfile_body(),
        "backslash doubled, quote escaped, newline folded to \\n"
    );
}

#[test]
fn serve_pod_with_no_references_needs_no_runtime_dir() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = std::env::var("XDG_RUNTIME_DIR").ok();
    std::env::remove_var("XDG_RUNTIME_DIR");
    let refs: BTreeMap<String, SecretSource> = BTreeMap::new();
    let served = serve_pod(Path::new("/nonexistent-pod"), "p", 1, &refs, None).unwrap();
    if let Some(dir) = saved {
        std::env::set_var("XDG_RUNTIME_DIR", dir);
    }
    assert_eq!(served, ServedSecrets::default());
}

#[test]
fn serve_pod_fails_loud_naming_the_var_before_any_envfile_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    let pod = pod_state_root(tmp.path());
    let refs = BTreeMap::from([
        ("GOOD".to_string(), env_ref("NAU_SECRETS_TEST_GOOD")),
        ("BAD".to_string(), env_ref("NAU_SECRETS_TEST_ABSENT")),
    ]);
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("NAU_SECRETS_TEST_GOOD", "v");
    let err = format!(
        "{}",
        serve_pod(&pod, "p", 1, &refs, Some(&cache)).unwrap_err()
    );
    std::env::remove_var("NAU_SECRETS_TEST_GOOD");
    assert!(err.contains("NAU_SECRETS_TEST_ABSENT"), "{err}");
    assert!(err.contains("BAD"), "{err}");
    // D7: an all-or-nothing resolve means NOTHING landed — no cache
    // entry, no envfile, no partial export set downstream.
    assert!(read_dir_count(&cache).is_none() || read_dir_count(&cache) == Some(0));
    assert_eq!(
        std::fs::read_dir(pod_cache_entry_path(&cache, "p", "x").parent().unwrap())
            .map(|d| d.count())
            .unwrap_or(0),
        0,
        "no cache dir contents"
    );
}

#[test]
fn warm_cache_render_writes_the_envfile_without_any_provider_call() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    let refs = BTreeMap::from([(
        "K".to_string(),
        SecretSource::Exec {
            command: vec!["/no/such/program-184".to_string()],
        },
    )]);
    // A WARM entry already in the cache (nothing resolves here —
    // the provider named above does not even exist).
    let hash = decl_hash(&refs).unwrap();
    write_cache_entry(
        &pod_cache_entry_path(&cache, "p", &hash),
        &CacheEntry {
            generation: 4,
            values: BTreeMap::from([("K".to_string(), "cached".to_string())]),
        },
    )
    .unwrap();
    let rendered = render_pod_envfile_from_warm_cache("p", &refs, Some(&cache));
    assert_eq!(rendered, 1);
    let envfile = pod_cache_entry_path(&cache, "p", &hash).with_extension("env");
    assert_eq!(std::fs::read_to_string(&envfile).unwrap(), "K=\"cached\"\n");
    assert_eq!(file_mode(&envfile), 0o600);
    // Idempotent: a second warm sync rewrites the same content.
    assert_eq!(
        render_pod_envfile_from_warm_cache("p", &refs, Some(&cache)),
        1
    );
    // A COLD cache writes nothing — the unit's start-time failure
    // is the designed state (D7).
    let cold = tmp.path().join("cold");
    assert_eq!(
        render_pod_envfile_from_warm_cache("p", &refs, Some(&cold)),
        0,
        "cache miss renders nothing"
    );
    assert!(!cold.join("p").join(format!("{hash}.env")).exists());
    // No references → nothing, no runtime dir required.
    let empty: BTreeMap<String, SecretSource> = BTreeMap::new();
    assert_eq!(
        render_pod_envfile_from_warm_cache("p", &empty, Some(&cache)),
        0
    );
}

#[test]
fn pod_envfile_path_passive_derives_from_the_refs_and_fails_named_without_runtime_dir() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = std::env::var("XDG_RUNTIME_DIR").ok();
    std::env::remove_var("XDG_RUNTIME_DIR");
    let refs = BTreeMap::from([("K".to_string(), env_ref("ANY"))]);
    let err = format!(
        "{}",
        pod_envfile_path_passive("p", &refs, None).unwrap_err()
    );
    let empty: BTreeMap<String, SecretSource> = BTreeMap::new();
    let none = pod_envfile_path_passive("p", &empty, None).unwrap();
    if let Some(dir) = saved {
        std::env::set_var("XDG_RUNTIME_DIR", dir);
    }
    assert!(err.contains("XDG_RUNTIME_DIR"), "{err}");
    assert!(err.contains("p"), "{err}");
    assert!(none.is_none(), "secret-less pods get no envfile line");
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("run/nau/secrets");
    let some = pod_envfile_path_passive("p", &refs, Some(&base))
        .unwrap()
        .unwrap();
    let hash = decl_hash(&refs).unwrap();
    assert_eq!(some, base.join("p").join(format!("{hash}.env")));
}

// ── empty reference set + runtime-dir gate ──

#[test]
fn empty_reference_set_needs_no_runtime_dir_and_resolves_empty() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = std::env::var("XDG_RUNTIME_DIR").ok();
    std::env::remove_var("XDG_RUNTIME_DIR");
    let refs: BTreeMap<String, SecretSource> = BTreeMap::new();
    let values = resolve_references(Path::new("/nonexistent-pod"), "p", 3, &refs, None);
    if let Some(dir) = saved {
        std::env::set_var("XDG_RUNTIME_DIR", dir);
    }
    assert!(values.unwrap().is_empty());
}

#[test]
fn xdg_runtime_dir_absent_is_a_hard_failure_naming_the_gap() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = std::env::var("XDG_RUNTIME_DIR").ok();
    std::env::remove_var("XDG_RUNTIME_DIR");
    let refs = BTreeMap::from([("K".to_string(), env_ref("ANY"))]);
    let err = format!(
        "{}",
        resolve_references(Path::new("/nonexistent-pod"), "p", 3, &refs, None).unwrap_err()
    );
    if let Some(dir) = saved {
        std::env::set_var("XDG_RUNTIME_DIR", dir);
    }
    assert!(err.contains("XDG_RUNTIME_DIR"), "{err}");
    assert!(err.contains("tmpfs"), "{err}");
}

#[test]
fn tmpfs_gate_accepts_dev_shm_and_rejects_a_disk_dir() {
    assert!(is_tmpfs(Path::new("/dev/shm")).unwrap());
    assert!(
        !is_tmpfs(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap(),
        "the workspace is expected to sit on a non-tmpfs filesystem"
    );
}

// ── verbs: list ──
