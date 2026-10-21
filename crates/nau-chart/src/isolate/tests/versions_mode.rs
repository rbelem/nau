use super::*;

#[test]
fn versions_mode_caps_are_errors_not_truncations() {
    // 1001 entries — one past the cap.
    let ok = versions_worker(
        r#"
            local t = {}
            for i = 1, 1001 do t[i] = "1.0." .. i end
            return { d = snap { name = "x", version = "1", versions = function() return t end } }
            "#,
    );
    let err = ok.versions["d"].error.as_deref().unwrap();
    assert!(err.contains("1001") && err.contains("cap"), "got: {err}");

    // A version string 129 bytes long.
    let ok = versions_worker(
        r#"
            return { d = snap { name = "x", version = "1",
                versions = function() return { string.rep("v", 129) } end } }
            "#,
    );
    let err = ok.versions["d"].error.as_deref().unwrap();
    assert!(err.contains("128-char cap"), "got: {err}");

    // Exactly at both caps is still valid.
    let ok = versions_worker(
        r#"
            local t = {}
            for i = 1, 999 do t[i] = "1.0." .. i end
            t[1000] = string.rep("v", 128)
            return { d = snap { name = "x", version = "1", versions = function() return t end } }
            "#,
    );
    let l = ok.versions["d"].clone();
    assert!(
        l.error.is_none(),
        "at-cap listing must be valid: {:?}",
        l.error
    );
    assert_eq!(l.versions.as_ref().map(Vec::len), Some(1000));
}

#[test]
fn versions_mode_empty_listing_is_a_valid_answer() {
    let ok = versions_worker(
        r#"
            return { d = snap { name = "x", version = "1", versions = function() return {} end } }
            "#,
    );
    let l = ok.versions["d"].clone();
    assert_eq!(l.versions.as_deref(), Some(&[][..]));
    assert!(l.error.is_none());
}

#[test]
fn normal_mode_still_ships_outputs_carrying_a_versions_fn() {
    // Regression guard for the pre-serialization strip: today a
    // function field makes lua_to_json skip the WHOLE output; the
    // strip keeps the output flowing instead, with no listing call.
    let req = EvalRequest {
        prelude: crate::dsl::prelude(),
        index_data: serde_json::json!({ "version": 1, "snaps": [] }),
        arch: "amd64".into(),
        sources: Default::default(),
        entry: r#"
                return {
                    default = snap {
                        name = "probe",
                        version = "2.0.21",
                        versions = function() error("must never be called") end,
                    },
                }
            "#
        .into(),
        entry_label: "normal-mode-test".into(),
        allow_fetch: false,
        constraint: None,
        versions_mode: false,
    };
    let ok = match run_worker(&req) {
        WorkerOutcome::Ok(ok) => ok,
        WorkerOutcome::Err(e) => panic!("worker failed: {}", e.diagnostics.join("; ")),
    };
    assert!(
        ok.outputs.contains_key("default"),
        "the output must not be skipped: {:?}",
        ok.diagnostics
    );
    assert!(ok.diagnostics.is_empty(), "{:?}", ok.diagnostics);
    // The listing was never called and never shipped — listing-only.
    assert!(ok.versions.is_empty());
    assert_eq!(ok.versions_declared, vec!["default".to_string()]);
    // The stripped field must not reach the JSON.
    assert!(ok.outputs["default"].get("versions").is_none());
}

#[test]
fn normal_mode_outcome_line_stays_byte_identical() {
    // The additive fields must vanish from the serialization when
    // empty — every recipe shipped today has no versions field, so
    // the worker's outcome bytes cannot move.
    let req = EvalRequest {
        prelude: crate::dsl::INIT_LUA.to_string(),
        index_data: serde_json::json!({ "version": 1, "snaps": [] }),
        arch: "amd64".into(),
        sources: Default::default(),
        entry: r#"return { default = snap { name = "p", version = "1" } }"#.into(),
        entry_label: "bytes-test".into(),
        allow_fetch: false,
        constraint: None,
        versions_mode: false,
    };
    let ok = match run_worker(&req) {
        WorkerOutcome::Ok(ok) => ok,
        WorkerOutcome::Err(e) => panic!("worker failed: {}", e.diagnostics.join("; ")),
    };
    let line = serde_json::to_string(&ok).unwrap();
    assert!(
        !line.contains("\"versions\""),
        "empty versions maps must not serialize: {line}"
    );
}

// ── stderr forwarder: cap + deadline (issue #76) ──

#[test]
fn for_build_allowlists_the_entrys_pkgs_tree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let entry = dir.path().join("pkgs/v/valkey/init.lua");
    std::fs::create_dir_all(entry.parent().unwrap()).expect("mkdirs");
    std::fs::write(&entry, "return {}").expect("write");
    let r = SourceResolver::for_build(entry.to_str().unwrap());
    let pkgs = dir.path().join("pkgs").canonicalize().expect("canon");
    assert!(
        r.roots.contains(&pkgs),
        "roots must contain the entry's own pkgs tree, got {:?}",
        r.roots
    );
    // Containment: a sibling tree the entry does not belong to stays out.
    let other = dir.path().join("other-tree/pkgs");
    std::fs::create_dir_all(&other).expect("mkdirs");
    assert!(!r.roots.contains(&other.canonicalize().unwrap()));
}

#[test]
fn forward_capped_below_cap_forwards_everything() {
    let src = b"hello stderr".to_vec();
    let mut reader = std::io::Cursor::new(src.clone());
    let mut dst = Vec::new();
    forward_capped(&mut reader, &mut dst, 1024);
    assert_eq!(dst, src, "below the cap forwarding must be unchanged");
    assert_eq!(
        reader.position(),
        src.len() as u64,
        "source must be drained to EOF"
    );
}

#[test]
fn forward_capped_truncates_at_cap_and_drains_rest() {
    let mut reader = std::io::Cursor::new(vec![b'x'; 3000]);
    let mut dst = Vec::new();
    forward_capped(&mut reader, &mut dst, 1000);
    assert_eq!(dst.len(), 1000, "forwarding must stop at the cap");
    assert!(dst.iter().all(|&b| b == b'x'));
    assert_eq!(
        reader.position(),
        3000,
        "past the cap the stream must still drain to EOF (a stopped \
             drain would fill the child's stderr pipe and stall it)"
    );
}

#[test]
fn forward_capped_dead_sink_switches_to_discard_not_early_exit() {
    let mut reader = std::io::Cursor::new(vec![b'y'; 4096]);
    let mut dst = DeadSink;
    forward_capped(&mut reader, &mut dst, 1024);
    assert_eq!(
        reader.position(),
        4096,
        "a dead sink must not stop the drain; the child's stderr pipe \
             has to keep emptying"
    );
}

#[test]
fn wait_stderr_forwarder_detaches_a_wedged_sink_at_deadline() {
    let mut reader = std::io::Cursor::new(vec![0u8; 8192]);
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut sink = WedgedSink;
        forward_capped(&mut reader, &mut sink, 1024);
        let _ = done_tx.send(());
    });
    let start = Instant::now();
    wait_stderr_forwarder(&done_rx, start + Duration::from_millis(150));
    let waited = start.elapsed();
    assert!(
        waited >= Duration::from_millis(140) && waited < Duration::from_secs(2),
        "the wait must be bounded by the deadline, not by the wedged \
             sink: {waited:?}"
    );
}
