use super::*;

#[test]
fn vm_memory_limit_stays_128mb_below_rlimit_as() {
    // Regression: at VM_MEMORY_LIMIT == RLIMIT_AS the Rust/C++ base
    // memory plus a full VM heap tripped RLIMIT_AS first, so the clean
    // Luau "not enough memory" error path was dead code. The VM cap
    // must leave headroom under the rlimit.
    assert_eq!(VM_MEMORY_LIMIT, 384 * 1024 * 1024);
    assert_eq!(RLIMIT_AS_BYTES - VM_MEMORY_LIMIT as u64, 128 * 1024 * 1024);
    // The check worker's wall-clock deadline must sit above the
    // analyzer's own bound so the clean in-worker timeout normally wins.
    assert!(
        CHECK_WALL_DEADLINE
            > std::time::Duration::from_secs_f64(crate::analysis::ANALYZER_TIME_LIMIT_SECS),
        "wall-clock killer must be the backstop, not the primary bound"
    );
    // The cooperative abort must fire BEFORE the parent's hard kill,
    // otherwise the clean Lua error never reaches the operator.
    assert!(
        WORKER_ABORT_BUDGET < WALL_DEADLINE,
        "the worker's cooperative budget must sit inside the parent's wall-clock deadline"
    );
}

// ── ADR-0010 Decision 4: the VM interrupt hook (issue #12) ──

/// The Luau VM interrupt hook must abort a runaway chunk with a
/// clean, diagnosable Lua error — not a crash, not a silent kill.
#[test]
fn vm_interrupt_hook_aborts_a_runaway_chunk_with_a_clean_error() {
    let lua = mlua::Lua::new_with(worker_stdlib(), mlua::LuaOptions::default())
        .expect("worker-shaped VM");
    // Start already past the budget: the hook fires at the first
    // clock check.
    arm_worker_interrupt(&lua, Instant::now() - WORKER_ABORT_BUDGET);
    let err = lua
        .load("while true do end")
        .exec()
        .expect_err("the runaway chunk must be aborted, not run to completion");
    let msg = err.to_string();
    assert!(
        msg.contains("wall-clock deadline"),
        "the abort must name the deadline, got: {msg}"
    );
}

/// A chunk that finishes inside the budget must never be disturbed by
/// the hook.
#[test]
fn vm_interrupt_hook_leaves_a_chunk_inside_the_budget_alone() {
    let lua = mlua::Lua::new_with(worker_stdlib(), mlua::LuaOptions::default())
        .expect("worker-shaped VM");
    arm_worker_interrupt(&lua, Instant::now());
    let v: f64 = lua
        .load("local n = 0 for i = 1, 100000 do n = n + i end return n")
        .eval()
        .expect("a chunk inside the budget must finish");
    assert_eq!(v, 5_000_050_000.0);
}

// ── Luau VM sandbox mode (issue #12) ──

/// The worker VM runs in Luau sandbox mode: the DSL globals installed
/// before the switch still resolve, and the collector cannot be
/// stopped from inside the sandbox.
#[test]
fn worker_vm_runs_in_luau_sandbox_mode() {
    let req = EvalRequest {
        prelude: crate::dsl::prelude(),
        index_data: serde_json::json!({ "version": 1, "snaps": [] }),
        arch: "amd64".into(),
        sources: Default::default(),
        entry: String::new(),
        entry_label: "sandbox-test".into(),
        allow_fetch: false,
        constraint: Some("22".into()),
        versions_mode: false,
    };
    let lua = build_worker_lua(&req, Instant::now()).expect("worker VM");
    // The DSL globals installed before the sandbox must still resolve
    // through the sandbox's proxy environment.
    let constraint: Option<String> = lua
        .load("return constraint")
        .eval()
        .expect("the constraint global must resolve");
    assert_eq!(constraint.as_deref(), Some("22"));
    let index_kind: String = lua
        .load("return type(index)")
        .eval()
        .expect("the index global must resolve");
    assert_eq!(index_kind, "function");
    // The collector cannot be stopped from inside the sandbox: that
    // door is what a hostile chart opens before it blows the VM cap.
    let err = lua
        .load("collectgarbage('stop')")
        .exec()
        .expect_err("sandbox mode must refuse collectgarbage('stop')");
    assert!(
        err.to_string().contains("invalid option"),
        "expected the collectgarbage refusal, got: {err}"
    );
}

// ── The VM memory limit with the collector stopped (issue #12) ──
//
// The probe runs in a re-exec'd child process: the failure mode under
// test (a hard abort instead of a catchable Lua error) would take the
// whole test binary down with it.

/// Runs only inside the re-exec'd child; a no-op in the parent run.
#[test]
fn vm_memory_limit_probe_child() {
    let Ok(mode) = std::env::var(MEM_LIMIT_PROBE_ENV) else {
        return;
    };
    let lua = mlua::Lua::new_with(worker_stdlib(), mlua::LuaOptions::default())
        .expect("worker-shaped VM");
    lua.set_memory_limit(PROBE_MEMORY_LIMIT)
        .expect("memory limit");
    if mode == "sandbox" {
        // Same order as the worker: the DSL globals go in BEFORE the
        // sandbox, the sandbox makes the globals readonly.
        lua.globals().set("dsl_global", 7).expect("dsl global");
        lua.sandbox(true).expect("sandbox mode");
        // The DSL global installed before the sandbox must still read
        // back through the sandbox's proxy environment.
        let seen: i64 = lua.load("return dsl_global").eval().expect("dsl global");
        assert_eq!(seen, 7, "the sandbox must not hide the DSL globals");
        // Under sandbox mode the collector cannot be stopped from Lua.
        let err = lua
            .load("collectgarbage('stop')")
            .exec()
            .expect_err("sandbox mode must refuse collectgarbage('stop')");
        assert!(
            err.to_string().contains("invalid option"),
            "expected the collectgarbage refusal, got: {err}"
        );
    }
    lua.gc_stop();
    let err = lua
        .load(PROBE_ALLOC_CHUNK)
        .exec()
        .expect_err("the allocation past the cap must fail");
    eprintln!("[PROBE {mode}] clean error: {err}");
    assert!(
        matches!(err, mlua::Error::MemoryError(_)),
        "the failure must be the clean VM out-of-memory error, got: {err}"
    );
}

#[test]
fn vm_memory_limit_is_a_clean_error_with_the_collector_stopped() {
    for mode in ["plain", "sandbox"] {
        let exe = std::env::current_exe().expect("test binary path");
        let status = std::process::Command::new(exe)
            .arg("vm_memory_limit_probe_child")
            .env(MEM_LIMIT_PROBE_ENV, mode)
            .status()
            .expect("the probe child must run");
        assert!(
            status.success(),
            "the {mode} memory-limit probe must observe a catchable Lua error \
                 (child status: {status})"
        );
    }
}

#[test]
fn test_resolver_serves_module_inside_root() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("common.lua"), "return {}").unwrap();
    let resolver = resolver_with_root(dir.path());
    assert!(resolver.resolve("common").is_ok());
}

#[test]
fn test_resolver_serves_init_lua() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("mod")).unwrap();
    std::fs::write(dir.path().join("mod/init.lua"), "return {}").unwrap();
    let resolver = resolver_with_root(dir.path());
    assert!(resolver.resolve("mod").is_ok());
    assert!(resolver.resolve("mod.init").is_ok());
}

#[test]
fn test_resolver_rejects_traversal() {
    let dir = tempfile::tempdir().unwrap();
    let resolver = resolver_with_root(dir.path());
    let err = resolver.resolve("../escape").unwrap_err();
    assert!(err.contains("rejected"), "got: {err}");
    assert!(resolver.resolve("a/../../b").is_err());
}

#[test]
fn test_resolver_aliases_the_adr_pkgs_prefix() {
    // Issue #109: the ADR-0032 spelling `require("pkgs.lib.daemon")`
    // must resolve against an allowlisted pkgs root (which IS the
    // pkgs dir) instead of doubling to pkgs/pkgs/lib/…, as a
    // FALLBACK behind the unaliased spelling.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("lib")).unwrap();
    std::fs::write(dir.path().join("lib/daemon.lua"), "return 'aliased'").unwrap();
    let resolver = resolver_with_root(dir.path());
    assert!(resolver.resolve("lib.daemon").is_ok());
    assert_eq!(
        resolver.resolve("pkgs.lib.daemon").unwrap(),
        "return 'aliased'"
    );
    // A real pkgs/pkgs/… subtree under the root wins over the alias.
    std::fs::create_dir_all(dir.path().join("pkgs/lib")).unwrap();
    std::fs::write(dir.path().join("pkgs/lib/daemon.lua"), "return 'direct'").unwrap();
    assert_eq!(
        resolver.resolve("pkgs.lib.daemon").unwrap(),
        "return 'direct'"
    );
    // The alias cannot conjure files that do not exist, and the
    // safety checks apply to the aliased spelling too.
    assert!(resolver.resolve("pkgs.lib.nope").is_err());
    assert!(resolver.resolve("pkgs...").is_err());
}

#[test]
fn test_resolver_rejects_absolute_path() {
    let dir = tempfile::tempdir().unwrap();
    let resolver = resolver_with_root(dir.path());
    let err = resolver.resolve("/etc/passwd").unwrap_err();
    assert!(err.contains("rejected"), "got: {err}");
}

#[test]
fn test_resolver_rejects_dot_to_slash_absolute_synthesis() {
    // Regression: `name.replace('.', "/")` can synthesize an absolute
    // candidate ("...." → "////"), and `root.join` replaces its base
    // with an absolute segment. A dot-to-slash result that starts with
    // '/' must be rejected at the same layer as the explicit '/' check,
    // not left to the downstream canonicalize+prefix check.
    let dir = tempfile::tempdir().unwrap();
    let resolver = resolver_with_root(dir.path());
    for hostile in ["....", "...", ".", "..hidden"] {
        let err = resolver.resolve(hostile).unwrap_err();
        assert!(
            err.contains("rejected absolute path") && err.contains(hostile),
            "name {hostile:?}: got: {err}"
        );
    }
    // Normal dotted names still resolve through the same mapping.
    std::fs::create_dir_all(dir.path().join("foo/bar")).unwrap();
    std::fs::write(dir.path().join("foo/bar/baz.lua"), "return {}").unwrap();
    std::fs::write(dir.path().join("top.lua"), "return {}").unwrap();
    assert!(resolver.resolve("foo.bar.baz").is_ok());
    assert!(resolver.resolve("top").is_ok());
}

#[test]
fn test_resolver_rejects_empty_name() {
    let dir = tempfile::tempdir().unwrap();
    let resolver = resolver_with_root(dir.path());
    assert!(resolver.resolve("").is_err());
}

#[test]
fn test_resolver_rejects_oversized_name() {
    // Regression: a hostile giant require() name must be refused in O(1),
    // not amplified into parent-side CPU/memory work (wall-clock bounds
    // the child, not the parent's resolve path).
    let dir = tempfile::tempdir().unwrap();
    let resolver = resolver_with_root(dir.path());
    let giant = "a".repeat(32 * 1024 * 1024);
    let err = resolver.resolve(&giant).unwrap_err();
    assert!(err.contains("oversized"), "got: {err}");
    assert!(err.len() < 200, "error must not embed the name");
}

#[test]
fn test_read_line_capped() {
    let mut r: &[u8] = b"one\ntwo\n\nlast";
    assert_eq!(read_line_capped(&mut r, 100).unwrap().unwrap(), b"one");
    assert_eq!(read_line_capped(&mut r, 100).unwrap().unwrap(), b"two");
    assert_eq!(read_line_capped(&mut r, 100).unwrap().unwrap(), b"");
    assert_eq!(read_line_capped(&mut r, 100).unwrap().unwrap(), b"last");
    assert!(read_line_capped(&mut r, 100).unwrap().is_none());

    let mut r: &[u8] = &[b'x'; 64];
    assert!(
        read_line_capped(&mut r, 8).is_err(),
        "over-long line must error"
    );
}

#[test]
fn test_resolver_miss_is_not_found_error() {
    let dir = tempfile::tempdir().unwrap();
    let resolver = resolver_with_root(dir.path());
    let err = resolver.resolve("missing").unwrap_err();
    assert!(err.contains("not found in allowlisted roots"), "got: {err}");
}

#[test]
fn test_lua_to_json_shapes() {
    let lua = mlua::Lua::new();
    let v: mlua::Value = lua
        .load(r#"return { name = "x", tags = { "a", "b" }, n = 1.5, ok = true }"#)
        .eval()
        .unwrap();
    let json = lua_to_json(&v).unwrap();
    assert_eq!(json["name"], "x");
    assert_eq!(json["tags"][0], "a");
    assert_eq!(json["tags"][1], "b");
    assert_eq!(json["n"], 1.5);
    assert_eq!(json["ok"], true);
}

#[test]
fn test_lua_to_json_rejects_functions_and_cycles() {
    let lua = mlua::Lua::new();
    let v: mlua::Value = lua.load(r#"return { f = print }"#).eval().unwrap();
    assert!(lua_to_json(&v).is_err());

    let v: mlua::Value = lua
        .load("local t = {} t.self = t return { x = t }")
        .eval()
        .unwrap();
    assert!(lua_to_json(&v).is_err());
}

// ── Versions-mode extraction (ADR-0052 Decision 1) ──

#[test]
fn versions_mode_extracts_listing_and_resolved() {
    let ok = versions_worker(
        r#"
            return {
                default = snap {
                    name = "probe",
                    version = "2.0.21",
                    versions = function() return { "2.0.21", "2.0.20", "2.0.19" } end,
                },
            }
            "#,
    );
    let l = ok.versions.get("default").expect("listing recorded");
    assert_eq!(l.resolved, "2.0.21");
    assert_eq!(
        l.versions.as_deref().unwrap(),
        [
            "2.0.21".to_string(),
            "2.0.20".to_string(),
            "2.0.19".to_string()
        ]
    );
    assert!(l.error.is_none());
    assert_eq!(ok.versions_declared, vec!["default".to_string()]);
}

#[test]
fn versions_mode_reports_absent_method_as_null() {
    let ok = versions_worker(
        r#"
            return { default = snap { name = "plain", version = "1.0" } }
            "#,
    );
    let l = ok.versions.get("default").expect("entry recorded for skip");
    assert_eq!(l.resolved, "1.0");
    assert!(l.versions.is_none());
    assert!(l.error.is_none());
    assert!(ok.versions_declared.is_empty());
}

#[test]
fn versions_mode_names_non_snap_outputs_nowhere() {
    // A raw (non-snap-shaped) output carries no name+version pair and
    // must not appear in the listing map at all.
    let ok = versions_worker(r#"return { cfg = { some = "data" } }"#);
    assert!(ok.versions.is_empty());
}

#[test]
fn versions_mode_captures_a_raising_listing() {
    let ok = versions_worker(
        r#"
            return {
                default = snap {
                    name = "boom",
                    version = "1.0",
                    versions = function() error("upstream gone") end,
                },
            }
            "#,
    );
    let l = ok.versions.get("default").unwrap();
    assert!(l.versions.is_none());
    let err = l.error.as_deref().expect("the raise must be captured");
    assert!(err.contains("upstream gone"), "got: {err}");
}

#[test]
fn versions_mode_rejects_wrong_shapes_by_name() {
    // Non-table return.
    let ok = versions_worker(
        r#"
            return { d = snap { name = "x", version = "1",
                versions = function() return "2.0.0" end } }
            "#,
    );
    let err = ok.versions["d"].error.as_deref().unwrap();
    assert!(err.contains("must return an array"), "got: {err}");

    // Non-string entries.
    let ok = versions_worker(
        r#"
            return { d = snap { name = "x", version = "1",
                versions = function() return { "1.0", 42 } end } }
            "#,
    );
    let err = ok.versions["d"].error.as_deref().unwrap();
    assert!(err.contains("entries must be strings"), "got: {err}");

    // Non-array table (string keys).
    let ok = versions_worker(
        r#"
            return { d = snap { name = "x", version = "1",
                versions = function() return { latest = "1.0" } end } }
            "#,
    );
    let err = ok.versions["d"].error.as_deref().unwrap();
    assert!(err.contains("key type"), "got: {err}");

    // Sparse array (a hole breaks the 1..n run).
    let ok = versions_worker(
        r#"
            return { d = snap { name = "x", version = "1",
                versions = function() local t = {} t[1] = "1.0" t[3] = "0.9" return t end } }
            "#,
    );
    let err = ok.versions["d"].error.as_deref().unwrap();
    assert!(err.contains("dense 1..n"), "got: {err}");
}
