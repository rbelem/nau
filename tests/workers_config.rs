//! `workers = { ... }` config surface (ADR-0040 Decision 3, issue #189):
//! the global rides the bounded-subprocess eval payload, validates
//! Rust-side with one named diagnostic per malformed shape, and absent
//! means the inert default — no workers, the pool's local slot count.

use shuttle::lua::evaluate_string_with_inputs;

fn eval_with(workers_decl: &str) -> Result<shuttle::lua::EvalOutput, String> {
    let src = format!(
        r#"
{workers_decl}
return {{ default = snap {{ name = "workers-cfg", version = "1.0" }} }}
"#
    );
    evaluate_string_with_inputs("workers-test", &src).map_err(|e| e.to_string())
}

fn eval_err(workers_decl: &str) -> String {
    eval_with(workers_decl)
        .err()
        .unwrap_or_else(|| panic!("expected a refusal, got green: {workers_decl}"))
}

#[test]
fn absent_workers_is_the_inert_default() {
    let out = eval_with("").expect("absent workers must eval fine");
    assert!(out.workers.workers.is_empty());
    assert_eq!(
        out.workers.local_jobs, 3,
        "default = today's MAX_PARALLEL_BUILD_WORKERS"
    );
    assert_eq!(out.outputs["default"].name, "workers-cfg");
}

#[test]
fn empty_workers_table_is_also_inert() {
    let out = eval_with("workers = { }").expect("empty workers must eval fine");
    assert!(out.workers.workers.is_empty());
}

#[test]
fn valid_workers_carry_address_jobs_arch() {
    let out = eval_with(
        r#"
workers = {
  local_jobs = 5,
  { address = "ssh://rodrigo@nuci.local", jobs = 4 },
  { address = "ssh://build@edge01" },
  { address = "ssh://arm@builder-aws", arch = "aarch64-linux-gnu" },
}
"#,
    )
    .expect("valid workers must eval fine");
    assert_eq!(out.workers.local_jobs, 5);
    assert_eq!(out.workers.workers.len(), 3);
    assert_eq!(out.workers.workers[0].address, "ssh://rodrigo@nuci.local");
    assert_eq!(out.workers.workers[0].jobs, 4);
    assert_eq!(out.workers.workers[1].jobs, 2, "default jobs");
    assert!(out.workers.workers[1].arch.is_none());
    assert_eq!(
        out.workers.workers[2].arch.as_deref(),
        Some("aarch64-linux-gnu")
    );
    // The workers table is config, not a snap output.
    assert_eq!(out.outputs.len(), 1);
}

#[test]
fn ipv6_bracket_address_with_port_is_valid() {
    let out = eval_with(r#"workers = { { address = "ssh://user@[fe80::1%25eth0]:2222" } }"#)
        .expect("IPv6 bracket form must be accepted");
    assert_eq!(
        out.workers.workers[0].address,
        "ssh://user@[fe80::1%25eth0]:2222"
    );
}

#[test]
fn missing_address_is_a_named_refusal() {
    let err = eval_err(r#"workers = { { jobs = 2 } }"#);
    assert!(err.contains("missing required field 'address'"), "{err:#}");
}

#[test]
fn bad_scheme_is_a_named_refusal() {
    let err = eval_err(r#"workers = { { address = "tcp://nuci.local" } }"#);
    assert!(err.contains("must start with ssh://"), "{err:#}");
}

#[test]
fn host_starting_with_dash_is_refused() {
    let err = eval_err(r#"workers = { { address = "ssh://-oProxyCommand=evil" } }"#);
    assert!(err.contains("must not start with '-'"), "{err:#}");
}

#[test]
fn user_starting_with_dash_is_refused() {
    // ssh://-o...@host re-creates the option-injection hole from the
    // host side: the destination argument still begins with '-'.
    let err = eval_err(r#"workers = { { address = "ssh://-oProxyCommand=/bin/x@buildhost" } }"#);
    assert!(err.contains("invalid user part"), "{err:#}");
}

#[test]
fn ipv6_bracket_without_port_is_valid() {
    let out = eval_with(r#"workers = { { address = "ssh://user@[::1]" } }"#)
        .expect("bracket form without port must be accepted");
    assert_eq!(out.workers.workers[0].address, "ssh://user@[::1]");
}

#[test]
fn port_zero_and_port_overflow_are_refused() {
    let err = eval_err(r#"workers = { { address = "ssh://h:0" } }"#);
    assert!(err.contains("1-65535"), "{err:#}");
    let err = eval_err(r#"workers = { { address = "ssh://h:99999" } }"#);
    assert!(err.contains("1-65535"), "{err:#}");
}

#[test]
fn bare_ipv6_without_brackets_is_refused() {
    // Unbracketed IPv6 would silently misparse (the last ':' becomes the
    // port separator); the grammar requires the bracket form.
    let err = eval_err(r#"workers = { { address = "ssh://fe80::1" } }"#);
    assert!(err.contains("bracket form"), "{err:#}");
    let err = eval_err(r#"workers = { { address = "ssh://::1" } }"#);
    assert!(err.contains("bracket form"), "{err:#}");
    let err = eval_err(r#"workers = { { address = "ssh://fe80::" } }"#);
    assert!(err.contains("bracket form"), "{err:#}");
}

#[test]
fn zero_jobs_is_refused() {
    let err = eval_err(r#"workers = { { address = "ssh://h", jobs = 0 } }"#);
    assert!(err.contains("must be an integer >= 1"), "{err:#}");
}

#[test]
fn fractional_jobs_is_refused() {
    let err = eval_err(r#"workers = { { address = "ssh://h", jobs = 2.5 } }"#);
    assert!(err.contains("must be an integer"), "{err:#}");
}

#[test]
fn unknown_field_is_refused_fail_closed() {
    let err = eval_err(r#"workers = { { address = "ssh://h", speed = 2.0 } }"#);
    assert!(err.contains("unknown field 'speed'"), "{err:#}");
}

#[test]
fn unknown_top_level_key_is_refused() {
    let err = eval_err(r#"workers = { provision = { }, { address = "ssh://h" } }"#);
    assert!(err.contains("unknown key 'provision'"), "{err:#}");
}

#[test]
fn duplicate_addresses_are_refused() {
    let err = eval_err(
        r#"
workers = {
  { address = "ssh://nuci.local" },
  { address = "ssh://nuci.local" },
}
"#,
    );
    assert!(err.contains("duplicate address"), "{err:#}");
}

#[test]
fn wrong_types_are_refused() {
    let err = eval_err("workers = 4");
    assert!(err.contains("'workers' must be a table"), "{err:#}");
    let err = eval_err(r#"workers = { { address = 42 } }"#);
    assert!(err.contains("field 'address' must be a string"), "{err:#}");
    let err = eval_err(r#"workers = { "ssh://h" }"#);
    assert!(err.contains("workers[1] must be a table"), "{err:#}");
}

#[test]
fn local_jobs_type_and_bound_are_checked() {
    let err = eval_err(r#"workers = { local_jobs = 0, { address = "ssh://h" } }"#);
    assert!(err.contains("'local_jobs'"), "{err:#}");
    let err = eval_err(r#"workers = { local_jobs = "many" }"#);
    assert!(err.contains("'local_jobs'"), "{err:#}");
}
