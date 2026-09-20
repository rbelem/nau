//! `node {}` DSL plumbing (ADR-0033 Decision 6): the declaration rides
//! the bounded-subprocess eval payload to Rust as an optional
//! `NodeConfig` beside the snap outputs — present when the fixture
//! declares a node, absent when it does not, and never mistaken for a
//! snap output.

use shuttle::lua::{evaluate_file_with_inputs, DEFAULT_SERVE_ADDRESS};

fn fixture(path: &str) -> String {
    format!("{}/tests/{path}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn eval_without_node_carries_no_config() {
    let out = evaluate_file_with_inputs(&fixture("fixtures/node-absent/shuttle.lua"))
        .expect("eval without node{} must succeed");
    assert!(out.node.is_none(), "absent node declaration = nothing");
    assert_eq!(out.outputs.len(), 1);
    assert_eq!(out.outputs["default"].name, "plain");
}

#[test]
fn eval_with_node_carries_the_declaration() {
    let out = evaluate_file_with_inputs(&fixture("fixtures/node-decl/shuttle.lua"))
        .expect("eval with node{} must succeed");
    let node = out.node.expect("node{} must ride the eval payload");
    assert_eq!(node.name, "devbox");
    assert!(node.serve.announce);
    assert_eq!(
        node.peers,
        vec!["shuttle://nuci.local:7780".to_string()],
        "the first entry is the origin peer"
    );
    // The node table is config, not a snap output — it must not leak
    // into the outputs map.
    assert_eq!(out.outputs.len(), 1);
    assert_eq!(out.outputs["default"].name, "shared");
}

#[test]
fn node_config_defaults_serve_address_to_loopback() {
    // A node{} with no serve table: announce off, loopback default.
    let src = r#"
    return { node = node { name = "bare" } }
    "#;
    let out = shuttle::lua::evaluate_string_with_inputs("bare-node", src)
        .expect("minimal node{} must evaluate");
    let node = out.node.expect("node{} must ride the eval payload");
    assert!(!node.serve.announce);
    assert!(node.peers.is_empty());
    assert_eq!(
        node.serve.address, None,
        "unset serve.address stays unset on the struct"
    );
    assert_eq!(node.serve_address(), DEFAULT_SERVE_ADDRESS);
}
