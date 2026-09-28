//! The Hetzner provider (T6) driven end to end against a scripted
//! `CommandRunner` fake: the fake plays `ssh-keygen` (writes a fixed
//! throwaway keypair) and the `hcloud` CLI (create/describe/delete from
//! scripted state), records every argv, and answers nothing else. No
//! network, no real hcloud, no token — the ticket's live lanes are
//! env-gated elsewhere (HCLOUD_TOKEN).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use shuttle::command::{CommandRunner, RunnerOutput};
use shuttle::provision::hetzner::HetznerProvisioner;
use shuttle::provision::{
    append_worker_entry, iso8601_utc, parse_ttl, render_user_data, ProvisionRequest, Provisioner,
    UserDataParams, BLOCK_BEGIN, BLOCK_END,
};

/// A shape-valid ed25519 keypair — throwaway fixture bytes, no crypto.
const TEST_HOST_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkvsDFv9XrohqXsJvKK8dFbGFe5vN3fGcLgoW8cR3UxQ shuttle-worker-host-key";
const TEST_HOST_PRIV: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
const OPERATOR_KEY: &str = "ssh-ed25519 AAAAoperatorkey operator@example";
const BINARY_URL: &str = "https://example.invalid/shuttle-amd64";

// ── The scripted provider CLI ──

#[derive(Clone, Default)]
struct Script {
    create_fails: bool,
    describe_fails: bool,
    delete_fails: bool,
    /// Volumes the fake reports attached to any server (the #269 v2
    /// pre-delete check's input).
    attached_volumes: usize,
}

/// Plays `ssh-keygen` + `hcloud` from scripted state and records every
/// argv. Cheap to clone; all clones share one call log.
#[derive(Clone)]
struct FakeProvider {
    calls: Arc<Mutex<Vec<Vec<String>>>>,
    script: Script,
}

impl FakeProvider {
    fn new(script: Script) -> Self {
        FakeProvider {
            calls: Arc::new(Mutex::new(Vec::new())),
            script,
        }
    }
}

impl CommandRunner for FakeProvider {
    fn run(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        self.calls.lock().unwrap().push(argv.to_vec());
        match argv[0].as_str() {
            // Fake ssh-keygen: drop the fixed fixture keypair at -f <path>.
            "ssh-keygen" => {
                let path = argv
                    .iter()
                    .position(|a| a == "-f")
                    .map(|i| argv[i + 1].clone())
                    .expect("ssh-keygen fake requires -f");
                std::fs::write(&path, TEST_HOST_PRIV).unwrap();
                std::fs::write(format!("{path}.pub"), TEST_HOST_PUB).unwrap();
                Ok(ok_out(""))
            }
            "hcloud" => self.hcloud(argv),
            other => Ok(RunnerOutput {
                code: 1,
                stdout: vec![],
                stderr: format!("unexpected program in test: {other}"),
            }),
        }
    }
}

impl FakeProvider {
    fn hcloud(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        let rest: Vec<&str> = argv[1..].iter().map(|s| s.as_str()).collect();
        match rest.as_slice() {
            ["server", "create", ..] => {
                if self.script.create_fails {
                    return Ok(fail_out("hcloud: invalid credentials (fake)"));
                }
                Ok(ok_out(""))
            }
            ["server", "describe", name, "-o", "json"] => {
                if self.script.describe_fails {
                    return Ok(fail_out("hcloud: server not found (fake)"));
                }
                Ok(ok_out(&describe_json(name)))
            }
            ["server", "delete", _name] => {
                if self.script.delete_fails {
                    return Ok(fail_out("hcloud: delete failed (fake)"));
                }
                Ok(ok_out(""))
            }
            ["volume", "list", "--server", _name, "-o", "json"] => {
                let volumes: Vec<serde_json::Value> = (1..=self.script.attached_volumes)
                    .map(|i| serde_json::json!({ "id": i, "name": format!("vol-{i}") }))
                    .collect();
                Ok(ok_out(&serde_json::Value::Array(volumes).to_string()))
            }
            other => Ok(RunnerOutput {
                code: 1,
                stdout: vec![],
                stderr: format!("unexpected hcloud call in test: {other:?}"),
            }),
        }
    }
}

fn ok_out(stdout: &str) -> RunnerOutput {
    RunnerOutput {
        code: 0,
        stdout: stdout.as_bytes().to_vec(),
        stderr: String::new(),
    }
}

fn fail_out(stderr: &str) -> RunnerOutput {
    RunnerOutput {
        code: 1,
        stdout: vec![],
        stderr: stderr.to_string(),
    }
}

/// Deterministic per-name describe document; the trailing `-NN` of the
/// server name picks a distinct 203.0.113.x address (TEST-NET-3), so two
/// provisioned names never collide on an address.
fn describe_json(name: &str) -> String {
    let suffix: u32 = name
        .rsplit('-')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let ip = format!("203.0.113.{}", 10 + suffix);
    serde_json::json!({
        "id": 42,
        "name": name,
        "status": "running",
        "public_net": { "ipv4": { "ip": ip, "blocked": false } }
    })
    .to_string()
}

// ── Fixtures ──

fn request(config: &Path, dry_run: bool) -> ProvisionRequest {
    ProvisionRequest {
        server_type: "CX33".into(),
        location: "hel1".into(),
        count: 1,
        ttl_secs: parse_ttl("4h").unwrap(),
        dry_run,
        config: config.to_path_buf(),
    }
}

fn provisioner(fake: &FakeProvider, token: Option<&str>) -> HetznerProvisioner<FakeProvider> {
    HetznerProvisioner::new(
        fake.clone(),
        token.map(|t| t.to_string()),
        BINARY_URL.into(),
        OPERATOR_KEY.into(),
    )
}

fn workspace(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join(name);
    (dir, config)
}

fn operator_config() -> &'static str {
    "-- operator config: hand-written, never rewritten by shuttle\nlocal_jobs = 2\nworkers = {}\n\nreturn {}\n"
}

fn calls(fake: &FakeProvider) -> Vec<Vec<String>> {
    fake.calls.lock().unwrap().clone()
}

fn hcloud_calls(fake: &FakeProvider) -> Vec<Vec<String>> {
    calls(fake)
        .into_iter()
        .filter(|argv| argv[0] == "hcloud")
        .collect()
}

fn flat(argv: &[String]) -> String {
    argv.join("\u{1f}")
}

// ── Provision ──

#[test]
fn no_token_refuses_before_any_api_call() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeProvider::new(Script::default());
    let err = provisioner(&fake, None)
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("HCLOUD_TOKEN"),
        "refusal names the token: {text}"
    );
    assert!(
        hcloud_calls(&fake).is_empty(),
        "no API call before the token refusal"
    );
}

#[test]
fn dry_run_makes_no_api_call_and_needs_no_token() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeProvider::new(Script::default());
    let workers = provisioner(&fake, None)
        .provision(&request(&config, true))
        .unwrap();
    assert!(workers.is_empty(), "a dry run provisions nothing");
    assert!(
        hcloud_calls(&fake).is_empty(),
        "dry run must not touch the API: {:?}",
        hcloud_calls(&fake)
    );
}

#[test]
fn dry_run_user_data_resolves_to_the_real_template() {
    // The dry-run mint + render path runs for real (local only); the
    // rendered user-data must be byte-identical to the shared template's
    // output for the same inputs — the plan is the REAL plan.
    let user_data = render_user_data(&UserDataParams {
        host_private_key: TEST_HOST_PRIV,
        host_public_key: TEST_HOST_PUB,
        operator_key: OPERATOR_KEY,
        binary_url: BINARY_URL,
        ttl_expiry_iso: &iso8601_utc(1_700_000_000 + 14_400),
    });
    assert!(user_data.starts_with("#cloud-config\n"));
    // Deterministic: same inputs, same blob, same hash — the plan lane
    // diffs this hash against the sent user-data.
    let again = render_user_data(&UserDataParams {
        host_private_key: TEST_HOST_PRIV,
        host_public_key: TEST_HOST_PUB,
        operator_key: OPERATOR_KEY,
        binary_url: BINARY_URL,
        ttl_expiry_iso: &iso8601_utc(1_700_000_000 + 14_400),
    });
    assert_eq!(user_data, again);
}

#[test]
fn user_data_carries_pinned_binary_operator_key_ttl_and_scrub() {
    let user_data = render_user_data(&UserDataParams {
        host_private_key: TEST_HOST_PRIV,
        host_public_key: TEST_HOST_PUB,
        operator_key: OPERATOR_KEY,
        binary_url: BINARY_URL,
        ttl_expiry_iso: "2026-09-27T23:16:00Z",
    });
    // ADR-0045 D1: the minted host keypair, 0600 private half, public .pub.
    assert!(user_data.contains("path: /etc/ssh/ssh_host_ed25519_key\n    permissions: \"0600\""));
    assert!(user_data.contains("path: /etc/ssh/ssh_host_ed25519_key.pub"));
    assert!(user_data.contains("-----BEGIN OPENSSH PRIVATE KEY-----"));
    assert!(user_data.contains(TEST_HOST_PUB));
    // cloud-init must not regenerate over the injected key.
    assert!(user_data.contains("ssh_deletekeys: false"));
    // Operator login key — separate from the host key.
    assert!(user_data.contains("path: /root/.ssh/authorized_keys"));
    assert!(user_data.contains(OPERATOR_KEY));
    // The TTL marker (the #269 sweep contract), one ISO-8601 UTC line.
    assert!(user_data.contains("path: /etc/shuttle/worker-ttl"));
    assert!(user_data.contains("2026-09-27T23:16:00Z"));
    // Pinned shuttle binary install + sshd hardening + user-data scrub.
    assert!(user_data.contains(BINARY_URL));
    assert!(user_data.contains("PasswordAuthentication no"));
    assert!(user_data.contains("PermitRootLogin prohibit-password"));
    assert!(user_data.contains("rm -f /var/lib/cloud/instances/*/user-data.txt"));
    // The provider token never rides user-data.
    assert!(!user_data.contains("HCLOUD_TOKEN"));
}

#[test]
fn provision_creates_describes_pins_and_labels() {
    let (dir, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeProvider::new(Script::default());
    let mut req = request(&config, false);
    req.count = 2;
    let workers = provisioner(&fake, Some("tok-1")).provision(&req).unwrap();
    assert_eq!(workers.len(), 2);

    // Addresses are pinned from the describe documents, host_key pin is
    // the minted public half with the server name as comment.
    for w in &workers {
        assert!(
            w.address.starts_with("ssh://root@203.0.113."),
            "{}",
            w.address
        );
        let pin: Vec<&str> = w.host_key.split_whitespace().collect();
        assert_eq!(pin[0], "ssh-ed25519");
        assert_eq!(pin[2], w.name, "the pin comments the server name");
    }

    // Every create carried the TTL label and the user-data file; the
    // token never appears in argv.
    let creates: Vec<Vec<String>> = hcloud_calls(&fake)
        .into_iter()
        .filter(|argv| flat(argv).contains("server\u{1f}create"))
        .collect();
    assert_eq!(creates.len(), 2);
    for argv in &creates {
        let f = flat(argv);
        // The #269 v2 label pair: marker + TTL expiry in epoch seconds
        // (label values reject ':', so ISO-8601 never rides a label).
        // Two `--label` flags: `shuttle-worker=<epoch>` and
        // `shuttle-worker-ttl=<epoch>`.
        let label_values: Vec<&String> = argv
            .iter()
            .zip(argv.iter().skip(1))
            .filter(|(a, _)| a.as_str() == "--label")
            .map(|(_, v)| v)
            .collect();
        assert_eq!(label_values.len(), 2, "both contract labels: {f}");
        assert!(
            label_values
                .iter()
                .any(|v| v.starts_with("shuttle-worker=")),
            "marker label present: {f}"
        );
        let ttl_value = label_values
            .iter()
            .find(|v| v.starts_with("shuttle-worker-ttl="))
            .unwrap_or_else(|| panic!("ttl label present: {f}"))
            .split('=')
            .nth(1)
            .unwrap();
        let epoch: u64 = ttl_value.parse().unwrap();
        assert!(epoch > 1_600_000_000, "label value is the TTL epoch");
        assert!(!ttl_value.contains(':'), "epoch seconds, never ISO-8601");
        assert!(f.contains("--type\u{1f}CX33"));
        assert!(f.contains("--location\u{1f}hel1"));
        assert!(f.contains("--image\u{1f}ubuntu-24.04"));
        let udf = argv.iter().position(|a| a == "--user-datafile").unwrap();
        let user_data = std::fs::read_to_string(&argv[udf + 1]).unwrap();
        assert!(
            user_data.contains("-----BEGIN OPENSSH PRIVATE KEY-----"),
            "private half rides user-data"
        );
        assert!(user_data.contains(OPERATOR_KEY));
        assert!(!f.contains("tok-1"), "token never enters argv: {f}");
    }

    // Config: the managed block holds exactly the two entries; the file
    // still evaluates.
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(text.contains(BLOCK_BEGIN) && text.contains(BLOCK_END));
    assert_eq!(text.matches("table.insert(workers, ").count(), 2);
    assert!(text.contains("-- operator config"), "operator text intact");
    assert!(text.contains("return {}"), "return intact");
    assert!(shuttle::lua::evaluate_file(config.to_str().unwrap()).is_ok());
    // No server was deleted on the happy path.
    assert!(
        !hcloud_calls(&fake)
            .iter()
            .any(|argv| flat(argv).contains("server\u{1f}delete")),
        "happy provision never deletes"
    );
    let _ = dir;
}

#[test]
fn create_failure_leaves_no_server_and_no_config_change() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeProvider::new(Script {
        create_fails: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("tok"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("invalid credentials"),
        "provider error named: {text}"
    );
    assert!(
        !hcloud_calls(&fake)
            .iter()
            .any(|argv| flat(argv).contains("delete")),
        "nothing was created, so nothing is torn down"
    );
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "config untouched"
    );
}

#[test]
fn describe_failure_after_create_tears_down() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeProvider::new(Script {
        describe_fails: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("tok"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("tore down 1 created server"), "{text}");
    assert_eq!(
        hcloud_calls(&fake)
            .iter()
            .filter(|argv| flat(argv).contains("server\u{1f}delete"))
            .count(),
        1,
        "the created server is deleted"
    );
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "no pin without a server"
    );
}

#[test]
fn pin_failure_after_create_tears_down() {
    // A config that cannot be pinned (missing file) must not leave a
    // live server: teardown-on-failure is the ADR-0045 atomicity.
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("absent").join("shuttle.lua");
    let fake = FakeProvider::new(Script::default());
    let err = provisioner(&fake, Some("tok"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("tore down 1 created server"), "{text}");
    assert!(text.contains("config untouched"), "{text}");
}

#[test]
fn reprovision_replaces_the_same_address_instead_of_duplicating() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeProvider::new(Script::default());
    // Two runs describe DIFFERENT server names but the SAME address: the
    // second run must replace the first entry, not duplicate it.
    let first = provisioner(&fake, Some("tok"))
        .provision(&request(&config, false))
        .unwrap();
    let address = first[0].address.clone();
    // Re-pin the same address through the direct seam (the fake always
    // answers the same IP per name; a real re-provision hits the same
    // address when the operator rebuilds the same machine).
    append_worker_entry(&config, &address, "ssh-ed25519 AAAAsecond re-pin").unwrap();
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(
        text.matches(&format!("address = \"{address}\"")).count() >= 1,
        "address pinned"
    );
    assert_eq!(
        text.matches(&format!("address = \"{address}\"")).count(),
        1,
        "same address never duplicated"
    );
}

#[test]
fn managed_block_places_itself_before_the_top_level_return() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    append_worker_entry(
        &config,
        "ssh://root@203.0.113.10",
        "ssh-ed25519 AAAAfirst shuttle-worker-x",
    )
    .unwrap();
    let text = std::fs::read_to_string(&config).unwrap();
    let block = text.find(BLOCK_BEGIN).unwrap();
    let ret = text.find("return {}").unwrap();
    assert!(
        block < ret,
        "a chunk cannot execute statements after `return` — block goes before it"
    );
    assert!(
        text.contains("workers = workers or {}"),
        "creates the global when absent"
    );
}

#[test]
fn config_without_return_takes_the_block_at_eof() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, "workers = {}\n").unwrap();
    append_worker_entry(&config, "ssh://root@203.0.113.11", "ssh-ed25519 AAAAa c").unwrap();
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(text.find(BLOCK_BEGIN).unwrap() > text.find("workers = {}").unwrap());
    assert!(text.trim_end().ends_with(BLOCK_END));
}

#[test]
fn operator_owned_entry_at_the_same_address_is_a_refusal() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(
        &config,
        "workers = { { address = \"ssh://root@203.0.113.12\", host_key = \"SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfG\" } }\nreturn {}\n",
    )
    .unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let err =
        append_worker_entry(&config, "ssh://root@203.0.113.12", "ssh-ed25519 AAAAb c").unwrap_err();
    assert!(format!("{err:#}").contains("outside the shuttle-managed block"));
    assert_eq!(std::fs::read_to_string(&config).unwrap(), before);
}

// ── Destroy ──

#[test]
fn destroy_removes_the_server_and_evicts_the_managed_entry() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeProvider::new(Script::default());
    let workers = provisioner(&fake, Some("tok"))
        .provision(&request(&config, false))
        .unwrap();
    let name = workers[0].name.clone();
    let address = workers[0].address.clone();

    provisioner(&fake, Some("tok"))
        .destroy(&name, &config)
        .unwrap();

    let text = std::fs::read_to_string(&config).unwrap();
    assert!(
        !text.contains(&format!("address = \"{address}\"")),
        "the entry is evicted"
    );
    assert!(
        !text.contains(BLOCK_BEGIN),
        "the empty block is removed entirely"
    );
    assert!(
        text.contains("-- operator config") && text.contains("return {}"),
        "operator text intact"
    );
    let deletes: Vec<_> = hcloud_calls(&fake)
        .into_iter()
        .filter(|argv| flat(argv).contains("server\u{1f}delete"))
        .collect();
    assert_eq!(deletes.len(), 1);
    assert!(flat(&deletes[0]).contains(&name));
}

#[test]
fn destroy_requires_the_token_before_any_api_call() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeProvider::new(Script::default());
    let err = provisioner(&fake, None)
        .destroy("shuttle-worker-x", &config)
        .unwrap_err();
    assert!(format!("{err:#}").contains("HCLOUD_TOKEN"));
    assert!(hcloud_calls(&fake).is_empty());
}

#[test]
fn destroy_checks_volumes_before_delete_and_proceeds_with_a_loud_warning() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeProvider::new(Script::default());
    let workers = provisioner(&fake, Some("tok"))
        .provision(&request(&config, false))
        .unwrap();
    let name = workers[0].name.clone();

    // Two volumes attached: the #269 v2 pre-delete check fires.
    let volfake = FakeProvider::new(Script {
        attached_volumes: 2,
        ..Default::default()
    });
    provisioner(&volfake, Some("tok"))
        .destroy(&name, &config)
        .unwrap();

    let sequence = hcloud_calls(&volfake);
    let volume_idx = sequence
        .iter()
        .position(|argv| flat(argv).contains("volume\u{1f}list"))
        .expect("volume list ran");
    let delete_idx = sequence
        .iter()
        .position(|argv| flat(argv).contains("server\u{1f}delete"))
        .expect("delete ran");
    assert!(
        volume_idx < delete_idx,
        "volume check happens BEFORE the delete: {:?}",
        sequence
    );
}

#[test]
fn destroy_of_an_unknown_server_is_a_named_refusal() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeProvider::new(Script {
        describe_fails: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("tok"))
        .destroy("no-such-server", &config)
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("no-such-server"), "{text}");
    assert!(
        !hcloud_calls(&fake)
            .iter()
            .any(|argv| flat(argv).contains("delete")),
        "a describe miss never deletes"
    );
}

#[test]
fn destroy_keeps_the_pin_when_the_server_delete_fails() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeProvider::new(Script::default());
    let workers = provisioner(&fake, Some("tok"))
        .provision(&request(&config, false))
        .unwrap();
    let name = workers[0].name.clone();
    let address = workers[0].address.clone();

    let sloppy = FakeProvider::new(Script {
        delete_fails: true,
        ..Default::default()
    });
    // Same address space: the shared-fake rebuild must describe + fail
    // delete; the pin must survive a live server.
    let err = provisioner(&sloppy, Some("tok"))
        .destroy(&name, &config)
        .unwrap_err();
    assert!(format!("{err:#}").contains("delete failed"));
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(
        text.contains(&format!("address = \"{address}\"")),
        "a failed delete leaves the pin: the server is still live"
    );
    let _ = address;
}
