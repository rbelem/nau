//! `nau workers burst` + `nau workers down --all-managed` (#301), driven
//! end to end against the same scripted fakes as provision_hetzner: the
//! provider fake plays `hcloud` and — uniquely here — the GUESTS too:
//! each scripted create publishes its server's host key into the pending
//! store, the first-boot act burst's `issue --wait` exists to catch. The
//! signer fake plays `ssh-keygen`. No network, no real hcloud, no token.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser as _;
use nau::cli::{BurstCount, Cli, Command, WorkersCommand};
use nau::command::{CommandRunner, RunnerOutput};
use nau::provision::hetzner::HetznerProvisioner;
use nau::provision::publish::{pending_dir, pending_identities, PendingIdentity, PublishChannel};
use nau::provision::{
    burst_auto_count, managed_entries, parse_ttl, refuse_burst_above_max, run_burst,
    run_down_all_managed, ProvisionRequest, BLOCK_BEGIN, BLOCK_END,
};

// ── Fixtures (same shapes as provision_hetzner) ──

const TEST_HOST_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkvsDFv9XrohqXsJvKK8dFbGFe5vN3fGcLgoW8cR3UxQ nau-worker-host-key";
const OPERATOR_KEY: &str = "ssh-ed25519 AAAAoperatorkey operator@example";
const OPERATOR_IDENTITY: &str = "/nau-test-fixtures/operator_ed25519";
const BINARY_URL: &str = "https://example.invalid/nau-amd64";
const CA_FPR: &str = "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfG";
const PUBLISH_URL: &str = "https://coordinator.example/publish";
const CA_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOrZfC0rKJdBX8mUJIKdClRNKdVKmShWU8rjHfDrBKUM nau-host-ca";

/// The CA halves on disk: `inspect` fingerprints the public half,
/// issuance wants the private half present before it signs.
fn ca_on_disk(home: &Path) {
    std::fs::create_dir_all(nau::ca::ca_dir(home)).unwrap();
    std::fs::write(nau::ca::ca_secret_path(home), "test-ca-secret").unwrap();
    std::fs::write(nau::ca::ca_public_path(home), format!("{CA_PUB}\n")).unwrap();
}

fn workspace(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join(name);
    (dir, config)
}

fn operator_config() -> &'static str {
    "-- operator config: hand-written, never rewritten by nau\nlocal_jobs = 2\nworkers = {}\n\nreturn {}\n"
}

fn burst_request(config: &Path, count: u32) -> ProvisionRequest {
    ProvisionRequest {
        server_type: "CX33".into(),
        location: "hel1".into(),
        count,
        ttl_secs: parse_ttl("4h").unwrap(),
        spot: false,
        max_price: None,
        dry_run: false,
        config: config.to_path_buf(),
        ca_fingerprint: Some(CA_FPR.into()),
    }
}

/// A publish channel over a bound throwaway home — burst and down read
/// the pending store and the machine linkage back from it.
fn pubtmp() -> (tempfile::TempDir, PublishChannel) {
    let d = tempfile::tempdir().unwrap();
    let channel = PublishChannel {
        url: PUBLISH_URL.into(),
        home: d.path().to_path_buf(),
    };
    (d, channel)
}

fn provisioner(fake: &FakeProvider, channel: PublishChannel) -> HetznerProvisioner<FakeProvider> {
    HetznerProvisioner::new(
        fake.clone(),
        Some("tok".into()),
        BINARY_URL.into(),
        OPERATOR_KEY.into(),
        OPERATOR_IDENTITY.into(),
        Some(channel),
    )
}

fn calls(fake: &FakeProvider) -> Vec<Vec<String>> {
    fake.calls.lock().unwrap().clone()
}

fn hcloud_deletes(fake: &FakeProvider) -> usize {
    calls(fake)
        .into_iter()
        .filter(|argv| {
            argv.len() > 2 && argv[0] == "hcloud" && argv[1] == "server" && argv[2] == "delete"
        })
        .count()
}

// ── The scripted provider CLI ──

#[derive(Clone, Default)]
struct Script {
    create_fails: bool,
    describe_fails: bool,
    delete_fails: bool,
}

/// Plays `hcloud` from scripted state and records every argv. The
/// `publish_home` arm is the guest: every successful create publishes a
/// pending identity named after the created server (the first-boot act
/// the amendment defines), so burst's issue --wait has something to
/// catch without any timing games.
#[derive(Clone)]
struct FakeProvider {
    calls: Arc<Mutex<Vec<Vec<String>>>>,
    deletes_done: Arc<Mutex<usize>>,
    script: Script,
    publish_home: Option<PathBuf>,
}

impl FakeProvider {
    fn new(script: Script, publish_home: Option<PathBuf>) -> Self {
        FakeProvider {
            calls: Arc::new(Mutex::new(Vec::new())),
            deletes_done: Arc::new(Mutex::new(0)),
            script,
            publish_home,
        }
    }

    fn publish_pending(&self, home: &Path, identity: &str) {
        std::fs::create_dir_all(pending_dir(home)).unwrap();
        let entry = PendingIdentity {
            machine_identity: identity.to_string(),
            public_key: TEST_HOST_PUB.into(),
            instance_identity: serde_json::json!({
                "v1": { "instance_id": "i-burst", "cloud_name": "hetzner", "region": "hel1" }
            }),
            received_at_epoch: 1_000_000,
            token_sha256: "fake-token-sha".into(),
        };
        let text = serde_json::to_string_pretty(&entry).unwrap();
        std::fs::write(
            pending_dir(home).join(format!("pending-{identity}.json")),
            format!("{text}\n"),
        )
        .unwrap();
    }
}

impl CommandRunner for FakeProvider {
    fn run(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        self.calls.lock().unwrap().push(argv.to_vec());
        match argv[0].as_str() {
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
                if let Some(home) = &self.publish_home {
                    if let Some(i) = argv.iter().position(|a| a == "--name") {
                        self.publish_pending(home, &argv[i + 1]);
                    }
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
                *self.deletes_done.lock().unwrap() += 1;
                Ok(ok_out(""))
            }
            ["volume", "list", "-o", "json"] => Ok(ok_out("[]")),
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
/// server name picks a distinct 203.0.113.x address (TEST-NET-3).
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

/// Plays `ssh-keygen` for the issue window: answers `-lf` (CA
/// fingerprint) and plays `-s` by writing the `<input>-cert.pub`
/// sibling. Records every argv.
struct FakeSigner {
    calls: Arc<Mutex<Vec<Vec<String>>>>,
}

impl FakeSigner {
    fn new() -> Self {
        FakeSigner {
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl CommandRunner for FakeSigner {
    fn run(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        self.calls.lock().unwrap().push(argv.to_vec());
        if argv.contains(&"-lf".to_string()) {
            return Ok(ok_out(&format!("256 {CA_FPR} nau-host-ca (ED25519)\n")));
        }
        if argv.iter().any(|a| a == "-s") {
            let input = argv.last().unwrap();
            std::fs::write(format!("{input}-cert.pub"), "fake-cert\n").unwrap();
            return Ok(ok_out(""));
        }
        panic!("unexpected program in test: {argv:?}")
    }
}

// ── Burst ──

#[test]
fn burst_provisions_issues_runs_then_destroys() {
    let (_cfg, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let (pub_dir, channel) = pubtmp();
    ca_on_disk(pub_dir.path());
    let fake = FakeProvider::new(Script::default(), Some(pub_dir.path().to_path_buf()));
    let prov = provisioner(&fake, channel);

    let sentinel = _cfg.path().join("wrapped-ran");
    let command = vec![
        "sh".to_string(),
        "-c".to_string(),
        format!("touch {}", sentinel.display()),
    ];
    let code = run_burst(
        &prov,
        &FakeSigner::new(),
        pub_dir.path(),
        &burst_request(&config, 2),
        Duration::from_secs(30),
        false,
        &command,
    )
    .unwrap();

    assert_eq!(code, 0, "a green wrapped command propagates 0");
    assert!(
        sentinel.exists(),
        "the wrapped command ran inside the window"
    );
    assert_eq!(
        hcloud_deletes(&fake),
        2,
        "every burst worker was destroyed after the command"
    );
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(
        !text.contains(BLOCK_BEGIN),
        "the teardown emptied the managed block: {text}"
    );
    assert!(
        pending_identities(pub_dir.path()).unwrap().is_empty(),
        "every publish was signed and left the pending store"
    );
}

#[test]
fn burst_command_failure_still_destroys_and_propagates_the_code() {
    let (_cfg, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let (pub_dir, channel) = pubtmp();
    ca_on_disk(pub_dir.path());
    let fake = FakeProvider::new(Script::default(), Some(pub_dir.path().to_path_buf()));
    let prov = provisioner(&fake, channel);

    let command = vec!["sh".to_string(), "-c".to_string(), "exit 7".to_string()];
    let code = run_burst(
        &prov,
        &FakeSigner::new(),
        pub_dir.path(),
        &burst_request(&config, 1),
        Duration::from_secs(30),
        false,
        &command,
    )
    .unwrap();

    assert_eq!(code, 7, "the wrapped command's exit code is the burst's");
    assert_eq!(
        hcloud_deletes(&fake),
        1,
        "the failing command's workers were still reclaimed"
    );
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(
        !text.contains(BLOCK_BEGIN),
        "the teardown evicted the pins despite the failure: {text}"
    );
}

#[test]
fn burst_keep_skips_the_teardown_and_parks_the_pins() {
    let (_cfg, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let (pub_dir, channel) = pubtmp();
    ca_on_disk(pub_dir.path());
    let fake = FakeProvider::new(Script::default(), Some(pub_dir.path().to_path_buf()));
    let prov = provisioner(&fake, channel);

    let command = vec!["true".to_string()];
    let code = run_burst(
        &prov,
        &FakeSigner::new(),
        pub_dir.path(),
        &burst_request(&config, 2),
        Duration::from_secs(30),
        true,
        &command,
    )
    .unwrap();

    assert_eq!(code, 0);
    assert_eq!(
        hcloud_deletes(&fake),
        0,
        "--keep means no destroy, not even after a green run"
    );
    let kept = managed_entries(&config).unwrap();
    assert_eq!(kept.len(), 2, "--keep parks the pins for a later drain");
    assert!(
        pending_identities(pub_dir.path()).unwrap().is_empty(),
        "issuance still ran before the parked state"
    );
}

#[test]
fn burst_refuses_a_count_above_max_by_name() {
    let err = refuse_burst_above_max(8, 4).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("count 8"), "names the count: {text}");
    assert!(text.contains("--max 4"), "names the guard: {text}");
    assert!(text.contains("hourly"), "names the cost: {text}");

    assert!(
        refuse_burst_above_max(4, 4).is_ok(),
        "exactly at the guard is allowed"
    );
    assert!(refuse_burst_above_max(1, 4).is_ok());
}

// ── Down ──

#[test]
fn down_all_managed_drains_a_kept_burst_block() {
    let (_cfg, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let (pub_dir, channel) = pubtmp();
    ca_on_disk(pub_dir.path());
    let fake = FakeProvider::new(Script::default(), Some(pub_dir.path().to_path_buf()));
    let prov = provisioner(&fake, channel);

    // Park a burst: two pinned workers, two machine links.
    run_burst(
        &prov,
        &FakeSigner::new(),
        pub_dir.path(),
        &burst_request(&config, 2),
        Duration::from_secs(30),
        true,
        &["true".to_string()],
    )
    .unwrap();

    let drained = run_down_all_managed(&prov, pub_dir.path(), &config).unwrap();
    assert_eq!(drained, 2, "both managed entries were destroyed");
    assert_eq!(hcloud_deletes(&fake), 2, "each parked server was deleted");
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(
        !text.contains(BLOCK_BEGIN),
        "the drain leaves no managed block: {text}"
    );
}

#[test]
fn down_all_managed_is_green_on_an_empty_block() {
    let (_cfg, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let (pub_dir, channel) = pubtmp();
    let fake = FakeProvider::new(Script::default(), None);
    let prov = provisioner(&fake, channel);

    let drained = run_down_all_managed(&prov, pub_dir.path(), &config).unwrap();
    assert_eq!(drained, 0, "no block — a green no-op");
    assert_eq!(hcloud_deletes(&fake), 0, "a no-op makes no API calls");
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        operator_config(),
        "operator bytes are never rewritten by a no-op"
    );

    // A present-but-empty managed block drains the same way.
    std::fs::write(
        &config,
        format!("-- c\n{BLOCK_BEGIN}\n{BLOCK_END}\nreturn {{}}\n"),
    )
    .unwrap();
    let drained = run_down_all_managed(&prov, pub_dir.path(), &config).unwrap();
    assert_eq!(drained, 0, "an empty block is also a green no-op");
}

// ── CLI surface ──

#[test]
fn burst_cli_parses_the_defaults_and_the_wrapped_command() {
    let cli = Cli::try_parse_from([
        "nau",
        "workers",
        "burst",
        "--provider",
        "hetzner",
        "--type",
        "CX33",
        "--location",
        "hel1",
        "--",
        "echo",
        "hi",
        "there",
    ])
    .unwrap();
    match cli.command {
        Command::Workers {
            command:
                WorkersCommand::Burst {
                    provider,
                    server_type,
                    location,
                    count,
                    max,
                    ttl,
                    timeout,
                    keep,
                    file,
                    command,
                },
        } => {
            assert_eq!(provider, "hetzner");
            assert_eq!(server_type, "CX33");
            assert_eq!(location, "hel1");
            assert_eq!(
                count,
                BurstCount::Fixed(1),
                "v1 bursts are explicit-count, default 1"
            );
            assert_eq!(max, 4, "the fat-finger guard");
            assert_eq!(ttl, "4h");
            assert_eq!(timeout, 600, "the seeded issue --wait ceiling");
            assert!(!keep);
            assert_eq!(file, "nau.lua");
            assert_eq!(command, vec!["echo", "hi", "there"]);
        }
        _ => panic!("expected Workers Burst"),
    }
}

#[test]
fn burst_cli_refuses_a_count_over_the_flag_and_a_missing_command() {
    let err = Cli::try_parse_from([
        "nau",
        "workers",
        "burst",
        "--provider",
        "hetzner",
        "--type",
        "CX33",
        "--location",
        "hel1",
        "--max",
        "2",
        "--count",
        "51",
        "--",
        "true",
    ])
    .map(|_| ())
    .unwrap_err();
    assert!(
        err.to_string().contains("51"),
        "the range parser still bounds --count: {err}"
    );

    let err = Cli::try_parse_from([
        "nau",
        "workers",
        "burst",
        "--provider",
        "hetzner",
        "--type",
        "CX33",
        "--location",
        "hel1",
    ])
    .map(|_| ())
    .unwrap_err();
    assert!(
        err.to_string().contains("--"),
        "no wrapped command after '--' is a parse refusal: {err}"
    );
}

#[test]
fn down_cli_requires_all_managed() {
    let cli = Cli::try_parse_from([
        "nau",
        "workers",
        "down",
        "--all-managed",
        "--provider",
        "hetzner",
        "--file",
        "farm.lua",
    ])
    .unwrap();
    match cli.command {
        Command::Workers {
            command:
                WorkersCommand::Down {
                    all_managed,
                    provider,
                    file,
                },
        } => {
            assert!(all_managed);
            assert_eq!(provider, "hetzner");
            assert_eq!(file, "farm.lua");
        }
        _ => panic!("expected Workers Down"),
    }

    let err = Cli::try_parse_from(["nau", "workers", "down", "--provider", "hetzner"])
        .map(|_| ())
        .unwrap_err();
    assert!(
        err.to_string().contains("--all-managed"),
        "the mode flag is required: {err}"
    );
}

// ── `--count auto` (#304) ──

#[test]
fn burst_auto_count_sizes_the_ticket_fixture() {
    // pending=5, jobs-per-worker=2, max=4 → ceil(5/2)=3, under the guard.
    assert_eq!(burst_auto_count(5, 2, 4).unwrap(), 3);
    assert_eq!(
        burst_auto_count(4, 2, 4).unwrap(),
        2,
        "an exact division never rounds up"
    );
}

#[test]
fn burst_auto_count_clamps_at_max() {
    assert_eq!(
        burst_auto_count(100, 2, 4).unwrap(),
        4,
        "pending beyond the guard cannot buy more workers"
    );
    assert_eq!(
        burst_auto_count(9, 3, 2).unwrap(),
        2,
        "ceil(9/3)=3 clamps to --max 2"
    );
}

#[test]
fn burst_auto_count_refuses_zero_pending_by_name() {
    let err = burst_auto_count(0, 2, 4).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("0 pending"), "names the count: {text}");
    assert!(
        text.contains("nothing to build"),
        "names why nothing is provisioned: {text}"
    );
}

#[test]
fn burst_auto_refuses_a_non_build_command_by_name() {
    let err = nau::cli::wrapped_build(&["echo".to_string(), "hi".to_string()])
        .map(|_| ())
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("is not one"), "names the refusal: {text}");
    assert!(
        text.contains("echo hi"),
        "names the wrapped command: {text}"
    );

    let err = nau::cli::wrapped_build(&[
        "nau".to_string(),
        "workers".to_string(),
        "burst".to_string(),
    ])
    .map(|_| ())
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("is not one"),
        "a nau command that is not a build refuses the same way: {err:#}"
    );

    assert!(
        nau::cli::wrapped_build(&["build".to_string(), "--offline".to_string()]).is_ok(),
        "the bare `build` shorthand is the documented wrapped spelling"
    );
}

#[test]
fn burst_cli_parses_count_auto_beside_explicit_counts() {
    let burst = |count: &[&str]| {
        Cli::try_parse_from(
            [
                "nau",
                "workers",
                "burst",
                "--provider",
                "hetzner",
                "--type",
                "CX33",
                "--location",
                "hel1",
            ]
            .iter()
            .copied()
            .chain(count.iter().copied())
            .chain(["--", "true"])
            .collect::<Vec<_>>(),
        )
        .unwrap()
    };
    match burst(&["--count", "auto"]).command {
        Command::Workers {
            command: WorkersCommand::Burst { count, .. },
        } => assert_eq!(count, BurstCount::Auto, "`auto` parses as the sizing mode"),
        _ => panic!("expected Workers Burst"),
    }
    match burst(&["--count", "3"]).command {
        Command::Workers {
            command: WorkersCommand::Burst { count, .. },
        } => assert_eq!(
            count,
            BurstCount::Fixed(3),
            "an explicit count is unchanged"
        ),
        _ => panic!("expected Workers Burst"),
    }
    match burst(&[]).command {
        Command::Workers {
            command: WorkersCommand::Burst { count, .. },
        } => assert_eq!(count, BurstCount::Fixed(1), "the default stays 1"),
        _ => panic!("expected Workers Burst"),
    }
}
