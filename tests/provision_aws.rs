//! The AWS provider (#195) driven end to end against a scripted
//! `CommandRunner` fake: the fake plays the `aws` CLI (SSM parameter,
//! run-instances, describe, describe-volumes, terminate — from scripted
//! state), records every argv, and answers nothing else. No network, no
//! real aws, no credentials — the ticket's live lanes (env-gated on AWS
//! credentials) are deferred; this fake-API suite plus the dry-run plan
//! is the proof surface. (No ssh-keygen arm: the amendment removed the
//! coordinator-side mint — a provision that tried to ssh-keygen would
//! fail loudly here.)

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use nau::command::{CommandRunner, RunnerOutput};
use nau::provision::aws::{
    AwsProvisioner, UBUNTU_LTS_SSM_PARAMETER, WORKER_SPOT_TAG, WORKER_TAG, WORKER_TTL_TAG,
};
use nau::provision::publish::PublishChannel;
use nau::provision::{
    parse_ttl, render_user_data, ProvisionRequest, Provisioner, UserDataParams, BLOCK_BEGIN,
    BLOCK_END, PLAN_MACHINE_IDENTITY, PLAN_PUBLISH_TOKEN, PLAN_PUBLISH_URL,
};

const OPERATOR_KEY: &str = "ssh-ed25519 AAAAoperatorkey operator@example";
const BINARY_URL: &str = "https://example.invalid/nau-amd64";
const REGION: &str = "eu-central-1";
const AMI: &str = "ami-0abcdef1234567890";
/// The host CA fingerprint the request carries (valid
/// `SHA256:` + 43 base64 chars — the pin grammar's fingerprint form).
const CA_FPR: &str = "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfG";
const PUBLISH_URL: &str = "https://coordinator.example/publish";

/// A shape-valid ed25519 public line — throwaway fixture bytes, no
/// crypto. Reused as the published-key fixture in payload-shape tests.
const TEST_HOST_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkvsDFv9XrohqXsJvKK8dFbGFe5vN3fGcLgoW8cR3UxQ nau-worker-host-key";

/// A fixed marker expiry for template-shape assertions (decimal epoch
/// seconds — the #269 sweep's `is_epoch` shape).
const MARKER_EPOCH: u64 = 1_788_000_000;

// ── The scripted provider CLI ──

#[derive(Clone, Default)]
struct Script {
    /// The SSM parameter resolves to a non-AMI string.
    bad_ami: bool,
    create_fails: bool,
    /// The created instances come back with NO public IPv4 (a subnet that
    /// does not auto-assign).
    no_public_ip: bool,
    describe_fails: bool,
    terminate_fails: bool,
    /// Fail terminates once this many have already succeeded — scripts a
    /// MIXED teardown: some instances terminated, some stuck billing.
    terminate_fails_after: usize,
    /// Volumes the fake reports attached to any instance (the #269 v2
    /// pre-delete check's input).
    attached_volumes: usize,
}

/// Plays the `aws` CLI from scripted state and records every argv.
/// Cheap to clone; all clones share one call log.
#[derive(Clone)]
struct FakeAws {
    calls: Arc<Mutex<Vec<Vec<String>>>>,
    /// (path, unix mode, content) of every `--user-data file://` blob the
    /// fake served, captured at call time — the real blob is removed once
    /// its create call served it.
    user_data_files: Arc<Mutex<Vec<(PathBuf, u32, String)>>>,
    /// Successful terminate count, shared across clones (drives
    /// `terminate_fails_after`).
    terminates_done: Arc<Mutex<usize>>,
    /// Successful create count, shared across clones — the per-create
    /// instance-id namespace.
    creates_done: Arc<Mutex<usize>>,
    script: Script,
}

impl FakeAws {
    fn new(script: Script) -> Self {
        FakeAws {
            calls: Arc::new(Mutex::new(Vec::new())),
            user_data_files: Arc::new(Mutex::new(Vec::new())),
            terminates_done: Arc::new(Mutex::new(0)),
            creates_done: Arc::new(Mutex::new(0)),
            script,
        }
    }
}

impl CommandRunner for FakeAws {
    fn run(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        self.calls.lock().unwrap().push(argv.to_vec());
        match argv[0].as_str() {
            "aws" => self.aws(argv),
            other => Ok(RunnerOutput {
                code: 1,
                stdout: vec![],
                stderr: format!("unexpected program in test: {other}"),
            }),
        }
    }
}

impl FakeAws {
    fn aws(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        // The destroy path resolves the region from the ambient CLI
        // configuration, so `--region X` is OPTIONAL here.
        let rest: &[String] = if argv.get(1).map(|s| s.as_str()) == Some("--region") {
            &argv[3..]
        } else {
            &argv[1..]
        };
        let rest: Vec<&str> = rest.iter().map(|s| s.as_str()).collect();
        match rest.as_slice() {
            ["ssm", "get-parameter", "--name", _param, "--query", "Parameter.Value", "--output", "text"] =>
            {
                if self.script.bad_ami {
                    return Ok(ok_out("None"));
                }
                Ok(ok_out(&format!("{AMI}\n")))
            }
            ["ec2", "run-instances", ..] => {
                if self.script.create_fails {
                    return Ok(fail_out(
                        "An error occurred (AuthFailure) when calling the RunInstances operation (fake)",
                    ));
                }
                if let Some(i) = argv.iter().position(|a| a == "--user-data") {
                    // The value is the `file://` URL; capture the blob and
                    // its mode at call time.
                    let raw = &argv[i + 1];
                    let path = PathBuf::from(raw.strip_prefix("file://").unwrap_or(raw));
                    use std::os::unix::fs::PermissionsExt;
                    let mode = std::fs::metadata(&path)
                        .map(|m| m.permissions().mode() & 0o777)
                        .unwrap_or(0);
                    let content = std::fs::read_to_string(&path).unwrap_or_default();
                    self.user_data_files
                        .lock()
                        .unwrap()
                        .push((path, mode, content));
                }
                let count: usize = argv
                    .iter()
                    .position(|a| a == "--count")
                    .and_then(|i| argv[i + 1].parse().ok())
                    .unwrap_or(1);
                // Distinct ids per create call: the amendment makes
                // provision issue one `--count 1` create per machine,
                // and two machines must never collide on an id.
                assert_eq!(count, 1, "the amendment pins per-instance creates");
                let call = {
                    let mut c = self.creates_done.lock().unwrap();
                    *c += 1;
                    *c
                };
                let ids: Vec<serde_json::Value> = (1..=count)
                    .map(|_| serde_json::json!(format!("i-0{call:04x}")))
                    .collect();
                Ok(ok_out(&serde_json::Value::Array(ids).to_string()))
            }
            ["ec2", "describe-instances", "--instance-ids", id, "--query", _, "--output", "json"] =>
            {
                if self.script.describe_fails {
                    return Ok(fail_out(
                        "An error occurred (InvalidInstanceID.NotFound) when calling the DescribeInstances operation (fake)",
                    ));
                }
                if self.script.no_public_ip {
                    return Ok(ok_out("{}"));
                }
                Ok(ok_out(&describe_json(id)))
            }
            ["ec2", "describe-volumes", "--filters", _filter, "--query", _, "--output", "json"] => {
                let volumes: Vec<serde_json::Value> = (1..=self.script.attached_volumes)
                    .map(|i| serde_json::json!(format!("vol-{i:08x}")))
                    .collect();
                Ok(ok_out(&serde_json::Value::Array(volumes).to_string()))
            }
            ["ec2", "terminate-instances", "--instance-ids", _id] => {
                let mut done = self.terminates_done.lock().unwrap();
                if self.script.terminate_fails
                    || (self.script.terminate_fails_after > 0
                        && *done >= self.script.terminate_fails_after)
                {
                    return Ok(fail_out(
                        "An error occurred (InternalError) when calling the TerminateInstances operation (fake)",
                    ));
                }
                *done += 1;
                Ok(ok_out("{}"))
            }
            other => Ok(RunnerOutput {
                code: 1,
                stdout: vec![],
                stderr: format!("unexpected aws call in test: {other:?}"),
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

/// Deterministic per-id describe document: the trailing hex of the fake
/// id picks a distinct 203.0.113.x address (TEST-NET-3).
fn describe_json(id: &str) -> String {
    let nibble = id.chars().last().and_then(|c| c.to_digit(16)).unwrap_or(1);
    let ip = format!("203.0.113.{}", 10 + nibble);
    serde_json::json!({
        "InstanceId": id,
        "State": { "Name": "running" },
        "PublicIpAddress": ip
    })
    .to_string()
}

// ── Fixtures ──

fn request(config: &Path, dry_run: bool) -> ProvisionRequest {
    ProvisionRequest {
        server_type: "c7i.large".into(),
        location: REGION.into(),
        count: 1,
        ttl_secs: parse_ttl("4h").unwrap(),
        spot: false,
        max_price: None,
        dry_run,
        config: config.to_path_buf(),
        ca_fingerprint: Some(CA_FPR.into()),
    }
}

/// A publish channel over a throwaway (recreated-on-demand) home — the
/// provider tests never read the registry back.
fn throwaway_publish_channel() -> PublishChannel {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    PublishChannel {
        url: PUBLISH_URL.into(),
        home: std::env::temp_dir().join(format!("nau-aws-publish-test-{nanos}")),
    }
}

/// A publish channel over a bound throwaway home — for tests that read
/// the token registry back.
fn pubtmp() -> (tempfile::TempDir, PublishChannel) {
    let d = tempfile::tempdir().unwrap();
    let channel = PublishChannel {
        url: PUBLISH_URL.into(),
        home: d.path().to_path_buf(),
    };
    (d, channel)
}

fn provisioner(fake: &FakeAws, credentials: Option<&str>) -> AwsProvisioner<FakeAws> {
    provisioner_with(fake, credentials, Some(throwaway_publish_channel()))
}

fn provisioner_with(
    fake: &FakeAws,
    credentials: Option<&str>,
    publish: Option<PublishChannel>,
) -> AwsProvisioner<FakeAws> {
    AwsProvisioner::new(
        fake.clone(),
        credentials.map(|c| c.to_string()),
        BINARY_URL.into(),
        OPERATOR_KEY.into(),
        publish,
    )
}

fn workspace(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join(name);
    (dir, config)
}

fn operator_config() -> &'static str {
    "-- operator config: hand-written, never rewritten by nau\nlocal_jobs = 2\nworkers = {}\n\nreturn {}\n"
}

fn calls(fake: &FakeAws) -> Vec<Vec<String>> {
    fake.calls.lock().unwrap().clone()
}

fn aws_calls(fake: &FakeAws) -> Vec<Vec<String>> {
    calls(fake)
        .into_iter()
        .filter(|argv| argv[0] == "aws")
        .collect()
}

fn flat(argv: &[String]) -> String {
    argv.join("\u{1f}")
}

// ── Local refusals (all before ANY API call) ──

#[test]
fn no_credentials_refuse_before_any_api_call() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAws::new(Script::default());
    let err = provisioner(&fake, None)
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("no AWS credentials"),
        "refusal names the missing credentials: {text}"
    );
    assert!(
        text.contains("AWS_ACCESS_KEY_ID"),
        "refusal names the checked sources: {text}"
    );
    assert!(
        aws_calls(&fake).is_empty(),
        "no API call before the credentials refusal"
    );
}

#[test]
fn spot_requires_a_price_cap() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAws::new(Script::default());
    let mut req = request(&config, false);
    req.spot = true;
    let err = provisioner(&fake, Some("env")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("--spot requires --max-price"), "{text}");
    assert!(
        aws_calls(&fake).is_empty(),
        "an uncapped spot bid is refused before any API call"
    );
}

#[test]
fn a_price_cap_requires_spot() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAws::new(Script::default());
    let mut req = request(&config, false);
    req.max_price = Some("0.05".into());
    let err = provisioner(&fake, Some("env")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("--max-price requires --spot"),
        "on-demand has no bid to cap: {text}"
    );
    assert!(aws_calls(&fake).is_empty(), "refused before any API call");
}

#[test]
fn the_price_cap_must_be_positive_finite_decimal() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    for cap in ["0", "-1", "abc", "NaN", "inf"] {
        let fake = FakeAws::new(Script::default());
        let mut req = request(&config, false);
        req.spot = true;
        req.max_price = Some(cap.into());
        let err = provisioner(&fake, Some("env")).provision(&req).unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("--max-price must be"),
            "cap '{cap}' refused: {text}"
        );
        assert!(
            aws_calls(&fake).is_empty(),
            "a bad cap never reaches the API (cap: {cap})"
        );
    }
}

// ── Dry run ──

#[test]
fn dry_run_makes_no_api_call_and_needs_no_credentials() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAws::new(Script::default());
    let mut req = request(&config, true);
    req.spot = true;
    req.max_price = Some("0.043".into());
    let workers = provisioner(&fake, None).provision(&req).unwrap();
    assert!(workers.is_empty(), "a dry run provisions nothing");
    assert!(
        aws_calls(&fake).is_empty(),
        "dry run must not touch the API: {:?}",
        aws_calls(&fake)
    );
}

// ── Provision ──

#[test]
fn provision_resolves_creates_describes_pins_and_tags() {
    let (dir, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAws::new(Script::default());
    let mut req = request(&config, false);
    req.count = 2;
    let workers = provisioner(&fake, Some("AWS_ACCESS_KEY_ID"))
        .provision(&req)
        .unwrap();
    assert_eq!(workers.len(), 2);

    // The worker handle is the instance id (the destroy verb's argument);
    // the address comes from the describe document; the pin is the CA
    // fingerprint (the amendment's pin — one root, not per-worker keys).
    for w in &workers {
        assert!(w.name.starts_with("i-"), "{}", w.name);
        assert!(
            w.address.starts_with("ssh://root@203.0.113."),
            "{}",
            w.address
        );
        assert_eq!(w.host_key, CA_FPR, "the pin IS the CA fingerprint");
    }

    // The create shape: AMI from the SSM parameter, instance type, count,
    // user-data file, contract tags, and the region on every call — with
    // NO market options on the on-demand default. One create PER
    // instance (`--count 1` each): EC2 user-data is immutable and the
    // one-time publish token is per machine, so the batch create became
    // per-instance creates (the amendment's per-machine identity).
    let creates: Vec<Vec<String>> = aws_calls(&fake)
        .into_iter()
        .filter(|argv| flat(argv).contains("ec2\u{1f}run-instances"))
        .collect();
    assert_eq!(
        creates.len(),
        2,
        "one create per instance (per-machine token + identity)"
    );
    for argv in &creates {
        let f = flat(argv);
        assert!(
            f.contains("--region\u{1f}eu-central-1"),
            "region rides the call: {f}"
        );
        assert!(f.contains(&format!("--image-id\u{1f}{AMI}")), "{f}");
        assert!(f.contains("--instance-type\u{1f}c7i.large"), "{f}");
        assert!(f.contains("--count\u{1f}1"), "{f}");
        assert!(
            f.contains("--user-data\u{1f}file://"),
            "user-data rides the authenticated channel: {f}"
        );
        let tag_idx = argv
            .iter()
            .position(|a| a == "--tag-specifications")
            .unwrap();
        let tags = &argv[tag_idx + 1];
        assert!(
            tags.contains(&format!("Key={WORKER_TAG},Value=true")),
            "{tags}"
        );
        assert!(
            !tags.contains(WORKER_SPOT_TAG),
            "on-demand carries no spot tag: {tags}"
        );
        let ttl_frag_start = tags
            .find(&format!("Key={WORKER_TTL_TAG},"))
            .expect("ttl tag present");
        let rest = &tags[ttl_frag_start..];
        let value_start = rest.find("Value=").unwrap() + "Value=".len();
        let value_end = rest[value_start..].find('}').unwrap() + value_start;
        let epoch: u64 = rest[value_start..value_end].parse().unwrap();
        assert!(epoch > 1_600_000_000, "the tag value is the TTL epoch");
        assert!(
            !f.contains("--instance-market-options"),
            "on-demand default never bids: {f}"
        );
        assert!(
            !f.contains("AWS_ACCESS_KEY_ID"),
            "credentials never enter argv: {f}"
        );
    }

    // The staged blobs (captured at create time — removed once served):
    // NO private half anywhere (the amendment's absence property, over
    // the real sent bytes), the publish block rides it, each instance's
    // machine identity is its own name, and the two tokens differ.
    let staged = fake.user_data_files.lock().unwrap();
    assert_eq!(staged.len(), 2, "one staged blob per create");
    for (_, _, user_data) in staged.iter() {
        assert!(
            !user_data.contains("BEGIN OPENSSH PRIVATE KEY"),
            "no private half rides user-data"
        );
        assert!(user_data.contains("/etc/nau/publish-host-key.sh"));
        assert!(user_data.contains(OPERATOR_KEY));
        assert!(
            user_data.contains("MACHINE_IDENTITY='nau-worker-"),
            "the machine identity is the instance name"
        );
    }
    let token_of = |blob: &str| {
        blob.lines()
            .find(|l| l.trim_start().starts_with("PUBLISH_TOKEN='"))
            .map(|l| {
                l.trim()
                    .trim_start_matches("PUBLISH_TOKEN='")
                    .trim_end_matches('\'')
            })
            .expect("token line")
            .to_string()
    };
    assert_ne!(token_of(&staged[0].2), token_of(&staged[1].2));
    drop(staged);

    // Config: the managed block holds exactly the two entries; the file
    // still evaluates.
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(text.contains(BLOCK_BEGIN) && text.contains(BLOCK_END));
    assert_eq!(text.matches("table.insert(workers, ").count(), 2);
    assert!(text.contains("-- operator config"), "operator text intact");
    assert!(text.contains("return {}"), "return intact");
    assert!(nau::lua::evaluate_file(config.to_str().unwrap()).is_ok());
    // Nothing was terminated on the happy path.
    assert!(
        !aws_calls(&fake)
            .iter()
            .any(|argv| flat(argv).contains("terminate-instances")),
        "happy provision never terminates"
    );
    let _ = dir;
}

#[test]
fn spot_shape_bids_the_cap_and_terminates_on_eviction() {
    // #195 spot shape: one-time, terminate-on-interruption (eviction =
    // T5 worker loss — never a stop/hibernate that pretends the machine
    // survives), the cap riding MaxPrice verbatim, and the spot tag
    // naming the eviction class.
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAws::new(Script::default());
    let mut req = request(&config, false);
    req.spot = true;
    req.max_price = Some("0.043".into());
    provisioner(&fake, Some("env")).provision(&req).unwrap();

    let create = aws_calls(&fake)
        .into_iter()
        .find(|argv| flat(argv).contains("ec2\u{1f}run-instances"))
        .unwrap();
    let mo_idx = create
        .iter()
        .position(|a| a == "--instance-market-options")
        .expect("spot run carries market options");
    let options: serde_json::Value = serde_json::from_str(&create[mo_idx + 1]).unwrap();
    assert_eq!(options["MarketType"], "spot");
    assert_eq!(options["SpotOptions"]["MaxPrice"], "0.043");
    assert_eq!(options["SpotOptions"]["SpotInstanceType"], "one-time");
    assert_eq!(
        options["SpotOptions"]["InstanceInterruptionBehavior"], "terminate",
        "an eviction is worker loss, never a stop/hibernate"
    );
    let tag_idx = create
        .iter()
        .position(|a| a == "--tag-specifications")
        .unwrap();
    assert!(
        create[tag_idx + 1].contains(&format!("Key={WORKER_SPOT_TAG},Value=true")),
        "the spot tag names the eviction class: {}",
        create[tag_idx + 1]
    );
}

#[test]
fn ami_resolution_failure_refuses_before_any_create() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeAws::new(Script {
        bad_ami: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains(UBUNTU_LTS_SSM_PARAMETER), "{text}");
    assert!(text.contains("did not resolve to an AMI id"), "{text}");
    assert!(
        !aws_calls(&fake)
            .iter()
            .any(|argv| flat(argv).contains("run-instances")),
        "no create with a guessed image"
    );
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "config untouched"
    );
}

#[test]
fn create_failure_leaves_no_instance_and_no_config_change() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeAws::new(Script {
        create_fails: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("AuthFailure") || text.contains("RunInstances"),
        "provider error named: {text}"
    );
    assert!(
        !aws_calls(&fake)
            .iter()
            .any(|argv| flat(argv).contains("terminate-instances")),
        "nothing was created, so nothing is torn down"
    );
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "config untouched"
    );
}

#[test]
fn describe_failure_after_create_terminates() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeAws::new(Script {
        describe_fails: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("terminated 1 created instance(s)"), "{text}");
    assert_eq!(
        aws_calls(&fake)
            .iter()
            .filter(|argv| flat(argv).contains("terminate-instances"))
            .count(),
        1,
        "the created instance is terminated"
    );
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "no pin without an address"
    );
}

#[test]
fn no_public_ipv4_refuses_and_tears_down() {
    // A subnet that does not auto-assign public IPv4 would produce an
    // unreachable worker: fail-closed with the remedy named, never a pin
    // to an address that cannot be reached.
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeAws::new(Script {
        no_public_ip: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("no public IPv4"), "{text}");
    assert!(text.contains("auto-assign"), "the remedy is named: {text}");
    assert!(text.contains("terminated 1 created instance(s)"), "{text}");
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "config untouched"
    );
}

#[test]
fn pin_failure_after_create_terminates() {
    // A config that cannot be pinned (missing file) must not leave a
    // live instance: teardown-on-failure is the ADR-0045 atomicity.
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("absent").join("nau.lua");
    let fake = FakeAws::new(Script::default());
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("terminated 1 created instance(s)"), "{text}");
    assert!(text.contains("config untouched"), "{text}");
}

// ── Teardown truthfulness ──

#[test]
fn teardown_terminate_failure_names_the_residual_instance() {
    // A teardown terminate that fails must NOT read as torn down: the
    // error names the still-billing residual and the reclaim path.
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeAws::new(Script {
        describe_fails: true,
        terminate_fails: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("terminated 0 created instance(s)"), "{text}");
    assert!(text.contains("FAILED to terminate i-"), "{text}");
    assert!(text.contains("still running and billing"), "{text}");
    assert!(text.contains("'nau workers destroy'"), "{text}");
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "config untouched"
    );
}

#[test]
fn teardown_reports_mixed_terminate_results() {
    // Two instances created, the SECOND pin refuses (an operator-owned
    // entry already holds its address — nau never rewrites operator
    // text), and the SECOND teardown terminate fails: the first is
    // honestly counted terminated AND the stuck one is named — neither
    // half can vanish into a blanket success line.
    let (_dir, config) = workspace("nau.lua");
    // Fake ids i-0aaa21 / i-0aaa22 describe to 203.0.113.11 / .12: the
    // operator-owned entry at .12 makes pin #2 refuse after pin #1
    // pinned .11.
    std::fs::write(
        &config,
        "workers = { { address = \"ssh://root@203.0.113.12\", host_key = \"ssh-ed25519 AAAAoperator operator\" } }\nreturn {}\n",
    )
    .unwrap();
    let fake = FakeAws::new(Script {
        terminate_fails_after: 1,
        ..Default::default()
    });
    let mut req = request(&config, false);
    req.count = 2;
    let err = provisioner(&fake, Some("env")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("terminated 1 created instance(s)"), "{text}");
    assert!(text.contains("FAILED to terminate i-"), "{text}");
    assert!(text.contains("still running and billing"), "{text}");
    // NOTE: the pin that DID succeed stays in the config (the torn-down
    // instance residue) — the same pre-existing partial-pin residue the
    // #281 review names for hetzner (m1), not this ticket's scope.
}

// ── User-data staging hygiene ──

#[test]
fn user_data_is_staged_inside_the_provision_tempdir_at_0600() {
    // The blob carries the one-time publish bearer: it must live in the
    // provision tempdir (so it dies with the run) at mode 0600.
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAws::new(Script::default());
    provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap();

    let staged = fake.user_data_files.lock().unwrap();
    assert_eq!(staged.len(), 1, "one run, one staged blob: {staged:?}");
    let (path, mode, _) = staged[0].clone();
    drop(staged);
    assert_eq!(
        path.file_name().unwrap(),
        "user-data.yaml",
        "staged inside the provision tempdir"
    );
    assert_ne!(
        path.parent().unwrap(),
        std::env::temp_dir(),
        "not directly in the OS temp dir"
    );
    assert_eq!(mode, 0o600, "the blob is 0600 while it exists");
    assert!(
        !path.exists(),
        "the staged blob is removed once its create call served it"
    );
}

// ── Destroy ──

#[test]
fn destroy_terminates_the_instance_and_evicts_the_managed_entry() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAws::new(Script::default());
    let workers = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap();
    let name = workers[0].name.clone();
    let address = workers[0].address.clone();

    let evicted = provisioner(&fake, Some("env"))
        .destroy(&name, &config)
        .unwrap();
    assert!(evicted, "a managed entry was evicted");

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
    let terminates: Vec<_> = aws_calls(&fake)
        .into_iter()
        .filter(|argv| flat(argv).contains("terminate-instances"))
        .collect();
    assert_eq!(terminates.len(), 1);
    assert!(flat(&terminates[0]).contains(&name));
}

#[test]
fn destroy_requires_credentials_before_any_api_call() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAws::new(Script::default());
    let err = provisioner(&fake, None)
        .destroy("i-0aaa11", &config)
        .unwrap_err();
    assert!(format!("{err:#}").contains("no AWS credentials"));
    assert!(aws_calls(&fake).is_empty());
}

#[test]
fn destroy_checks_volumes_before_terminate_and_proceeds_with_a_loud_warning() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAws::new(Script::default());
    let workers = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap();
    let name = workers[0].name.clone();

    // Two volumes attached: the #269 v2 pre-delete check fires.
    let volfake = FakeAws::new(Script {
        attached_volumes: 2,
        ..Default::default()
    });
    provisioner(&volfake, Some("env"))
        .destroy(&name, &config)
        .unwrap();

    let sequence = aws_calls(&volfake);
    let volume_idx = sequence
        .iter()
        .position(|argv| flat(argv).contains("describe-volumes"))
        .expect("volume check ran");
    let terminate_idx = sequence
        .iter()
        .position(|argv| flat(argv).contains("terminate-instances"))
        .expect("terminate ran");
    assert!(
        volume_idx < terminate_idx,
        "the volume check happens BEFORE the terminate: {:?}",
        sequence
    );
}

#[test]
fn destroy_of_an_unknown_instance_is_a_named_refusal() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAws::new(Script {
        describe_fails: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .destroy("i-0nosuch", &config)
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("i-0nosuch"), "{text}");
    assert!(
        !aws_calls(&fake)
            .iter()
            .any(|argv| flat(argv).contains("terminate-instances")),
        "a describe miss never terminates"
    );
}

#[test]
fn destroy_keeps_the_pin_when_the_terminate_fails() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAws::new(Script::default());
    let workers = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap();
    let name = workers[0].name.clone();
    let address = workers[0].address.clone();

    let sloppy = FakeAws::new(Script {
        terminate_fails: true,
        ..Default::default()
    });
    // The shared fake address space: describe succeeds, terminate fails;
    // the pin must survive a live instance.
    let err = provisioner(&sloppy, Some("env"))
        .destroy(&name, &config)
        .unwrap_err();
    assert!(format!("{err:#}").contains("InternalError"));
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(
        text.contains(&format!("address = \"{address}\"")),
        "a failed terminate leaves the pin: the instance is still live"
    );
}

#[test]
fn destroy_of_an_instance_without_a_managed_pin_reports_not_evicted() {
    // Eviction honesty: a terminated instance whose address no managed
    // entry pins must read as NOT evicted — `Ok(false)` — so the verb
    // never claims an eviction that did not happen.
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAws::new(Script::default());
    let evicted = provisioner(&fake, Some("env"))
        .destroy("i-0aaa11", &config)
        .unwrap();
    assert!(!evicted, "no managed entry → nothing evicted");
}

// ── The base-image pin ──

#[test]
fn the_base_image_resolves_the_latest_ubuntu_lts_never_a_codename() {
    // ADR-0046: the contract pins "latest LTS" — the SSM parameter path
    // carries the release number (26.04 at the 2026-09-27 decision,
    // #273's reconciliation), never a codename. The shape rule is the
    // same one the Hetzner slug test asserts.
    assert!(UBUNTU_LTS_SSM_PARAMETER.contains("/26.04/"));
    let release = UBUNTU_LTS_SSM_PARAMETER
        .split("/canonical/ubuntu/server/")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .expect("the release segment");
    assert_eq!(
        release.len(),
        "NN.NN".len(),
        "ubuntu-NN.NN, never a codename: {UBUNTU_LTS_SSM_PARAMETER}"
    );
    assert!(
        UBUNTU_LTS_SSM_PARAMETER.ends_with("ami-id"),
        "the parameter resolves to an AMI id"
    );
}

// ── Amendment convergence: guest-local keys, publish callback, one-time tokens ──
// (the same block the Hetzner suite carries — one converted shape, five providers)

#[test]
fn dry_run_user_data_resolves_to_the_real_template() {
    // The dry-run render path runs for real (local only); the rendered
    // user-data must be byte-identical to the shared template's output
    // for the same inputs — the plan is the REAL plan (shape-wise: the
    // publish slots carry the documented placeholders, the real
    // per-instance blob differs only there).
    let user_data = render_user_data(&UserDataParams {
        machine_identity: PLAN_MACHINE_IDENTITY,
        publish_url: PLAN_PUBLISH_URL,
        publish_token: PLAN_PUBLISH_TOKEN,
        operator_key: OPERATOR_KEY,
        binary_url: BINARY_URL,
        ttl_expiry_epoch: 1_700_000_000 + 14_400,
    });
    assert!(user_data.starts_with("#cloud-config\n"));
    // Deterministic: same inputs, same blob, same hash — the plan lane
    // diffs this hash against the sent user-data.
    let again = render_user_data(&UserDataParams {
        machine_identity: PLAN_MACHINE_IDENTITY,
        publish_url: PLAN_PUBLISH_URL,
        publish_token: PLAN_PUBLISH_TOKEN,
        operator_key: OPERATOR_KEY,
        binary_url: BINARY_URL,
        ttl_expiry_epoch: 1_700_000_000 + 14_400,
    });
    assert_eq!(user_data, again);
}

#[test]
fn user_data_generates_keys_guest_side_and_never_carries_a_private_half() {
    // THE amendment assertion (ADR-0045): the template turns host-key
    // generation ON (explicit — never a default relied on) and contains
    // NO private half anywhere. The absence is the security property.
    let user_data = render_user_data(&UserDataParams {
        machine_identity: "nau-worker-abc-01",
        publish_url: PUBLISH_URL,
        publish_token: "a".repeat(64).as_str(),
        operator_key: OPERATOR_KEY,
        binary_url: BINARY_URL,
        ttl_expiry_epoch: MARKER_EPOCH,
    });
    // Guest-local generation, explicit.
    assert!(user_data.contains("ssh_deletekeys: true"));
    assert!(user_data.contains("ssh_genkey: true"));
    // Absence: no injected keypair write_files, no PEM, no mint.
    assert!(!user_data.contains("path: /etc/ssh/ssh_host_ed25519_key\n"));
    assert!(!user_data.contains("BEGIN OPENSSH PRIVATE KEY"));
    assert!(!user_data.contains("ssh-keygen"));
    assert!(
        !user_data.contains(TEST_HOST_PUB),
        "no coordinator-minted key material rides the blob"
    );
    // The old post-sshd scrub is dead code under the amendment — removed.
    assert!(!user_data.contains("rm -f /var/lib/cloud/instances"));
    // The operator login flow is untouched.
    assert!(user_data.contains("path: /root/.ssh/authorized_keys"));
    assert!(user_data.contains(OPERATOR_KEY));
}

#[test]
fn user_data_carries_the_publish_callback_and_one_time_token() {
    // The publish block: a 0600 env file with the three per-machine
    // slots, a 0700 script that reads the GUEST-GENERATED public half +
    // the cloud-init instance-data document, and the POST with the
    // one-time bearer. The URL/token/identity ride the env file, never
    // loose argv interpolation.
    let token = "b".repeat(64);
    let user_data = render_user_data(&UserDataParams {
        machine_identity: "nau-worker-abc-01",
        publish_url: PUBLISH_URL,
        publish_token: &token,
        operator_key: OPERATOR_KEY,
        binary_url: BINARY_URL,
        ttl_expiry_epoch: MARKER_EPOCH,
    });
    assert!(user_data.contains("path: /etc/nau/publish.env\n    permissions: \"0600\""));
    assert!(user_data.contains(&format!("MACHINE_IDENTITY='nau-worker-abc-01'")));
    assert!(user_data.contains(&format!("PUBLISH_URL='{PUBLISH_URL}'")));
    assert!(user_data.contains(&format!("PUBLISH_TOKEN='{token}'")));
    assert!(user_data.contains("path: /etc/nau/publish-host-key.sh\n    permissions: \"0700\""));
    // The script reads the locally generated ed25519 public half and the
    // cloud-init normalized instance-data (the D3 principal content).
    assert!(user_data.contains("/etc/ssh/ssh_host_ed25519_key.pub"));
    assert!(user_data.contains("/run/cloud-init/instance-data.json"));
    assert!(user_data.contains("instance_identity"));
    assert!(user_data.contains("Authorization: Bearer $PUBLISH_TOKEN"));
    // The publish runs LAST (after curl is installed) and retries are
    // bounded — a not-yet-up coordinator never bricks the boot.
    let runcmds: Vec<&str> = user_data
        .lines()
        .filter(|l| l.starts_with("  - "))
        .collect();
    assert_eq!(
        runcmds.last().copied(),
        Some("  - systemctl enable --now nau-pickup-host-cert.service"),
        "the pickup unit enable is the final runcmd: {runcmds:?}"
    );
    let publish_at = runcmds
        .iter()
        .position(|l| *l == "  - /etc/nau/publish-host-key.sh")
        .expect("publish is a runcmd");
    assert_eq!(
        publish_at + 1,
        runcmds.len() - 1,
        "publish directly precedes the pickup enable (the channel is proven up): {runcmds:?}"
    );
    assert!(user_data.contains("while [ \"$i\" -lt 10 ]"));
    assert!(user_data.contains("curl -fsS -m 30"));
    // The TTL marker (the #269 sweep contract): one DECIMAL EPOCH-SECONDS
    // line — the sweep's is_epoch parses decimal only.
    assert!(user_data.contains("path: /etc/nau/worker-ttl"));
    assert!(user_data.contains(&format!("content: |\n      {MARKER_EPOCH}\n")));
    // Pinned nau binary install + sshd hardening.
    assert!(user_data.contains(BINARY_URL));
    assert!(user_data.contains("PasswordAuthentication no"));
    assert!(user_data.contains("PermitRootLogin prohibit-password"));
    // The provider credential never rides user-data.
    assert!(!user_data.contains("AWS_SECRET_ACCESS_KEY"));
}

#[test]
fn each_server_gets_its_own_recorded_one_time_token() {
    // The convergence property, read back from the coordinator registry:
    // N instances → N recorded tokens, each bound to its own machine
    // identity, none consumed (issuance is sub-task 3).
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let (pubhome, publish) = pubtmp();
    let fake = FakeAws::new(Script::default());
    let mut req = request(&config, false);
    req.count = 2;
    provisioner_with(&fake, Some("env"), Some(publish))
        .provision(&req)
        .unwrap();

    let registry =
        std::fs::read_to_string(pubhome.path().join(".config/nau/ca/pending/tokens.json"))
            .expect("the registry exists after provision");
    let v: serde_json::Value = serde_json::from_str(&registry).unwrap();
    let tokens = v["tokens"].as_array().unwrap();
    assert_eq!(tokens.len(), 2, "one recorded issuance per instance");
    let mut identities: Vec<&str> = tokens
        .iter()
        .map(|t| t["machine_identity"].as_str().unwrap())
        .collect();
    identities.sort();
    assert!(
        identities.windows(2).all(|w| w[0] != w[1]),
        "one identity per instance: {identities:?}"
    );
    for t in tokens {
        assert!(
            t["consumed_at_epoch"].is_null(),
            "nothing consumed yet — issuance is sub-task 3"
        );
    }
}

#[test]
fn no_publish_channel_refuses_before_any_api_call() {
    // Fail-closed: a provision whose guest cannot publish can never be
    // issued a certificate — refused before the create, nothing torn
    // down, config untouched.
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAws::new(Script::default());
    let err = provisioner_with(&fake, Some("env"), None)
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("no publish channel"), "{text}");
    assert!(text.contains("NAU_PUBLISH_URL"), "{text}");
    assert!(
        aws_calls(&fake).is_empty(),
        "no API call before the publish-channel refusal"
    );
}

#[test]
fn no_ca_fingerprint_refuses_before_any_api_call() {
    // Fail-closed interim: the pin IS the CA fingerprint; a request
    // without one is a named refusal before any API call.
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAws::new(Script::default());
    let mut req = request(&config, false);
    req.ca_fingerprint = None;
    let err = provisioner(&fake, Some("env")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("no host CA fingerprint"), "{text}");
    assert!(text.contains("nau ca keygen"), "{text}");
    assert!(
        aws_calls(&fake).is_empty(),
        "no API call before the CA-pin refusal"
    );
}
