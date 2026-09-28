//! The GCP provider (#196) driven end to end against a scripted
//! `CommandRunner` fake: the fake plays the `gcloud` CLI (instances
//! create, describe, delete — from scripted state), records every argv,
//! and answers nothing else. No network, no real gcloud, no credentials —
//! the ticket's live lanes (env-gated on GCP credentials) are deferred;
//! this fake-API suite plus the dry-run plan is the proof surface. (No
//! ssh-keygen arm: the amendment removed the coordinator-side mint — a
//! provision that tried to ssh-keygen would fail loudly here.)

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use shuttle::command::{CommandRunner, RunnerOutput};
use shuttle::provision::gcp::{
    GcpProvisioner, IMAGE_FAMILY, IMAGE_PROJECT, WORKER_LABEL, WORKER_PREEMPTIBLE_LABEL,
    WORKER_TTL_LABEL,
};
use shuttle::provision::publish::PublishChannel;
use shuttle::provision::{
    parse_ttl, render_user_data, ProvisionRequest, Provisioner, UserDataParams, BLOCK_BEGIN,
    BLOCK_END, PLAN_MACHINE_IDENTITY, PLAN_PUBLISH_TOKEN, PLAN_PUBLISH_URL,
};

const OPERATOR_KEY: &str = "ssh-ed25519 AAAAoperatorkey operator@example";
const BINARY_URL: &str = "https://example.invalid/shuttle-amd64";
const ZONE: &str = "us-central1-a";
const MACHINE_TYPE: &str = "e2-standard-4";
/// The host CA fingerprint the request carries (valid
/// `SHA256:` + 43 base64 chars — the pin grammar's fingerprint form).
const CA_FPR: &str = "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfG";
const PUBLISH_URL: &str = "https://coordinator.example/publish";

/// A shape-valid ed25519 public line — throwaway fixture bytes, no
/// crypto. Reused as the published-key fixture in payload-shape tests.
const TEST_HOST_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkvsDFv9XrohqXsJvKK8dFbGFe5vN3fGcLgoW8cR3UxQ shuttle-worker-host-key";

/// A fixed marker expiry for template-shape assertions (decimal epoch
/// seconds — the #269 sweep's `is_epoch` shape).
const MARKER_EPOCH: u64 = 1_788_000_000;

// ── The scripted provider CLI ──

#[derive(Clone, Default)]
struct Script {
    create_fails: bool,
    describe_fails: bool,
    /// The created instance comes back with NO external IP (a VPC that
    /// grants none).
    no_external_ip: bool,
    delete_fails: bool,
    /// Fail deletes once this many have already succeeded — scripts a
    /// MIXED teardown: some instances deleted, some stuck billing.
    delete_fails_after: usize,
    /// Extra attached disks with auto-delete OFF (they survive an
    /// instance delete and keep billing — the #269 v2 pre-delete check's
    /// input). The boot disk is always present with auto-delete on.
    attached_disks: usize,
}

/// Plays the `gcloud` CLI from scripted state and records every argv.
/// Cheap to clone; all clones share one call log.
#[derive(Clone)]
struct FakeGcp {
    calls: Arc<Mutex<Vec<Vec<String>>>>,
    /// (path, unix mode, content) of every `--metadata-from-file` blob
    /// the fake served, captured at call time — the real blob is removed
    /// once its create call served it.
    user_data_files: Arc<Mutex<Vec<(PathBuf, u32, String)>>>,
    /// Successful delete count, shared across clones (drives
    /// `delete_fails_after`).
    deletes_done: Arc<Mutex<usize>>,
    script: Script,
}

impl FakeGcp {
    fn new(script: Script) -> Self {
        FakeGcp {
            calls: Arc::new(Mutex::new(Vec::new())),
            user_data_files: Arc::new(Mutex::new(Vec::new())),
            deletes_done: Arc::new(Mutex::new(0)),
            script,
        }
    }
}

impl CommandRunner for FakeGcp {
    fn run(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        self.calls.lock().unwrap().push(argv.to_vec());
        match argv[0].as_str() {
            "gcloud" => self.gcloud(argv),
            other => Ok(RunnerOutput {
                code: 1,
                stdout: vec![],
                stderr: format!("unexpected program in test: {other}"),
            }),
        }
    }
}

impl FakeGcp {
    fn gcloud(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        // The destroy path resolves the zone from the ambient gcloud
        // configuration, so `--zone X` is OPTIONAL here.
        let rest: &[String] = if argv.get(1).map(|s| s.as_str()) == Some("--zone") {
            &argv[3..]
        } else {
            &argv[1..]
        };
        let rest: Vec<&str> = rest.iter().map(|s| s.as_str()).collect();
        match rest.as_slice() {
            ["compute", "instances", "create", _name, ..] => {
                if self.script.create_fails {
                    return Ok(fail_out(
                        "ERROR: (gcloud.compute.instances.create) quota exceeded (fake)",
                    ));
                }
                if let Some(i) = argv.iter().position(|a| a == "--metadata-from-file") {
                    // The value is the `user-data=<path>` hand-off;
                    // capture the blob and its mode at call time.
                    let kv = &argv[i + 1];
                    let path = PathBuf::from(kv.strip_prefix("user-data=").unwrap_or(kv));
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
                Ok(ok_out(""))
            }
            ["compute", "instances", "describe", name, "--format", "json"] => {
                if self.script.describe_fails {
                    return Ok(fail_out(&format!(
                        "ERROR: (gcloud.compute.instances.describe) Instance not found: {name} (fake)"
                    )));
                }
                Ok(ok_out(&describe_json(
                    name,
                    self.script.no_external_ip,
                    self.script.attached_disks,
                )))
            }
            ["compute", "instances", "delete", _name, "--quiet"] => {
                let mut done = self.deletes_done.lock().unwrap();
                if self.script.delete_fails
                    || (self.script.delete_fails_after > 0
                        && *done >= self.script.delete_fails_after)
                {
                    return Ok(fail_out(
                        "ERROR: (gcloud.compute.instances.delete) InternalError (fake)",
                    ));
                }
                *done += 1;
                Ok(ok_out(""))
            }
            other => Ok(RunnerOutput {
                code: 1,
                stdout: vec![],
                stderr: format!("unexpected gcloud call in test: {other:?}"),
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

/// Deterministic per-name describe document: the trailing `-NN` of the
/// fake instance name picks a distinct 203.0.113.x address (TEST-NET-3),
/// so describe agrees with itself across the provision/destroy paths.
fn describe_json(name: &str, no_external_ip: bool, attached_disks: usize) -> String {
    let nn: u32 = name
        .rsplit('-')
        .next()
        .and_then(|t| t.parse().ok())
        .unwrap_or(1);
    let ip = format!("203.0.113.{}", 10 + nn);
    let access = if no_external_ip {
        serde_json::json!([])
    } else {
        serde_json::json!([{ "natIP": ip }])
    };
    let mut disks = vec![serde_json::json!({
        "deviceName": format!("{name}-boot"),
        "boot": true,
        "autoDelete": true
    })];
    for i in 1..=attached_disks {
        disks.push(serde_json::json!({
            "deviceName": format!("{name}-disk-{i}"),
            "boot": false,
            "autoDelete": false
        }));
    }
    serde_json::json!({
        "name": name,
        "zone": ZONE,
        "networkInterfaces": [{ "accessConfigs": access }],
        "disks": disks
    })
    .to_string()
}

// ── Fixtures ──

fn request(config: &Path, dry_run: bool) -> ProvisionRequest {
    ProvisionRequest {
        server_type: MACHINE_TYPE.into(),
        location: ZONE.into(),
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
        home: std::env::temp_dir().join(format!("shuttle-gcp-publish-test-{nanos}")),
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

fn provisioner(fake: &FakeGcp, credentials: Option<&str>) -> GcpProvisioner<FakeGcp> {
    provisioner_with(fake, credentials, Some(throwaway_publish_channel()))
}

fn provisioner_with(
    fake: &FakeGcp,
    credentials: Option<&str>,
    publish: Option<PublishChannel>,
) -> GcpProvisioner<FakeGcp> {
    GcpProvisioner::new(
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
    "-- operator config: hand-written, never rewritten by shuttle\nlocal_jobs = 2\nworkers = {}\n\nreturn {}\n"
}

fn calls(fake: &FakeGcp) -> Vec<Vec<String>> {
    fake.calls.lock().unwrap().clone()
}

fn gcloud_calls(fake: &FakeGcp) -> Vec<Vec<String>> {
    calls(fake)
        .into_iter()
        .filter(|argv| argv[0] == "gcloud")
        .collect()
}

fn flat(argv: &[String]) -> String {
    argv.join("\u{1f}")
}

fn creates(fake: &FakeGcp) -> Vec<Vec<String>> {
    gcloud_calls(fake)
        .into_iter()
        .filter(|argv| flat(argv).contains("instances\u{1f}create"))
        .collect()
}

fn deletes(fake: &FakeGcp) -> Vec<Vec<String>> {
    gcloud_calls(fake)
        .into_iter()
        .filter(|argv| flat(argv).contains("instances\u{1f}delete"))
        .collect()
}

// ── Local refusals (all before ANY API call) ──

#[test]
fn no_credentials_refuse_before_any_api_call() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeGcp::new(Script::default());
    let err = provisioner(&fake, None)
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("no GCP credentials"),
        "refusal names the missing credentials: {text}"
    );
    assert!(
        text.contains("GOOGLE_APPLICATION_CREDENTIALS"),
        "refusal names the checked chain: {text}"
    );
    assert!(text.contains("CLOUDSDK_CONFIG"), "{text}");
    assert!(
        text.contains("gcloud auth login"),
        "refusal names the remedy: {text}"
    );
    assert!(
        gcloud_calls(&fake).is_empty(),
        "no API call before the credentials refusal"
    );
}

#[test]
fn max_price_is_refused_on_gcp() {
    // Preemptible pricing is fixed per machine type — there is no bid a
    // cap could name. The flag is refused by name, never silently
    // ignored, with or without --preemptible.
    for spot in [false, true] {
        let (_d, config) = workspace("shuttle.lua");
        std::fs::write(&config, operator_config()).unwrap();
        let fake = FakeGcp::new(Script::default());
        let mut req = request(&config, false);
        req.spot = spot;
        req.max_price = Some("0.05".into());
        let err = provisioner(&fake, Some("env")).provision(&req).unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("--max-price is not supported on gcp"),
            "spot={spot}: {text}"
        );
        assert!(
            gcloud_calls(&fake).is_empty(),
            "refused before any API call (spot={spot})"
        );
    }
}

// ── Dry run ──

#[test]
fn dry_run_makes_no_api_call_and_needs_no_credentials() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeGcp::new(Script::default());
    let mut req = request(&config, true);
    req.spot = true;
    let workers = provisioner(&fake, None).provision(&req).unwrap();
    assert!(workers.is_empty(), "a dry run provisions nothing");
    assert!(
        gcloud_calls(&fake).is_empty(),
        "dry run must not touch the API: {:?}",
        gcloud_calls(&fake)
    );
}

// ── Provision ──

#[test]
fn provision_resolves_creates_describes_pins_and_labels() {
    let (dir, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeGcp::new(Script::default());
    let mut req = request(&config, false);
    req.count = 2;
    let workers = provisioner(&fake, Some("env")).provision(&req).unwrap();
    assert_eq!(workers.len(), 2);

    // The worker handle is the instance name (the destroy verb's
    // argument); the address comes from the describe document; the pin
    // is the CA fingerprint (the amendment's pin — one root, not
    // per-worker keys).
    for w in &workers {
        assert!(w.name.starts_with("shuttle-worker-"), "{}", w.name);
        assert!(
            w.address.starts_with("ssh://root@203.0.113."),
            "{}",
            w.address
        );
        assert_eq!(w.host_key, CA_FPR, "the pin IS the CA fingerprint");
    }

    // The create shape: machine type, image family + project, the zone on
    // every call, the user-data metadata hand-off, contract labels — with
    // NO preemptible flag on the on-demand default.
    let all_creates = creates(&fake);
    assert_eq!(all_creates.len(), 2, "one create call per instance");
    let f = flat(&all_creates[0]);
    assert!(
        f.contains(&format!("--zone\u{1f}{ZONE}")),
        "zone rides the call: {f}"
    );
    assert!(
        f.contains(&format!("--machine-type\u{1f}{MACHINE_TYPE}")),
        "{f}"
    );
    assert!(
        f.contains(&format!("--image-family\u{1f}{IMAGE_FAMILY}")),
        "{f}"
    );
    assert!(
        f.contains(&format!("--image-project\u{1f}{IMAGE_PROJECT}")),
        "{f}"
    );
    assert!(
        f.contains("--metadata-from-file\u{1f}user-data="),
        "user-data rides the authenticated channel: {f}"
    );
    assert!(
        !f.contains("--preemptible"),
        "on-demand default never rides the preemptible flag: {f}"
    );
    assert!(
        !f.contains("GOOGLE_APPLICATION_CREDENTIALS"),
        "credentials never enter argv: {f}"
    );

    // The contract labels: presence=true and the TTL epoch-seconds expiry
    // (the #269 v2 source of truth), no preemptible label on-demand.
    let labels_idx = all_creates[0].iter().position(|a| a == "--labels").unwrap();
    let labels = &all_creates[0][labels_idx + 1];
    assert!(labels.contains(&format!("{WORKER_LABEL}=true")), "{labels}");
    assert!(
        !labels.contains(WORKER_PREEMPTIBLE_LABEL),
        "on-demand carries no preemptible label: {labels}"
    );
    let ttl_frag = labels
        .split(',')
        .find(|kv| kv.starts_with(&format!("{WORKER_TTL_LABEL}=")))
        .expect("ttl label present");
    let epoch: u64 = ttl_frag
        .split('=')
        .nth(1)
        .unwrap()
        .parse()
        .expect("the ttl label value is decimal epoch seconds");
    assert!(epoch > 1_600_000_000, "{ttl_frag}");

    // The staged blobs (captured at create time — removed once served):
    // NO private half anywhere (the amendment's absence property, over
    // the real sent bytes), the publish block rides each blob, and each
    // instance carries its own machine identity + one-time token.
    let staged = fake.user_data_files.lock().unwrap();
    assert_eq!(staged.len(), 2, "one blob capture per create call");
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
    assert_ne!(
        staged[0].2, staged[1].2,
        "each instance carries its own blob (distinct one-time token)"
    );
    for (_, _mode, content) in staged.iter() {
        assert!(
            !content.contains("BEGIN OPENSSH PRIVATE KEY"),
            "no private half rides user-data"
        );
        assert!(content.contains("/etc/shuttle/publish-host-key.sh"));
        assert!(content.contains(OPERATOR_KEY));
        assert!(
            content.contains("MACHINE_IDENTITY='shuttle-worker-"),
            "the machine identity is the instance name"
        );
    }
    drop(staged);

    // Config: the managed block holds exactly the two entries; the file
    // still evaluates.
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(text.contains(BLOCK_BEGIN) && text.contains(BLOCK_END));
    assert_eq!(text.matches("table.insert(workers, ").count(), 2);
    assert!(text.contains("-- operator config"), "operator text intact");
    assert!(text.contains("return {}"), "return intact");
    assert!(shuttle::lua::evaluate_file(config.to_str().unwrap()).is_ok());
    // Nothing was deleted on the happy path.
    assert!(deletes(&fake).is_empty(), "happy provision never deletes");
    let _ = dir;
}

#[test]
fn preemptible_shape_rides_the_flag_and_names_the_eviction_class() {
    // #196: the preemptible VM rides --preemptible on the create call and
    // carries the label naming its eviction class (an eviction is T5
    // worker loss, ADR-0040 Amendment 1 — the machine does not come back).
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeGcp::new(Script::default());
    let mut req = request(&config, false);
    req.spot = true;
    provisioner(&fake, Some("env")).provision(&req).unwrap();

    let create = creates(&fake).into_iter().next().unwrap();
    assert!(
        create.iter().any(|a| a == "--preemptible"),
        "the create call carries --preemptible: {:?}",
        create
    );
    let labels_idx = create.iter().position(|a| a == "--labels").unwrap();
    assert!(
        create[labels_idx + 1].contains(&format!("{WORKER_PREEMPTIBLE_LABEL}=true")),
        "the label names the eviction class: {}",
        create[labels_idx + 1]
    );
}

#[test]
fn create_failure_leaves_no_instance_and_no_config_change() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeGcp::new(Script {
        create_fails: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("quota exceeded"),
        "provider error named: {text}"
    );
    assert!(
        deletes(&fake).is_empty(),
        "nothing was created, so nothing is torn down"
    );
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "config untouched"
    );
}

#[test]
fn describe_failure_after_create_deletes() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeGcp::new(Script {
        describe_fails: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("tore down 1 created instance(s)"), "{text}");
    assert_eq!(deletes(&fake).len(), 1, "the created instance is deleted");
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "no pin without an address"
    );
}

#[test]
fn no_external_ip_refuses_and_tears_down() {
    // A VPC that grants no external address would produce an unreachable
    // worker: fail-closed with the remedy named, never a pin to an
    // address that cannot be reached.
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeGcp::new(Script {
        no_external_ip: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("no external IP"), "{text}");
    assert!(
        text.contains("external address"),
        "the remedy is named: {text}"
    );
    assert!(text.contains("tore down 1 created instance(s)"), "{text}");
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "config untouched"
    );
}

#[test]
fn pin_failure_after_create_deletes() {
    // A config that cannot be pinned (missing file) must not leave a
    // live instance: teardown-on-failure is the ADR-0045 atomicity.
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("absent").join("shuttle.lua");
    let fake = FakeGcp::new(Script::default());
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("tore down 1 created instance(s)"), "{text}");
    assert!(text.contains("config untouched"), "{text}");
}

// ── Teardown truthfulness ──

#[test]
fn teardown_delete_failure_names_the_residual_instance() {
    // A teardown delete that fails must NOT read as torn down: the error
    // names the still-billing residual and the reclaim path.
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeGcp::new(Script {
        describe_fails: true,
        delete_fails: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("tore down 0 created instance(s)"), "{text}");
    assert!(text.contains("FAILED to delete shuttle-worker-"), "{text}");
    assert!(text.contains("still running and billing"), "{text}");
    assert!(text.contains("'shuttle workers destroy'"), "{text}");
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "config untouched"
    );
}

#[test]
fn teardown_reports_mixed_delete_results() {
    // Two instances created, the SECOND pin refuses (an operator-owned
    // entry already holds its address — shuttle never rewrites operator
    // text), and the SECOND teardown delete fails: the first is honestly
    // counted torn down AND the stuck one is named — neither half can
    // vanish into a blanket success line.
    let (_d, config) = workspace("shuttle.lua");
    // Fake names trail -01 / -02, which describe to 203.0.113.11 / .12:
    // the operator-owned entry at .12 makes pin #2 refuse after pin #1
    // pinned .11.
    std::fs::write(
        &config,
        "workers = { { address = \"ssh://root@203.0.113.12\", host_key = \"ssh-ed25519 AAAAoperator operator\" } }\nreturn {}\n",
    )
    .unwrap();
    let fake = FakeGcp::new(Script {
        delete_fails_after: 1,
        ..Default::default()
    });
    let mut req = request(&config, false);
    req.count = 2;
    let err = provisioner(&fake, Some("env")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("tore down 1 created instance(s)"), "{text}");
    assert!(text.contains("FAILED to delete shuttle-worker-"), "{text}");
    assert!(text.contains("still running and billing"), "{text}");
}

// ── User-data staging hygiene ──

#[test]
fn user_data_is_staged_inside_the_provision_tempdir_at_0600() {
    // The blob carries the one-time publish bearer: it must live in the
    // provision tempdir (so it dies with the run) at mode 0600.
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeGcp::new(Script::default());
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
fn destroy_deletes_the_instance_and_evicts_the_managed_entry() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeGcp::new(Script::default());
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
    let all_deletes = deletes(&fake);
    assert_eq!(all_deletes.len(), 1);
    assert!(flat(&all_deletes[0]).contains(&name));
    assert!(
        flat(&all_deletes[0]).contains("--quiet"),
        "the delete never hangs on an interactive prompt"
    );
}

#[test]
fn destroy_requires_credentials_before_any_api_call() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeGcp::new(Script::default());
    let err = provisioner(&fake, None)
        .destroy("shuttle-worker-aa-01", &config)
        .unwrap_err();
    assert!(format!("{err:#}").contains("no GCP credentials"));
    assert!(gcloud_calls(&fake).is_empty());
}

#[test]
fn destroy_checks_surviving_disks_before_delete_and_proceeds_with_a_loud_warning() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeGcp::new(Script::default());
    let workers = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap();
    let name = workers[0].name.clone();

    // Two extra disks with auto-delete off: the #269 v2 pre-delete check
    // fires (they survive the instance and keep billing).
    let diskfake = FakeGcp::new(Script {
        attached_disks: 2,
        ..Default::default()
    });
    provisioner(&diskfake, Some("env"))
        .destroy(&name, &config)
        .unwrap();

    let sequence = gcloud_calls(&diskfake);
    let describe_idx = sequence
        .iter()
        .position(|argv| flat(argv).contains("instances\u{1f}describe"))
        .expect("describe ran");
    let delete_idx = sequence
        .iter()
        .position(|argv| flat(argv).contains("instances\u{1f}delete"))
        .expect("delete ran");
    assert!(
        describe_idx < delete_idx,
        "the disk check happens BEFORE the delete: {:?}",
        sequence
    );
}

#[test]
fn destroy_of_an_unknown_instance_is_a_named_refusal() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeGcp::new(Script {
        describe_fails: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .destroy("shuttle-worker-nosuch-01", &config)
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("shuttle-worker-nosuch-01"), "{text}");
    assert!(deletes(&fake).is_empty(), "a describe miss never deletes");
}

#[test]
fn destroy_keeps_the_pin_when_the_delete_fails() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeGcp::new(Script::default());
    let workers = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap();
    let name = workers[0].name.clone();
    let address = workers[0].address.clone();

    let sloppy = FakeGcp::new(Script {
        delete_fails: true,
        ..Default::default()
    });
    // The shared fake address space: describe succeeds, delete fails;
    // the pin must survive a live instance.
    let err = provisioner(&sloppy, Some("env"))
        .destroy(&name, &config)
        .unwrap_err();
    assert!(format!("{err:#}").contains("InternalError"));
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(
        text.contains(&format!("address = \"{address}\"")),
        "a failed delete leaves the pin: the instance is still live"
    );
}

#[test]
fn destroy_of_an_instance_without_a_managed_pin_reports_not_evicted() {
    // Eviction honesty: a deleted instance whose address no managed
    // entry pins must read as NOT evicted — `Ok(false)` — so the verb
    // never claims an eviction that did not happen.
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeGcp::new(Script::default());
    let evicted = provisioner(&fake, Some("env"))
        .destroy("shuttle-worker-aa-01", &config)
        .unwrap();
    assert!(!evicted, "no managed entry → nothing evicted");
}

// ── The base-image pin ──

#[test]
fn the_base_image_resolves_the_latest_ubuntu_lts_never_a_codename() {
    // ADR-0046: the contract pins "latest LTS" — the ubuntu-os-cloud
    // family carries the release number (2604 at the 2026-09-27
    // decision, #273's reconciliation), never a codename. The shape rule
    // is the same one the Hetzner slug and aws SSM-parameter tests
    // assert.
    assert!(IMAGE_FAMILY.starts_with("ubuntu-"));
    assert!(IMAGE_FAMILY.ends_with("-lts-amd64"), "{IMAGE_FAMILY}");
    let release = IMAGE_FAMILY
        .strip_prefix("ubuntu-")
        .unwrap()
        .strip_suffix("-lts-amd64")
        .unwrap();
    assert_eq!(
        release.len(),
        4,
        "ubuntu-NNNN-lts-amd64 (GCP family shape), never a codename: {IMAGE_FAMILY}"
    );
    assert_eq!(IMAGE_PROJECT, "ubuntu-os-cloud");
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
        machine_identity: "shuttle-worker-abc-01",
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
        machine_identity: "shuttle-worker-abc-01",
        publish_url: PUBLISH_URL,
        publish_token: &token,
        operator_key: OPERATOR_KEY,
        binary_url: BINARY_URL,
        ttl_expiry_epoch: MARKER_EPOCH,
    });
    assert!(user_data.contains("path: /etc/shuttle/publish.env\n    permissions: \"0600\""));
    assert!(user_data.contains(&format!("MACHINE_IDENTITY='shuttle-worker-abc-01'")));
    assert!(user_data.contains(&format!("PUBLISH_URL='{PUBLISH_URL}'")));
    assert!(user_data.contains(&format!("PUBLISH_TOKEN='{token}'")));
    assert!(user_data.contains("path: /etc/shuttle/publish-host-key.sh\n    permissions: \"0700\""));
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
        Some("  - systemctl enable --now shuttle-pickup-host-cert.service"),
        "the pickup unit enable is the final runcmd: {runcmds:?}"
    );
    let publish_at = runcmds
        .iter()
        .position(|l| *l == "  - /etc/shuttle/publish-host-key.sh")
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
    assert!(user_data.contains("path: /etc/shuttle/worker-ttl"));
    assert!(user_data.contains(&format!("content: |\n      {MARKER_EPOCH}\n")));
    // Pinned shuttle binary install + sshd hardening.
    assert!(user_data.contains(BINARY_URL));
    assert!(user_data.contains("PasswordAuthentication no"));
    assert!(user_data.contains("PermitRootLogin prohibit-password"));
    // The provider credential never rides user-data.
    assert!(!user_data.contains("GOOGLE_APPLICATION_CREDENTIALS"));
}

#[test]
fn each_server_gets_its_own_recorded_one_time_token() {
    // The convergence property, read back from the coordinator registry:
    // N instances → N recorded tokens, each bound to its own machine
    // identity, none consumed (issuance is sub-task 3).
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let (pubhome, publish) = pubtmp();
    let fake = FakeGcp::new(Script::default());
    let mut req = request(&config, false);
    req.count = 2;
    provisioner_with(&fake, Some("env"), Some(publish))
        .provision(&req)
        .unwrap();

    let registry = std::fs::read_to_string(
        pubhome
            .path()
            .join(".config/shuttle/ca/pending/tokens.json"),
    )
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
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeGcp::new(Script::default());
    let err = provisioner_with(&fake, Some("env"), None)
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("no publish channel"), "{text}");
    assert!(text.contains("SHUTTLE_PUBLISH_URL"), "{text}");
    assert!(
        gcloud_calls(&fake).is_empty(),
        "no API call before the publish-channel refusal"
    );
}

#[test]
fn no_ca_fingerprint_refuses_before_any_api_call() {
    // Fail-closed interim: the pin IS the CA fingerprint; a request
    // without one is a named refusal before any API call.
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeGcp::new(Script::default());
    let mut req = request(&config, false);
    req.ca_fingerprint = None;
    let err = provisioner(&fake, Some("env")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("no host CA fingerprint"), "{text}");
    assert!(text.contains("shuttle ca keygen"), "{text}");
    assert!(
        gcloud_calls(&fake).is_empty(),
        "no API call before the CA-pin refusal"
    );
}
