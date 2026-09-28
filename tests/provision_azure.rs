//! The Azure provider (#197) driven end to end against a scripted
//! `CommandRunner` fake: the fake plays the `az` CLI (group create, vm
//! create, vm show, vm list, disk list, vm delete, nic/public-ip list —
//! from scripted state), records every argv, and answers nothing else.
//! No network, no real az, no credentials — the ticket's live lanes
//! (env-gated on Azure credentials) are deferred; this fake-API suite
//! plus the dry-run plan is the proof surface. (No ssh-keygen arm: the
//! amendment removed the coordinator-side mint — a provision that tried
//! to ssh-keygen would fail loudly here.)

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use shuttle::command::{CommandRunner, RunnerOutput};
use shuttle::provision::azure::{
    AzureProvisioner, ADMIN_USERNAME, IMAGE_URN, WORKER_SPOT_TAG, WORKER_TAG, WORKER_TTL_TAG,
};
use shuttle::provision::publish::PublishChannel;
use shuttle::provision::{
    parse_ttl, render_user_data, ProvisionRequest, Provisioner, UserDataParams, BLOCK_BEGIN,
    BLOCK_END, PLAN_MACHINE_IDENTITY, PLAN_PUBLISH_TOKEN, PLAN_PUBLISH_URL,
};

const OPERATOR_KEY: &str = "ssh-ed25519 AAAAoperatorkey operator@example";
const BINARY_URL: &str = "https://example.invalid/shuttle-amd64";
const REGION: &str = "westeurope";
const SIZE: &str = "Standard_D4s_v5";
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
    group_create_fails: bool,
    create_fails: bool,
    /// The created VM comes back with NO public IP (a subnet that
    /// grants none).
    no_public_ip: bool,
    /// `az vm list` comes back empty (a destroy of a VM that does not
    /// exist), even when VMs were "created" in this fake.
    list_empty: bool,
    describe_fails: bool,
    delete_fails: bool,
    /// Fail deletes once this many have already succeeded — scripts a
    /// MIXED teardown: some VMs deleted, some stuck billing.
    delete_fails_after: usize,
    /// Extra attached data disks with `deleteOption` Detach (they
    /// survive a VM delete and keep billing — the #269 v2 pre-delete
    /// check's input). The OS disk is always present with Delete.
    attached_disks: usize,
}

/// Plays the `az` CLI from scripted state and records every argv.
/// Cheap to clone; all clones share one call log.
#[derive(Clone)]
struct FakeAz {
    calls: Arc<Mutex<Vec<Vec<String>>>>,
    /// (path, unix mode, content) of every `--custom-data @` blob the
    /// fake served, captured at call time — the real blob is removed
    /// once its create call served it.
    user_data_files: Arc<Mutex<Vec<(PathBuf, u32, String)>>>,
    /// VM names the fake has "created" (vm create ok) and not yet
    /// "deleted" — the vm list / disk list sources of truth.
    created: Arc<Mutex<Vec<String>>>,
    /// VM names "deleted" (vm delete ok) — their NIC/public IP turn
    /// into the orphan residuals the post-delete check finds.
    deleted: Arc<Mutex<Vec<String>>>,
    /// Successful delete count, shared across clones (drives
    /// `delete_fails_after`).
    deletes_done: Arc<Mutex<usize>>,
    script: Script,
}

impl FakeAz {
    fn new(script: Script) -> Self {
        FakeAz {
            calls: Arc::new(Mutex::new(Vec::new())),
            user_data_files: Arc::new(Mutex::new(Vec::new())),
            created: Arc::new(Mutex::new(Vec::new())),
            deleted: Arc::new(Mutex::new(Vec::new())),
            deletes_done: Arc::new(Mutex::new(0)),
            script,
        }
    }
}

impl CommandRunner for FakeAz {
    fn run(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        self.calls.lock().unwrap().push(argv.to_vec());
        match argv[0].as_str() {
            "az" => self.az(argv),
            other => Ok(RunnerOutput {
                code: 1,
                stdout: vec![],
                stderr: format!("unexpected program in test: {other}"),
            }),
        }
    }
}

impl FakeAz {
    fn az(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        let rest: Vec<&str> = argv[1..].iter().map(|s| s.as_str()).collect();
        match (rest.first().copied(), rest.get(1).copied()) {
            (Some("group"), Some("create")) => self.group_create(),
            (Some("vm"), Some("create")) => self.vm_create(argv),
            (Some("vm"), Some("show")) => self.vm_show(&rest),
            (Some("vm"), Some("list")) => self.vm_list(),
            (Some("vm"), Some("delete")) => self.vm_delete(&rest),
            (Some("disk"), Some("list")) => self.disk_list(),
            (Some("network"), Some("nic")) => self.orphan_list("VMNic"),
            (Some("network"), Some("public-ip")) => self.orphan_list("PublicIP"),
            other => Ok(RunnerOutput {
                code: 1,
                stdout: vec![],
                stderr: format!("unexpected az call in test: {other:?}"),
            }),
        }
    }

    fn group_create(&self) -> io::Result<RunnerOutput> {
        if self.script.group_create_fails {
            return Ok(fail_out(
                "(LocationNotAvailableForResourceGroup) The provided location is not available \
                 for resource group (fake)",
            ));
        }
        Ok(ok_out(
            &serde_json::json!({
                "name": "shuttle-workers-x",
                "properties": { "provisioningState": "Succeeded" }
            })
            .to_string(),
        ))
    }

    fn vm_create(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        if self.script.create_fails {
            return Ok(fail_out(
                "(DeploymentFailed) vm create failed: SKU not available (fake)",
            ));
        }
        if let Some(i) = argv.iter().position(|a| a == "--custom-data") {
            // The value is the `@<path>` hand-off; capture the blob and
            // its mode at call time.
            let raw = &argv[i + 1];
            let path = PathBuf::from(raw.strip_prefix('@').unwrap_or(raw));
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
        let name = flag_value(argv, "--name").expect("vm create fake requires --name");
        self.created.lock().unwrap().push(name);
        Ok(ok_out(
            &serde_json::json!({ "powerState": "VM running" }).to_string(),
        ))
    }

    fn vm_show(&self, rest: &[&str]) -> io::Result<RunnerOutput> {
        if self.script.describe_fails {
            return Ok(fail_out(
                "(ResourceNotFound) The Resource 'Microsoft.Compute/virtualMachines/x' under \
                 resource group 'y' was not found (fake)",
            ));
        }
        let name = flag_value(
            &rest.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "--name",
        )
        .expect("vm show fake requires --name");
        if self.script.no_public_ip {
            return Ok(ok_out("null"));
        }
        Ok(ok_out(&serde_json::json!(public_ip_of(&name)).to_string()))
    }

    fn vm_list(&self) -> io::Result<RunnerOutput> {
        if self.script.list_empty {
            return Ok(ok_out("[]"));
        }
        let names = self.created.lock().unwrap().clone();
        let vms: Vec<serde_json::Value> = names
            .iter()
            .map(|n| {
                serde_json::json!({
                    "name": n,
                    "rg": format!("shuttle-workers-{REGION}"),
                })
            })
            .collect();
        Ok(ok_out(&serde_json::Value::Array(vms).to_string()))
    }

    fn disk_list(&self) -> io::Result<RunnerOutput> {
        // One OS disk (Delete) plus the scripted Detach extras per
        // created VM; the provider filters to the destroyed VM
        // client-side.
        let names = self.created.lock().unwrap().clone();
        let mut disks: Vec<serde_json::Value> = Vec::new();
        for n in names {
            disks.push(serde_json::json!({
                "name": format!("{n}-OsDisk_1"),
                "vm": format!("/subscriptions/fake/virtualMachines/{n}"),
                "del": "Delete",
            }));
            for i in 1..=self.script.attached_disks {
                disks.push(serde_json::json!({
                    "name": format!("{n}-disk-{i}"),
                    "vm": format!("/subscriptions/fake/virtualMachines/{n}"),
                    "del": "Detach",
                }));
            }
        }
        Ok(ok_out(&serde_json::Value::Array(disks).to_string()))
    }

    fn vm_delete(&self, rest: &[&str]) -> io::Result<RunnerOutput> {
        let mut done = self.deletes_done.lock().unwrap();
        if self.script.delete_fails
            || (self.script.delete_fails_after > 0 && *done >= self.script.delete_fails_after)
        {
            return Ok(fail_out("(InternalOperationError) vm delete failed (fake)"));
        }
        *done += 1;
        drop(done);
        let name = flag_value(
            &rest.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "--name",
        )
        .expect("vm delete fake requires --name");
        self.created.lock().unwrap().retain(|n| *n != name);
        self.deleted.lock().unwrap().push(name);
        Ok(ok_out(""))
    }

    /// After a vm delete the fake leaves the VM's NIC/public IP behind,
    /// unattached — the residuals the provider's post-delete check
    /// finds.
    fn orphan_list(&self, suffix: &str) -> io::Result<RunnerOutput> {
        let deleted = self.deleted.lock().unwrap().clone();
        let names: Vec<serde_json::Value> = deleted
            .iter()
            .map(|n| serde_json::json!(format!("{n}-{suffix}")))
            .collect();
        Ok(ok_out(&serde_json::Value::Array(names).to_string()))
    }
}

/// The argv element following `flag`, when present.
fn flag_value(argv: &[String], flag: &str) -> Option<String> {
    argv.iter()
        .position(|a| a == flag)
        .and_then(|i| argv.get(i + 1).cloned())
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

/// Deterministic per-name public IP: the trailing `-NN` of the fake VM
/// name picks a distinct 203.0.113.x address (TEST-NET-3), so vm show
/// agrees with itself across the provision/destroy paths.
fn public_ip_of(name: &str) -> String {
    let nn: u32 = name
        .rsplit('-')
        .next()
        .and_then(|t| t.parse().ok())
        .unwrap_or(1);
    format!("203.0.113.{}", 10 + nn)
}

// ── Fixtures ──

fn request(config: &Path, dry_run: bool) -> ProvisionRequest {
    ProvisionRequest {
        server_type: SIZE.into(),
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
        home: std::env::temp_dir().join(format!("shuttle-azure-publish-test-{nanos}")),
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

fn provisioner(fake: &FakeAz, credentials: Option<&str>) -> AzureProvisioner<FakeAz> {
    provisioner_with(fake, credentials, Some(throwaway_publish_channel()))
}

fn provisioner_with(
    fake: &FakeAz,
    credentials: Option<&str>,
    publish: Option<PublishChannel>,
) -> AzureProvisioner<FakeAz> {
    AzureProvisioner::new(
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

fn calls(fake: &FakeAz) -> Vec<Vec<String>> {
    fake.calls.lock().unwrap().clone()
}

fn az_calls(fake: &FakeAz) -> Vec<Vec<String>> {
    calls(fake)
        .into_iter()
        .filter(|argv| argv[0] == "az")
        .collect()
}

fn flat(argv: &[String]) -> String {
    argv.join("\u{1f}")
}

// ── Local refusals (all before ANY API call) ──

#[test]
fn no_credentials_refusal_names_az_login_before_any_api_call() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAz::new(Script::default());
    let err = provisioner(&fake, None)
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("no Azure credentials"),
        "refusal names the missing credentials: {text}"
    );
    assert!(
        text.contains("az login"),
        "the refusal names the login remedy (the live lane-2 rule): {text}"
    );
    assert!(
        az_calls(&fake).is_empty(),
        "no API call before the credentials refusal"
    );
}

#[test]
fn spot_requires_a_price_cap() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAz::new(Script::default());
    let mut req = request(&config, false);
    req.spot = true;
    let err = provisioner(&fake, Some("env")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("--spot requires --max-price"), "{text}");
    assert!(
        az_calls(&fake).is_empty(),
        "an uncapped spot bid is refused before any API call"
    );
}

#[test]
fn a_price_cap_requires_spot() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAz::new(Script::default());
    let mut req = request(&config, false);
    req.max_price = Some("0.05".into());
    let err = provisioner(&fake, Some("env")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("--max-price requires --spot"),
        "on-demand has no bid to cap: {text}"
    );
    assert!(az_calls(&fake).is_empty(), "refused before any API call");
}

#[test]
fn the_price_cap_must_be_positive_finite_decimal() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    for cap in ["0", "-1", "abc", "NaN", "inf"] {
        let fake = FakeAz::new(Script::default());
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
            az_calls(&fake).is_empty(),
            "a bad cap never reaches the API (cap: {cap})"
        );
    }
}

// ── Dry run ──

#[test]
fn dry_run_makes_no_api_call_and_needs_no_credentials() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAz::new(Script::default());
    let mut req = request(&config, true);
    req.spot = true;
    req.max_price = Some("0.043".into());
    let workers = provisioner(&fake, None).provision(&req).unwrap();
    assert!(workers.is_empty(), "a dry run provisions nothing");
    assert!(
        az_calls(&fake).is_empty(),
        "dry run must not touch the API: {:?}",
        az_calls(&fake)
    );
}

// ── Provision ──

#[test]
fn provision_creates_group_vms_describes_and_pins() {
    let (dir, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAz::new(Script::default());
    let mut req = request(&config, false);
    req.count = 2;
    let workers = provisioner(&fake, Some("env")).provision(&req).unwrap();
    assert_eq!(workers.len(), 2);

    // The worker handle is the VM name (the destroy verb's argument);
    // the address comes from the show document; the pin is the CA
    // fingerprint (the amendment's pin — one root, not per-worker keys).
    for w in &workers {
        assert!(w.name.starts_with("shuttle-worker-"), "{}", w.name);
        assert!(
            w.address.starts_with("ssh://root@203.0.113."),
            "{}",
            w.address
        );
        assert_eq!(w.host_key, CA_FPR, "the pin IS the CA fingerprint");
    }

    // The create shape: the per-region group exists before the VM (a
    // VM's region is its group's region), the image is the pinned URN,
    // the size is `--type`, user-data rides the authenticated channel
    // as a file hand-off, the contract tags ride at create — with NO
    // priority block on the on-demand default.
    let seq = az_calls(&fake);
    let group_idx = seq
        .iter()
        .position(|argv| flat(argv).contains("group\u{1f}create"))
        .expect("the group create runs");
    let creates: Vec<usize> = seq
        .iter()
        .enumerate()
        .filter(|(_, argv)| flat(argv).contains("vm\u{1f}create"))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(creates.len(), 2, "one vm create per count");
    assert!(
        group_idx < creates[0],
        "the group exists before the first VM: {:?}",
        seq
    );
    assert!(
        flat(&seq[group_idx]).contains(&format!("--location\u{1f}{REGION}")),
        "--location takes effect via the group: {}",
        flat(&seq[group_idx])
    );

    let f = flat(&seq[creates[0]]);
    assert!(
        f.contains(&format!("--resource-group\u{1f}shuttle-workers-{REGION}")),
        "every create-path call carries the group: {f}"
    );
    assert!(f.contains(&format!("--size\u{1f}{SIZE}")), "{f}");
    assert!(f.contains(&format!("--image\u{1f}{IMAGE_URN}")), "{f}");
    assert!(
        f.contains(&format!("--admin-username\u{1f}{ADMIN_USERNAME}")),
        "{f}"
    );
    assert!(
        f.contains(&format!("--ssh-key-value\u{1f}{OPERATOR_KEY}")),
        "the operator key authorizes the admin user as break-glass: {f}"
    );
    assert!(
        f.contains("--custom-data\u{1f}@"),
        "user-data rides the authenticated channel as a file hand-off: {f}"
    );
    let tag_idx = seq[creates[0]].iter().position(|a| a == "--tags").unwrap();
    let tags = &seq[creates[0]][tag_idx + 1];
    assert!(tags.contains(&format!("{WORKER_TAG}=true")), "{tags}");
    assert!(
        !tags.contains(WORKER_SPOT_TAG),
        "on-demand carries no spot tag: {tags}"
    );
    let ttl_frag_start = tags
        .find(&format!("{WORKER_TTL_TAG}="))
        .expect("ttl tag present");
    let epoch: u64 = tags[ttl_frag_start + WORKER_TTL_TAG.len() + 1..]
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(epoch > 1_600_000_000, "the tag value is the TTL epoch");
    assert!(
        !f.contains("--priority"),
        "on-demand default never bids: {f}"
    );
    assert!(
        !f.contains("AZURE_CLIENT"),
        "credentials never enter argv: {f}"
    );

    // The staged blobs (captured at create time — removed once served):
    // NO private half anywhere (the amendment's absence property, over
    // the real sent bytes), the publish block rides each blob, and each
    // VM carries its own machine identity + one-time token.
    let staged = fake.user_data_files.lock().unwrap();
    assert_eq!(staged.len(), 2, "one staged blob per vm create");
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
    for (_, _, content) in staged.iter() {
        assert!(
            !content.contains("BEGIN OPENSSH PRIVATE KEY"),
            "no private half rides user-data"
        );
        assert!(content.contains("/etc/shuttle/publish-host-key.sh"));
        assert!(content.contains(OPERATOR_KEY));
        assert!(
            content.contains("MACHINE_IDENTITY='shuttle-worker-"),
            "the machine identity is the VM name"
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
    assert!(
        !az_calls(&fake)
            .iter()
            .any(|argv| flat(argv).contains("vm\u{1f}delete")),
        "happy provision never deletes"
    );
    let _ = dir;
}

#[test]
fn spot_shape_rides_priority_delete_eviction_and_the_cap() {
    // #197 spot shape: priority Spot, eviction-policy Delete (an
    // eviction is T5 worker loss — never a Deallocate that pretends the
    // machine survives and keeps billing its disks), the cap riding
    // --max-price verbatim, and the spot tag naming the eviction class.
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAz::new(Script::default());
    let mut req = request(&config, false);
    req.spot = true;
    req.max_price = Some("0.043".into());
    provisioner(&fake, Some("env")).provision(&req).unwrap();

    let create = az_calls(&fake)
        .into_iter()
        .find(|argv| flat(argv).contains("vm\u{1f}create"))
        .unwrap();
    let f = flat(&create);
    assert!(
        f.contains("--priority\u{1f}Spot"),
        "spot rides the priority flag: {f}"
    );
    assert!(
        f.contains("--eviction-policy\u{1f}Delete"),
        "the eviction policy is Delete: {f}"
    );
    assert!(
        !f.contains("Deallocate"),
        "Deallocate would pretend the machine survives: {f}"
    );
    assert!(
        f.contains("--max-price\u{1f}0.043"),
        "the cap rides verbatim: {f}"
    );
    let tag_idx = create
        .iter()
        .position(|a| a == "--tags")
        .expect("tags ride at create");
    assert!(
        create[tag_idx + 1].contains(&format!("{WORKER_SPOT_TAG}=true")),
        "the spot tag names the eviction class: {}",
        create[tag_idx + 1]
    );
}

#[test]
fn create_failure_leaves_no_vm_and_no_config_change() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeAz::new(Script {
        create_fails: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("SKU not available"),
        "provider error named: {text}"
    );
    assert!(
        !az_calls(&fake)
            .iter()
            .any(|argv| flat(argv).contains("vm\u{1f}delete")),
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
    let fake = FakeAz::new(Script {
        describe_fails: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("deleted 1 created VM(s)"), "{text}");
    assert_eq!(
        az_calls(&fake)
            .iter()
            .filter(|argv| flat(argv).contains("vm\u{1f}delete"))
            .count(),
        1,
        "the created VM is deleted"
    );
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "no pin without an address"
    );
}

#[test]
fn no_public_ip_refuses_and_tears_down() {
    // A subnet that grants no public IP would produce an unreachable
    // worker: fail-closed with the remedy named, never a pin to an
    // address that cannot be reached.
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeAz::new(Script {
        no_public_ip: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("no public IP"), "{text}");
    assert!(text.contains("deleted 1 created VM(s)"), "{text}");
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "config untouched"
    );
}

#[test]
fn pin_failure_after_create_deletes() {
    // A config that cannot be pinned (missing file) must not leave a
    // live VM: teardown-on-failure is the ADR-0045 atomicity.
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("absent").join("shuttle.lua");
    let fake = FakeAz::new(Script::default());
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("deleted 1 created VM(s)"), "{text}");
    assert!(text.contains("config untouched"), "{text}");
}

// ── Teardown truthfulness ──

#[test]
fn teardown_delete_failure_names_the_residual_vm() {
    // A teardown delete that fails must NOT read as torn down: the
    // error names the still-billing residual and the reclaim path.
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeAz::new(Script {
        describe_fails: true,
        delete_fails: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("deleted 0 created VM(s)"), "{text}");
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
    // Two VMs created, the SECOND pin refuses (an operator-owned entry
    // already holds its address — shuttle never rewrites operator
    // text), and the SECOND teardown delete fails: the first is
    // honestly counted deleted AND the stuck one is named — neither
    // half can vanish into a blanket success line.
    let (dir, config) = workspace("shuttle.lua");
    // Fake names …-01 / …-02 show to 203.0.113.11 / .12: the
    // operator-owned entry at .12 makes pin #2 refuse after pin #1
    // pinned .11.
    std::fs::write(
        &config,
        "workers = { { address = \"ssh://root@203.0.113.12\", host_key = \"ssh-ed25519 AAAAoperator operator\" } }\nreturn {}\n",
    )
    .unwrap();
    let fake = FakeAz::new(Script {
        delete_fails_after: 1,
        ..Default::default()
    });
    let mut req = request(&config, false);
    req.count = 2;
    let err = provisioner(&fake, Some("env")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("deleted 1 created VM(s)"), "{text}");
    assert!(text.contains("FAILED to delete shuttle-worker-"), "{text}");
    assert!(text.contains("still running and billing"), "{text}");
    // NOTE: the pin that DID succeed stays in the config (the torn-down
    // VM residue) — the same pre-existing partial-pin residue the
    // #281 review names for hetzner (m1), not this ticket's scope.
    let _ = dir;
}

// ── User-data staging hygiene ──

#[test]
fn user_data_is_staged_inside_the_provision_tempdir_at_0600() {
    // The blob carries the one-time publish bearer: it must live in
    // provision tempdir (so it dies with the run) at mode 0600.
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAz::new(Script::default());
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
fn destroy_lists_shows_deletes_in_order_and_evicts_the_managed_entry() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAz::new(Script::default());
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
    let seq = az_calls(&fake);
    // The destroy tail starts at the vm list (the create path's own
    // vm show precedes it); the order rule is about the destroy path.
    let list_idx = seq
        .iter()
        .position(|argv| flat(argv).contains("vm\u{1f}list"))
        .expect("vm list ran (destroy resolves the group)");
    let tail = &seq[list_idx..];
    let show_idx = tail
        .iter()
        .position(|argv| flat(argv).contains("vm\u{1f}show"))
        .expect("vm show ran")
        + list_idx;
    let disk_idx = tail
        .iter()
        .position(|argv| flat(argv).contains("disk\u{1f}list"))
        .expect("the disk check ran")
        + list_idx;
    let delete_idx = tail
        .iter()
        .position(|argv| flat(argv).contains("vm\u{1f}delete"))
        .expect("vm delete ran")
        + list_idx;
    assert!(
        list_idx < show_idx && show_idx < disk_idx && disk_idx < delete_idx,
        "the group resolves, the address is read, disks warn, THEN the delete: {:?}",
        seq
    );
    assert!(
        flat(&seq[delete_idx]).contains(&format!("--name\u{1f}{name}")),
        "{}",
        flat(&seq[delete_idx])
    );
}

#[test]
fn destroy_requires_credentials_before_any_api_call() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAz::new(Script::default());
    let err = provisioner(&fake, None)
        .destroy("shuttle-worker-x-01", &config)
        .unwrap_err();
    assert!(format!("{err:#}").contains("no Azure credentials"));
    assert!(az_calls(&fake).is_empty());
}

#[test]
fn destroy_of_an_unknown_vm_is_a_named_refusal() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAz::new(Script {
        list_empty: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .destroy("shuttle-worker-nosuch-01", &config)
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("shuttle-worker-nosuch-01"), "{text}");
    assert!(
        !az_calls(&fake)
            .iter()
            .any(|argv| flat(argv).contains("vm\u{1f}delete")),
        "a list miss never deletes"
    );
}

#[test]
fn destroy_keeps_the_pin_when_the_delete_fails() {
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAz::new(Script::default());
    let workers = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap();
    let name = workers[0].name.clone();
    let address = workers[0].address.clone();

    let sloppy = FakeAz::new(Script {
        delete_fails: true,
        ..Default::default()
    });
    // Seed the fake state with the live VM (a fresh fake knows
    // nothing): vm list/show succeed, delete fails; the pin must
    // survive a live VM.
    sloppy.created.lock().unwrap().push(name.clone());
    let err = provisioner(&sloppy, Some("env"))
        .destroy(&name, &config)
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("InternalOperationError"),
        "{err:#}"
    );
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(
        text.contains(&format!("address = \"{address}\"")),
        "a failed delete leaves the pin: the VM is still live"
    );
}

#[test]
fn destroy_of_a_vm_without_a_managed_pin_reports_not_evicted() {
    // Eviction honesty: a deleted VM whose address no managed entry
    // pins must read as NOT evicted — `Ok(false)` — so the verb never
    // claims an eviction that did not happen.
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAz::new(Script::default());
    let workers = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap();
    let (_other, fresh) = workspace("other.lua");
    std::fs::write(&fresh, operator_config()).unwrap();
    let evicted = provisioner(&fake, Some("env"))
        .destroy(&workers[0].name, &fresh)
        .unwrap();
    assert!(!evicted, "no managed entry → nothing evicted");
}

#[test]
fn destroy_warns_disks_that_survive_and_orphans_that_still_bill() {
    // Teardown truthfulness: Detach disks outlive the VM (warned BEFORE
    // the delete); the deleted VM's NIC and public IP are left behind
    // (public IPs bill) — named after it, never silently removed.
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let name = "shuttle-worker-abc-01".to_string();

    let demolisher = FakeAz::new(Script {
        attached_disks: 2,
        ..Default::default()
    });
    // Seed the fake state with one existing VM (a fresh fake knows
    // nothing), then destroy it.
    demolisher.created.lock().unwrap().push(name.clone());
    provisioner(&demolisher, Some("env"))
        .destroy(&name, &config)
        .unwrap();

    let seq = az_calls(&demolisher);
    let disk_idx = seq
        .iter()
        .position(|argv| flat(argv).contains("disk\u{1f}list"))
        .expect("the disk check ran");
    let delete_idx = seq
        .iter()
        .position(|argv| flat(argv).contains("vm\u{1f}delete"))
        .expect("delete ran");
    let nic_idx = seq
        .iter()
        .position(|argv| flat(argv).contains("nic\u{1f}list"))
        .expect("the nic check ran");
    let pip_idx = seq
        .iter()
        .position(|argv| flat(argv).contains("public-ip\u{1f}list"))
        .expect("the public-ip check ran");
    assert!(
        disk_idx < delete_idx && delete_idx < nic_idx && nic_idx < pip_idx,
        "disks warn before the delete; orphans are checked after: {:?}",
        seq
    );
}

// ── The base-image pin ──

#[test]
fn the_base_image_pins_the_latest_ubuntu_lts_never_a_codename() {
    // ADR-0046: the contract pins "latest LTS" — the URN carries the
    // release number (26.04 at the 2026-09-27 decision, #273's
    // reconciliation), never a codename. The shape rule is the same one
    // the Hetzner slug and GCP family tests assert.
    let sku = IMAGE_URN
        .split(':')
        .nth(2)
        .expect("urn is publisher:offer:sku:version");
    assert!(
        sku.contains("2604"),
        "the 26.04 release number pins the LTS: {IMAGE_URN}"
    );
    let lower = IMAGE_URN.to_lowercase();
    assert!(
        !lower.contains("noble") && !lower.contains("jammy") && !lower.contains("bionic"),
        "never a codename: {IMAGE_URN}"
    );
    assert!(
        IMAGE_URN.ends_with(":latest"),
        "the version leg rolls security updates: {IMAGE_URN}"
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
    // per-VM blob differs only there).
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
    assert!(!user_data.contains("AZURE_CLIENT_SECRET"));
}

#[test]
fn each_server_gets_its_own_recorded_one_time_token() {
    // The convergence property, read back from the coordinator registry:
    // N VMs → N recorded tokens, each bound to its own machine identity,
    // none consumed (issuance is sub-task 3).
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let (pubhome, publish) = pubtmp();
    let fake = FakeAz::new(Script::default());
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
    assert_eq!(tokens.len(), 2, "one recorded issuance per VM");
    let mut identities: Vec<&str> = tokens
        .iter()
        .map(|t| t["machine_identity"].as_str().unwrap())
        .collect();
    identities.sort();
    assert!(
        identities.windows(2).all(|w| w[0] != w[1]),
        "one identity per VM: {identities:?}"
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
    let fake = FakeAz::new(Script::default());
    let err = provisioner_with(&fake, Some("env"), None)
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("no publish channel"), "{text}");
    assert!(text.contains("SHUTTLE_PUBLISH_URL"), "{text}");
    assert!(
        az_calls(&fake).is_empty(),
        "no API call before the publish-channel refusal"
    );
}

#[test]
fn no_ca_fingerprint_refuses_before_any_api_call() {
    // Fail-closed interim: the pin IS the CA fingerprint; a request
    // without one is a named refusal before any API call.
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeAz::new(Script::default());
    let mut req = request(&config, false);
    req.ca_fingerprint = None;
    let err = provisioner(&fake, Some("env")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("no host CA fingerprint"), "{text}");
    assert!(text.contains("shuttle ca keygen"), "{text}");
    assert!(
        az_calls(&fake).is_empty(),
        "no API call before the CA-pin refusal"
    );
}
