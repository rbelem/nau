//! The Scaleway provider (#198) driven end to end against a scripted
//! `CommandRunner` fake: the fake plays the `scw` CLI (server create,
//! get, list, delete — from scripted state), records every argv, and
//! answers nothing else. No network, no real scw, no credentials — the
//! ticket's live lanes (env-gated on Scaleway credentials) are deferred;
//! this fake-API suite plus the dry-run plan is the proof surface. (No
//! ssh-keygen arm: the amendment removed the coordinator-side mint — a
//! provision that tried to ssh-keygen would fail loudly here.)

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use nau::command::{CommandRunner, RunnerOutput};
use nau::provision::publish::PublishChannel;
use nau::provision::scaleway::{ScalewayProvisioner, IMAGE_LABEL, WORKER_TAG, WORKER_TTL_TAG};
use nau::provision::{
    parse_ttl, render_user_data, ProvisionRequest, Provisioner, UserDataParams, BLOCK_BEGIN,
    BLOCK_END, PLAN_MACHINE_IDENTITY, PLAN_PUBLISH_TOKEN, PLAN_PUBLISH_URL,
};

const OPERATOR_KEY: &str = "ssh-ed25519 AAAAoperatorkey operator@example";
/// The client identity pinned into provisioned entries (#298) — a
/// throwaway fixture path, no crypto.
const OPERATOR_IDENTITY: &str = "/nau-test-fixtures/operator_ed25519";
const BINARY_URL: &str = "https://example.invalid/nau-amd64";
const ZONE: &str = "fr-par-1";
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
    create_fails: bool,
    /// The created servers come back with NO public IP (a zone/IP quota
    /// that denied the dynamic flexible IP).
    no_public_ip: bool,
    get_fails: bool,
    delete_fails: bool,
    /// Fail deletes once this many have already succeeded — scripts a
    /// MIXED teardown: some servers deleted, some stuck billing.
    delete_fails_after: usize,
    /// Block-storage volumes the fake reports on any server (the
    /// pre-delete residual check's input).
    sbs_volumes: usize,
    /// `scw instance server list` comes back empty (a destroy of a server
    /// that does not exist in the zone).
    empty_list: bool,
}

/// Plays the `scw` CLI from scripted state and records every argv.
/// Cheap to clone; all clones share one call log and one world state.
#[derive(Clone)]
struct FakeScw {
    calls: Arc<Mutex<Vec<Vec<String>>>>,
    /// (path, unix mode, content) of every `user-data.0.content=file://`
    /// blob the fake served, captured at call time — the real blob is
    /// removed once its create call served it.
    user_data_files: Arc<Mutex<Vec<(PathBuf, u32, String)>>>,
    /// Servers the fake has "created" (create ok) and not yet "deleted":
    /// (id, name) — the server list source of truth.
    servers: Arc<Mutex<Vec<(String, String)>>>,
    /// Successful delete count, shared across clones (drives
    /// `delete_fails_after`).
    deletes_done: Arc<Mutex<usize>>,
    script: Script,
}

impl FakeScw {
    fn new(script: Script) -> Self {
        FakeScw {
            calls: Arc::new(Mutex::new(Vec::new())),
            user_data_files: Arc::new(Mutex::new(Vec::new())),
            servers: Arc::new(Mutex::new(Vec::new())),
            deletes_done: Arc::new(Mutex::new(0)),
            script,
        }
    }
}

impl CommandRunner for FakeScw {
    fn run(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        self.calls.lock().unwrap().push(argv.to_vec());
        match argv[0].as_str() {
            "scw" => self.scw(argv),
            other => Ok(RunnerOutput {
                code: 1,
                stdout: vec![],
                stderr: format!("unexpected program in test: {other}"),
            }),
        }
    }
}

impl FakeScw {
    fn scw(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        // The destroy path resolves the zone from the ambient scw
        // configuration, so the leading `-z <zone>` is OPTIONAL here.
        let rest: &[String] = if argv.get(1).map(|s| s.as_str()) == Some("-z") {
            &argv[3..]
        } else {
            &argv[1..]
        };
        let rest: Vec<&str> = rest.iter().map(|s| s.as_str()).collect();
        match rest.as_slice() {
            ["instance", "server", "create", ..] => self.server_create(argv),
            ["instance", "server", "get", id, "-o", "json"] => self.server_get(id),
            ["instance", "server", "list", "-o", "json"] => self.server_list(),
            ["instance", "server", "delete", sid] => self.server_delete(sid),
            other => Ok(RunnerOutput {
                code: 1,
                stdout: vec![],
                stderr: format!("unexpected scw call in test: {other:?}"),
            }),
        }
    }

    fn server_create(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        if self.script.create_fails {
            return Ok(fail_out(
                "scw: instance server create: quota exceeded for GP1 machines in fr-par-1 (fake)",
            ));
        }
        if let Some(i) = argv.iter().position(|a| a == "user-data.0.key=cloud-init") {
            // The next element is the `user-data.0.content=file://` hand-
            // off; capture the blob and its mode at call time.
            let raw = argv
                .get(i + 1)
                .expect("create fake requires user-data.0.content");
            let path = PathBuf::from(
                raw.strip_prefix("user-data.0.content=file://")
                    .unwrap_or(raw),
            );
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
        let name = argv
            .iter()
            .find_map(|a| a.strip_prefix("name="))
            .expect("create fake requires name=");
        let id = id_for(name);
        self.servers
            .lock()
            .unwrap()
            .push((id.clone(), name.to_string()));
        Ok(ok_out(
            &serde_json::json!({ "id": id, "name": name, "state": "starting" }).to_string(),
        ))
    }

    fn server_get(&self, id: &str) -> io::Result<RunnerOutput> {
        if self.script.get_fails {
            return Ok(fail_out("scw: instance server get: not found (fake)"));
        }
        let known = self
            .servers
            .lock()
            .unwrap()
            .iter()
            .any(|(sid, _)| sid == id);
        if !known {
            return Ok(fail_out("scw: instance server get: not found (fake)"));
        }
        let name = self
            .servers
            .lock()
            .unwrap()
            .iter()
            .find(|(sid, _)| sid == id)
            .map(|(_, n)| n.clone())
            .unwrap_or_default();
        let mut volumes = serde_json::Map::new();
        volumes.insert(
            "0".to_string(),
            serde_json::json!({
                "id": format!("{id}-root"),
                "volume_type": "l_ssd"
            }),
        );
        for i in 1..=self.script.sbs_volumes {
            volumes.insert(
                i.to_string(),
                serde_json::json!({
                    "id": format!("{id}-sbs{i}"),
                    "volume_type": "sbs_volume"
                }),
            );
        }
        let mut doc = serde_json::json!({
            "id": id,
            "name": name,
            "state": "running",
            "volumes": volumes
        });
        if !self.script.no_public_ip {
            doc["public_ip"] = serde_json::json!({
                "id": format!("{id}-ip"),
                "address": ip_for(id)
            });
        }
        Ok(ok_out(&doc.to_string()))
    }

    fn server_list(&self) -> io::Result<RunnerOutput> {
        if self.script.empty_list {
            return Ok(ok_out(
                &serde_json::json!({ "servers": [], "total_count": 0 }).to_string(),
            ));
        }
        let servers: Vec<serde_json::Value> = self
            .servers
            .lock()
            .unwrap()
            .iter()
            .map(|(id, name)| serde_json::json!({ "id": id, "name": name }))
            .collect();
        Ok(ok_out(
            &serde_json::json!({
                "servers": servers,
                "total_count": servers.len()
            })
            .to_string(),
        ))
    }

    fn server_delete(&self, sid: &str) -> io::Result<RunnerOutput> {
        let mut done = self.deletes_done.lock().unwrap();
        if self.script.delete_fails
            || (self.script.delete_fails_after > 0 && *done >= self.script.delete_fails_after)
        {
            return Ok(fail_out(
                "scw: instance server delete: the server is still running, retry later (fake)",
            ));
        }
        *done += 1;
        let id = sid.strip_prefix("server-id=").unwrap_or(sid);
        self.servers.lock().unwrap().retain(|(sid, _)| sid != id);
        Ok(ok_out(""))
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

/// Deterministic fake identities: the trailing two digits of the
/// `nau-worker-…-NN` name pick the uuid tail and a distinct
/// 203.0.113.x address (TEST-NET-3).
fn id_for(name: &str) -> String {
    let n: u32 = name
        .rsplit('-')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    format!("aa0b0804-0000-7000-8000-{n:012}")
}

fn ip_for(id: &str) -> String {
    let nibble = id.chars().last().and_then(|c| c.to_digit(16)).unwrap_or(1);
    format!("203.0.113.{}", 10 + nibble)
}

// ── Fixtures ──

fn request(config: &Path, dry_run: bool) -> ProvisionRequest {
    ProvisionRequest {
        server_type: "GP1-XS".into(),
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
        home: std::env::temp_dir().join(format!("nau-scw-publish-test-{nanos}")),
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

fn provisioner(fake: &FakeScw, credentials: Option<&str>) -> ScalewayProvisioner<FakeScw> {
    provisioner_with(fake, credentials, Some(throwaway_publish_channel()))
}

fn provisioner_with(
    fake: &FakeScw,
    credentials: Option<&str>,
    publish: Option<PublishChannel>,
) -> ScalewayProvisioner<FakeScw> {
    ScalewayProvisioner::new(
        fake.clone(),
        credentials.map(|c| c.to_string()),
        BINARY_URL.into(),
        OPERATOR_KEY.into(),
        OPERATOR_IDENTITY.into(),
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

fn calls(fake: &FakeScw) -> Vec<Vec<String>> {
    fake.calls.lock().unwrap().clone()
}

fn scw_calls(fake: &FakeScw) -> Vec<Vec<String>> {
    calls(fake)
        .into_iter()
        .filter(|argv| argv[0] == "scw")
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
    let fake = FakeScw::new(Script::default());
    let err = provisioner(&fake, None)
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("no Scaleway credentials"),
        "refusal names the missing credentials: {text}"
    );
    assert!(
        text.contains("SCW_ACCESS_KEY"),
        "refusal names the checked sources: {text}"
    );
    assert!(
        scw_calls(&fake).is_empty(),
        "no API call before the credentials refusal"
    );
}

#[test]
fn spot_is_refused_scaleway_has_no_spot_product() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeScw::new(Script::default());
    let mut req = request(&config, false);
    req.spot = true;
    let err = provisioner(&fake, Some("env")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("--spot is not supported on scaleway"),
        "{text}"
    );
    assert!(
        text.contains("no spot product"),
        "the refusal names the product gap: {text}"
    );
    assert!(scw_calls(&fake).is_empty(), "refused before any API call");
}

#[test]
fn a_price_cap_is_refused_fixed_price_has_nothing_to_cap() {
    // The GCP fixed-price pairing: --max-price is refused — there is no
    // bid a cap could name in any class. With --spot also set, the spot
    // refusal fires first (both are API-free; the spot product gap is
    // the first thing named).
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeScw::new(Script::default());
    let mut req = request(&config, false);
    req.max_price = Some("0.05".into());
    let err = provisioner(&fake, Some("env")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("--max-price is not supported on scaleway"),
        "{text}"
    );
    assert!(
        text.contains("fixed-price"),
        "the refusal names the pricing class: {text}"
    );
    assert!(scw_calls(&fake).is_empty(), "refused before any API call");

    let both = FakeScw::new(Script::default());
    let mut req = request(&config, false);
    req.spot = true;
    req.max_price = Some("0.05".into());
    let err = provisioner(&both, Some("env")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("--spot is not supported on scaleway"),
        "the spot refusal fires first when both flags ride: {text}"
    );
    assert!(scw_calls(&both).is_empty(), "refused before any API call");
}

// ── Dry run ──

#[test]
fn dry_run_makes_no_api_call_and_needs_no_credentials() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeScw::new(Script::default());
    let workers = provisioner(&fake, None)
        .provision(&request(&config, true))
        .unwrap();
    assert!(workers.is_empty(), "a dry run provisions nothing");
    assert!(
        scw_calls(&fake).is_empty(),
        "dry run must not touch the API: {:?}",
        scw_calls(&fake)
    );
}

// ── Provision ──

#[test]
fn provision_creates_gets_pins_and_tags() {
    let (dir, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeScw::new(Script::default());
    let mut req = request(&config, false);
    req.count = 2;
    let workers = provisioner(&fake, Some("SCW_ACCESS_KEY + SCW_SECRET_KEY"))
        .provision(&req)
        .unwrap();
    assert_eq!(workers.len(), 2);

    // The worker handle is the server NAME (the destroy verb's argument);
    // the address comes from the server get document; the pin is the CA
    // fingerprint (the amendment's pin — one root, not per-worker keys).
    for w in &workers {
        assert!(w.name.starts_with("nau-worker-"), "{}", w.name);
        assert!(
            w.address.starts_with("ssh://root@203.0.113."),
            "{}",
            w.address
        );
        assert_eq!(w.host_key, CA_FPR, "the pin IS the CA fingerprint");
    }

    // The create shape: name, type, the latest-LTS image label, a dynamic
    // flexible IP, the cloud-init user-data file hand-off, the contract
    // tags — and the zone riding every call, credentials in no call.
    let creates: Vec<Vec<String>> = scw_calls(&fake)
        .into_iter()
        .filter(|argv| flat(argv).contains("server\u{1f}create"))
        .collect();
    assert_eq!(creates.len(), 2, "one create call per server");
    let f = flat(&creates[0]);
    assert!(f.contains("-z\u{1f}fr-par-1"), "zone rides the call: {f}");
    assert!(f.contains("type=GP1-XS"), "{f}");
    assert!(
        f.contains("image=ubuntu_2604"),
        "the latest-LTS label pin: {f}"
    );
    assert!(
        f.contains("ip=flexible"),
        "a dynamic public IP is requested: {f}"
    );
    assert!(f.contains("user-data.0.key=cloud-init"), "{f}");
    assert!(
        f.contains("user-data.0.content=file://"),
        "user-data rides the authenticated channel as a file hand-off: {f}"
    );
    let tag_idx = creates[0]
        .iter()
        .position(|a| a == &format!("tags.0={WORKER_TAG}=true"))
        .expect("presence tag stamped at create");
    let ttl_tag = &creates[0][tag_idx + 1];
    assert!(
        ttl_tag.starts_with(&format!("tags.1={WORKER_TTL_TAG}=")),
        "the TTL tag rides next: {ttl_tag}"
    );
    let epoch: u64 = ttl_tag
        .rsplit('=')
        .next()
        .unwrap()
        .parse()
        .expect("the tag value is the TTL epoch");
    assert!(epoch > 1_600_000_000, "the tag value is an expiry epoch");

    assert!(
        !scw_calls(&fake)
            .iter()
            .any(|argv| flat(argv).contains("SCW_ACCESS_KEY")),
        "credentials never enter argv"
    );

    // The staged blobs (captured at create time — removed once served):
    // NO private half anywhere (the amendment's absence property, over
    // the real sent bytes), the publish block rides each blob, and each
    // server carries its own machine identity + one-time token.
    let staged = fake.user_data_files.lock().unwrap();
    assert_eq!(staged.len(), 2, "one staged blob per server");
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
        assert!(content.contains("/etc/nau/publish-host-key.sh"));
        assert!(content.contains(OPERATOR_KEY));
        assert!(
            content.contains("MACHINE_IDENTITY='nau-worker-"),
            "the machine identity is the server name"
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
    assert!(nau::lua::evaluate_file(config.to_str().unwrap()).is_ok());
    // Nothing was deleted on the happy path.
    assert!(
        !scw_calls(&fake)
            .iter()
            .any(|argv| flat(argv).contains("server\u{1f}delete")),
        "happy provision never deletes"
    );
    let _ = dir;
}

#[test]
fn create_failure_leaves_no_server_and_no_config_change() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeScw::new(Script {
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
        !scw_calls(&fake)
            .iter()
            .any(|argv| flat(argv).contains("server\u{1f}delete")),
        "nothing was created, so nothing is torn down"
    );
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "config untouched"
    );
}

#[test]
fn get_failure_after_create_tears_down() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeScw::new(Script {
        get_fails: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("tore down 1 created server(s)"), "{text}");
    assert_eq!(
        scw_calls(&fake)
            .iter()
            .filter(|argv| flat(argv).contains("server\u{1f}delete"))
            .count(),
        1,
        "the created server is deleted"
    );
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "no pin without an address"
    );
}

#[test]
fn no_public_ip_refuses_and_tears_down() {
    // A zone/IP quota that denies the dynamic flexible IP would produce
    // an unreachable worker: fail-closed with the remedy named, never a
    // pin to an address that cannot be reached.
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeScw::new(Script {
        no_public_ip: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("no public IP"), "{text}");
    assert!(text.contains("ip=flexible"), "the remedy is named: {text}");
    assert!(text.contains("tore down 1 created server(s)"), "{text}");
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "config untouched"
    );
}

#[test]
fn pin_failure_after_create_tears_down() {
    // A config that cannot be pinned (missing file) must not leave a
    // live server: teardown-on-failure is the ADR-0045 atomicity.
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("absent").join("nau.lua");
    let fake = FakeScw::new(Script::default());
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("tore down 1 created server(s)"), "{text}");
    assert!(text.contains("config untouched"), "{text}");
}

// ── Teardown truthfulness ──

#[test]
fn teardown_delete_failure_names_the_residual_server() {
    // A teardown delete that fails must NOT read as torn down: the
    // error names the still-billing residual and the reclaim path.
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeScw::new(Script {
        get_fails: true,
        delete_fails: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("tore down 0 created server(s)"), "{text}");
    assert!(text.contains("FAILED to delete nau-worker-"), "{text}");
    assert!(text.contains("still running and billing"), "{text}");
    assert!(text.contains("'nau workers destroy'"), "{text}");
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "config untouched"
    );
}

#[test]
fn teardown_reports_mixed_delete_results() {
    // Two servers created, the SECOND pin refuses (an operator-owned
    // entry already holds its address — nau never rewrites operator
    // text), and the SECOND teardown delete fails: the first is honestly
    // counted torn down AND the stuck one is named — neither half can
    // vanish into a blanket success line.
    let (_d, config) = workspace("nau.lua");
    // The fake ids derive from the -NN name suffix: servers -01 / -02
    // describe to 203.0.113.11 / .12; the operator-owned entry at .12
    // makes pin #2 refuse after pin #1 pinned .11.
    std::fs::write(
        &config,
        "workers = { { address = \"ssh://root@203.0.113.12\", host_key = \"ssh-ed25519 AAAAoperator operator\" } }\nreturn {}\n",
    )
    .unwrap();
    let fake = FakeScw::new(Script {
        delete_fails_after: 1,
        ..Default::default()
    });
    let mut req = request(&config, false);
    req.count = 2;
    let err = provisioner(&fake, Some("env")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("tore down 1 created server(s)"), "{text}");
    assert!(text.contains("FAILED to delete nau-worker-"), "{text}");
    assert!(text.contains("still running and billing"), "{text}");
    // NOTE: the pin that DID succeed stays in the config (the torn-down
    // instance residue) — the same pre-existing partial-pin residue the
    // #281 review names for hetzner (m1), not this ticket's scope.
}

// ── User-data staging hygiene ──

#[test]
fn user_data_is_staged_inside_the_mint_tempdir_at_0600() {
    // The blob carries the minted private host half: it must live in the
    // provision tempdir (so it dies with the run) at mode 0600 — and it
    // must never enter argv.
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeScw::new(Script::default());
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
    assert!(
        !calls(&fake)
            .iter()
            .any(|argv| argv.iter().any(|a| a.contains("PRIVATE KEY"))),
        "the private half never enters argv"
    );
}

// ── Destroy ──

#[test]
fn destroy_resolves_by_name_deletes_and_evicts_the_managed_entry() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeScw::new(Script::default());
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
    // The destroy tail: list (name → id) BEFORE get (ip + volumes)
    // BEFORE delete, and the delete carries the resolved id. (The
    // provision path's own create/get calls precede the tail — search
    // from the list onward.)
    let sequence = scw_calls(&fake);
    let list_idx = sequence
        .iter()
        .position(|argv| flat(argv).contains("server\u{1f}list"))
        .expect("list ran (destroy resolves the id)");
    let tail = &sequence[list_idx..];
    let get_idx = tail
        .iter()
        .position(|argv| flat(argv).contains("server\u{1f}get"))
        .expect("get ran in the destroy tail");
    let delete_idx = tail
        .iter()
        .position(|argv| flat(argv).contains("server\u{1f}delete"))
        .expect("delete ran in the destroy tail");
    assert!(get_idx < delete_idx, "{tail:?}");
    let del = &tail[delete_idx];
    assert!(
        del.last().unwrap().starts_with("server-id="),
        "the delete names the resolved id: {del:?}"
    );
}

#[test]
fn destroy_requires_credentials_before_any_api_call() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeScw::new(Script::default());
    let err = provisioner(&fake, None)
        .destroy("nau-worker-x-01", &config)
        .unwrap_err();
    assert!(format!("{err:#}").contains("no Scaleway credentials"));
    assert!(scw_calls(&fake).is_empty());
}

#[test]
fn destroy_checks_block_volumes_before_delete_and_proceeds() {
    // Block-storage volumes survive a server delete (detached, still
    // billing): the pre-delete check must run BEFORE the delete — and
    // the delete still proceeds (the operator asked for it).
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeScw::new(Script::default());
    let workers = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap();
    let name = workers[0].name.clone();

    let sbsfake = FakeScw::new(Script {
        sbs_volumes: 2,
        ..Default::default()
    });
    // Mirror the world into the scripted fake (the provision ran against
    // `fake`; `sbsfake` starts empty) so the destroy resolves the name.
    let world = fake.servers.lock().unwrap().clone();
    for (id, server) in &world {
        sbsfake
            .servers
            .lock()
            .unwrap()
            .push((id.clone(), server.clone()));
    }
    provisioner(&sbsfake, Some("env"))
        .destroy(&name, &config)
        .unwrap();

    let sequence = scw_calls(&sbsfake);
    let get_idx = sequence
        .iter()
        .position(|argv| flat(argv).contains("server\u{1f}get"))
        .expect("the volume check's describe ran");
    let delete_idx = sequence
        .iter()
        .position(|argv| flat(argv).contains("server\u{1f}delete"))
        .expect("delete ran");
    assert!(
        get_idx < delete_idx,
        "the volume check happens BEFORE the delete: {:?}",
        sequence
    );
}

#[test]
fn destroy_of_an_unknown_server_is_a_named_refusal() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeScw::new(Script {
        empty_list: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("env"))
        .destroy("nau-worker-nosuch-01", &config)
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("nau-worker-nosuch-01"), "{text}");
    assert!(text.contains("nothing was deleted"), "{text}");
    assert!(
        !scw_calls(&fake)
            .iter()
            .any(|argv| flat(argv).contains("server\u{1f}delete")),
        "a list miss never deletes"
    );
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "config untouched"
    );
}

#[test]
fn destroy_keeps_the_pin_when_the_delete_fails() {
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeScw::new(Script::default());
    let workers = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap();
    let name = workers[0].name.clone();
    let address = workers[0].address.clone();

    let sloppy = FakeScw::new(Script {
        delete_fails: true,
        ..Default::default()
    });
    let world = fake.servers.lock().unwrap().clone();
    for (id, server) in &world {
        sloppy
            .servers
            .lock()
            .unwrap()
            .push((id.clone(), server.clone()));
    }
    let err = provisioner(&sloppy, Some("env"))
        .destroy(&name, &config)
        .unwrap_err();
    assert!(format!("{err:#}").contains("still running"), "{err:#}");
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(
        text.contains(&format!("address = \"{address}\"")),
        "a failed delete leaves the pin: the server is still live"
    );
}

#[test]
fn destroy_of_a_server_without_a_managed_pin_reports_not_evicted() {
    // Eviction honesty: a deleted server whose address no managed entry
    // pins must read as NOT evicted — `Ok(false)` — so the verb never
    // claims an eviction that did not happen.
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeScw::new(Script::default());
    let workers = provisioner(&fake, Some("env"))
        .provision(&request(&config, false))
        .unwrap();
    // Evict the managed entry out-of-band first: the destroy then finds
    // no managed entry at the server's address.
    let address = workers[0].address.clone();
    let text = std::fs::read_to_string(&config).unwrap();
    let block_start = text.find(BLOCK_BEGIN).unwrap();
    let block_end = text.find(BLOCK_END).unwrap() + BLOCK_END.len();
    let stripped: String = text[..block_start].to_string() + &text[block_end..];
    std::fs::write(&config, stripped).unwrap();

    let evicted = provisioner(&fake, Some("env"))
        .destroy(&workers[0].name, &config)
        .unwrap();
    assert!(!evicted, "no managed entry → nothing evicted ({address})");
}

// ── The base-image pin ──

#[test]
fn the_base_image_resolves_the_latest_ubuntu_lts_never_a_codename() {
    // ADR-0046: the contract pins "latest LTS" — the marketplace label
    // carries the release digits (26.04 at the 2026-09-27 decision,
    // #273's reconciliation), never a codename. The shape rule is the
    // same one the aws SSM-parameter test asserts.
    let label = IMAGE_LABEL;
    assert!(label.starts_with("ubuntu_"));
    let release = label.strip_prefix("ubuntu_").unwrap();
    assert_eq!(
        release.len(),
        4,
        "ubuntu_NNNN release digits, never a codename: {label}"
    );
    assert!(
        release.chars().all(|c| c.is_ascii_digit()),
        "numeric release, never a codename: {label}"
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
    // per-server blob differs only there).
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
    assert!(!user_data.contains("SCW_SECRET_KEY"));
}

#[test]
fn each_server_gets_its_own_recorded_one_time_token() {
    // The convergence property, read back from the coordinator registry:
    // N servers → N recorded tokens, each bound to its own machine
    // identity, none consumed (issuance is sub-task 3).
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let (pubhome, publish) = pubtmp();
    let fake = FakeScw::new(Script::default());
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
    assert_eq!(tokens.len(), 2, "one recorded issuance per server");
    let mut identities: Vec<&str> = tokens
        .iter()
        .map(|t| t["machine_identity"].as_str().unwrap())
        .collect();
    identities.sort();
    assert!(
        identities.windows(2).all(|w| w[0] != w[1]),
        "one identity per server: {identities:?}"
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
    let fake = FakeScw::new(Script::default());
    let err = provisioner_with(&fake, Some("env"), None)
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("no publish channel"), "{text}");
    assert!(text.contains("NAU_PUBLISH_URL"), "{text}");
    assert!(
        scw_calls(&fake).is_empty(),
        "no API call before the publish-channel refusal"
    );
}

#[test]
fn no_ca_fingerprint_refuses_before_any_api_call() {
    // Fail-closed interim: the pin IS the CA fingerprint; a request
    // without one is a named refusal before any API call.
    let (_d, config) = workspace("nau.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeScw::new(Script::default());
    let mut req = request(&config, false);
    req.ca_fingerprint = None;
    let err = provisioner(&fake, Some("env")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("no host CA fingerprint"), "{text}");
    assert!(text.contains("nau ca keygen"), "{text}");
    assert!(
        scw_calls(&fake).is_empty(),
        "no API call before the CA-pin refusal"
    );
}
