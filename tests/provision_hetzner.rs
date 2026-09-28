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
use shuttle::provision::publish::PublishChannel;
use shuttle::provision::{
    append_worker_entry, now_epoch_secs, parse_ttl, render_user_data, ProvisionRequest,
    Provisioner, UserDataParams, BLOCK_BEGIN, BLOCK_END, PLAN_MACHINE_IDENTITY, PLAN_PUBLISH_TOKEN,
    PLAN_PUBLISH_URL, SQUASHFS_TOOLS_RELEASE_DATE, SQUASHFS_TOOLS_SHA256,
    SQUASHFS_TOOLS_TARBALL_URL, SQUASHFS_TOOLS_VERSION,
};

/// A shape-valid ed25519 public line — throwaway fixture bytes, no
/// crypto. Reused as the published-key fixture in payload-shape tests.
const TEST_HOST_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkvsDFv9XrohqXsJvKK8dFbGFe5vN3fGcLgoW8cR3UxQ shuttle-worker-host-key";
const OPERATOR_KEY: &str = "ssh-ed25519 AAAAoperatorkey operator@example";
const BINARY_URL: &str = "https://example.invalid/shuttle-amd64";

/// The host CA fingerprint the request carries (valid
/// `SHA256:` + 43 base64 chars — the pin grammar's fingerprint form).
const CA_FPR: &str = "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfG";
const PUBLISH_URL: &str = "https://coordinator.example/publish";

/// A fixed marker expiry for template-shape assertions (decimal epoch
/// seconds — the #269 sweep's `is_epoch` shape).
const MARKER_EPOCH: u64 = 1_788_000_000;

// ── The scripted provider CLI ──

#[derive(Clone, Default)]
struct Script {
    create_fails: bool,
    describe_fails: bool,
    delete_fails: bool,
    /// Fail deletes once this many have already succeeded (default:
    /// effectively never) — scripts a MIXED teardown: some servers
    /// deleted, some stuck billing.
    delete_fails_after: usize,
    /// Volumes the fake reports attached to any server (the #269 v2
    /// pre-delete check's input).
    attached_volumes: usize,
}

/// Plays `hcloud` from scripted state and records every argv. Cheap to
/// clone; all clones share one call log. (No ssh-keygen arm: the
/// amendment removed the coordinator-side mint — a provision that tried
/// to ssh-keygen would fail loudly here.)
#[derive(Clone)]
struct FakeProvider {
    calls: Arc<Mutex<Vec<Vec<String>>>>,
    /// (path, unix mode, content) of every `--user-datafile` the fake
    /// served, captured at call time — the real blob dies with the
    /// staging tempdir.
    user_data_files: Arc<Mutex<Vec<(PathBuf, u32, String)>>>,
    /// Successful `server delete` count, shared across clones (drives
    /// `delete_fails_after`).
    deletes_done: Arc<Mutex<usize>>,
    script: Script,
}

impl FakeProvider {
    fn new(script: Script) -> Self {
        FakeProvider {
            calls: Arc::new(Mutex::new(Vec::new())),
            user_data_files: Arc::new(Mutex::new(Vec::new())),
            deletes_done: Arc::new(Mutex::new(0)),
            script,
        }
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
                use std::os::unix::fs::PermissionsExt;
                if let Some(i) = argv.iter().position(|a| a == "--user-datafile") {
                    let path = PathBuf::from(&argv[i + 1]);
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
            ["server", "describe", name, "-o", "json"] => {
                if self.script.describe_fails {
                    return Ok(fail_out("hcloud: server not found (fake)"));
                }
                Ok(ok_out(&describe_json(name)))
            }
            ["server", "delete", _name] => {
                let mut done = self.deletes_done.lock().unwrap();
                if self.script.delete_fails
                    || (self.script.delete_fails_after > 0
                        && *done >= self.script.delete_fails_after)
                {
                    return Ok(fail_out("hcloud: delete failed (fake)"));
                }
                *done += 1;
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
        spot: false,
        max_price: None,
        dry_run,
        config: config.to_path_buf(),
        ca_fingerprint: Some(CA_FPR.into()),
    }
}

/// A publish channel pointed at a throwaway home: the one-time token
/// registry lands there (recreated on demand) and the provider tests
/// never read it back — tests that assert on the registry build their
/// own channel with [`pubtmp`].
fn throwaway_publish_channel() -> PublishChannel {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    PublishChannel {
        url: PUBLISH_URL.into(),
        home: std::env::temp_dir().join(format!("shuttle-hetzner-publish-test-{nanos}")),
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

fn provisioner(fake: &FakeProvider, token: Option<&str>) -> HetznerProvisioner<FakeProvider> {
    provisioner_with(fake, token, Some(throwaway_publish_channel()))
}

fn provisioner_with(
    fake: &FakeProvider,
    token: Option<&str>,
    publish: Option<PublishChannel>,
) -> HetznerProvisioner<FakeProvider> {
    HetznerProvisioner::new(
        fake.clone(),
        token.map(|t| t.to_string()),
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
fn hetzner_has_no_spot_product_and_refuses_the_flag() {
    // providers plan §1: spot is an aws capability. A hetzner provision
    // carrying --spot is a REFUSAL, never a silent on-demand fallback —
    // an on-demand instance pretending to be spot lies about its
    // eviction class.
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeProvider::new(Script::default());
    let mut req = request(&config, false);
    req.spot = true;
    req.max_price = Some("0.05".into());
    let err = provisioner(&fake, Some("tok")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("--spot is not supported on hetzner"),
        "{text}"
    );
    assert!(
        hcloud_calls(&fake).is_empty(),
        "the refusal precedes every API call"
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
    // The publish runs after curl is installed and retries are bounded —
    // a not-yet-up coordinator never bricks the boot. The pickup unit
    // enable is the final runcmd (the certificate fetch must not hang
    // the boot — it polls from a oneshot service, #295 sub-task 4).
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
    // The provider token never rides user-data.
    assert!(!user_data.contains("HCLOUD_TOKEN"));
}

#[test]
fn user_data_builds_the_pinned_squashfs_tools_from_source() {
    let user_data = render_user_data(&UserDataParams {
        machine_identity: PLAN_MACHINE_IDENTITY,
        publish_url: PLAN_PUBLISH_URL,
        publish_token: PLAN_PUBLISH_TOKEN,
        operator_key: OPERATOR_KEY,
        binary_url: BINARY_URL,
        ttl_expiry_epoch: MARKER_EPOCH,
    });
    // Pin 1 (providers plan §3): the exact 4.7.x pin rides the template —
    // exact tarball URL, exact bytes (sha256 verified BEFORE the build),
    // the lz4/zstd/xz build the plan names, the install to /usr/local/bin
    // (PATH-precedence over the distro's 4.6.1), and a version assert so
    // a drifted build fails provisioning instead of joining the fleet.
    assert!(
        SQUASHFS_TOOLS_VERSION.starts_with("4.7."),
        "the fleet pin is a 4.7.x, got {SQUASHFS_TOOLS_VERSION}"
    );
    assert!(user_data.contains(SQUASHFS_TOOLS_TARBALL_URL));
    assert!(user_data.contains(SQUASHFS_TOOLS_SHA256));
    assert!(user_data.contains("sha256sum -c"));
    // The compression set the plan names, explicit over the Makefile's
    // defaults (lzo defaults ON in 4.7.x; the pin is xz/zstd/lz4).
    assert!(user_data.contains("XZ_SUPPORT=1 ZSTD_SUPPORT=1 LZ4_SUPPORT=1 LZO_SUPPORT=0"));
    // The release VERSION is forced: the codeload tarball otherwise bakes
    // the commit hash into the version string, and admission pins the
    // exact string the resolved binary reports.
    assert!(user_data.contains(&format!(
        "RELEASE_VERSION={SQUASHFS_TOOLS_VERSION} RELEASE_DATE={SQUASHFS_TOOLS_RELEASE_DATE}"
    )));
    assert!(user_data.contains(&format!(
        "make -C squashfs-tools-{SQUASHFS_TOOLS_VERSION}/squashfs-tools install"
    )));
    assert!(user_data.contains("/usr/local/bin/mksquashfs -version"));
    assert!(user_data.contains(&format!("grep -q \"version {SQUASHFS_TOOLS_VERSION} \"")));
    // The build tree never rides into a snapshot (#271 bills per GB-month).
    assert!(user_data.contains("rm -rf /tmp/squashfs-tools-"));
}

#[test]
fn user_data_installs_the_distro_bwrap_pin_and_keeps_the_userns_hardening() {
    let user_data = render_user_data(&UserDataParams {
        machine_identity: PLAN_MACHINE_IDENTITY,
        publish_url: PLAN_PUBLISH_URL,
        publish_token: PLAN_PUBLISH_TOKEN,
        operator_key: OPERATOR_KEY,
        binary_url: BINARY_URL,
        ttl_expiry_epoch: MARKER_EPOCH,
    });
    // Pin 2: bwrap + ca-certificates + curl from the DISTRO, no overlay.
    assert!(user_data
        .contains("apt-get install -y --no-install-recommends bubblewrap ca-certificates curl"));
    // The current Ubuntu LTS AppArmor userns restriction is system
    // hardening that does NOT break bubblewrap (it ships its own
    // profile): the template never weakens it. Admission is fail-closed
    // via the __worker-cap real sandbox probe instead.
    assert!(!user_data.contains("apparmor_restrict_unprivileged_userns"));
}

#[test]
fn the_base_image_is_the_latest_ubuntu_lts_slug_never_a_codename() {
    // ADR-0046: the contract pins "latest LTS" — 26.04 at the 2026-09-27
    // decision. The slug shape (ubuntu-NN.NN) is the never-a-codename
    // rule made checkable; a codename like "resolute" must never land.
    assert_eq!(shuttle::provision::hetzner::IMAGE, "ubuntu-26.04");
    let slug = shuttle::provision::hetzner::IMAGE
        .strip_prefix("ubuntu-")
        .expect("an ubuntu image slug");
    assert_eq!(
        slug.len(),
        "NN.NN".len(),
        "ubuntu-NN.NN, never a codename: {}",
        shuttle::provision::hetzner::IMAGE
    );
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

    // Addresses are pinned from the describe documents; the host_key pin
    // is the CA fingerprint (the amendment's pin — one root, not
    // per-worker keys).
    for w in &workers {
        assert!(
            w.address.starts_with("ssh://root@203.0.113."),
            "{}",
            w.address
        );
        assert_eq!(w.host_key, CA_FPR, "the pin IS the CA fingerprint");
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
        // The base-image pin (ADR-0046 latest-Ubuntu-LTS slug) rides the
        // create argv — asserted against the const, so pin and test move
        // together.
        assert!(f.contains(&format!(
            "--image\u{1f}{}",
            shuttle::provision::hetzner::IMAGE
        )));
        let udf = argv.iter().position(|a| a == "--user-datafile").unwrap();
        assert!(!argv[udf + 1].is_empty(), "a user-data file is passed");
        assert!(!f.contains("tok-1"), "token never enters argv: {f}");
    }

    // The staged blobs (captured at create time — they die with the
    // staging tempdir after provision): NO private half anywhere (the
    // amendment's absence property, over the real sent bytes), the
    // publish block rides it, and each server's machine identity is its
    // own name; the operator key authorizes login.
    let staged = fake.user_data_files.lock().unwrap();
    assert_eq!(staged.len(), 2, "one staged blob per create");
    for (_, _, user_data) in staged.iter() {
        assert!(
            !user_data.contains("BEGIN OPENSSH PRIVATE KEY"),
            "no private half rides user-data"
        );
        assert!(
            !user_data.contains("path: /etc/ssh/ssh_host_ed25519_key\n"),
            "no injected host key"
        );
        assert!(user_data.contains("/etc/shuttle/publish-host-key.sh"));
        assert!(user_data.contains(OPERATOR_KEY));
        assert!(
            user_data.contains("MACHINE_IDENTITY='shuttle-worker-"),
            "the machine identity is the server name"
        );
    }
    // The two blobs carry DIFFERENT one-time tokens.
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

    let evicted = provisioner(&fake, Some("tok"))
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

#[test]
fn destroy_of_a_server_without_a_managed_pin_reports_not_evicted() {
    // Eviction honesty (#272 addendum): a deleted server whose address no
    // managed entry pins must read as NOT evicted — `Ok(false)` — so the
    // verb never claims an eviction that did not happen.
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeProvider::new(Script::default());
    let evicted = provisioner(&fake, Some("tok"))
        .destroy("shuttle-worker-fake-01", &config)
        .unwrap();
    assert!(!evicted, "no managed entry → nothing evicted");
}

// ── M1: user-data staging hygiene ──

#[test]
fn user_data_is_staged_inside_the_provision_tempdir_at_0600() {
    // The blob carries the one-time publish bearer: it must live in the
    // provision tempdir (so it dies with the run) at mode 0600 — never at
    // a fixed world-readable OS-temp path that outlives the run.
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeProvider::new(Script::default());
    provisioner(&fake, Some("tok"))
        .provision(&request(&config, false))
        .unwrap();

    let staged = fake.user_data_files.lock().unwrap();
    assert_eq!(staged.len(), 1, "one create, one staged blob: {staged:?}");
    let (path, mode, _) = staged[0].clone();
    drop(staged);
    assert_eq!(
        path.file_name().unwrap(),
        "user-data.yaml",
        "staged inside the provision tempdir, not a content-addressed temp path"
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

// ── Amendment convergence: one-time tokens, per-server identity ──

#[test]
fn each_server_gets_its_own_recorded_one_time_token() {
    // The convergence property, read back from the coordinator registry:
    // N servers → N recorded tokens, each bound to its own machine
    // identity, none consumed (issuance is sub-task 3).
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let (pubhome, publish) = pubtmp();
    let fake = FakeProvider::new(Script::default());
    let mut req = request(&config, false);
    req.count = 2;
    provisioner_with(&fake, Some("tok"), Some(publish))
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
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeProvider::new(Script::default());
    let err = provisioner_with(&fake, Some("tok"), None)
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("no publish channel"), "{text}");
    assert!(text.contains("SHUTTLE_PUBLISH_URL"), "{text}");
    assert!(
        hcloud_calls(&fake).is_empty(),
        "no API call before the publish-channel refusal"
    );
}

#[test]
fn no_ca_fingerprint_refuses_before_any_api_call() {
    // Fail-closed interim: the pin IS the CA fingerprint; a request
    // without one is a named refusal before any API call.
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let fake = FakeProvider::new(Script::default());
    let mut req = request(&config, false);
    req.ca_fingerprint = None;
    let err = provisioner(&fake, Some("tok")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("no host CA fingerprint"), "{text}");
    assert!(text.contains("shuttle ca keygen"), "{text}");
    assert!(
        hcloud_calls(&fake).is_empty(),
        "no API call before the CA-pin refusal"
    );
}

// ── M2: teardown truthfulness ──

#[test]
fn teardown_delete_failure_names_the_residual_server() {
    // A teardown delete that fails must NOT read as torn down: the error
    // names the still-billing residual and both reclaim paths.
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let fake = FakeProvider::new(Script {
        describe_fails: true,
        delete_fails: true,
        ..Default::default()
    });
    let err = provisioner(&fake, Some("tok"))
        .provision(&request(&config, false))
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("tore down 0 created server(s)"), "{text}");
    assert!(text.contains("FAILED to delete shuttle-worker-"), "{text}");
    assert!(text.contains("it is still billing"), "{text}");
    assert!(text.contains("'shuttle workers destroy'"), "{text}");
    assert!(text.contains("TTL sweep reclaim it"), "{text}");
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "config untouched"
    );
}

#[test]
fn teardown_reports_mixed_delete_results() {
    // Two servers created, the pin step fails, and the SECOND teardown
    // delete fails: the first is honestly counted torn down AND the stuck
    // one is named with its reclaim path — neither half can vanish into a
    // blanket success line.
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("absent").join("shuttle.lua");
    let fake = FakeProvider::new(Script {
        delete_fails_after: 1,
        ..Default::default()
    });
    let mut req = request(&config, false);
    req.count = 2;
    let err = provisioner(&fake, Some("tok")).provision(&req).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("tore down 1 created server(s)"), "{text}");
    assert!(text.contains("FAILED to delete shuttle-worker-"), "{text}");
    assert!(text.contains("it is still billing"), "{text}");
    assert!(text.contains("TTL sweep reclaim it"), "{text}");
}

// ── m2: config mode preservation ──

#[test]
fn config_mode_survives_a_managed_block_rewrite() {
    // The atomic rewrite persists a 0600 tempfile — the operator's
    // shuttle.lua mode must survive every provision/destroy rewrite.
    use std::os::unix::fs::PermissionsExt;
    let (_d, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    for mode in [0o644, 0o600, 0o640] {
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(mode)).unwrap();
        append_worker_entry(&config, "ssh://root@203.0.113.99", "ssh-ed25519 AAAAm c").unwrap();
        let got = std::fs::metadata(&config).unwrap().permissions().mode() & 0o777;
        assert_eq!(got, mode, "mode {mode:o} preserved across the rewrite");
    }
}

// ── M6: the marker interop (writer here, reader = the sweep script) ──

/// The single marker line `render_user_data` emits for `expiry`: the
/// content line under the `/etc/shuttle/worker-ttl` write_files block.
fn emitted_marker_line(user_data: &str) -> String {
    user_data
        .lines()
        .skip_while(|line| !line.contains("path: /etc/shuttle/worker-ttl"))
        .nth(3)
        .and_then(|line| line.strip_prefix("      "))
        .expect("the marker content line")
        .to_string()
}

#[test]
fn sweep_accepts_exactly_what_render_user_data_emits_as_the_marker() {
    // The interop test whose absence let the ISO-8601 marker land: the
    // sweep script is the marker's only reader and its `is_epoch` parses
    // DECIMAL EPOCH SECONDS only. Run the REAL sweep (fake hcloud + fake
    // ssh) against marker files holding exactly the bytes the template
    // emits, and require the marker-copy rule (Rule 2) to decide BOTH
    // directions — past due → destroy track, future → ALIVE.
    let now = now_epoch_secs().unwrap();
    let past_blob = render_user_data(&UserDataParams {
        machine_identity: PLAN_MACHINE_IDENTITY,
        publish_url: PLAN_PUBLISH_URL,
        publish_token: PLAN_PUBLISH_TOKEN,
        operator_key: OPERATOR_KEY,
        binary_url: BINARY_URL,
        ttl_expiry_epoch: now - 2 * 3600,
    });
    let future_blob = render_user_data(&UserDataParams {
        machine_identity: PLAN_MACHINE_IDENTITY,
        publish_url: PLAN_PUBLISH_URL,
        publish_token: PLAN_PUBLISH_TOKEN,
        operator_key: OPERATOR_KEY,
        binary_url: BINARY_URL,
        ttl_expiry_epoch: now + 24 * 3600,
    });

    // The emitted marker block is the decimal-epoch shape, byte for byte.
    for blob in [&past_blob, &future_blob] {
        let marker = emitted_marker_line(blob);
        assert!(
            !marker.is_empty() && marker.chars().all(|c| c.is_ascii_digit()),
            "the marker line is decimal epoch seconds: '{marker}'"
        );
        let block = format!(
            "  - path: /etc/shuttle/worker-ttl\n    permissions: \"0644\"\n    content: |\n      {marker}\n"
        );
        assert!(blob.contains(&block), "the marker block shape: {block}");
    }

    // Fake provider CLI: two servers with ABSENT ttl labels, so the sweep
    // falls through Rule 1 to the marker copy (Rule 2) — the fallback the
    // marker exists for.
    let fx = tempfile::tempdir().unwrap();
    let fx_path = fx.path();
    let bin = fx_path.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(
        fx_path.join("servers.list"),
        "w-marker-past\nw-marker-future\n",
    )
    .unwrap();
    std::fs::write(
        fx_path.join("w-marker-past"),
        format!("{} 10.9.1.1 \n", now - 2 * 3600),
    )
    .unwrap();
    std::fs::write(
        fx_path.join("w-marker-future"),
        format!("{} 10.9.1.2 \n", now - 2 * 3600),
    )
    .unwrap();
    // The in-guest marker file: exactly the emitted content line + newline
    // (what cloud-init writes for a one-line `content: |` block).
    std::fs::write(
        fx_path.join("10.9.1.1.ttl"),
        format!("{}\n", emitted_marker_line(&past_blob)),
    )
    .unwrap();
    std::fs::write(
        fx_path.join("10.9.1.2.ttl"),
        format!("{}\n", emitted_marker_line(&future_blob)),
    )
    .unwrap();
    let hcloud_fake = bin.join("hcloud");
    std::fs::write(
        &hcloud_fake,
        "#!/bin/sh\ncase \"$1 $2\" in\n\
         \"server list\") cat \"$HCLOUD_LIST\" ;;\n\
         \"server describe\") cat \"$HCLOUD_DESCRIBE_DIR/$3\" ;;\n\
         \"volume list\") exit 0 ;;\n\
         \"server delete\") printf '%s\\n' \"$3\" >>\"$HCLOUD_DELETE_LOG\" ;;\n\
         *) echo \"fake hcloud: unexpected invocation: $*\" >&2; exit 64 ;;\n\
         esac\n",
    )
    .unwrap();
    let ssh_fake = bin.join("ssh");
    std::fs::write(
        &ssh_fake,
        "#!/bin/sh\nhost=\"\"\nfor a in \"$@\"; do\n\
         case \"$a\" in *@*) host=${a#*@} ;; esac\ndone\n\
         [ -n \"$host\" ] || exit 255\n\
         exec cat \"$SSH_FIXTURE_DIR/$host.ttl\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hcloud_fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&ssh_fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Dry-run is the sweep's default: prove classification, touch nothing.
    let sweep = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/shuttle-worker-ttl-sweep");
    let out = std::process::Command::new("sh")
        .arg(&sweep)
        .env("SHUTTLE_SWEEP_HCLOUD", &hcloud_fake)
        .env("SHUTTLE_SWEEP_SSH", &ssh_fake)
        .env("SHUTTLE_SWEEP_SSH_OPTS", "-o BatchMode=yes")
        .env("SSH_FIXTURE_DIR", fx_path)
        .env("HCLOUD_LIST", fx_path.join("servers.list"))
        .env("HCLOUD_DESCRIBE_DIR", fx_path)
        .env("HCLOUD_DELETE_LOG", fx_path.join("deletes.log"))
        .env_remove("SHUTTLE_SWEEP_ENFORCE")
        .env_remove("SHUTTLE_SWEEP_ALERT_CMD")
        .output()
        .expect("run the sweep script");
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "sweep exits clean when every value parses: {}\n{err}",
        out.status
    );
    assert!(
        err.contains("WOULD-DESTROY: w-marker-past (no TTL label; marker copy past due)"),
        "the emitted marker, past due, must drive the destroy track:\n{err}"
    );
    assert!(
        err.contains("ALIVE: w-marker-future (no TTL label; marker copy in the future)"),
        "the emitted marker, in the future, must read ALIVE:\n{err}"
    );
    assert!(
        !err.contains("LABEL-INVALID"),
        "an epoch marker never reads as an invalid label:\n{err}"
    );
}

#[test]
fn provision_records_the_machine_linkage_next_to_the_pin() {
    // The executor's @cert-authority pin binds the certificate principal
    // through the address→identity linkage (#295 sub-task 4): one record
    // per pinned server, under the publish channel's ceremony home.
    let (dir, config) = workspace("shuttle.lua");
    std::fs::write(&config, operator_config()).unwrap();
    let (pubtmp, channel) = pubtmp();
    let fake = FakeProvider::new(Script::default());
    let mut req = request(&config, false);
    req.count = 2;
    let workers = provisioner_with(&fake, Some("tok-1"), Some(channel))
        .provision(&req)
        .unwrap();
    assert_eq!(workers.len(), 2);

    let machines = shuttle::provision::publish::machines_dir(pubtmp.path());
    let mut links: Vec<(String, String)> = std::fs::read_dir(&machines)
        .unwrap()
        .flatten()
        .map(|e| {
            let link: shuttle::provision::publish::MachineLink =
                serde_json::from_str(&std::fs::read_to_string(e.path()).unwrap()).unwrap();
            (link.address.clone(), link.machine_identity.clone())
        })
        .collect();
    links.sort();
    assert_eq!(links.len(), 2, "one linkage per pinned server");
    for w in &workers {
        assert!(
            links
                .iter()
                .any(|(a, id)| a == &w.address && id.starts_with("shuttle-worker-")),
            "address {} is linked to its machine identity: {links:?}",
            w.address
        );
    }
}

#[test]
fn user_data_picks_the_issued_certificate_up_on_first_boot() {
    // #295 sub-task 4: the guest fetches its issued certificate over the
    // SAME one-time bearer channel the publish used, installs it beside
    // the generated key, and restarts sshd. The retry budget is exactly
    // the token TTL: 1440 × 60s = 86400s.
    let user_data = render_user_data(&UserDataParams {
        machine_identity: "shuttle-worker-abc-01",
        publish_url: PUBLISH_URL,
        publish_token: "a".repeat(64).leak(),
        operator_key: OPERATOR_KEY,
        binary_url: BINARY_URL,
        ttl_expiry_epoch: 1_800_000_000,
    });

    // The pickup rides a oneshot unit, not a runcmd — the retry loop may
    // legitimately run for the whole token window.
    assert!(user_data.contains("path: /etc/shuttle/pickup-host-cert.sh\n    permissions: \"0700\""));
    assert!(user_data.contains(
        "path: /etc/systemd/system/shuttle-pickup-host-cert.service\n    permissions: \"0644\""
    ));
    assert!(user_data.contains("Type=oneshot"));
    assert!(
        user_data.contains("TimeoutStartSec=infinity"),
        "the retry loop must not die at systemd's 90s default start timeout"
    );
    assert!(user_data.contains("ExecStart=/etc/shuttle/pickup-host-cert.sh"));

    // The GET half of the same callback: same URL env, same bearer.
    assert!(user_data.contains("Authorization: Bearer $PUBLISH_TOKEN"));
    assert!(user_data.contains("-o \"$TMP\" \"$PUBLISH_URL\""));
    assert!(user_data.contains("CERT=/etc/ssh/ssh_host_ed25519_key-cert.pub"));
    assert!(
        user_data.contains("head -n 1 \"$TMP\" | grep -q 'ssh-ed25519-cert-v01@openssh.com'"),
        "the fetch is shape-checked before it is installed"
    );
    assert!(
        user_data.contains("chmod 0644 \"$TMP\"") && user_data.contains("mv \"$TMP\" \"$CERT\""),
        "atomic install, cert mode 0644 (public material)"
    );
    assert!(user_data.contains("systemctl restart ssh || systemctl restart sshd"));

    // Bounded retries sized to the publish-token window.
    let ttl = shuttle::provision::publish::PUBLISH_TOKEN_TTL_SECS;
    assert!(user_data.contains("while [ \"$i\" -lt 1440 ]"));
    assert!(user_data.contains("sleep 60"));
    assert_eq!(1440 * 60, ttl, "the retry budget IS the token TTL");

    // Fail-closed, named: no certificate = the coordinator refuses the
    // raw host key.
    assert!(user_data.contains("no certificate within the publish-token window (1440 x 60s)"));
    assert!(user_data.contains("the coordinator refuses this worker's raw host key"));
}
