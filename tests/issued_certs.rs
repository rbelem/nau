//! Host-certificate issuance + pickup (#295 sub-task 3) end to end
//! through the real binary with the REAL `ssh-keygen`: a ceremony-minted
//! CA signs a SHORT-LIVED host certificate for a pending identity —
//! principals binding the machine identity plus the provider
//! instance-identity content (ADR-0045 Decision 3) — the identity moves
//! pending → issued (audit trail), and the guest picks the certificate
//! up under its one-time publish token. Every signed certificate is
//! verified with `ssh-keygen -L`: the principal list, the validity
//! window, and the signing CA fingerprint must all be what the flow
//! claimed. Every path runs under an isolated `--home`/HOME — the
//! operator's real CA is never touched.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const IDENTITY: &str = "nau-worker-itest-01";

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_in(dir: &Path, args: &[&str]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_nau"))
        .args(args)
        .env("HOME", dir)
        .current_dir(dir)
        .output()
        .expect("failed to spawn nau");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Run nau with stdin piped (the receive-publish payload) and the
/// publish bearer in the environment (the transport front's contract).
fn run_in_with_stdin(dir: &Path, args: &[&str], stdin: &[u8], token: &str) -> Run {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nau"))
        .args(args)
        .env("HOME", dir)
        .env("NAU_PUBLISH_TOKEN", token)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn nau");
    child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(stdin)
        .expect("payload written");
    let out = child.wait_with_output().expect("nau waited");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn json_out(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("--json report must parse ({e}): {stdout}"))
}

/// A REAL guest host key: minted by the real ssh-keygen, the .pub line
/// the guest would publish. (The coordinator signs whatever public half
/// was published; a fabricated line would prove nothing here.)
fn real_guest_pub_line(dir: &Path) -> String {
    let path = dir.join("guest_host_key");
    let out = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "itest-guest-host-key",
            "-f",
            path.to_str().unwrap(),
        ])
        .output()
        .expect("real ssh-keygen must be available (openssh)");
    assert!(
        out.status.success(),
        "ssh-keygen mint failed: {}",
        out.status
    );
    std::fs::read_to_string(path.with_extension("pub"))
        .expect("guest .pub")
        .trim()
        .to_string()
}

fn instance_identity() -> serde_json::Value {
    serde_json::json!({
        "v1": {
            "instance_id": "i-0itest",
            "cloud_name": "hetzner",
            "region": "hel1",
            "availability_zone": "hel1-dc2",
            "hostname": "host-alias-77",
            "local_hostname": "host-alias-77.internal",
        }
    })
}

/// The real intake flow: mint + record a token (library — provision
/// does this mid-create), then push the payload through the REAL
/// `workers receive-publish` verb (stdin + bearer env).
fn enroll_and_publish_via_binary(dir: &Path, identity: &str, guest_pub: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = nau::provision::publish::mint_publish_token().unwrap();
    nau::provision::publish::record_issue(dir, &token, identity, now).unwrap();
    let payload = serde_json::json!({
        "machine_identity": identity,
        "public_key": guest_pub,
        "instance_identity": instance_identity(),
    })
    .to_string();
    let run = run_in_with_stdin(dir, &["pool", "publish"], payload.as_bytes(), &token);
    assert_eq!(run.code, Some(0), "receive-publish: {}", run.stderr);
    assert!(
        run.stderr.contains("pending identity"),
        "intake names the stored identity: {}",
        run.stderr
    );
    token
}

#[test]
fn issue_and_pickup_round_trip_through_the_real_binary() {
    let dir = tempfile::tempdir().unwrap();
    let home = format!("--home={}", dir.path().display());
    let ca_dir = dir.path().join(".config/nau/ca");

    // ── the ceremony: a real CA keypair ──
    let run = run_in(dir.path(), &["trust", "keygen", "--ca", &home, "--json"]);
    assert_eq!(run.code, Some(0), "ca keygen: {}", run.stderr);
    let ca_fingerprint = json_out(&run.stdout)["fingerprint"]
        .as_str()
        .unwrap()
        .to_string();

    let guest_pub = real_guest_pub_line(dir.path());
    let token = enroll_and_publish_via_binary(dir.path(), IDENTITY, &guest_pub);

    // ── issuance through the real binary, REAL ssh-keygen -s ──
    let run = run_in(dir.path(), &["pool", "issue", &home, "--json"]);
    assert_eq!(run.code, Some(0), "issue: {}", run.stderr);
    let report = json_out(&run.stdout);
    let issued = &report["issued"];
    assert_eq!(
        issued.as_array().map(Vec::len),
        Some(1),
        "one pending identity, one certificate: {report}"
    );
    assert_eq!(issued[0]["machine_identity"], serde_json::json!(IDENTITY));
    let principals: Vec<&str> = issued[0]["principals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert_eq!(
        principals,
        vec![IDENTITY, "i-0itest", "hetzner", "hel1", "hel1-dc2"],
        "machine identity first, then Decision 3 content — addresses excluded"
    );
    assert_eq!(issued[0]["validity"], serde_json::json!("+48h"));
    assert_eq!(
        issued[0]["ca_fingerprint"],
        serde_json::json!(ca_fingerprint)
    );

    // The identity left the pending store into the issued record.
    assert!(
        !ca_dir
            .join("pending")
            .join(format!("pending-{IDENTITY}.json"))
            .exists(),
        "pending entry gone"
    );
    let record_path = ca_dir
        .join("issued")
        .join(format!("issued-{IDENTITY}.json"));
    assert!(
        record_path.exists(),
        "issued record (audit trail) at {record_path:?}"
    );
    let record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&record_path).unwrap()).unwrap();
    assert_eq!(record["public_key"], serde_json::json!(guest_pub));
    assert_eq!(
        record["token_sha256"],
        serde_json::json!(nau::oci::sha256_hex(token.as_bytes())),
        "the record ties back to the publish token (hashed at rest)"
    );
    assert!(
        record["cert"]
            .as_str()
            .unwrap()
            .starts_with("ssh-ed25519-cert-v01"),
        "the record carries the certificate: {}",
        record["cert"]
    );

    // ── pickup through the real binary: same bearer, cert on stdout ──
    let run = run_in_with_stdin(dir.path(), &["pool", "pickup", &home], b"", &token);
    assert_eq!(run.code, Some(0), "pickup: {}", run.stderr);
    let cert = run.stdout.trim().to_string();
    assert!(
        cert.starts_with("ssh-ed25519-cert-v01"),
        "the certificate is the stdout artifact: {cert}"
    );

    // Idempotent: the guest polls; every GET serves the same cert.
    let again = run_in_with_stdin(dir.path(), &["pool", "pickup", &home], b"", &token);
    assert_eq!(again.code, Some(0));
    assert_eq!(again.stdout.trim(), cert);

    // A wrong bearer never serves anything.
    let run = run_in_with_stdin(dir.path(), &["pool", "pickup", &home], b"", &"f".repeat(64));
    assert_ne!(run.code, Some(0), "unknown token must refuse");
    assert!(run.stderr.contains("unknown publish token"));

    // ── THE PROOF: the real `ssh-keygen -L` reads the certificate back ──
    let cert_path = dir.path().join("host-cert.pub");
    std::fs::write(&cert_path, format!("{cert}\n")).unwrap();
    let out = Command::new("ssh-keygen")
        .args(["-L", "-f", cert_path.to_str().unwrap()])
        .output()
        .expect("real ssh-keygen -L");
    assert!(out.status.success(), "ssh-keygen -L failed on our cert");
    let listing = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        listing.contains("ssh-ed25519-cert-v01") && listing.contains("host certificate"),
        "it IS a host certificate: {listing}"
    );
    assert!(
        listing.contains(&format!("Key ID: \"{IDENTITY}\"")),
        "Key ID binds the machine identity: {listing}"
    );
    for principal in [IDENTITY, "i-0itest", "hetzner", "hel1", "hel1-dc2"] {
        assert!(
            listing.contains(principal),
            "principal '{principal}' bound: {listing}"
        );
    }
    assert!(
        !listing.contains("host-alias-77"),
        "addresses are not identity — hostname must not be a principal: {listing}"
    );
    assert!(
        listing.contains("Valid: from") && !listing.contains("forever"),
        "short-lived window, not forever: {listing}"
    );
    assert!(
        listing.contains(&format!("Signing CA: ED25519 {ca_fingerprint}")),
        "the ceremony CA signed it: {listing}"
    );
}

#[test]
fn pickup_before_issue_refuses_then_serves_after_issue() {
    let dir = tempfile::tempdir().unwrap();
    let home = format!("--home={}", dir.path().display());
    let run = run_in(dir.path(), &["trust", "keygen", "--ca", &home, "--json"]);
    assert_eq!(run.code, Some(0), "ca keygen: {}", run.stderr);

    let guest_pub = real_guest_pub_line(dir.path());
    let token = enroll_and_publish_via_binary(dir.path(), IDENTITY, &guest_pub);

    // Not yet signed → the retryable refusal (nonzero; the guest retries).
    let run = run_in_with_stdin(dir.path(), &["pool", "pickup", &home], b"", &token);
    assert_ne!(run.code, Some(0), "pre-issuance pickup must refuse");
    assert!(
        run.stderr.contains("no issued certificate yet"),
        "names the gap: {}",
        run.stderr
    );

    let run = run_in(dir.path(), &["pool", "issue", &home, "--json"]);
    assert_eq!(run.code, Some(0), "issue: {}", run.stderr);

    let run = run_in_with_stdin(dir.path(), &["pool", "pickup", &home], b"", &token);
    assert_eq!(run.code, Some(0), "post-issuance pickup: {}", run.stderr);
    assert!(run.stdout.contains("ssh-ed25519-cert-v01"));
}

#[test]
fn issue_refusals_name_the_gap() {
    let dir = tempfile::tempdir().unwrap();
    let home = format!("--home={}", dir.path().display());
    let guest_pub = real_guest_pub_line(dir.path());
    let token = enroll_and_publish_via_binary(dir.path(), IDENTITY, &guest_pub);
    let _ = token;

    // (a) No CA — the refusal names the ceremony verb. miette wraps long
    // refusals at width-dependent points and paints `│` gutters on
    // continuation lines; strip the gutters and flatten whitespace so
    // phrase matches survive any wrap position.
    let run = run_in(dir.path(), &["pool", "issue", &home]);
    assert_ne!(run.code, Some(0), "issue without a CA must refuse");
    let flat = |s: &str| {
        s.replace('│', " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    assert!(flat(&run.stderr).contains("no host CA"), "{}", run.stderr);
    assert!(flat(&run.stderr).contains("ca keygen"), "{}", run.stderr);

    // (b) Unknown identity.
    let run = run_in(dir.path(), &["trust", "keygen", "--ca", &home]);
    assert_eq!(run.code, Some(0), "ca keygen: {}", run.stderr);
    let run = run_in(
        dir.path(),
        &["pool", "issue", &home, "--identity", "nau-worker-nope"],
    );
    assert_ne!(run.code, Some(0));
    assert!(
        flat(&run.stderr).contains("no pending identity named 'nau-worker-nope'"),
        "{}",
        run.stderr
    );

    // (c) Already issued → named refusal unless --force.
    let run = run_in(dir.path(), &["pool", "issue", &home, "--json"]);
    assert_eq!(run.code, Some(0), "first issue: {}", run.stderr);
    let run = run_in(
        dir.path(),
        &["pool", "issue", &home, "--identity", IDENTITY],
    );
    assert_ne!(run.code, Some(0));
    assert!(
        flat(&run.stderr).contains("already issued"),
        "{}",
        run.stderr
    );
    assert!(flat(&run.stderr).contains("--force"), "{}", run.stderr);
    let run = run_in(
        dir.path(),
        &[
            "pool",
            "issue",
            &home,
            "--identity",
            IDENTITY,
            "--force",
            "--json",
        ],
    );
    assert_eq!(run.code, Some(0), "forced re-issue: {}", run.stderr);

    // (d) A forever window is refused — certificates must age out
    // (ADR-0045 amendment).
    let run = run_in(
        dir.path(),
        &[
            "pool",
            "issue",
            &home,
            "--identity",
            IDENTITY,
            "--force",
            "--validity",
            "forever",
        ],
    );
    assert_ne!(run.code, Some(0));
    assert!(
        run.stderr.contains("short-lived"),
        "names the posture: {}",
        run.stderr
    );
}

/// The executor side of the CA form (#295 sub-task 4), driven by the
/// REAL `ssh-keygen`: the pinned fingerprint ↔ the presented certificate's
/// Signing CA are the same identity, the executor resolves it through the
/// real `ssh-keygen -lf`, the machine linkage binds the pinned address to
/// the certificate principal, and the managed known_hosts becomes ONE
/// `@cert-authority` line whose pattern is the issued principals
/// (machine identity first) while ssh connects under `HostKeyAlias=<machine
/// identity>`. The worker channel is a scripted fake — what this proves
/// is the known_hosts/ssh-keygen layer; a live sshd handshake (the guest
/// serving the cert, principal matching against the real connection
/// name) is the QEMU/live-run axis.
#[test]
fn ca_form_executor_pins_the_signing_ca_through_the_real_keygen() {
    use std::io;
    use std::sync::{Arc, Mutex};

    use nau::command::{CommandRunner, RunnerOutput};
    use nau::lua::WorkerConfig;
    use nau::ssh_exec::{PreflightChecks, SshExecutor};

    /// Answers the coordinator's channel without a network: `ssh` gets a
    /// happy capability document, `ssh-keygen -lf` runs the REAL binary,
    /// everything else is a bug.
    struct CapWorker {
        calls: Arc<Mutex<Vec<Vec<String>>>>,
    }
    impl CommandRunner for CapWorker {
        fn run(&self, argv: &[String]) -> io::Result<RunnerOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            match argv[0].as_str() {
                "ssh" => Ok(RunnerOutput {
                    code: 0,
                    stdout: serde_json::to_vec(&serde_json::json!({
                        "protocol": nau::worker::WORKER_PROTOCOL_VERSION,
                        "arch": "x86_64",
                        "nproc": 4,
                        "ram_bytes": 8_000_000_000u64,
                        "free_disk_bytes": 1024u64.pow(4),
                        "bwrap": true,
                        "mksquashfs": true,
                        "kvm": false,
                        "sandbox": true,
                        "mksquashfs_version": nau::provision::SQUASHFS_TOOLS_VERSION,
                    }))
                    .unwrap(),
                    stderr: String::new(),
                }),
                "ssh-keygen" => Command::new("ssh-keygen")
                    .args(argv[1..].iter().map(String::as_str))
                    .output()
                    .map(|out| RunnerOutput {
                        code: out.status.code().unwrap_or(1),
                        stdout: out.stdout,
                        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                    })
                    .map_err(|e| io::Error::other(e.to_string())),
                other => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("ca-form harness: unexpected program {other}"),
                )),
            }
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let home = format!("--home={}", dir.path().display());
    let ceremony = dir.path();

    // ── the ceremony mints a REAL CA; the fingerprint is the pin ──
    let run = run_in(dir.path(), &["trust", "keygen", "--ca", &home, "--json"]);
    assert_eq!(run.code, Some(0), "keygen: {}", run.stderr);
    let fingerprint = json_out(&run.stdout)["fingerprint"]
        .as_str()
        .expect("fingerprint in the --json report")
        .to_string();
    assert!(fingerprint.starts_with("SHA256:"), "{fingerprint}");

    // ── enroll + publish + issue through the real verbs ──
    let guest = real_guest_pub_line(dir.path());
    enroll_and_publish_via_binary(dir.path(), IDENTITY, &guest);
    let run = run_in(dir.path(), &["pool", "issue", &home, "--json"]);
    assert_eq!(run.code, Some(0), "issue: {}", run.stderr);

    // ── the issued record: the audit trail the executor consumes ──
    let record_text = std::fs::read_to_string(
        ceremony
            .join(".config/nau/ca/issued")
            .join(format!("issued-{IDENTITY}.json")),
    )
    .expect("issued record");
    let record: nau::provision::publish::IssuedIdentity =
        serde_json::from_str(&record_text).unwrap();
    assert_eq!(record.ca_fingerprint, fingerprint);
    assert_eq!(record.principals[0], IDENTITY, "machine identity first");

    // ── the provision-time machine linkage: address → identity ──
    let address = "ssh://root@203.0.113.9";
    nau::provision::publish::record_machine_link(ceremony, IDENTITY, address).unwrap();

    // ── the executor resolves the pin through the REAL ssh-keygen ──
    let worker = WorkerConfig {
        address: address.to_string(),
        jobs: 1,
        arch: None,
        host_key: Some(fingerprint.clone()),
        identity: None,
    };
    let fake = CapWorker {
        calls: Arc::new(Mutex::new(Vec::new())),
    };
    let calls = fake.calls.clone();
    let cache = tempfile::tempdir().unwrap();
    let ex = SshExecutor::with_ceremony_home(&worker, fake, cache.path(), ceremony)
        .expect("executor builds");
    ex.preflight(PreflightChecks {
        arch: None,
        min_free_disk: 0,
    })
    .expect("the CA pin enforces through the real ssh-keygen");

    // ONE @cert-authority line; the pattern is the certificate's
    // principal list, machine identity first; the key half is the
    // ceremony CA whose REAL fingerprint equals the pin.
    let pinned = std::fs::read_to_string(ex.known_hosts_path()).unwrap();
    let ca_pub_line =
        std::fs::read_to_string(ceremony.join(".config/nau/ca/ca.pub")).expect("ca.pub");
    let key_half = ca_pub_line
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(
        pinned,
        format!("@cert-authority {} {key_half}", record.principals.join(",")),
        "the pinned fingerprint ↔ the cert's Signing CA are one identity"
    );

    // The connection runs under the machine identity.
    let ssh_argv = calls
        .lock()
        .unwrap()
        .iter()
        .find(|argv| argv[0] == "ssh")
        .expect("probed")
        .clone();
    assert!(ssh_argv.contains(&format!("HostKeyAlias={IDENTITY}")));
    assert!(ssh_argv.contains(&"StrictHostKeyChecking=yes".to_string()));
}
