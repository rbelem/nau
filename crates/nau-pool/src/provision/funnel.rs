//! The worker funnel lifecycle (ADR-0055 Decision 1, #350): the
//! tailscale funnel that fronts the coordinator's publish/pickup channel
//! is stood up by `pool provision` and torn down by the destroy paths —
//! never a persistent manual task.
//!
//! The funnel runs on the host nau runs on (the front's host), NOT on
//! the cloud workers: workers get no tailscale (the cloud-init template
//! installs none — they are plain guests that publish over HTTPS), and
//! the funnel exists precisely so they can reach the front WITHOUT
//! being on the tailnet (nau-ops-runbook §1.6: front on
//! `127.0.0.1:8477`, exposed ONLY via `tailscale funnel` on 8443).
//!
//! Port contract (the AllowFunnel granularity is host-wide per
//! host:port on this tailscale): the public front rides **8443** and
//! 443 stays free for tailnet-only services — the split that lived in
//! session prose is now product behavior. Nau owns ONLY the 8443
//! funnel: `funnel_down` reads the serve config for that one port and
//! never touches a 443 entry.
//!
//! Ownership rule: nau manages the funnel only when the publish URL
//! points at THIS machine's tailnet DNS name on 8443. Any other
//! publish endpoint (a foreign front host, a non-tailscale URL) is not
//! nau's funnel — provisioning skips funnel management entirely rather
//! than touching state it does not own. When it does own it, every
//! real provision re-asserts the funnel (idempotent — the same serve
//! spec replaces itself in tailscaled) and then PREFLIGHTS public
//! reachability BEFORE any cloud API call: a dead channel kills every
//! guest publish/pickup, so a window behind one must never spend.

use std::path::Path;
use std::time::Duration;

use nau_infra::command::{exit_code, CommandRunner};

/// The public front port the funnel serves (ADR-0055 Decision 3).
/// AllowFunnel is host-wide per host:port on this tailscale, so 443
/// stays free for tailnet-only services — this port is the ONLY one nau
/// ever stands up or tears down.
pub const FUNNEL_PUBLIC_PORT: u16 = 8443;

/// The front's local bind port the funnel forwards to (nau-ops-runbook
/// §1.6: the publish front answers on `127.0.0.1:8477`). Until #351's
/// `pool front` verb owns the front itself, the operator's shim binds
/// this port; the funnel forwards to it either way.
pub const FUNNEL_FRONT_PORT: u16 = 8477;

/// The funnel preflight's retry budget. First-ever funnel use makes
/// tailscale provision a certificate before the port answers; a
/// re-asserted funnel answers at once. 10 × 3s ≈ 30s covers the cold
/// case without hanging the operator's shell — the same boot-scale
/// shape as the publish script's budget (#308).
pub const FUNNEL_PREFLIGHT_TRIES: usize = 10;
pub const FUNNEL_PREFLIGHT_SLEEP: Duration = Duration::from_secs(3);

/// The public funnel URL for a tailnet DNS name: the exact address the
/// guests' publish/pickup/binary URLs ride (`NAU_PUBLISH_URL` etc.).
pub fn funnel_public_url(dns_name: &str) -> String {
    format!("https://{dns_name}:{FUNNEL_PUBLIC_PORT}")
}

/// The `host[:port]` of an http(s) URL — the only URL grammar the
/// publish channel validates for (`validate_publish_url`), so the parse
/// stays as small as the producer.
fn url_authority(url: &str) -> Option<&str> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    (!authority.is_empty()).then_some(authority)
}

fn authority_host(authority: &str) -> &str {
    authority.split(':').next().unwrap_or(authority)
}

fn authority_port(authority: &str) -> u16 {
    // `https` without an explicit port means 443; anything else is
    // explicit in the authority.
    match authority.rsplit_once(':') {
        Some((_, p)) => p.parse().unwrap_or(0),
        None => 443,
    }
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// The tailnet DNS name of the machine nau runs on: `tailscale status
/// --json` → `.Self.DNSName`, trailing dot trimmed (tailscale reports
/// `host.tailnet.ts.net.`).
pub fn tailnet_dns_name(runner: &dyn CommandRunner) -> miette::Result<String> {
    let argv: Vec<String> = vec!["tailscale".into(), "status".into(), "--json".into()];
    let out = runner.run(&argv).map_err(|e| {
        miette::miette!("funnel: cannot run the tailscale CLI (is it installed and on PATH?): {e}")
    })?;
    if exit_code(&out) != 0 {
        return Err(miette::miette!(
            "funnel: tailscale status failed: {}",
            out.stderr.trim()
        ));
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| miette::miette!("funnel: tailscale status is not JSON: {e}"))?;
    let dns = v["Self"]["DNSName"]
        .as_str()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_string();
    if dns.is_empty() {
        return Err(miette::miette!(
            "funnel: tailscale reports no DNS name for this node — the funnel needs the \
             tailnet DNS name (MagicDNS)"
        ));
    }
    Ok(dns)
}

/// Stand the funnel up for a provision/burst window whose publish
/// endpoint may be funnel-fronted, then preflight public reachability —
/// BOTH strictly before any cloud API call.
///
/// Returns the public funnel URL when nau owns the channel (the
/// publish URL names this machine's tailnet DNS name on
/// [`FUNNEL_PUBLIC_PORT`]), `None` when it does not (a foreign or
/// non-tailscale front — funnel management is skipped, never guessed).
/// A same-host publish URL naming any other port is a REFUSAL, not a
/// skip: it asks for this funnel on a port the port contract forbids.
pub fn funnel_window_up(
    runner: &dyn CommandRunner,
    publish_url: &str,
    tries: usize,
    sleep: Duration,
) -> miette::Result<Option<String>> {
    let Some(authority) = url_authority(publish_url) else {
        return Ok(None);
    };
    let host = normalize_host(authority_host(authority));
    if !host.ends_with(".ts.net") {
        // Not a tailscale front at all — nothing here is nau's to own.
        return Ok(None);
    }
    let dns = normalize_host(&tailnet_dns_name(runner)?);
    if host != dns {
        nau_infra::output::info(format!(
            "publish front {host} is another host's funnel — nau owns only this node's; \
             leaving the funnel untouched"
        ));
        return Ok(None);
    }
    let port = authority_port(authority);
    if port != FUNNEL_PUBLIC_PORT {
        return Err(miette::miette!(
            "the publish URL rides :{port} but the public front port is \
             {FUNNEL_PUBLIC_PORT} — AllowFunnel is host-wide per host:port, and 443 must \
             stay free for tailnet-only services (ADR-0055); point NAU_PUBLISH_URL at \
             https://{host}:{FUNNEL_PUBLIC_PORT}/..."
        ));
    }
    let url = funnel_up(runner)?;
    funnel_preflight(runner, &url, tries, sleep)?;
    nau_infra::output::ok(format!(
        "funnel up: {url} → 127.0.0.1:{FUNNEL_FRONT_PORT} (public front; 443 stays \
         tailnet-only)"
    ));
    Ok(Some(url))
}

/// Re-assert the funnel: `tailscale funnel --bg` installs the serve
/// spec into tailscaled, where it survives this CLI process — the
/// backgrounded shape, so provision returns while the funnel runs.
/// Idempotent by construction: the same serve spec replaces itself, so
/// re-running provision never duplicates or conflicts. Returns the
/// public URL.
pub fn funnel_up(runner: &dyn CommandRunner) -> miette::Result<String> {
    let dns = tailnet_dns_name(runner)?;
    let argv: Vec<String> = vec![
        "tailscale".into(),
        "funnel".into(),
        "--bg".into(),
        format!("--https={FUNNEL_PUBLIC_PORT}"),
        format!("127.0.0.1:{FUNNEL_FRONT_PORT}"),
    ];
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("funnel: cannot run the tailscale CLI: {e}"))?;
    if exit_code(&out) != 0 {
        return Err(miette::miette!(
            "funnel: tailscale funnel --https={FUNNEL_PUBLIC_PORT} failed: {} — is \
             tailscaled running, and is funnel enabled for this node?",
            out.stderr.trim()
        ));
    }
    Ok(funnel_public_url(&dns))
}

/// The preflight: prove the funnel actually serves before any API
/// spend — the ticket's dead-funnel-before-spend gate. Any HTTP status
/// under 500 proves the channel (the front 404s unknown paths by
/// design); 5xx means the funnel edge is up but the front behind it is
/// dead; transport errors mean the funnel itself is dead. Both die
/// here, named, instead of at the first guest publish after the
/// servers are already billing.
pub fn funnel_preflight(
    runner: &dyn CommandRunner,
    url: &str,
    tries: usize,
    sleep: Duration,
) -> miette::Result<()> {
    let argv: Vec<String> = vec![
        "curl".into(),
        "-sS".into(),
        "-o".into(),
        "/dev/null".into(),
        "-w".into(),
        "%{http_code}".into(),
        "--connect-timeout".into(),
        "10".into(),
        "--max-time".into(),
        "15".into(),
        url.into(),
    ];
    let mut last = String::from("no attempt");
    for i in 0..tries {
        let out = runner.run(&argv).map_err(|e| {
            miette::miette!("funnel preflight: cannot run curl (is it installed?): {e}")
        })?;
        if exit_code(&out) == 0 {
            let status: u16 = String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse()
                .unwrap_or(0);
            if (1..500).contains(&status) {
                return Ok(());
            }
            last = format!("HTTP {status} (funnel edge up, front behind it dead)");
        } else {
            last = format!("curl exit {}", exit_code(&out));
        }
        if i + 1 < tries {
            std::thread::sleep(sleep);
        }
    }
    Err(miette::miette!(
        "the funnel {url} does not serve ({last}) after {tries} tries — a dead channel \
         kills every guest publish and pickup, so no server is created; start the front \
         on 127.0.0.1:{FUNNEL_FRONT_PORT} (nau-ops-runbook §1.6) or clear a stale funnel \
         by hand: tailscale funnel --https={FUNNEL_PUBLIC_PORT} off"
    ))
}

/// True when the serve config currently exposes [`FUNNEL_PUBLIC_PORT`]
/// as a funnel: any `TCP["8443"]` entry, or any `Web` handler keyed
/// `<host>:8443`. Any ambiguity (CLI absent, tailscaled down, status
/// failing, unparseable JSON) reads as NOT served — the funnel is
/// tailscaled state, so a host that cannot answer `tailscale status`
/// is not serving one. Down then skips instead of running an `off` that
/// would fail; the parse is also fail-safe in the other direction: a
/// text-format drift that hides a live funnel only skips a redundant
/// `off`.
fn funnel_served(runner: &dyn CommandRunner) -> miette::Result<bool> {
    let argv: Vec<String> = vec![
        "tailscale".into(),
        "funnel".into(),
        "status".into(),
        "--json".into(),
    ];
    let Ok(out) = runner.run(&argv) else {
        return Ok(false);
    };
    if exit_code(&out) != 0 {
        return Ok(false);
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
        return Ok(false);
    };
    let port_key = FUNNEL_PUBLIC_PORT.to_string();
    if v["TCP"]
        .as_object()
        .is_some_and(|tcp| tcp.contains_key(&port_key))
    {
        return Ok(true);
    }
    Ok(v["Web"].as_object().is_some_and(|web| {
        web.keys()
            .any(|k| k.rsplit_once(':').is_some_and(|(_, p)| p == port_key))
    }))
}

/// Tear the funnel down: port-scoped `off`, gated on the serve config
/// actually exposing the port. The gate is what makes this idempotent —
/// `tailscale funnel --https=8443 off` exits 1 ("handler does not
/// exist") when nothing is served, and must never be aimed at a 443
/// tailnet-only entry (AllowFunnel is host-wide per host:port; nau owns
/// 8443 only).
pub fn funnel_down(runner: &dyn CommandRunner) -> miette::Result<()> {
    if !funnel_served(runner)? {
        return Ok(());
    }
    let argv: Vec<String> = vec![
        "tailscale".into(),
        "funnel".into(),
        format!("--https={FUNNEL_PUBLIC_PORT}"),
        "off".into(),
    ];
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("funnel: cannot run the tailscale CLI: {e}"))?;
    if exit_code(&out) != 0 {
        return Err(miette::miette!(
            "funnel teardown failed: {} — funnel residue remains on port \
             {FUNNEL_PUBLIC_PORT}; clear it by hand: tailscale funnel \
             --https={FUNNEL_PUBLIC_PORT} off",
            out.stderr.trim()
        ));
    }
    nau_infra::output::ok(format!(
        "funnel down: port {FUNNEL_PUBLIC_PORT} closed — no residue (443 tailnet-only \
         services untouched)"
    ));
    Ok(())
}

/// The destroy-path seam: tear the funnel down ONLY when the managed
/// workers block just drained. The funnel fronts every worker's
/// publish/pickup channel host-wide, so a mid-window destroy of one of
/// several workers must leave it up; the last destroy (or a full
/// `down --all-managed` drain, or a burst teardown) closes it. Idempotent
/// both ways: an already-empty block with no funnel served is a no-op.
pub fn funnel_down_drained(runner: &dyn CommandRunner, config: &Path) -> miette::Result<()> {
    if !super::managed_entries(config)?.is_empty() {
        // Workers still pinned — their channel stays up.
        return Ok(());
    }
    funnel_down(runner)
}

/// The verb-path wrapper: the real runner.
pub fn funnel_down_if_drained(config: &Path) -> miette::Result<()> {
    funnel_down_drained(&nau_infra::command::RealRunner, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nau_infra::command::RunnerOutput;
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// A runner that fails the test the moment anything is executed —
    /// proves the skip paths never shell out.
    struct NeverRunner;

    impl CommandRunner for NeverRunner {
        fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
            panic!("no subprocess expected, got {argv:?}");
        }
    }

    /// Routes on argv[1] (`status` / `funnel`) or argv[0] (`curl`),
    /// the exact surface the funnel steps drive.
    struct FakeTailscale {
        /// The `tailscale status --json` document (the DNS name source).
        status_json: &'static str,
        /// Exit code + stderr for `tailscale funnel ...` calls.
        funnel_code: i32,
        funnel_stderr: &'static str,
        /// Exit code + stdout for `curl` calls (the -w status line).
        curl_code: i32,
        curl_status_line: &'static str,
        calls: Mutex<Vec<String>>,
    }

    impl FakeTailscale {
        fn new(status_json: &'static str) -> Self {
            FakeTailscale {
                status_json,
                funnel_code: 0,
                funnel_stderr: "",
                curl_code: 0,
                curl_status_line: "200",
                calls: Mutex::new(Vec::new()),
            }
        }

        fn with_curl(mut self, code: i32, status_line: &'static str) -> Self {
            self.curl_code = code;
            self.curl_status_line = status_line;
            self
        }

        fn with_funnel(mut self, code: i32, stderr: &'static str) -> Self {
            self.funnel_code = code;
            self.funnel_stderr = stderr;
            self
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn summary(&self) -> String {
            self.calls().join(" | ")
        }
    }

    impl CommandRunner for FakeTailscale {
        fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
            self.calls.lock().unwrap().push(argv.join(" "));
            match argv[0].as_str() {
                "tailscale" => {
                    match (argv[1].as_str(), argv.get(2).map(|s| s.as_str())) {
                        // `tailscale status --json` (DNS name) and
                        // `tailscale funnel status --json` (the serve
                        // config — the live CLI shows the merged view)
                        // both read the status document.
                        ("status", _) | ("funnel", Some("status")) => Ok(RunnerOutput {
                            code: 0,
                            stdout: self.status_json.as_bytes().to_vec(),
                            stderr: String::new(),
                        }),
                        ("funnel", _) => Ok(RunnerOutput {
                            code: self.funnel_code,
                            stdout: Vec::new(),
                            stderr: self.funnel_stderr.to_string(),
                        }),
                        other => panic!("unexpected tailscale subcommand {other:?}"),
                    }
                }
                "curl" => Ok(RunnerOutput {
                    code: self.curl_code,
                    stdout: self.curl_status_line.as_bytes().to_vec(),
                    stderr: String::new(),
                }),
                other => panic!("unexpected program {other}"),
            }
        }
    }

    /// This host's shape: DNSName carries a trailing dot, as tailscale
    /// reports it.
    const STATUS_JSON: &str = r#"{"Self":{"DNSName":"book3.tail9e1045.ts.net.","Online":true}}"#;

    /// A serve config holding ONLY a 443 tailnet-only entry — the port
    /// the funnel code must never touch.
    const STATUS_443_SERVE_JSON: &str = r#"{"TCP":{"443":{"HTTPS":true}},"Web":{"book3.tail9e1045.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:9119"}}}}}"#;

    /// The funnel config nau owns: 8443 fronting the front port.
    const STATUS_8443_FUNNEL_JSON: &str = r#"{"TCP":{"8443":{"HTTPS":true,"Funnel":true}},"Web":{"book3.tail9e1045.ts.net:8443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:8477"}}}}}"#;

    const PUBLISH_URL: &str = "https://book3.tail9e1045.ts.net:8443/publish";

    #[test]
    fn window_up_stands_the_funnel_and_preflights_in_order() {
        let fake = FakeTailscale::new(STATUS_JSON).with_curl(0, "404");
        let url = funnel_window_up(&fake, PUBLISH_URL, 1, Duration::ZERO)
            .expect("a funnel-fronted window stands up")
            .expect("this publish URL is this node's funnel");
        assert_eq!(url, "https://book3.tail9e1045.ts.net:8443");
        let calls = fake.summary();
        assert!(
            calls.contains("tailscale status --json"),
            "resolves the DNS name first: {calls}"
        );
        assert!(
            calls.contains("tailscale funnel --bg --https=8443 127.0.0.1:8477"),
            "re-asserts the serve spec: {calls}"
        );
        assert!(
            calls.contains("curl"),
            "preflights before returning: {calls}"
        );
        // Status before funnel, funnel before curl.
        let s = calls.find("status --json").unwrap();
        let f = calls.find("funnel --bg").unwrap();
        let c = calls.find("curl").unwrap();
        assert!(s < f && f < c, "up → preflight order: {calls}");
    }

    #[test]
    fn window_up_skips_without_shelling_out_for_a_non_tailnet_front() {
        let skipped = funnel_window_up(
            &NeverRunner,
            "https://front.example.com:8443/publish",
            1,
            Duration::ZERO,
        )
        .expect("a non-tailscale front is skipped");
        assert!(skipped.is_none(), "nothing to own");
    }

    #[test]
    fn window_up_skips_a_foreign_ts_net_front_without_touching_the_local_funnel() {
        let fake = FakeTailscale::new(STATUS_JSON);
        let skipped = funnel_window_up(
            &fake,
            "https://other.tail9e1045.ts.net:8443/publish",
            1,
            Duration::ZERO,
        )
        .expect("resolution succeeds");
        assert!(skipped.is_none(), "a foreign funnel is not nau's");
        assert_eq!(
            fake.calls().len(),
            1,
            "only the DNS resolution ran, never an up: {:?}",
            fake.calls()
        );
    }

    #[test]
    fn window_up_refuses_a_same_host_publish_url_on_a_forbidden_port() {
        let fake = FakeTailscale::new(STATUS_JSON);
        let err = funnel_window_up(
            &fake,
            "https://book3.tail9e1045.ts.net:443/publish",
            1,
            Duration::ZERO,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("8443"), "names the public port: {err}");
        assert!(err.contains("443"), "names the forbidden port: {err}");
        assert!(
            !fake.summary().contains("funnel --bg"),
            "never stands anything up on a refused port: {:?}",
            fake.calls()
        );
    }

    #[test]
    fn funnel_up_failure_names_the_daemon_question() {
        let mut fake = FakeTailscale::new(STATUS_JSON);
        fake.funnel_code = 1;
        fake.funnel_stderr = "funnel requires MagicDNS";
        let err = funnel_up(&fake).unwrap_err().to_string();
        assert!(err.contains("tailscaled"), "{err}");
        assert!(err.contains("MagicDNS"), "carries the CLI stderr: {err}");
    }

    #[test]
    fn preflight_accepts_any_real_http_answer_including_the_shim_404() {
        let fake = FakeTailscale::new(STATUS_JSON).with_curl(0, "404");
        funnel_preflight(
            &fake,
            "https://book3.tail9e1045.ts.net:8443",
            1,
            Duration::ZERO,
        )
        .expect("a 404 proves the channel serves");
    }

    #[test]
    fn preflight_refuses_a_5xx_front_before_any_api_spend() {
        let fake = FakeTailscale::new(STATUS_JSON).with_curl(0, "502");
        let err = funnel_preflight(
            &fake,
            "https://book3.tail9e1045.ts.net:8443",
            1,
            Duration::ZERO,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("does not serve"), "{err}");
        assert!(err.contains("502"), "{err}");
        assert!(
            err.contains("127.0.0.1:8477"),
            "names the front port: {err}"
        );
    }

    #[test]
    fn preflight_refuses_a_dead_funnel_and_exhausts_its_budget_exactly() {
        let fake = FakeTailscale::new(STATUS_JSON).with_curl(7, "000");
        let err = funnel_preflight(
            &fake,
            "https://book3.tail9e1045.ts.net:8443",
            3,
            Duration::ZERO,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("curl exit 7"), "{err}");
        assert!(err.contains("after 3 tries"), "{err}");
        assert_eq!(
            fake.calls()
                .iter()
                .filter(|c| c.starts_with("curl"))
                .count(),
            3,
            "exactly the budget: {:?}",
            fake.calls()
        );
    }

    #[test]
    fn down_closes_only_8443_and_never_a_443_tailnet_entry() {
        // The host serves 443 tailnet-only → nothing funnel-owned → no
        // `off` call at all.
        let fake = FakeTailscale::new(STATUS_443_SERVE_JSON);
        funnel_down(&fake).expect("a 443-only host has no funnel residue");
        assert!(
            !fake.summary().contains("off"),
            "443 must stay tailnet-only: {:?}",
            fake.calls()
        );

        // The funnel nau owns → port-scoped off.
        let fake = FakeTailscale::new(STATUS_8443_FUNNEL_JSON);
        funnel_down(&fake).expect("the owned funnel closes");
        let calls = fake.summary();
        assert!(
            calls.contains("tailscale funnel --https=8443 off"),
            "port-scoped teardown: {calls}"
        );
        assert!(!calls.contains("--https=443"), "{calls}");
    }

    #[test]
    fn down_is_a_no_op_when_nothing_is_served() {
        let fake = FakeTailscale::new(r#"{}"#);
        funnel_down(&fake).expect("nothing served — no residue possible");
        assert!(
            !fake.summary().contains("off"),
            "the gate skips the non-idempotent off: {:?}",
            fake.calls()
        );
    }

    #[test]
    fn down_failure_names_the_hand_remedy() {
        let fake = FakeTailscale::new(STATUS_8443_FUNNEL_JSON).with_funnel(1, "permission denied");
        let err = funnel_down(&fake).unwrap_err().to_string();
        assert!(err.contains("residue"), "{err}");
        assert!(err.contains("tailscale funnel --https=8443 off"), "{err}");
    }

    #[test]
    fn down_reads_unspawnable_tailscale_as_nothing_served() {
        struct SpawnError;
        impl CommandRunner for SpawnError {
            fn run(&self, _: &[String]) -> std::io::Result<RunnerOutput> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no such file",
                ))
            }
        }
        funnel_down(&SpawnError).expect("a host that cannot answer status serves nothing");
    }

    fn write_config(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("nau.lua");
        std::fs::write(
            &path,
            format!(
                "-- operator stuff\n{begin}\nworkers = workers or {{}}\n{body}{end}\n",
                begin = super::super::BLOCK_BEGIN,
                body = body,
                end = super::super::BLOCK_END
            ),
        )
        .unwrap();
        path
    }

    const ENTRY_LINE: &str =
        "table.insert(workers, { address = \"ssh://root@1.2.3.4\", host_key = \"SHA256:abc\" })\n";

    #[test]
    fn down_if_drained_closes_the_funnel_only_when_the_block_emptied() {
        let dir = tempfile::tempdir().unwrap();

        // A worker still pinned → the channel stays up, tailscale is
        // never consulted.
        let config = write_config(dir.path(), ENTRY_LINE);
        funnel_down_drained(&NeverRunner, &config)
            .expect("workers remain — the funnel must stay up");

        // Drained → the funnel closes.
        let config = write_config(dir.path(), "");
        let fake = FakeTailscale::new(STATUS_8443_FUNNEL_JSON);
        funnel_down_drained(&fake, &config).expect("the drained window closes its funnel");
        assert!(
            fake.summary().contains("tailscale funnel --https=8443 off"),
            "{:?}",
            fake.calls()
        );
    }
}
