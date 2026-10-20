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
mod tests;
