//! mDNS peer discovery (ADR-0033 Decisions 3+6): `shuttle serve`
//! announces the pod store as `_shuttle._tcp.local.` (the node name is
//! the instance name) and `shuttle peers` browses the LAN for
//! announcing nodes.
//!
//! Discovery is never trust (ADR-0033 Decisions 3+7): an mDNS response
//! is unauthenticated and raceable — it only yields `host:port` hints
//! for [`crate::pull_ref`]; every manifest stays fail-closed on pull.
//!
//! Announcing uses a TXT record `shuttle=1` to version the protocol
//! cheaply: browse accepts only instances whose value matches
//! [`PROTOCOL_VERSION`], so a future wire change can refuse stale peers
//! instead of guessing. Host selection prefers an IPv4 address within a
//! sighting, and repeat sightings upgrade the host toward the best
//! connectable address (global IPv4 > global IPv6 > loopback >
//! link-local v6) — mDNS resolves incrementally and early responses can
//! carry only a link-local address. IPv6 literals are bracketed (the
//! result is consumed as `host:port`).
//!
//! Dependency stance (ADR-0033 Decision 4): `mdns-sd` is the one
//! sanctioned new runtime crate — synchronous pure Rust, no async
//! runtime. Its transitive tree at 0.21.3 (`cargo tree -e normal -p
//! mdns-sd`): fastrand, flume (+ futures-core, futures-sink, spin →
//! lock_api → scopeguard), if-addrs, log, mio, socket-pktinfo,
//! socket2. Genuinely new units in `Cargo.lock`: mdns-sd, flume,
//! futures-sink, if-addrs, mio, socket-pktinfo, socket2 —
//! fastrand/futures-core/spin/lock_api/scopeguard/log were already
//! vendored via pgp/tempfile and libc only bumps. No tokio, no hyper,
//! no libp2p.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use mdns_sd::{Receiver, RecvTimeoutError, ScopedIp, ServiceDaemon, ServiceEvent, ServiceInfo};

/// The service type every shuttle node announces and browses for
/// (ADR-0033 Decision 3). The trailing dot is DNS-SD convention.
pub const SERVICE_TYPE: &str = "_shuttle._tcp.local.";

/// The fullname suffix that separates an instance name from
/// [`SERVICE_TYPE`] (`"<instance>._shuttle._tcp.local."`).
const SERVICE_TYPE_SUFFIX: &str = "._shuttle._tcp.local.";

/// The TXT key carrying the discovery protocol version.
pub const PROTOCOL_KEY: &str = "shuttle";

/// The discovery protocol version announced in the TXT record and
/// required from browsed peers — bump when the record's meaning changes
/// so old and new nodes refuse each other instead of guessing.
pub const PROTOCOL_VERSION: &str = "1";

/// How long [`AnnounceGuard::drop`] waits for the daemon to confirm the
/// goodbye (unregister) and wind down. Bounded so a stuck daemon cannot
/// hang serve shutdown; best-effort either way.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// One shuttle node found on the LAN. `name` is the mDNS instance name
/// (the announcing node's name); `host` is ready for `host:port` use
/// (IPv6 literals arrive bracketed); `port` is the peer's serve port.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DiscoveredPeer {
    pub name: String,
    pub host: String,
    pub port: u16,
}

/// Keeps one mDNS registration alive; dropping it unregisters the
/// service (goodbye packet) and shuts the daemon down. `shuttle serve`
/// holds it for the lifetime of the accept loop.
pub struct AnnounceGuard {
    daemon: ServiceDaemon,
    fullname: String,
}

/// Register `name` on the LAN as `<name>._shuttle._tcp.local.` on
/// `port`, with the `shuttle=1` version TXT. Addresses are published
/// automatically from the host's interfaces (`addr_auto`) — the caller
/// names and ports the service, the network layer owns the addresses.
///
/// The registration stays alive until the returned guard is dropped.
pub fn announce(name: &str, port: u16) -> miette::Result<AnnounceGuard> {
    if name.trim().is_empty() {
        miette::bail!("cannot announce a shuttle node without a name");
    }
    let daemon = ServiceDaemon::new().map_err(|e| miette::miette!("starting mDNS daemon: {e}"))?;
    // No static IP: with addr_auto the daemon fills in the host's
    // interface addresses at register time (mdns-sd contract for an
    // empty address set) and keeps them current as interfaces change.
    let props: HashMap<String, String> =
        [(PROTOCOL_KEY.to_string(), PROTOCOL_VERSION.to_string())].into();
    let service = ServiceInfo::new(
        SERVICE_TYPE,
        name,
        &format!("{name}.local."),
        "",
        port,
        props,
    )
    .map_err(|e| miette::miette!("announcing '{name}' as {SERVICE_TYPE}: {e}"))?
    .enable_addr_auto();
    daemon
        .register(service)
        .map_err(|e| miette::miette!("registering '{name}' on the LAN: {e}"))?;
    Ok(AnnounceGuard {
        daemon,
        fullname: format!("{name}.{SERVICE_TYPE}"),
    })
}

/// Drop the registration: a best-effort, bounded goodbye. Unregister
/// first (so LAN peers learn the service is gone), then stop the
/// daemon thread. Both steps tolerate a daemon that already left.
impl Drop for AnnounceGuard {
    fn drop(&mut self) {
        if let Ok(status) = self.daemon.unregister(&self.fullname) {
            let _ = status.recv_timeout(SHUTDOWN_GRACE);
        }
        if let Ok(status) = self.daemon.shutdown() {
            let _ = status.recv_timeout(SHUTDOWN_GRACE);
        }
    }
}

/// Browse the LAN for announcing shuttle nodes, stopping after
/// `timeout` (mDNS responses trickle in over ~1-2s; [`SERVICE_TYPE`]
/// queries repeat under the hood). One entry per instance name —
/// re-resolutions of the same node collapse, and each repeat refines
/// the host toward the best connectable address. Only peers whose TXT
/// carries `shuttle=[PROTOCOL_VERSION]` are returned (the cheap
/// protocol version gate).
pub fn browse(timeout: Duration) -> miette::Result<Vec<DiscoveredPeer>> {
    let daemon = ServiceDaemon::new().map_err(|e| miette::miette!("starting mDNS daemon: {e}"))?;
    let receiver: Receiver<ServiceEvent> = daemon
        .browse(SERVICE_TYPE)
        .map_err(|e| miette::miette!("browsing {SERVICE_TYPE}: {e}"))?;
    let deadline = Instant::now() + timeout;
    let mut peers: Vec<DiscoveredPeer> = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if let Some(peer) = peer_from_resolved(&info) {
                    upsert_unique(&mut peers, peer);
                }
            }
            Ok(_) => {} // SearchStarted/ServiceFound/ServiceRemoved/SearchStopped
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
        }
    }
    // Stop the query and the daemon thread; neither failure matters to
    // the caller — the results are already in hand.
    let _ = daemon.stop_browse(SERVICE_TYPE);
    let _ = daemon.shutdown();
    Ok(peers)
}

/// True when a TXT `shuttle` value matches the protocol version this
/// build speaks (absent = not a shuttle peer; wrong version = a peer
/// speaking a different discovery protocol — both are skipped).
fn protocol_version_matches(value: Option<&str>) -> bool {
    value == Some(PROTOCOL_VERSION)
}

/// The instance name of a resolved service: the fullname minus the
/// [`SERVICE_TYPE_SUFFIX`]. `None` for anything that is not our
/// service shape (defensive — the browse filter should never let one in).
fn instance_name(fullname: &str) -> Option<String> {
    fullname
        .strip_suffix(SERVICE_TYPE_SUFFIX)
        .map(|name| name.to_string())
}

/// Collapse re-resolutions of the same instance, refining the host as
/// sightings improve. mdns-sd resolves incrementally: an early
/// resolution may carry only a link-local v6 where a later one has the
/// LAN IPv4 — so a repeat sighting UPGRADES the host when its address
/// ranks better (see [`host_score`]), never downgrades it. Peers are
/// few and small, so the linear scan beats a set.
fn upsert_unique(peers: &mut Vec<DiscoveredPeer>, peer: DiscoveredPeer) {
    match peers.iter_mut().find(|p| p.name == peer.name) {
        Some(seen) => {
            if host_score(&peer.host) > host_score(&seen.host) {
                seen.host = peer.host;
            }
        }
        None => peers.push(peer),
    }
}

/// Connectability rank of a discovered host, highest wins: global IPv4
/// (the LAN case `shuttle://host:port/` needs) > global IPv6 > loopback
/// IPv4 (loopback is only ever sighted same-host, where it does work) >
/// link-local IPv6 (unscoped — unusable beyond the local link) > a
/// hostname (resolves only where mDNS resolution works).
fn host_score(host: &str) -> u8 {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            if v4.is_loopback() {
                2
            } else {
                4
            }
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            if v6.is_unicast_link_local() {
                1
            } else {
                3
            }
        }
        Err(_) => 0,
    }
}

/// A resolved instance → a peer record, or `None` when the version TXT
/// disqualifies it or the name is not our service shape.
fn peer_from_resolved(info: &mdns_sd::ResolvedService) -> Option<DiscoveredPeer> {
    if !protocol_version_matches(info.get_property_val_str(PROTOCOL_KEY)) {
        return None;
    }
    Some(DiscoveredPeer {
        name: instance_name(info.get_fullname())?,
        host: host_of(info),
        port: info.get_port(),
    })
}

/// The connectable host for a resolved service: the first IPv4 address
/// (sorted for determinism across multi-homed responses), else any
/// address — IPv6 bracketed, since the value is consumed as
/// `host:port` — else the mDNS hostname without its trailing dot.
fn host_of(info: &mdns_sd::ResolvedService) -> String {
    let mut v4: Vec<String> = info
        .get_addresses()
        .iter()
        .filter(|ip| ip.is_ipv4())
        .map(scoped_ip_to_string)
        .collect();
    v4.sort();
    if let Some(ip) = v4.into_iter().next() {
        return ip;
    }
    let mut any: Vec<String> = info
        .get_addresses()
        .iter()
        .map(scoped_ip_to_string)
        .collect();
    any.sort();
    if let Some(ip) = any.into_iter().next() {
        if ip.contains(':') {
            return format!("[{ip}]");
        }
        return ip;
    }
    info.get_hostname().trim_end_matches('.').to_string()
}

/// Render a scoped address as a bare IP literal (scope/interface data
/// is not meaningful to a `host:port` consumer).
fn scoped_ip_to_string(ip: &ScopedIp) -> String {
    ip.to_ip_addr().to_string()
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    /// A port unlikely to collide with a running serve instance — the
    /// announce integration test only needs a number to publish, not a
    /// bound socket.
    const LOOPBACK_TEST_PORT: u16 = 7780;

    // ── Protocol version gate ──

    #[test]
    fn version_gate_accepts_only_the_current_version() {
        assert!(protocol_version_matches(Some("1")));
        assert!(!protocol_version_matches(Some("2")));
        assert!(!protocol_version_matches(None));
        assert!(!protocol_version_matches(Some("")));
    }

    #[test]
    fn txt_constants_are_the_versioned_protocol_marker() {
        assert_eq!(PROTOCOL_KEY, "shuttle");
        assert_eq!(PROTOCOL_VERSION, "1");
        assert_eq!(SERVICE_TYPE, "_shuttle._tcp.local.");
        assert_eq!(SERVICE_TYPE_SUFFIX, "._shuttle._tcp.local.");
    }

    // ── Instance-name shape ──

    #[test]
    fn instance_name_strips_the_service_suffix() {
        assert_eq!(
            instance_name("devbox._shuttle._tcp.local."),
            Some("devbox".to_string())
        );
        // Dots and spaces are legal in instance names (RFC 6763) —
        // only the suffix is stripped.
        assert_eq!(
            instance_name("lab bench 2._shuttle._tcp.local."),
            Some("lab bench 2".to_string())
        );
        assert_eq!(instance_name("not-our-service._http._tcp.local."), None);
        assert_eq!(instance_name("_shuttle._tcp.local."), None);
    }

    // ── Dedup ──

    #[test]
    fn dedup_keeps_one_entry_per_name_and_refines_the_host() {
        let mut peers = Vec::new();
        // First sighting: an early resolution with only a link-local v6.
        upsert_unique(
            &mut peers,
            DiscoveredPeer {
                name: "devbox".into(),
                host: "[fe80::9]".into(),
                port: 7780,
            },
        );
        // Repeat sighting at an equal rank: no churn.
        upsert_unique(
            &mut peers,
            DiscoveredPeer {
                name: "devbox".into(),
                host: "[fe80::7]".into(),
                port: 7780,
            },
        );
        // Better hosts upgrade the sighting in place (global IPv6 beats
        // link-local, global IPv4 beats everything).
        upsert_unique(
            &mut peers,
            DiscoveredPeer {
                name: "devbox".into(),
                host: "[2001:db8::9]".into(),
                port: 7780,
            },
        );
        upsert_unique(
            &mut peers,
            DiscoveredPeer {
                name: "devbox".into(),
                host: "192.168.1.6".into(),
                port: 7780,
            },
        );
        // A worse repeat sighting never downgrades.
        upsert_unique(
            &mut peers,
            DiscoveredPeer {
                name: "devbox".into(),
                host: "127.0.0.1".into(),
                port: 7780,
            },
        );
        upsert_unique(
            &mut peers,
            DiscoveredPeer {
                name: "nuci".into(),
                host: "192.168.1.9".into(),
                port: 7780,
            },
        );
        assert_eq!(peers.len(), 2, "one entry per instance name");
        assert_eq!(peers[0].host, "192.168.1.6", "best-ranked host wins");
        assert_eq!(peers[1].name, "nuci");
    }

    #[test]
    fn host_score_ranks_connectability() {
        assert_eq!(host_score("192.168.1.5"), 4);
        assert_eq!(host_score("[2001:db8::1]"), 3);
        assert_eq!(host_score("127.0.0.1"), 2);
        assert_eq!(host_score("[fe80::1]"), 1);
        assert_eq!(host_score("nuci.local"), 0);
    }

    // ── Resolved service → peer ──

    /// A [`mdns_sd::ResolvedService`] as the daemon would emit it for a
    /// registered shuttle node: build the (pure, offline) ServiceInfo
    /// and convert — `ips` are comma-fed to the crate's own IP parser,
    /// `version` is the TXT `shuttle` value (`None` = property absent).
    fn resolved(name: &str, ips: &[&str], version: Option<&str>) -> mdns_sd::ResolvedService {
        let props: HashMap<String, String> = match version {
            Some(v) => [(PROTOCOL_KEY.to_string(), v.to_string())].into(),
            None => HashMap::new(),
        };
        ServiceInfo::new(
            SERVICE_TYPE,
            name,
            &format!("{name}.local."),
            ips.join(","),
            LOOPBACK_TEST_PORT,
            props,
        )
        .expect("test service info parses")
        .as_resolved_service()
    }

    #[test]
    fn resolved_service_maps_to_a_peer_record() {
        let peer = peer_from_resolved(&resolved("devbox", &["192.168.1.5"], Some("1")))
            .expect("a current-version instance is a peer");
        assert_eq!(peer.name, "devbox");
        assert_eq!(peer.host, "192.168.1.5");
        assert_eq!(peer.port, LOOPBACK_TEST_PORT);
    }

    #[test]
    fn resolved_service_without_the_version_txt_is_skipped() {
        assert!(peer_from_resolved(&resolved("devbox", &["192.168.1.5"], None)).is_none());
        assert!(peer_from_resolved(&resolved("devbox", &["192.168.1.5"], Some("2"))).is_none());
    }

    #[test]
    fn host_selection_prefers_ipv4_and_brackets_ipv6() {
        // IPv6-only responses arrive bracketed for host:port use.
        let v6 = peer_from_resolved(&resolved("devbox", &["fe80::1"], Some("1"))).unwrap();
        assert_eq!(v6.host, "[fe80::1]");

        // IPv4 wins over IPv6 when both are present.
        let both =
            peer_from_resolved(&resolved("nuci", &["fe80::2", "192.168.1.9"], Some("1"))).unwrap();
        assert_eq!(both.host, "192.168.1.9");

        // No addresses at all: fall back to the hostname, dot-trimmed.
        let bare = resolved("lab", &[], Some("1"));
        let peer = peer_from_resolved(&bare).unwrap();
        assert_eq!(peer.host, "lab.local");
    }

    // ── Loopback integration (multicast required) ──

    /// Announce → browse over the real multicast stack. `#[ignore]`d
    /// because sandboxed CI often has no multicast route and a flaky
    /// network test must not gate the suite — run it explicitly where
    /// multicast works: `cargo test -- --ignored`
    #[test]
    #[ignore = "needs a multicast-capable network; run explicitly: cargo test -- --ignored"]
    fn announce_is_visible_to_browse_on_the_lan() {
        let name = "shuttle-mdns-it";
        let port = LOOPBACK_TEST_PORT;
        let guard = announce(name, port).expect("announce registers");
        // First probe may race the daemon's initial announcement; the
        // query repeats, so a short window is enough. Retry once to
        // absorb the probe-vs-announce race without lengthening CI.
        let mut peers = browse(Duration::from_secs(2)).expect("browse");
        if !peers.iter().any(|p| p.name == name) {
            peers = browse(Duration::from_secs(2)).expect("browse retry");
        }
        assert!(
            peers.iter().any(|p| p.name == name && p.port == port),
            "expected '{name}' among peers, got: {peers:?}"
        );
        drop(guard);
    }
}
