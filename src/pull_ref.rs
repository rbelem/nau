//! Pull reference grammar for the sharing lanes (ADR-0033 Decisions 5
//! and 10): one `shuttle pull <reference>` argument dispatches across
//! three lanes — the existing OCI registries, direct peer addresses
//! (`shuttle://host[:port]/<pkg>`), and static export trees behind any
//! web server (`http(s)://…/<pkg>`).
//!
//! Parsing is total and fail-closed: every lane's package name is
//! validated to the ADR-0032 collision-classifier charset (`[a-z0-9-]`)
//! at the boundary, so a downstream lane can never request a malformed
//! name — the client side of the wire grammar (Decision 4). Anything
//! unrecognized falls through to the OCI grammar, whose own errors
//! (scheme-bearing references, missing registry host) stay the
//! registry lane's messages.

use crate::oci;

/// Default port of a `shuttle://` peer reference (ADR-0033 Decision 4:
/// one configurable, unprivileged port; 7780 everywhere a default is
/// needed — CLI flag, `node {}` serve address, peer reference).
pub const DEFAULT_PEER_PORT: u16 = 7780;

/// A static-lane URL (Decision 10). Deliberately minimal: the pull lane
/// fetches through the repo's curl seam, which wants the raw reference
/// string — no URL algebra is performed, so the `url` crate stays out
/// of the dependency tree. Parsing only validates the shape and lifts
/// the package name.
#[derive(Debug, Clone)]
pub struct Url {
    raw: String,
}

impl Url {
    /// The full URL as parsed, ready for the fetch seam.
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

/// One parsed `shuttle pull` reference.
#[derive(Debug, Clone)]
pub enum PullRef {
    /// The existing OCI-registry lane (ADR-0012 Decision 7) — behavior
    /// unchanged, dispatched to the original pull body.
    Oci(crate::oci::Reference),
    /// A peer serving its store: `shuttle://host[:port]/<pkg>`.
    Peer {
        host: String,
        port: u16,
        pkg: String,
    },
    /// A static export tree (Decision 10): `http(s)://…/<pkg>` — any
    /// web server works, no shuttle code runs server-side.
    Url { url: Url, pkg: String },
}

impl PullRef {
    /// Parse a pull reference across the three lanes (see the module
    /// docs for the grammar and the charset rule).
    pub fn parse(s: &str) -> miette::Result<PullRef> {
        if let Some(rest) = s.strip_prefix("shuttle://") {
            return Self::parse_peer(rest, s);
        }
        if s.starts_with("http://") || s.starts_with("https://") {
            return Self::parse_url(s);
        }
        Ok(PullRef::Oci(oci::Reference::parse(s)?))
    }

    /// `host[:port]/pkg` — the part after `shuttle://`.
    fn parse_peer(rest: &str, original: &str) -> miette::Result<PullRef> {
        let Some((authority, pkg)) = rest.split_once('/') else {
            miette::bail!(
                "peer reference '{original}' carries no package name — \
                 expected shuttle://host[:port]/<pkg>"
            );
        };
        Self::validate_pkg(pkg, original)?;
        let (host, port) = Self::parse_authority(authority, original)?;
        if host.is_empty() {
            miette::bail!("peer reference '{original}' has an empty host");
        }
        Ok(PullRef::Peer {
            host,
            port,
            pkg: pkg.to_string(),
        })
    }

    /// The authority: `host[:port]`. Bracketed IPv6 literals
    /// (`shuttle://[::1]/pkg`, `shuttle://[::1]:7780/pkg`) parse whole —
    /// a bare `rsplit_once(':')` would split inside the brackets. The
    /// stored `host` is the bare literal; URL builders re-bracket it.
    fn parse_authority(authority: &str, original: &str) -> miette::Result<(String, u16)> {
        if let Some(inner) = authority.strip_prefix('[') {
            let Some((host, tail)) = inner.split_once(']') else {
                miette::bail!(
                    "peer reference '{original}' has an unterminated '[' — \
                     expected shuttle://[host][:port]/<pkg>"
                );
            };
            let port = match tail.strip_prefix(':') {
                Some(p) => Self::parse_port(p, original)?,
                None => {
                    if !tail.is_empty() {
                        miette::bail!(
                            "peer reference '{original}' has trailing junk '{tail}' after ']' — \
                             expected [host][:port]"
                        );
                    }
                    DEFAULT_PEER_PORT
                }
            };
            return Ok((host.to_string(), port));
        }
        match authority.rsplit_once(':') {
            Some((h, p)) => {
                if h.is_empty() {
                    miette::bail!("peer reference '{original}' has an empty host");
                }
                Ok((h.to_string(), Self::parse_port(p, original)?))
            }
            None => Ok((authority.to_string(), DEFAULT_PEER_PORT)),
        }
    }

    fn parse_port(p: &str, original: &str) -> miette::Result<u16> {
        p.parse::<u16>().map_err(|_| {
            miette::miette!(
                "peer reference '{original}' has an out-of-range port '{p}' — \
                 ports are 1-65535"
            )
        })
    }

    /// `http(s)://host/…/pkg` — the package is the URL's final path
    /// segment; the reference must END in `/<pkg>`.
    fn parse_url(s: &str) -> miette::Result<PullRef> {
        let rest = s.split_once("://").expect("caller matched the scheme").1;
        let Some((authority, path)) = rest.split_once('/') else {
            miette::bail!(
                "static reference '{s}' names no package — expected {}://host/…/<pkg>",
                s.split(':').next().unwrap_or("http")
            );
        };
        if authority.is_empty() {
            miette::bail!("static reference '{s}' has an empty host");
        }
        let pkg = path.rsplit('/').next().unwrap_or_default();
        if pkg.is_empty() {
            miette::bail!("static reference '{s}' must end in /<pkg>");
        }
        Self::validate_pkg(pkg, s)?;
        Ok(PullRef::Url {
            url: Url { raw: s.to_string() },
            pkg: pkg.to_string(),
        })
    }

    /// The wire grammar's package-name rule (ADR-0033 Decision 4): a
    /// package name is `[a-z0-9-]` — the ADR-0032 collision-classifier
    /// charset. The client strictly requests only well-formed names.
    fn validate_pkg(pkg: &str, original: &str) -> miette::Result<()> {
        if pkg.is_empty() {
            miette::bail!("reference '{original}' names no package");
        }
        if !pkg
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            miette::bail!(
                "reference '{original}' package name '{pkg}' must match \
                 [a-z0-9-] (the ADR-0032 collision-classifier charset)"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_reference_parses_host_port_pkg() {
        let r = PullRef::parse("shuttle://nuci.local:7780/hello").unwrap();
        match r {
            PullRef::Peer { host, port, pkg } => {
                assert_eq!(host, "nuci.local");
                assert_eq!(port, 7780);
                assert_eq!(pkg, "hello");
            }
            other => panic!("expected Peer, got {other:?}"),
        }
    }

    #[test]
    fn peer_reference_defaults_port() {
        let r = PullRef::parse("shuttle://nuci.local/hello").unwrap();
        match r {
            PullRef::Peer { host, port, pkg } => {
                assert_eq!(host, "nuci.local");
                assert_eq!(port, DEFAULT_PEER_PORT);
                assert_eq!(pkg, "hello");
            }
            other => panic!("expected Peer, got {other:?}"),
        }
    }

    /// Bracketed IPv6 literals parse whole (default and explicit
    /// port); the stored host is the bare literal `::1` — URL builders
    /// re-bracket it. A bare rsplit_once(':') would split inside the
    /// brackets and mis-parse both shapes.
    #[test]
    fn bracketed_ipv6_peer_references_parse_whole() {
        let explicit = PullRef::parse("shuttle://[::1]:7780/hello").unwrap();
        match explicit {
            PullRef::Peer { host, port, pkg } => {
                assert_eq!(host, "::1");
                assert_eq!(port, 7780);
                assert_eq!(pkg, "hello");
            }
            other => panic!("expected Peer, got {other:?}"),
        }
        let defaulted = PullRef::parse("shuttle://[::1]/hello").unwrap();
        match defaulted {
            PullRef::Peer { host, port, pkg } => {
                assert_eq!(host, "::1");
                assert_eq!(port, DEFAULT_PEER_PORT);
                assert_eq!(pkg, "hello");
            }
            other => panic!("expected Peer, got {other:?}"),
        }
    }

    #[test]
    fn unterminated_bracket_is_refused() {
        assert!(PullRef::parse("shuttle://[::1/hello").is_err());
        assert!(PullRef::parse("shuttle://[]/hello").is_err());
    }

    #[test]
    fn static_url_parses_pkg_from_final_segment() {
        let r = PullRef::parse("https://mirror.example/shuttle/git").unwrap();
        match r {
            PullRef::Url { url, pkg } => {
                assert_eq!(pkg, "git");
                assert_eq!(url.as_str(), "https://mirror.example/shuttle/git");
            }
            other => panic!("expected Url, got {other:?}"),
        }
    }

    #[test]
    fn plain_http_is_the_static_lane_too() {
        let r = PullRef::parse("http://10.0.0.7:9000/mirror/vim").unwrap();
        match r {
            PullRef::Url { pkg, .. } => assert_eq!(pkg, "vim"),
            other => panic!("expected Url, got {other:?}"),
        }
    }

    #[test]
    fn everything_else_falls_to_the_oci_grammar() {
        let r = PullRef::parse("localhost:5000/ns/repo:v1").unwrap();
        match r {
            PullRef::Oci(reference) => {
                assert_eq!(reference.registry, "localhost:5000");
                assert_eq!(reference.repo, "ns/repo");
                assert_eq!(reference.tag.as_deref(), Some("v1"));
            }
            other => panic!("expected Oci, got {other:?}"),
        }
    }

    #[test]
    fn peer_reference_with_empty_pkg_is_refused() {
        assert!(PullRef::parse("shuttle://nuci.local/").is_err());
        assert!(PullRef::parse("shuttle://nuci.local").is_err());
        assert!(PullRef::parse("shuttle:///hello").is_err());
    }

    #[test]
    fn peer_reference_with_out_of_range_port_is_refused() {
        let err =
            PullRef::parse("shuttle://nuci.local:99999/hello").expect_err("99999 exceeds u16");
        assert!(err.to_string().contains("out-of-range port '99999'"));
        assert!(PullRef::parse("shuttle://nuci.local:/hello").is_err());
    }

    #[test]
    fn unknown_schemes_reach_the_oci_error() {
        // A scheme-bearing reference is not a peer or static lane — the
        // OCI grammar owns the refusal (it rejects every scheme).
        let err = PullRef::parse("ftp://mirror.example/git").expect_err("ftp:// must not parse");
        assert!(err.to_string().contains("must not include a scheme"));
    }

    #[test]
    fn package_names_are_charset_checked_on_both_lanes() {
        let err = PullRef::parse("shuttle://nuci.local/Hello_World")
            .expect_err("uppercase/underscore must be refused");
        assert!(err.to_string().contains("[a-z0-9-]"));
        assert!(PullRef::parse("https://mirror.example/shuttle/..%2fetc").is_err());
    }

    #[test]
    fn static_url_without_final_pkg_segment_is_refused() {
        assert!(PullRef::parse("https://mirror.example").is_err());
        assert!(PullRef::parse("https://mirror.example/").is_err());
        assert!(PullRef::parse("https://mirror.example/shuttle/git/").is_err());
    }
}
