//! The build-request queue (ADR-0052 Decision 4 + Security): a
//! file-backed request directory — one JSON file per build request —
//! with atomic writes (temp + rename) and claim-by-rename into a
//! `claimed/` subtree as the atomicity boundary. Receipts land in
//! `done/` beside the settled request file.
//!
//! Layout (all under the queue root, default
//! `$XDG_DATA_HOME/nau/build-requests`):
//!
//! ```text
//! <root>/<id>.json              pending requests, `<millis>-<hash16>` ids
//! <root>/claimed/<id>.json      claimed by the drain, in flight
//! <root>/done/<id>.json         settled request (the claim's rename)
//! <root>/done/<id>.receipt.json the outcome: manifest/blob urls, or the error
//! ```
//!
//! Requests carry recipe IDENTITY (`package` + `version` + who asked)
//! and never client-supplied build text (ADR-0052 Security): the drain
//! re-evaluates the farm's own recipe file. The grammar is enforced
//! here too — `enqueue` refuses a malformed identity, so no writer
//! (the serve route today, a future one tomorrow) can bypass it.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use miette::{IntoDiagnostic, WrapErr};
use serde::{Deserialize, Serialize};

/// One queued build request: recipe identity only (ADR-0052 Security —
/// the drain never executes client-supplied build text).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildRequest {
    /// Package name, `[a-z0-9-]+` (the ADR-0032 collision-classifier
    /// charset — the same grammar the serving wire and `nau pull` use).
    pub package: String,
    /// The requested version: a plain `X.Y.Z` triple (the ADR-0052
    /// shape for always-latest recipe releases).
    pub version: String,
    /// Who asked (an opaque label for the farm's audit trail; free-form
    /// printable, never a path).
    pub requested_by: String,
}

/// The outcome of one drained request, written to
/// `done/<id>.receipt.json` (ADR-0052 Decision 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// The request the receipt settles.
    pub request: BuildRequest,
    /// `"released"` or `"error"`.
    pub status: String,
    /// The signed manifest's public URL (`status = "released"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_url: Option<String>,
    /// Every uploaded blob's public URL, sha256-addressed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blob_urls: Vec<String>,
    /// The failure chain (`status = "error"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Unix seconds when the request settled.
    pub finished_epoch: u64,
}

/// One claimed request: its queue id (the request file's stem) plus the
/// parsed identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedRequest {
    pub id: String,
    pub request: BuildRequest,
}

// ── Grammar (fail-closed, shared by every writer) ──

/// Package-name grammar: `[a-z0-9-]+` (the `pull_ref` / serve-wire
/// charset). A name failing this can never be a path segment.
pub fn is_pkg_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Version grammar: a plain numeric triple `X.Y.Z`. Each component is
/// one or more ASCII digits; anything else (ranges, `v` prefixes,
/// suffixes) is refused — the request names an exact upstream release.
pub fn is_version_triple(s: &str) -> bool {
    let mut parts = s.split('.');
    let clean = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    parts.next().is_some_and(clean)
        && parts.next().is_some_and(clean)
        && parts.next().is_some_and(clean)
        && parts.next().is_none()
}

/// `requested_by` grammar: printable, no control characters, non-empty,
/// bounded — it is an audit label that lands in filenames' siblings and
/// logs, never a path itself.
pub fn is_requested_by(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.chars().all(|c| !c.is_control())
}

impl BuildRequest {
    /// Validate the identity grammar. Every enqueue passes through
    /// here — a malformed request can never enter the queue.
    pub fn validate(&self) -> miette::Result<()> {
        if !is_pkg_name(&self.package) {
            miette::bail!(
                "package '{}' must match [a-z0-9-] (the ADR-0032 collision-classifier charset)",
                self.package
            );
        }
        if !is_version_triple(&self.version) {
            miette::bail!(
                "version '{}' must be a plain numeric triple (X.Y.Z)",
                self.version
            );
        }
        if !is_requested_by(&self.requested_by) {
            miette::bail!(
                "requested_by must be non-empty printable text under 256 bytes, no control characters"
            );
        }
        Ok(())
    }
}

// ── The queue ──

/// The file-backed build-request queue. All path and serialization
/// logic lives here; callers hand identities in and take ids out.
#[derive(Debug, Clone)]
pub struct BuildQueue {
    root: PathBuf,
}

impl BuildQueue {
    /// A queue rooted at `root` (`--queue-dir` override).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        BuildQueue { root: root.into() }
    }

    /// The default queue root (ADR-0052 Decision 4): the XDG data root's
    /// nau directory — `$XDG_DATA_HOME/nau/build-requests`, defaulting
    /// to `~/.local/share/nau/build-requests` (the pod-root precedence).
    pub fn default_dir() -> PathBuf {
        let data_home = match std::env::var("XDG_DATA_HOME") {
            Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
            _ => PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
                .join(".local/share"),
        };
        data_home.join("nau").join("build-requests")
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn claimed_dir(&self) -> PathBuf {
        self.root.join("claimed")
    }

    fn done_dir(&self) -> PathBuf {
        self.root.join("done")
    }

    /// Create the layout (`pending` is the root itself, `claimed/` and
    /// `done/` the subtrees). Idempotent.
    pub fn ensure_dirs(&self) -> miette::Result<()> {
        for dir in [self.root.clone(), self.claimed_dir(), self.done_dir()] {
            fs::create_dir_all(&dir)
                .into_diagnostic()
                .wrap_err_with(|| format!("creating queue dir {}", dir.display()))?;
        }
        Ok(())
    }

    /// Write one request file atomically (temp + rename — a crash never
    /// leaves a half-written request visible) and return its id. The id
    /// is `<unix-millis>-<sha256(canonical json)[..16]>`: the epoch
    /// prefix makes ids sort chronologically (the drain's FIFO order),
    /// the content hash keeps same-millisecond requests distinct.
    pub fn enqueue(&self, request: &BuildRequest) -> miette::Result<String> {
        request.validate()?;
        self.ensure_dirs()?;
        let json = serde_json::to_vec_pretty(request)
            .map_err(|e| miette::miette!("serialize build request: {e}"))?;
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let hash = nau_core::cache_key::sha256_hex(&json);
        let id = format!("{millis}-{}", &hash[..16]);
        write_atomic(&self.root.join(format!("{id}.json")), &json)?;
        Ok(id)
    }

    /// Claim the oldest pending request by rename into `claimed/` — the
    /// rename IS the atomicity boundary (ADR-0052 Security): a file
    /// either fully moves (one drain owns it) or nothing changes.
    /// Returns `None` when the queue is empty.
    ///
    /// Single-drain by contract: the rename claims against the pending
    /// set; two concurrent drains would need a no-replace claim primitive
    /// std does not offer (`renameat2(RENAME_NOREPLACE)`), and the ADR's
    /// drain is one farm-side loop.
    pub fn claim(&self) -> miette::Result<Option<QueuedRequest>> {
        let Some((id, path)) = self.oldest_pending()? else {
            return Ok(None);
        };
        let claimed = self.claimed_dir().join(format!("{id}.json"));
        fs::rename(&path, &claimed)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "claiming request {id} (rename {} → {})",
                    path.display(),
                    claimed.display()
                )
            })?;
        let raw = fs::read(&claimed)
            .into_diagnostic()
            .wrap_err_with(|| format!("reading claimed request {}", claimed.display()))?;
        let request: BuildRequest = serde_json::from_slice(&raw).map_err(|e| {
            miette::miette!("claimed request {id} does not parse as a build request: {e}")
        })?;
        Ok(Some(QueuedRequest { id, request }))
    }

    /// The oldest pending file: the lexicographically smallest id — the
    /// epoch-millis prefix makes that the chronological order.
    fn oldest_pending(&self) -> miette::Result<Option<(String, PathBuf)>> {
        let mut oldest: Option<(String, PathBuf)> = None;
        for entry in fs::read_dir(&self.root)
            .into_diagnostic()
            .wrap_err_with(|| format!("reading queue root {}", self.root.display()))?
        {
            let entry = entry
                .into_diagnostic()
                .wrap_err_with(|| format!("reading queue root {}", self.root.display()))?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            // Ignore anything that is not an id-shaped file (the
            // claimed/done subtrees are directories; stray files skip).
            if id.is_empty() || id.contains('/') {
                continue;
            }
            if oldest.as_ref().is_none_or(|(best, _)| id < best.as_str()) {
                oldest = Some((id.to_string(), path));
            }
        }
        Ok(oldest)
    }

    /// Settle a claimed request as released: write the receipt into
    /// `done/` FIRST, then move the request file in (a crash between
    /// the two leaves a claimed request with its receipt already
    /// recorded — never a released claim without a receipt).
    pub fn complete(
        &self,
        id: &str,
        request: &BuildRequest,
        manifest_url: &str,
        blob_urls: &[String],
    ) -> miette::Result<()> {
        let receipt = Receipt {
            request: request.clone(),
            status: "released".into(),
            manifest_url: Some(manifest_url.to_string()),
            blob_urls: blob_urls.to_vec(),
            error: None,
            finished_epoch: epoch_secs(),
        };
        self.settle(id, &receipt)
    }

    /// Settle a claimed request as failed: the error lands in the
    /// receipt (ADR-0052 Decision 4), the claimed file moves to `done/`.
    pub fn fail(&self, id: &str, request: &BuildRequest, error: &str) -> miette::Result<()> {
        let receipt = Receipt {
            request: request.clone(),
            status: "error".into(),
            manifest_url: None,
            blob_urls: Vec::new(),
            error: Some(error.to_string()),
            finished_epoch: epoch_secs(),
        };
        self.settle(id, &receipt)
    }

    fn settle(&self, id: &str, receipt: &Receipt) -> miette::Result<()> {
        self.ensure_dirs()?;
        let json = serde_json::to_vec_pretty(receipt)
            .map_err(|e| miette::miette!("serialize receipt: {e}"))?;
        // Receipt first: after the move below there is no source of
        // truth left in `claimed/`, so the receipt must already exist.
        write_atomic(&self.done_dir().join(format!("{id}.receipt.json")), &json)?;
        let claimed = self.claimed_dir().join(format!("{id}.json"));
        let done = self.done_dir().join(format!("{id}.json"));
        fs::rename(&claimed, &done)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "settling request {id} (rename {} → {})",
                    claimed.display(),
                    done.display()
                )
            })?;
        Ok(())
    }

    /// Number of pending request files (the drain's idle log line).
    pub fn pending_count(&self) -> miette::Result<usize> {
        let entries = fs::read_dir(&self.root)
            .into_diagnostic()
            .wrap_err_with(|| format!("reading queue root {}", self.root.display()))?;
        Ok(entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".json"))
            })
            .count())
    }
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write `bytes` to `dest` atomically: temp file beside the
/// destination, then rename (the `pull_peer::write_atomic` precedent —
/// a crash never leaves a half-written file at the real name).
fn write_atomic(dest: &Path, bytes: &[u8]) -> miette::Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| miette::miette!("path {} has no parent directory", dest.display()))?;
    fs::create_dir_all(parent)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", parent.display()))?;
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = parent.join(format!(".{}.{}.part", name, std::process::id()));
    fs::write(&tmp, bytes)
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, dest)
        .into_diagnostic()
        .wrap_err_with(|| format!("renaming {} into {}", tmp.display(), dest.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> BuildRequest {
        BuildRequest {
            package: "hello-world".into(),
            version: "1.2.3".into(),
            requested_by: "device-7".into(),
        }
    }

    #[test]
    fn grammar_helpers_match_the_contract() {
        assert!(is_pkg_name("hello-world-2"));
        assert!(!is_pkg_name(""));
        assert!(!is_pkg_name("Hello"));
        assert!(!is_pkg_name("a/b"));
        assert!(!is_pkg_name(".."));

        assert!(is_version_triple("1.2.3"));
        assert!(is_version_triple("0.0.0"));
        assert!(is_version_triple("10.20.30"));
        assert!(!is_version_triple("1.2"));
        assert!(!is_version_triple("1.2.3.4"));
        assert!(!is_version_triple("v1.2.3"));
        assert!(!is_version_triple("1.2.x"));
        assert!(!is_version_triple("1..3"));
        assert!(!is_version_triple(""));

        assert!(is_requested_by("device-7"));
        assert!(is_requested_by("operator@farm"));
        assert!(!is_requested_by(""));
        assert!(!is_requested_by("bad\nnewline"));
        assert!(!is_requested_by(&"x".repeat(257)));
    }

    #[test]
    fn enqueue_refuses_malformed_identities() {
        let dir = tempfile::tempdir().unwrap();
        let q = BuildQueue::new(dir.path());
        for bad in [
            BuildRequest {
                package: "Hello".into(),
                version: "1.2.3".into(),
                requested_by: "d".into(),
            },
            BuildRequest {
                package: "ok".into(),
                version: "1.2".into(),
                requested_by: "d".into(),
            },
            BuildRequest {
                package: "ok".into(),
                version: "1.2.3".into(),
                requested_by: String::new(),
            },
        ] {
            assert!(q.enqueue(&bad).is_err(), "{bad:?} must be refused");
        }
        // Nothing was written: the refusals never touched the queue.
        assert_eq!(q.pending_count().unwrap(), 0);
    }

    #[test]
    fn enqueue_writes_one_complete_file_and_claim_renames_it() {
        let dir = tempfile::tempdir().unwrap();
        let q = BuildQueue::new(dir.path());
        let id = q.enqueue(&request()).unwrap();

        // Exactly one pending request file, readable as the request we
        // sent (the claimed/done subtrees exist but are directories).
        let pending: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        assert_eq!(pending.len(), 1, "one request file per build");
        let raw = fs::read(&pending[0]).unwrap();
        let parsed: BuildRequest = serde_json::from_slice(&raw).unwrap();
        assert_eq!(parsed, request());

        // The claim moves the file into claimed/ (atomicity boundary)
        // and returns the parsed identity.
        let claimed = q.claim().unwrap().expect("claim finds the request");
        assert_eq!(claimed.id, id);
        assert_eq!(claimed.request, request());
        assert!(!dir.path().join(format!("{id}.json")).exists());
        assert!(dir
            .path()
            .join("claimed")
            .join(format!("{id}.json"))
            .exists());
        assert!(!dir.path().join("done").join(format!("{id}.json")).exists());
    }

    #[test]
    fn claim_on_an_empty_queue_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let q = BuildQueue::new(dir.path());
        assert!(q.claim().unwrap().is_none());
    }

    #[test]
    fn claims_come_out_in_fifo_order() {
        let dir = tempfile::tempdir().unwrap();
        let q = BuildQueue::new(dir.path());
        let first = q.enqueue(&request()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let second = q
            .enqueue(&BuildRequest {
                package: "second-pkg".into(),
                ..request()
            })
            .unwrap();
        assert!(first < second, "ids sort chronologically");
        let a = q.claim().unwrap().unwrap();
        let b = q.claim().unwrap().unwrap();
        assert_eq!(a.id, first);
        assert_eq!(b.id, second);
        assert!(q.claim().unwrap().is_none(), "queue drained");
    }

    #[test]
    fn complete_writes_the_receipt_and_moves_the_request_to_done() {
        let dir = tempfile::tempdir().unwrap();
        let q = BuildQueue::new(dir.path());
        let id = q.enqueue(&request()).unwrap();
        let claimed = q.claim().unwrap().unwrap();

        q.complete(
            &claimed.id,
            &claimed.request,
            "https://download.example/nau/manifests/hello-world.json",
            &["https://download.example/nau/blobs/ab".to_string()],
        )
        .unwrap();

        let receipt_path = dir.path().join("done").join(format!("{id}.receipt.json"));
        let receipt: Receipt = serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
        assert_eq!(receipt.status, "released");
        assert_eq!(
            receipt.manifest_url.as_deref(),
            Some("https://download.example/nau/manifests/hello-world.json")
        );
        assert_eq!(
            receipt.blob_urls,
            vec!["https://download.example/nau/blobs/ab"]
        );
        assert_eq!(receipt.request, request());
        // The claimed slot is empty; the settled request sits in done/.
        assert!(!dir
            .path()
            .join("claimed")
            .join(format!("{id}.json"))
            .exists());
        assert!(dir.path().join("done").join(format!("{id}.json")).exists());
    }

    #[test]
    fn fail_records_the_error_in_the_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let q = BuildQueue::new(dir.path());
        let id = q.enqueue(&request()).unwrap();
        let claimed = q.claim().unwrap().unwrap();
        q.fail(&claimed.id, &claimed.request, "recipe not found")
            .unwrap();

        let receipt: Receipt = serde_json::from_slice(
            &fs::read(dir.path().join("done").join(format!("{id}.receipt.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt.status, "error");
        assert_eq!(receipt.error.as_deref(), Some("recipe not found"));
        assert!(receipt.manifest_url.is_none());
        assert!(dir.path().join("done").join(format!("{id}.json")).exists());
    }

    #[test]
    fn default_dir_lands_under_the_nau_data_dir() {
        // The path SHAPE is the contract (`<data home>/nau/build-requests`);
        // XDG_DATA_HOME redirection mirrors the pod-root precedence and is
        // covered by the pod_root suite — this test only pins the tail so
        // a rename cannot silently strand existing queues.
        let d = BuildQueue::default_dir();
        assert!(d.ends_with(std::path::Path::new("nau").join("build-requests")));
    }
}
