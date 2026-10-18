use super::*;

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
