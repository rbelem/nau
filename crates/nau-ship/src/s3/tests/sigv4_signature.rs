use super::*;

#[test]
fn sigv4_signature_matches_the_canned_vector() {
    let sig = sigv4_signature(
        SECRET,
        REGION,
        "20261002T000000Z",
        "PUT",
        "/nau-tree/manifests/hello.json",
        "s3.internal.example",
        PAYLOAD_SHA,
    );
    assert_eq!(sig, EXPECTED_SIG);
}

#[test]
fn sigv4_signature_depends_on_every_input() {
    let base = |uri: &str, host: &str| {
        sigv4_signature(
            SECRET,
            REGION,
            "20261002T000000Z",
            "PUT",
            uri,
            host,
            PAYLOAD_SHA,
        )
    };
    let reference = base("/nau-tree/manifests/hello.json", "s3.internal.example");
    assert_eq!(reference, EXPECTED_SIG);
    assert_ne!(base("/nau-tree/blobs/aa", "s3.internal.example"), reference);
    assert_ne!(
        base("/nau-tree/manifests/hello.json", "s3.other.example"),
        reference
    );
    assert_ne!(
        sigv4_signature(
            "other-secret",
            REGION,
            "20261002T000000Z",
            "PUT",
            "/nau-tree/manifests/hello.json",
            "s3.internal.example",
            PAYLOAD_SHA
        ),
        reference
    );
}

#[test]
fn amz_dates_render_the_sigv4_shapes() {
    assert_eq!(amz_dates(0), ("19700101T000000Z".into(), "19700101".into()));
    // 2026-01-01T00:00:00Z
    assert_eq!(
        amz_dates(1_767_225_600),
        ("20260101T000000Z".into(), "20260101".into())
    );
}

#[test]
fn uri_encode_keeps_unreserved_and_encodes_the_rest() {
    assert_eq!(uri_encode("blobs/ab12", true), "blobs/ab12");
    assert_eq!(
        uri_encode("manifests/hello.json", true),
        "manifests/hello.json"
    );
    assert_eq!(uri_encode("a b/c+d", true), "a%20b/c%2Bd");
    assert_eq!(uri_encode("a/b", false), "a%2Fb");
}

#[test]
fn endpoint_host_parses_and_refuses() {
    assert_eq!(
        endpoint_host("https://s3.internal.example").unwrap(),
        "s3.internal.example"
    );
    assert_eq!(
        endpoint_host("http://127.0.0.1:9000").unwrap(),
        "127.0.0.1:9000"
    );
    assert!(endpoint_host("s3.internal.example").is_err());
    assert!(endpoint_host("https://").is_err());
}

#[test]
fn parse_status_reads_the_first_final_response_line() {
    assert_eq!(parse_status("HTTP/1.1 200 OK\r\nx: y\r\n"), Some(200));
    assert_eq!(parse_status("HTTP/1.1 404 Not Found\r\n"), Some(404));
    assert_eq!(parse_status("garbage"), None);
    assert_eq!(parse_status(""), None);
}

/// The `Expect: 100-continue` regression (live RustFS, 2026-10-02):
/// curl's header dump carries the server's interim `HTTP/1.1 100
/// Continue` above the final response, and the first-line parse took
/// the 100 as the verdict. 1xx lines are never final.
#[test]
fn parse_status_skips_interim_100_lines() {
    let dump = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nx-amz-id-2: y\r\n";
    assert_eq!(parse_status(dump), Some(200));
    let failing = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 500 Internal Server Error\r\n";
    assert_eq!(parse_status(failing), Some(500));
    assert_eq!(parse_status("HTTP/1.1 100 Continue\r\n\r\n"), None);
}

/// A body-carrying request suppresses `Expect:` outright — curl then
/// never opens the 100-continue exchange the dump parser would have
/// to skip.
#[test]
fn put_argv_carries_the_expect_suppression() {
    let target = S3Target {
        endpoint: "http://127.0.0.1:9000".into(),
        bucket: "b".into(),
        region: "r".into(),
        access_key: "a".into(),
        secret_key: "s".into(),
    };
    let (fake, calls) = FakeCurl::new(200);
    let client = S3Client::with_runner(target, Box::new(fake)).unwrap();
    client.put("k", b"payload").unwrap();
    let argv = calls.lock().unwrap()[0].clone();
    let expect_at = argv.iter().position(|a| a == "Expect:").unwrap();
    assert_eq!(argv[expect_at - 1], "-H", "rides a -H pair");
    // GET carries no body and no suppression.
    let _ = client.get("k").unwrap();
    let get_argv = calls.lock().unwrap()[1].clone();
    assert!(!get_argv.contains(&"Expect:".to_string()));
}

#[test]
fn put_carries_the_sigv4_headers_and_path_style_url() {
    let (fake, calls) = FakeCurl::new(200);
    let client = S3Client::with_runner(test_target(), Box::new(fake)).unwrap();
    client.put("blobs/aa", b"payload").unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let argv = &calls[0];
    assert_eq!(FakeCurl::method_of(argv), "PUT");
    assert!(
        argv.last().unwrap().ends_with("/nau-tree/blobs/aa"),
        "path-style URL, got {argv:?}"
    );
    let auth = argv
        .iter()
        .find(|a| a.starts_with("Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"))
        .expect("signed Authorization header");
    assert!(auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
    assert!(auth.contains("/us-east-1/s3/aws4_request"));
    let payload_header = argv
        .iter()
        .find(|a| a.starts_with("x-amz-content-sha256: "))
        .expect("payload hash header");
    assert_eq!(
        payload_header.trim_start_matches("x-amz-content-sha256: "),
        sha256_hex(b"payload")
    );
}

#[test]
fn get_maps_404_to_none_and_200_to_body() {
    let missing = S3Client::with_runner(test_target(), Box::new(FakeCurl::new(404).0)).unwrap();
    assert_eq!(missing.get("index.json").unwrap(), None);

    let present = S3Client::with_runner(test_target(), Box::new(FakeCurl::new(200).0)).unwrap();
    assert_eq!(present.get("index.json").unwrap().unwrap(), b"resp");
}

#[test]
fn put_names_the_object_on_http_errors() {
    let client = S3Client::with_runner(test_target(), Box::new(FakeCurl::new(403).0)).unwrap();
    let err = client.put("blobs/aa", b"payload").unwrap_err().to_string();
    assert!(err.contains("blobs/aa"), "{err}");
    assert!(err.contains("403"), "{err}");
}

/// The path helper sanity: object_url joins endpoint/bucket/key and
/// tolerates a trailing slash on the endpoint.
#[test]
fn object_url_is_path_style() {
    let client = S3Client::with_runner(test_target(), Box::new(FakeCurl::new(200).0)).unwrap();
    assert_eq!(
        client.object_url("manifests/hello.json"),
        "https://s3.internal.example/nau-tree/manifests/hello.json"
    );
}
