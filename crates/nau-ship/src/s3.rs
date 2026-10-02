//! The rustfs (S3-compatible) transport for the release seam (ADR-0052
//! Decision 5): SigV4-signed PUT/GET over the curl-behind-the-command-seam
//! transport — the [`crate::oci`] precedent, no tokio/hyper anywhere.
//!
//! Scope is deliberately narrow: exactly the two verbs the release lane
//! needs ([`S3Client::put`], [`S3Client::get`] with 404 → `None` for the
//! tree probes), path-style addressing (`<endpoint>/<bucket>/<key>` —
//! the layout rustfs fronts), and SigV4 over the three headers the
//! object verbs require (`host`, `x-amz-content-sha256`,
//! `x-amz-date`). Crypto rides `hmac` + `sha2` (both already locked in
//! the workspace graph — no new vendored code); hex encoding is
//! [`nau_core::sign::to_hex`], the core keychain's own encoder.

use hmac::{Hmac, Mac};
use miette::{bail, IntoDiagnostic, WrapErr};
use nau_core::cache_key::sha256_hex;
use nau_infra::command::{exit_code, CommandRunner, RealRunner};

use crate::oci::{BLOB_TIMEOUT_SECS, CONNECT_TIMEOUT_SECS};
use crate::release::S3Target;

/// HMAC-SHA256 over `data` under `key` (the SigV4 key-derivation chain
/// and the final request signature).
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(key).expect("hmac accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// The SigV4 clock pair from unix seconds: `<YYYYMMDDTHHMMSSZ>` (the
/// `x-amz-date` header value) and `<YYYYMMDD>` (the credential scope's
/// date). Reuses the core RFC3339 rendering — SigV4's shape is exactly
/// that rendering minus the `-`/`:` separators.
fn amz_dates(unix: i64) -> (String, String) {
    let rfc = nau_core::sign::unix_to_rfc3339(unix);
    let amzdate: String = rfc.chars().filter(|c| *c != '-' && *c != ':').collect();
    (amzdate.clone(), amzdate[..8].to_string())
}

/// AWS strict URI encoding: unreserved characters (`A-Za-z0-9-._~`)
/// pass through, everything else is `%XX` uppercase. `preserve_slash`
/// keeps `/` literal (path segments vs the whole canonical path).
fn uri_encode(s: &str, preserve_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b'/' if preserve_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The host (authority) of an `http(s)` endpoint — the canonical-headers
/// `host` value. A scheme-less or empty endpoint is refused at client
/// construction, never mid-request.
fn endpoint_host(endpoint: &str) -> miette::Result<String> {
    let rest = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .ok_or_else(|| {
            miette::miette!(
                "s3 endpoint '{endpoint}' must be an http(s) URL (e.g. \
                 https://s3.internal.example)"
            )
        })?;
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        bail!("s3 endpoint '{endpoint}' carries no host");
    }
    Ok(authority.to_string())
}

/// The SigV4 signature over one request (pure — the canned-vector test
/// pins it against an independently computed AWS-documented example):
/// canonical request → string-to-sign → the four-step HMAC key
/// derivation → lowercase-hex signature. `amzdate` carries its own
/// scope date (its first 8 chars ARE the datestamp).
fn sigv4_signature(
    secret_key: &str,
    region: &str,
    amzdate: &str,
    method: &str,
    canonical_uri: &str,
    host: &str,
    payload_sha256_hex: &str,
) -> String {
    const SIGNED_HEADERS: &str = "host;x-amz-content-sha256;x-amz-date";
    let datestamp = &amzdate[..8];
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n\n\
         host:{host}\n\
         x-amz-content-sha256:{payload_sha256_hex}\n\
         x-amz-date:{amzdate}\n\n\
         {SIGNED_HEADERS}\n\
         {payload_sha256_hex}"
    );
    let scope = format!("{datestamp}/{region}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{}",
        sha256_hex(&canonical_request)
    );
    let k_date = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), datestamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    nau_core::sign::to_hex(&hmac_sha256(&k_signing, string_to_sign.as_bytes()))
}

/// The HTTP status from a curl `-D` header dump (first response line:
/// `HTTP/1.1 200 OK`).
fn parse_status(head: &str) -> Option<u16> {
    head.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
}

/// A signed rustfs client bound to one [`S3Target`]: endpoint, bucket,
/// region, and the access pair every request is signed under.
pub struct S3Client {
    target: S3Target,
    runner: Box<dyn CommandRunner>,
    scratch: tempfile::TempDir,
}

impl S3Client {
    pub fn new(target: S3Target) -> miette::Result<S3Client> {
        Self::with_runner(target, Box::new(RealRunner))
    }

    /// The test seam (the oci.rs client's shape): inject the curl
    /// runner so fake runners can capture or emulate requests without a
    /// network.
    pub(crate) fn with_runner(
        target: S3Target,
        runner: Box<dyn CommandRunner>,
    ) -> miette::Result<S3Client> {
        // Fail fast on a malformed endpoint — never mid-release.
        endpoint_host(&target.endpoint)?;
        let scratch = tempfile::tempdir()
            .into_diagnostic()
            .wrap_err("creating the s3 client scratch dir")?;
        Ok(S3Client {
            target,
            runner,
            scratch,
        })
    }

    /// Path-style object URL: `<endpoint>/<bucket>/<key>` — the layout
    /// rustfs fronts behind Caddy.
    fn object_url(&self, key: &str) -> String {
        format!(
            "{}/{}/{}",
            self.target.endpoint.trim_end_matches('/'),
            self.target.bucket,
            key
        )
    }

    /// The request headers one signed call carries: Authorization,
    /// x-amz-date, x-amz-content-sha256 (the real payload hash — rustfs
    /// verifies it). Returns them in send order.
    fn signed_headers(
        &self,
        method: &str,
        key: &str,
        payload: &[u8],
    ) -> miette::Result<Vec<String>> {
        let host = endpoint_host(&self.target.endpoint)?;
        let payload_sha = sha256_hex(payload);
        let (amzdate, datestamp) = amz_dates(nau_core::sign::now_unix());
        let canonical_uri = format!(
            "/{}/{}",
            uri_encode(&self.target.bucket, true),
            uri_encode(key, true)
        );
        let signature = sigv4_signature(
            &self.target.secret_key,
            &self.target.region,
            &amzdate,
            method,
            &canonical_uri,
            &host,
            &payload_sha,
        );
        let scope = format!("{datestamp}/{}/s3/aws4_request", self.target.region);
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature={signature}",
            self.target.access_key, scope
        );
        Ok(vec![
            format!("Authorization: {authorization}"),
            format!("x-amz-date: {amzdate}"),
            format!("x-amz-content-sha256: {payload_sha}"),
        ])
    }

    /// The curl argv for one request: fixed timeout flags, the method,
    /// the signed headers, the staged body when present, and the file
    /// plumbing (-D/-o) the response is read back through.
    fn curl_argv(
        &self,
        method: &str,
        key: &str,
        headers: Vec<String>,
        body: Option<&[u8]>,
    ) -> miette::Result<Vec<String>> {
        let mut argv: Vec<String> = vec![
            "curl".into(),
            "-sS".into(),
            "--connect-timeout".into(),
            CONNECT_TIMEOUT_SECS.to_string(),
            "--max-time".into(),
            BLOB_TIMEOUT_SECS.to_string(),
            "-X".into(),
            method.to_string(),
        ];
        for header in headers {
            argv.extend(["-H".into(), header]);
        }
        if let Some(bytes) = body {
            let upload = self.scratch.path().join("upload.bin");
            std::fs::write(&upload, bytes)
                .into_diagnostic()
                .wrap_err_with(|| format!("staging the upload body for {key}"))?;
            argv.extend(["--data-binary".into(), format!("@{}", upload.display())]);
        }
        argv.extend([
            "-D".into(),
            self.scratch
                .path()
                .join("headers.txt")
                .to_string_lossy()
                .into_owned(),
            "-o".into(),
            self.scratch
                .path()
                .join("body.bin")
                .to_string_lossy()
                .into_owned(),
        ]);
        argv.push(self.object_url(key));
        Ok(argv)
    }

    /// Read one curl response back: exit code → header dump → status,
    /// then the body file. Returns (status, body).
    fn read_response(&self, url: &str) -> miette::Result<(u16, Vec<u8>)> {
        let header_file = self.scratch.path().join("headers.txt");
        let body_file = self.scratch.path().join("body.bin");
        let head = std::fs::read_to_string(&header_file)
            .into_diagnostic()
            .wrap_err_with(|| format!("reading the rustfs response headers for {url}"))?;
        let status = parse_status(&head).ok_or_else(|| {
            miette::miette!("could not parse HTTP status from the rustfs response for {url}")
        })?;
        let resp = std::fs::read(&body_file)
            .into_diagnostic()
            .wrap_err_with(|| format!("reading the rustfs response body for {url}"))?;
        Ok((status, resp))
    }

    /// Run curl for one request and read the response back:
    /// (status, body). curl's implicit Host header carries exactly the
    /// signed authority; timeouts ride the oci.rs client's bounds.
    fn run_curl(
        &self,
        method: &str,
        key: &str,
        headers: Vec<String>,
        body: Option<&[u8]>,
    ) -> miette::Result<(u16, Vec<u8>)> {
        let argv = self.curl_argv(method, key, headers, body)?;
        let url = self.object_url(key);
        let out = self
            .runner
            .run(&argv)
            .map_err(|e| miette::miette!("curl not found: {e}"))?;
        let code = exit_code(&out);
        if code != 0 {
            bail!(
                "s3 {method} of {url} failed (curl exit {code}): {}",
                out.stderr.trim()
            );
        }
        self.read_response(&url)
    }

    /// One signed request; returns (status, response body).
    fn exec(&self, method: &str, key: &str, body: Option<&[u8]>) -> miette::Result<(u16, Vec<u8>)> {
        let headers = self.signed_headers(method, key, body.unwrap_or(b""))?;
        self.run_curl(method, key, headers, body)
    }

    /// PUT one object. Any non-2xx is a named error (the response body
    /// rides along when present). Re-PUT of identical content is
    /// idempotent — the payload hash is part of the signature.
    pub fn put(&self, key: &str, body: &[u8]) -> miette::Result<()> {
        let (status, resp) = self.exec("PUT", key, Some(body))?;
        if !(200..300).contains(&status) {
            bail!(
                "rustfs PUT of {key} returned HTTP {status}: {}",
                String::from_utf8_lossy(&resp).trim()
            );
        }
        Ok(())
    }

    /// GET one object: `Ok(None)` on 404 (the tree probes — an empty
    /// tree is a valid starting state), any other non-2xx a named error.
    pub fn get(&self, key: &str) -> miette::Result<Option<Vec<u8>>> {
        let (status, resp) = self.exec("GET", key, None)?;
        match status {
            200..=299 => Ok(Some(resp)),
            404 => Ok(None),
            _ => bail!(
                "rustfs GET of {key} returned HTTP {status}: {}",
                String::from_utf8_lossy(&resp).trim()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::RunnerOutput;
    use nau_infra::command::CommandRunner;
    use std::sync::{Arc, Mutex};

    /// The canned vector (computed independently with python
    /// hashlib/hmac over the exact canonical shapes this signer
    /// produces): one PUT, fixed date, fixed payload.
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const REGION: &str = "us-east-1";
    const ACCESS: &str = "AKIDEXAMPLE";
    const PAYLOAD_SHA: &str = "f2c2cea1426c9de0b1c3cb316d5fd93f9814e4f9a0bb6eec067b7f97a87d01f7";
    const EXPECTED_SIG: &str = "5eb099e57d57b372dbddf9e86cf62b40643207097467375a29b370908ac42998";

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
    fn parse_status_reads_the_first_response_line() {
        assert_eq!(parse_status("HTTP/1.1 200 OK\r\nx: y\r\n"), Some(200));
        assert_eq!(parse_status("HTTP/1.1 404 Not Found\r\n"), Some(404));
        assert_eq!(parse_status("garbage"), None);
        assert_eq!(parse_status(""), None);
    }

    /// Runner that emulates curl's file side effects and records each
    /// invocation: writes the header dump + response body the argv
    /// names, so the client's plumbing runs unmodified.
    struct FakeCurl {
        status: u16,
        calls: Arc<Mutex<Vec<Vec<String>>>>,
    }

    impl FakeCurl {
        fn new(status: u16) -> (FakeCurl, Arc<Mutex<Vec<Vec<String>>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            (
                FakeCurl {
                    status,
                    calls: calls.clone(),
                },
                calls,
            )
        }

        fn method_of(argv: &[String]) -> String {
            argv.iter()
                .position(|a| a == "-X")
                .and_then(|i| argv.get(i + 1).cloned())
                .unwrap_or_default()
        }
    }

    impl CommandRunner for FakeCurl {
        fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            let header_file = argv
                .iter()
                .position(|a| a == "-D")
                .and_then(|i| argv.get(i + 1))
                .expect("client always dumps headers");
            std::fs::write(header_file, format!("HTTP/1.1 {} X\r\n\r\n", self.status))?;
            let body_file = argv
                .iter()
                .position(|a| a == "-o")
                .and_then(|i| argv.get(i + 1))
                .expect("client always names an output file");
            std::fs::write(body_file, b"resp")?;
            Ok(RunnerOutput {
                code: 0,
                stdout: Vec::new(),
                stderr: String::new(),
            })
        }
    }

    fn test_target() -> S3Target {
        S3Target {
            endpoint: "https://s3.internal.example".into(),
            bucket: "nau-tree".into(),
            region: REGION.into(),
            access_key: ACCESS.into(),
            secret_key: SECRET.into(),
        }
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
}
