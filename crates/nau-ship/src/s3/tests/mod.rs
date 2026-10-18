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

mod sigv4_signature;
