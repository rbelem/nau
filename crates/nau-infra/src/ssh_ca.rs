//! SSH CA material primitives (issue #326 PR 9): the on-disk CA paths,
//! the identity introspection ([`inspect`]), and the ssh-keygen
//! fingerprint machinery. Mechanical primitives only — the issuance
//! CEREMONY ([`create_ca_keypair`], the named refusals, the trust-root
//! policy) stays in `nau-trust::ca`, which re-exports everything here so
//! every pre-existing `crate::ca::` path keeps resolving. The pgp
//! precedent: packet primitives to infra, policy stays with the domain.

use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};

use crate::command::{exit_code, CommandRunner};

/// The CA keypair directory under the ceremony home:
/// `~/.config/nau/ca/`.
pub fn ca_dir(home: &Path) -> PathBuf {
    home.join(".config").join("nau").join("ca")
}

/// The CA private key: `<home>/.config/nau/ca/ca` (0600).
pub fn ca_secret_path(home: &Path) -> PathBuf {
    ca_dir(home).join("ca")
}

/// The CA public key: `<home>/.config/nau/ca/ca.pub`.
pub fn ca_public_path(home: &Path) -> PathBuf {
    ca_dir(home).join("ca.pub")
}

/// Operator-visible identity of a host CA: the raw public line (what a
/// `@cert-authority` entry embeds), the ssh-keygen SHA256 fingerprint
/// (what workers entries will carry), and whether the private half is
/// on disk (issuance needs it; a pin-only consumer does not).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaInfo {
    pub public_line: String,
    pub fingerprint: String,
    pub secret_present: bool,
}

/// Load the host CA's identity, `Ok(None)` when neither half exists (the
/// ceremony has not run). A private half without its public half is a
/// named error — the keypair is incomplete and every downstream consumer
/// needs the public line; fail closed rather than report a half-root.
pub fn inspect(runner: &dyn CommandRunner, home: &Path) -> miette::Result<Option<CaInfo>> {
    let secret = ca_secret_path(home);
    let public = ca_public_path(home);
    match (secret.exists(), public.exists()) {
        (false, false) => Ok(None),
        (true, false) => Err(miette::miette!(
            "host CA private key exists at {} but its public half {} is missing — the \
             keypair is incomplete; refusing to report it",
            secret.display(),
            public.display()
        )),
        (secret_present, true) => {
            let text = std::fs::read_to_string(&public)
                .into_diagnostic()
                .wrap_err_with(|| format!("reading {}", public.display()))?;
            Ok(Some(CaInfo {
                public_line: text.trim().to_string(),
                fingerprint: key_fingerprint(runner, &public)?,
                secret_present,
            }))
        }
    }
}

/// The ssh-keygen SHA256 fingerprint of a public key file — the stable,
/// short identity a `known_hosts` comment or a workers entry carries.
/// `ssh-keygen -lf` behind the command seam; a nonzero exit (not a key
/// file, truncated, corrupt) is a named error naming the path.
pub fn key_fingerprint(runner: &dyn CommandRunner, public_path: &Path) -> miette::Result<String> {
    let argv = vec![
        "ssh-keygen".to_string(),
        "-lf".to_string(),
        public_path.to_string_lossy().into_owned(),
    ];
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("ca: cannot run ssh-keygen (is openssh installed?): {e}"))?;
    if exit_code(&out) != 0 {
        return Err(miette::miette!(
            "ca: {} is not a usable public key file (ssh-keygen -lf failed: {})",
            public_path.display(),
            out.stderr.trim()
        ));
    }
    parse_fingerprint_line(&String::from_utf8_lossy(&out.stdout)).wrap_err_with(|| {
        format!(
            "parsing ssh-keygen fingerprint of {}",
            public_path.display()
        )
    })
}

/// The fingerprint is the second whitespace field of `ssh-keygen -lf`'s
/// single line: `256 SHA256:base64… comment (ED25519)`.
fn parse_fingerprint_line(output: &str) -> miette::Result<String> {
    let line = output.lines().next().unwrap_or("");
    let fingerprint = line
        .split_whitespace()
        .nth(1)
        .filter(|f| f.starts_with("SHA256:"))
        .ok_or_else(|| {
            miette::miette!(
                "ssh-keygen fingerprint output is not the expected `bits SHA256:…` shape: {line:?}"
            )
        })?;
    Ok(fingerprint.to_string())
}

/// The known SSH host-key types (the published-half grammar and the
/// legacy-pin shape check).
pub const HOST_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
    "rsa-sha2-256",
    "rsa-sha2-512",
];

/// The published public-key-line grammar: `<keytype> <base64> [comment]`,
/// usable verbatim as a known_hosts key. This is the GUEST's published
/// host-key half (the publish receive surface and the issue-path defense
/// re-check), not a config pin — config pins are CA fingerprints only.
/// Moved DOWN from `nau-chart::lua` (issue #326 PR 9): pure ssh
/// public-key-line grammar, no Lua machinery; the chart re-exports it
/// for its pin-shape checks.
pub fn validate_public_key_line(raw: &str) -> miette::Result<()> {
    let mut parts = raw.split_whitespace();
    let key_type = parts.next();
    let key = parts.next();
    let comment = parts.next();
    if parts.next().is_some() {
        return Err(miette::miette!(
            "expected '<keytype> <base64> [comment]', got '{raw}'"
        ));
    }
    match (key_type, key, comment) {
        (Some(k), Some(key), comment) if HOST_KEY_TYPES.contains(&k) => {
            let comment_ok = comment.is_none_or(|c| !c.starts_with('-') && !c.contains(char::is_whitespace));
            let key_ok = key.len() >= 16 && key.bytes().all(|b| is_base64_char(b) || b == b'=');
            if key_ok && comment_ok {
                return Ok(());
            }
            Err(miette::miette!(
                "'{k}' is a known host-key type, but the entry is not a valid public-key line: '{raw}'"
            ))
        }
        (Some(k), ..) if !HOST_KEY_TYPES.contains(&k) => Err(miette::miette!(
            "unknown host-key type '{k}' (expected ssh-ed25519, ecdsa-sha2-nistp*, ssh-rsa, or rsa-sha2-*)"
        )),
        _ => Err(miette::miette!(
            "expected '<keytype> <base64> [comment]', got '{raw}'"
        )),
    }
}

/// One base64 character (standard alphabet, no padding).
pub fn is_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/'
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::RunnerOutput;
    use std::io;
    use std::sync::{Arc, Mutex};

    /// Shape-valid throwaway ed25519 material — no crypto, like the
    /// provision fakes. Two distinct fixtures so the fingerprinting
    /// fake can answer per-content.
    const FIXTURE_A_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkvsDFv9XrohqXsJvKK8dFbGFe5vN3fGcLgoW8cR3UxQ nau-host-ca";
    const FIXTURE_A_FPR: &str = "SHA256:FAKEAAAA";
    const FIXTURE_B_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOrZfC0rKJdBX8mUJIKdClRNKdVKmShWU8rjHfDrBKUM nau-host-ca";
    const FIXTURE_B_FPR: &str = "SHA256:FAKEBBBB";

    fn ok_out(stdout: &str) -> RunnerOutput {
        RunnerOutput {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: String::new(),
        }
    }

    /// Plays `ssh-keygen`: answers `-lf <path>` from the matching
    /// fixture fingerprint, and records every argv.
    #[derive(Clone)]
    struct FakeKeygen {
        calls: Arc<Mutex<Vec<Vec<String>>>>,
        fail_after: Arc<Mutex<Option<usize>>>,
    }

    impl FakeKeygen {
        fn new() -> Self {
            FakeKeygen {
                calls: Arc::new(Mutex::new(Vec::new())),
                fail_after: Arc::new(Mutex::new(None)),
            }
        }

        /// Script the (n+1)-th call to fail — used to prove refusal
        /// paths against a failing subprocess.
        fn fail_after(&self, n: usize) {
            *self.fail_after.lock().unwrap() = Some(n);
        }
    }

    impl CommandRunner for FakeKeygen {
        fn run(&self, argv: &[String]) -> io::Result<RunnerOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            let fail = self.fail_after.lock().unwrap();
            if let Some(n) = *fail {
                if self.calls.lock().unwrap().len() > n {
                    return Ok(RunnerOutput {
                        code: 1,
                        stdout: vec![],
                        stderr: "scripted ssh-keygen failure".into(),
                    });
                }
            }
            drop(fail);
            match argv[0].as_str() {
                "ssh-keygen" => {
                    if let Some(i) = argv.iter().position(|a| a == "-lf") {
                        let path = &argv[i + 1];
                        let text = std::fs::read_to_string(path).unwrap();
                        let fpr = if text.contains(FIXTURE_B_PUB) {
                            FIXTURE_B_FPR
                        } else {
                            FIXTURE_A_FPR
                        };
                        return Ok(ok_out(&fpr_out(fpr)));
                    }
                    panic!("unexpected ssh-keygen mode in test: {argv:?}")
                }
                other => panic!("unexpected program in test: {other}"),
            }
        }
    }

    /// A runner that must NEVER be called — refusal paths prove no
    /// subprocess runs.
    struct NeverRunner;
    impl CommandRunner for NeverRunner {
        fn run(&self, argv: &[String]) -> io::Result<RunnerOutput> {
            panic!("no subprocess may run on a refusal path: {argv:?}")
        }
    }

    fn fpr_out(fpr: &str) -> String {
        format!("256 {fpr} nau-host-ca (ED25519)\n")
    }

    #[test]
    fn paths_follow_the_documented_contract() {
        let home = Path::new("/somewhere/home");
        assert_eq!(
            ca_dir(home),
            PathBuf::from("/somewhere/home/.config/nau/ca")
        );
        assert_eq!(
            ca_secret_path(home),
            PathBuf::from("/somewhere/home/.config/nau/ca/ca")
        );
        assert_eq!(
            ca_public_path(home),
            PathBuf::from("/somewhere/home/.config/nau/ca/ca.pub")
        );
    }

    #[test]
    fn inspect_is_none_on_an_empty_ceremony_home() {
        let dir = tempfile::tempdir().unwrap();
        let found = inspect(&NeverRunner, dir.path()).unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn inspect_refuses_a_secret_without_its_public_half() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(ca_dir(dir.path())).unwrap();
        std::fs::write(ca_secret_path(dir.path()), "private").unwrap();
        let err = inspect(&NeverRunner, dir.path()).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("incomplete"), "{msg}");
        assert!(
            msg.contains(&ca_public_path(dir.path()).display().to_string()),
            "names the missing public half: {msg}"
        );
    }

    #[test]
    fn inspect_reports_a_public_only_chain_honestly() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(ca_dir(dir.path())).unwrap();
        std::fs::write(ca_public_path(dir.path()), format!("{FIXTURE_A_PUB}\n")).unwrap();
        let info = inspect(&FakeKeygen::new(), dir.path()).unwrap().unwrap();
        assert!(!info.secret_present);
        assert_eq!(info.public_line, FIXTURE_A_PUB);
    }

    #[test]
    fn fingerprint_parses_the_second_field_and_demands_the_sha256_shape() {
        assert_eq!(
            parse_fingerprint_line(&fpr_out("SHA256:AbCd+/12")).unwrap(),
            "SHA256:AbCd+/12"
        );
        let err = parse_fingerprint_line("256 deadbeef nau-host-ca (ED25519)").unwrap_err();
        assert!(format!("{err:?}").contains("SHA256:"), "{err:?}");
        let err = parse_fingerprint_line("").unwrap_err();
        assert!(format!("{err:?}").contains("SHA256:"), "{err:?}");
    }

    #[test]
    fn fingerprint_failure_names_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.pub");
        std::fs::write(&path, "not a key\n").unwrap();
        let fake = FakeKeygen::new();
        fake.fail_after(0);
        let err = key_fingerprint(&fake, &path).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("not a usable public key file"), "{msg}");
        assert!(msg.contains(&path.display().to_string()), "{msg}");
    }
}
