//! The coordinator SSH host CA (ADR-0045 amendment, #283 decided): the
//! one ed25519 keypair that signs short-lived host certificates for every
//! provisioned worker. A DIFFERENT trust root from the update-manifest
//! signing key (`shuttle key` ceremony, ADR-0024 §4) — the CA anchors
//! host identity (`@cert-authority`, one pinned line per operator), the
//! signing key anchors update manifests — so it never shares a keychain
//! with it. A `ca.pub` dropped into `~/.config/shuttle/keys/` would be
//! misread by [`crate::sign::Keychain::load_dir`] as a manifest trust
//! anchor; the dedicated `~/.config/shuttle/ca/` directory keeps the two
//! roots apart by construction.
//!
//! Ceremony (joins ADR-0024's — the amendment records the join):
//!
//! - `shuttle ca keygen` — mint the keypair via `ssh-keygen` behind the
//!   [`CommandRunner`][crate::command::CommandRunner] seam (the repo's
//!   subprocess convention — `mint_host_keypair` precedent — no new
//!   crates). Refuses to overwrite an existing CA without `--force`:
//!   replacing the high-value trust root is a deliberate act, never an
//!   accident.
//! - `shuttle ca list` — introspect: presence per half, the public line,
//!   and the ssh-keygen SHA256 fingerprint (the identity workers entries
//!   will carry once #295 sub-task 4 lands).
//!
//! Storage contract (tests pin it):
//!
//! - `~/.config/shuttle/ca/ca`     — private half, 0600 (ssh-keygen);
//!   what `ssh-keygen -s` consumes at issuance time (sub-task 3).
//! - `~/.config/shuttle/ca/ca.pub` — public half; the future
//!   `@cert-authority` line source (sub-task 4).
//! - the directory itself is 0700.

use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};

use crate::command::{exit_code, CommandRunner};

/// The keypair comment ssh-keygen stamps on both halves — the marker
/// provisioning output greps for when wiring pins by hand.
pub const CA_COMMENT: &str = "shuttle-host-ca";

/// The CA keypair directory under the ceremony home:
/// `~/.config/shuttle/ca/`.
pub fn ca_dir(home: &Path) -> PathBuf {
    home.join(".config").join("shuttle").join("ca")
}

/// The CA private key: `<home>/.config/shuttle/ca/ca` (0600).
pub fn ca_secret_path(home: &Path) -> PathBuf {
    ca_dir(home).join("ca")
}

/// The CA public key: `<home>/.config/shuttle/ca/ca.pub`.
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

/// Mint the host CA keypair under `home` via `ssh-keygen`. Creates
/// `~/.config/shuttle/ca/` (0700) when absent. An existing CA is a named
/// refusal unless `force` — and `force` removes both stale halves BEFORE
/// the mint so a failed regeneration cannot leave a mixed keypair.
pub fn create_ca_keypair(
    runner: &dyn CommandRunner,
    home: &Path,
    force: bool,
) -> miette::Result<CaInfo> {
    let secret = ca_secret_path(home);
    let public = ca_public_path(home);
    if !force && (secret.exists() || public.exists()) {
        return Err(miette::miette!(
            "host CA already exists at {} — refusing to overwrite (the CA is the high-value \
             trust root; pass --force to replace it deliberately)",
            secret.display()
        ));
    }
    if force {
        // Remove both halves first: a mint that fails after a partial
        // overwrite must not pair the old public half with the new
        // secret (or vice versa).
        let _ = std::fs::remove_file(&secret);
        let _ = std::fs::remove_file(&public);
    }

    let dir = ca_dir(home);
    std::fs::create_dir_all(&dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .into_diagnostic()
            .wrap_err_with(|| format!("chmod 0700 {}", dir.display()))?;
    }

    let secret_str = secret.to_string_lossy().into_owned();
    let argv = vec![
        "ssh-keygen".to_string(),
        "-t".to_string(),
        "ed25519".to_string(),
        "-N".to_string(),
        String::new(),
        "-C".to_string(),
        CA_COMMENT.to_string(),
        "-f".to_string(),
        secret_str,
    ];
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("ca: cannot run ssh-keygen (is openssh installed?): {e}"))?;
    if exit_code(&out) != 0 {
        return Err(miette::miette!(
            "ca: ssh-keygen failed: {}",
            out.stderr.trim()
        ));
    }

    let public_line = std::fs::read_to_string(&public)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading minted {}", public.display()))?;
    let public_line = public_line.trim().to_string();
    let fingerprint = key_fingerprint(runner, &public)?;
    Ok(CaInfo {
        public_line,
        fingerprint,
        secret_present: true,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::RunnerOutput;
    use std::io;
    use std::sync::{Arc, Mutex};

    /// Shape-valid throwaway ed25519 material — no crypto, like the
    /// provision fakes. Two distinct fixtures so a `--force` mint is
    /// observably different from the first.
    const FIXTURE_A_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkvsDFv9XrohqXsJvKK8dFbGFe5vN3fGcLgoW8cR3UxQ shuttle-host-ca";
    const FIXTURE_A_FPR: &str = "SHA256:FAKEAAAA";
    const FIXTURE_B_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOrZfC0rKJdBX8mUJIKdClRNKdVKmShWU8rjHfDrBKUM shuttle-host-ca";
    const FIXTURE_B_FPR: &str = "SHA256:FAKEBBBB";

    fn ok_out(stdout: &str) -> RunnerOutput {
        RunnerOutput {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: String::new(),
        }
    }

    /// Plays `ssh-keygen`: writes the fixture keypair at `-f <path>`,
    /// answers `-lf <path>` from the matching fixture fingerprint, and
    /// records every argv. Fails the run when the script says so.
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

        /// Script the (n+1)-th call to fail — used to prove refusal and
        /// cleanup paths against a failing subprocess.
        fn fail_after(&self, n: usize) {
            *self.fail_after.lock().unwrap() = Some(n);
        }

        fn argvs(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandRunner for FakeKeygen {
        fn run(&self, argv: &[String]) -> io::Result<RunnerOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            let mut fail = self.fail_after.lock().unwrap();
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
                    let i = argv.iter().position(|a| a == "-f").expect("-f");
                    let path = argv[i + 1].clone();
                    // The current call is already in the log: the first
                    // mint is fixture A, every later mint fixture B.
                    let (priv_text, pub_text) = if self.calls.lock().unwrap().len() >= 3 {
                        ("B-priv", format!("{FIXTURE_B_PUB}\n"))
                    } else {
                        ("A-priv", format!("{FIXTURE_A_PUB}\n"))
                    };
                    std::fs::write(&path, priv_text).unwrap();
                    std::fs::write(format!("{path}.pub"), pub_text).unwrap();
                    Ok(ok_out(""))
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
        format!("256 {fpr} shuttle-host-ca (ED25519)\n")
    }

    #[test]
    fn paths_follow_the_documented_contract() {
        let home = Path::new("/somewhere/home");
        assert_eq!(
            ca_dir(home),
            PathBuf::from("/somewhere/home/.config/shuttle/ca")
        );
        assert_eq!(
            ca_secret_path(home),
            PathBuf::from("/somewhere/home/.config/shuttle/ca/ca")
        );
        assert_eq!(
            ca_public_path(home),
            PathBuf::from("/somewhere/home/.config/shuttle/ca/ca.pub")
        );
    }

    #[test]
    fn keygen_mints_via_ssh_keygen_with_the_ceremony_argv() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeKeygen::new();
        let info = create_ca_keypair(&fake, dir.path(), false).unwrap();
        assert_eq!(info.fingerprint, FIXTURE_A_FPR);
        assert_eq!(info.public_line, FIXTURE_A_PUB);
        assert!(info.secret_present);

        let argvs = fake.argvs();
        assert_eq!(argvs.len(), 2, "mint + -lf");
        let mint = &argvs[0];
        assert_eq!(mint[0], "ssh-keygen");
        assert!(mint.windows(2).any(|w| w == ["-t", "ed25519"]));
        assert!(mint.windows(2).any(|w| w == ["-N", ""]));
        assert!(mint.windows(2).any(|w| w == ["-C", CA_COMMENT]));
        let i = mint.iter().position(|a| a == "-f").unwrap();
        assert_eq!(
            Path::new(&mint[i + 1]),
            ca_secret_path(dir.path()),
            "-f targets the contract secret path"
        );
        assert!(ca_secret_path(dir.path()).exists());
        assert!(ca_public_path(dir.path()).exists());
    }

    #[test]
    fn keygen_creates_the_ca_directory_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        create_ca_keypair(&FakeKeygen::new(), dir.path(), false).unwrap();
        let mode = std::fs::metadata(ca_dir(dir.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "the high-value root lives behind 0700");
    }

    #[test]
    fn keygen_refuses_an_existing_ca_without_force_and_runs_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(ca_dir(dir.path())).unwrap();
        std::fs::write(ca_public_path(dir.path()), "existing\n").unwrap();

        let err = create_ca_keypair(&NeverRunner, dir.path(), false).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("already exists"), "{msg}");
        assert!(msg.contains("--force"), "{msg}");
        assert!(
            msg.contains(&ca_secret_path(dir.path()).display().to_string()),
            "names the CA location: {msg}"
        );
    }

    #[test]
    fn force_mints_a_fresh_pair_over_both_stale_halves() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeKeygen::new();
        let first = create_ca_keypair(&fake, dir.path(), false).unwrap();
        assert_eq!(first.fingerprint, FIXTURE_A_FPR);

        let second = create_ca_keypair(&fake, dir.path(), true).unwrap();
        assert_eq!(second.fingerprint, FIXTURE_B_FPR, "force regenerates");
        assert_eq!(second.public_line, FIXTURE_B_PUB);
        let pub_text = std::fs::read_to_string(ca_public_path(dir.path())).unwrap();
        assert!(pub_text.contains("shuttle-host-ca"));
    }

    #[test]
    fn a_failed_force_mint_leaves_no_mixed_keypair() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeKeygen::new();
        fake.fail_after(2); // mint ok, -lf ok, second mint FAILS
        create_ca_keypair(&fake, dir.path(), false).unwrap();
        let err = create_ca_keypair(&fake, dir.path(), true).unwrap_err();
        assert!(format!("{err:?}").contains("scripted ssh-keygen failure"));
        // Both halves were removed before the failing mint: no stale
        // public half survives to pair with a never-written secret.
        assert!(
            !ca_public_path(dir.path()).exists(),
            "stale public half must not survive a failed force mint"
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
        let err = parse_fingerprint_line("256 deadbeef shuttle-host-ca (ED25519)").unwrap_err();
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
