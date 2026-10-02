//! The coordinator SSH host CA (ADR-0045 amendment, #283 decided): the
//! one ed25519 keypair that signs short-lived host certificates for every
//! provisioned worker. A DIFFERENT trust root from the update-manifest
//! signing key (`nau key` ceremony, ADR-0024 §4) — the CA anchors
//! host identity (`@cert-authority`, one pinned line per operator), the
//! signing key anchors update manifests — so it never shares a keychain
//! with it. A `ca.pub` dropped into `~/.config/nau/keys/` would be
//! misread by [`crate::sign::Keychain::load_dir`] as a manifest trust
//! anchor; the dedicated `~/.config/nau/ca/` directory keeps the two
//! roots apart by construction.
//!
//! Ceremony (joins ADR-0024's — the amendment records the join):
//!
//! - `nau ca keygen` — mint the keypair via `ssh-keygen` behind the
//!   [`CommandRunner`][nau_infra::command::CommandRunner] seam (the repo's
//!   subprocess convention — every provisioning-side ssh-keygen call
//!   rides it — no new crates). Refuses to overwrite an existing CA
//!   without `--force`: replacing the high-value trust root is a
//!   deliberate act, never an accident.
//! - `nau ca list` — introspect: presence per half, the public line,
//!   and the ssh-keygen SHA256 fingerprint (the identity workers entries
//!   will carry once #295 sub-task 4 lands).
//!
//! Storage contract (tests pin it):
//!
//! - `~/.config/nau/ca/ca`     — private half, 0600 (ssh-keygen);
//!   what `ssh-keygen -s` consumes at issuance time (sub-task 3).
//! - `~/.config/nau/ca/ca.pub` — public half; the future
//!   `@cert-authority` line source (sub-task 4).
//! - the directory itself is 0700.

use std::path::Path;

use miette::{IntoDiagnostic, WrapErr};

use nau_infra::command::{exit_code, CommandRunner};

// The CA material primitives (paths, introspection, fingerprinting)
// moved DOWN into `nau_infra::ssh_ca` (issue #326 PR 9, the pgp
// precedent: primitives to infra, ceremony policy stays with the
// domain). Re-exported so every trust-internal caller and the root
// `crate::ca` shim keep resolving byte-identically.
pub use nau_infra::ssh_ca::{
    ca_dir, ca_public_path, ca_secret_path, inspect, key_fingerprint, CaInfo,
};

/// The keypair comment ssh-keygen stamps on both halves — the marker
/// provisioning output greps for when wiring pins by hand.
pub const CA_COMMENT: &str = "nau-host-ca";

/// Mint the host CA keypair under `home` via `ssh-keygen`. Creates
/// `~/.config/nau/ca/` (0700) when absent. An existing CA is a named
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

#[cfg(test)]
mod tests {
    use super::*;
    use nau_infra::command::RunnerOutput;
    use std::io;
    use std::sync::{Arc, Mutex};

    /// Shape-valid throwaway ed25519 material — no crypto, like the
    /// provision fakes. Two distinct fixtures so a `--force` mint is
    /// observably different from the first.
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
        format!("256 {fpr} nau-host-ca (ED25519)\n")
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
        assert!(pub_text.contains("nau-host-ca"));
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
}
