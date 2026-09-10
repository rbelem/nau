//! Shared subprocess command seam.
//!
//! One injectable adapter for every host tool shuttle shells out to. A
//! production caller passes the real [`RealRunner`], which executes the
//! exact argv it is handed ([`CommandRunner::run`]); hermetic tests inject
//! a fake that records invocations and answers from scripted state. The
//! trait exists so a pipeline can be driven end to end in-process, with no
//! host tooling and no real subprocess.
//!
//! [`CurlRunner`] is retained as the OCI client's alias for the real
//! runner — an all-`curl` pipeline that resolves response bodies from
//! `-D`/`-o` FILES (see the OCI client's fake contract) rather than
//! [`RunnerOutput::stdout`].

/// Result of one injected command run — the exit code plus captured
/// streams for callers that parse reader output (e.g. `sfdisk -J`).
#[derive(Debug, Clone)]
pub struct RunnerOutput {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

/// Injectable command seam (the [`RuntimeTools`][crate::runtime::RuntimeTools]
/// precedent): production uses [`RealRunner`] (a real subprocess); hermetic
/// tests inject fakes.
///
/// # Contract
///
/// `argv[0]` is the program name; the rest are its arguments, passed
/// verbatim. The runner returns the exit code and both captured streams —
/// no shell is involved, and stdout is not interpreted beyond what the
/// caller parses.
pub trait CommandRunner {
    fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput>;
}

/// The exit code a call site should report for [`RunnerOutput`]: the code
/// itself when the process exited, or `1` when it was signal-terminated
/// (mirroring `std::process::ExitStatus::code().unwrap_or(1)`, the historical
/// posture across the image pipeline).
pub fn exit_code(out: &RunnerOutput) -> i32 {
    if out.code < 0 {
        1
    } else {
        out.code
    }
}

/// The real runner: executes `argv[0]` with the exact remaining argv,
/// capturing stdout/stderr and the exit code (`-1` when the process was
/// signal-terminated and carried no code).
pub struct RealRunner;

impl CommandRunner for RealRunner {
    fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
        let (program, args) = argv.split_first().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty command argv")
        })?;
        let out = std::process::Command::new(program).args(args).output()?;
        Ok(RunnerOutput {
            code: out.status.code().unwrap_or(-1),
            stdout: out.stdout,
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

/// The OCI client's real runner: [`RealRunner`] under the historical name.
/// The OCI pipeline resolves response bodies from `-D`/`-o` files, which
/// the subprocess writes directly — [`RunnerOutput::stdout`] is unused
/// there.
pub use RealRunner as CurlRunner;
