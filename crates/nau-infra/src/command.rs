//! Shared subprocess command seam.
//!
//! One injectable adapter for every host tool nau shells out to. A
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

/// Injectable command seam (the `RuntimeTools` precedent from the root
/// runtime module): production uses [`RealRunner`] (a real subprocess); hermetic
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
        let mut command = std::process::Command::new(program);
        command.args(args);
        Self::run_command(command)
    }
}

impl RealRunner {
    /// Run `path` with `args` through the seam. Widened over `AsRef` for the
    /// retry helper's shape, which takes a program plus its argv as
    /// `AsRef<OsStr>`; the governor attach lives in [`Self::run_command`],
    /// so every path through here is covered.
    pub(crate) fn run_path<S: AsRef<std::ffi::OsStr>>(
        path: impl AsRef<std::path::Path>,
        args: &[S],
    ) -> std::io::Result<RunnerOutput> {
        let mut command = std::process::Command::new(path.as_ref());
        command.args(args);
        Self::run_command(command)
    }

    fn run_command(mut command: std::process::Command) -> std::io::Result<RunnerOutput> {
        let joined = crate::governor::attach_if_configured(&mut command);
        let output = command.output();
        drop(command);
        let out = output?;
        if let Some(joined) = joined {
            joined.finish();
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_maps_a_signal_termination_to_1() {
        assert_eq!(
            exit_code(&RunnerOutput {
                code: -1,
                stdout: vec![],
                stderr: String::new()
            }),
            1
        );
        assert_eq!(
            exit_code(&RunnerOutput {
                code: -9,
                stdout: vec![],
                stderr: String::new()
            }),
            1
        );
        assert_eq!(
            exit_code(&RunnerOutput {
                code: 0,
                stdout: vec![],
                stderr: String::new()
            }),
            0
        );
        assert_eq!(
            exit_code(&RunnerOutput {
                code: 7,
                stdout: vec![],
                stderr: String::new()
            }),
            7
        );
    }

    #[test]
    fn real_runner_rejects_an_empty_argv() {
        let err = RealRunner.run(&[]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn real_runner_captures_streams_and_the_exit_code() {
        let argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            "echo out; echo err >&2; exit 3".to_string(),
        ];
        let out = RealRunner.run(&argv).unwrap();
        assert_eq!(out.code, 3);
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "out");
        assert_eq!(out.stderr.trim(), "err");
    }

    #[test]
    fn real_runner_reports_a_missing_program_as_io_error() {
        let argv = vec!["nau-no-such-binary-zz9x".to_string()];
        assert!(RealRunner.run(&argv).is_err());
    }
}
