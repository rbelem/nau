
    use super::*;
    use nau_infra::command::RunnerOutput;
    use std::sync::Mutex;

    /// Serializes the env-mutating tests (process-global state).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// A canned curl: answers with the given exit code and the -w
    /// status line on stdout.
    struct FakeCurl {
        code: i32,
        status_line: &'static str,
    }

    impl nau_infra::command::CommandRunner for FakeCurl {
        fn run(&self, _argv: &[String]) -> std::io::Result<RunnerOutput> {
            Ok(RunnerOutput {
                code: self.code,
                stdout: self.status_line.as_bytes().to_vec(),
                stderr: String::new(),
            })
        }
    }


mod binary_probe;
