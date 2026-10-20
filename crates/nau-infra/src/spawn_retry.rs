//! Retrying a spawn the kernel answered with `ETXTBSY` (issue #8).
//!
//! Linux refuses to `exec` an inode that still carries a writer
//! (`deny_write_access`), so a caller that writes a file, chmods it and
//! execs it a moment later can lose the race against the filesystem's own
//! writeback on hosts that defer the close. That is what the kernel
//! reports as `Text file busy (os error 26)`, and the standard remedy is a
//! short retry: the writer is not held by anybody by then, so the second
//! look almost always wins.
//!
//! The retry lives here, in the mechanism leaf, so the doctor's probe and
//! the secret `exec` source share one policy instead of each growing its
//! own loop. The wait is bounded so a genuinely busy binary still fails
//! fast, and only `ETXTBSY` is retried: a missing or non-executable
//! program will not heal by waiting.

use std::io;
use std::ffi::OsStr;
use std::process::Output;
use std::time::Duration;

/// Exec-probe budget: three tries with a short gap covers the
/// write/chmod/exec race window without hiding a real failure.
pub const ATTEMPTS: u32 = 3;
/// First backoff; a retry waits its attempt number times this.
pub const BACKOFF: Duration = Duration::from_millis(100);

/// The `ETXTBSY` errno (Linux `Text file busy`).
const ETXTBSY: i32 = 26;

/// Whether `e` is the kernel answering "this file still has a writer".
///
/// [`io::ErrorKind::ExecutableFileBusy`] is the portable spelling; the
/// raw errno is the backstop for any std build that has not mapped 26.
pub fn is_text_file_busy(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::ExecutableFileBusy || e.raw_os_error() == Some(ETXTBSY)
}

/// Run `spawn` until it stops answering `ETXTBSY`, under the default
/// policy ([`ATTEMPTS`], [`BACKOFF`]).
pub fn spawn<T>(spawn: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    retry(ATTEMPTS, BACKOFF, spawn)
}

/// [`spawn`] for a program plus its argv — the shape both production call
/// sites (the doctor's probe, the secret `exec` source) take.
pub fn output<S: AsRef<OsStr>>(program: impl AsRef<OsStr>, args: &[S]) -> io::Result<Output> {
    spawn(|| std::process::Command::new(&program).args(args).output())
}

/// [`spawn`] with the budget and backoff open: the shape a test can pin
/// without waiting (a zero backoff makes the retries instant) and a
/// caller can tighten.
///
/// The operation is a closure rather than a built [`std::process::Command`]
/// because `Command` is consumed by its own spawn and cannot be replayed;
/// a closure rebuilds it per attempt. A non-`ETXTBSY` error is returned on
/// the first attempt, unretried.
pub fn retry<T>(
    attempts: u32,
    backoff: Duration,
    mut spawn: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    let mut attempt = 1u32;
    loop {
        match spawn() {
            Err(e) if is_text_file_busy(&e) && attempt < attempts => {
                std::thread::sleep(backoff * attempt);
                attempt += 1;
            }
            other => return other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};
    use std::path::Path;

    /// A spawn that fails `busy` times with a synthesized `ETXTBSY` and
    /// then answers `Ok("ran")`.
    fn scripted(busy: u32, calls: &std::cell::Cell<u32>) -> impl FnMut() -> io::Result<&'static str> + '_ {
        move || {
            calls.set(calls.get() + 1);
            if calls.get() <= busy {
                Err(Error::from_raw_os_error(ETXTBSY))
            } else {
                Ok("ran")
            }
        }
    }

    #[test]
    fn retries_until_the_spawn_succeeds() {
        let calls = std::cell::Cell::new(0);
        let out = retry(5, Duration::ZERO, scripted(2, &calls)).unwrap();
        assert_eq!(out, "ran");
        assert_eq!(calls.get(), 3, "two busy attempts, then the real one");
    }

    #[test]
    fn gives_up_after_the_attempt_budget() {
        let calls = std::cell::Cell::new(0);
        let err = retry(4, Duration::ZERO, scripted(u32::MAX, &calls)).unwrap_err();
        assert_eq!(calls.get(), 4, "the budget is the ceiling, not a hint");
        assert!(is_text_file_busy(&err), "the last failure surfaces: {err}");
    }

    #[test]
    fn a_non_busy_error_is_not_retried() {
        let calls = std::cell::Cell::new(0);
        let err = retry(5, Duration::ZERO, || {
            calls.set(calls.get() + 1);
            Err::<(), _>(Error::from(ErrorKind::NotFound))
        })
        .unwrap_err();
        assert_eq!(calls.get(), 1, "waiting cannot heal a missing program");
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }

    /// The class itself, reproduced locally: the kernel really answers
    /// `ETXTBSY` while a writer is open on the script, and the retry wins
    /// once that writer closes. The failure assertion rides the first
    /// attempt's errno, so this cannot pass on a filesystem that never
    /// produces the error.
    #[test]
    fn a_real_writer_held_across_exec_is_retried() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("counting-provider");
        let mut writer = std::fs::File::create(&script).unwrap();
        writer.write_all(b"#!/bin/sh\nprintf ok\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        // The writer stays open for the first attempt (the runner's race),
        // and closes only after that attempt failed, so the retry sees the
        // state every ordinary caller sees.
        let mut writer = Some(writer);
        let errnos = std::cell::RefCell::new(Vec::new());
        let out = retry(3, Duration::ZERO, || {
            let run = std::process::Command::new(&script).output();
            if let Err(e) = &run {
                errnos.borrow_mut().push(e.raw_os_error());
            }
            drop(writer.take());
            run
        })
        .unwrap();

        assert_eq!(
            errnos.into_inner().as_slice(),
            [Some(ETXTBSY)],
            "attempt 1 must be the kernel's own ETXTBSY"
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout), "ok");
        assert!(Path::new(&script).is_file());
    }
}
