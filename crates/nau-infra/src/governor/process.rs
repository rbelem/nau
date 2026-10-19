use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Output};
use std::sync::atomic::{AtomicBool, Ordering};

use super::state::process_state;

static WARNED_JOIN: AtomicBool = AtomicBool::new(false);

pub fn spawn(mut command: Command) -> io::Result<Child> {
    super::state::ensure_auto_configured()?;
    let joined = attach_if_configured(&mut command);
    let child = command.spawn();
    drop(command);
    let child = child?;
    if let Some(joined) = joined {
        joined.finish();
    }
    Ok(child)
}

pub fn status(mut command: Command) -> io::Result<ExitStatus> {
    super::state::ensure_auto_configured()?;
    let joined = attach_if_configured(&mut command);
    let status = command.status();
    drop(command);
    let status = status?;
    if let Some(joined) = joined {
        joined.finish();
    }
    Ok(status)
}

pub fn output(mut command: Command) -> io::Result<Output> {
    super::state::ensure_auto_configured()?;
    let joined = attach_if_configured(&mut command);
    let output = command.output();
    drop(command);
    let output = output?;
    if let Some(joined) = joined {
        joined.finish();
    }
    Ok(output)
}

pub(crate) fn attach_if_configured(command: &mut Command) -> Option<JoinReport> {
    let cgroup = {
        let state = process_state();
        let configured = state.configured.as_ref()?;
        if configured.degrade.is_some()
            || configured.limit == nau_core::resource_limit::ResourceLimit::Off
        {
            return None;
        }
        configured.cgroup.as_ref()?.clone()
    };
    let procs = match CString::new(cgroup.join("cgroup.procs").as_os_str().as_bytes()) {
        Ok(path) => path,
        Err(_) => {
            warn_join(&cgroup);
            return None;
        }
    };
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        warn_join(&cgroup);
        return None;
    }
    let reader = unsafe { File::from_raw_fd(fds[0]) };
    let writer = unsafe { File::from_raw_fd(fds[1]) };
    let read_fd = reader.as_raw_fd();
    unsafe {
        use std::os::unix::process::CommandExt;
        // Fork copy-on-write prevents an atomic in the child from notifying the parent.
        command.pre_exec(move || {
            libc::close(read_fd);
            if !join_cgroup(&procs) {
                let marker = [1u8];
                libc::write(writer.as_raw_fd(), marker.as_ptr().cast(), marker.len());
            }
            Ok(())
        });
    }
    Some(JoinReport { reader, cgroup })
}

pub(crate) struct JoinReport {
    reader: File,
    cgroup: PathBuf,
}

impl JoinReport {
    pub(crate) fn finish(mut self) {
        let mut marker = [0u8; 1];
        if !matches!(self.reader.read(&mut marker), Ok(0)) {
            warn_join(&self.cgroup);
        }
    }
}

fn warn_join(cgroup: &std::path::Path) {
    if !WARNED_JOIN.swap(true, Ordering::Relaxed) {
        eprintln!(
            "resource limit could not join {}; the child continues uncapped",
            cgroup.display()
        );
    }
}

fn join_cgroup(procs: &CStr) -> bool {
    let fd = unsafe { libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return false;
    }
    let joined = write_current_pid(fd);
    let closed = unsafe { libc::close(fd) } == 0;
    joined && closed
}

fn write_current_pid(fd: libc::c_int) -> bool {
    let pid = unsafe { libc::getpid() };
    if pid <= 0 {
        return false;
    }
    let mut buffer = [0u8; 12];
    let mut offset = buffer.len() - 1;
    buffer[offset] = b'\n';
    let mut value = pid as u32;
    loop {
        offset -= 1;
        buffer[offset] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let bytes = &buffer[offset..];
    let mut written = 0;
    while written < bytes.len() {
        let count =
            unsafe { libc::write(fd, bytes[written..].as_ptr().cast(), bytes.len() - written) };
        if count <= 0 {
            return false;
        }
        written += count as usize;
    }
    true
}
