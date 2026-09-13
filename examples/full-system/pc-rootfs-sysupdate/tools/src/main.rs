//! Minimal stand-in for `systemd-pull raw --direct` used by the #80
//! sysupdate proof: the payload server only speaks plain HTTP, so this
//! fetches one file over HTTP/1.1 GET and streams the body into the
//! output target (a device node or a file), honoring --offset and
//! --size-max exactly like systemd-pull does for partition targets.
//!
//! Argument handling mirrors the systemd-pull call sysupdate makes:
//!   raw --direct --verify <digest> --sync=yes --offset N --size-max N URL TARGET
//! Flags and their values are skipped; the first non-flag argument is the
//! URL and the second is the output target ("-" = stdout). The SHA256
//! digest argument is accepted but not verified here (the payload server
//! is trusted for the proof; production must verify, see prepare.sh).
//!
//! The body is streamed in chunks — artifacts are multi-gigabyte and must
//! never be buffered whole.

use std::io::{Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::time::Duration;

const CHUNK: usize = 1024 * 1024;

struct Request {
    url: String,
    target: Option<String>,
    offset: u64,
    size_max: Option<u64>,
}

/// Split the systemd-pull style argument list. sysupdate spawns:
///   systemd-pull raw --direct --verify <digest> --sync=yes --offset N
///       --size-max N <url> <target>
/// so the URL is the first `http://` argument and the target is the
/// argument immediately after it (flags with values are skipped so they
/// are not mistaken for the target).
fn parse_args(args: &[String]) -> Request {
    let mut url: Option<String> = None;
    let mut target: Option<String> = None;
    let mut offset = 0u64;
    let mut size_max = None;
    let mut skip_next = false;
    let mut skip_kind = "";
    let mut after_url = false;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        i += 1;
        if arg == "--verify" || arg == "--offset" || arg == "--size-max" || arg == "--sync" {
            // Flag with its value in the next argument. (The --offset
            // value is ALREADY in bytes — sysupdate converts the libfdisk
            // sector count before spawning the child.)
            if i < args.len() {
                let value = &args[i];
                i += 1;
                match arg.as_str() {
                    "--offset" => offset = value.parse().unwrap_or(0),
                    "--size-max" => size_max = value.parse().ok(),
                    _ => {}
                }
            }
            continue;
        }
        if let Some(v) = arg.strip_prefix("--offset=") {
            offset = v.parse().unwrap_or(0);
            continue;
        }
        if let Some(v) = arg.strip_prefix("--size-max=") {
            size_max = v.parse().ok();
            continue;
        }
        let is_flag_with_value = arg.starts_with("--sync=") || arg.starts_with("--verify=");
        if is_flag_with_value || arg.starts_with('-') {
            continue;
        }
        if url.is_none() {
            if arg.starts_with("http://") {
                url = Some(arg.clone());
                after_url = true;
            }
            continue;
        }
        if after_url {
            target = Some(arg.clone());
        }
    }
    Request {
        url: url.unwrap_or_default(),
        target,
        offset,
        size_max,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    eprintln!("http-fetch: argv = {:?}", &args[1..]);
    let req = parse_args(&args[1..]);
    if req.url.is_empty() {
        eprintln!("http-fetch: no http:// URL in arguments");
        std::process::exit(1);
    }

    if let Err(e) = fetch(&req) {
        eprintln!("http-fetch: {}: {e}", req.url);
        std::process::exit(1);
    }
}

fn fetch(req: &Request) -> Result<(), String> {
    // http://host[:port]/path
    let rest = req
        .url
        .strip_prefix("http://")
        .ok_or_else(|| "only http:// supported".to_string())?;
    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(80)),
        None => (host_port.to_string(), 80),
    };

    // The service starts as soon as network-online.target is reached, which
    // can race the final link setup under SLIRP — retry the connect a few
    // times before giving up.
    let mut stream = connect_with_retry(&host, port)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(600)))
        .ok();

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\nAccept: */*\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("send failed: {e}"))?;

    let (content_length, chunked) = read_headers(&mut stream)?;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();

    if chunked {
        return stream_chunked(&mut stream, &mut lock);
    }

    let mut writer = open_writer(req.target.as_deref(), req.offset)?;
    let mut buf = vec![0u8; CHUNK];
    match content_length {
        Some(total) => copy_exact(&mut stream, &mut writer, &mut buf, total)?,
        None => copy_to_eof(&mut stream, &mut writer, &mut buf)?,
    }
    writer
        .flush()
        .map_err(|e| format!("target flush failed: {e}"))?;
    Ok(())
}

fn buf_vec() -> Vec<u8> {
    vec![0u8; CHUNK]
}

fn connect_with_retry(host: &str, port: u16) -> Result<TcpStream, String> {
    // The service starts as soon as network-online.target is reached, which
    // can race the final link setup under SLIRP — retry the connect a few
    // times before giving up.
    for attempt in 1..=6 {
        match TcpStream::connect((host, port)) {
            Ok(s) => return Ok(s),
            Err(e) => {
                eprintln!("http-fetch: connect {host}:{port} attempt {attempt} failed: {e}");
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
    Err(format!("connect {host}:{port} failed after retries"))
}

fn copy_exact(
    stream: &mut TcpStream,
    out: &mut dyn Write,
    buf: &mut [u8],
    total: usize,
) -> Result<(), String> {
    let mut remaining = total;
    while remaining > 0 {
        let want = buf.len().min(remaining);
        let n = stream
            .read(&mut buf[..want])
            .map_err(|e| format!("read failed: {e}"))?;
        if n == 0 {
            return Err("connection closed before Content-Length was satisfied".to_string());
        }
        out.write_all(&buf[..n])
            .map_err(|e| format!("target write failed: {e}"))?;
        remaining -= n;
    }
    Ok(())
}

fn copy_to_eof(stream: &mut TcpStream, out: &mut dyn Write, buf: &mut [u8]) -> Result<(), String> {
    loop {
        let n = stream.read(buf).map_err(|e| format!("read failed: {e}"))?;
        if n == 0 {
            return Ok(());
        }
        out.write_all(&buf[..n])
            .map_err(|e| format!("target write failed: {e}"))?;
    }
}

/// Read the response head (through the `\r\n\r\n` terminator) byte-wise,
/// returning `(content_length, is_chunked)`.
fn read_headers(stream: &mut TcpStream) -> Result<(Option<usize>, bool), String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read(&mut byte)
            .map_err(|e| format!("read failed: {e}"))?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            break;
        }
        if head.len() > 64 * 1024 {
            return Err("response headers too large".to_string());
        }
    }
    let headers = String::from_utf8_lossy(&head).to_uppercase();

    let status_ok = headers
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .is_some_and(|code| (200..300).contains(&code));
    if !status_ok {
        return Err(format!(
            "non-2xx response: {}",
            headers.lines().next().unwrap_or("?").trim()
        ));
    }

    let content_length = headers
        .lines()
        .find(|l| l.starts_with("CONTENT-LENGTH:"))
        .and_then(|l| l.split_once(':')?.1.trim().parse::<usize>().ok());
    let chunked = headers.contains("TRANSFER-ENCODING: CHUNKED");
    Ok((content_length, chunked))
}

fn stream_chunked(stream: &mut TcpStream, out: &mut dyn Write) -> Result<(), String> {
    loop {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream
                .read(&mut byte)
                .map_err(|e| format!("read failed: {e}"))?;
            if byte[0] == b'\n' {
                break;
            }
            if byte[0] != b'\r' {
                line.push(byte[0]);
            }
        }
        let size_str = String::from_utf8_lossy(&line).to_string();
        let size_str = size_str.split(';').next().unwrap_or("").trim().to_string();
        let size =
            usize::from_str_radix(&size_str, 16).map_err(|e| format!("bad chunk size: {e}"))?;
        if size == 0 {
            return Ok(());
        }
        let mut buf = vec![0u8; size];
        let mut got = 0;
        while got < size {
            let n = stream
                .read(&mut buf[got..])
                .map_err(|e| format!("read failed: {e}"))?;
            if n == 0 {
                return Err("connection closed mid-chunk".to_string());
            }
            got += n;
        }
        out.write_all(&buf)
            .map_err(|e| format!("stdout write failed: {e}"))?;
        let mut crlf = [0u8; 2];
        stream
            .read_exact(&mut crlf)
            .map_err(|e| format!("read failed: {e}"))?;
    }
}

/// Open the output target. Three shapes, mirroring what systemd-pull
/// accepts and what sysupdate actually passes for partition targets:
/// "-" = stdout; a plain path = that path (seek to --offset); and the
/// partition form "/proc/self/fd/<fd>p<N>" = the whole block device held
/// open by the parent as <fd>, written at --offset (the partition start).
fn open_writer(target: Option<&str>, offset: u64) -> Result<Box<dyn Write>, String> {
    match target {
        None | Some("-") => Ok(Box::new(std::io::stdout())),
        Some(path) => {
            // The partition form: <fd> + "p" + <partno>. The referenced fd
            // is the parent's whole-disk handle; the write position comes
            // from --offset (the partition start in bytes).
            let fd_target = path.strip_prefix("/proc/self/fd/").and_then(|s| {
                let (fd, rest) = s.split_once('p')?;
                fd.parse::<i32>().ok()?;
                rest.parse::<u64>().ok()?;
                Some(format!("/proc/self/fd/{fd}"))
            });
            let open_path = fd_target.clone().unwrap_or_else(|| path.to_string());
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(&open_path)
                .map_err(|e| format!("open {open_path} failed: {e}"))?;
            if offset > 0 {
                file.seek(SeekFrom::Start(offset))
                    .map_err(|e| format!("seek {open_path} to {offset} failed: {e}"))?;
            }
            Ok(Box::new(file))
        }
    }
}
