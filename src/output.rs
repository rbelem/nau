//! Output formatting — colored status, progress bars, and structured JSON output.
//!
//! The `OutputMode` enum controls whether the CLI prints human-friendly colored
//! output (default) or structured JSON (`--json`). All status messages flow
//! through this module so switching modes is transparent to callers.

use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;
use serde::Serialize;

// ── Output mode ──

/// CLI output mode: normal (colored TTY) or JSON (structured).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputMode {
    Normal,
    Json,
}

// ── Global output mode (set once from CLI args) ──

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

static JSON_MODE: AtomicBool = AtomicBool::new(false);
static BUILD_RESULTS: Mutex<Option<Vec<BuildResultJson>>> = Mutex::new(None);
static DEP_RESULTS: Mutex<Option<Vec<DepResultJson>>> = Mutex::new(None);
static ORDER_RESULTS: Mutex<Option<Vec<OrderResultJson>>> = Mutex::new(None);

/// Set the output mode globally.
pub fn set_mode(json: bool) {
    JSON_MODE.store(json, Ordering::SeqCst);
}

/// True if JSON output mode is active.
pub fn is_json() -> bool {
    JSON_MODE.load(Ordering::SeqCst)
}

// ── Colored status helpers (Normal mode only) ──

/// Print a success message with green checkmark.
pub fn ok(msg: impl std::fmt::Display) {
    if !is_json() {
        eprintln!("  {} {}", "✓".green().bold(), msg);
    }
}

/// Print an error message with red X.
pub fn err(msg: impl std::fmt::Display) {
    if !is_json() {
        eprintln!("  {} {}", "✗".red().bold(), msg);
    }
}

/// Print a warning with yellow triangle.
pub fn warn(msg: impl std::fmt::Display) {
    if !is_json() {
        eprintln!("  {} {}", "⚠".yellow().bold(), msg);
    }
}

/// Print an info message with blue info icon.
pub fn info(msg: impl std::fmt::Display) {
    if !is_json() {
        eprintln!("  {} {}", "ℹ".cyan().bold(), msg);
    }
}

/// Print a regular status line (no icon).
pub fn status(msg: impl std::fmt::Display) {
    if !is_json() {
        eprintln!("  {}", msg);
    }
}

// ── Progress bar helpers ──

/// Create a spinner with the given message.
pub fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message(msg.to_string());
    pb
}

/// Create a determinate progress bar for downloads.
pub fn progress_bar(len: u64, msg: &str) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.cyan} {msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("##-"),
    );
    pb.set_message(msg.to_string());
    pb
}

/// Finish a spinner as successful.
pub fn finish_ok(pb: &ProgressBar, msg: &str) {
    pb.finish_with_message(format!("{} {}", "✓".green(), msg));
}

/// Finish a spinner as failed.
pub fn finish_err(pb: &ProgressBar, msg: &str) {
    pb.finish_with_message(format!("{} {}", "✗".red(), msg));
}

// ── JSON output structs ──

/// One built snap result for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct BuildResultJson {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub filename: String,
    pub sha256: Option<String>,
}

/// One dependency entry for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct DepResultJson {
    pub name: String,
    pub requires: Vec<String>,
    pub kind: String, // "direct" or "transitive"
}

/// Build order entry for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct OrderResultJson {
    pub name: String,
    pub kind: String, // "direct" or "transitive"
}

/// Top-level JSON build output.
#[derive(Debug, Clone, Serialize)]
pub struct BuildOutputJson {
    pub command: String, // "build", "image", "deps", "order"
    pub results: Vec<BuildResultJson>,
}

/// Top-level JSON deps output.
#[derive(Debug, Clone, Serialize)]
pub struct DepsOutputJson {
    pub command: String,
    pub results: Vec<DepResultJson>,
}

/// Top-level JSON order output.
#[derive(Debug, Clone, Serialize)]
pub struct OrderOutputJson {
    pub command: String,
    pub results: Vec<OrderResultJson>,
}

// ── Accumulators for JSON output ──

pub fn record_build_result(result: BuildResultJson) {
    if let Ok(mut guard) = BUILD_RESULTS.lock() {
        let vec = guard.get_or_insert_with(Vec::new);
        vec.push(result);
    }
}

pub fn record_dep_result(result: DepResultJson) {
    if let Ok(mut guard) = DEP_RESULTS.lock() {
        let vec = guard.get_or_insert_with(Vec::new);
        vec.push(result);
    }
}

pub fn record_order_result(result: OrderResultJson) {
    if let Ok(mut guard) = ORDER_RESULTS.lock() {
        let vec = guard.get_or_insert_with(Vec::new);
        vec.push(result);
    }
}

/// Flush accumulated JSON results to stdout.
pub fn flush_json(cmd: &str) {
    if !is_json() {
        return;
    }

    let output: String = match cmd {
        "build" | "image" => {
            if let Ok(mut guard) = BUILD_RESULTS.lock() {
                let results = guard.take().unwrap_or_default();
                serde_json::to_string_pretty(&BuildOutputJson {
                    command: cmd.to_string(),
                    results,
                })
                .unwrap_or_default()
            } else {
                String::new()
            }
        }
        "deps" => {
            if let Ok(mut guard) = DEP_RESULTS.lock() {
                let results = guard.take().unwrap_or_default();
                serde_json::to_string_pretty(&DepsOutputJson {
                    command: cmd.to_string(),
                    results,
                })
                .unwrap_or_default()
            } else {
                String::new()
            }
        }
        "order" => {
            if let Ok(mut guard) = ORDER_RESULTS.lock() {
                let results = guard.take().unwrap_or_default();
                serde_json::to_string_pretty(&OrderOutputJson {
                    command: cmd.to_string(),
                    results,
                })
                .unwrap_or_default()
            } else {
                String::new()
            }
        }
        _ => String::new(),
    };

    if !output.is_empty() {
        println!("{}", output);
    }
}

/// Clear all accumulated results.
pub fn clear() {
    if let Ok(mut guard) = BUILD_RESULTS.lock() {
        *guard = None;
    }
    if let Ok(mut guard) = DEP_RESULTS.lock() {
        *guard = None;
    }
    if let Ok(mut guard) = ORDER_RESULTS.lock() {
        *guard = None;
    }
}

// ── Doctor JSON ──

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheckJson {
    pub name: String,
    pub status: String, // "ok", "missing"
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorOutputJson {
    pub command: String,
    pub all_ok: bool,
    pub checks: Vec<DoctorCheckJson>,
}
