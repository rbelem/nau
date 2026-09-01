//! Safe Rust wrapper over the Luau 0.663 type analyzer (`Luau.Analysis`).
//!
//! Ported from `analyzer-spike/src/lib.rs` (the proven recipe; see
//! `analyzer-spike/REPORT.md`). Built by `build.rs`: upstream C++ +
//! `shim/shuttle_shim.cpp` compiled with the `cc` crate, linked statically.
//!
//! Check-stage entry points:
//!   * [`check_definition`] / [`check_definition_file`] — check a shuttle
//!     definition in `--!strict` mode with the typed prelude bound (the six
//!     injected globals) and `require()` names resolved through the same
//!     allowlisted-root policy the eval subprocess uses.
//!   * [`check_once`] / [`Checker`] — raw analyzer access (spike parity).
//!
//! Strict-mode policy: definitions are checked in strict mode. A
//! `--!nonstrict` / `--!nocheck` hot-comment inside the definition *does*
//! override the host's strict default (upstream semantics: `Frontend::parse`
//! → `parseMode(hotcomments)` wins over the ConfigResolver — proven in the
//! spike's `in_source_mode_hotcomment_overrides_resolver_default` test). The
//! gate therefore trusts the author's mode choice for v1, which is
//! acceptable because the Rust-side schema validation runs regardless
//! (ADR-0010 Decision 3); rejecting mode hot-comments is future work
//! (REPORT.md recommendation 3).

use std::collections::{HashSet, VecDeque};
use std::ffi::{c_char, c_int, c_uint, c_void, CString};

/// The typed prelude loaded into every definition checker: binds the globals
/// the eval prelude injects at runtime (`snap`, `merge`, `pin`, `index`,
/// `app`, `image`). See the file header for the loose-typing rationale.
pub const PRELUDE_DEFS: &str = include_str!("shuttle-prelude.d.luau");

/// Upper bound on modules seeded from `require()` resolution per check.
/// Matches the scale of real corpora (templates + their deps); anything
/// beyond this fails closed as "Unknown require" diagnostics.
const MAX_SEED_MODULES: usize = 64;

/// One analyzer diagnostic, mapped from `Luau::TypeError`.
///
/// Positions are 1-based lines and columns; `end_col` is exclusive (the
/// convention `luau-analyze` prints). `message` is `Luau::toString(error)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub begin_line: u32,
    pub begin_col: u32,
    pub end_line: u32,
    pub end_col: u32,
    pub message: String,
}

/// 1-based source span of a diagnostic (`end_col` exclusive).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub begin_line: u32,
    pub begin_col: u32,
    pub end_line: u32,
    pub end_col: u32,
}

impl Diagnostic {
    pub fn span(&self) -> Span {
        Span {
            begin_line: self.begin_line,
            begin_col: self.begin_col,
            end_line: self.end_line,
            end_col: self.end_col,
        }
    }
}

// Raw FFI surface (see shim for semantics).
extern "C" {
    fn shuttle_checker_new(
        strict: c_int,
        prelude: *const c_char,
        prelude_len: usize,
    ) -> *mut c_void;
    fn shuttle_checker_free(checker: *mut c_void);
    fn shuttle_checker_seed_module(
        checker: *mut c_void,
        name: *const c_char,
        source: *const c_char,
        len: usize,
    );
    fn shuttle_checker_check(
        checker: *mut c_void,
        name: *const c_char,
        source: *const c_char,
        len: usize,
    ) -> *mut c_void;
    fn shuttle_error_count(result: *mut c_void) -> c_int;
    fn shuttle_error_at(
        result: *mut c_void,
        index: c_int,
        begin_line: *mut c_uint,
        begin_col: *mut c_uint,
        end_line: *mut c_uint,
        end_col: *mut c_uint,
        message: *mut *const c_char,
        message_len: *mut usize,
    ) -> c_int;
    fn shuttle_timeout_hits(result: *mut c_void) -> c_int;
    fn shuttle_check_result_free(result: *mut c_void);
}

/// Read a result handle into owned Rust diagnostics, then free the handle.
///
/// # Safety
/// `result` must be a valid handle from `shuttle_checker_check`, or null.
unsafe fn collect_diagnostics(result: *mut c_void) -> (Vec<Diagnostic>, u32) {
    let mut out = Vec::new();
    if result.is_null() {
        return (out, 0);
    }
    let count = shuttle_error_count(result);
    for i in 0..count {
        let (mut bl, mut bc, mut el, mut ec) = (0u32, 0u32, 0u32, 0u32);
        let mut msg: *const c_char = std::ptr::null();
        let mut msg_len: usize = 0;
        if shuttle_error_at(
            result,
            i,
            &mut bl,
            &mut bc,
            &mut el,
            &mut ec,
            &mut msg,
            &mut msg_len,
        ) != 0
        {
            break;
        }
        let bytes = std::slice::from_raw_parts(msg.cast::<u8>(), msg_len);
        out.push(Diagnostic {
            begin_line: bl,
            begin_col: bc,
            end_line: el,
            end_col: ec,
            message: String::from_utf8_lossy(bytes).into_owned(),
        });
    }
    let timeouts = shuttle_timeout_hits(result);
    shuttle_check_result_free(result);
    (out, timeouts.max(0) as u32)
}

/// A reusable analyzer instance: `Luau::Frontend` + registered, frozen builtin
/// globals + the mode fixed at construction.
///
/// A `Checker` is neither `Send` nor `Sync`: the C++ `Frontend` is
/// single-threaded state. Use one per thread (or per subprocess).
pub struct Checker {
    inner: *mut c_void,
}

impl Checker {
    /// Create an analyzer whose per-module mode is fixed (`--!strict` when
    /// `strict`) with no typed prelude. First construction parses and freezes
    /// the builtin type graph — this is the cold-start cost (see REPORT.md
    /// latency numbers).
    pub fn new(strict: bool) -> Checker {
        Checker::with_prelude(strict, "")
    }

    /// Create a strict analyzer with shuttle's typed prelude bound, so
    /// definitions using the injected globals (`snap`, `merge`, `pin`,
    /// `index`, `app`, `image`) check cleanly.
    pub fn for_definitions() -> Checker {
        Checker::with_prelude(true, PRELUDE_DEFS)
    }

    fn with_prelude(strict: bool, prelude: &str) -> Checker {
        let prelude_ptr = if prelude.is_empty() {
            std::ptr::null()
        } else {
            prelude.as_ptr().cast::<c_char>()
        };
        // SAFETY: returns a fresh handle or dies inside C++ (no error return
        // path); null-check on the Rust side. `prelude` is only read during
        // construction; the copied sources outlive the call.
        let inner = unsafe { shuttle_checker_new(strict as c_int, prelude_ptr, prelude.len()) };
        assert!(!inner.is_null(), "shuttle_checker_new returned null");
        Checker { inner }
    }

    /// Make an extra module visible to `require("name")` and to `readSource`
    /// (typed prelude, `pkgs/lib` templates). The source is copied into the
    /// C++ side.
    ///
    /// Module names cross as NUL-terminated C strings; sources are
    /// length-delimited (so sources may contain any bytes except NUL).
    pub fn seed_module(&mut self, name: &str, source: &str) {
        let c_name = CString::new(name).expect("module name contains NUL");
        // SAFETY: valid handle; C++ copies both strings (name via C-string
        // semantics, source via explicit length).
        unsafe {
            shuttle_checker_seed_module(
                self.inner,
                c_name.as_ptr(),
                source.as_ptr().cast::<c_char>(),
                source.len(),
            );
        }
    }

    /// Type-check `source` as module `name` in the checker's mode.
    /// Panics on FFI-contract violation (NUL byte), which is a caller bug.
    pub fn check(&mut self, name: &str, source: &str) -> Vec<Diagnostic> {
        let c_name = CString::new(name).expect("module name contains NUL");
        assert!(!source.contains('\0'), "source contains NUL byte");
        // SAFETY: valid handle; C++ copies both strings.
        let result = unsafe {
            shuttle_checker_check(
                self.inner,
                c_name.as_ptr(),
                source.as_ptr().cast::<c_char>(),
                source.len(),
            )
        };
        // SAFETY: fresh handle from the call above.
        unsafe { collect_diagnostics(result) }.0
    }

    /// Number of modules that hit the internal time limit in the last check
    /// (always 0 here — `moduleTimeLimitSec` is not set by the shim).
    pub fn timeout_hits(&self) -> u32 {
        // SAFETY: valid handle.
        unsafe { shuttle_timeout_hits(self.inner) }.max(0) as u32
    }
}

impl Drop for Checker {
    fn drop(&mut self) {
        // SAFETY: valid handle, runs exactly once.
        unsafe { shuttle_checker_free(self.inner) }
    }
}

/// One-shot cold check: constructs a full `Frontend` (builtin globals), runs
/// the check, and tears everything down. This is the per-subprocess cost.
pub fn check_once(name: &str, source: &str, strict: bool) -> Vec<Diagnostic> {
    let mut checker = Checker::new(strict);
    checker.check(name, source)
}

/// Check one shuttle definition: strict mode, typed prelude bound, and
/// constant `require()` names resolved (transitively) through the same
/// allowlisted-root policy as the eval subprocess
/// ([`crate::isolate::SourceResolver`]). Unresolvable requires stay unseeded
/// and fail closed as analyzer diagnostics at the use site.
pub fn check_definition(label: &str, source: &str) -> Vec<Diagnostic> {
    if source.contains('\0') {
        // A NUL byte cannot cross the length-delimited-but-NUL-checked FFI
        // contract; report it instead of panicking on author input.
        return vec![Diagnostic {
            begin_line: 1,
            begin_col: 1,
            end_line: 1,
            end_col: 0,
            message: "definition source contains a NUL byte; not type-checkable".to_string(),
        }];
    }
    let mut checker = Checker::for_definitions();
    seed_required_modules(&mut checker, label, source);
    checker.check(label, source)
}

/// [`check_definition`] for a file path. An unreadable file yields no
/// diagnostics here — the eval stage reports read failures uniformly for
/// both output modes of `shuttle check`.
pub fn check_definition_file(path: &str) -> Vec<Diagnostic> {
    match std::fs::read_to_string(path) {
        Ok(source) => check_definition(path, &source),
        Err(_) => Vec::new(),
    }
}

/// Seed every transitively required module reachable from `source` into the
/// checker, resolving names with the eval path's resolver (entry directory,
/// `pkgs/`, initialized input roots).
fn seed_required_modules(checker: &mut Checker, label: &str, source: &str) {
    let resolver = crate::isolate::SourceResolver::for_build(label);
    let mut seeded: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(source.to_string());
    let mut budget = MAX_SEED_MODULES;
    while let Some(src) = queue.pop_front() {
        for name in scan_requires(&src) {
            if !seeded.insert(name.clone()) {
                continue;
            }
            if budget == 0 {
                continue;
            }
            budget -= 1;
            if let Ok(module_source) = resolver.resolve(&name) {
                checker.seed_module(&name, &module_source);
                queue.push_back(module_source);
            }
            // Unresolvable names stay unseeded: Luau reports
            // "Unknown require" at the use site — the fail-closed gate.
        }
    }
}

/// Constant-string `require` arguments in `source`, in order of appearance.
/// Handles `require("x")`, `require 'x'`, and `require[[x]]`.
///
/// Only literal strings are returned — exactly the shape the analyzer's
/// `resolveModule` understands (`AstExprConstantString`); computed requires
/// are left unseeded and fail closed inside Luau itself. Known limitation:
/// the word `require` inside string/comment text can produce a
/// false-positive literal — harmless, since such a "name" never resolves to
/// a module and nothing gets seeded for it.
fn scan_requires(source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    while let Some(rel) = source[i..].find("require") {
        let start = i + rel;
        i = start + "require".len();
        if !word_boundary(bytes, start, i) {
            continue;
        }
        if let Some((name, next)) = require_arg(source, i) {
            names.push(name);
            i = next;
        }
    }
    names
}

/// True when `require` at `bytes[start..end]` is a whole word.
fn word_boundary(bytes: &[u8], start: usize, end: usize) -> bool {
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    (start == 0 || !ident(bytes[start - 1])) && (end >= bytes.len() || !ident(bytes[end]))
}

/// Parse the argument of a `require` call starting just past the keyword.
/// Handles `require("x")`, `require 'x'`, and `require[[x]]` (Lua's
/// string-call sugar). Returns the literal string and the position after it.
fn require_arg(source: &str, i: usize) -> Option<(String, usize)> {
    let b = source.as_bytes();
    let after_ws = skip_ws(b, i);
    let j = match b.get(after_ws) {
        Some(b'(') => skip_ws(b, after_ws + 1),
        Some(b'"' | b'\'') => after_ws,
        Some(b'[') if b.get(after_ws + 1) == Some(&b'[') => after_ws,
        _ => return None,
    };
    if j >= b.len() {
        return None;
    }
    string_literal_at(source, b, j)
}

/// Skip ASCII whitespace from `j`.
fn skip_ws(b: &[u8], mut j: usize) -> usize {
    while j < b.len() && b[j].is_ascii_whitespace() {
        j += 1;
    }
    j
}

/// Read a Lua string literal at `j` (`"..."`, `'...'`, or `[[...]]`).
/// Returns the literal contents and the position after the closing delimiter.
fn string_literal_at(source: &str, b: &[u8], j: usize) -> Option<(String, usize)> {
    match b[j] {
        quote @ (b'"' | b'\'') => {
            let start = j + 1;
            let end = start + source[start..].find(quote as char)?;
            Some((source[start..end].to_string(), end + 1))
        }
        b'[' if b.get(j + 1) == Some(&b'[') => {
            let start = j + 2;
            let end = start + source[start..].find("]]")?;
            Some((source[start..end].to_string(), end + 2))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEAN: &str = r#"
--!strict
local function snap(meta: {
    name: string,
    version: string,
}): { name: string, version: string }
    return { name = meta.name, version = meta.version }
end

snap { name = "hello", version = "2.10" }
"#;

    const TYPE_ERROR: &str = r#"
--!strict
local function snap(meta: {
    name: string,
    version: string,
}): { name: string, version: string }
    return { name = meta.name, version = meta.version }
end

snap { name = 42, version = "2.10" }
"#;

    // ── Raw analyzer (spike-parity tests) ──

    #[test]
    fn clean_definition_has_no_diagnostics() {
        let diags = check_once("clean", CLEAN, true);
        assert!(diags.is_empty(), "expected clean, got {diags:?}");
    }

    #[test]
    fn field_type_mismatch_is_structured() {
        let diags = check_once("mismatch", TYPE_ERROR, true);
        assert!(!diags.is_empty(), "expected at least one diagnostic");
        let first = &diags[0];
        assert!(first.begin_line >= 1, "positions are 1-based");
        assert!(
            first.message.contains("number") && first.message.contains("string"),
            "diagnostic should mention number vs string: {}",
            first.message
        );
    }

    // ── Typed prelude (injected globals) ──

    #[test]
    fn typed_prelude_binds_all_injected_globals() {
        // Every global the eval prelude injects must type-check cleanly in
        // strict mode — this is the corpus-shaped case.
        let def = r#"
return {
    default = snap {
        name = "hello",
        version = "2.10",
        apps = { hello = app { command = "bin/hello" } },
    },
    img = image { name = "sys", version = "1.0.0", base = pin("core22") },
    ref = index("hello"),
    merged = merge({ a = 1 }, { b = 2 }),
}
"#;
        let diags = check_definition("typed-prelude", def);
        assert!(
            diags.is_empty(),
            "injected globals must be bound: {diags:?}"
        );
    }

    #[test]
    fn misspelled_global_still_flagged_with_prelude() {
        // The prelude binds the six injected globals; anything else that is
        // not a Luau builtin stays an unknown global (the gate still fires).
        let diags = check_definition("typo", r#"return { default = snp { name = "x" } }"#);
        assert!(
            diags
                .iter()
                .any(|d| d.message.contains("Unknown global 'snp'")),
            "got: {diags:?}"
        );
    }

    // ── `name = 42`-style type error → spanned diagnostic ──

    #[test]
    fn annotated_field_type_error_is_spanned() {
        let def = r#"
local meta: { name: string, version: string } = {
    name = 42,
    version = "1.0",
}
return { default = snap(meta) }
"#;
        let diags = check_definition("name-42", def);
        assert!(!diags.is_empty(), "expected a type error for name = 42");
        let first = &diags[0];
        // Luau reports the conversion error on the table constructor's line
        // (line 2 — `local meta: ... = {`), not the offending property line.
        assert_eq!(
            first.begin_line, 2,
            "span must be 1-based and at the constructor"
        );
        assert!(first.begin_col >= 1, "columns are 1-based");
        assert!(
            first.message.contains("number") && first.message.contains("string"),
            "diagnostic should mention number vs string: {}",
            first.message
        );
    }

    // ── Cross-module require typing ──

    fn write_module(dir: &std::path::Path, name: &str, source: &str) -> String {
        std::fs::write(dir.join(name), source).unwrap();
        dir.join(name).to_str().unwrap().to_string()
    }

    #[test]
    fn require_composed_type_error_is_caught_across_modules() {
        let dir = tempfile::tempdir().unwrap();
        let label = write_module(
            dir.path(),
            "shuttle.lua",
            r#"
local tpl = require("apptpl")

return {
    default = snap {
        name = tpl.app({ command = 42 }).command,
        version = "1.0",
    },
}
"#,
        );
        write_module(
            dir.path(),
            "apptpl.lua",
            r#"
local M = {}
function M.app(opts: { command: string }): { command: string }
    return opts
end
return M
"#,
        );
        let diags = check_definition(&label, &std::fs::read_to_string(&label).unwrap());
        assert!(
            !diags.is_empty(),
            "type error must cross the module boundary"
        );
        assert!(
            diags
                .iter()
                .any(|d| d.message.contains("number") && d.message.contains("string")),
            "got: {diags:?}"
        );
    }

    #[test]
    fn require_composed_clean_definition_passes() {
        let dir = tempfile::tempdir().unwrap();
        let label = write_module(
            dir.path(),
            "shuttle.lua",
            r#"
local tpl = require("apptpl")

return {
    default = snap {
        name = tpl.app({ command = "bin/hello" }).command,
        version = "1.0",
    },
}
"#,
        );
        write_module(
            dir.path(),
            "apptpl.lua",
            r#"
local M = {}
function M.app(opts: { command: string }): { command: string }
    return opts
end
return M
"#,
        );
        let diags = check_definition(&label, &std::fs::read_to_string(&label).unwrap());
        assert!(diags.is_empty(), "expected clean, got {diags:?}");
    }

    #[test]
    fn unresolved_require_fails_closed() {
        // No module seeded under this name: the analyzer reports it instead
        // of silently passing (the fail-closed gate).
        let diags = check_definition("missing", r#"local x = require("nowhere") return x"#);
        assert!(
            diags.iter().any(|d| d.message.contains("Unknown require")),
            "got: {diags:?}"
        );
    }

    // ── require scanner ──

    #[test]
    fn scan_requires_finds_constant_strings() {
        let src = r#"
local a = require("base")
local b = require 'single'
local c = require([[long]])
local d = require("pkgs.lib.cli")
local e = myrequire(fn)
local f = require(variable)
local g = requireNotWord("nope")
"#;
        let names = scan_requires(src);
        let expected = ["base", "single", "long", "pkgs.lib.cli"];
        assert_eq!(names.len(), expected.len(), "got: {names:?}");
        for (got, want) in names.iter().zip(expected) {
            assert_eq!(got, want);
        }
    }
}
