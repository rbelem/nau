//! Safe Rust wrapper over the Luau 0.663 type analyzer (`Luau.Analysis`).
//!
//! Ported from `analyzer-spike/src/lib.rs` (the proven recipe; see
//! `analyzer-spike/REPORT.md`). Built by `build.rs`: upstream C++ +
//! `shim/shuttle_shim.cpp` compiled with the `cc` crate, linked statically.
//!
//! Check-stage entry points:
//!   * [`check_definition_file`] — the production gate: the strict-analyzer
//!     stage runs in the dedicated `__check-worker` subprocess (same
//!     containment shape as the eval stage, src/isolate.rs), with the typed
//!     prelude bound (the six injected globals) and `require()` names
//!     resolved parent-side through the same allowlisted-root policy the
//!     eval subprocess uses.
//!   * [`check_definition`] / [`check_definition_with_limit`] — in-process
//!     checks for tests only (deterministic time-limit injection); the
//!     production path never runs the analyzer on untrusted sources
//!     in-process.
//!   * [`check_once`] / [`Checker`] — raw analyzer access (spike parity).
//!
//! Strict-mode policy: definitions are checked in strict mode. Mode
//! hot-comments that would downgrade the gate (`--!nonstrict` /
//! `--!nocheck`) are rejected with a named diagnostic before analysis runs
//! (REPORT.md recommendation 3): upstream semantics give the source's
//! hot-comments priority over the host's strict default (`Frontend::parse`
//! → `parseMode(hotcomments)` wins over the ConfigResolver — proven in the
//! spike's `in_source_mode_hotcomment_overrides_resolver_default` test), so
//! without the rejection an author could voluntarily downgrade the gate
//! with one comment line. Strictness is a host decision; `--!strict` stays
//! legal.
//!
//! Wall-clock bound: every definition check runs under a generous analyzer
//! time limit ([`ANALYZER_TIME_LIMIT_SECS`], wired to upstream's
//! `FrontendOptions::moduleTimeLimitSec`). A module that exceeds the bound
//! is aborted by the solver and reported as a single
//! `analysis timed out after Ns` diagnostic — `shuttle check` fails closed
//! (the eval stage never sees a source the analyzer could not finish). The
//! check worker also carries a parent-side wall-clock killer
//! (src/isolate.rs) as the backstop, mirroring the eval stage's.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::ffi::{c_char, c_double, c_int, c_uint, c_void, CString};

use serde::{Deserialize, Serialize};

/// The typed prelude loaded into every definition checker: binds the globals
/// the eval prelude injects at runtime (`snap`, `merge`, `pin`, `index`,
/// `app`, `image`). See the file header for the loose-typing rationale.
pub const PRELUDE_DEFS: &str = include_str!("shuttle-prelude.d.luau");

/// Upper bound on modules seeded from `require()` resolution per check.
/// Matches the scale of real corpora (templates + their deps); anything
/// beyond this fails closed as "Unknown require" diagnostics.
const MAX_SEED_MODULES: usize = 64;

/// Wall-clock bound on the strict-analyzer stage of `shuttle check`, in
/// seconds (analyzer-spike REPORT.md §5 deferred `moduleTimeLimitSec`; now
/// wired). Generous by design: a cold in-process check of a corpus-scale
/// definition is ~1.4ms, so 10s only fires on pathological sources — the
/// eval stage stays the real resource bound (subprocess + rlimits,
/// src/isolate.rs), this one keeps the gate itself finite.
pub const ANALYZER_TIME_LIMIT_SECS: f64 = 10.0;

/// One analyzer diagnostic, mapped from `Luau::TypeError`.
///
/// Positions are 1-based lines and columns; `end_col` is exclusive (the
/// convention `luau-analyze` prints). `message` is `Luau::toString(error)`.
///
/// Serializes so diagnostics can cross the `__check-worker` protocol
/// (newline-JSON, src/isolate.rs) unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        // NaN = no limit; anything else is the literal bound in seconds
        // (0.0 is a valid, immediately-expiring bound — the test hook).
        module_time_limit_secs: c_double,
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
    fn shuttle_locate_output_key(
        source: *const c_char,
        source_len: usize,
        key: *const c_char,
        key_len: usize,
        begin_line: *mut c_uint,
        begin_col: *mut c_uint,
        end_line: *mut c_uint,
        end_col: *mut c_uint,
    ) -> c_int;
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
    /// The per-module wall-clock bound handed to the C++ constructor
    /// (`None` = unbounded), kept so timeout diagnostics can name it.
    time_limit_secs: Option<f64>,
}

impl Checker {
    /// Create an analyzer whose per-module mode is fixed (`--!strict` when
    /// `strict`) with no typed prelude. First construction parses and freezes
    /// the builtin type graph — this is the cold-start cost (see REPORT.md
    /// latency numbers).
    pub fn new(strict: bool) -> Checker {
        Checker::with_prelude(strict, "", None)
    }

    /// Create a strict analyzer with shuttle's typed prelude bound, so
    /// definitions using the injected globals (`snap`, `merge`, `pin`,
    /// `index`, `app`, `image`) check cleanly.
    pub fn for_definitions() -> Checker {
        Checker::for_definitions_with_limit(Some(ANALYZER_TIME_LIMIT_SECS))
    }

    /// [`Checker::for_definitions`] with an injectable per-module time
    /// bound: `None` disables the limit, `Some(0.0)` expires immediately
    /// (the deterministic hook tests use). This is the constructor the
    /// `__check-worker` child uses with the bound shipped in the request.
    pub fn for_definitions_with_limit(time_limit_secs: Option<f64>) -> Checker {
        Checker::with_prelude(true, PRELUDE_DEFS, time_limit_secs)
    }

    fn with_prelude(strict: bool, prelude: &str, time_limit_secs: Option<f64>) -> Checker {
        let prelude_ptr = if prelude.is_empty() {
            std::ptr::null()
        } else {
            prelude.as_ptr().cast::<c_char>()
        };
        // NaN is the C++ "no limit" sentinel; `Some(0.0)` crosses as a
        // literal (immediately-expiring) bound.
        let limit_arg = time_limit_secs.unwrap_or(f64::NAN);
        // SAFETY: returns a fresh handle or dies inside C++ (no error return
        // path); null-check on the Rust side. `prelude` is only read during
        // construction; the copied sources outlive the call.
        let inner =
            unsafe { shuttle_checker_new(strict as c_int, prelude_ptr, prelude.len(), limit_arg) };
        assert!(!inner.is_null(), "shuttle_checker_new returned null");
        Checker {
            inner,
            time_limit_secs,
        }
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
        self.check_collect(name, source).0
    }

    /// Like [`Checker::check`], but honors the checker's time limit: when any
    /// module hit the bound, the (partial, unreliable) result set is replaced
    /// by a single `analysis timed out after Ns` diagnostic — the fail-closed
    /// shape `shuttle check` consumes. Unbounded checkers behave like
    /// [`Checker::check`].
    pub fn check_bounded(&mut self, name: &str, source: &str) -> Vec<Diagnostic> {
        let (diagnostics, timeouts) = self.check_collect(name, source);
        if timeouts == 0 {
            return diagnostics;
        }
        let after = match self.time_limit_secs {
            Some(secs) => format!(" after {secs}s"),
            None => String::new(),
        };
        vec![Diagnostic {
            begin_line: 1,
            begin_col: 1,
            end_line: 1,
            end_col: 0,
            message: format!("analysis timed out{after}"),
        }]
    }

    /// Run the FFI check and read the result handle back.
    fn check_collect(&mut self, name: &str, source: &str) -> (Vec<Diagnostic>, u32) {
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
        unsafe { collect_diagnostics(result) }
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

/// Check one shuttle definition in-process: strict mode, typed prelude
/// bound, [`ANALYZER_TIME_LIMIT_SECS`] wall-clock bound, and constant
/// `require()` names resolved (transitively) through the same
/// allowlisted-root policy as the eval subprocess
/// ([`crate::isolate::SourceResolver`]). Unresolvable requires stay
/// unseeded and fail closed as analyzer diagnostics at the use site.
///
/// Test entry point: the production gate is
/// [`check_definition_file`] (worker-subprocess backed).
pub fn check_definition(label: &str, source: &str) -> Vec<Diagnostic> {
    check_definition_with_limit(label, source, Some(ANALYZER_TIME_LIMIT_SECS))
}

/// [`check_definition`] with an injectable time bound: `None` disables the
/// limit, `Some(0.0)` expires immediately (the deterministic hook tests use).
pub fn check_definition_with_limit(
    label: &str,
    source: &str,
    time_limit_secs: Option<f64>,
) -> Vec<Diagnostic> {
    let sources = match check_inputs(label, source) {
        Ok(sources) => sources,
        Err(d) => return vec![d],
    };
    let mut checker = Checker::with_prelude(true, PRELUDE_DEFS, time_limit_secs);
    for (name, module_source) in &sources {
        checker.seed_module(name, module_source);
    }
    checker.check_bounded(label, source)
}

/// The production strict-analyzer gate: like [`check_definition_with_limit`]
/// but the analysis runs in the bounded `__check-worker` subprocess
/// (`crate::isolate::run_check`), mirroring the eval stage's containment.
/// Every contained child failure (timeout, crash, protocol garbage) comes
/// back as a fail-closed diagnostic — this function never panics on a
/// hostile source, and only parent-side infrastructure failures surface as
/// diagnostics carrying the spawn/bookkeeping error.
pub fn check_definition_in_worker(label: &str, source: &str) -> Vec<Diagnostic> {
    let request = match check_inputs(label, source) {
        Ok(sources) => crate::isolate::CheckRequest {
            label: label.to_string(),
            entry: source.to_string(),
            sources,
            time_limit_secs: Some(ANALYZER_TIME_LIMIT_SECS),
        },
        Err(d) => return vec![d],
    };
    match crate::isolate::run_check(&request) {
        Ok(diagnostics) => diagnostics,
        Err(e) => vec![Diagnostic {
            begin_line: 1,
            begin_col: 1,
            end_line: 1,
            end_col: 0,
            message: format!("analyzer worker failed: {e}"),
        }],
    }
}

/// [`check_definition_in_worker`] for a file path. An unreadable file yields
/// no diagnostics here — the eval stage reports read failures uniformly for
/// both output modes of `shuttle check`.
pub fn check_definition_file(path: &str) -> Vec<Diagnostic> {
    match std::fs::read_to_string(path) {
        Ok(source) => check_definition_in_worker(path, &source),
        Err(_) => Vec::new(),
    }
}

/// Shared front-end for every check path (`__check-worker` production gate
/// and the in-process test entries): NUL guard, hot-comment rejection, and
/// parent-side transitive require resolution. One implementation — the
/// paths cannot diverge. `Err` is a rejection diagnostic (gate fails closed
/// before any analysis runs).
fn check_inputs(label: &str, source: &str) -> Result<BTreeMap<String, String>, Diagnostic> {
    if source.contains('\0') {
        // A NUL byte cannot cross the length-delimited-but-NUL-checked FFI
        // contract; report it instead of panicking on author input.
        return Err(Diagnostic {
            begin_line: 1,
            begin_col: 1,
            end_line: 1,
            end_col: 0,
            message: "definition source contains a NUL byte; not type-checkable".to_string(),
        });
    }
    if let Some(d) = mode_downgrade_diagnostic(source) {
        return Err(d);
    }
    Ok(collect_required_sources(label, source))
}

/// Transitively resolve every constant `require()` reachable from `source`
/// through the eval path's resolver (entry directory, `pkgs/`, initialized
/// input roots), returning name → source. Modules the resolver cannot serve
/// stay out of the map and fail closed as "Unknown require" diagnostics at
/// the use site.
fn collect_required_sources(label: &str, source: &str) -> BTreeMap<String, String> {
    let resolver = crate::isolate::SourceResolver::for_build(label);
    let mut sources = BTreeMap::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(source.to_string());
    let mut budget = MAX_SEED_MODULES;
    while let Some(src) = queue.pop_front() {
        for name in scan_requires(&src) {
            if !seen.insert(name.clone()) {
                continue;
            }
            if budget == 0 {
                continue;
            }
            budget -= 1;
            if let Ok(module_source) = resolver.resolve(&name) {
                sources.insert(name, module_source.clone());
                queue.push_back(module_source);
            }
        }
    }
    sources
}

/// Reject mode-downgrading hot comments in a definition source with a named
/// diagnostic (REPORT.md recommendation 3): `--!nonstrict` / `--!nocheck`
/// would let an author voluntarily downgrade the strict gate, because
/// upstream gives source hot-comments priority over the host's mode default.
/// Upgrading (`--!strict`) and non-mode directives stay legal.
///
/// Lexing mirrors the vendored luau-0.663 parser (`Ast/src/Parser.cpp`): a
/// hot comment is a *line* comment whose content starts with `!`, and
/// `Analysis/src/Frontend.cpp::parseMode` honors the exact lowercase words
/// (`nocheck`, `nonstrict`, `strict`) with trailing whitespace trimmed. The
/// scan skips string literals and long brackets, so `--!nonstrict` inside a
/// string never false-positives. One deliberate over-rejection: a match is
/// rejected anywhere in the file, although upstream only lets header
/// hot-comments set the mode — a hostile author should not be able to lean
/// on that parser detail, and the diagnostic names the exact comment either
/// way.
pub fn mode_downgrade_diagnostic(source: &str) -> Option<Diagnostic> {
    let (line, col, word) = find_mode_downgrade(source.as_bytes())?;
    Some(Diagnostic {
        begin_line: line,
        begin_col: col,
        end_line: line,
        end_col: 0,
        message: format!(
            "definition downgrades the analyzer gate with hot comment '--!{word}': \
             strictness is host-controlled; remove the comment (--!strict is allowed)"
        ),
    })
}

/// The mode words a source may use to downgrade the gate (exact, lowercase —
/// upstream `parseMode` compares case-sensitively).
fn is_mode_downgrade(word: &str) -> bool {
    matches!(word, "nonstrict" | "nocheck")
}

/// Byte walker for [`mode_downgrade_diagnostic`]: returns the 1-based line,
/// 1-based column, and offending word of the first `--!nonstrict` /
/// `--!nocheck` line-comment hot comment outside string literals and long
/// brackets.
fn find_mode_downgrade(b: &[u8]) -> Option<(u32, u32, String)> {
    let (mut line, mut col) = (1u32, 1u32);
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\n' => {
                line += 1;
                col = 1;
                i += 1;
            }
            b'-' if b.get(i + 1) == Some(&b'-') => {
                // A hot comment is a line comment starting `--!` (long
                // comments are never hot comments in luau-0.663).
                if b.get(i + 2) == Some(&b'!') {
                    if let Some(word) = hot_comment_word(b, i + 3) {
                        if is_mode_downgrade(word) {
                            return Some((line, col, word.to_string()));
                        }
                    }
                }
                let next = skip_line_comment(b, i);
                col += (next - i) as u32;
                i = next;
            }
            quote @ (b'"' | b'\'') => {
                let next = skip_quoted(b, i, quote);
                col += (next - i) as u32;
                i = next;
            }
            b'[' if long_bracket_level(b, i).is_some() => {
                let level = long_bracket_level(b, i).unwrap_or(0);
                let next = skip_long_bracket(b, i, level);
                col += (next - i) as u32;
                i = next;
            }
            _ => {
                col += 1;
                i += 1;
            }
        }
    }
    None
}

/// Read the hot-comment word starting right after `--!`. Returns it only
/// when delimited like upstream `parseMode` sees it: ident characters, then
/// whitespace/newline/EOF (trailing whitespace is trimmed upstream; any
/// other trailing junk makes the directive inert, so it must not match).
fn hot_comment_word(b: &[u8], mut j: usize) -> Option<&str> {
    let start = j;
    while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
        j += 1;
    }
    if j == start {
        return None;
    }
    match b.get(j) {
        None | Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n') => {}
        Some(_) => return None,
    }
    std::str::from_utf8(&b[start..j]).ok()
}

/// Index just past the line comment starting at `i` (`--`), not consuming
/// the terminating newline.
fn skip_line_comment(b: &[u8], i: usize) -> usize {
    let mut j = i;
    while j < b.len() && b[j] != b'\n' {
        j += 1;
    }
    j
}

/// Scan a quoted string literal starting at `i`; returns the index just past
/// the closing quote (or past the line — Lua strings do not span newlines).
fn skip_quoted(b: &[u8], i: usize, quote: u8) -> usize {
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            c if c == quote => return j + 1,
            b'\n' => return j,
            _ => j += 1,
        }
    }
    j
}

/// Long-bracket level at `i`: `Some(n)` when the bytes form `[` followed by
/// exactly `n` `=`s and another `[`.
fn long_bracket_level(b: &[u8], i: usize) -> Option<usize> {
    if b.get(i) != Some(&b'[') {
        return None;
    }
    let mut j = i + 1;
    while b.get(j) == Some(&b'=') {
        j += 1;
    }
    if b.get(j) == Some(&b'[') {
        Some(j - i - 1)
    } else {
        None
    }
}

/// Index just past the long bracket (`[`=n`[` ... `]`=n`]`) opening at `i`;
/// an unterminated bracket runs to end of input.
fn skip_long_bracket(b: &[u8], i: usize, level: usize) -> usize {
    let mut j = i + level + 2;
    while j < b.len() {
        if b[j] == b']' {
            let mut k = j + 1;
            while b.get(k) == Some(&b'=') {
                k += 1;
            }
            if b.get(k) == Some(&b']') {
                return k + 1;
            }
            j = k;
        } else {
            j += 1;
        }
    }
    b.len()
}

/// Locate the declaration site of output `key` in a definition `source`: the
/// *direct* field `key` of a table that is a value of a top-level `return`
/// statement (`return { default = snap { ... } }`, also through call
/// arguments as in `return merge({ default = ... }, ...)`). Fields of tables
/// nested inside other tables are never output keys and are not matched.
///
/// Best-effort span for schema-stage diagnostics: `None` when the source
/// does not parse, has no such field, or builds the returned table some
/// other way (e.g. mutates a local). The parser is the vendored Luau one —
/// the same AST the analyzer stage sees.
pub fn locate_output_key(source: &str, key: &str) -> Option<Span> {
    if source.contains('\0') || key.contains('\0') {
        return None;
    }
    let c_source = CString::new(source).ok()?;
    let c_key = CString::new(key).ok()?;
    let (mut bl, mut bc, mut el, mut ec) = (0u32, 0u32, 0u32, 0u32);
    // SAFETY: both C strings are valid for the call and have no interior
    // NUL (checked above); the out-params are stack locals.
    let found = unsafe {
        shuttle_locate_output_key(
            c_source.as_ptr().cast(),
            source.len(),
            c_key.as_ptr().cast(),
            key.len(),
            &mut bl,
            &mut bc,
            &mut el,
            &mut ec,
        )
    } == 0;
    found.then_some(Span {
        begin_line: bl,
        begin_col: bc,
        end_line: el,
        end_col: ec,
    })
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

    // ── Hot-comment rejection (REPORT.md rec 3: gate integrity) ──

    #[test]
    fn hot_comment_nonstrict_is_rejected_with_named_diagnostic() {
        let diags = check_definition("downgrade", &format!("--!nonstrict\n{CLEAN}"));
        assert_eq!(
            diags.len(),
            1,
            "the downgrade must be rejected before analysis: {diags:?}"
        );
        let d = &diags[0];
        assert!(
            d.message.contains("--!nonstrict") && d.message.contains("host-controlled"),
            "diagnostic must name the offending comment: {:?}",
            d.message
        );
        assert_eq!(
            (d.begin_line, d.begin_col),
            (1, 1),
            "positioned at the comment"
        );
    }

    #[test]
    fn hot_comment_nocheck_is_rejected() {
        let diags = check_definition("nocheck", "--!nocheck\nreturn { default = snap {} }");
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert!(
            diags[0].message.contains("--!nocheck"),
            "got: {:?}",
            diags[0].message
        );
    }

    #[test]
    fn hot_comment_with_trailing_whitespace_is_still_rejected() {
        // Upstream trims trailing whitespace off the hot-comment word, so
        // `--!nonstrict   ` is live; the scanner must match that.
        let diags = check_definition("trailing-ws", "--!nonstrict   \nreturn { v = 1 }");
        assert_eq!(diags.len(), 1, "{diags:?}");
    }

    #[test]
    fn strict_hot_comment_stays_legal() {
        let diags = check_definition("strict-ok", &format!("--!strict\n{CLEAN}"));
        assert!(
            diags.is_empty(),
            "--!strict is an upgrade, must stay legal: {diags:?}"
        );
    }

    #[test]
    fn non_mode_hot_comments_stay_legal() {
        // Lint/compiler directives must not trip the mode rejection.
        let src = "--!noundef\n--!format off\nreturn { default = snap { name = \"x\", version = \"1\" } }";
        let diags = check_definition("other-directives", src);
        assert!(diags.is_empty(), "got: {diags:?}");
    }

    #[test]
    fn mode_word_inside_string_literal_is_not_a_hot_comment() {
        // Upstream only lexes comments for hot comments; a string mentioning
        // the word must not be rejected.
        let src = r#"local s = "--!nonstrict"
return { default = snap { name = s, version = "1" } }"#;
        let diags = check_definition("in-string", src);
        assert!(
            !diags.iter().any(|d| d.message.contains("downgrades")),
            "string literal must not false-positive: {diags:?}"
        );
    }

    #[test]
    fn downgrade_rejection_wins_over_the_check_itself() {
        // The whole point: without the rejection this source passes the gate
        // (nonstrict mode does not flag unknown globals). The rejection must
        // fire BEFORE analysis, and be the ONLY diagnostic.
        let src = "--!nonstrict\nreturn { default = snp { name = \"x\" } }";
        let diags = check_definition("downgrade-wins", src);
        assert_eq!(
            diags.len(),
            1,
            "no analysis diagnostics may leak: {diags:?}"
        );
        assert!(
            diags[0].message.contains("nonstrict"),
            "got: {:?}",
            diags[0].message
        );
    }

    #[test]
    fn downgrading_word_needs_hot_comment_shape() {
        // A plain comment mentioning the word is not a directive.
        let src = "-- nonstrict mode is banned here\nreturn { default = snap { name = \"x\", version = \"1\" } }";
        assert!(check_definition("plain-comment", src).is_empty());
        // `--! nonstrict` (space after !) is not a hot comment upstream.
        let src = "--! nonstrict\nreturn { default = snap { name = \"x\", version = \"1\" } }";
        assert!(check_definition("space-after-bang", src).is_empty());
        // `--!nonstrictx` is a different word upstream (inert).
        let src = "--!nonstrictx\nreturn { default = snap { name = \"x\", version = \"1\" } }";
        assert!(check_definition("word-extension", src).is_empty());
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

    // ── Analyzer wall-clock bound (moduleTimeLimitSec, REPORT.md §5) ──

    #[test]
    fn zero_limit_times_out_fail_closed() {
        // Some(0.0) expires immediately — the deterministic injection hook.
        let diags = check_definition_with_limit("timeout", CLEAN, Some(0.0));
        assert_eq!(
            diags.len(),
            1,
            "partial results must be replaced by one timeout diagnostic: {diags:?}"
        );
        assert!(
            diags[0].message.contains("analysis timed out after 0s"),
            "got: {:?}",
            diags[0].message
        );
    }

    #[test]
    fn production_limit_does_not_fire_on_corpus_scale_sources() {
        let diags = check_definition_with_limit("generous", CLEAN, Some(ANALYZER_TIME_LIMIT_SECS));
        assert!(diags.is_empty(), "10s must be generous, got: {diags:?}");
    }

    // ── Schema-stage span localization (locate_output_key) ──

    #[test]
    fn locate_output_key_finds_direct_field_with_exact_position() {
        let src = "\nreturn {\n    good = snap { name = \"fine\" },\n    bad = \"nope\",\n}\n";
        let span = locate_output_key(src, "bad").expect("direct field must be found");
        assert_eq!((span.begin_line, span.begin_col), (4, 5));
        assert_eq!((span.end_line, span.end_col), (4, 7), "end col exclusive");
    }

    #[test]
    fn locate_output_key_handles_bracketed_and_call_arg_forms() {
        let bracketed = "return { [\"srv\"] = snap {} }";
        let span = locate_output_key(bracketed, "srv").expect("bracketed string key");
        // The key expression is the string literal, so the span starts at
        // its opening quote, not the bracket.
        assert_eq!((span.begin_line, span.begin_col), (1, 11));

        let via_call = "\nreturn merge({\n    default = snap { name = \"m\" },\n}, {})";
        let span = locate_output_key(via_call, "default").expect("table behind call args");
        assert_eq!((span.begin_line, span.begin_col), (3, 5));
    }

    #[test]
    fn locate_output_key_is_none_for_nested_missing_or_unparsed() {
        // A field of a *nested* table is not an output key.
        let nested = "return { wrapper = { default = snap {} } }";
        assert_eq!(locate_output_key(nested, "default"), None);
        assert_eq!(
            locate_output_key("return { good = snap {} }", "missing"),
            None
        );
        // Source that does not parse has no localizable positions.
        assert_eq!(locate_output_key("return {", "default"), None);
        // Built through a local: the sound answer is "not localizable".
        let via_local = "local t = { default = snap {} } return t";
        assert_eq!(locate_output_key(via_local, "default"), None);
    }
}
