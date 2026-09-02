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
//! Unified parse (RULESET_VERSION): the Rust-side gate runs on ONE parse —
//! full-moon (luau feature), the full Luau dialect incl. type annotations.
//! One AST feeds require seeding ([`ast_requires`]), the named
//! literal-require gate ([`LITERAL_REQUIRE_MESSAGE`]), and schema-stage
//! spans ([`locate_output_key`]); the earlier ad-hoc text scanners and the
//! `shuttle_locate_output_key` FFI are gone.
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

use full_moon::ast::{
    self, Call, Expression, Field, FunctionArgs, FunctionCall, LastStmt, Prefix, Suffix,
};
use full_moon::node::Node;
use full_moon::tokenizer::{TokenReference, TokenType};
use full_moon::visitors::Visitor;

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

/// Version of the parse-level gate rule set applied to untrusted definition
/// sources (same pattern as `REGISTRY_VERSION`, src/plugins.rs, so anything
/// that caches or fingerprints gate behavior can key on it):
///
/// 1. hot-comment mode rejection (`--!nonstrict` / `--!nocheck`,
///    [`mode_downgrade_diagnostic`]);
/// 2. literal-require enforcement ([`LITERAL_REQUIRE_MESSAGE`]);
/// 3. AST-derived require seeding ([`ast_requires`], full-moon).
///
/// Bump whenever a rule changes meaning. v1 is the first versioned rule
/// set: the full-moon unified parse (single Rust-side parser feeding
/// require seeding, literal-require enforcement, and schema-diagnostic
/// spans) replacing the earlier ad-hoc text scanners.
pub const RULESET_VERSION: &str = "1";

/// The named fail-closed diagnostic for a `require()` whose argument is not
/// a string literal. Computed/concatenated/variable requires cannot be
/// resolved by the analyzer's `resolveModule` (it only understands
/// `AstExprConstantString`), so the gate refuses them by name instead of
/// leaving them to fail as opaque `Unknown require` errors — or worse, to
/// pass silently when the use site is never checked.
pub const LITERAL_REQUIRE_MESSAGE: &str = "require argument must be a string literal";

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
    if let Err(e) = parse_definition(source) {
        // The full-moon parse is the gate's parse (RULESET_VERSION): a
        // source it cannot read cannot be require-seeded soundly, so the
        // gate refuses it before analysis instead of guessing at a partial
        // require set.
        return Err(Diagnostic {
            begin_line: 1,
            begin_col: 1,
            end_line: 1,
            end_col: 0,
            message: format!("definition does not parse as Luau: {e}"),
        });
    }
    collect_required_sources(label, source)
}

/// Transitively resolve every `require()` reachable from `source` through
/// the eval path's resolver (entry directory, `pkgs/`, initialized input
/// roots), returning name → source. The require list is derived from the
/// full-moon AST ([`ast_requires`]), not a text scan. Modules the resolver
/// cannot serve stay out of the map and fail closed as "Unknown require"
/// diagnostics at the use site. Any non-literal require encountered on the
/// walk — entry or seeded module — fails closed with
/// [`LITERAL_REQUIRE_MESSAGE`].
fn collect_required_sources(
    label: &str,
    source: &str,
) -> Result<BTreeMap<String, String>, Diagnostic> {
    let resolver = crate::isolate::SourceResolver::for_build(label);
    let mut sources = BTreeMap::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(source.to_string());
    let mut budget = MAX_SEED_MODULES;
    while let Some(src) = queue.pop_front() {
        let scan = match parse_definition(&src) {
            Ok(ast) => ast_requires(&ast),
            // Queued sources were accepted by check_inputs' parse gate
            // before being enqueued (modules re-check defensively here);
            // an unparseable module cannot be seeded soundly.
            Err(e) => {
                return Err(Diagnostic {
                    begin_line: 1,
                    begin_col: 1,
                    end_line: 1,
                    end_col: 0,
                    message: format!("required module does not parse as Luau: {e}"),
                })
            }
        };
        if let Some(span) = scan.non_literal_span {
            return Err(Diagnostic {
                begin_line: span.begin_line,
                begin_col: span.begin_col,
                end_line: span.end_line,
                end_col: span.end_col,
                message: format!(
                    "{LITERAL_REQUIRE_MESSAGE}; computed requires cannot be \
                     resolved by the analyzer gate"
                ),
            });
        }
        for name in scan.literals {
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
    Ok(sources)
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
/// The span is derived from the same full-moon AST the gate uses
/// ([`RULESET_VERSION`]) — one parser, no FFI. Per the council standard for
/// schema-stage spans: a *unique* exact match yields the key's source span;
/// an ambiguous match (the same key declared more than once) or a computed
/// key yields `None` (`span: null` for consumers). A wrong span is never
/// produced: no heuristics, no first-match-wins. `None` also when the source
/// does not parse or builds the returned table some other way (e.g. mutates
/// a local).
pub fn locate_output_key(source: &str, key: &str) -> Option<Span> {
    if source.contains('\0') || key.contains('\0') {
        return None;
    }
    let ast = parse_definition(source).ok()?;
    let mut hits: Vec<Span> = Vec::new();
    if let Some(LastStmt::Return(ret)) = ast.nodes().last_stmt() {
        for value in ret.returns().iter() {
            collect_key_field_spans(value, key, &mut hits);
        }
    }
    if hits.len() == 1 {
        hits.pop()
    } else {
        // Zero matches (missing, computed, or built some other way) or an
        // ambiguous match: "not localizable", never a guess.
        None
    }
}

/// The full-moon AST of a definition source, with a clean parse required:
/// `Err` names the first tokenizer/syntax problem. This is the gate's parse
/// ([`RULESET_VERSION`]) — the single Rust-side parser feeding require
/// seeding, literal-require enforcement, and schema-diagnostic spans.
fn parse_definition(source: &str) -> Result<full_moon::ast::Ast, String> {
    full_moon::parse(source).map_err(|errors| {
        errors
            .first()
            .map(|e| {
                // Tokenizer errors carry a position; AST errors do not
                // expose one uniformly, so the message stands alone there.
                match e {
                    full_moon::Error::TokenizerError(te) => {
                        let pos = te.position();
                        format!("{} (at line {})", e, pos.line())
                    }
                    full_moon::Error::AstError(_) => e.to_string(),
                }
            })
            .unwrap_or_else(|| "unknown parse failure".to_string())
    })
}

/// One parse of a source, all `require` call sites classified:
/// string-literal arguments ([`RequireScan::literals`], the require-seeding
/// list) and every other argument shape
/// ([`RequireScan::non_literal_span`], the first non-literal site, for the
/// named [`LITERAL_REQUIRE_MESSAGE`] diagnostic).
#[derive(Default, Debug)]
struct RequireScan {
    literals: Vec<String>,
    non_literal_span: Option<Span>,
}

/// Derive the require classification of an already-parsed definition from
/// its AST. The visitor walks every expression position — local requires,
/// requires inside function bodies, requires inside table constructors —
/// so nothing the analyzer could resolve goes unseeded, and comments /
/// string *contents* can never produce phantom sites (they are not call
/// nodes, unlike in the old text scanner).
fn ast_requires(ast: &full_moon::ast::Ast) -> RequireScan {
    let mut scan = RequireScan::default();
    let mut visitor = RequireVisitor(&mut scan);
    visitor.visit_ast(ast);
    scan
}

struct RequireVisitor<'a>(&'a mut RequireScan);

impl RequireVisitor<'_> {
    /// Classify one call chain from its prefix + suffixes — shared by
    /// [`Visitor::visit_function_call`] (plain calls like
    /// `require("mod")`) and [`Visitor::visit_var_expression`] (call
    /// *chains* like `require("mod").field` / `require("mod"):method()`,
    /// which full-moon models as a `VarExpression`, not a `FunctionCall`).
    fn scan_call<'s>(&mut self, prefix: &Prefix, suffixes: impl Iterator<Item = &'s Suffix>) {
        if !matches!(prefix, Prefix::Name(name) if name.token().to_string() == "require") {
            return;
        }
        let mut suffixes = suffixes;
        let Some(Suffix::Call(Call::AnonymousCall(args))) = suffixes.next() else {
            return;
        };
        match require_arg_class(args) {
            Some(Ok(name)) => self.0.literals.push(name),
            Some(Err(())) if self.0.non_literal_span.is_none() => {
                self.0.non_literal_span = non_literal_site_span(prefix, args);
            }
            Some(Err(())) => {}
            // Not an argument-bearing call shape at all (`require` indexed
            // but not called directly on this node): not a require site.
            None => {}
        }
    }
}

impl Visitor for RequireVisitor<'_> {
    fn visit_function_call(&mut self, call: &FunctionCall) {
        self.scan_call(call.prefix(), call.suffixes());
    }

    fn visit_var_expression(&mut self, call: &ast::VarExpression) {
        self.scan_call(call.prefix(), call.suffixes());
    }
}

/// Span of the require call site, reconstructed from the prefix (call
/// start) and the argument-bearing suffix (call end).
fn non_literal_site_span(prefix: &Prefix, args: &impl Node) -> Option<Span> {
    let start = match prefix {
        Prefix::Name(name) => name.token().start_position(),
        Prefix::Expression(expr) => expr.start_position()?,
        // `#[non_exhaustive]` upstream; no other prefix shapes today.
        _ => return None,
    };
    let end = args.end_position()?;
    Some(Span {
        begin_line: start.line() as u32,
        begin_col: start.character() as u32,
        end_line: end.line() as u32,
        end_col: end.character().saturating_sub(1) as u32,
    })
}
/// Classify the argument of a require call: `Some(Ok(name))` a string
/// literal (quoted or long-bracket — exactly the shape the analyzer's
/// `resolveModule` understands), `Some(Err(()))` any other argument shape
/// (computed, concatenated, variable, table, wrong arity), `None` when
/// `args` is not an argument list at all.
fn require_arg_class(args: &FunctionArgs) -> Option<Result<String, ()>> {
    match args {
        FunctionArgs::Parentheses { arguments, .. } => {
            let mut iter = arguments.iter();
            match (iter.next(), iter.next()) {
                (Some(expr), None) => match string_literal_value(expr) {
                    Some(name) => Some(Ok(name)),
                    None => Some(Err(())),
                },
                _ => Some(Err(())),
            }
        }
        FunctionArgs::String(token) => Some(Ok(string_token_value(token))),
        FunctionArgs::TableConstructor(_) => Some(Err(())),
        // `#[non_exhaustive]` upstream: future argument shapes are not
        // literals the analyzer could resolve.
        _ => Some(Err(())),
    }
}

/// The string-literal contents of an expression, when the expression *is* a
/// plain string literal — no type assertion (`"x" :: any` is not the plain
/// constant the analyzer's `resolveModule` accepts), no concatenation.
fn string_literal_value(expr: &Expression) -> Option<String> {
    match expr {
        Expression::String(token) => Some(string_token_value(token)),
        _ => None,
    }
}

/// The literal contents of a string token (quotes stripped by the
/// tokenizer; escapes are preserved verbatim, which require names and
/// output keys never use — and unlike the old text scanner, an escaped
/// quote can no longer truncate or leak the value).
fn string_token_value(token: &TokenReference) -> String {
    match token.token().token_type() {
        TokenType::StringLiteral { literal, .. } => literal.to_string(),
        // Unreachable for expression-position strings; raw token text is
        // the safe fallback (it simply never matches a real name).
        _ => token.token().to_string(),
    }
}

/// 1-based span of an AST node in the analyzer's convention (begin 1-based;
/// end line 1-based, end column exclusive-0-based — the same numbers the
/// C++ analyzer diagnostics carry, so downstream printers need no special
/// casing).
fn node_span(node: &impl Node) -> Option<Span> {
    let (start, end) = node.range()?;
    Some(Span {
        begin_line: start.line() as u32,
        begin_col: start.character() as u32,
        end_line: end.line() as u32,
        end_col: end.character().saturating_sub(1) as u32,
    })
}

/// Collect the spans of every *direct* field named `key` inside an
/// expression that is a value of a top-level `return` statement — the
/// full-moon port of the vendored parser's `findKeyField`. Tables reached
/// through call arguments count (`return merge({ a = 1 }, {})`, including
/// chained-call forms); fields of tables nested inside other tables do not
/// (values are never descended into). All matches are collected so callers
/// can distinguish unique from ambiguous.
fn collect_key_field_spans(expr: &Expression, key: &str, hits: &mut Vec<Span>) {
    match expr {
        Expression::Parentheses { expression, .. } => {
            collect_key_field_spans(expression, key, hits);
        }
        Expression::FunctionCall(call) => {
            for suffix in call.suffixes() {
                let args = match suffix {
                    Suffix::Call(Call::AnonymousCall(args)) => args,
                    Suffix::Call(Call::MethodCall(method)) => method.args(),
                    // `#[non_exhaustive]` upstream; indexing suffixes don't
                    // add call arguments.
                    _ => continue,
                };
                match args {
                    FunctionArgs::Parentheses { arguments, .. } => {
                        for arg in arguments.iter() {
                            collect_key_field_spans(arg, key, hits);
                        }
                    }
                    FunctionArgs::TableConstructor(table) => {
                        collect_table_field_spans(table, key, hits);
                    }
                    FunctionArgs::String(_) => {}
                    _ => {}
                }
            }
        }
        Expression::TableConstructor(table) => collect_table_field_spans(table, key, hits),
        _ => {}
    }
}

/// Direct `key`-named fields of one table constructor. Unbracketed keys are
/// identifier tokens; bracketed keys are the inner string expression
/// (`["key"]`) — its span, like the analyzer's, starts at the quote.
fn collect_table_field_spans(table: &ast::TableConstructor, key: &str, hits: &mut Vec<Span>) {
    for field in table.fields().iter() {
        match field {
            Field::NameKey { key: name, .. } if name.token().to_string() == key => {
                if let Some(span) = node_span(name) {
                    hits.push(span);
                }
            }
            Field::ExpressionKey { key: expr, .. }
                if string_literal_value(expr).as_deref() == Some(key) =>
            {
                if let Some(span) = node_span(expr) {
                    hits.push(span);
                }
            }
            _ => {}
        }
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

    // ── Require seeding from the AST (replaces the text scanner) ──

    fn literal_requires(source: &str) -> Vec<String> {
        let ast = parse_definition(source).expect("test source must parse");
        ast_requires(&ast).literals
    }

    #[test]
    fn ast_requires_finds_constant_strings_in_all_positions() {
        let src = r#"
local a = require("base")
local b = require 'single'
local c = require([[long]])
local d = require("pkgs.lib.cli")
local t = { tpl = require("from-table"), plain = 1 }
local function f()
    if b == "x" then
        return require("from-function-body")
    end
    return nil
end
local e = myrequire(fn)
local g = requireNotWord("nope")
"#;
        let names = literal_requires(src);
        let expected = [
            "base",
            "single",
            "long",
            "pkgs.lib.cli",
            "from-table",
            "from-function-body",
        ];
        assert_eq!(names, expected, "every literal site, in visit order");
    }

    #[test]
    fn ast_requires_ignores_comments_strings_and_non_calls() {
        let src = r#"
-- require("in-comment")
local s = "require(\"in-string\")"
local r = require
r("indirect-call-is-not-a-site")
"#;
        assert!(
            literal_requires(src).is_empty(),
            "got: {:?}",
            literal_requires(src)
        );
    }

    #[test]
    fn ast_requires_handles_escaped_quotes_whole() {
        // The old text scanner stopped at the escaped quote and produced a
        // truncated name; the AST keeps the whole literal interior.
        let names = literal_requires(r#"local a = require("we\"ird")"#);
        assert_eq!(names, [r#"we\"ird"#]);
    }

    #[test]
    fn ast_requires_marks_non_literal_argument_sites_with_spans() {
        let scan = ast_requires(&parse_definition("local x = require(variable)").unwrap());
        assert!(scan.literals.is_empty());
        let span = scan.non_literal_span.expect("variable require is a site");
        // `require(variable)` — the whole call expression.
        assert_eq!((span.begin_line, span.begin_col), (1, 11));
        assert_eq!((span.end_line, span.end_col), (1, 27));

        for src in [
            r#"return require("a" .. "b")"#,     // concatenation
            r#"return require()"#,               // no argument
            r#"return require("a", "b")"#,       // wrong arity
            r#"return require({ name = "t" })"#, // table argument
            r#"return require(someFn("a"))"#,    // computed by call
        ] {
            let scan = ast_requires(&parse_definition(src).unwrap());
            assert!(
                scan.non_literal_span.is_some(),
                "non-literal site must be named: {src}"
            );
        }
    }

    #[test]
    fn ast_requires_accepts_chained_require_loads() {
        // Indexing the loaded module does not hide the literal require.
        let names = literal_requires(r#"local v = require("mod").field"#);
        assert_eq!(names, ["mod"]);
        let names = literal_requires(r#"local v = require("mod"):method()"#);
        assert_eq!(names, ["mod"]);
    }

    #[test]
    fn literal_require_is_a_named_fail_closed_diagnostic() {
        // Without the gate this source would pass analysis in nonstrict-
        // shaped ways; the point is the gate fires FIRST with its own name,
        // and no analysis diagnostics leak.
        let src = "local tpl = require(tpl_name)\nreturn { default = tpl }";
        let diags = check_definition("literal-require", src);
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert!(
            diags[0]
                .message
                .starts_with("require argument must be a string literal"),
            "got: {:?}",
            diags[0].message
        );
        // Spanned at the call site (line 1, col 13 — `require(tpl_name)`).
        assert_eq!(
            (
                diags[0].begin_line,
                diags[0].begin_col,
                diags[0].end_line,
                diags[0].end_col
            ),
            (1, 13, 1, 29)
        );
    }

    #[test]
    fn literal_require_gate_fires_before_analysis() {
        // A misspelled global WOULD produce an analyzer diagnostic; the
        // literal-require rejection must win and be the only diagnostic.
        let src = "local tpl = require(\"a\" .. \"b\")\nreturn { default = snp {} }";
        let diags = check_definition("literal-require-first", src);
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert!(
            diags[0].message.contains("string literal"),
            "got: {:?}",
            diags[0].message
        );
    }

    #[test]
    fn literal_require_in_a_required_module_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let label = write_module(
            dir.path(),
            "shuttle.lua",
            r#"
local tpl = require("shady")
return { default = tpl.output }
"#,
        );
        write_module(
            dir.path(),
            "shady.lua",
            r#"
local computed = "computed"
local m = { output = require(computed) }
return m
"#,
        );
        let diags = check_definition(&label, &std::fs::read_to_string(&label).unwrap());
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert!(
            diags[0]
                .message
                .starts_with("require argument must be a string literal"),
            "module-level computed requires fail closed too: {diags:?}"
        );
    }

    #[test]
    fn unparseable_definition_is_a_named_rejection() {
        // The full-moon parse is the gate's parse: a source it cannot read
        // cannot be require-seeded soundly, so the gate refuses it by name.
        let diags = check_definition("unparseable", "return {");
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert!(
            diags[0]
                .message
                .starts_with("definition does not parse as Luau"),
            "got: {:?}",
            diags[0].message
        );
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

    // ── Schema-stage span localization (locate_output_key, same AST) ──

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

    #[test]
    fn locate_output_key_is_none_for_ambiguous_matches() {
        // The same output key declared twice in the returned table: two
        // candidates, no honest single span.
        let duplicate = r#"return {
    default = snap { name = "a", version = "1" },
    default = snap { name = "b", version = "2" },
}"#;
        assert_eq!(locate_output_key(duplicate, "default"), None);
        // Distinct keys are still unique and localizable in the same source.
        let span = locate_output_key(duplicate, "default");
        assert!(span.is_none());
        assert!(locate_output_key(duplicate, "nonexistent").is_none());
        let unique = r#"return {
    srv = snap { name = "a", version = "1" },
    other = snap { name = "b", version = "2" },
}"#;
        let span = locate_output_key(unique, "srv").expect("unique match");
        assert_eq!((span.begin_line, span.begin_col), (2, 5));

        // Two candidate tables across separate return values are equally
        // ambiguous.
        let two_values = "return { default = 1 }, { default = 2 }";
        assert_eq!(locate_output_key(two_values, "default"), None);
    }

    #[test]
    fn locate_output_key_is_none_for_computed_keys() {
        // A computed key is not a literal the gate can vouch for.
        let computed =
            "local k = \"default\"\nreturn { [k] = snap { name = \"x\", version = \"1\" } }";
        assert_eq!(locate_output_key(computed, "default"), None);
        // While a bracketed *literal* key stays localizable.
        let literal = "return { [\"default\"] = snap {} }";
        assert!(locate_output_key(literal, "default").is_some());
    }
}
