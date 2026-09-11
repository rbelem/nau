//! Safe Rust wrapper over the Luau 0.663 type analyzer (`Luau.Analysis`).
//!
//! Built by `build.rs`: upstream C++ + `shim/shuttle_shim.cpp` compiled with
//! the `cc` crate, linked statically. See `shim/shuttle_shim.cpp` for the
//! C++ side and `REPORT.md` for the spike conclusions.

use std::ffi::{c_char, c_int, c_uint, c_void, CString};

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

impl Diagnostic {
    pub fn position(&self) -> (u32, u32) {
        (self.begin_line, self.begin_col)
    }
}

// Raw FFI surface (see shim for semantics).
extern "C" {
    fn shuttle_checker_new(strict: c_int) -> *mut c_void;
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
    /// `strict`). First construction parses and freezes the builtin type
    /// graph — this is the cold-start cost (see REPORT.md latency numbers).
    pub fn new(strict: bool) -> Checker {
        // SAFETY: shuttle_checker_new returns a fresh handle or dies inside
        // C++ (no error return path); null-check on the Rust side.
        let inner = unsafe { shuttle_checker_new(strict as c_int) };
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

    #[test]
    fn in_source_mode_hotcomment_overrides_resolver_default() {
        // Feasibility-critical behavior: `--!nonstrict` inside the source
        // overrides the checker's strict default (Frontend::parse ->
        // parseMode(hotcomments) wins over ConfigResolver). shuttle's gate
        // must strip or reject mode hot-comments in authored definitions.
        let downgraded = "--!nonstrict\nlocal function f(x)\n    return x + 1\nend\nf(\"hello\")\n";
        let res = check_once("hotcomment-downgrade", downgraded, true);
        assert!(
            res.iter()
                .all(|d| d.message.contains("consider adding a type annotation")),
            "expected nonstrict softening despite strict checker: {res:?}"
        );
    }

    #[test]
    fn unknown_globals_flagged_in_both_modes() {
        // Documents actual 0.663 behavior: unknown globals are enforced in
        // non-strict mode too — good news for the unbound-prelude gate.
        let unbound = "--!strict\nsnap { name = \"x\" }\n";
        assert_eq!(check_once("strict-globals", unbound, true).len(), 1);
        assert_eq!(check_once("nonstrict-globals", unbound, false).len(), 1);
    }

    #[test]
    fn annotated_param_mismatch_and_unknown_globals_fire_in_both_modes() {
        // Documents actual 0.663 behavior: explicit annotations AND unknown
        // globals are enforced even in non-strict mode.
        let strict = check_once("strict-mismatch", TYPE_ERROR, true);
        let nonstrict = check_once("nonstrict-mismatch", TYPE_ERROR, false);
        assert!(!strict.is_empty());
        assert!(!nonstrict.is_empty());

        let unbound = "--!strict\nsnap { name = \"x\" }\n";
        assert_eq!(check_once("strict-globals", unbound, true).len(), 1);
        assert_eq!(check_once("nonstrict-globals", unbound, false).len(), 1);
    }
}
