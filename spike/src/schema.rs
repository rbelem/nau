//! serde schema for golden-parity extraction + shoot-check diagnostics (ADR-0009 Decision 3/4/8).

use serde::{Deserialize, Serialize};

/// One app entry inside `apps` (mirrors the Lua `app()` output).
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppDef {
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slots: Option<Vec<String>>,
}

/// The snap (package) definition extracted via serde — the ADR-0009 Decision 3 path.
/// Optional fields use Option so both the Lua and Nickel paths deserialize the same shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PackageDef {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grade: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confinement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architectures: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apps: Option<serde_json::Map<String, serde_json::Value>>,
}

/// A pin reference inside an image (mirrors `pin()`/`index()` output).
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PinRef {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<serde_json::Number>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha3_384: Option<String>,
}

/// The image definition (mirrors `image()` output in system-base.lua).
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImageDef {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gadget: Option<PinRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootloader: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<PinRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snaps: Option<Vec<PinRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sysctl: Option<Vec<String>>,
}

/// Machine-checkable shape for shoot-check diagnostics (Decision 8: JSON with
/// span + expected/actual, schema-validated). `validate_diagnostics` enforces this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: String,
    pub message: String,
    pub span: Span,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    pub byte_start: usize,
    pub byte_end: usize,
    pub line_start: usize,
    pub col_start: usize,
    pub line_end: usize,
    pub col_end: usize,
    pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticSet {
    pub diagnostics: Vec<Diagnostic>,
}

/// Field-level diff between two extracted values, for the parity report.
pub fn diff_values(path: &str, a: &serde_json::Value, b: &serde_json::Value, out: &mut Vec<String>) {
    use serde_json::Value;
    // Nickel numbers deserialize as f64 (1.0); Lua keeps integers (1). Equal
    // numerically — compare via f64. (An extraction-seam finding: SnapMeta
    // fields must coerce Nickel numbers explicitly.)
    if let (Value::Number(na), Value::Number(nb)) = (a, b) {
        match (na.as_f64(), nb.as_f64()) {
            (Some(fa), Some(fb)) if fa == fb => return,
            _ => {}
        }
    }
    match (a, b) {
        (Value::Object(ma), Value::Object(mb)) => {
            for (k, va) in ma {
                match mb.get(k) {
                    Some(vb) => diff_values(&format!("{path}.{k}"), va, vb, out),
                    None => out.push(format!("{path}.{k}: present in A (Lua), missing in B (Nickel)")),
                }
            }
            for (k, vb) in mb {
                if !ma.contains_key(k) {
                    out.push(format!("{path}.{k}: missing in A (Lua), present in B (Nickel): {vb}"));
                }
            }
        }
        (Value::Array(aa), Value::Array(ab)) => {
            if aa.len() != ab.len() {
                out.push(format!("{path}: array length {len_a} (Lua) != {len_b} (Nickel)", len_a = aa.len(), len_b = ab.len()));
            }
            for (i, (va, vb)) in aa.iter().zip(ab.iter()).enumerate() {
                diff_values(&format!("{path}[{i}]"), va, vb, out);
            }
        }
        _ => {
            if a != b {
                out.push(format!("{path}: Lua={a:?} != Nickel={b:?}"));
            }
        }
    }
}
