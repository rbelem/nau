//! The ONE test-environment lock (compile-time `test`-only): every test
//! that mutates a process-global — `PATH`, `NAU_TOOLS_DIR`, tool env pins
//! — takes this lock for the whole mutation window, restore included.
//!
//! TODO(#326 final PR): dedupe test_env — this is a byte-copy of the
//! root crate's `src/test_env.rs`; the workspace will grow one shared
//! test-support crate (or move the helper into nau-infra itself) so the
//! per-crate copies converge.

use std::sync::Mutex;

pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());
