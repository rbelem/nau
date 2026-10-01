//! The ONE test-environment lock (compile-time `test`-only): every test
//! that mutates a process-global — `PATH`, `XDG_RUNTIME_DIR`,
//! `BWS_ACCESS_TOKEN`, `VAULT_ADDR`, the secret-service seam — takes
//! this lock for the whole mutation window, restore included.
//!
//! History: each env-mutating test module used to carry its OWN
//! `static ENV_LOCK`, which guarded nothing across modules (four
//! mutexes over one process-global exclude nothing mutually), and the
//! doctor PATH-probe tests raced the secrets PATH-swapping fixtures
//! into "version unknown" flakes under parallel `cargo test`. One
//! crate-global lock is the fix; the per-module statics are gone.
//!
//! Discipline: acquire at test start (`let _lock = ENV_LOCK.lock()…`),
//! hold to test end, restore env before dropping the guard (drop order
//! runs restores first when the guard is bound AFTER the values it
//! guards — keep the LIFO chain the secrets tests established).

use std::sync::Mutex;

pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());
