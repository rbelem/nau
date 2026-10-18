use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

/// Event log shared between the fake builder and the test.
#[derive(Clone)]
struct Log {
    events: std::sync::Arc<Mutex<Vec<String>>>,
    inflight: std::sync::Arc<AtomicUsize>,
    max_inflight: std::sync::Arc<AtomicUsize>,
}

impl Log {
    fn new() -> Self {
        Log {
            events: std::sync::Arc::new(Mutex::new(Vec::new())),
            inflight: std::sync::Arc::new(AtomicUsize::new(0)),
            max_inflight: std::sync::Arc::new(AtomicUsize::new(0)),
        }
    }

    fn record(&self, event: String) {
        self.events.lock().unwrap().push(event);
    }

    /// Record `start:<name>` and bump the in-flight counter. The job
    /// calls [`Log::end`] when its work is done.
    fn start(&self, name: &str) {
        self.record(format!("start:{name}"));
        let n = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_inflight.fetch_max(n, Ordering::SeqCst);
    }

    fn end(&self, name: &str) {
        self.record(format!("end:{name}"));
        self.inflight.fetch_sub(1, Ordering::SeqCst);
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    fn position(&self, event: &str) -> usize {
        self.events()
            .iter()
            .position(|e| e == event)
            .unwrap_or_else(|| panic!("event {event} not in log {:?}", self.events()))
    }
}

fn graph(pairs: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
    pairs
        .iter()
        .map(|(name, deps)| {
            (
                name.to_string(),
                deps.iter().map(|d| d.to_string()).collect(),
            )
        })
        .collect()
}

fn sleep_ms(ms: u64) {
    thread::sleep(Duration::from_millis(ms));
}

mod ready_set;
