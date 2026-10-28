//! Verifies operator-facing dispatch log volume without a global logger or live service.
use super::*;
use std::io::Write;

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn idle_dispatch_checks_are_field_debug_and_do_not_flood_product_logs() {
    let store = fleet_store::SqliteStore::in_memory().unwrap();
    let sessions = Arc::new(Mutex::new(AgentSessionRegistry::default()));
    for (level, expected_present) in [(tracing::Level::INFO, false), (tracing::Level::DEBUG, true)]
    {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = Capture(bytes.clone());
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(level)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let result = dispatch_pending_assignments(&store, &sessions, None, None, 16).unwrap();
            assert_eq!(result.dispatched_count, 0);
            assert_eq!(result.failed_count, 0);
        });
        let rendered = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert_eq!(rendered.contains("task_dispatch_checked"), expected_present);
    }
}
