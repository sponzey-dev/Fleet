//! Real bootstrap/lifetime tests using owned temporary data and loopback listeners.

use super::*;
use fleet_core::controller_data::{ControllerDataError, ControllerDataLease};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};

fn fixture() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

fn config(data_dir: &Path) -> ControllerServerConfig {
    ControllerServerConfig {
        host: "127.0.0.1".to_owned(),
        port: 0,
        external_url: None,
        tls_cert_path: None,
        tls_key_path: None,
        agent_client_ca_cert_path: None,
        data_dir: data_dir.to_path_buf(),
        database: None,
        secret_provider: None,
    }
}

#[test]
fn controller_lease_busy_precedes_default_or_custom_database_access() {
    let root = fixture();
    fs::write(root.path().join("preserved.fixture"), b"unchanged").unwrap();
    let _lease = ControllerDataLease::acquire(root.path()).unwrap();
    for database in [
        None,
        Some(DatabaseSettings::sqlite(root.path().join("custom.sqlite3")).unwrap()),
    ] {
        let mut config = config(root.path());
        config.database = database;
        let error = start_controller_server_until(config, || true).unwrap_err();
        assert_eq!(error.to_string(), ControllerDataError::Busy.to_string());
        assert!(!root.path().join("controller").exists());
        assert!(!root.path().join("custom.sqlite3").exists());
    }
    assert_eq!(
        fs::read(root.path().join("preserved.fixture")).unwrap(),
        b"unchanged"
    );
}

#[test]
fn controller_lease_unsafe_directory_fails_without_repair_or_database_access() {
    let root = fixture();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let error = start_controller_server_until(config(root.path()), || true).unwrap_err();
    assert_eq!(
        error.to_string(),
        ControllerDataError::UnsafeDirectory.to_string()
    );
    assert_eq!(
        fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert!(!root.path().join(".controller.lock").exists());
    assert!(!root.path().join("controller").exists());
}

#[test]
fn controller_lease_is_released_after_post_acquisition_startup_failure() {
    let root = fixture();
    fs::create_dir(root.path().join("controller")).unwrap();
    let result = start_controller_server_until(config(root.path()), || true);
    assert!(matches!(
        result,
        Err(ControllerError::SigningKeyRotation(_))
    ));
    assert!(root.path().join(".controller.lock").is_file());
    assert!(root.path().join("controller/fleet.db").is_file());
    let _lease = ControllerDataLease::acquire(root.path()).unwrap();
}

struct ShutdownOnDrop<'a>(&'a AtomicBool);

impl Drop for ShutdownOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn health_response(port: u16) -> String {
    use std::net::{SocketAddr, TcpStream};
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            stream
                .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            return response;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("owned Controller did not become healthy before the test deadline");
}

#[test]
fn controller_lease_covers_healthy_runtime_until_shutdown_completes() {
    let root = fixture();
    let controller = root.path().join("controller");
    fs::create_dir(&controller).unwrap();
    let pair = fleet_core::generate_agent_key_pair().unwrap();
    fs::write(
        controller.join("controller_public.key"),
        pair.public_key_hex,
    )
    .unwrap();
    let private_key = controller.join("controller_private.key");
    fs::write(&private_key, pair.private_key_hex).unwrap();
    fs::set_permissions(private_key, fs::Permissions::from_mode(0o600)).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut config = config(root.path());
    config.port = port;
    config.external_url = Some(format!("http://127.0.0.1:{port}"));
    let shutdown = Arc::new(AtomicBool::new(false));
    std::thread::scope(|scope| {
        let server_shutdown = shutdown.clone();
        let server = scope.spawn(move || {
            start_controller_server_until(config, move || server_shutdown.load(Ordering::SeqCst))
        });
        let _shutdown = ShutdownOnDrop(&shutdown);
        let response = health_response(port);
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("\"status\":\"ok\""));
        assert_eq!(
            ControllerDataLease::acquire(root.path()).unwrap_err(),
            ControllerDataError::Busy
        );
        shutdown.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
    });
    let _lease = ControllerDataLease::acquire(root.path()).unwrap();
}
