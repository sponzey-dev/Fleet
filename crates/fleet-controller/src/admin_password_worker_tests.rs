use super::*;
use fleet_application::admin_identity::{AdminOperation, AdminPasswordPort};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, mpsc};

struct HttpIdentityFixture {
    root: tempfile::TempDir,
    store: Arc<Mutex<crate::ControllerStore>>,
    settings: AdminAuthSettings,
}

impl HttpIdentityFixture {
    fn new() -> Self {
        use crate::admin_crypto::AdminTokenCrypto;
        use fleet_application::admin_identity::*;
        use fleet_domain::{AdminDisplayName, AuditActor};
        struct Local;
        impl AdminLocalAuthority for Local {
            fn require_exclusive(&self) -> Result<AuditActor, AdminAccessError> {
                Ok(AuditActor::new("local:http-worker-fixture"))
            }
        }
        let root = tempfile::tempdir().unwrap();
        let settings = AdminAuthSettings::new(1).unwrap();
        let initial = AdminPasswordWorker::spawn(settings).unwrap();
        let client = initial.client();
        let owner = AdminAuthRequest::new(settings).unwrap();
        let operation = owner.operation();
        let mut sqlite = fleet_store::SqliteStore::in_memory().unwrap();
        InitializeAdminOwner::execute(
            &mut sqlite,
            &Local,
            &operation,
            &client.passwords(&operation),
            &AdminTokenCrypto::system(),
            InitializeOwnerInput {
                username: AdminUsername::parse("mutex_owner").unwrap(),
                display_name: AdminDisplayName::parse("HTTP worker fixture").unwrap(),
                new_password: "Controller mutex fixture passphrase 42!",
            },
        )
        .unwrap();
        initial.shutdown().unwrap();
        Self {
            root,
            store: Arc::new(Mutex::new(crate::ControllerStore::Sqlite(sqlite))),
            settings,
        }
    }

    fn state(&self, client: AdminPasswordClient) -> crate::ControllerAppState {
        use crate::admin_http::{AdminHttpRuntime, CookiePolicy};
        use crate::{
            AgentSessionRegistry, ControllerAppState, ControllerIdentity, ControllerRuntimeMetadata,
        };
        ControllerAppState {
            store: self.store.clone(),
            artifact_store: Arc::new(Mutex::new(
                fleet_store::LocalArtifactStore::new(self.root.path().join("artifacts")).unwrap(),
            )),
            identity: Arc::new(ControllerIdentity::dev_insecure()),
            metadata: Arc::new(ControllerRuntimeMetadata {
                external_url: Some("http://127.0.0.1:7700".to_owned()),
                ..Default::default()
            }),
            sessions: Arc::new(Mutex::new(AgentSessionRegistry::default())),
            catalog_sync_submitter: None,
            admin_auth: Some(Arc::new(AdminHttpRuntime::with_client(
                self.settings,
                Some(CookiePolicy::parse(Some("http://127.0.0.1:7700")).unwrap()),
                Some(client),
            ))),
        }
    }

    fn request(&self) -> axum::extract::Request {
        axum::http::Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("Origin", "http://127.0.0.1:7700")
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({
                    "username":"mutex_owner","password":"Controller mutex fixture passphrase 42!"
                })
                .to_string(),
            ))
            .unwrap()
    }
}

#[test]
fn http_password_actions_release_the_controller_shared_store_mutex_during_real_kdf() {
    let fixture = HttpIdentityFixture::new();
    let probed = fixture.store.clone();
    let count = Arc::new(AtomicUsize::new(0));
    let observed = count.clone();
    let worker = AdminPasswordWorker::spawn_with(
        fixture.settings,
        Arc::new(move |task| {
            {
                let _guard = probed
                    .try_lock()
                    .map_err(|_| AdminAccessError::Unavailable)?;
                observed.fetch_add(1, Ordering::SeqCst);
            }
            execute_password(task)
        }),
    )
    .unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let state = fixture.state(worker.client());
    let response = runtime.block_on(crate::axum_http_fallback(
        axum::extract::State(state.clone()),
        fixture.request(),
    ));
    assert_eq!(
        response.status(),
        200,
        "shared store must be available inside the actual HTTP KDF"
    );
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let body = runtime
        .block_on(axum::body::to_bytes(response.into_body(), 16 * 1024))
        .unwrap();
    let profile: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let mut target = String::new();
    for (method, path, body, status) in [
        (
            "POST",
            "/api/admin/users".to_owned(),
            serde_json::json!({"username":"mutex_created","display_name":"Mutex fixture","role":"viewer","current_password":"Controller mutex fixture passphrase 42!"}),
            201,
        ),
        (
            "PATCH",
            format!(
                "/api/admin/users/{}",
                profile["user"]["id"].as_str().unwrap()
            ),
            serde_json::json!({"display_name":"Renamed mutex owner","current_password":"Controller mutex fixture passphrase 42!"}),
            200,
        ),
        (
            "POST",
            "reset_created".to_owned(),
            serde_json::json!({"current_password":"Controller mutex fixture passphrase 42!"}),
            201,
        ),
        (
            "POST",
            "/api/auth/tokens".to_owned(),
            serde_json::json!({"current_password":"Controller mutex fixture passphrase 42!"}),
            201,
        ),
        (
            "POST",
            "/api/auth/password".to_owned(),
            serde_json::json!({"current_password":"Controller mutex fixture passphrase 42!","new_password":"Changed mutex fixture passphrase 76!"}),
            204,
        ),
    ] {
        let path = if path == "reset_created" {
            format!("/api/admin/users/{target}/password-reset")
        } else {
            path
        };
        let request = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("Cookie", &cookie)
            .header("Origin", "http://127.0.0.1:7700")
            .header("X-Fleet-CSRF", profile["csrf_token"].as_str().unwrap())
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let response = runtime.block_on(crate::axum_http_fallback(
            axum::extract::State(state.clone()),
            request,
        ));
        assert_eq!(
            response.status(),
            status,
            "all password actions must release the shared store during actual KDF"
        );
        if status == 204 {
            continue;
        }
        let body = runtime
            .block_on(axum::body::to_bytes(response.into_body(), 16 * 1024))
            .unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if method == "POST" && target.is_empty() {
            target = result["user"]["id"].as_str().unwrap().to_owned();
        }
    }
    assert_eq!(count.load(Ordering::SeqCst), 7);
    drop(runtime);
    worker.shutdown().unwrap();
}

#[test]
fn http_password_mutations_share_admission_and_reject_revoked_or_cancelled_late_proofs() {
    use crate::admin_identity_store::SharedIdentityRepository;
    use fleet_application::admin_identity::{AdminIdentityRead, AdminIdentityRepository};
    for (personal, revoke) in [(false, true), (false, false), (true, true), (true, false)] {
        let fixture = HttpIdentityFixture::new();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let initial = AdminPasswordWorker::spawn(fixture.settings).unwrap();
        let response = runtime.block_on(crate::axum_http_fallback(
            axum::extract::State(fixture.state(initial.client())),
            fixture.request(),
        ));
        assert_eq!(response.status(), 200);
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let body = runtime
            .block_on(axum::body::to_bytes(response.into_body(), 16 * 1024))
            .unwrap();
        let profile: serde_json::Value = serde_json::from_slice(&body).unwrap();
        initial.shutdown().unwrap();
        let (worker, probe) = controlled(1);
        let client = worker.client();
        let gate = client.gate.clone();
        let state = fixture.state(client);
        let request = |username: &str| {
            let (path, body) = if personal {
                (
                    "/api/auth/tokens",
                    serde_json::json!({"label":username,"current_password":"Controller mutex fixture passphrase 42!"}),
                )
            } else {
                (
                    "/api/admin/users",
                    serde_json::json!({"username":username,"display_name":"Race fixture","role":"viewer","current_password":"Controller mutex fixture passphrase 42!"}),
                )
            };
            axum::http::Request::builder()
                .method("POST")
                .uri(path)
                .header("Cookie", &cookie)
                .header("Origin", "http://127.0.0.1:7700")
                .header("X-Fleet-CSRF", profile["csrf_token"].as_str().unwrap())
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap()
        };
        runtime.block_on(async {
            let first = tokio::spawn(crate::axum_http_fallback(
                axum::extract::State(state.clone()),
                request("late_proof"),
            ));
            let deadline = Instant::now() + Duration::from_secs(4);
            while probe.state.active.load(Ordering::SeqCst) != 1 {
                assert!(Instant::now() < deadline);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            if revoke {
                let mut repository = SharedIdentityRepository(fixture.store.clone());
                let account = repository
                    .account_by_username(&AdminUsername::parse("mutex_owner").unwrap())
                    .unwrap()
                    .unwrap();
                let operation = AdminAuthRequest::new(fixture.settings).unwrap();
                repository
                    .identity_transaction(|tx| {
                        tx.revoke_user_credentials(
                            &account.snapshot().id,
                            operation.operation().checked_now()?,
                        )
                    })
                    .unwrap();
                probe.release();
                assert_eq!(first.await.unwrap().status(), 401);
            } else {
                let second = tokio::spawn(crate::axum_http_fallback(
                    axum::extract::State(state.clone()),
                    request("accepted_proof"),
                ));
                while gate.lock().unwrap().admitted != 2 {
                    assert!(Instant::now() < deadline);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                assert_eq!(
                    crate::axum_http_fallback(axum::extract::State(state), fixture.request())
                        .await
                        .status(),
                    429
                );
                first.abort();
                assert!(first.await.unwrap_err().is_cancelled());
                probe.release();
                assert_eq!(second.await.unwrap().status(), 201);
            }
        });
        drop(runtime);
        worker.shutdown().unwrap();
        let mut repository = SharedIdentityRepository(fixture.store.clone());
        assert!(
            repository
                .account_by_username(&AdminUsername::parse("late_proof").unwrap())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            repository
                .account_by_username(&AdminUsername::parse("accepted_proof").unwrap())
                .unwrap()
                .is_some(),
            !personal && !revoke
        );
        let account = repository
            .account_by_username(&AdminUsername::parse("mutex_owner").unwrap())
            .unwrap()
            .unwrap();
        let request = AdminAuthRequest::new(fixture.settings).unwrap();
        let counts = repository
            .identity_transaction(|tx| {
                tx.credential_counts(
                    fleet_domain::AdminCredentialKind::PersonalToken,
                    &account.snapshot().id,
                    request.operation().checked_now()?,
                )
            })
            .unwrap();
        assert_eq!(
            counts.total_rows,
            usize::from(personal && !revoke),
            "late proof must not issue a second PAT"
        );
    }
}

#[test]
fn http_admission_is_bounded_and_cancelled_late_password_proof_cannot_issue_a_session() {
    use crate::admin_identity_store::SharedIdentityRepository;
    use fleet_application::admin_identity::{AdminIdentityRead, AdminIdentityRepository};
    use fleet_domain::AdminCredentialKind;
    let fixture = HttpIdentityFixture::new();
    let (worker, probe) = controlled(1);
    let client = worker.client();
    let gate = client.gate.clone();
    let state = fixture.state(client);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let first = tokio::spawn(crate::axum_http_fallback(
            axum::extract::State(state.clone()),
            fixture.request(),
        ));
        let deadline = Instant::now() + Duration::from_secs(5);
        while probe.state.active.load(Ordering::SeqCst) != 1 {
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let second = tokio::spawn(crate::axum_http_fallback(
            axum::extract::State(state.clone()),
            fixture.request(),
        ));
        while gate.lock().unwrap().admitted != 2 {
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let rejected =
            crate::axum_http_fallback(axum::extract::State(state), fixture.request()).await;
        assert_eq!(rejected.status(), 429);
        assert_eq!(probe.state.peak.load(Ordering::SeqCst), 1);
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        probe.release();
        assert_eq!(second.await.unwrap().status(), 200);
    });
    drop(runtime);
    worker.shutdown().unwrap();
    let mut repository = SharedIdentityRepository(fixture.store.clone());
    let account = repository
        .account_by_username(&AdminUsername::parse("mutex_owner").unwrap())
        .unwrap()
        .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let counts = repository
        .identity_transaction(|transaction| {
            transaction.credential_counts(
                AdminCredentialKind::WebSession,
                &account.snapshot().id,
                now,
            )
        })
        .unwrap();
    assert_eq!(
        (counts.valid_for_user, counts.total_rows),
        (1, 1),
        "cancelled CPU proof must not create a second session"
    );
}

struct ProbeState {
    released: Mutex<bool>,
    condition: Condvar,
    active: AtomicUsize,
    peak: AtomicUsize,
    calls: AtomicUsize,
}

struct Probe {
    state: Arc<ProbeState>,
    entered: mpsc::Receiver<()>,
}

impl Probe {
    fn entered(&self) {
        self.entered.recv_timeout(Duration::from_secs(3)).unwrap();
    }
    fn release(&self) {
        *self.state.released.lock().unwrap() = true;
        self.state.condition.notify_all();
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        self.release();
    }
}

fn controlled(workers: usize) -> (AdminPasswordWorker, Probe) {
    let state = Arc::new(ProbeState {
        released: Mutex::new(false),
        condition: Condvar::new(),
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        calls: AtomicUsize::new(0),
    });
    let (entered, receiver) = mpsc::sync_channel(8);
    let backend = state.clone();
    let worker = AdminPasswordWorker::spawn_with(
        AdminAuthSettings::new(workers).unwrap(),
        Arc::new(move |_| {
            backend.calls.fetch_add(1, Ordering::SeqCst);
            let active = backend.active.fetch_add(1, Ordering::SeqCst) + 1;
            backend.peak.fetch_max(active, Ordering::SeqCst);
            entered.try_send(()).unwrap();
            let mut released = backend.released.lock().unwrap();
            while !*released {
                let (next, timeout) = backend
                    .condition
                    .wait_timeout(released, Duration::from_secs(5))
                    .unwrap();
                released = next;
                if timeout.timed_out() && !*released {
                    backend.active.fetch_sub(1, Ordering::SeqCst);
                    return Err(AdminAccessError::Unavailable);
                }
            }
            backend.active.fetch_sub(1, Ordering::SeqCst);
            Ok(PasswordValue::Verified(true))
        }),
    )
    .unwrap();
    (
        worker,
        Probe {
            state,
            entered: receiver,
        },
    )
}

fn submit(
    client: &AdminPasswordClient,
    operation: &AdminAuthOperation,
) -> Result<PasswordTicket, AdminAccessError> {
    client.submit(operation, || PasswordTask::Verify {
        input: Zeroizing::new("synthetic fixture".to_owned()),
        verifier: None,
    })
}

#[test]
fn one_worker_one_pending_and_outstanding_reply_budget_are_enforced() {
    let (worker, probe) = controlled(1);
    let client = worker.client();
    let request = AdminAuthRequest::new(AdminAuthSettings::new(1).unwrap()).unwrap();
    let operation = request.operation();
    let first = submit(&client, &operation).unwrap();
    probe.entered();
    let second = submit(&client, &operation).unwrap();
    assert!(matches!(
        submit(&client, &operation),
        Err(AdminAccessError::Busy)
    ));
    assert_eq!(client.gate.lock().unwrap().admitted, 2);
    probe.release();
    probe.entered();
    // Completed but unread replies still retain their admission permits.
    assert!(matches!(
        submit(&client, &operation),
        Err(AdminAccessError::Busy)
    ));
    assert!(matches!(
        first.wait(&operation).unwrap(),
        PasswordValue::Verified(true)
    ));
    assert!(matches!(
        second.wait(&operation).unwrap(),
        PasswordValue::Verified(true)
    ));
    assert_eq!(client.gate.lock().unwrap().admitted, 0);
    assert_eq!(probe.state.peak.load(Ordering::SeqCst), 1);
    worker.shutdown().unwrap();
    assert!(matches!(
        submit(&client, &operation),
        Err(AdminAccessError::Unavailable)
    ));
}

#[test]
fn two_workers_never_run_three_hashes_and_have_only_one_queued_request() {
    let (worker, probe) = controlled(2);
    let client = worker.client();
    let request = AdminAuthRequest::new(AdminAuthSettings::new(2).unwrap()).unwrap();
    let operation = request.operation();
    let first = submit(&client, &operation).unwrap();
    probe.entered();
    let second = submit(&client, &operation).unwrap();
    probe.entered();
    let third = submit(&client, &operation).unwrap();
    assert!(matches!(
        submit(&client, &operation),
        Err(AdminAccessError::Busy)
    ));
    probe.release();
    for ticket in [first, second, third] {
        assert!(ticket.wait(&operation).is_ok());
    }
    assert_eq!(probe.state.peak.load(Ordering::SeqCst), 2);
    worker.shutdown().unwrap();
}

#[test]
fn cancellation_skips_queued_crypto_and_discards_running_results() {
    let (worker, probe) = controlled(1);
    let client = worker.client();
    let running_request = AdminAuthRequest::new(AdminAuthSettings::new(1).unwrap()).unwrap();
    let queued_request = AdminAuthRequest::new(AdminAuthSettings::new(1).unwrap()).unwrap();
    let running = running_request.operation();
    let queued = queued_request.operation();
    let first = submit(&client, &running).unwrap();
    probe.entered();
    let second = submit(&client, &queued).unwrap();
    queued_request.cancel();
    running_request.cancel();
    assert!(matches!(
        second.wait(&queued),
        Err(AdminAccessError::OperationExpired)
    ));
    probe.release();
    assert!(matches!(
        first.wait(&running),
        Err(AdminAccessError::OperationExpired)
    ));
    worker.shutdown().unwrap();
    assert_eq!(probe.state.calls.load(Ordering::SeqCst), 1);
    assert_eq!(client.gate.lock().unwrap().admitted, 0);
}

#[test]
fn shutdown_closes_cloned_clients_skips_queued_work_and_joins_running_crypto() {
    let (mut worker, probe) = controlled(1);
    let client = worker.client();
    let clone = client.clone();
    let request = AdminAuthRequest::new(AdminAuthSettings::new(1).unwrap()).unwrap();
    let operation = request.operation();
    let first = submit(&client, &operation).unwrap();
    probe.entered();
    let second = submit(&client, &operation).unwrap();
    worker.close_submission();
    assert!(matches!(
        submit(&clone, &operation),
        Err(AdminAccessError::Unavailable)
    ));
    probe.release();
    worker.shutdown().unwrap();
    assert!(matches!(
        first.wait(&operation),
        Err(AdminAccessError::Unavailable)
    ));
    assert!(matches!(
        second.wait(&operation),
        Err(AdminAccessError::Unavailable)
    ));
    assert_eq!(probe.state.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn fixed_deadline_and_request_drop_cancel_every_operation_handle() {
    let request = AdminAuthRequest::new(AdminAuthSettings::new(1).unwrap()).unwrap();
    let operation = request.operation();
    let deadline = operation.deadline;
    assert!(operation.checked_now().unwrap() > 0);
    assert_eq!(operation.deadline, deadline);
    drop(request);
    assert_eq!(
        operation.checked_now(),
        Err(AdminAccessError::OperationExpired)
    );
    let mut expired = AdminAuthRequest::new(AdminAuthSettings::new(1).unwrap()).unwrap();
    expired.operation.deadline = Instant::now();
    assert_eq!(
        expired.operation().checked_now(),
        Err(AdminAccessError::OperationExpired)
    );
}

#[test]
fn scoped_application_port_runs_real_crypto_and_rejects_invalid_input_without_admission() {
    let worker = AdminPasswordWorker::spawn(AdminAuthSettings::new(1).unwrap()).unwrap();
    let client = worker.client();
    let request = AdminAuthRequest::new(AdminAuthSettings::new(1).unwrap()).unwrap();
    let operation = request.operation();
    let passwords = client.passwords(&operation);
    let username = AdminUsername::parse("fixture_user").unwrap();
    let verifier = passwords
        .hash_new("real adapter fixture passphrase", &username)
        .unwrap();
    assert!(
        passwords
            .verify("real adapter fixture passphrase", Some(&verifier))
            .unwrap()
    );
    assert!(
        !passwords
            .verify("wrong adapter fixture passphrase", Some(&verifier))
            .unwrap()
    );
    assert!(
        !passwords
            .verify("real adapter fixture passphrase", None)
            .unwrap()
    );
    assert_eq!(
        passwords.verify(&"x".repeat(2_049), None),
        Err(AdminAccessError::InvalidRequest)
    );
    request.cancel();
    assert_eq!(
        passwords.verify("real adapter fixture passphrase", Some(&verifier)),
        Err(AdminAccessError::OperationExpired)
    );
    worker.shutdown().unwrap();
}

#[test]
fn worker_fault_closes_all_clients_and_reports_failure_at_shutdown() {
    let worker = AdminPasswordWorker::spawn_with(
        AdminAuthSettings::new(1).unwrap(),
        Arc::new(|_| panic!("synthetic executor fault")),
    )
    .unwrap();
    let client = worker.client();
    let request = AdminAuthRequest::new(AdminAuthSettings::new(1).unwrap()).unwrap();
    let operation = request.operation();
    let ticket = submit(&client, &operation).unwrap();
    assert!(matches!(
        ticket.wait(&operation),
        Err(AdminAccessError::Unavailable)
    ));
    assert!(matches!(
        submit(&client, &operation),
        Err(AdminAccessError::Unavailable)
    ));
    assert_eq!(worker.shutdown(), Err(AdminAccessError::Unavailable));
}

#[test]
fn dropping_owner_also_stops_and_joins_before_returning() {
    let (worker, probe) = controlled(1);
    let client = worker.client();
    let request = AdminAuthRequest::new(AdminAuthSettings::new(1).unwrap()).unwrap();
    let operation = request.operation();
    let ticket = submit(&client, &operation).unwrap();
    probe.entered();
    let (finished, done) = mpsc::sync_channel(1);
    let owner = std::thread::spawn(move || {
        drop(worker);
        finished.send(()).unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    while !client.stopping.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(client.stopping.load(Ordering::Acquire));
    assert!(matches!(done.try_recv(), Err(mpsc::TryRecvError::Empty)));
    probe.release();
    done.recv_timeout(Duration::from_secs(3)).unwrap();
    owner.join().unwrap();
    assert!(matches!(
        ticket.wait(&operation),
        Err(AdminAccessError::Unavailable)
    ));
}

#[test]
fn application_owner_flow_releases_sqlite_writer_before_real_password_work() {
    use crate::admin_crypto::AdminTokenCrypto;
    use fleet_application::admin_identity::{
        AdminIdentityRead, AdminIdentityRepository, AdminLocalAuthority,
        AuthenticateAdminCredential, InitializeAdminOwner, InitializeOwnerInput, LoginAdmin,
        LoginAdminInput,
    };
    use fleet_domain::{AdminAuthMode, AdminDisplayName, AdminRole, AuditActor, AuditEvent};
    use fleet_store::SqliteStore;

    struct FixtureLocalAuthority;
    impl AdminLocalAuthority for FixtureLocalAuthority {
        fn require_exclusive(&self) -> Result<AuditActor, AdminAccessError> {
            Ok(AuditActor::new("local:fixture"))
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("identity.sqlite3");
    let mut repository = SqliteStore::open(&database).unwrap();
    let legacy_hash = "a".repeat(64);
    repository.insert_admin_token_hash(&legacy_hash).unwrap();
    assert!(repository.verify_admin_token_hash(&legacy_hash).unwrap());
    let epoch = repository.auth_state().unwrap().epoch;
    let writes = Arc::new(AtomicUsize::new(0));
    let observed = writes.clone();
    let probe_path = database.clone();
    let settings = AdminAuthSettings::new(1).unwrap();
    let worker = AdminPasswordWorker::spawn_with(
        settings,
        Arc::new(move |task| {
            // This runs inside the CPU worker while the Application waits for KDF.
            // A caller-held SQLite write transaction makes the independent write fail.
            let other =
                SqliteStore::open(&probe_path).map_err(|_| AdminAccessError::Unavailable)?;
            other
                .write_audit_event(AuditEvent::security("iam_kdf_db_probe", "human-auth"))
                .map_err(|_| AdminAccessError::Unavailable)?;
            observed.fetch_add(1, Ordering::SeqCst);
            drop(other);
            execute_password(task)
        }),
    )
    .unwrap();
    let client = worker.client();
    let request = AdminAuthRequest::new(settings).unwrap();
    let operation = request.operation();
    let password = "integrated SQLite KDF fixture passphrase";
    let owner = InitializeAdminOwner::execute(
        &mut repository,
        &FixtureLocalAuthority,
        &operation,
        &client.passwords(&operation),
        &AdminTokenCrypto::system(),
        InitializeOwnerInput {
            username: AdminUsername::parse("lock_probe_owner").unwrap(),
            display_name: AdminDisplayName::parse("Lock probe owner").unwrap(),
            new_password: password,
        },
    )
    .unwrap();
    assert_eq!(owner.role, AdminRole::Owner);
    assert_eq!(
        repository.auth_state().unwrap().mode,
        AdminAuthMode::Personal
    );
    assert_eq!(repository.auth_state().unwrap().epoch, epoch);
    assert_eq!(repository.loginable_owner_count().unwrap(), 1);
    assert!(!repository.verify_admin_token_hash(&legacy_hash).unwrap());
    let account = repository
        .account_by_id(&owner.id)
        .unwrap()
        .unwrap()
        .snapshot();
    assert!(
        client
            .passwords(&operation)
            .verify(password, account.password_verifier.as_ref())
            .unwrap()
    );
    assert_eq!(writes.load(Ordering::SeqCst), 2);
    let crypto = AdminTokenCrypto::system();
    let login = LoginAdmin::execute(
        &mut repository,
        &operation,
        &client.passwords(&operation),
        &crypto,
        LoginAdminInput {
            username: "LOCK_PROBE_OWNER",
            password,
        },
    )
    .unwrap();
    assert_eq!(login.account.id, owner.id);
    let kind = fleet_domain::AdminCredentialKind::WebSession;
    let digest = crypto
        .digest(kind, login.session.secret.expose_for_delivery())
        .unwrap();
    let authenticated =
        AuthenticateAdminCredential::execute(&repository, &operation, kind, &digest).unwrap();
    assert_eq!(authenticated.user_id(), &owner.id);
    let credential = repository
        .credential_by_id(&login.session.id)
        .unwrap()
        .unwrap()
        .snapshot();
    assert_eq!(credential.expires_at - credential.created_at, 28_800);
    assert_eq!(
        LoginAdmin::execute(
            &mut repository,
            &operation,
            &client.passwords(&operation),
            &crypto,
            LoginAdminInput {
                username: "lock_probe_owner",
                password: "incorrect integrated passphrase"
            }
        )
        .unwrap_err(),
        AdminAccessError::Unauthorized
    );
    let counts = repository
        .identity_transaction(|tx| tx.credential_counts(kind, &owner.id, operation.checked_now()?))
        .unwrap();
    assert_eq!(counts.valid_for_user, 1);
    assert_eq!(counts.total_rows, 1);
    use fleet_application::admin_identity::{
        CreateAdminPersonalToken, CreateAdminPersonalTokenInput,
    };
    let pat = CreateAdminPersonalToken::execute(
        &mut repository,
        &authenticated,
        &operation,
        &client.passwords(&operation),
        &crypto,
        CreateAdminPersonalTokenInput {
            current_password: password,
            label: Some(fleet_domain::AdminTokenLabel::parse("Real KDF fixture").unwrap()),
        },
    )
    .unwrap();
    let pat_kind = fleet_domain::AdminCredentialKind::PersonalToken;
    let pat_digest = crypto
        .digest(pat_kind, pat.secret.expose_for_delivery())
        .unwrap();
    assert_eq!(
        AuthenticateAdminCredential::execute(&repository, &operation, pat_kind, &pat_digest)
            .unwrap()
            .user_id(),
        &owner.id
    );
    assert_eq!(
        repository
            .credential_by_id(&pat.id)
            .unwrap()
            .unwrap()
            .snapshot()
            .label
            .unwrap()
            .as_str(),
        "Real KDF fixture"
    );
    assert_eq!(writes.load(Ordering::SeqCst), 5); // Every real password operation obtained an independent writer.
    worker.shutdown().unwrap();
}

#[test]
#[ignore = "explicit fake-only bounded adapter timing; no listener or persisted credential"]
fn bounded_password_adapter_measurement() {
    let settings = AdminAuthSettings::new(1).unwrap();
    let worker = AdminPasswordWorker::spawn(settings).unwrap();
    let client = worker.client();
    let username = AdminUsername::parse("measurement_user").unwrap();
    let warmup = AdminAuthRequest::new(settings).unwrap();
    let operation = warmup.operation();
    let mut verifier = client
        .passwords(&operation)
        .hash_new("isolated adapter measurement phrase", &username)
        .unwrap();
    drop(warmup);
    let mut cases = Vec::new();
    for kind in ["hash", "valid_verify", "wrong_verify", "dummy_verify"] {
        let mut samples = Vec::new();
        for _ in 0..8 {
            let request = AdminAuthRequest::new(settings).unwrap();
            let operation = request.operation();
            let passwords = client.passwords(&operation);
            let started = Instant::now();
            match kind {
                "hash" => {
                    verifier = passwords
                        .hash_new("isolated adapter measurement phrase", &username)
                        .unwrap();
                }
                "valid_verify" => assert!(
                    passwords
                        .verify("isolated adapter measurement phrase", Some(&verifier))
                        .unwrap()
                ),
                "wrong_verify" => assert!(
                    !passwords
                        .verify("different adapter measurement phrase", Some(&verifier))
                        .unwrap()
                ),
                "dummy_verify" => assert!(
                    !passwords
                        .verify("isolated adapter measurement phrase", None)
                        .unwrap()
                ),
                _ => unreachable!(),
            }
            samples.push(started.elapsed().as_micros());
        }
        samples.sort_unstable();
        cases.push(serde_json::json!({"operation":kind,"samples":samples.len(),"p50_us":samples[4],"p95_us":samples[7],"max_us":samples[7]}));
    }
    worker.shutdown().unwrap();
    println!(
        "{}",
        serde_json::json!({"kind":"bounded_password_adapter_measurement","debug_assertions":cfg!(debug_assertions),"workers":1,"pending_capacity":1,"maximum_admitted_including_replies":2,"memory_kib":19456,"passes":2,"lanes":1,"warmup":1,"cases":cases,"scope":"crypto/channel cost only; excludes TLS, Store and Agent load"})
    );
}
