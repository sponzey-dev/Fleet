//! Canonical business-write ordering with server-verified human contexts and owned stores.

use super::account_mutations::mutation;
use super::*;
use fleet_domain::{AgentFingerprint, AgentIdentity, AgentName, AgentPublicKey};

const REMEDIATION_READ_ONLY_RUNBOOK: &str = "apiVersion: fleet.sponzey.dev/v1alpha1\nkind: Runbook\nname: identity-smoke\nselector: role=web\nsteps:\n  - id: collect\n    facts.collect:\n";

fn save_proposed_remediation(store: &SqliteStore, id: &str) {
    store
        .save_remediation_request_record(&fleet_application::RemediationRequestRecord {
            id: id.to_owned(),
            policy_id: "identity-policy".to_owned(),
            policy_name: "identity-policy".to_owned(),
            agent_id: "guard-agent".to_owned(),
            runbook_ref: "runbooks/readonly.yml".to_owned(),
            status: "proposed".to_owned(),
            approval_required: true,
            risk_summary: "owned fixture requires approval".to_owned(),
            job_id: None,
            origin_drift_report_id: None,
            policy_version: None,
            created_at: UNIX_EPOCH,
            updated_at: UNIX_EPOCH,
        })
        .unwrap();
}

#[test]
fn retained_context_cannot_request_remediation_approval_after_logout() {
    retained_remediation_context(false);
}
#[test]
fn retained_context_cannot_create_remediation_job_after_logout() {
    retained_remediation_context(true);
}

fn retained_remediation_context(approve: bool) {
    let server = Server::personal();
    let (cookie, person) = server.login();
    let store = SqliteStore::open(server._root.path().join("controller/fleet.db")).unwrap();
    save_offline_agent(&store);
    save_proposed_remediation(&store, "remed-before");
    save_proposed_remediation(&store, "remed-after");
    let context = authenticate_admin_request_with_metadata(
        &format!("GET /api/agents HTTP/1.1\r\nCookie: {cookie}\r\n\r\n"),
        &store,
        &ControllerRuntimeMetadata {
            external_url: Some(server.origin.clone()),
            ..Default::default()
        },
    )
    .unwrap()
    .unwrap();
    let request_body = |id: &str| serde_json::json!({"approval_id":format!("approval-{id}"),"job_id":format!("job-{id}"),"reason":"owned approval fixture","expires_in_seconds":120});
    let approve_body = |id: &str| serde_json::json!({"approval_id":format!("approval-{id}"),"job_id":format!("job-{id}"),"runbook_document":REMEDIATION_READ_ONLY_RUNBOOK,"timeout_seconds":30,"expires_in_seconds":120,"reason":"owned decision fixture"});
    let requested = mutation(
        &server,
        &cookie,
        &person,
        reqwest::Method::POST,
        "/api/remediations/remed-before/approval-request",
        request_body("remed-before"),
    );
    assert_eq!(requested.status(), 201);
    if approve {
        assert_eq!(
            mutation(
                &server,
                &cookie,
                &person,
                reqwest::Method::POST,
                "/api/remediations/remed-after/approval-request",
                request_body("remed-after")
            )
            .status(),
            201
        );
        assert_eq!(
            mutation(
                &server,
                &cookie,
                &person,
                reqwest::Method::POST,
                "/api/remediations/remed-before/approve",
                approve_body("remed-before")
            )
            .status(),
            200
        );
    }
    assert_eq!(
        mutation(
            &server,
            &cookie,
            &person,
            reqwest::Method::POST,
            "/api/auth/logout",
            serde_json::json!({})
        )
        .status(),
        204
    );
    let denied = if approve {
        approve_remediation_job(
            "remed-after",
            &approve_body("remed-after").to_string(),
            &store,
            &ControllerIdentity::dev_insecure(),
            &context,
        )
        .map(|_| ())
    } else {
        create_remediation_approval_request(
            "remed-after",
            &request_body("remed-after").to_string(),
            &store,
            &context,
        )
        .map(|_| ())
    };
    assert!(matches!(
        denied,
        Err(RemediationHttpError::Authorization(
            fleet_application::admin_identity::AdminAccessError::Unauthorized
        ))
    ));
    assert_eq!(
        store
            .find_remediation_request_record("remed-after")
            .unwrap()
            .unwrap()
            .status,
        if approve {
            "pending_approval"
        } else {
            "proposed"
        }
    );
    assert!(store.find_job_summary("job-remed-after").unwrap().is_none());
    if approve {
        assert!(
            store
                .find_job_summary("job-remed-before")
                .unwrap()
                .is_some()
        );
    } else {
        assert!(
            store
                .find_approval_request("approval-remed-after")
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn personal_remediation_request_and_job_are_atomic_and_keep_different_human_actors() {
    let server = Server::personal();
    let (owner_cookie, owner) = server.login();
    let (request_cookie, requester) =
        server.active_user(&owner_cookie, "remediation_requester", AdminRole::Operator);
    let (approve_cookie, approver) =
        server.active_user(&owner_cookie, "remediation_approver", AdminRole::Operator);
    let path = server._root.path().join("controller/fleet.db");
    let store = SqliteStore::open(&path).unwrap();
    save_offline_agent(&store);
    save_proposed_remediation(&store, "atomic-remed");
    let connection = rusqlite::Connection::open(path).unwrap();
    let count = || store.list_audit_events(100).unwrap().len();
    let before = count();
    let request_body = serde_json::json!({"approval_id":"approval-atomic-remed","job_id":"job-atomic-remed","reason":"owned request","expires_in_seconds":120,"requester":"spoof"});
    for trigger in [
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON audit_events WHEN NEW.action='remediation_approval_requested' BEGIN SELECT RAISE(ABORT,'private remediation diagnostic'); END;",
        "CREATE TRIGGER fixture_remed_fault BEFORE UPDATE OF status ON remediation_requests WHEN NEW.id='atomic-remed' BEGIN SELECT RAISE(ABORT,'private remediation diagnostic'); END;",
    ] {
        connection.execute_batch(trigger).unwrap();
        let failed = mutation(
            &server,
            &request_cookie,
            &requester,
            reqwest::Method::POST,
            "/api/remediations/atomic-remed/approval-request",
            request_body.clone(),
        );
        assert_eq!(failed.status(), 503);
        assert!(
            !failed
                .text()
                .unwrap()
                .contains("private remediation diagnostic")
        );
        assert_eq!(
            store
                .find_remediation_request_record("atomic-remed")
                .unwrap()
                .unwrap()
                .status,
            "proposed"
        );
        assert!(
            store
                .find_approval_request("approval-atomic-remed")
                .unwrap()
                .is_none()
        );
        assert_eq!(count(), before);
        connection
            .execute_batch("DROP TRIGGER fixture_remed_fault;")
            .unwrap();
    }
    let requested = mutation(
        &server,
        &request_cookie,
        &requester,
        reqwest::Method::POST,
        "/api/remediations/atomic-remed/approval-request",
        request_body,
    );
    assert_eq!(requested.status(), 201);
    let pending = store
        .find_approval_request("approval-atomic-remed")
        .unwrap()
        .unwrap();
    assert_eq!(pending.requester, requester["user"]["id"].as_str().unwrap());
    let after_request = count();
    let approve_body = serde_json::json!({"approval_id":"approval-atomic-remed","job_id":"job-atomic-remed","runbook_document":REMEDIATION_READ_ONLY_RUNBOOK,"timeout_seconds":30,"expires_in_seconds":120,"reason":"owned decision","approver":"spoof"});
    for trigger in [
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON jobs WHEN NEW.id='job-atomic-remed' BEGIN SELECT RAISE(ABORT,'private remediation diagnostic'); END;",
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON task_assignments WHEN NEW.job_id='job-atomic-remed' BEGIN SELECT RAISE(ABORT,'private remediation diagnostic'); END;",
        "CREATE TRIGGER fixture_remed_fault BEFORE UPDATE OF status ON approval_requests WHEN NEW.id='approval-atomic-remed' BEGIN SELECT RAISE(ABORT,'private remediation diagnostic'); END;",
        "CREATE TRIGGER fixture_remed_fault BEFORE UPDATE OF status ON remediation_requests WHEN NEW.id='atomic-remed' BEGIN SELECT RAISE(ABORT,'private remediation diagnostic'); END;",
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON audit_events WHEN NEW.action='approval_approved' BEGIN SELECT RAISE(ABORT,'private remediation diagnostic'); END;",
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON audit_events WHEN NEW.action='runbook_job_created' BEGIN SELECT RAISE(ABORT,'private remediation diagnostic'); END;",
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON audit_events WHEN NEW.action='remediation_job_created' BEGIN SELECT RAISE(ABORT,'private remediation diagnostic'); END;",
    ] {
        connection.execute_batch(trigger).unwrap();
        let failed = mutation(
            &server,
            &approve_cookie,
            &approver,
            reqwest::Method::POST,
            "/api/remediations/atomic-remed/approve",
            approve_body.clone(),
        );
        assert_eq!(failed.status(), 503);
        assert!(
            !failed
                .text()
                .unwrap()
                .contains("private remediation diagnostic")
        );
        assert_eq!(
            store
                .find_remediation_request_record("atomic-remed")
                .unwrap()
                .unwrap()
                .status,
            "pending_approval"
        );
        assert_eq!(
            store
                .find_approval_request("approval-atomic-remed")
                .unwrap()
                .unwrap(),
            pending
        );
        assert!(
            store
                .find_job_summary("job-atomic-remed")
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .list_task_assignment_summaries_for_job("job-atomic-remed")
                .unwrap()
                .is_empty()
        );
        assert_eq!(count(), after_request);
        connection
            .execute_batch("DROP TRIGGER fixture_remed_fault;")
            .unwrap();
    }
    let approved = mutation(
        &server,
        &approve_cookie,
        &approver,
        reqwest::Method::POST,
        "/api/remediations/atomic-remed/approve",
        approve_body.clone(),
    );
    assert_eq!(approved.status(), 200);
    assert!(!approved.text().unwrap().contains("facts.collect"));
    let record = store
        .find_approval_request("approval-atomic-remed")
        .unwrap()
        .unwrap();
    assert_eq!(record.requester, requester["user"]["id"].as_str().unwrap());
    assert_eq!(record.approver.as_deref(), approver["user"]["id"].as_str());
    assert_ne!(record.requester, record.approver.as_deref().unwrap());
    assert_eq!(
        store
            .find_remediation_request_record("atomic-remed")
            .unwrap()
            .unwrap()
            .status,
        "job_created"
    );
    assert_eq!(
        store
            .find_job_summary("job-atomic-remed")
            .unwrap()
            .unwrap()
            .status,
        "queued"
    );
    assert_eq!(count(), after_request + 3);
    let duplicate = mutation(
        &server,
        &approve_cookie,
        &approver,
        reqwest::Method::POST,
        "/api/remediations/atomic-remed/approve",
        approve_body,
    );
    assert_eq!(duplicate.status(), 400);
    assert_eq!(count(), after_request + 3);
    let changed = mutation(
        &server,
        &owner_cookie,
        &owner,
        reqwest::Method::PATCH,
        &format!(
            "/api/admin/users/{}",
            requester["user"]["id"].as_str().unwrap()
        ),
        serde_json::json!({"display_name":"Changed requester","role":"viewer","current_password":PASSWORD}),
    );
    assert_eq!(changed.status(), 200);
    let events = store.list_audit_events(100).unwrap();
    let request_events = events
        .iter()
        .filter(|event| event.action == "remediation_approval_requested")
        .collect::<Vec<_>>();
    assert_eq!(request_events.len(), 1);
    assert_eq!(
        request_events[0].actor.as_str(),
        requester["user"]["id"].as_str().unwrap()
    );
    let decision_events = events
        .iter()
        .filter(|event| {
            matches!(
                event.action.as_str(),
                "approval_approved" | "runbook_job_created" | "remediation_job_created"
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(decision_events.len(), 3);
    assert!(
        decision_events
            .iter()
            .all(|event| event.actor.as_str() == approver["user"]["id"].as_str().unwrap())
    );
    assert_eq!(
        store
            .find_job_summary("job-atomic-remed")
            .unwrap()
            .unwrap()
            .status,
        "queued"
    );
}

#[test]
fn remediation_signing_releases_the_writer_and_rejects_late_revocation_or_state_changes() {
    use fleet_application::admin_identity::AdminAccessError;
    use fleet_application::admin_remediation::{AdminRemediationError, ApproveAdminRemediationJob};
    #[derive(Clone, Copy)]
    enum Change {
        Logout,
        Canceled,
        ApprovalExpiry,
    }
    struct ChangingSigner<'a> {
        server: &'a Server,
        cookie: &'a str,
        csrf: &'a str,
        actual: ControllerTaskSigner<'a>,
        change: Change,
        called: bool,
    }
    impl TaskEnvelopeSigner for ChangingSigner<'_> {
        type Error = fleet_core::IdentityError;
        fn sign(&mut self, payload: &str) -> Result<String, Self::Error> {
            assert!(!self.called);
            self.called = true;
            let connection =
                rusqlite::Connection::open(self.server._root.path().join("controller/fleet.db"))
                    .unwrap();
            connection.busy_timeout(Duration::from_millis(50)).unwrap();
            connection
                .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
                .expect("signing must precede the canonical writer lock");
            let signature = self.actual.sign(payload)?;
            match self.change {
                Change::Logout => {
                    let revoked = self
                        .server
                        .client
                        .post(format!("{}/api/auth/logout", self.server.origin))
                        .header("Cookie", self.cookie)
                        .header("Origin", &self.server.origin)
                        .header("X-Fleet-CSRF", self.csrf)
                        .send()
                        .unwrap();
                    assert_eq!(revoked.status(), 204);
                }
                Change::Canceled => {
                    connection.execute("UPDATE remediation_requests SET status='canceled' WHERE id='remed-sign'",[]).unwrap();
                }
                Change::ApprovalExpiry => {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    connection.execute("UPDATE approval_requests SET created_at=?1,expires_at=?2 WHERE id='approval-remed-sign'",rusqlite::params![now-120,now-1]).unwrap();
                }
            }
            Ok(signature)
        }
    }
    for change in [Change::Logout, Change::Canceled, Change::ApprovalExpiry] {
        let server = Server::personal();
        let (cookie, person) = server.login();
        let mut store = SqliteStore::open(server._root.path().join("controller/fleet.db")).unwrap();
        save_offline_agent(&store);
        save_proposed_remediation(&store, "remed-sign");
        let context = authenticate_admin_request_with_metadata(
            &format!("GET /api/agents HTTP/1.1\r\nCookie: {cookie}\r\n\r\n"),
            &store,
            &ControllerRuntimeMetadata {
                external_url: Some(server.origin.clone()),
                ..Default::default()
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(mutation(&server,&cookie,&person,reqwest::Method::POST,"/api/remediations/remed-sign/approval-request",serde_json::json!({"approval_id":"approval-remed-sign","job_id":"job-remed-sign","reason":"signing fixture","expires_in_seconds":120})).status(),201);
        let identity = ControllerIdentity::dev_insecure();
        let mut signer = ChangingSigner {
            server: &server,
            cookie: &cookie,
            csrf: person["csrf_token"].as_str().unwrap(),
            actual: ControllerTaskSigner {
                private_key: &identity.private_key,
                signing_fingerprint: &identity.fingerprint,
            },
            change,
            called: false,
        };
        let owner = AdminAuthRequest::new(AdminAuthSettings::new(1).unwrap()).unwrap();
        let now = SystemTime::now();
        let result = ApproveAdminRemediationJob::execute(
            &mut store,
            &context.principal,
            &owner.operation(),
            &mut signer,
            ApproveRemediationRunbookJobInput {
                remediation_id: "remed-sign".to_owned(),
                approval_id: "approval-remed-sign".to_owned(),
                job_id: "job-remed-sign".to_owned(),
                runbook_document: REMEDIATION_READ_ONLY_RUNBOOK.to_owned(),
                timeout: Duration::from_secs(30),
                approver: "spoof".to_owned(),
                approval_reason: "owned signing fixture".to_owned(),
                issued_at: now,
                expires_at: now + Duration::from_secs(120),
                nonce_prefix: "nonce-remed-sign".to_owned(),
            },
        );
        let expected = if matches!(change, Change::Logout) {
            AdminAccessError::Unauthorized
        } else {
            AdminAccessError::Conflict
        };
        assert!(matches!(result,Err(AdminRemediationError::Access(error)) if error==expected));
        assert!(signer.called);
        assert!(store.find_job_summary("job-remed-sign").unwrap().is_none());
        let remediation = store
            .find_remediation_request_record("remed-sign")
            .unwrap()
            .unwrap();
        assert_eq!(
            remediation.status,
            if matches!(change, Change::Canceled) {
                "canceled"
            } else {
                "pending_approval"
            }
        );
        assert!(remediation.job_id.is_none());
        assert_eq!(
            store
                .find_approval_request("approval-remed-sign")
                .unwrap()
                .unwrap()
                .status,
            "pending"
        );
        assert!(
            !store
                .list_audit_events(100)
                .unwrap()
                .iter()
                .any(|event| event.target.as_str() == "job-remed-sign")
        );
    }
}

#[test]
fn retained_context_cannot_expire_approvals_after_logout() {
    let server = Server::personal();
    let (cookie, person) = server.login();
    let path = server._root.path().join("controller/fleet.db");
    let store = SqliteStore::open(&path).unwrap();
    save_offline_agent(&store);
    let context = authenticate_admin_request_with_metadata(
        &format!("GET /api/agents HTTP/1.1\r\nCookie: {cookie}\r\n\r\n"),
        &store,
        &ControllerRuntimeMetadata {
            external_url: Some(server.origin.clone()),
            ..Default::default()
        },
    )
    .unwrap()
    .unwrap();
    let mut approvals = Vec::new();
    for job in ["expiry-before", "expiry-after"] {
        let created = mutation(
            &server,
            &cookie,
            &person,
            reqwest::Method::POST,
            "/api/jobs/command",
            serde_json::json!({"job_id":job,"target_agent_ids":["guard-agent"],"program":"systemctl","args":["status","nginx"],"timeout_seconds":30,"confirmed_high_risk":true}),
        );
        assert_eq!(created.status(), 201);
        approvals.push(
            created.json::<serde_json::Value>().unwrap()["approval_request_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let connection = rusqlite::Connection::open(path).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    connection
        .execute(
            "UPDATE approval_requests SET created_at=?2,expires_at=?3 WHERE id=?1",
            rusqlite::params![approvals[0], now - 120, now - 60],
        )
        .unwrap();
    let positive = mutation(
        &server,
        &cookie,
        &person,
        reqwest::Method::POST,
        "/api/approvals/expire",
        serde_json::json!({}),
    );
    assert_eq!(positive.status(), 200);
    assert_eq!(
        positive.json::<serde_json::Value>().unwrap()["expired_count"],
        1
    );
    let events = store
        .list_audit_events(100)
        .unwrap()
        .into_iter()
        .filter(|event| event.action == "approval_expired")
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].actor.as_str(),
        person["user"]["id"].as_str().unwrap()
    );

    assert_eq!(
        mutation(
            &server,
            &cookie,
            &person,
            reqwest::Method::POST,
            "/api/auth/logout",
            serde_json::json!({})
        )
        .status(),
        204
    );
    connection
        .execute(
            "UPDATE approval_requests SET created_at=?2,expires_at=?3 WHERE id=?1",
            rusqlite::params![approvals[1], now - 120, now - 60],
        )
        .unwrap();
    let denied = expire_approvals(&store, &context);
    assert!(matches!(
        denied,
        Err(CreateCommandJobHttpError::Authorization(
            fleet_application::admin_identity::AdminAccessError::Unauthorized
        ))
    ));
    assert_eq!(
        store
            .find_job_summary("expiry-before")
            .unwrap()
            .unwrap()
            .status,
        "expired"
    );
    assert_eq!(
        store
            .find_job_summary("expiry-after")
            .unwrap()
            .unwrap()
            .status,
        "pending_approval"
    );
    assert_eq!(
        store
            .find_approval_request(&approvals[1])
            .unwrap()
            .unwrap()
            .status,
        "pending"
    );
}

#[test]
fn retained_context_cannot_cancel_a_queued_job_after_logout() {
    let server = Server::personal();
    let (owner_cookie, _) = server.login();
    let (cookie, person) =
        server.active_user(&owner_cookie, "cancel_operator", AdminRole::Operator);
    let store = SqliteStore::open(server._root.path().join("controller/fleet.db")).unwrap();
    save_offline_agent(&store);
    let context = authenticate_admin_request_with_metadata(
        &format!("GET /api/agents HTTP/1.1\r\nCookie: {cookie}\r\n\r\n"),
        &store,
        &ControllerRuntimeMetadata {
            external_url: Some(server.origin.clone()),
            ..Default::default()
        },
    )
    .unwrap()
    .unwrap();
    for job in ["cancel-before", "cancel-retained"] {
        let created = mutation(
            &server,
            &cookie,
            &person,
            reqwest::Method::POST,
            "/api/jobs/command",
            serde_json::json!({"job_id":job,"target_agent_ids":["guard-agent"],"program":"uptime","args":[],"timeout_seconds":30,"confirmed_high_risk":false}),
        );
        assert_eq!(created.status(), 201);
    }
    let positive = mutation(
        &server,
        &cookie,
        &person,
        reqwest::Method::POST,
        "/api/jobs/cancel-before/cancel",
        serde_json::json!({"reason":"owned cancel fixture"}),
    );
    assert_eq!(
        positive.status(),
        200,
        "actual cancel succeeds before logout"
    );
    assert_eq!(
        store
            .find_job_summary("cancel-before")
            .unwrap()
            .unwrap()
            .status,
        "canceled"
    );
    assert_eq!(
        mutation(
            &server,
            &cookie,
            &person,
            reqwest::Method::POST,
            "/api/auth/logout",
            serde_json::json!({})
        )
        .status(),
        204
    );
    let denied = cancel_job("cancel-retained", "{}", &store, None, &context);
    assert!(matches!(
        denied,
        Err(CreateCommandJobHttpError::Authorization(
            fleet_application::admin_identity::AdminAccessError::Unauthorized
        ))
    ));
    assert_eq!(
        store
            .find_job_summary("cancel-retained")
            .unwrap()
            .unwrap()
            .status,
        "queued"
    );
}

#[test]
fn personal_cancellation_http_rolls_back_faults_and_audits_the_real_actor_once() {
    let server = Server::personal();
    let (owner_cookie, _) = server.login();
    let (cookie, person) =
        server.active_user(&owner_cookie, "atomic_canceler", AdminRole::Operator);
    let path = server._root.path().join("controller/fleet.db");
    let store = SqliteStore::open(&path).unwrap();
    save_offline_agent(&store);
    save_named_offline_agent(&store, "guard-agent-2");
    let created = mutation(
        &server,
        &cookie,
        &person,
        reqwest::Method::POST,
        "/api/jobs/command",
        serde_json::json!({"job_id":"atomic-cancel","target_agent_ids":["guard-agent","guard-agent-2"],"program":"uptime","args":[],"timeout_seconds":30,"confirmed_high_risk":false}),
    );
    assert_eq!(created.status(), 201);
    let approval = created.json::<serde_json::Value>().unwrap()["approval_request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        mutation(
            &server,
            &cookie,
            &person,
            reqwest::Method::POST,
            &format!("/api/approvals/{approval}/approve"),
            serde_json::json!({})
        )
        .status(),
        200
    );
    let connection = rusqlite::Connection::open(&path).unwrap();
    let before = store.list_audit_events(100).unwrap().len();
    let reason = "owned cancellation token=fixture-cancel-secret";
    for fault in [
        "CREATE TRIGGER fixture_cancel_fault BEFORE INSERT ON audit_events WHEN NEW.action='job_canceled' BEGIN SELECT RAISE(ABORT,'private cancellation diagnostic'); END;",
        "CREATE TRIGGER fixture_cancel_fault BEFORE UPDATE OF status ON jobs WHEN NEW.id='atomic-cancel' BEGIN SELECT RAISE(ABORT,'private cancellation diagnostic'); END;",
        "CREATE TRIGGER fixture_cancel_fault BEFORE UPDATE OF status ON task_assignments WHEN NEW.agent_id='guard-agent-2' AND NEW.status='canceled' BEGIN SELECT RAISE(ABORT,'private cancellation diagnostic'); END;",
    ] {
        connection.execute_batch(fault).unwrap();
        let failed = mutation(
            &server,
            &cookie,
            &person,
            reqwest::Method::POST,
            "/api/jobs/atomic-cancel/cancel",
            serde_json::json!({"reason":reason,"actor":"spoof"}),
        );
        assert_eq!(failed.status(), 503);
        assert!(
            !failed
                .text()
                .unwrap()
                .contains("private cancellation diagnostic")
        );
        assert_eq!(
            store
                .find_job_summary("atomic-cancel")
                .unwrap()
                .unwrap()
                .status,
            "queued"
        );
        assert!(store.list_task_assignment_summaries_for_job("atomic-cancel").unwrap().iter().all(|assignment|assignment.status=="queued" && assignment.last_error.is_empty()));
        assert_eq!(store.list_audit_events(100).unwrap().len(), before);
        connection
            .execute_batch("DROP TRIGGER fixture_cancel_fault;")
            .unwrap();
    }
    let canceled = mutation(
        &server,
        &cookie,
        &person,
        reqwest::Method::POST,
        "/api/jobs/atomic-cancel/cancel",
        serde_json::json!({"reason":reason,"actor":"spoof"}),
    );
    assert_eq!(canceled.status(), 200);
    let output: serde_json::Value = canceled.json().unwrap();
    assert_eq!(output["status"], "canceled");
    assert_eq!(output["canceled_count"], 2);
    assert_eq!(output["cancel_delivered_count"], 0);
    let events = store
        .list_audit_events(100)
        .unwrap()
        .into_iter()
        .filter(|event| event.target.as_str() == "atomic-cancel" && event.action == "job_canceled")
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].actor.as_str(),
        person["user"]["id"].as_str().unwrap()
    );
    let AuditValue::Plain(value) = &events[0].value else {
        panic!("structured cancellation audit");
    };
    assert!(!value.contains("fixture-cancel-secret"));
    assert!(value.contains("token=[REDACTED]"));
    assert!(value.contains("cancel_dispatch_candidate_count=0"));
    let repeated = mutation(
        &server,
        &cookie,
        &person,
        reqwest::Method::POST,
        "/api/jobs/atomic-cancel/cancel",
        serde_json::json!({"reason":"different reason"}),
    );
    assert_eq!(repeated.status(), 200);
    assert_eq!(
        repeated.json::<serde_json::Value>().unwrap()["canceled_count"],
        0
    );
    assert!(
        store
            .list_task_assignment_summaries_for_job("atomic-cancel")
            .unwrap()
            .iter()
            .all(|assignment| assignment.status == "canceled" && assignment.last_error == reason)
    );
    assert_eq!(store.list_audit_events(100).unwrap().len(), before + 1);
}

#[test]
fn retained_context_cannot_create_runbook_after_logout() {
    retained_structured_context(true);
}
#[test]
fn retained_context_cannot_create_drift_after_logout() {
    retained_structured_context(false);
}

fn retained_structured_context(runbook: bool) {
    let server = Server::personal();
    let (owner_cookie, _) = server.login();
    let (cookie, person) =
        server.active_user(&owner_cookie, "structured_operator", AdminRole::Operator);
    let store = SqliteStore::open(server._root.path().join("controller/fleet.db")).unwrap();
    save_offline_agent(&store);
    let context = authenticate_admin_request_with_metadata(
        &format!("GET /api/agents HTTP/1.1\r\nCookie: {cookie}\r\n\r\n"),
        &store,
        &ControllerRuntimeMetadata {
            external_url: Some(server.origin.clone()),
            ..Default::default()
        },
    )
    .unwrap()
    .unwrap();
    let body = |id: &str| {
        let mut value = serde_json::json!({"job_id":id,"target_agent_ids":["guard-agent"],"timeout_seconds":30,"confirmed_high_risk":true,"confirmed_by":"spoof","created_by":"spoof","expires_in_seconds":120});
        if runbook {
            value["runbook_document"] =
                include_str!("../../../examples/runbooks/nginx-basic.yml").into();
        } else {
            value["policy_document"] =
                include_str!("../../../examples/policies/nginx-running.yml").into();
        }
        value.to_string()
    };
    let identity = ControllerIdentity::dev_insecure();
    let create = |id: &str| {
        if runbook {
            create_runbook_job(&body(id), &store, &identity, &context)
        } else {
            create_drift_check_job(&body(id), &store, &identity, &context)
        }
    };
    assert!(
        create("structured-before").is_ok(),
        "real creation succeeds before revocation"
    );
    assert_eq!(
        mutation(
            &server,
            &cookie,
            &person,
            reqwest::Method::POST,
            "/api/auth/logout",
            serde_json::json!({})
        )
        .status(),
        204
    );
    assert!(
        matches!(
            create("structured-after"),
            Err(CreateCommandJobHttpError::Authorization(
                fleet_application::admin_identity::AdminAccessError::Unauthorized
            ))
        ),
        "retained structured Job context must be unauthorized"
    );
    assert!(
        store
            .find_job_summary("structured-after")
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .find_job_summary("structured-before")
            .unwrap()
            .is_some()
    );
}

#[test]
fn retained_approver_context_cannot_decide_after_logout() {
    for approve in [true, false] {
        let server = Server::personal();
        let (owner_cookie, _) = server.login();
        let (cookie, profile) =
            server.active_user(&owner_cookie, "decision_operator", AdminRole::Operator);
        let store = SqliteStore::open(server._root.path().join("controller/fleet.db")).unwrap();
        save_offline_agent(&store);
        let context = authenticate_admin_request_with_metadata(
            &format!("GET /api/agents HTTP/1.1\r\nCookie: {cookie}\r\n\r\n"),
            &store,
            &ControllerRuntimeMetadata {
                external_url: Some(server.origin.clone()),
                ..Default::default()
            },
        )
        .unwrap()
        .unwrap();
        let mut approvals = Vec::new();
        for job in ["decision-before", "decision-after"] {
            let created = mutation(
                &server,
                &cookie,
                &profile,
                reqwest::Method::POST,
                "/api/jobs/command",
                serde_json::json!({"job_id":job,"target_agent_ids":["guard-agent"],"program":"systemctl","args":["status","nginx"],"timeout_seconds":30,"confirmed_high_risk":true}),
            );
            assert_eq!(created.status(), 201);
            approvals.push(
                created.json::<serde_json::Value>().unwrap()["approval_request_id"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            );
        }
        let action = if approve { "approve" } else { "reject" };
        let decided = mutation(
            &server,
            &cookie,
            &profile,
            reqwest::Method::POST,
            &format!("/api/approvals/{}/{action}", approvals[0]),
            serde_json::json!({"reason":"owned fixture"}),
        );
        assert_eq!(
            decided.status(),
            200,
            "success prerequisite must use the real route"
        );
        assert_eq!(
            mutation(
                &server,
                &cookie,
                &profile,
                reqwest::Method::POST,
                "/api/auth/logout",
                serde_json::json!({})
            )
            .status(),
            204
        );
        let denied = if approve {
            approve_approval(
                &approvals[1],
                "{\"reason\":\"stale fixture\"}",
                &store,
                &context,
            )
            .map(|_| ())
        } else {
            reject_approval(
                &approvals[1],
                "{\"reason\":\"stale fixture\"}",
                &store,
                &context,
            )
            .map(|_| ())
        };
        assert!(
            matches!(
                denied,
                Err(CreateCommandJobHttpError::Authorization(
                    fleet_application::admin_identity::AdminAccessError::Unauthorized
                ))
            ),
            "a retained approver context must be unauthorized after logout"
        );
        assert_eq!(
            store
                .find_approval_request(&approvals[1])
                .unwrap()
                .unwrap()
                .status,
            "pending"
        );
        assert_eq!(
            store
                .find_job_summary("decision-after")
                .unwrap()
                .unwrap()
                .status,
            "pending_approval"
        );
        assert_eq!(
            store
                .find_approval_request(&approvals[0])
                .unwrap()
                .unwrap()
                .status,
            if approve { "approved" } else { "rejected" }
        );
    }
}

#[test]
fn personal_approval_decisions_are_atomic_and_preserve_both_actors() {
    let server = Server::personal();
    let (owner_cookie, owner) = server.login();
    let (request_cookie, requester) =
        server.active_user(&owner_cookie, "request_operator", AdminRole::Operator);
    let (decision_cookie, approver) =
        server.active_user(&owner_cookie, "approve_operator", AdminRole::Operator);
    let path = server._root.path().join("controller/fleet.db");
    let store = SqliteStore::open(&path).unwrap();
    save_offline_agent(&store);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let count = || {
        connection
            .query_row("SELECT count(*) FROM audit_events", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
    };
    for action in ["approve", "reject"] {
        let job = format!("atomic-{action}");
        let created = mutation(
            &server,
            &request_cookie,
            &requester,
            reqwest::Method::POST,
            "/api/jobs/command",
            serde_json::json!({"job_id":job,"target_agent_ids":["guard-agent"],"program":"systemctl","args":["status","nginx"],"timeout_seconds":30,"confirmed_high_risk":true,"confirmed_by":"spoof"}),
        );
        assert_eq!(created.status(), 201);
        let approval = created.json::<serde_json::Value>().unwrap()["approval_request_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let endpoint = format!("/api/approvals/{approval}/{action}");
        let body = serde_json::json!({"reason":"owned decision fixture","approver":"spoof"});
        let before = count();
        for fault in [
            "CREATE TRIGGER fixture_approval_fault BEFORE INSERT ON audit_events WHEN NEW.action IN ('approval_approved','approval_rejected') BEGIN SELECT RAISE(ABORT,'private approval diagnostic'); END;",
            "CREATE TRIGGER fixture_approval_fault BEFORE UPDATE OF status ON jobs BEGIN SELECT RAISE(ABORT,'private approval diagnostic'); END;",
        ] {
            connection.execute_batch(fault).unwrap();
            let failed = mutation(
                &server,
                &decision_cookie,
                &approver,
                reqwest::Method::POST,
                &endpoint,
                body.clone(),
            );
            assert_eq!(failed.status(), 503);
            assert!(
                !failed
                    .text()
                    .unwrap()
                    .contains("private approval diagnostic")
            );
            let record = store.find_approval_request(&approval).unwrap().unwrap();
            assert_eq!(record.status, "pending");
            assert!(record.approver.is_none());
            assert_eq!(
                store.find_job_summary(&job).unwrap().unwrap().status,
                "pending_approval"
            );
            assert_eq!(count(), before);
            connection
                .execute_batch("DROP TRIGGER fixture_approval_fault;")
                .unwrap();
        }
        let decided = mutation(
            &server,
            &decision_cookie,
            &approver,
            reqwest::Method::POST,
            &endpoint,
            body.clone(),
        );
        assert_eq!(decided.status(), 200);
        let record = store.find_approval_request(&approval).unwrap().unwrap();
        assert_eq!(record.requester, requester["user"]["id"].as_str().unwrap());
        assert_eq!(record.approver.as_deref(), approver["user"]["id"].as_str());
        assert_ne!(record.requester, record.approver.as_deref().unwrap());
        assert_eq!(
            record.status,
            if action == "approve" {
                "approved"
            } else {
                "rejected"
            }
        );
        assert_eq!(
            store.find_job_summary(&job).unwrap().unwrap().status,
            if action == "approve" {
                "queued"
            } else {
                "failed"
            }
        );
        let duplicate = mutation(
            &server,
            &decision_cookie,
            &approver,
            reqwest::Method::POST,
            &endpoint,
            body,
        );
        assert_eq!(duplicate.status(), 400);
        assert_eq!(
            count(),
            before + 1,
            "a repeated decision creates no audit or other effect"
        );
    }
    let edited = mutation(
        &server,
        &owner_cookie,
        &owner,
        reqwest::Method::PATCH,
        &format!(
            "/api/admin/users/{}",
            approver["user"]["id"].as_str().unwrap()
        ),
        serde_json::json!({"display_name":"Changed name","role":"viewer","current_password":PASSWORD}),
    );
    assert_eq!(edited.status(), 200);
    for job in ["atomic-approve", "atomic-reject"] {
        let events = store
            .list_audit_events(100)
            .unwrap()
            .into_iter()
            .filter(|event| event.target.as_str() == job)
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 3);
        assert!(
            events
                .iter()
                .filter(
                    |event| event.action == "approval_requested" || event.action == "job_created"
                )
                .all(|event| event.actor.as_str() == requester["user"]["id"].as_str().unwrap())
        );
        assert!(
            events
                .iter()
                .filter(|event| event.action == "approval_approved"
                    || event.action == "approval_rejected")
                .all(|event| event.actor.as_str() == approver["user"]["id"].as_str().unwrap())
        );
    }
    assert_eq!(
        store
            .find_job_summary("atomic-approve")
            .unwrap()
            .unwrap()
            .status,
        "queued"
    );
}

fn save_offline_agent(store: &SqliteStore) {
    save_named_offline_agent(store, "guard-agent");
}

fn save_named_offline_agent(store: &SqliteStore, id: &str) {
    let key = fleet_core::generate_agent_key_pair().unwrap();
    store
        .save_agent(Agent::new(
            AgentId::new(id).unwrap(),
            AgentName::new(id).unwrap(),
            AgentIdentity {
                public_key: AgentPublicKey::new(key.public_key_hex).unwrap(),
                fingerprint: AgentFingerprint::new(key.fingerprint).unwrap(),
            },
        ))
        .unwrap();
}

#[test]
fn structured_job_http_faults_roll_back_targets_assignments_approval_and_audit() {
    let server = Server::personal();
    let (owner_cookie, _) = server.login();
    let (cookie, profile) =
        server.active_user(&owner_cookie, "atomic_structured", AdminRole::Operator);
    let path = server._root.path().join("controller/fleet.db");
    let store = SqliteStore::open(&path).unwrap();
    save_offline_agent(&store);
    save_named_offline_agent(&store, "guard-agent-2");
    let connection = rusqlite::Connection::open(path).unwrap();
    let counts = || {
        connection.query_row("SELECT (SELECT count(*) FROM jobs),(SELECT count(*) FROM task_assignments),(SELECT count(*) FROM job_targets),(SELECT count(*) FROM approval_requests),(SELECT count(*) FROM audit_events)", [], |row| Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?,row.get::<_,i64>(3)?,row.get::<_,i64>(4)?))).unwrap()
    };
    for runbook in [true, false] {
        let job = if runbook {
            "atomic-runbook"
        } else {
            "atomic-drift"
        };
        let endpoint = if runbook {
            "/api/jobs/runbook"
        } else {
            "/api/jobs/drift-check"
        };
        let mut body = serde_json::json!({"job_id":job,"target_agent_ids":["guard-agent","guard-agent-2"],"timeout_seconds":30,"confirmed_high_risk":true,"confirmed_by":"spoof","created_by":"spoof","strategy":{"concurrency":2,"maxFailures":1}});
        if runbook {
            body["runbook_document"] =
                include_str!("../../../examples/runbooks/nginx-basic.yml").into();
        } else {
            body["policy_document"] =
                include_str!("../../../examples/policies/nginx-running.yml").into();
        }
        let before = counts();
        for fault in [
            "CREATE TRIGGER fixture_structured_fault BEFORE INSERT ON audit_events WHEN NEW.action IN ('runbook_job_created','drift_check_job_created') BEGIN SELECT RAISE(ABORT,'private structured diagnostic'); END;",
            "CREATE TRIGGER fixture_structured_fault BEFORE INSERT ON approval_requests BEGIN SELECT RAISE(ABORT,'private structured diagnostic'); END;",
            "CREATE TRIGGER fixture_structured_fault BEFORE INSERT ON task_assignments WHEN NEW.agent_id='guard-agent-2' BEGIN SELECT RAISE(ABORT,'private structured diagnostic'); END;",
        ] {
            connection.execute_batch(fault).unwrap();
            let failed = mutation(
                &server,
                &cookie,
                &profile,
                reqwest::Method::POST,
                endpoint,
                body.clone(),
            );
            assert!(failed.status().is_server_error());
            assert!(
                !failed
                    .text()
                    .unwrap()
                    .contains("private structured diagnostic")
            );
            assert_eq!(counts(), before, "every creation effect must roll back");
            connection
                .execute_batch("DROP TRIGGER fixture_structured_fault;")
                .unwrap();
        }
        let created = mutation(
            &server,
            &cookie,
            &profile,
            reqwest::Method::POST,
            endpoint,
            body.clone(),
        );
        assert_eq!(created.status(), 201);
        let output: serde_json::Value = created.json().unwrap();
        assert_eq!(output["status"], "pending_approval");
        assert_eq!(output["target_count"], 2);
        assert_eq!(output["assignment_count"], 2);
        let approval = store
            .find_approval_request(output["approval_request_id"].as_str().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(approval.requester, profile["user"]["id"].as_str().unwrap());
        let summary = store.find_job_summary(job).unwrap().unwrap();
        assert_eq!(summary.strategy_concurrency, 2);
        assert_eq!(summary.strategy_max_failures, Some(1));
        assert_eq!(summary.selector_kind, "explicit_ids");
        let after = counts();
        let duplicate = mutation(
            &server,
            &cookie,
            &profile,
            reqwest::Method::POST,
            endpoint,
            body,
        );
        assert_eq!(duplicate.status(), 409);
        assert_eq!(
            duplicate.json::<serde_json::Value>().unwrap()["error"],
            "job_already_exists"
        );
        assert_eq!(counts(), after);
    }
}

#[test]
fn command_transaction_serializes_the_guard_and_preserves_a_job_committed_before_logout() {
    use fleet_application::admin_identity::{
        AdminAccessError, AdminMutationPrincipal, AdminOperation,
    };
    use fleet_application::{
        AdminCommandCommitError, AdminCommandJobRepository, CommandCreationMetadata,
        CreateAuthorizedCommandJob, PreparedCommandJob,
    };
    use std::sync::{Condvar, atomic::AtomicBool, mpsc};
    struct Gate {
        entered: mpsc::SyncSender<()>,
        released: Mutex<bool>,
        changed: Condvar,
        used: AtomicBool,
    }
    struct Paused<'a> {
        inner: &'a dyn AdminOperation,
        gate: &'a Gate,
    }
    impl AdminOperation for Paused<'_> {
        fn checked_now(&self) -> Result<i64, AdminAccessError> {
            if !self.gate.used.swap(true, Ordering::SeqCst) {
                self.gate
                    .entered
                    .send(())
                    .map_err(|_| AdminAccessError::Unavailable)?;
                let released = self
                    .gate
                    .released
                    .lock()
                    .map_err(|_| AdminAccessError::Unavailable)?;
                let (released, timeout) = self
                    .gate
                    .changed
                    .wait_timeout_while(released, Duration::from_secs(3), |value| !*value)
                    .map_err(|_| AdminAccessError::Unavailable)?;
                if timeout.timed_out() && !*released {
                    return Err(AdminAccessError::OperationExpired);
                }
            }
            self.inner.checked_now()
        }
    }
    struct Repository {
        store: SqliteStore,
        gate: Arc<Gate>,
    }
    impl AdminCommandJobRepository for Repository {
        type Error = fleet_store::StoreError;
        fn commit_admin_command_job(
            &mut self,
            principal: &AdminMutationPrincipal,
            operation: &dyn AdminOperation,
            creation: &PreparedCommandJob,
            metadata: &CommandCreationMetadata,
        ) -> Result<(), AdminCommandCommitError<Self::Error>> {
            self.store.commit_admin_command_record(
                principal,
                &Paused {
                    inner: operation,
                    gate: &self.gate,
                },
                creation,
                metadata,
            )
        }
    }
    struct Release(Arc<Gate>);
    impl Drop for Release {
        fn drop(&mut self) {
            *self.0.released.lock().unwrap() = true;
            self.0.changed.notify_all();
        }
    }
    let server = Server::personal();
    let (owner_cookie, _) = server.login();
    let (cookie, profile) =
        server.active_user(&owner_cookie, "ordered_operator", AdminRole::Operator);
    let path = server._root.path().join("controller/fleet.db");
    let store = SqliteStore::open(&path).unwrap();
    save_offline_agent(&store);
    let context = authenticate_admin_request_with_metadata(
        &format!("GET /api/agents HTTP/1.1\r\nCookie: {cookie}\r\n\r\n"),
        &store,
        &ControllerRuntimeMetadata {
            external_url: Some(server.origin.clone()),
            ..Default::default()
        },
    )
    .unwrap()
    .unwrap();
    let (entered, receiver) = mpsc::sync_channel(1);
    let gate = Arc::new(Gate {
        entered,
        released: Mutex::new(false),
        changed: Condvar::new(),
        used: AtomicBool::new(false),
    });
    std::thread::scope(|scope| {
        let release = Release(gate.clone());
        let gate = gate.clone();
        let writer_path = path.clone();
        let writer = scope.spawn(move || {
            let mut repository = Repository {
                store: SqliteStore::open(writer_path).unwrap(),
                gate,
            };
            let identity = ControllerIdentity::dev_insecure();
            let mut signer = ControllerTaskSigner {
                private_key: &identity.private_key,
                signing_fingerprint: &identity.fingerprint,
            };
            let request = AdminAuthRequest::new(AdminAuthSettings::new(1).unwrap()).unwrap();
            let now = SystemTime::now();
            CreateAuthorizedCommandJob::execute(
                &mut repository,
                &context.principal,
                &request.operation(),
                &mut signer,
                CreateCommandJobInput {
                    job_id: "write-before-logout".to_owned(),
                    target_agent_ids: vec!["guard-agent".to_owned()],
                    program: "uptime".to_owned(),
                    args: Vec::new(),
                    timeout: Duration::from_secs(30),
                    confirmed_high_risk: false,
                    confirmed_by: "spoof".to_owned(),
                    issued_at: now,
                    expires_at: now + Duration::from_secs(120),
                    nonce_prefix: "ordered-write".to_owned(),
                    approval_request_id: "ordered-approval".to_owned(),
                    approval_expires_at: now + Duration::from_secs(120),
                },
                &CommandCreationMetadata::new(
                    1,
                    None,
                    "explicit_ids",
                    "[\"guard-agent\"]".to_owned(),
                )
                .unwrap(),
            )
            .is_ok()
        });
        receiver.recv_timeout(Duration::from_secs(3)).unwrap();
        let other = rusqlite::Connection::open(&path).unwrap();
        other.busy_timeout(Duration::from_millis(50)).unwrap();
        let busy = other.execute_batch("BEGIN IMMEDIATE;").unwrap_err();
        assert!(
            matches!(busy,rusqlite::Error::SqliteFailure(error,_) if error.code==rusqlite::ErrorCode::DatabaseBusy),
            "the canonical guard must already hold the same writer transaction as its effects"
        );
        drop(release);
        assert!(writer.join().unwrap());
    });
    let before = store
        .find_job_summary("write-before-logout")
        .unwrap()
        .unwrap();
    assert_eq!(
        mutation(
            &server,
            &cookie,
            &profile,
            reqwest::Method::POST,
            "/api/auth/logout",
            serde_json::json!({})
        )
        .status(),
        204
    );
    let after = store
        .find_job_summary("write-before-logout")
        .unwrap()
        .unwrap();
    assert_eq!(after.status, before.status);
    assert_eq!(after.target_agents, before.target_agents);
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .header("Cookie", &cookie)
            .send()
            .unwrap()
            .status(),
        401
    );
}

#[test]
fn personal_command_http_audit_failure_rolls_back_job_assignments_approval_and_settings() {
    let server = Server::personal();
    let (owner_cookie, _) = server.login();
    let (cookie, profile) =
        server.active_user(&owner_cookie, "atomic_operator", AdminRole::Operator);
    let store = SqliteStore::open(server._root.path().join("controller/fleet.db")).unwrap();
    save_offline_agent(&store);
    let connection =
        rusqlite::Connection::open(server._root.path().join("controller/fleet.db")).unwrap();
    let counts = || {
        connection.query_row("SELECT (SELECT count(*) FROM jobs),(SELECT count(*) FROM task_assignments),(SELECT count(*) FROM approval_requests),(SELECT count(*) FROM audit_events)",[],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?,row.get::<_,i64>(3)?))).unwrap()
    };
    let before = counts();
    let body = serde_json::json!({"job_id":"atomic-command","target_agent_ids":["guard-agent"],"program":"systemctl","args":["status","nginx"],"timeout_seconds":30,"confirmed_high_risk":true,"confirmed_by":"spoof","strategy":{"concurrency":2,"maxFailures":1}});
    for trigger in [
        "CREATE TRIGGER fixture_command_fault BEFORE INSERT ON audit_events WHEN NEW.action='job_created' BEGIN SELECT RAISE(ABORT,'fixture private command diagnostic'); END;",
        "CREATE TRIGGER fixture_command_fault BEFORE UPDATE OF strategy_concurrency ON jobs WHEN NEW.id='atomic-command' BEGIN SELECT RAISE(ABORT,'fixture private command diagnostic'); END;",
    ] {
        connection.execute_batch(trigger).unwrap();
        let failed = mutation(
            &server,
            &cookie,
            &profile,
            reqwest::Method::POST,
            "/api/jobs/command",
            body.clone(),
        );
        assert!(failed.status().is_server_error());
        assert!(
            !failed
                .text()
                .unwrap()
                .contains("private command diagnostic")
        );
        assert_eq!(
            counts(),
            before,
            "audit or metadata failure must roll back every creation effect"
        );
        connection
            .execute_batch("DROP TRIGGER fixture_command_fault;")
            .unwrap();
    }
    let created = mutation(
        &server,
        &cookie,
        &profile,
        reqwest::Method::POST,
        "/api/jobs/command",
        body.clone(),
    );
    assert_eq!(created.status(), 201);
    let created: serde_json::Value = created.json().unwrap();
    assert_eq!(created["status"], "pending_approval");
    let summary = store.find_job_summary("atomic-command").unwrap().unwrap();
    assert_eq!(summary.strategy_concurrency, 2);
    assert_eq!(summary.strategy_max_failures, Some(1));
    assert_eq!(summary.selector_kind, "explicit_ids");
    let actors = store
        .list_audit_events(100)
        .unwrap()
        .into_iter()
        .filter(|event| event.target.as_str() == "atomic-command")
        .map(|event| event.actor.as_str().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        actors,
        vec![profile["user"]["id"].as_str().unwrap().to_owned(); 2]
    );
    let committed = counts();
    let duplicate = mutation(
        &server,
        &cookie,
        &profile,
        reqwest::Method::POST,
        "/api/jobs/command",
        body,
    );
    assert_eq!(duplicate.status(), 409);
    assert_eq!(
        duplicate.json::<serde_json::Value>().unwrap()["error"],
        "job_already_exists"
    );
    assert_eq!(
        counts(),
        committed,
        "duplicate creation never adds approval/audit rows"
    );
}

#[test]
fn command_preparation_keeps_sqlite_writer_available_and_revoked_proof_never_commits() {
    use fleet_application::admin_identity::AdminAccessError;
    use fleet_application::{
        AdminCommandCommitError, CommandCreationMetadata, CreateAuthorizedCommandJob,
        CreateAuthorizedCommandJobError,
    };
    struct RevokeSigner<'a> {
        server: &'a Server,
        cookie: &'a str,
        csrf: &'a str,
        actual: ControllerTaskSigner<'a>,
        called: bool,
    }
    impl TaskEnvelopeSigner for RevokeSigner<'_> {
        type Error = fleet_core::IdentityError;
        fn sign(&mut self, payload: &str) -> Result<String, Self::Error> {
            assert!(!self.called);
            self.called = true;
            let connection =
                rusqlite::Connection::open(self.server._root.path().join("controller/fleet.db"))
                    .unwrap();
            connection.busy_timeout(Duration::from_millis(50)).unwrap();
            connection
                .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
                .expect("signing preparation must not hold the writer lock");
            let revoked = self
                .server
                .client
                .post(format!("{}/api/auth/logout", self.server.origin))
                .header("Cookie", self.cookie)
                .header("Origin", &self.server.origin)
                .header("X-Fleet-CSRF", self.csrf)
                .send()
                .unwrap();
            assert_eq!(revoked.status(), 204);
            self.actual.sign(payload)
        }
    }
    let server = Server::personal();
    let (owner_cookie, _) = server.login();
    let (cookie, profile) =
        server.active_user(&owner_cookie, "preparation_operator", AdminRole::Operator);
    let mut store = SqliteStore::open(server._root.path().join("controller/fleet.db")).unwrap();
    save_offline_agent(&store);
    let context = authenticate_admin_request_with_metadata(
        &format!("GET /api/agents HTTP/1.1\r\nCookie: {cookie}\r\n\r\n"),
        &store,
        &ControllerRuntimeMetadata {
            external_url: Some(server.origin.clone()),
            ..Default::default()
        },
    )
    .unwrap()
    .unwrap();
    let identity = ControllerIdentity::dev_insecure();
    let mut signer = RevokeSigner {
        server: &server,
        cookie: &cookie,
        csrf: profile["csrf_token"].as_str().unwrap(),
        actual: ControllerTaskSigner {
            private_key: &identity.private_key,
            signing_fingerprint: &identity.fingerprint,
        },
        called: false,
    };
    let now = SystemTime::now();
    let owner = AdminAuthRequest::new(AdminAuthSettings::new(1).unwrap()).unwrap();
    let result = CreateAuthorizedCommandJob::execute(
        &mut store,
        &context.principal,
        &owner.operation(),
        &mut signer,
        CreateCommandJobInput {
            job_id: "revoked-during-prepare".to_owned(),
            target_agent_ids: vec!["guard-agent".to_owned()],
            program: "uptime".to_owned(),
            args: Vec::new(),
            timeout: Duration::from_secs(30),
            confirmed_high_risk: false,
            confirmed_by: "spoof".to_owned(),
            issued_at: now,
            expires_at: now + Duration::from_secs(120),
            nonce_prefix: "guard-prep".to_owned(),
            approval_request_id: "guard-prep-approval".to_owned(),
            approval_expires_at: now + Duration::from_secs(120),
        },
        &CommandCreationMetadata::new(1, None, "explicit_ids", "[\"guard-agent\"]".to_owned())
            .unwrap(),
    );
    assert!(matches!(
        result,
        Err(CreateAuthorizedCommandJobError::Commit(
            AdminCommandCommitError::Authorization(AdminAccessError::Unauthorized)
        ))
    ));
    assert!(signer.called);
    assert!(
        store
            .find_job_summary("revoked-during-prepare")
            .unwrap()
            .is_none()
    );
    assert!(
        !store
            .list_audit_events(100)
            .unwrap()
            .iter()
            .any(|event| event.target.as_str() == "revoked-during-prepare")
    );
}

fn revoked_context_cannot_create_command(disable: bool) {
    let server = Server::personal();
    let (owner_cookie, owner) = server.login();
    let (cookie, person) =
        server.active_user(&owner_cookie, "business_operator", AdminRole::Operator);
    let store = SqliteStore::open(server._root.path().join("controller/fleet.db")).unwrap();
    save_offline_agent(&store);
    let metadata = ControllerRuntimeMetadata {
        external_url: Some(server.origin.clone()),
        ..Default::default()
    };
    let request = format!("GET /api/agents HTTP/1.1\r\nCookie: {cookie}\r\n\r\n");
    let context = authenticate_admin_request_with_metadata(&request, &store, &metadata)
        .unwrap()
        .unwrap();
    assert_eq!(context.actor_id, person["user"]["id"].as_str().unwrap());
    let body = |job: &str| {
        serde_json::json!({"job_id":job,"target_agent_ids":["guard-agent"],"program":"uptime","args":[],"timeout_seconds":30,"confirmed_high_risk":false,"confirmed_by":"untrusted-body-actor","expires_in_seconds":120}).to_string()
    };
    let identity = ControllerIdentity::dev_insecure();
    assert!(create_command_job(&body("guard-before"), &store, &identity, &context).is_ok());
    assert!(store.find_job_summary("guard-before").unwrap().is_some());
    let revoked = if disable {
        mutation(
            &server,
            &owner_cookie,
            &owner,
            reqwest::Method::PATCH,
            &format!("/api/admin/users/{}", context.actor_id),
            serde_json::json!({"disable":true,"current_password":PASSWORD}),
        )
    } else {
        mutation(
            &server,
            &cookie,
            &person,
            reqwest::Method::POST,
            "/api/auth/logout",
            serde_json::json!({}),
        )
    };
    assert_eq!(revoked.status(), if disable { 200 } else { 204 });
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .header("Cookie", &cookie)
            .send()
            .unwrap()
            .status(),
        401
    );
    let result = create_command_job(&body("guard-after"), &store, &identity, &context);
    assert!(
        matches!(
            result,
            Err(CreateCommandJobHttpError::Authorization(
                fleet_application::admin_identity::AdminAccessError::Unauthorized
            ))
        ),
        "a server-verified context retained before revocation must not commit a later Command Job"
    );
    assert!(store.find_job_summary("guard-after").unwrap().is_none());
    assert!(
        store.find_job_summary("guard-before").unwrap().is_some(),
        "a previously committed Job survives human revocation"
    );
}

#[test]
fn disabled_operator_context_cannot_commit_a_new_command_after_revocation() {
    revoked_context_cannot_create_command(true);
}

#[test]
fn logged_out_operator_context_cannot_commit_a_new_command_while_account_stays_active() {
    revoked_context_cannot_create_command(false);
}

#[test]
fn human_logout_keeps_agent_websocket_and_delivered_job_and_survives_controller_restart() {
    use tungstenite::Message;
    fn send(
        socket: &mut tungstenite::WebSocket<std::net::TcpStream>,
        payload: fleet_protocol::WirePayload,
        id: &str,
    ) {
        socket
            .send(Message::Text(
                fleet_protocol::encode_message(&fleet_protocol::WireMessage::new(
                    id,
                    "identity-agent-session",
                    Some("guard-agent".to_owned()),
                    1,
                    payload,
                ))
                .unwrap(),
            ))
            .unwrap();
    }
    fn read(
        socket: &mut tungstenite::WebSocket<std::net::TcpStream>,
    ) -> fleet_protocol::WireMessage {
        loop {
            match socket.read().unwrap() {
                Message::Text(text) => return fleet_protocol::decode_message(&text).unwrap(),
                Message::Ping(value) => socket.send(Message::Pong(value)).unwrap(),
                other => panic!("expected agent wire message, got {other:?}"),
            }
        }
    }
    let mut server = Server::personal();
    let (cookie, person) = server.login();
    let store = SqliteStore::open(server._root.path().join("controller/fleet.db")).unwrap();
    let keys = fleet_core::generate_agent_key_pair().unwrap();
    store
        .save_agent(Agent::new(
            AgentId::new("guard-agent").unwrap(),
            AgentName::new("guard-agent").unwrap(),
            AgentIdentity {
                public_key: AgentPublicKey::new(keys.public_key_hex).unwrap(),
                fingerprint: AgentFingerprint::new(keys.fingerprint.clone()).unwrap(),
            },
        ))
        .unwrap();
    let address = server.origin.strip_prefix("http://").unwrap();
    let stream = std::net::TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (mut socket, _) =
        tungstenite::client(format!("ws://{address}/api/agents/ws"), stream).unwrap();
    send(
        &mut socket,
        fleet_protocol::WirePayload::AgentHello {
            agent_id: "guard-agent".to_owned(),
            fingerprint: keys.fingerprint,
        },
        "identity-hello",
    );
    let fleet_protocol::WirePayload::AuthChallenge { nonce } = read(&mut socket).payload else {
        panic!("identity challenge required");
    };
    send(
        &mut socket,
        fleet_protocol::WirePayload::AuthResponse {
            signature: fleet_core::sign_challenge(&keys.private_key_hex, &nonce).unwrap(),
            nonce,
        },
        "identity-proof",
    );
    assert!(matches!(
        read(&mut socket).payload,
        fleet_protocol::WirePayload::AuthAccepted { .. }
    ));
    let body = serde_json::json!({"job_id":"delivered-before-logout","target_agent_ids":["guard-agent"],
        "program":"uptime","args":[],"timeout_seconds":30,"confirmed_high_risk":false,"expires_in_seconds":120});
    let created = mutation(
        &server,
        &cookie,
        &person,
        reqwest::Method::POST,
        "/api/jobs/command",
        body.clone(),
    );
    assert_eq!(created.status(), 201);
    assert!(matches!(
        read(&mut socket).payload,
        fleet_protocol::WirePayload::TaskAssignment { .. }
    ));
    let before = store
        .find_job_summary("delivered-before-logout")
        .unwrap()
        .unwrap();
    assert_eq!(
        mutation(
            &server,
            &cookie,
            &person,
            reqwest::Method::POST,
            "/api/auth/logout",
            serde_json::json!({})
        )
        .status(),
        204
    );
    // A control round-trip after human revocation proves that this authenticated
    // Agent transport is still usable, without executing any host command.
    socket.send(Message::Ping(vec![1, 2, 3])).unwrap();
    loop {
        match socket.read().unwrap() {
            Message::Pong(value) => {
                assert_eq!(value, vec![1, 2, 3]);
                break;
            }
            Message::Ping(value) => socket.send(Message::Pong(value)).unwrap(),
            other => panic!("human logout must not send a cancel or close: {other:?}"),
        }
    }
    assert_eq!(
        store
            .find_job_summary("delivered-before-logout")
            .unwrap()
            .unwrap(),
        before
    );
    assert_eq!(
        mutation(
            &server,
            &cookie,
            &person,
            reqwest::Method::POST,
            "/api/jobs/command",
            {
                let mut denied = body.clone();
                denied["job_id"] = serde_json::json!("denied-after-logout");
                denied
            }
        )
        .status(),
        401
    );
    socket.close(None).unwrap();
    drop(socket);
    server.shutdown.store(true, Ordering::SeqCst);
    assert!(matches!(server.thread.take().unwrap().join(), Ok(Ok(()))));
    let port = url::Url::parse(&server.origin).unwrap().port().unwrap();
    let config = ControllerServerConfig {
        host: "127.0.0.1".to_owned(),
        port,
        external_url: Some(server.origin.clone()),
        tls_cert_path: None,
        tls_key_path: None,
        agent_client_ca_cert_path: None,
        data_dir: server._root.path().to_path_buf(),
        database: None,
        secret_provider: None,
    };
    server.shutdown = Arc::new(AtomicBool::new(false));
    let stop = server.shutdown.clone();
    server.thread = Some(std::thread::spawn(move || {
        start_controller_server_until(config, move || stop.load(Ordering::SeqCst))
    }));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !server
        .client
        .get(format!("{}/healthz", server.origin))
        .send()
        .is_ok_and(|response| response.status() == 200)
    {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .header("Cookie", &cookie)
            .send()
            .unwrap()
            .status(),
        401
    );
    let (fresh, _) = server.login();
    assert_eq!(
        server
            .client
            .get(format!("{}/api/agents", server.origin))
            .header("Cookie", fresh)
            .send()
            .unwrap()
            .status(),
        200
    );
    let saved = store
        .find_job_summary("delivered-before-logout")
        .unwrap()
        .unwrap();
    assert!(
        store
            .list_audit_events(100)
            .unwrap()
            .iter()
            .any(|event| event.action == "job_created"
                && event.target.as_str() == "delivered-before-logout"
                && event.actor.as_str() == person["user"]["id"].as_str().unwrap())
    );
    assert_ne!(saved.status, "canceled");
    assert!(
        store
            .find_job_summary("denied-after-logout")
            .unwrap()
            .is_none()
    );
}
