//! Explicit owned-loopback PostgreSQL acceptance; missing/mismatched fixtures fail before mutation.

use super::*;
use crate::{CURRENT_SCHEMA_VERSION, PostgresStore};
use ::postgres::{Client, Config, NoTls, config::Host};
use fleet_application::AdminTokenRepository;

struct PgFixture {
    store: PostgresStore,
    client: Client,
    url: String,
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_authorized_remediation_commits_every_effect_or_rolls_back() {
    use fleet_application::admin_remediation::AdminRemediationError;
    let mut fixture = fixture();
    let principal = assert_authorized_remediation_contract(&mut fixture.store);
    let before = fixture
        .client
        .query_one("SELECT count(*) FROM audit_events", &[])
        .unwrap()
        .get::<_, i64>(0);
    fixture.client.batch_execute("CREATE FUNCTION fixture_remed_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private remed diagnostic'; END $$;").unwrap();
    for trigger in [
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON audit_events FOR EACH ROW WHEN (NEW.action='remediation_approval_requested') EXECUTE FUNCTION fixture_remed_fault();",
        "CREATE TRIGGER fixture_remed_fault BEFORE UPDATE OF status ON remediation_requests FOR EACH ROW WHEN (NEW.id='remed-contract-fault') EXECUTE FUNCTION fixture_remed_fault();",
    ] {
        fixture.client.batch_execute(trigger).unwrap();
        assert!(matches!(
            request_remediation_contract(&mut fixture.store, &principal, "remed-contract-fault"),
            Err(AdminRemediationError::Access(AdminAccessError::Unavailable))
        ));
        assert_eq!(
            fixture
                .client
                .query_one(
                    "SELECT status FROM remediation_requests WHERE id='remed-contract-fault'",
                    &[]
                )
                .unwrap()
                .get::<_, String>(0),
            "proposed"
        );
        assert!(
            fixture
                .client
                .query_opt(
                    "SELECT 1 FROM approval_requests WHERE id='approval-remed-contract-fault'",
                    &[]
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(
            fixture
                .client
                .query_one("SELECT count(*) FROM audit_events", &[])
                .unwrap()
                .get::<_, i64>(0),
            before
        );
        fixture.client.batch_execute("DROP TRIGGER IF EXISTS fixture_remed_fault ON audit_events; DROP TRIGGER IF EXISTS fixture_remed_fault ON remediation_requests;").unwrap();
    }
    request_remediation_contract(&mut fixture.store, &principal, "remed-contract-fault").unwrap();
    let before = fixture
        .client
        .query_one("SELECT count(*) FROM audit_events", &[])
        .unwrap()
        .get::<_, i64>(0);
    for trigger in [
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON jobs FOR EACH ROW WHEN (NEW.id='job-remed-contract-after') EXECUTE FUNCTION fixture_remed_fault();",
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON task_assignments FOR EACH ROW WHEN (NEW.job_id='job-remed-contract-after') EXECUTE FUNCTION fixture_remed_fault();",
        "CREATE TRIGGER fixture_remed_fault BEFORE UPDATE OF status ON approval_requests FOR EACH ROW WHEN (NEW.id='approval-remed-contract-after') EXECUTE FUNCTION fixture_remed_fault();",
        "CREATE TRIGGER fixture_remed_fault BEFORE UPDATE OF status ON remediation_requests FOR EACH ROW WHEN (NEW.id='remed-contract-after') EXECUTE FUNCTION fixture_remed_fault();",
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON audit_events FOR EACH ROW WHEN (NEW.action='approval_approved') EXECUTE FUNCTION fixture_remed_fault();",
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON audit_events FOR EACH ROW WHEN (NEW.action='runbook_job_created') EXECUTE FUNCTION fixture_remed_fault();",
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON audit_events FOR EACH ROW WHEN (NEW.action='remediation_job_created') EXECUTE FUNCTION fixture_remed_fault();",
    ] {
        fixture.client.batch_execute(trigger).unwrap();
        assert!(matches!(
            approve_remediation_contract(&mut fixture.store, &principal, "remed-contract-after"),
            Err(AdminRemediationError::Access(AdminAccessError::Unavailable))
        ));
        assert_eq!(
            fixture
                .client
                .query_one(
                    "SELECT status FROM remediation_requests WHERE id='remed-contract-after'",
                    &[]
                )
                .unwrap()
                .get::<_, String>(0),
            "pending_approval"
        );
        assert_eq!(
            fixture
                .client
                .query_one(
                    "SELECT status FROM approval_requests WHERE id='approval-remed-contract-after'",
                    &[]
                )
                .unwrap()
                .get::<_, String>(0),
            "pending"
        );
        assert!(
            fixture
                .client
                .query_opt(
                    "SELECT 1 FROM jobs WHERE id='job-remed-contract-after'",
                    &[]
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(
            fixture
                .client
                .query_one(
                    "SELECT count(*) FROM task_assignments WHERE job_id='job-remed-contract-after'",
                    &[]
                )
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        assert_eq!(
            fixture
                .client
                .query_one("SELECT count(*) FROM audit_events", &[])
                .unwrap()
                .get::<_, i64>(0),
            before
        );
        fixture.client.batch_execute("DROP TRIGGER IF EXISTS fixture_remed_fault ON audit_events; DROP TRIGGER IF EXISTS fixture_remed_fault ON jobs; DROP TRIGGER IF EXISTS fixture_remed_fault ON task_assignments; DROP TRIGGER IF EXISTS fixture_remed_fault ON approval_requests; DROP TRIGGER IF EXISTS fixture_remed_fault ON remediation_requests;").unwrap();
    }
    fixture
        .client
        .batch_execute("DROP FUNCTION fixture_remed_fault();")
        .unwrap();
    approve_remediation_contract(&mut fixture.store, &principal, "remed-contract-after").unwrap();
    assert_eq!(
        fixture
            .client
            .query_one(
                "SELECT status FROM jobs WHERE id='job-remed-contract-after'",
                &[]
            )
            .unwrap()
            .get::<_, String>(0),
        "queued"
    );
    assert_eq!(
        fixture
            .client
            .query_one("SELECT count(*) FROM audit_events", &[])
            .unwrap()
            .get::<_, i64>(0),
        before + 3
    );
    assert!(matches!(
        approve_remediation_contract(&mut fixture.store, &principal, "remed-contract-after"),
        Err(AdminRemediationError::Invalid(_))
    ));
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_authorized_expiry_is_atomic_and_preserves_canceled_jobs() {
    let mut fixture = fixture();
    let principal = assert_authorized_expiry_contract(&mut fixture.store);
    let before = fixture
        .client
        .query_one("SELECT count(*) FROM audit_events", &[])
        .unwrap()
        .get::<_, i64>(0);
    fixture.client.batch_execute("CREATE FUNCTION fixture_expiry_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private expiry diagnostic'; END $$;").unwrap();
    for trigger in [
        "CREATE TRIGGER fixture_expiry_fault BEFORE INSERT ON audit_events FOR EACH ROW WHEN (NEW.action='approval_expired') EXECUTE FUNCTION fixture_expiry_fault();",
        "CREATE TRIGGER fixture_expiry_fault BEFORE UPDATE OF status ON jobs FOR EACH ROW WHEN (NEW.id='structured-before-drift' AND NEW.status='expired') EXECUTE FUNCTION fixture_expiry_fault();",
        "CREATE TRIGGER fixture_expiry_fault BEFORE UPDATE OF status ON approval_requests FOR EACH ROW WHEN (NEW.id='approval-structured-before-drift' AND NEW.status='expired') EXECUTE FUNCTION fixture_expiry_fault();",
    ] {
        fixture.client.batch_execute(trigger).unwrap();
        assert!(matches!(
            expire_contract_approvals(&mut fixture.store, &principal, 1_120),
            Err(
                fleet_application::admin_approval::AdminApprovalError::Access(
                    AdminAccessError::Unavailable
                )
            )
        ));
        assert_eq!(
            fixture
                .client
                .query_one(
                    "SELECT status FROM jobs WHERE id='structured-before-runbook'",
                    &[]
                )
                .unwrap()
                .get::<_, String>(0),
            "canceled"
        );
        assert!(fixture.client.query("SELECT status FROM jobs WHERE id LIKE 'structured-%' AND id<>'structured-before-runbook'",&[]).unwrap().iter().all(|row|row.get::<_,String>(0)=="pending_approval"));
        assert_eq!(fixture.client.query_one("SELECT count(*) FROM approval_requests WHERE id LIKE 'approval-structured-%' AND status='pending'",&[]).unwrap().get::<_,i64>(0),4);
        assert_eq!(
            fixture
                .client
                .query_one("SELECT count(*) FROM audit_events", &[])
                .unwrap()
                .get::<_, i64>(0),
            before
        );
        fixture.client.batch_execute("DROP TRIGGER IF EXISTS fixture_expiry_fault ON audit_events; DROP TRIGGER IF EXISTS fixture_expiry_fault ON jobs; DROP TRIGGER IF EXISTS fixture_expiry_fault ON approval_requests;").unwrap();
    }
    fixture
        .client
        .batch_execute("DROP FUNCTION fixture_expiry_fault();")
        .unwrap();
    assert_eq!(
        expire_contract_approvals(&mut fixture.store, &principal, 1_120)
            .unwrap()
            .expired
            .len(),
        4
    );
    assert_eq!(
        fixture
            .client
            .query_one(
                "SELECT status FROM jobs WHERE id='structured-before-runbook'",
                &[]
            )
            .unwrap()
            .get::<_, String>(0),
        "canceled"
    );
    assert!(fixture.client.query("SELECT status FROM jobs WHERE id LIKE 'structured-%' AND id<>'structured-before-runbook'",&[]).unwrap().iter().all(|row|row.get::<_,String>(0)=="expired"));
    let actors = fixture
        .client
        .query(
            "SELECT actor FROM audit_events WHERE action='approval_expired'",
            &[],
        )
        .unwrap();
    assert_eq!(actors.len(), 4);
    assert!(
        actors
            .iter()
            .all(|row| row.get::<_, String>(0) == principal.actor_id())
    );
    assert!(
        expire_contract_approvals(&mut fixture.store, &principal, 1_120)
            .unwrap()
            .expired
            .is_empty()
    );
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_authorized_cancellation_preserves_terminal_state_and_rolls_back_faults() {
    let mut fixture = fixture();
    let principal = assert_authorized_cancellation_contract(&mut fixture.store);
    let before = fixture
        .client
        .query_one("SELECT count(*) FROM audit_events", &[])
        .unwrap()
        .get::<_, i64>(0);
    fixture.client.batch_execute("CREATE FUNCTION fixture_cancel_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private cancel diagnostic'; END $$;").unwrap();
    for trigger in [
        "CREATE TRIGGER fixture_cancel_fault BEFORE INSERT ON audit_events FOR EACH ROW WHEN (NEW.action='job_canceled') EXECUTE FUNCTION fixture_cancel_fault();",
        "CREATE TRIGGER fixture_cancel_fault BEFORE UPDATE OF status ON jobs FOR EACH ROW WHEN (NEW.id='structured-after-runbook') EXECUTE FUNCTION fixture_cancel_fault();",
        "CREATE TRIGGER fixture_cancel_fault BEFORE UPDATE OF status ON task_assignments FOR EACH ROW WHEN (NEW.agent_id='structured-agent-b' AND NEW.status='canceled') EXECUTE FUNCTION fixture_cancel_fault();",
    ] {
        fixture.client.batch_execute(trigger).unwrap();
        assert!(matches!(
            cancel_contract_job(&mut fixture.store, &principal, "structured-after-runbook"),
            Err(AdminAccessError::Unavailable)
        ));
        assert_eq!(
            fixture
                .client
                .query_one(
                    "SELECT status FROM jobs WHERE id='structured-after-runbook'",
                    &[]
                )
                .unwrap()
                .get::<_, String>(0),
            "pending_approval"
        );
        assert!(fixture.client.query("SELECT status,last_error FROM task_assignments WHERE job_id='structured-after-runbook'",&[]).unwrap().iter().all(|row|row.get::<_,String>(0)=="queued" && row.get::<_,String>(1).is_empty()));
        assert_eq!(
            fixture
                .client
                .query_one("SELECT count(*) FROM audit_events", &[])
                .unwrap()
                .get::<_, i64>(0),
            before
        );
        fixture.client.batch_execute("DROP TRIGGER IF EXISTS fixture_cancel_fault ON audit_events; DROP TRIGGER IF EXISTS fixture_cancel_fault ON jobs; DROP TRIGGER IF EXISTS fixture_cancel_fault ON task_assignments;").unwrap();
    }
    fixture
        .client
        .batch_execute("DROP FUNCTION fixture_cancel_fault();")
        .unwrap();
    cancel_contract_job(&mut fixture.store, &principal, "structured-after-runbook").unwrap();
    let decision = fleet_application::admin_approval::DecideAdminApproval::execute(
        &mut fixture.store,
        &principal,
        &FixtureOperation,
        "approval-structured-after-runbook",
        fleet_application::admin_approval::AdminApprovalDecision::Approve,
        "after cancellation".to_owned(),
    );
    assert!(matches!(
        decision,
        Err(
            fleet_application::admin_approval::AdminApprovalError::Access(
                AdminAccessError::Conflict
            )
        )
    ));
    assert_eq!(
        fixture
            .client
            .query_one(
                "SELECT status FROM jobs WHERE id='structured-after-runbook'",
                &[]
            )
            .unwrap()
            .get::<_, String>(0),
        "canceled"
    );
    assert_eq!(
        fixture
            .client
            .query_one(
                "SELECT status FROM approval_requests WHERE id='approval-structured-after-runbook'",
                &[]
            )
            .unwrap()
            .get::<_, String>(0),
        "pending"
    );
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_authorized_catalog_jobs_recheck_human_authority_and_roll_back_every_effect() {
    let mut fixture = fixture();
    let principal = assert_authorized_catalog_contract(&mut fixture.store);
    let counts = |client: &mut Client| {
        client.query_one("SELECT (SELECT count(*) FROM jobs),(SELECT count(*) FROM job_catalog_runbook_provenance),(SELECT count(*) FROM task_assignments),(SELECT count(*) FROM job_targets),(SELECT count(*) FROM approval_requests),(SELECT count(*) FROM audit_events)",&[]).unwrap()
    };
    let before = counts(&mut fixture.client);
    fixture.client.batch_execute("CREATE FUNCTION fixture_catalog_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private catalog diagnostic'; END $$;").unwrap();
    for trigger in [
        "CREATE TRIGGER fixture_catalog_fault BEFORE INSERT ON audit_events FOR EACH ROW WHEN (NEW.action='catalog_runbook_job_created') EXECUTE FUNCTION fixture_catalog_fault();",
        "CREATE TRIGGER fixture_catalog_fault BEFORE INSERT ON job_catalog_runbook_provenance FOR EACH ROW EXECUTE FUNCTION fixture_catalog_fault();",
        "CREATE TRIGGER fixture_catalog_fault BEFORE INSERT ON task_assignments FOR EACH ROW WHEN (NEW.agent_id='agent-2') EXECUTE FUNCTION fixture_catalog_fault();",
    ] {
        fixture.client.batch_execute(trigger).unwrap();
        assert!(matches!(
            create_catalog_contract_job(&mut fixture.store, &principal, "catalog-fault"),
            Err(fleet_application::CreateCatalogRunbookJobError::Repository(
                fleet_application::AdminJobCommitError::Repository(_)
            ))
        ));
        let after = counts(&mut fixture.client);
        for index in 0..6 {
            assert_eq!(after.get::<_, i64>(index), before.get::<_, i64>(index));
        }
        fixture.client.batch_execute("DROP TRIGGER IF EXISTS fixture_catalog_fault ON audit_events; DROP TRIGGER IF EXISTS fixture_catalog_fault ON job_catalog_runbook_provenance; DROP TRIGGER IF EXISTS fixture_catalog_fault ON task_assignments;").unwrap();
    }
    fixture
        .client
        .batch_execute("DROP FUNCTION fixture_catalog_fault();")
        .unwrap();
    create_catalog_contract_job(&mut fixture.store, &principal, "catalog-fault").unwrap();
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_authorized_structured_jobs_preserve_provenance_and_roll_back_faults() {
    let mut fixture = fixture();
    let principal = assert_authorized_structured_contract(&mut fixture.store);
    let row = fixture.client.query_one("SELECT drift_policy_id,drift_policy_version,drift_purpose FROM jobs WHERE id='structured-before-drift'",&[]).unwrap();
    assert_eq!(
        (
            row.get::<_, String>(0),
            row.get::<_, i64>(1),
            row.get::<_, String>(2)
        ),
        ("structured-policy".to_owned(), 7, "evaluation".to_owned())
    );
    let counts = |client: &mut Client| {
        client.query_one("SELECT (SELECT count(*) FROM jobs),(SELECT count(*) FROM task_assignments),(SELECT count(*) FROM job_targets),(SELECT count(*) FROM approval_requests),(SELECT count(*) FROM audit_events)",&[]).unwrap()
    };
    let before = counts(&mut fixture.client);
    fixture.client.batch_execute("CREATE FUNCTION fixture_structured_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private structured diagnostic'; END $$;").unwrap();
    for trigger in [
        "CREATE TRIGGER fixture_structured_fault BEFORE INSERT ON audit_events FOR EACH ROW WHEN (NEW.action IN ('runbook_job_created','drift_check_job_created')) EXECUTE FUNCTION fixture_structured_fault();",
        "CREATE TRIGGER fixture_structured_fault BEFORE INSERT ON approval_requests FOR EACH ROW EXECUTE FUNCTION fixture_structured_fault();",
        "CREATE TRIGGER fixture_structured_fault BEFORE INSERT ON task_assignments FOR EACH ROW WHEN (NEW.agent_id='structured-agent-b') EXECUTE FUNCTION fixture_structured_fault();",
    ] {
        fixture.client.batch_execute(trigger).unwrap();
        for runbook in [true, false] {
            let failed = create_structured_contract_job(
                &mut fixture.store,
                &principal,
                if runbook {
                    "structured-fault-runbook"
                } else {
                    "structured-fault-drift"
                },
                runbook,
            );
            assert!(matches!(
                failed,
                Err(fleet_application::AdminStructuredJobError::Commit(
                    fleet_application::AdminJobCommitError::Repository(_)
                ))
            ));
            let after = counts(&mut fixture.client);
            for index in 0..5 {
                assert_eq!(after.get::<_, i64>(index), before.get::<_, i64>(index));
            }
        }
        fixture.client.batch_execute("DROP TRIGGER IF EXISTS fixture_structured_fault ON audit_events; DROP TRIGGER IF EXISTS fixture_structured_fault ON approval_requests; DROP TRIGGER IF EXISTS fixture_structured_fault ON task_assignments;").unwrap();
    }
    fixture
        .client
        .batch_execute("DROP FUNCTION fixture_structured_fault();")
        .unwrap();
    create_structured_contract_job(
        &mut fixture.store,
        &principal,
        "structured-fault-runbook",
        true,
    )
    .unwrap();
    create_structured_contract_job(
        &mut fixture.store,
        &principal,
        "structured-fault-drift",
        false,
    )
    .unwrap();
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_authorized_command_creation_rechecks_identity_and_commits_the_whole_bundle() {
    let mut fixture = fixture();
    // This case exercises actual first-token issuance. The frozen migration fixture's
    // marker hash is deliberately not a real SHA-256 credential, and insertion never rotates it.
    fixture
        .client
        .execute("DELETE FROM admin_tokens", &[])
        .unwrap();
    let principal = assert_authorized_command_contract(&mut fixture.store);
    let actors=fixture.client.query("SELECT actor FROM audit_events WHERE target='guard-contract-before' AND action IN ('job_created','approval_requested') ORDER BY id",&[]).unwrap()
        .iter().map(|row|row.get::<_,String>(0)).collect::<Vec<_>>();
    assert_eq!(
        actors,
        vec!["usr_00000000000000000000000000000001".to_owned(); 2]
    );
    use fleet_application::admin_approval::{
        AdminApprovalDecision, AdminApprovalError, DecideAdminApproval,
    };
    let before: i64 = fixture
        .client
        .query_one("SELECT count(*) FROM audit_events", &[])
        .unwrap()
        .get(0);
    fixture.client.batch_execute("CREATE FUNCTION fixture_approval_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private approval diagnostic'; END $$;").unwrap();
    for trigger in [
        "CREATE TRIGGER fixture_approval_fault BEFORE INSERT ON audit_events FOR EACH ROW WHEN (NEW.action='approval_rejected') EXECUTE FUNCTION fixture_approval_fault();",
        "CREATE TRIGGER fixture_approval_fault BEFORE UPDATE OF status ON jobs FOR EACH ROW WHEN (NEW.id='guard-contract-after') EXECUTE FUNCTION fixture_approval_fault();",
    ] {
        fixture.client.batch_execute(trigger).unwrap();
        let failed = DecideAdminApproval::execute(
            &mut fixture.store,
            &principal,
            &FixtureOperation,
            "approval-guard-contract-after",
            AdminApprovalDecision::Reject,
            "owned PG fixture".to_owned(),
        );
        assert!(matches!(
            failed,
            Err(AdminApprovalError::Access(AdminAccessError::Unavailable))
        ));
        let row = fixture.client.query_one("SELECT status,approver FROM approval_requests WHERE id='approval-guard-contract-after'", &[]).unwrap();
        assert_eq!(row.get::<_, String>(0), "pending");
        assert!(row.get::<_, Option<String>>(1).is_none());
        assert_eq!(
            fixture
                .client
                .query_one(
                    "SELECT status FROM jobs WHERE id='guard-contract-after'",
                    &[]
                )
                .unwrap()
                .get::<_, String>(0),
            "pending_approval"
        );
        assert_eq!(
            fixture
                .client
                .query_one("SELECT count(*) FROM audit_events", &[])
                .unwrap()
                .get::<_, i64>(0),
            before
        );
        fixture.client.batch_execute("DROP TRIGGER IF EXISTS fixture_approval_fault ON audit_events; DROP TRIGGER IF EXISTS fixture_approval_fault ON jobs;").unwrap();
    }
    fixture
        .client
        .batch_execute("DROP FUNCTION fixture_approval_fault();")
        .unwrap();
    DecideAdminApproval::execute(
        &mut fixture.store,
        &principal,
        &FixtureOperation,
        "approval-guard-contract-after",
        AdminApprovalDecision::Reject,
        "owned PG fixture".to_owned(),
    )
    .unwrap();
    assert_eq!(
        fixture
            .client
            .query_one(
                "SELECT status FROM jobs WHERE id='guard-contract-after'",
                &[]
            )
            .unwrap()
            .get::<_, String>(0),
        "failed"
    );
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_owner_account_metadata_is_bounded_and_rejects_corrupt_lookahead() {
    let mut fixture = fixture();
    let (actor, other) = assert_owner_account_metadata_contract(&mut fixture.store);
    fixture
        .client
        .execute(
            "UPDATE admin_accounts SET display_name=chr(1) WHERE user_id=$1",
            &[&other.as_str()],
        )
        .unwrap();
    assert!(matches!(
        ListAdminAccountMetadata::execute(
            &fixture.store,
            &actor,
            &FixtureOperation,
            ListAdminAccountMetadataInput {
                after: None,
                limit: AdminMetadataPageSize::new(1).unwrap()
            }
        ),
        Err(AdminAccessError::Unavailable)
    ));
    assert_eq!(
        GetAdminAccountMetadata::execute(&fixture.store, &actor, &FixtureOperation, &other),
        Err(AdminAccessError::Unavailable)
    );
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_login_session_admission_serializes_counts() {
    let mut fixture = fixture();
    assert_login_admission_contract(&mut fixture.store);
    assert_eq!(
        fixture
            .client
            .query_one(
                "SELECT count(*) FROM audit_events WHERE action='admin_session_created'",
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        8
    );
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_concurrent_sixteenth_personal_tokens_admit_exactly_one() {
    let mut fixture = fixture();
    let (owner, actor) = prepare_fifteen_personal_tokens(&mut fixture.store);
    let peers = [
        PostgresStore::connect(&fixture.url).unwrap(),
        PostgresStore::connect(&fixture.url).unwrap(),
    ];
    let gate = Rendezvous::new();
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = peers
            .into_iter()
            .enumerate()
            .map(|(slot, mut peer)| {
                let gate = gate.clone();
                let actor = actor.clone();
                scope.spawn(move || racing_personal_token(&mut peer, &actor, gate, slot as u128))
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(AdminAccessError::Limit)))
            .count(),
        1
    );
    assert_eq!(
        fixture
            .store
            .identity_transaction(|tx| tx.credential_counts(
                AdminCredentialKind::PersonalToken,
                &owner,
                1_000
            ))
            .unwrap(),
        AdminCredentialCounts {
            valid_for_user: 16,
            total_rows: 16
        }
    );
    assert_eq!(
        fixture
            .client
            .query_one(
                "SELECT count(*) FROM audit_events WHERE action='admin_personal_token_created'",
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        16
    );
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_self_auth_audit_failure_rolls_back_revoke_logout_and_retired_cleanup() {
    let mut fixture = fixture();
    let (actor, id) = prepare_self_auth_fault(&mut fixture.store);
    fixture.client.batch_execute("CREATE FUNCTION fail_self_auth_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('admin_session_logged_out','admin_personal_token_revoked') THEN RAISE EXCEPTION 'owned self-auth audit fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_self_auth_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_self_auth_audit();").unwrap();
    let before = pg_snapshot(
        &mut fixture.client,
        &[
            "admin_auth_state",
            "admin_accounts",
            "admin_credentials",
            "audit_events",
        ],
    );
    for logout in [true, false] {
        let result = if logout {
            LogoutAdminSession::execute(&mut fixture.store, &actor, &FixtureOperation)
        } else {
            RevokeOwnAdminPersonalToken::execute(&mut fixture.store, &actor, &FixtureOperation, &id)
        };
        assert_eq!(result, Err(AdminAccessError::Unavailable));
        assert!(
            pg_snapshot(
                &mut fixture.client,
                &[
                    "admin_auth_state",
                    "admin_accounts",
                    "admin_credentials",
                    "audit_events"
                ]
            ) == before
        );
        authenticate(&fixture.store, 0xb1, AdminCredentialKind::WebSession).unwrap();
        authenticate(&fixture.store, 0xb2, AdminCredentialKind::PersonalToken).unwrap();
    }
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_personal_token_labels_and_scoped_metadata_roundtrip_and_malformed_labels_fail_closed() {
    let mut fixture = fixture();
    let id = assert_personal_token_metadata_contract(&mut fixture.store);
    let valid = fixture
        .store
        .credential_by_id(&id)
        .unwrap()
        .unwrap()
        .snapshot();
    let actor = AuthenticateAdminCredential::execute(
        &fixture.store,
        &FixtureOperation,
        AdminCredentialKind::PersonalToken,
        &valid.digest,
    )
    .unwrap();
    let foreign = AdminCredentialId::parse(format!("crd_{:032x}", 0x91)).unwrap();
    assert_eq!(
        fixture
            .client
            .execute(
                "UPDATE admin_credentials SET label=$1 WHERE credential_id=$2",
                &[&"synthetic-label\n", &foreign.as_str()]
            )
            .unwrap(),
        1
    );
    assert_eq!(
        fixture.store.credential_by_id(&foreign).unwrap_err(),
        AdminAccessError::Unavailable
    );
    assert_eq!(
        RevokeOwnAdminPersonalToken::execute(
            &mut fixture.store,
            &actor,
            &FixtureOperation,
            &foreign
        ),
        Err(AdminAccessError::NotFound)
    );
    assert_eq!(
        fixture
            .client
            .query_one(
                "SELECT count(*) FROM audit_events WHERE action='admin_personal_token_created'",
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        4
    );
    fixture
        .client
        .execute(
            "UPDATE admin_credentials SET label=$1 WHERE credential_id=$2",
            &[&"synthetic-label\n", &id.as_str()],
        )
        .unwrap();
    assert_eq!(
        fixture.store.credential_by_id(&id).unwrap_err(),
        AdminAccessError::Unavailable
    );
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_concurrent_eighth_sessions_admit_exactly_one_at_the_canonical_transaction() {
    let mut fixture = fixture();
    let owner = prepare_seven_sessions(&mut fixture.store);
    let peers = [
        PostgresStore::connect(&fixture.url).unwrap(),
        PostgresStore::connect(&fixture.url).unwrap(),
    ];
    let gate = Rendezvous::new();
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = peers
            .into_iter()
            .enumerate()
            .map(|(slot, mut peer)| {
                let gate = gate.clone();
                scope.spawn(move || racing_session(&mut peer, gate, slot as u128))
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(AdminAccessError::Limit)))
            .count(),
        1
    );
    assert_eq!(
        fixture
            .store
            .identity_transaction(|tx| tx.credential_counts(
                AdminCredentialKind::WebSession,
                &owner,
                1_000
            ))
            .unwrap(),
        AdminCredentialCounts {
            valid_for_user: 8,
            total_rows: 8
        }
    );
    assert_eq!(
        fixture
            .client
            .query_one(
                "SELECT count(*) FROM audit_events WHERE action='admin_session_created'",
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        8
    );
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_lookup_cleanup_is_per_kind_bounded_and_preserves_accounts_and_audit() {
    let mut fixture = fixture();
    assert_bounded_lookup_cleanup_contract(&mut fixture.store);
    assert_eq!(
        fixture
            .client
            .query_one("SELECT count(*) FROM audit_events", &[])
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        fixture
            .client
            .query_one("SELECT count(*) FROM admin_accounts", &[])
            .unwrap()
            .get::<_, i64>(0),
        2
    );
}

fn fixture() -> PgFixture {
    let url = std::env::var("FLEET_TEST_POSTGRES_URL")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| panic!("explicit owned FLEET_TEST_POSTGRES_URL required"));
    let config: Config = url
        .parse()
        .unwrap_or_else(|_| panic!("invalid owned PostgreSQL fixture configuration"));
    assert_eq!(config.get_dbname(), Some("fleet_iam_contract"));
    assert_eq!(config.get_ports(), &[35432]);
    assert_eq!(config.get_hosts().len(), 1);
    assert!(matches!(&config.get_hosts()[0],Host::Tcp(host) if host=="127.0.0.1"));
    assert_eq!(
        config.get_options(),
        Some("-c search_path=fleet_iam_contract_test")
    );
    let mut client = config
        .connect(NoTls)
        .unwrap_or_else(|_| panic!("owned PostgreSQL fixture unavailable"));
    let owner = client
        .query_one(
            "SELECT owner_uid,purpose FROM public.fleet_iam_fixture_owner WHERE id=1",
            &[],
        )
        .unwrap_or_else(|_| panic!("owned PostgreSQL marker required before fixture reset"));
    assert_eq!(
        owner.get::<_, i64>(0),
        i64::from(rustix::process::geteuid().as_raw())
    );
    assert_eq!(owner.get::<_, String>(1), "codex-owned-iam-acceptance");
    client.batch_execute("DROP SCHEMA IF EXISTS fleet_iam_contract_test CASCADE; CREATE SCHEMA fleet_iam_contract_test;")
        .unwrap_or_else(|_|panic!("owned PostgreSQL schema reset failed"));
    let mut store = PostgresStore::connect(&url)
        .unwrap_or_else(|_| panic!("owned PostgreSQL store connection failed"));
    store.migrate().unwrap();
    PgFixture { store, client, url }
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_identity_application_contract_and_legacy_cutover() {
    let PgFixture {
        mut store,
        mut client,
        ..
    } = fixture();
    let hash = "a".repeat(64);
    AdminTokenRepository::insert_admin_token_hash(&mut store, &hash).unwrap();
    assert!(AdminTokenRepository::verify_admin_token_hash(&store, &hash).unwrap());
    let (_, user) = assert_application_contract(&mut store, &FixtureGenerator::new());
    assert!(!AdminTokenRepository::verify_admin_token_hash(&store, &hash).unwrap());
    assert!(
        AdminTokenRepository::find_admin_token_record(&store, &hash)
            .unwrap()
            .is_none()
    );
    assert!(AdminTokenRepository::admin_token_exists(&store).unwrap());
    assert!(
        AdminTokenRepository::insert_admin_token_hash(&mut store, "synthetic-unused-hash").is_err()
    );
    let epoch = store.auth_state().unwrap().epoch;
    store.migrate().unwrap();
    assert_eq!(
        store.schema_version().unwrap(),
        Some(CURRENT_SCHEMA_VERSION)
    );
    assert_eq!(store.auth_state().unwrap().epoch, epoch);
    let audit = client
        .query_one(
            "SELECT actor,value_kind FROM audit_events WHERE action='admin_password_changed'",
            &[],
        )
        .unwrap();
    assert_eq!(audit.get::<_, String>(0), user.as_str());
    assert_eq!(audit.get::<_, String>(1), "redacted");
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_human_restore_preserves_accounts_credentials_agent_and_delivery_history() {
    let PgFixture {
        mut store,
        mut client,
        ..
    } = fixture();
    AdminTokenRepository::insert_admin_token_hash(&mut store, &"a".repeat(64)).unwrap();
    client.batch_execute("INSERT INTO agents(id,name,public_key,fingerprint,labels,status,created_at,updated_at)
        VALUES('legacy-agent','legacy-agent','synthetic-public','synthetic-fingerprint','role=web','active',1000,1000);
        INSERT INTO agent_identities(agent_id,public_key,fingerprint,created_at)
        VALUES('legacy-agent','synthetic-public','synthetic-fingerprint',1000);
        INSERT INTO jobs(id,status,risk,approval_requirement,timeout_ms,command_program,command_args_json,created_at)
        VALUES('legacy-job','queued','high','admin_confirmation',30000,'uptime','[]',1000);
        INSERT INTO approval_requests(id,job_id,requester,approver,reason,status,expires_at,created_at,decided_at)
        VALUES('legacy-approval','legacy-job','bootstrap-admin','legacy-approver','synthetic history','approved',2000,1000,1000);
        INSERT INTO audit_events(category,action,actor,target,value_kind,value_text,occurred_at)
        VALUES('security','legacy_fixture_event','bootstrap-admin','legacy-job','redacted','',1000);").unwrap();
    let tables = [
        "admin_tokens",
        "agents",
        "agent_identities",
        "jobs",
        "approval_requests",
        "audit_events",
        "controller_delivery_identity",
    ];
    let before = pg_snapshot(&mut client, &tables);
    assert_restore_contract(&mut store);
    let after = pg_snapshot(&mut client, &tables);
    for (table, rows) in before {
        if table == "audit_events" {
            assert!(
                rows.iter().all(|row| after[&table].contains(row)),
                "prior audit rows must survive human restore"
            );
        } else {
            assert!(
                after[&table] == rows,
                "nonhuman/legacy rows must remain unchanged"
            );
        }
    }
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_human_restore_legacy_rejection_and_audit_fault_rollback() {
    let PgFixture {
        mut store,
        mut client,
        ..
    } = fixture();
    let hash = "b".repeat(64);
    AdminTokenRepository::insert_admin_token_hash(&mut store, &hash).unwrap();
    assert!(AdminTokenRepository::verify_admin_token_hash(&store, &hash).unwrap());
    let before_delivery = pg_snapshot(&mut client, &["controller_delivery_identity"]);
    let epoch = next_restore_epoch(&store);
    assert_eq!(
        InvalidateAdminCredentialsAfterRestore::execute(
            &mut store,
            &FixtureLocalAuthority,
            &FixtureOperation,
            &epoch
        )
        .unwrap(),
        AdminAuthMode::LocalSetupRequired
    );
    assert!(!AdminTokenRepository::verify_admin_token_hash(&store, &hash).unwrap());
    assert!(AdminTokenRepository::admin_token_exists(&store).unwrap());
    assert!(pg_snapshot(&mut client, &["controller_delivery_identity"]) == before_delivery);
    seed_restore_credentials(&mut store);
    let tables = [
        "admin_auth_state",
        "admin_accounts",
        "admin_credentials",
        "audit_events",
        "controller_delivery_identity",
        "admin_tokens",
    ];
    let before = pg_snapshot(&mut client, &tables);
    client.batch_execute("CREATE FUNCTION reject_restore_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NEW.action='admin_credentials_invalidated_after_restore' THEN RAISE EXCEPTION 'synthetic human restore audit fault'; END IF;
        RETURN NEW; END $$;
        CREATE TRIGGER reject_restore_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_restore_audit();").unwrap();
    let epoch = next_restore_epoch(&store);
    assert_eq!(
        InvalidateAdminCredentialsAfterRestore::execute(
            &mut store,
            &FixtureLocalAuthority,
            &FixtureOperation,
            &epoch
        )
        .unwrap_err(),
        AdminAccessError::Unavailable
    );
    assert!(
        pg_snapshot(&mut client, &tables) == before,
        "restore epoch and audit must roll back together"
    );
    authenticate(&store, 0xa1, AdminCredentialKind::WebSession).unwrap();
    authenticate(&store, 0xa2, AdminCredentialKind::PersonalToken).unwrap();
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_identity_audit_failure_rolls_back_reset_account_and_credentials() {
    let PgFixture {
        mut store,
        mut client,
        ..
    } = fixture();
    let generator = FixtureGenerator::new();
    let (_, user) = assert_application_contract(&mut store, &generator);
    let actor = authenticate(&store, 0xa1, AdminCredentialKind::WebSession).unwrap();
    let before = store.account_by_id(&user).unwrap().unwrap().snapshot();
    let credentials: i64 = client
        .query_one("SELECT COUNT(*) FROM admin_credentials", &[])
        .unwrap()
        .get(0);
    let audits: i64 = client
        .query_one("SELECT COUNT(*) FROM audit_events", &[])
        .unwrap()
        .get(0);
    let before_rows = pg_snapshot(
        &mut client,
        &[
            "admin_auth_state",
            "admin_accounts",
            "admin_credentials",
            "audit_events",
        ],
    );
    client.batch_execute("CREATE FUNCTION reject_reset_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NEW.action='admin_password_reset_requested' THEN RAISE EXCEPTION 'synthetic reset audit fault'; END IF;
        RETURN NEW; END $$;
        CREATE TRIGGER reject_reset_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_reset_audit();").unwrap();
    assert_eq!(
        ResetAdminPassword::execute(
            &mut store,
            &actor,
            &FixtureOperation,
            &FixturePasswords,
            &generator,
            ResetAdminPasswordInput {
                user_id: user.clone(),
                current_password: CURRENT_PASSWORD
            }
        )
        .unwrap_err(),
        AdminAccessError::Unavailable
    );
    assert_eq!(
        store.account_by_id(&user).unwrap().unwrap().snapshot(),
        before
    );
    assert_eq!(
        client
            .query_one("SELECT COUNT(*) FROM admin_credentials", &[])
            .unwrap()
            .get::<_, i64>(0),
        credentials
    );
    assert_eq!(
        client
            .query_one("SELECT COUNT(*) FROM audit_events", &[])
            .unwrap()
            .get::<_, i64>(0),
        audits
    );
    assert_eq!(
        pg_snapshot(
            &mut client,
            &[
                "admin_auth_state",
                "admin_accounts",
                "admin_credentials",
                "audit_events"
            ]
        ),
        before_rows
    );
}

fn pg_snapshot(
    client: &mut Client,
    tables: &[&str],
) -> std::collections::BTreeMap<String, Vec<String>> {
    tables
        .iter()
        .map(|table| {
            let sql = format!("SELECT row_to_json(t)::text AS body FROM {table} t ORDER BY body");
            let rows = client
                .query(sql.as_str(), &[])
                .unwrap()
                .into_iter()
                .map(|row| row.get::<_, String>(0))
                .collect();
            ((*table).to_owned(), rows)
        })
        .collect()
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_identity_schema27_upgrade_and_version_failure_preserve_legacy_rows() {
    let PgFixture {
        mut store,
        mut client,
        ..
    } = fixture();
    AdminTokenRepository::insert_admin_token_hash(&mut store, &"a".repeat(64)).unwrap();
    client.batch_execute("INSERT INTO agents(id,name,public_key,fingerprint,labels,status,created_at,updated_at)
        VALUES('legacy-agent','legacy-agent','synthetic-public','synthetic-fingerprint','role=web','active',1000,1000);
        INSERT INTO agent_identities(agent_id,public_key,fingerprint,created_at)
        VALUES('legacy-agent','synthetic-public','synthetic-fingerprint',1000);
        INSERT INTO jobs(id,status,risk,approval_requirement,timeout_ms,command_program,command_args_json,created_at)
        VALUES('legacy-job','queued','high','admin_confirmation',30000,'uptime','[]',1000);
        INSERT INTO approval_requests(id,job_id,requester,approver,reason,status,expires_at,created_at,decided_at)
        VALUES('legacy-approval','legacy-job','bootstrap-admin','legacy-approver','synthetic history','approved',2000,1000,1000);
        INSERT INTO audit_events(category,action,actor,target,value_kind,value_text,occurred_at)
        VALUES('security','legacy_fixture_event','bootstrap-admin','legacy-job','redacted','',1000);
        DROP TABLE admin_credentials; DROP TABLE admin_accounts; DROP TABLE admin_auth_state;
        UPDATE schema_migrations SET version=27,applied_at=1000 WHERE name='fleet_store';
        CREATE FUNCTION reject_identity_version() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
            IF NEW.version=28 THEN RAISE EXCEPTION 'synthetic identity version fault'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_identity_version BEFORE UPDATE ON schema_migrations FOR EACH ROW EXECUTE FUNCTION reject_identity_version();").unwrap();
    let tables = [
        "admin_tokens",
        "agents",
        "agent_identities",
        "jobs",
        "approval_requests",
        "audit_events",
        "controller_delivery_identity",
    ];
    let before = pg_snapshot(&mut client, &tables);
    assert!(store.migrate().is_err());
    assert_eq!(store.schema_version().unwrap(), Some(27));
    assert_eq!(pg_snapshot(&mut client, &tables), before);
    assert!(client.query_one("SELECT to_regclass('admin_auth_state') IS NULL AND to_regclass('admin_accounts') IS NULL AND to_regclass('admin_credentials') IS NULL",&[]).unwrap().get::<_,bool>(0));
    client.batch_execute("DROP TRIGGER reject_identity_version ON schema_migrations; DROP FUNCTION reject_identity_version();").unwrap();
    store.migrate().unwrap();
    assert_eq!(store.schema_version().unwrap(), Some(28));
    assert_eq!(
        store.auth_state().unwrap().mode,
        AdminAuthMode::LegacyBootstrap
    );
    assert_eq!(pg_snapshot(&mut client, &tables), before);
    let epoch = store.auth_state().unwrap().epoch;
    store.migrate().unwrap();
    assert_eq!(store.auth_state().unwrap().epoch, epoch);
    client
        .batch_execute("UPDATE schema_migrations SET version=29 WHERE name='fleet_store'")
        .unwrap();
    assert!(store.migrate().is_err());
    assert_eq!(store.schema_version().unwrap(), Some(29));
    assert_eq!(store.auth_state().unwrap().epoch, epoch);
    assert_eq!(pg_snapshot(&mut client, &tables), before);
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_identity_missing_schema28_object_never_recreates_legacy_access() {
    let PgFixture {
        mut store,
        mut client,
        ..
    } = fixture();
    let hash = "a".repeat(64);
    AdminTokenRepository::insert_admin_token_hash(&mut store, &hash).unwrap();
    initialize_owner(&mut store, &FixtureGenerator::new());
    let before = store.auth_state().unwrap();
    client
        .batch_execute("DROP TABLE admin_credentials")
        .unwrap();
    assert!(store.migrate().is_err());
    assert_eq!(store.auth_state().unwrap(), before);
    assert!(!AdminTokenRepository::verify_admin_token_hash(&store, &hash).unwrap());
    assert!(
        client
            .query_one("SELECT to_regclass('admin_credentials') IS NULL", &[])
            .unwrap()
            .get::<_, bool>(0)
    );
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_identity_concurrent_owners_cannot_both_demote_themselves() {
    let PgFixture { mut store, url, .. } = fixture();
    let first = initialize_owner(&mut store, &FixtureGenerator::new()).id;
    let second = second_owner(&mut store);
    let actors = [
        seed_credential(&mut store, &first, 0xb1, AdminCredentialKind::WebSession),
        seed_credential(&mut store, &second, 0xb2, AdminCredentialKind::WebSession),
    ];
    let gate = Rendezvous::new();
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = actors
            .into_iter()
            .map(|actor| {
                let url = url.clone();
                let gate = gate.clone();
                scope.spawn(move || {
                    let mut repository = PostgresStore::connect(&url)
                        .unwrap_or_else(|_| panic!("owned PostgreSQL race connection failed"));
                    let user_id = actor.user_id().clone();
                    ChangeAdminAccount::execute(
                        &mut repository,
                        &actor,
                        &FixtureOperation,
                        &RacingPasswords {
                            gate,
                            at: RendezvousAt::Verify,
                        },
                        ChangeAdminAccountInput {
                            user_id,
                            display_name: None,
                            role: Some(AdminRole::Admin),
                            disable: false,
                            current_password: CURRENT_PASSWORD,
                        },
                    )
                    .map(|_| ())
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(AdminAccessError::LastOwner))
            .count(),
        1
    );
    assert_eq!(store.loginable_owner_count().unwrap(), 1);
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_identity_concurrent_setup_claim_commits_once() {
    let PgFixture {
        mut store,
        url,
        mut client,
    } = fixture();
    let generator = FixtureGenerator::new();
    let owner = initialize_owner(&mut store, &generator).id;
    let actor = seed_credential(&mut store, &owner, 0xb1, AdminCredentialKind::WebSession);
    let created = CreateAdminAccount::execute(
        &mut store,
        &actor,
        &FixtureOperation,
        &FixturePasswords,
        &generator,
        CreateAdminAccountInput {
            username: AdminUsername::parse("claim_target").unwrap(),
            display_name: AdminDisplayName::parse("Claim target").unwrap(),
            role: AdminRole::Viewer,
            current_password: CURRENT_PASSWORD,
        },
    )
    .unwrap();
    let grant = store
        .credential_by_id(&created.setup.id)
        .unwrap()
        .unwrap()
        .snapshot();
    let gate = Rendezvous::new();
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let url = url.clone();
                let gate = gate.clone();
                let grant = grant.clone();
                scope.spawn(move || {
                    let mut repository = PostgresStore::connect(&url)
                        .unwrap_or_else(|_| panic!("owned PostgreSQL race connection failed"));
                    CompleteAdminSetup::execute(
                        &mut repository,
                        &FixtureOperation,
                        &RacingPasswords {
                            gate,
                            at: RendezvousAt::Hash,
                        },
                        CompleteAdminSetupInput {
                            kind: grant.kind,
                            digest: grant.digest,
                            new_password: CURRENT_PASSWORD,
                        },
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(AdminAccessError::Unauthorized))
            .count(),
        1
    );
    assert_eq!(
        store
            .account_by_id(&created.account.id)
            .unwrap()
            .unwrap()
            .snapshot()
            .credential_revision
            .value(),
        1
    );
    assert_eq!(
        client
            .query_one(
                "SELECT COUNT(*) FROM audit_events WHERE action='admin_password_setup_completed'",
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        1
    );
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_identity_concurrent_first_owners_have_one_atomic_cutover() {
    let PgFixture {
        mut store,
        url,
        mut client,
    } = fixture();
    let hash = "b".repeat(64);
    AdminTokenRepository::insert_admin_token_hash(&mut store, &hash).unwrap();
    let epoch = store.auth_state().unwrap().epoch;
    let gate = Rendezvous::new();
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2u128)
            .map(|index| {
                let url = url.clone();
                let gate = gate.clone();
                scope.spawn(move || {
                    let mut repository = PostgresStore::connect(&url)
                        .unwrap_or_else(|_| panic!("owned PostgreSQL race connection failed"));
                    InitializeAdminOwner::execute(
                        &mut repository,
                        &FixtureLocalAuthority,
                        &FixtureOperation,
                        &RacingPasswords {
                            gate,
                            at: RendezvousAt::Hash,
                        },
                        &FixtureGenerator {
                            users: Cell::new(index),
                            credentials: Cell::new(0),
                        },
                        InitializeOwnerInput {
                            username: AdminUsername::parse(format!("racing_owner_{index}"))
                                .unwrap(),
                            display_name: AdminDisplayName::parse(format!("Racing owner {index}"))
                                .unwrap(),
                            new_password: CURRENT_PASSWORD,
                        },
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(AdminAccessError::Conflict)))
            .count(),
        1
    );
    assert_eq!(store.auth_state().unwrap().epoch, epoch);
    assert_eq!(store.auth_state().unwrap().mode, AdminAuthMode::Personal);
    assert_eq!(store.loginable_owner_count().unwrap(), 1);
    assert!(!AdminTokenRepository::verify_admin_token_hash(&store, &hash).unwrap());
    assert_eq!(
        client
            .query_one("SELECT COUNT(*) FROM admin_accounts", &[])
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        client
            .query_one(
                "SELECT COUNT(*) FROM audit_events WHERE action='admin_owner_initialized'",
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        1
    );
}

#[test]
#[ignore = "requires explicitly marked disposable localhost PostgreSQL IAM fixture"]
fn postgres_identity_role_revocation_before_commit_blocks_a_stale_password_result() {
    let PgFixture {
        mut store,
        url,
        mut client,
    } = fixture();
    let first = initialize_owner(&mut store, &FixtureGenerator::new()).id;
    let second = second_owner(&mut store);
    let first_actor = seed_credential(&mut store, &first, 0xb1, AdminCredentialKind::WebSession);
    let second_actor = seed_credential(&mut store, &second, 0xb2, AdminCredentialKind::WebSession);
    let (entered, started) = std::sync::mpsc::sync_channel(1);
    let (release, resume) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let handle = scope.spawn(move || {
            let mut repository = PostgresStore::connect(&url)
                .unwrap_or_else(|_| panic!("owned PostgreSQL race connection failed"));
            CreateAdminAccount::execute(
                &mut repository,
                &second_actor,
                &FixtureOperation,
                &HeldPassword {
                    entered,
                    release: resume,
                },
                &FixtureGenerator {
                    users: Cell::new(2),
                    credentials: Cell::new(0),
                },
                CreateAdminAccountInput {
                    username: AdminUsername::parse("raced_new_user").unwrap(),
                    display_name: AdminDisplayName::parse("Raced new user").unwrap(),
                    role: AdminRole::Owner,
                    current_password: CURRENT_PASSWORD,
                },
            )
            .map(|_| ())
        });
        started
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        ChangeAdminAccount::execute(
            &mut store,
            &first_actor,
            &FixtureOperation,
            &FixturePasswords,
            ChangeAdminAccountInput {
                user_id: second,
                display_name: None,
                role: Some(AdminRole::Viewer),
                disable: false,
                current_password: CURRENT_PASSWORD,
            },
        )
        .unwrap();
        release.send(()).unwrap();
        assert_eq!(handle.join().unwrap(), Err(AdminAccessError::Unauthorized));
    });
    assert!(
        store
            .account_by_username(&AdminUsername::parse("raced_new_user").unwrap())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        client
            .query_one("SELECT COUNT(*) FROM admin_credentials", &[])
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    authenticate(&store, 0xb1, AdminCredentialKind::WebSession).unwrap();
    assert_eq!(
        authenticate(&store, 0xb2, AdminCredentialKind::WebSession).unwrap_err(),
        AdminAccessError::Unauthorized
    );
    assert_eq!(
        client
            .query_one(
                "SELECT COUNT(*) FROM audit_events WHERE action='admin_account_created'",
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        0
    );
}
