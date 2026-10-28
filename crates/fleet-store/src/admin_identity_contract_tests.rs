//! Shared Application contracts and real SQLite concurrency; crypto/clock/local authority are controlled fixtures.

use super::{fixture_store, legacy_snapshot, table_snapshot};
use crate::SqliteStore;
use fleet_application::admin_identity::*;
use fleet_domain::*;
use std::cell::Cell;

const CURRENT_PASSWORD: &str = "fixture current password";

fn assert_authorized_command_contract<R>(store: &mut R) -> AdminMutationPrincipal
where
    R: AdminIdentityRepository
        + fleet_application::admin_approval::AdminApprovalRepository
        + fleet_application::AdminCommandJobRepository<Error = crate::StoreError>
        + fleet_application::AgentRepository<Error = crate::StoreError>
        + fleet_application::JobQueryRepository<Error = crate::StoreError>
        + fleet_application::AdminTokenRepository<Error = crate::StoreError>,
{
    use fleet_application::{
        AdminCommandCommitError, CommandCreationMetadata, CreateAuthorizedCommandJob,
        CreateAuthorizedCommandJobError, CreateCommandJobInput, TaskEnvelopeSigner,
    };
    struct Signer;
    impl TaskEnvelopeSigner for Signer {
        type Error = &'static str;
        fn sign(&mut self, _: &str) -> Result<String, Self::Error> {
            Ok("fixture-signature".to_owned())
        }
    }
    fleet_application::AgentRepository::save(
        store,
        Agent::new(
            AgentId::new("guard-contract-agent").unwrap(),
            AgentName::new("guard-contract-agent").unwrap(),
            AgentIdentity {
                public_key: AgentPublicKey::new("fixture-public").unwrap(),
                fingerprint: AgentFingerprint::new("0123456789abcdef").unwrap(),
            },
        ),
    )
    .unwrap();
    let input = |id: &str| {
        let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        CreateCommandJobInput {
            job_id: id.to_owned(),
            target_agent_ids: vec!["guard-contract-agent".to_owned()],
            program: "systemctl".to_owned(),
            args: vec!["status".to_owned(), "nginx".to_owned()],
            timeout: std::time::Duration::from_secs(30),
            confirmed_high_risk: true,
            confirmed_by: "spoof".to_owned(),
            issued_at: now,
            expires_at: now + std::time::Duration::from_secs(120),
            nonce_prefix: format!("nonce-{id}"),
            approval_request_id: format!("approval-{id}"),
            approval_expires_at: now + std::time::Duration::from_secs(120),
        }
    };
    let metadata = CommandCreationMetadata::new(
        2,
        Some(1),
        "explicit_ids",
        "[\"guard-contract-agent\"]".to_owned(),
    )
    .unwrap();
    let digest = "cd".repeat(32);
    fleet_application::AdminTokenRepository::insert_admin_token_hash(store, &digest).unwrap();
    let record = fleet_application::AdminTokenRepository::find_admin_token_record(store, &digest)
        .unwrap()
        .unwrap();
    let legacy = AdminMutationPrincipal::legacy(&digest, &record).unwrap();
    let output = CreateAuthorizedCommandJob::execute(
        store,
        &legacy,
        &FixtureOperation,
        &mut Signer,
        input("guard-contract-legacy"),
        &metadata,
    )
    .unwrap();
    use fleet_application::admin_approval::{
        AdminApprovalDecision, AdminApprovalError, DecideAdminApproval,
    };
    let legacy_approval = output.approval_request.unwrap();
    assert_eq!(legacy_approval.requester, record.actor_id);
    let approved = DecideAdminApproval::execute(
        store,
        &legacy,
        &FixtureOperation,
        &legacy_approval.id,
        AdminApprovalDecision::Approve,
        "legacy fixture".to_owned(),
    )
    .unwrap();
    assert_eq!(
        approved.approval.approver.as_deref(),
        Some(record.actor_id.as_str())
    );
    let owner = initialize_owner(store, &FixtureGenerator::new());
    let actor = seed_credential(store, &owner.id, 70, AdminCredentialKind::WebSession);
    let sibling = seed_credential(store, &owner.id, 71, AdminCredentialKind::WebSession);
    let retired = CreateAuthorizedCommandJob::execute(
        store,
        &legacy,
        &FixtureOperation,
        &mut Signer,
        input("guard-contract-legacy-after-cutover"),
        &metadata,
    );
    assert!(matches!(
        retired,
        Err(CreateAuthorizedCommandJobError::Commit(
            AdminCommandCommitError::Authorization(AdminAccessError::Unauthorized)
        ))
    ));
    assert!(
        fleet_application::JobQueryRepository::find_job_summary(
            store,
            "guard-contract-legacy-after-cutover"
        )
        .unwrap()
        .is_none()
    );
    let principal = AdminMutationPrincipal::personal(actor.clone());
    let output = CreateAuthorizedCommandJob::execute(
        store,
        &principal,
        &FixtureOperation,
        &mut Signer,
        input("guard-contract-before"),
        &metadata,
    )
    .unwrap();
    let pending = output.approval_request.unwrap();
    assert_eq!(pending.requester, owner.id.as_str());
    let before =
        fleet_application::JobQueryRepository::find_job_summary(store, "guard-contract-before")
            .unwrap()
            .unwrap();
    assert_eq!(before.strategy_concurrency, 2);
    assert_eq!(before.strategy_max_failures, Some(1));
    assert_eq!(before.selector_kind, "explicit_ids");
    LogoutAdminSession::execute(store, &actor, &FixtureOperation).unwrap();
    let stale_decision = DecideAdminApproval::execute(
        store,
        &principal,
        &FixtureOperation,
        &pending.id,
        AdminApprovalDecision::Approve,
        "stale fixture".to_owned(),
    );
    assert!(matches!(
        stale_decision,
        Err(AdminApprovalError::Access(AdminAccessError::Unauthorized))
    ));
    let denied = CreateAuthorizedCommandJob::execute(
        store,
        &principal,
        &FixtureOperation,
        &mut Signer,
        input("guard-contract-denied"),
        &metadata,
    );
    assert!(matches!(
        denied,
        Err(CreateAuthorizedCommandJobError::Commit(
            AdminCommandCommitError::Authorization(AdminAccessError::Unauthorized)
        ))
    ));
    assert!(
        fleet_application::JobQueryRepository::find_job_summary(store, "guard-contract-denied")
            .unwrap()
            .is_none()
    );
    assert!(
        fleet_application::JobQueryRepository::find_job_summary(store, "guard-contract-before")
            .unwrap()
            .is_some()
    );
    let principal = AdminMutationPrincipal::personal(sibling);
    let decided = DecideAdminApproval::execute(
        store,
        &principal,
        &FixtureOperation,
        &pending.id,
        AdminApprovalDecision::Approve,
        "current fixture".to_owned(),
    )
    .unwrap();
    assert_eq!(decided.approval.requester, owner.id.as_str());
    assert_eq!(
        decided.approval.approver.as_deref(),
        Some(owner.id.as_str())
    );
    let duplicate_decision = DecideAdminApproval::execute(
        store,
        &principal,
        &FixtureOperation,
        &pending.id,
        AdminApprovalDecision::Reject,
        "duplicate fixture".to_owned(),
    );
    assert!(matches!(
        duplicate_decision,
        Err(AdminApprovalError::Domain(_))
    ));
    let duplicate = CreateAuthorizedCommandJob::execute(
        store,
        &principal,
        &FixtureOperation,
        &mut Signer,
        input("guard-contract-before"),
        &metadata,
    );
    assert!(matches!(
        duplicate,
        Err(CreateAuthorizedCommandJobError::Commit(
            AdminCommandCommitError::DuplicateJob
        ))
    ));
    assert!(
        CreateAuthorizedCommandJob::execute(
            store,
            &principal,
            &FixtureOperation,
            &mut Signer,
            input("guard-contract-after"),
            &metadata
        )
        .is_ok()
    );
    principal
}

#[test]
fn sqlite_authorized_command_creation_rechecks_identity_and_commits_the_whole_bundle() {
    let mut store = SqliteStore::in_memory().unwrap();
    assert_authorized_command_contract(&mut store);
}

#[test]
fn sqlite_approval_commit_rejects_expiry_and_clock_rollback_after_audit() {
    use fleet_application::admin_approval::{
        AdminApprovalDecision, AdminApprovalError, DecideAdminApproval,
    };
    let mut store = SqliteStore::in_memory().unwrap();
    let principal = assert_authorized_command_contract(&mut store);
    struct Clock<'a> {
        store: &'a SqliteStore,
        rollback: bool,
    }
    impl AdminOperation for Clock<'_> {
        fn checked_now(&self) -> Result<i64, AdminAccessError> {
            let written: bool = self.store.connection.query_row("SELECT EXISTS(SELECT 1 FROM audit_events WHERE target='guard-contract-after' AND action='approval_rejected')", [], |row| row.get(0)).unwrap();
            Ok(if written {
                if self.rollback { 999 } else { 1_120 }
            } else {
                1_000
            })
        }
    }
    for rollback in [false, true] {
        let denied = DecideAdminApproval::execute(
            &mut &store,
            &principal,
            &Clock {
                store: &store,
                rollback,
            },
            "approval-guard-contract-after",
            AdminApprovalDecision::Reject,
            "clock fixture".to_owned(),
        );
        assert!(
            matches!(denied, Err(AdminApprovalError::Access(error)) if error == if rollback { AdminAccessError::OperationExpired } else { AdminAccessError::Conflict })
        );
        let approval = store
            .find_approval_request("approval-guard-contract-after")
            .unwrap()
            .unwrap();
        assert_eq!(approval.status, "pending");
        assert!(approval.approver.is_none());
        assert_eq!(
            store
                .find_job_summary("guard-contract-after")
                .unwrap()
                .unwrap()
                .status,
            "pending_approval"
        );
        assert!(!store.connection.query_row("SELECT EXISTS(SELECT 1 FROM audit_events WHERE target='guard-contract-after' AND action='approval_rejected')", [], |row| row.get::<_,bool>(0)).unwrap());
    }
}

fn create_structured_contract_job<
    R: fleet_application::AdminStructuredJobRepository<Error = crate::StoreError>,
>(
    store: &mut R,
    principal: &AdminMutationPrincipal,
    id: &str,
    runbook: bool,
) -> Result<
    fleet_application::AuthorizedJobCreationOutput,
    fleet_application::AdminStructuredJobError<crate::StoreError, &'static str>,
> {
    use fleet_application::{
        CreateAuthorizedStructuredJob, CreateDriftCheckJobInput, CreateRunbookJobInput,
        JobCreationMetadata, TaskEnvelopeSigner,
    };
    struct Signer;
    impl TaskEnvelopeSigner for Signer {
        type Error = &'static str;
        fn sign(&mut self, _: &str) -> Result<String, Self::Error> {
            Ok("fixture-signature".to_owned())
        }
    }
    let issued_at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
    let expires_at = issued_at + std::time::Duration::from_secs(120);
    let target_agent_ids = vec![
        "structured-agent-a".to_owned(),
        "structured-agent-b".to_owned(),
    ];
    let metadata = JobCreationMetadata::new(
        2,
        Some(1),
        "explicit_ids",
        "[\"structured-agent-a\",\"structured-agent-b\"]".to_owned(),
    )
    .unwrap();
    if runbook {
        CreateAuthorizedStructuredJob::runbook(
            store,
            principal,
            &FixtureOperation,
            &mut Signer,
            CreateRunbookJobInput {
                job_id: id.to_owned(),
                target_agent_ids,
                runbook_document: include_str!("../../../examples/runbooks/nginx-basic.yml")
                    .to_owned(),
                timeout: std::time::Duration::from_secs(30),
                confirmed_high_risk: true,
                confirmed_by: "spoof".to_owned(),
                issued_at,
                expires_at,
                nonce_prefix: format!("nonce-{id}"),
                approval_request_id: format!("approval-{id}"),
                approval_expires_at: expires_at,
            },
            &metadata,
        )
    } else {
        CreateAuthorizedStructuredJob::drift(
            store,
            principal,
            &FixtureOperation,
            &mut Signer,
            CreateDriftCheckJobInput {
                job_id: id.to_owned(),
                target_agent_ids,
                policy_document: include_str!("../../../examples/policies/nginx-running.yml")
                    .to_owned(),
                provenance: Some(DriftJobProvenance::scheduled("structured-policy", 7)),
                timeout: std::time::Duration::from_secs(30),
                created_by: "spoof".to_owned(),
                issued_at,
                expires_at,
                nonce_prefix: format!("nonce-{id}"),
                approval_request_id: format!("approval-{id}"),
                approval_expires_at: expires_at,
            },
            &metadata,
        )
    }
}
fn assert_authorized_structured_contract<R>(store: &mut R) -> AdminMutationPrincipal
where
    R: AdminIdentityRepository
        + fleet_application::AdminStructuredJobRepository<Error = crate::StoreError>
        + fleet_application::AgentRepository<Error = crate::StoreError>
        + fleet_application::JobQueryRepository<Error = crate::StoreError>,
{
    use fleet_application::{AdminJobCommitError, AdminStructuredJobError, JobQueryRepository};
    for (index, id) in ["structured-agent-a", "structured-agent-b"]
        .into_iter()
        .enumerate()
    {
        fleet_application::AgentRepository::save(
            store,
            Agent::new(
                AgentId::new(id).unwrap(),
                AgentName::new(id).unwrap(),
                AgentIdentity {
                    public_key: AgentPublicKey::new(format!("fixture-public-{index}")).unwrap(),
                    fingerprint: AgentFingerprint::new(format!("{:016x}", index + 10)).unwrap(),
                },
            ),
        )
        .unwrap();
    }
    let owner = initialize_owner(store, &FixtureGenerator::new());
    let actor = seed_credential(store, &owner.id, 72, AdminCredentialKind::WebSession);
    let sibling = seed_credential(store, &owner.id, 73, AdminCredentialKind::WebSession);
    let principal = AdminMutationPrincipal::personal(actor.clone());
    for runbook in [true, false] {
        let id = if runbook {
            "structured-before-runbook"
        } else {
            "structured-before-drift"
        };
        let output = create_structured_contract_job(store, &principal, id, runbook).unwrap();
        assert_eq!(output.target_count, 2);
        assert_eq!(output.assignment_count, 2);
        assert_eq!(
            output.approval_request.unwrap().requester,
            owner.id.as_str()
        );
        let job = JobQueryRepository::find_job_summary(store, id)
            .unwrap()
            .unwrap();
        assert_eq!(job.status, "pending_approval");
        assert_eq!(job.strategy_concurrency, 2);
        assert_eq!(job.strategy_max_failures, Some(1));
        assert_eq!(job.target_count, 2);
    }
    LogoutAdminSession::execute(store, &actor, &FixtureOperation).unwrap();
    for runbook in [true, false] {
        let id = if runbook {
            "structured-denied-runbook"
        } else {
            "structured-denied-drift"
        };
        assert!(matches!(
            create_structured_contract_job(store, &principal, id, runbook),
            Err(AdminStructuredJobError::Commit(
                AdminJobCommitError::Authorization(AdminAccessError::Unauthorized)
            ))
        ));
        assert!(
            JobQueryRepository::find_job_summary(store, id)
                .unwrap()
                .is_none()
        );
    }
    let principal = AdminMutationPrincipal::personal(sibling);
    for runbook in [true, false] {
        let before = if runbook {
            "structured-before-runbook"
        } else {
            "structured-before-drift"
        };
        assert_eq!(
            JobQueryRepository::find_job_summary(store, before)
                .unwrap()
                .unwrap()
                .status,
            "pending_approval"
        );
        assert!(matches!(
            create_structured_contract_job(store, &principal, before, runbook),
            Err(AdminStructuredJobError::Commit(
                AdminJobCommitError::DuplicateJob
            ))
        ));
        create_structured_contract_job(
            store,
            &principal,
            if runbook {
                "structured-after-runbook"
            } else {
                "structured-after-drift"
            },
            runbook,
        )
        .unwrap();
    }
    principal
}
#[test]
fn sqlite_authorized_structured_jobs_preserve_provenance_and_deny_revoked_contexts() {
    let mut store = SqliteStore::in_memory().unwrap();
    assert_authorized_structured_contract(&mut store);
    let provenance = store.connection.query_row("SELECT drift_policy_id,drift_policy_version,drift_purpose FROM jobs WHERE id='structured-before-drift'",[],|row|Ok((row.get::<_,String>(0)?,row.get::<_,i64>(1)?,row.get::<_,String>(2)?))).unwrap();
    assert_eq!(
        provenance,
        ("structured-policy".to_owned(), 7, "evaluation".to_owned())
    );
}

fn catalog_contract_input(id: &str) -> fleet_application::CreateCatalogRunbookJobInput {
    let mut input = crate::catalog_job_creation::tests::input();
    input.job_id = id.to_owned();
    input.nonce_prefix = format!("nonce-{id}");
    input.approval_request_id = format!("approval-{id}");
    input.confirmed_by = "spoof".to_owned();
    input.issued_at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
    input.expires_at = input.issued_at + std::time::Duration::from_secs(120);
    input.approval_expires_at = input.expires_at;
    input
}
fn create_catalog_contract_job<
    R: fleet_application::AdminCatalogJobRepository<Error = crate::StoreError>,
>(
    store: &mut R,
    principal: &AdminMutationPrincipal,
    id: &str,
) -> Result<
    fleet_application::CreateRunbookJobOutput,
    fleet_application::AuthorizedCatalogJobError<crate::StoreError, &'static str>,
> {
    struct Signer;
    impl fleet_application::TaskEnvelopeSigner for Signer {
        type Error = &'static str;
        fn sign(&mut self, _: &str) -> Result<String, Self::Error> {
            Ok("fixture-signature".to_owned())
        }
    }
    fleet_application::CreateAuthorizedCatalogRunbookJob::execute(
        store,
        principal,
        &FixtureOperation,
        &mut Signer,
        catalog_contract_input(id),
    )
}
fn assert_authorized_catalog_contract<R>(store: &mut R) -> AdminMutationPrincipal
where
    R: AdminIdentityRepository
        + fleet_application::AdminCatalogJobRepository<Error = crate::StoreError>
        + fleet_application::AgentRepository<Error = crate::StoreError>
        + fleet_application::CatalogRepository<Error = crate::StoreError>
        + fleet_application::JobQueryRepository<Error = crate::StoreError>
        + fleet_application::catalog_execution::CatalogRunbookJobQueryRepository<
            Error = crate::StoreError,
        >,
{
    use fleet_application::{
        AdminJobCommitError, CreateCatalogRunbookJobError, JobQueryRepository,
    };
    crate::catalog_job_creation::tests::seed_catalog(
        store,
        &catalog_contract_input("catalog-before"),
    );
    let owner = initialize_owner(store, &FixtureGenerator::new());
    let actor = seed_credential(store, &owner.id, 74, AdminCredentialKind::WebSession);
    let sibling = seed_credential(store, &owner.id, 75, AdminCredentialKind::WebSession);
    let principal = AdminMutationPrincipal::personal(actor.clone());
    let created = create_catalog_contract_job(store, &principal, "catalog-before").unwrap();
    assert_eq!(created.targets.len(), 2);
    assert_eq!(
        created.approval_request.unwrap().requester,
        owner.id.as_str()
    );
    LogoutAdminSession::execute(store, &actor, &FixtureOperation).unwrap();
    let denied = create_catalog_contract_job(store, &principal, "catalog-denied");
    assert!(matches!(
        denied,
        Err(CreateCatalogRunbookJobError::Repository(
            AdminJobCommitError::Authorization(AdminAccessError::Unauthorized)
        ))
    ));
    assert!(
        JobQueryRepository::find_job_summary(store, "catalog-denied")
            .unwrap()
            .is_none()
    );
    let before = JobQueryRepository::find_job_summary(store, "catalog-before")
        .unwrap()
        .unwrap();
    assert_eq!(before.status, "pending_approval");
    assert_eq!(before.target_count, 2);
    assert_eq!(before.strategy_concurrency, 3);
    assert_eq!(before.strategy_max_failures, Some(2));
    let provenance = fleet_application::catalog_execution::CatalogRunbookJobQueryRepository::find_catalog_runbook_job_provenance(store,&JobId::new("catalog-before").unwrap()).unwrap().unwrap();
    assert_eq!(provenance.source_id().as_str(), "catalog-atomic");
    assert_eq!(provenance.commit().as_str(), "a".repeat(40));
    assert_eq!(provenance.path(), "runbooks/atomic.yaml");
    let principal = AdminMutationPrincipal::personal(sibling);
    assert!(matches!(
        create_catalog_contract_job(store, &principal, "catalog-before"),
        Err(CreateCatalogRunbookJobError::DuplicateJob)
    ));
    create_catalog_contract_job(store, &principal, "catalog-after").unwrap();
    principal
}
#[test]
fn sqlite_authorized_catalog_jobs_recheck_human_authority_and_roll_back_every_effect() {
    let mut store = SqliteStore::in_memory().unwrap();
    let principal = assert_authorized_catalog_contract(&mut store);
    let counts = |store: &SqliteStore| {
        store.connection.query_row("SELECT (SELECT count(*) FROM jobs),(SELECT count(*) FROM job_catalog_runbook_provenance),(SELECT count(*) FROM task_assignments),(SELECT count(*) FROM job_targets),(SELECT count(*) FROM approval_requests),(SELECT count(*) FROM audit_events)",[],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?,row.get::<_,i64>(3)?,row.get::<_,i64>(4)?,row.get::<_,i64>(5)?))).unwrap()
    };
    let before = counts(&store);
    for trigger in [
        "CREATE TRIGGER fixture_catalog_fault BEFORE INSERT ON audit_events WHEN NEW.action='catalog_runbook_job_created' BEGIN SELECT RAISE(ABORT,'private catalog diagnostic'); END;",
        "CREATE TRIGGER fixture_catalog_fault BEFORE INSERT ON job_catalog_runbook_provenance BEGIN SELECT RAISE(ABORT,'private catalog diagnostic'); END;",
        "CREATE TRIGGER fixture_catalog_fault BEFORE INSERT ON task_assignments WHEN NEW.agent_id='agent-2' BEGIN SELECT RAISE(ABORT,'private catalog diagnostic'); END;",
    ] {
        store.connection.execute_batch(trigger).unwrap();
        assert!(matches!(
            create_catalog_contract_job(&mut store, &principal, "catalog-fault"),
            Err(fleet_application::CreateCatalogRunbookJobError::Repository(
                fleet_application::AdminJobCommitError::Repository(_)
            ))
        ));
        assert_eq!(counts(&store), before);
        store
            .connection
            .execute_batch("DROP TRIGGER fixture_catalog_fault;")
            .unwrap();
    }
    create_catalog_contract_job(&mut store, &principal, "catalog-fault").unwrap();
}

fn cancel_contract_job<R: fleet_application::admin_cancel::AdminCancellationRepository>(
    store: &mut R,
    principal: &AdminMutationPrincipal,
    job: &str,
) -> Result<fleet_application::admin_cancel::CancelAdminJobOutput, AdminAccessError> {
    fleet_application::admin_cancel::CancelAdminJob::execute(
        store,
        principal,
        &FixtureOperation,
        job,
        "fixture cancellation token=hidden".to_owned(),
        |_| "fixture cancellation token=[REDACTED]".to_owned(),
    )
}
fn assert_authorized_cancellation_contract<R>(store: &mut R) -> AdminMutationPrincipal
where
    R: AdminIdentityRepository
        + fleet_application::AdminStructuredJobRepository<Error = crate::StoreError>
        + fleet_application::admin_cancel::AdminCancellationRepository
        + fleet_application::AgentRepository<Error = crate::StoreError>
        + fleet_application::JobQueryRepository<Error = crate::StoreError>,
{
    use fleet_application::JobQueryRepository;
    let sibling = assert_authorized_structured_contract(store);
    let user = AdminUserId::parse(sibling.actor_id()).unwrap();
    let actor = seed_credential(store, &user, 76, AdminCredentialKind::WebSession);
    let principal = AdminMutationPrincipal::personal(actor.clone());
    let canceled = cancel_contract_job(store, &principal, "structured-before-runbook").unwrap();
    assert_eq!(canceled.status, JobStatus::Canceled);
    assert_eq!(canceled.canceled.len(), 2);
    LogoutAdminSession::execute(store, &actor, &FixtureOperation).unwrap();
    assert!(matches!(
        cancel_contract_job(store, &principal, "structured-after-runbook"),
        Err(AdminAccessError::Unauthorized)
    ));
    assert_eq!(
        JobQueryRepository::find_job_summary(store, "structured-after-runbook")
            .unwrap()
            .unwrap()
            .status,
        "pending_approval"
    );
    assert_eq!(
        JobQueryRepository::find_job_summary(store, "structured-before-runbook")
            .unwrap()
            .unwrap()
            .status,
        "canceled"
    );
    let repeated = cancel_contract_job(store, &sibling, "structured-before-runbook").unwrap();
    assert!(repeated.canceled.is_empty());
    assert_eq!(repeated.status, JobStatus::Canceled);
    sibling
}
#[test]
fn sqlite_authorized_cancellation_preserves_terminal_state_and_rolls_back_faults() {
    let mut store = SqliteStore::in_memory().unwrap();
    let principal = assert_authorized_cancellation_contract(&mut store);
    let before = store.list_audit_events(100).unwrap().len();
    for trigger in [
        "CREATE TRIGGER fixture_cancel_fault BEFORE INSERT ON audit_events WHEN NEW.action='job_canceled' BEGIN SELECT RAISE(ABORT,'private cancel diagnostic'); END;",
        "CREATE TRIGGER fixture_cancel_fault BEFORE UPDATE OF status ON jobs WHEN NEW.id='structured-after-runbook' BEGIN SELECT RAISE(ABORT,'private cancel diagnostic'); END;",
        "CREATE TRIGGER fixture_cancel_fault BEFORE UPDATE OF status ON task_assignments WHEN NEW.agent_id='structured-agent-b' AND NEW.status='canceled' BEGIN SELECT RAISE(ABORT,'private cancel diagnostic'); END;",
    ] {
        store.connection.execute_batch(trigger).unwrap();
        assert!(matches!(
            cancel_contract_job(&mut store, &principal, "structured-after-runbook"),
            Err(AdminAccessError::Unavailable)
        ));
        assert_eq!(
            store
                .find_job_summary("structured-after-runbook")
                .unwrap()
                .unwrap()
                .status,
            "pending_approval"
        );
        assert!(store.list_task_assignment_summaries_for_job("structured-after-runbook").unwrap().iter().all(|assignment|assignment.status=="queued" && assignment.last_error.is_empty()));
        assert_eq!(store.list_audit_events(100).unwrap().len(), before);
        store
            .connection
            .execute_batch("DROP TRIGGER fixture_cancel_fault;")
            .unwrap();
    }
    cancel_contract_job(&mut store, &principal, "structured-after-runbook").unwrap();
    let decision = fleet_application::admin_approval::DecideAdminApproval::execute(
        &mut store,
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
        store
            .find_job_summary("structured-after-runbook")
            .unwrap()
            .unwrap()
            .status,
        "canceled"
    );
    assert_eq!(
        store
            .find_approval_request("approval-structured-after-runbook")
            .unwrap()
            .unwrap()
            .status,
        "pending"
    );
}

struct ExpiryOperation(i64);
impl AdminOperation for ExpiryOperation {
    fn checked_now(&self) -> Result<i64, AdminAccessError> {
        Ok(self.0)
    }
}
fn expire_contract_approvals<R: fleet_application::admin_approval::AdminApprovalRepository>(
    store: &mut R,
    principal: &AdminMutationPrincipal,
    now: i64,
) -> Result<
    fleet_application::ExpireApprovalsOutput,
    fleet_application::admin_approval::AdminApprovalError,
> {
    fleet_application::admin_approval::ExpireAdminApprovals::execute(
        store,
        principal,
        &ExpiryOperation(now),
    )
}
fn assert_authorized_expiry_contract<R>(store: &mut R) -> AdminMutationPrincipal
where
    R: AdminIdentityRepository
        + fleet_application::AdminStructuredJobRepository<Error = crate::StoreError>
        + fleet_application::admin_cancel::AdminCancellationRepository
        + fleet_application::admin_approval::AdminApprovalRepository
        + fleet_application::AgentRepository<Error = crate::StoreError>
        + fleet_application::JobQueryRepository<Error = crate::StoreError>,
{
    let principal = assert_authorized_cancellation_contract(store);
    let user = AdminUserId::parse(principal.actor_id()).unwrap();
    let actor = seed_credential(store, &user, 78, AdminCredentialKind::WebSession);
    let stale = AdminMutationPrincipal::personal(actor.clone());
    assert!(
        expire_contract_approvals(store, &stale, 1_119)
            .unwrap()
            .expired
            .is_empty()
    );
    LogoutAdminSession::execute(store, &actor, &FixtureOperation).unwrap();
    assert!(matches!(
        expire_contract_approvals(store, &stale, 1_120),
        Err(
            fleet_application::admin_approval::AdminApprovalError::Access(
                AdminAccessError::Unauthorized
            )
        )
    ));
    principal
}
#[test]
fn sqlite_authorized_expiry_is_atomic_and_preserves_canceled_jobs() {
    let mut store = SqliteStore::in_memory().unwrap();
    let principal = assert_authorized_expiry_contract(&mut store);
    let before = store.list_audit_events(100).unwrap().len();
    for trigger in [
        "CREATE TRIGGER fixture_expiry_fault BEFORE INSERT ON audit_events WHEN NEW.action='approval_expired' BEGIN SELECT RAISE(ABORT,'private expiry diagnostic'); END;",
        "CREATE TRIGGER fixture_expiry_fault BEFORE UPDATE OF status ON jobs WHEN NEW.id='structured-before-drift' AND NEW.status='expired' BEGIN SELECT RAISE(ABORT,'private expiry diagnostic'); END;",
        "CREATE TRIGGER fixture_expiry_fault BEFORE UPDATE OF status ON approval_requests WHEN NEW.id='approval-structured-before-drift' AND NEW.status='expired' BEGIN SELECT RAISE(ABORT,'private expiry diagnostic'); END;",
    ] {
        store.connection.execute_batch(trigger).unwrap();
        assert!(matches!(
            expire_contract_approvals(&mut store, &principal, 1_120),
            Err(
                fleet_application::admin_approval::AdminApprovalError::Access(
                    AdminAccessError::Unavailable
                )
            )
        ));
        assert_eq!(
            store
                .find_job_summary("structured-before-runbook")
                .unwrap()
                .unwrap()
                .status,
            "canceled"
        );
        for job in [
            "structured-before-drift",
            "structured-after-runbook",
            "structured-after-drift",
        ] {
            assert_eq!(
                store.find_job_summary(job).unwrap().unwrap().status,
                "pending_approval"
            );
        }
        assert_eq!(
            store
                .list_approval_requests(Some("pending"), 100)
                .unwrap()
                .len(),
            4
        );
        assert_eq!(store.list_audit_events(100).unwrap().len(), before);
        store
            .connection
            .execute_batch("DROP TRIGGER fixture_expiry_fault;")
            .unwrap();
    }
    let expired = expire_contract_approvals(&mut store, &principal, 1_120).unwrap();
    assert_eq!(expired.expired.len(), 4);
    assert!(
        expired
            .expired
            .iter()
            .all(|record| record.status == "expired")
    );
    assert_eq!(
        store
            .find_job_summary("structured-before-runbook")
            .unwrap()
            .unwrap()
            .status,
        "canceled"
    );
    for job in [
        "structured-before-drift",
        "structured-after-runbook",
        "structured-after-drift",
    ] {
        assert_eq!(
            store.find_job_summary(job).unwrap().unwrap().status,
            "expired"
        );
    }
    let events = store
        .list_audit_events(100)
        .unwrap()
        .into_iter()
        .filter(|event| event.action == "approval_expired")
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 4);
    assert!(
        events
            .iter()
            .all(|event| event.actor.as_str() == principal.actor_id())
    );
    assert!(
        expire_contract_approvals(&mut store, &principal, 1_120)
            .unwrap()
            .expired
            .is_empty()
    );
    assert_eq!(store.list_audit_events(100).unwrap().len(), before + 4);
}

const REMEDIATION_CONTRACT_BODY: &str = "apiVersion: fleet.sponzey.dev/v1alpha1\nkind: Runbook\nname: identity-smoke\nselector: role=web\nsteps:\n  - id: collect\n    facts.collect:\n";
fn request_remediation_contract<
    R: fleet_application::admin_approval::AdminApprovalRepository
        + fleet_application::admin_remediation::AdminRemediationRead,
>(
    store: &mut R,
    principal: &AdminMutationPrincipal,
    id: &str,
) -> Result<
    fleet_application::RequestRemediationApprovalOutput,
    fleet_application::admin_remediation::AdminRemediationError,
> {
    let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
    fleet_application::admin_remediation::RequestAdminRemediationApproval::execute(
        store,
        principal,
        &FixtureOperation,
        fleet_application::RequestRemediationApprovalInput {
            remediation_id: id.to_owned(),
            approval_id: format!("approval-{id}"),
            job_id: format!("job-{id}"),
            requester: "spoof".to_owned(),
            reason: "owned request".to_owned(),
            expires_at: now + std::time::Duration::from_secs(120),
            now,
        },
    )
}
fn approve_remediation_contract<
    R: fleet_application::admin_approval::AdminApprovalRepository
        + fleet_application::admin_remediation::AdminRemediationRead,
>(
    store: &mut R,
    principal: &AdminMutationPrincipal,
    id: &str,
) -> Result<
    fleet_application::ApproveRemediationRunbookJobOutput,
    fleet_application::admin_remediation::AdminRemediationError<&'static str>,
> {
    struct Signer;
    impl fleet_application::TaskEnvelopeSigner for Signer {
        type Error = &'static str;
        fn sign(&mut self, _: &str) -> Result<String, Self::Error> {
            Ok("fixture-signature".to_owned())
        }
    }
    let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
    fleet_application::admin_remediation::ApproveAdminRemediationJob::execute(
        store,
        principal,
        &FixtureOperation,
        &mut Signer,
        fleet_application::ApproveRemediationRunbookJobInput {
            remediation_id: id.to_owned(),
            approval_id: format!("approval-{id}"),
            job_id: format!("job-{id}"),
            runbook_document: REMEDIATION_CONTRACT_BODY.to_owned(),
            timeout: std::time::Duration::from_secs(30),
            approver: "spoof".to_owned(),
            approval_reason: "owned decision".to_owned(),
            issued_at: now,
            expires_at: now + std::time::Duration::from_secs(120),
            nonce_prefix: format!("nonce-{id}"),
        },
    )
}
fn assert_authorized_remediation_contract<R>(store: &mut R) -> AdminMutationPrincipal
where
    R: AdminIdentityRepository
        + fleet_application::admin_approval::AdminApprovalRepository
        + fleet_application::admin_remediation::AdminRemediationRead
        + fleet_application::RemediationRequestRepository<Error = crate::StoreError>
        + fleet_application::AgentRepository<Error = crate::StoreError>
        + fleet_application::JobQueryRepository<Error = crate::StoreError>,
{
    use fleet_application::admin_remediation::AdminRemediationError;
    fleet_application::AgentRepository::save(
        store,
        Agent::new(
            AgentId::new("remediation-agent").unwrap(),
            AgentName::new("remediation-agent").unwrap(),
            AgentIdentity {
                public_key: AgentPublicKey::new("fixture-public-remediation").unwrap(),
                fingerprint: AgentFingerprint::new("0123456789abcdef").unwrap(),
            },
        ),
    )
    .unwrap();
    for id in [
        "remed-contract-before",
        "remed-contract-after",
        "remed-contract-denied",
        "remed-contract-fault",
    ] {
        fleet_application::RemediationRequestRepository::save_remediation_request(
            store,
            fleet_application::RemediationRequestRecord {
                id: id.to_owned(),
                policy_id: "identity-policy".to_owned(),
                policy_name: "identity-policy".to_owned(),
                agent_id: "remediation-agent".to_owned(),
                runbook_ref: "runbooks/readonly.yml".to_owned(),
                status: "proposed".to_owned(),
                approval_required: true,
                risk_summary: "owned approval fixture".to_owned(),
                job_id: None,
                origin_drift_report_id: None,
                policy_version: None,
                created_at: std::time::UNIX_EPOCH,
                updated_at: std::time::UNIX_EPOCH,
            },
        )
        .unwrap();
    }
    let owner = initialize_owner(store, &FixtureGenerator::new());
    let actor = seed_credential(store, &owner.id, 80, AdminCredentialKind::WebSession);
    let sibling = seed_credential(store, &owner.id, 81, AdminCredentialKind::WebSession);
    let principal = AdminMutationPrincipal::personal(actor.clone());
    let requested =
        request_remediation_contract(store, &principal, "remed-contract-before").unwrap();
    assert_eq!(requested.approval.requester, owner.id.as_str());
    let approved =
        approve_remediation_contract(store, &principal, "remed-contract-before").unwrap();
    assert_eq!(approved.remediation.status, "job_created");
    assert_eq!(
        approved.approval.approver.as_deref(),
        Some(owner.id.as_str())
    );
    assert_eq!(approved.envelopes.len(), 1);
    request_remediation_contract(store, &principal, "remed-contract-after").unwrap();
    LogoutAdminSession::execute(store, &actor, &FixtureOperation).unwrap();
    assert!(matches!(
        request_remediation_contract(store, &principal, "remed-contract-denied"),
        Err(AdminRemediationError::Access(
            AdminAccessError::Unauthorized
        ))
    ));
    assert!(matches!(
        approve_remediation_contract(store, &principal, "remed-contract-after"),
        Err(AdminRemediationError::Access(
            AdminAccessError::Unauthorized
        ))
    ));
    assert_eq!(
        fleet_application::RemediationRequestRepository::find_remediation_request(
            store,
            "remed-contract-denied"
        )
        .unwrap()
        .unwrap()
        .status,
        "proposed"
    );
    assert_eq!(
        fleet_application::RemediationRequestRepository::find_remediation_request(
            store,
            "remed-contract-after"
        )
        .unwrap()
        .unwrap()
        .status,
        "pending_approval"
    );
    assert!(
        fleet_application::JobQueryRepository::find_job_summary(store, "job-remed-contract-after")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fleet_application::JobQueryRepository::find_job_summary(store, "job-remed-contract-before")
            .unwrap()
            .unwrap()
            .status,
        "queued"
    );
    let principal = AdminMutationPrincipal::personal(sibling);
    request_remediation_contract(store, &principal, "remed-contract-denied").unwrap();
    assert!(matches!(
        request_remediation_contract(store, &principal, "remed-contract-denied"),
        Err(AdminRemediationError::Invalid(_))
    ));
    principal
}
#[test]
fn sqlite_authorized_remediation_commits_every_effect_or_rolls_back() {
    use fleet_application::admin_remediation::AdminRemediationError;
    let mut store = SqliteStore::in_memory().unwrap();
    let principal = assert_authorized_remediation_contract(&mut store);
    let before = store.list_audit_events(100).unwrap().len();
    for trigger in [
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON audit_events WHEN NEW.action='remediation_approval_requested' BEGIN SELECT RAISE(ABORT,'private remed diagnostic'); END;",
        "CREATE TRIGGER fixture_remed_fault BEFORE UPDATE OF status ON remediation_requests WHEN NEW.id='remed-contract-fault' BEGIN SELECT RAISE(ABORT,'private remed diagnostic'); END;",
    ] {
        store.connection.execute_batch(trigger).unwrap();
        assert!(matches!(
            request_remediation_contract(&mut store, &principal, "remed-contract-fault"),
            Err(AdminRemediationError::Access(AdminAccessError::Unavailable))
        ));
        assert_eq!(
            store
                .find_remediation_request_record("remed-contract-fault")
                .unwrap()
                .unwrap()
                .status,
            "proposed"
        );
        assert!(
            store
                .find_approval_request("approval-remed-contract-fault")
                .unwrap()
                .is_none()
        );
        assert_eq!(store.list_audit_events(100).unwrap().len(), before);
        store
            .connection
            .execute_batch("DROP TRIGGER fixture_remed_fault;")
            .unwrap();
    }
    request_remediation_contract(&mut store, &principal, "remed-contract-fault").unwrap();
    let before = store.list_audit_events(100).unwrap().len();
    for trigger in [
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON jobs WHEN NEW.id='job-remed-contract-after' BEGIN SELECT RAISE(ABORT,'private remed diagnostic'); END;",
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON task_assignments WHEN NEW.job_id='job-remed-contract-after' BEGIN SELECT RAISE(ABORT,'private remed diagnostic'); END;",
        "CREATE TRIGGER fixture_remed_fault BEFORE UPDATE OF status ON approval_requests WHEN NEW.id='approval-remed-contract-after' BEGIN SELECT RAISE(ABORT,'private remed diagnostic'); END;",
        "CREATE TRIGGER fixture_remed_fault BEFORE UPDATE OF status ON remediation_requests WHEN NEW.id='remed-contract-after' BEGIN SELECT RAISE(ABORT,'private remed diagnostic'); END;",
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON audit_events WHEN NEW.action='approval_approved' BEGIN SELECT RAISE(ABORT,'private remed diagnostic'); END;",
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON audit_events WHEN NEW.action='runbook_job_created' BEGIN SELECT RAISE(ABORT,'private remed diagnostic'); END;",
        "CREATE TRIGGER fixture_remed_fault BEFORE INSERT ON audit_events WHEN NEW.action='remediation_job_created' BEGIN SELECT RAISE(ABORT,'private remed diagnostic'); END;",
    ] {
        store.connection.execute_batch(trigger).unwrap();
        assert!(matches!(
            approve_remediation_contract(&mut store, &principal, "remed-contract-after"),
            Err(AdminRemediationError::Access(AdminAccessError::Unavailable))
        ));
        assert_eq!(
            store
                .find_remediation_request_record("remed-contract-after")
                .unwrap()
                .unwrap()
                .status,
            "pending_approval"
        );
        assert_eq!(
            store
                .find_approval_request("approval-remed-contract-after")
                .unwrap()
                .unwrap()
                .status,
            "pending"
        );
        assert!(
            store
                .find_job_summary("job-remed-contract-after")
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .list_task_assignment_summaries_for_job("job-remed-contract-after")
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.list_audit_events(100).unwrap().len(), before);
        store
            .connection
            .execute_batch("DROP TRIGGER fixture_remed_fault;")
            .unwrap();
    }
    approve_remediation_contract(&mut store, &principal, "remed-contract-after").unwrap();
    assert_eq!(
        store
            .find_job_summary("job-remed-contract-after")
            .unwrap()
            .unwrap()
            .status,
        "queued"
    );
    assert_eq!(store.list_audit_events(100).unwrap().len(), before + 3);
    assert!(matches!(
        approve_remediation_contract(&mut store, &principal, "remed-contract-after"),
        Err(AdminRemediationError::Invalid(_))
    ));
}

struct FixtureOperation;
impl AdminOperation for FixtureOperation {
    fn checked_now(&self) -> Result<i64, AdminAccessError> {
        Ok(1_000)
    }
}

struct FixtureLocalAuthority;
impl AdminLocalAuthority for FixtureLocalAuthority {
    fn require_exclusive(&self) -> Result<AuditActor, AdminAccessError> {
        Ok(AuditActor::new("local:fixture"))
    }
}

struct FixturePasswords;
impl AdminPasswordPort for FixturePasswords {
    fn hash_new(
        &self,
        input: &str,
        _: &AdminUsername,
    ) -> Result<AdminPasswordVerifier, AdminAccessError> {
        NewAdminPassword::parse(input)?;
        Ok(AdminPasswordVerifier::from_parts(
            AdminPasswordVerifier::PROFILE_ID,
            &[4; 16],
            &[5; 32],
        )?)
    }
    fn verify(
        &self,
        input: &str,
        verifier: Option<&AdminPasswordVerifier>,
    ) -> Result<bool, AdminAccessError> {
        Ok(input == CURRENT_PASSWORD && verifier.is_some())
    }
}

struct FixtureGenerator {
    users: Cell<u128>,
    credentials: Cell<u128>,
}
impl FixtureGenerator {
    fn new() -> Self {
        Self {
            users: Cell::new(0),
            credentials: Cell::new(0),
        }
    }
}
impl AdminIdentityGenerator for FixtureGenerator {
    fn user_id(&self) -> Result<AdminUserId, AdminAccessError> {
        let next = self.users.get() + 1;
        self.users.set(next);
        Ok(AdminUserId::parse(format!("usr_{next:032x}"))?)
    }
    fn credential(
        &self,
        kind: AdminCredentialKind,
    ) -> Result<AdminNewCredential, AdminAccessError> {
        let next = self.credentials.get() + 1;
        self.credentials.set(next);
        Ok(AdminNewCredential {
            id: AdminCredentialId::parse(format!("crd_{next:032x}"))
                .map_err(|_| AdminAccessError::Unavailable)?,
            kind,
            digest: AdminCredentialDigest::from_bytes([next as u8; 32]),
            secret: AdminSecret::from_adapter(format!("fixture_secret_{next:064x}"))?,
        })
    }
}

fn authenticate<R: AdminIdentityRead>(
    repository: &R,
    marker: u8,
    kind: AdminCredentialKind,
) -> Result<AuthenticatedAdmin, AdminAccessError> {
    AuthenticateAdminCredential::execute(
        repository,
        &FixtureOperation,
        kind,
        &AdminCredentialDigest::from_bytes([marker; 32]),
    )
}

fn seed_credential<R: AdminIdentityRepository>(
    repository: &mut R,
    user: &AdminUserId,
    marker: u8,
    kind: AdminCredentialKind,
) -> AuthenticatedAdmin {
    repository
        .identity_transaction(|tx| {
            let account = tx.account_by_id(user)?.ok_or(AdminAccessError::NotFound)?;
            let state = tx.auth_state()?;
            let credential = AdminCredential::issue(
                AdminCredentialId::parse(format!("crd_{marker:032x}")).unwrap(),
                kind,
                AdminCredentialDigest::from_bytes([marker; 32]),
                AdminCredentialBinding::for_account(&account, state.epoch),
                1_000,
            )
            .unwrap();
            tx.insert_credential(&credential.snapshot())
        })
        .unwrap();
    authenticate(repository, marker, kind).unwrap()
}

fn initialize_owner<R: AdminIdentityRepository>(
    repository: &mut R,
    generator: &FixtureGenerator,
) -> AdminAccountSummary {
    InitializeAdminOwner::execute(
        repository,
        &FixtureLocalAuthority,
        &FixtureOperation,
        &FixturePasswords,
        generator,
        InitializeOwnerInput {
            username: AdminUsername::parse("fixture_owner").unwrap(),
            display_name: AdminDisplayName::parse("Fixture owner").unwrap(),
            new_password: CURRENT_PASSWORD,
        },
    )
    .unwrap()
}

fn assert_owner_account_metadata_contract<R: AdminIdentityRepository + AdminAccountQuery>(
    repository: &mut R,
) -> (AuthenticatedAdmin, AdminUserId) {
    let generator = FixtureGenerator::new();
    let owner = initialize_owner(repository, &generator);
    let actor = seed_credential(repository, &owner.id, 0x90, AdminCredentialKind::WebSession);
    let mut users = vec![owner.id.clone()];
    let mut nonowners = Vec::new();
    for (name, role, active, disable) in [
        ("metadata_admin", AdminRole::Admin, true, false),
        ("metadata_operator", AdminRole::Operator, true, false),
        ("metadata_viewer", AdminRole::Viewer, true, false),
        ("metadata_pending", AdminRole::Viewer, false, false),
        ("metadata_disabled", AdminRole::Viewer, false, true),
    ] {
        let created = CreateAdminAccount::execute(
            repository,
            &actor,
            &FixtureOperation,
            &FixturePasswords,
            &generator,
            CreateAdminAccountInput {
                username: AdminUsername::parse(name).unwrap(),
                display_name: AdminDisplayName::parse(name).unwrap(),
                role,
                current_password: CURRENT_PASSWORD,
            },
        )
        .unwrap();
        if active {
            let grant = repository
                .credential_by_id(&created.setup.id)
                .unwrap()
                .unwrap()
                .snapshot();
            CompleteAdminSetup::execute(
                repository,
                &FixtureOperation,
                &FixturePasswords,
                CompleteAdminSetupInput {
                    kind: grant.kind,
                    digest: grant.digest,
                    new_password: CURRENT_PASSWORD,
                },
            )
            .unwrap();
            let other = seed_credential(
                repository,
                &created.account.id,
                0xa0 + users.len() as u8,
                AdminCredentialKind::PersonalToken,
            );
            nonowners.push(other);
        }
        if disable {
            ChangeAdminAccount::execute(
                repository,
                &actor,
                &FixtureOperation,
                &FixturePasswords,
                ChangeAdminAccountInput {
                    user_id: created.account.id.clone(),
                    display_name: None,
                    role: None,
                    disable: true,
                    current_password: CURRENT_PASSWORD,
                },
            )
            .unwrap();
        }
        users.push(created.account.id);
    }
    let before: Vec<_> = users
        .iter()
        .map(|id| repository.account_by_id(id).unwrap().unwrap().snapshot())
        .collect();
    let credential = repository
        .credential_by_id(actor.credential_id())
        .unwrap()
        .unwrap()
        .snapshot();
    let state = repository.auth_state().unwrap();
    let mut collected = Vec::new();
    let mut after = None;
    loop {
        let page = ListAdminAccountMetadata::execute(
            repository,
            &actor,
            &FixtureOperation,
            ListAdminAccountMetadataInput {
                after: after.as_ref(),
                limit: AdminMetadataPageSize::new(2).unwrap(),
            },
        )
        .unwrap();
        assert!(page.items.len() <= 2);
        collected.extend(page.items.iter().map(|account| account.id.clone()));
        after = page.next_after;
        if after.is_none() {
            break;
        }
        assert!(collected.len() < users.len());
    }
    assert_eq!(collected, users);
    assert_eq!(
        GetAdminAccountMetadata::execute(repository, &actor, &FixtureOperation, &users[4])
            .unwrap()
            .status,
        AdminAccountStatus::PendingSetup
    );
    assert_eq!(
        GetAdminAccountMetadata::execute(repository, &actor, &FixtureOperation, &users[5])
            .unwrap()
            .status,
        AdminAccountStatus::Disabled
    );
    let missing = AdminUserId::parse("usr_ffffffffffffffffffffffffffffffff").unwrap();
    assert_eq!(
        GetAdminAccountMetadata::execute(repository, &actor, &FixtureOperation, &missing),
        Err(AdminAccessError::NotFound)
    );
    for other in nonowners {
        assert!(matches!(
            ListAdminAccountMetadata::execute(
                repository,
                &other,
                &FixtureOperation,
                ListAdminAccountMetadataInput {
                    after: None,
                    limit: AdminMetadataPageSize::default()
                }
            ),
            Err(AdminAccessError::Forbidden)
        ));
        assert_eq!(
            GetAdminAccountMetadata::execute(repository, &other, &FixtureOperation, &owner.id),
            Err(AdminAccessError::Forbidden)
        );
    }
    for limit in [0, 102, usize::MAX] {
        assert!(matches!(
            repository.account_page(None, limit),
            Err(AdminAccessError::InvalidRequest)
        ));
    }
    assert_eq!(repository.account_page(None, 1).unwrap().len(), 1);
    assert_eq!(
        repository.account_page(Some(&users[2]), 101).unwrap().len(),
        3
    );
    assert_eq!(repository.auth_state().unwrap(), state);
    assert!(
        repository
            .credential_by_id(actor.credential_id())
            .unwrap()
            .unwrap()
            .snapshot()
            == credential
    );
    assert!(
        users
            .iter()
            .map(|id| repository.account_by_id(id).unwrap().unwrap().snapshot())
            .eq(before)
    );
    (actor, users[1].clone())
}

#[test]
fn sqlite_owner_account_metadata_is_bounded_and_rejects_corrupt_lookahead() {
    let mut store = fixture_store();
    store.migrate().unwrap();
    let (actor, other) = assert_owner_account_metadata_contract(&mut store);
    store
        .connection
        .execute(
            "UPDATE admin_accounts SET display_name=char(1) WHERE user_id=?1",
            [other.as_str()],
        )
        .unwrap();
    assert!(matches!(
        ListAdminAccountMetadata::execute(
            &store,
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
        GetAdminAccountMetadata::execute(&store, &actor, &FixtureOperation, &other),
        Err(AdminAccessError::Unavailable)
    );
}

fn assert_login_admission_contract<R: AdminIdentityRepository>(repository: &mut R) {
    let generator = FixtureGenerator::new();
    let owner = initialize_owner(repository, &generator);
    for _ in 0..8 {
        let login = LoginAdmin::execute(
            repository,
            &FixtureOperation,
            &FixturePasswords,
            &generator,
            LoginAdminInput {
                username: "FIXTURE_OWNER",
                password: CURRENT_PASSWORD,
            },
        )
        .unwrap();
        let credential = repository
            .credential_by_id(&login.session.id)
            .unwrap()
            .unwrap()
            .snapshot();
        let authenticated = AuthenticateAdminCredential::execute(
            repository,
            &FixtureOperation,
            AdminCredentialKind::WebSession,
            &credential.digest,
        )
        .unwrap();
        assert_eq!(authenticated.user_id(), &owner.id);
        assert_eq!(login.session.expires_at, 29_800);
    }
    assert_eq!(
        LoginAdmin::execute(
            repository,
            &FixtureOperation,
            &FixturePasswords,
            &generator,
            LoginAdminInput {
                username: "fixture_owner",
                password: CURRENT_PASSWORD
            }
        )
        .unwrap_err(),
        AdminAccessError::Limit
    );
    assert_eq!(
        repository
            .identity_transaction(|tx| tx.credential_counts(
                AdminCredentialKind::WebSession,
                &owner.id,
                1_000
            ))
            .unwrap(),
        AdminCredentialCounts {
            valid_for_user: 8,
            total_rows: 8
        }
    );
    assert!(
        repository
            .credential_by_id(&AdminCredentialId::parse(format!("crd_{:032x}", 9)).unwrap())
            .unwrap()
            .is_none()
    );
}

fn assert_personal_token_metadata_contract<R: AdminIdentityRepository + AdminPersonalTokenQuery>(
    repository: &mut R,
) -> AdminCredentialId {
    let generator = FixtureGenerator::new();
    let owner = initialize_owner(repository, &generator);
    let actor = seed_credential(repository, &owner.id, 0x90, AdminCredentialKind::WebSession);
    let mut ids = Vec::new();
    for _ in 0..4 {
        let token = CreateAdminPersonalToken::execute(
            repository,
            &actor,
            &FixtureOperation,
            &FixturePasswords,
            &generator,
            CreateAdminPersonalTokenInput {
                current_password: CURRENT_PASSWORD,
                label: Some(AdminTokenLabel::parse("한글 CLI").unwrap()),
            },
        )
        .unwrap();
        let row = repository
            .credential_by_id(&token.id)
            .unwrap()
            .unwrap()
            .snapshot();
        assert_eq!(row.label.as_ref().unwrap().as_str(), "한글 CLI");
        AuthenticateAdminCredential::execute(
            repository,
            &FixtureOperation,
            AdminCredentialKind::PersonalToken,
            &row.digest,
        )
        .unwrap();
        ids.push(token.id);
    }
    let mut other = AdminAccount::pending(
        generator.user_id().unwrap(),
        AdminUsername::parse("other.user").unwrap(),
        AdminDisplayName::parse("Other user").unwrap(),
        AdminRole::Viewer,
    );
    other
        .install_password(
            FixturePasswords
                .hash_new(CURRENT_PASSWORD, &other.snapshot().username)
                .unwrap(),
        )
        .unwrap();
    repository
        .identity_transaction(|tx| tx.insert_account(&other.snapshot()))
        .unwrap();
    let other_actor = seed_credential(
        repository,
        &other.snapshot().id,
        0x91,
        AdminCredentialKind::PersonalToken,
    );
    let first = ListOwnAdminPersonalTokens::execute(
        repository,
        &actor,
        &FixtureOperation,
        ListOwnAdminPersonalTokensInput {
            after: None,
            limit: AdminMetadataPageSize::new(2).unwrap(),
        },
    )
    .unwrap();
    assert_eq!(first.items.len(), 2);
    assert_eq!(first.items[0].id, ids[0]);
    assert!(
        first
            .items
            .iter()
            .all(|row| row.active && row.label.as_ref().unwrap().as_str() == "한글 CLI")
    );
    let next = ListOwnAdminPersonalTokens::execute(
        repository,
        &actor,
        &FixtureOperation,
        ListOwnAdminPersonalTokensInput {
            after: first.next_after.as_ref(),
            limit: AdminMetadataPageSize::new(2).unwrap(),
        },
    )
    .unwrap();
    assert_eq!(next.items.len(), 2);
    assert!(next.next_after.is_none());
    assert_eq!(next.items[0].id, ids[2]);
    let other_page = ListOwnAdminPersonalTokens::execute(
        repository,
        &other_actor,
        &FixtureOperation,
        ListOwnAdminPersonalTokensInput {
            after: None,
            limit: AdminMetadataPageSize::default(),
        },
    )
    .unwrap();
    assert_eq!(other_page.items.len(), 1);
    assert_eq!(&other_page.items[0].id, other_actor.credential_id());
    let before = repository
        .credential_by_id(&ids[0])
        .unwrap()
        .unwrap()
        .snapshot();
    let mut renamed = before.clone();
    renamed.label = Some(AdminTokenLabel::parse("cannot rename immutable metadata").unwrap());
    assert_eq!(
        repository.identity_transaction(|tx| tx.replace_credential(&before, &renamed)),
        Err(AdminAccessError::Conflict)
    );
    assert!(
        repository
            .credential_by_id(&ids[0])
            .unwrap()
            .unwrap()
            .snapshot()
            == before
    );
    for limit in [0, 102] {
        assert_eq!(
            repository
                .personal_token_page(&owner.id, None, limit)
                .unwrap_err(),
            AdminAccessError::InvalidRequest
        );
    }
    let revoked = repository
        .credential_by_id(&ids[1])
        .unwrap()
        .unwrap()
        .snapshot();
    RevokeOwnAdminPersonalToken::execute(repository, &actor, &FixtureOperation, &ids[1]).unwrap();
    assert!(repository.credential_by_id(&ids[1]).unwrap().is_none());
    assert_eq!(
        AuthenticateAdminCredential::execute(
            repository,
            &FixtureOperation,
            AdminCredentialKind::PersonalToken,
            &revoked.digest
        )
        .unwrap_err(),
        AdminAccessError::Unauthorized
    );
    let cookie = repository
        .credential_by_id(actor.credential_id())
        .unwrap()
        .unwrap()
        .snapshot();
    LogoutAdminSession::execute(repository, &actor, &FixtureOperation).unwrap();
    assert!(
        repository
            .credential_by_id(actor.credential_id())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        AuthenticateAdminCredential::execute(
            repository,
            &FixtureOperation,
            AdminCredentialKind::WebSession,
            &cookie.digest
        )
        .unwrap_err(),
        AdminAccessError::Unauthorized
    );
    let retained = repository
        .credential_by_id(&ids[0])
        .unwrap()
        .unwrap()
        .snapshot();
    let pat_actor = AuthenticateAdminCredential::execute(
        repository,
        &FixtureOperation,
        AdminCredentialKind::PersonalToken,
        &retained.digest,
    )
    .unwrap();
    let remaining = ListOwnAdminPersonalTokens::execute(
        repository,
        &pat_actor,
        &FixtureOperation,
        ListOwnAdminPersonalTokensInput {
            after: None,
            limit: AdminMetadataPageSize::default(),
        },
    )
    .unwrap();
    assert_eq!(remaining.items.len(), 3);
    assert_eq!(
        LogoutAdminSession::execute(repository, &pat_actor, &FixtureOperation),
        Err(AdminAccessError::Forbidden)
    );
    assert_eq!(
        RevokeOwnAdminPersonalToken::execute(repository, &other_actor, &FixtureOperation, &ids[0]),
        Err(AdminAccessError::NotFound)
    );
    ids.remove(0)
}

#[test]
fn sqlite_personal_token_labels_and_scoped_metadata_roundtrip_and_malformed_labels_fail_closed() {
    let mut store = fixture_store();
    store.migrate().unwrap();
    let before = legacy_snapshot(&store);
    let id = assert_personal_token_metadata_contract(&mut store);
    let after = legacy_snapshot(&store);
    assert_eq!(
        after["audit_events"].len(),
        before["audit_events"].len() + 7
    );
    for (table, rows) in before {
        assert!(
            rows.iter().all(|row| after[&table].contains(row)),
            "prior {table} changed"
        );
    }
    let valid = store.credential_by_id(&id).unwrap().unwrap().snapshot();
    let actor = AuthenticateAdminCredential::execute(
        &store,
        &FixtureOperation,
        AdminCredentialKind::PersonalToken,
        &valid.digest,
    )
    .unwrap();
    let foreign = AdminCredentialId::parse(format!("crd_{:032x}", 0x91)).unwrap();
    assert_eq!(
        store
            .connection
            .execute(
                "UPDATE admin_credentials SET label=? WHERE credential_id=?",
                ["synthetic-label\n", foreign.as_str()]
            )
            .unwrap(),
        1
    );
    assert_eq!(
        store.credential_by_id(&foreign).unwrap_err(),
        AdminAccessError::Unavailable
    );
    assert_eq!(
        RevokeOwnAdminPersonalToken::execute(&mut store, &actor, &FixtureOperation, &foreign),
        Err(AdminAccessError::NotFound)
    );
    store
        .connection
        .execute(
            "UPDATE admin_credentials SET label=? WHERE credential_id=?",
            ["synthetic-label\n", id.as_str()],
        )
        .unwrap();
    let error = store.credential_by_id(&id).unwrap_err();
    assert_eq!(error, AdminAccessError::Unavailable);
    assert!(!format!("{error:?} {error}").contains("synthetic-label"));
}

fn prepare_seven_sessions<R: AdminIdentityRepository>(repository: &mut R) -> AdminUserId {
    let generator = FixtureGenerator::new();
    let owner = initialize_owner(repository, &generator);
    for _ in 0..7 {
        LoginAdmin::execute(
            repository,
            &FixtureOperation,
            &FixturePasswords,
            &generator,
            LoginAdminInput {
                username: "fixture_owner",
                password: CURRENT_PASSWORD,
            },
        )
        .unwrap();
    }
    owner.id
}

fn racing_session<R: AdminIdentityRepository>(
    repository: &mut R,
    gate: Rendezvous,
    slot: u128,
) -> Result<AdminLogin, AdminAccessError> {
    let generator = FixtureGenerator {
        users: Cell::new(0),
        credentials: Cell::new(100 + slot),
    };
    LoginAdmin::execute(
        repository,
        &FixtureOperation,
        &RacingPasswords {
            gate,
            at: RendezvousAt::Verify,
        },
        &generator,
        LoginAdminInput {
            username: "fixture_owner",
            password: CURRENT_PASSWORD,
        },
    )
}

fn prepare_fifteen_personal_tokens<R: AdminIdentityRepository>(
    repository: &mut R,
) -> (AdminUserId, AuthenticatedAdmin) {
    let generator = FixtureGenerator::new();
    let owner = initialize_owner(repository, &generator);
    let actor = seed_credential(repository, &owner.id, 0xc1, AdminCredentialKind::WebSession);
    for _ in 0..15 {
        CreateAdminPersonalToken::execute(
            repository,
            &actor,
            &FixtureOperation,
            &FixturePasswords,
            &generator,
            CreateAdminPersonalTokenInput {
                current_password: CURRENT_PASSWORD,
                label: None,
            },
        )
        .unwrap();
    }
    (owner.id, actor)
}

fn racing_personal_token<R: AdminIdentityRepository>(
    repository: &mut R,
    actor: &AuthenticatedAdmin,
    gate: Rendezvous,
    slot: u128,
) -> Result<IssuedAdminCredential, AdminAccessError> {
    CreateAdminPersonalToken::execute(
        repository,
        actor,
        &FixtureOperation,
        &RacingPasswords {
            gate,
            at: RendezvousAt::Verify,
        },
        &FixtureGenerator {
            users: Cell::new(0),
            credentials: Cell::new(100 + slot),
        },
        CreateAdminPersonalTokenInput {
            current_password: CURRENT_PASSWORD,
            label: None,
        },
    )
}

#[test]
fn sqlite_concurrent_sixteenth_personal_tokens_admit_exactly_one() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("identity.sqlite3");
    let mut repository = SqliteStore::open(&database).unwrap();
    let (owner, actor) = prepare_fifteen_personal_tokens(&mut repository);
    let peers = [
        SqliteStore::open(&database).unwrap(),
        SqliteStore::open(&database).unwrap(),
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
        repository
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
        repository
            .connection
            .query_row(
                "SELECT count(*) FROM audit_events WHERE action='admin_personal_token_created'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        16
    );
}

fn prepare_self_auth_fault<R: AdminIdentityRepository>(
    repository: &mut R,
) -> (AuthenticatedAdmin, AdminCredentialId) {
    let generator = FixtureGenerator::new();
    let owner = initialize_owner(repository, &generator);
    let actor = seed_credential(repository, &owner.id, 0xb1, AdminCredentialKind::WebSession);
    let token = seed_credential(
        repository,
        &owner.id,
        0xb2,
        AdminCredentialKind::PersonalToken,
    );
    let retired = seed_credential(
        repository,
        &owner.id,
        0xb3,
        AdminCredentialKind::PersonalToken,
    );
    repository
        .identity_transaction(|tx| {
            let mut credential = tx.credential_by_id(retired.credential_id())?.unwrap();
            let before = credential.snapshot();
            credential.revoke(1_000).unwrap();
            tx.replace_credential(&before, &credential.snapshot())
        })
        .unwrap();
    (actor, token.credential_id().clone())
}

#[test]
fn sqlite_self_auth_audit_failure_rolls_back_revoke_logout_and_retired_cleanup() {
    let mut store = fixture_store();
    store.migrate().unwrap();
    let (actor, id) = prepare_self_auth_fault(&mut store);
    store.connection.execute_batch("CREATE TRIGGER fail_self_auth_audit BEFORE INSERT ON audit_events WHEN NEW.action IN ('admin_session_logged_out','admin_personal_token_revoked') BEGIN SELECT RAISE(ABORT,'owned self-auth audit fault'); END;").unwrap();
    let before = table_snapshot(
        &store,
        &[
            "admin_auth_state",
            "admin_accounts",
            "admin_credentials",
            "audit_events",
        ],
    );
    for logout in [true, false] {
        let result = if logout {
            LogoutAdminSession::execute(&mut store, &actor, &FixtureOperation)
        } else {
            RevokeOwnAdminPersonalToken::execute(&mut store, &actor, &FixtureOperation, &id)
        };
        assert_eq!(result, Err(AdminAccessError::Unavailable));
        assert!(
            table_snapshot(
                &store,
                &[
                    "admin_auth_state",
                    "admin_accounts",
                    "admin_credentials",
                    "audit_events"
                ]
            ) == before
        );
        authenticate(&store, 0xb1, AdminCredentialKind::WebSession).unwrap();
        authenticate(&store, 0xb2, AdminCredentialKind::PersonalToken).unwrap();
    }
}

#[test]
fn sqlite_concurrent_eighth_sessions_admit_exactly_one_at_the_canonical_transaction() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("identity.sqlite3");
    let mut repository = SqliteStore::open(&database).unwrap();
    let owner = prepare_seven_sessions(&mut repository);
    let peers = [
        SqliteStore::open(&database).unwrap(),
        SqliteStore::open(&database).unwrap(),
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
        repository
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
        repository
            .connection
            .query_row(
                "SELECT count(*) FROM audit_events WHERE action='admin_session_created'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        8
    );
}

fn assert_bounded_lookup_cleanup_contract<R: AdminIdentityRepository>(repository: &mut R) {
    let generator = FixtureGenerator::new();
    let owner = initialize_owner(repository, &generator);
    let before = repository.account_by_id(&owner.id).unwrap().unwrap();
    let pending = AdminAccount::pending(
        AdminUserId::parse(format!("usr_{:032x}", 2)).unwrap(),
        AdminUsername::parse("pending_fixture").unwrap(),
        AdminDisplayName::parse("Pending fixture").unwrap(),
        AdminRole::Viewer,
    );
    let state = repository.auth_state().unwrap();
    let mut stale = *state.epoch.bytes();
    stale[0] ^= 0xff;
    let kinds = [
        AdminCredentialKind::WebSession,
        AdminCredentialKind::PersonalToken,
        AdminCredentialKind::SetupGrant,
        AdminCredentialKind::ResetGrant,
    ];
    repository
        .identity_transaction(|tx| {
            tx.insert_account(&pending.snapshot())?;
            for (fresh, ordinals) in [(false, 0_u128..130), (true, 130_u128..132)] {
                if fresh {
                    // Insert current credentials first, then make them stale through the same
                    // validated epoch transition used by restore. Never weaken insert guards.
                    tx.set_auth_state(
                        state,
                        AdminAuthState {
                            mode: state.mode,
                            epoch: HumanAuthEpoch::from_bytes(stale),
                        },
                    )?;
                }
                for (index, kind) in kinds.into_iter().enumerate() {
                    let account = if kind.is_grant() { &pending } else { &before };
                    for ordinal in ordinals.clone() {
                        let value = (index as u128 + 1) * 1_000 + ordinal;
                        let mut digest = [0; 32];
                        digest[..16].copy_from_slice(&value.to_be_bytes());
                        let binding = AdminCredentialBinding::for_account(
                            account,
                            if fresh {
                                HumanAuthEpoch::from_bytes(stale)
                            } else {
                                state.epoch
                            },
                        );
                        let credential = AdminCredential::issue(
                            AdminCredentialId::parse(format!("crd_{value:032x}")).unwrap(),
                            kind,
                            AdminCredentialDigest::from_bytes(digest),
                            binding,
                            if ordinal == 131 { 3_000_100 } else { 2_999_900 },
                        )
                        .unwrap();
                        tx.insert_credential(&credential.snapshot())?;
                    }
                }
            }
            Ok(())
        })
        .unwrap();
    for kind in [
        AdminCredentialKind::WebSession,
        AdminCredentialKind::PersonalToken,
    ] {
        assert_eq!(
            repository
                .identity_transaction(|tx| tx.credential_counts(kind, &owner.id, 3_000_000))
                .unwrap(),
            AdminCredentialCounts {
                valid_for_user: 1,
                total_rows: 132
            }
        );
    }
    for (index, kind) in kinds.into_iter().enumerate() {
        for expected in [128, 2, 0] {
            assert_eq!(
                repository
                    .identity_transaction(|tx| tx.cleanup_retired_credentials(kind, 3_000_000, 128))
                    .unwrap(),
                expected
            );
        }
        for ordinal in [130_u128, 131] {
            let value = (index as u128 + 1) * 1_000 + ordinal;
            assert!(
                repository
                    .credential_by_id(
                        &AdminCredentialId::parse(format!("crd_{value:032x}")).unwrap()
                    )
                    .unwrap()
                    .is_some()
            );
        }
    }
    for kind in [
        AdminCredentialKind::WebSession,
        AdminCredentialKind::PersonalToken,
    ] {
        assert_eq!(
            repository
                .identity_transaction(|tx| tx.credential_counts(kind, &owner.id, 3_000_000))
                .unwrap(),
            AdminCredentialCounts {
                valid_for_user: 1,
                total_rows: 2
            }
        );
    }
    for limit in [0, 129] {
        assert_eq!(
            repository.identity_transaction(|tx| tx.cleanup_retired_credentials(
                AdminCredentialKind::WebSession,
                3_000_000,
                limit
            )),
            Err(AdminAccessError::InvalidRequest)
        );
    }
    assert_eq!(
        repository.identity_transaction(|tx| tx.cleanup_retired_credentials(
            AdminCredentialKind::WebSession,
            -1,
            128
        )),
        Err(AdminAccessError::InvalidRequest)
    );
    assert!(
        repository
            .account_by_id(&owner.id)
            .unwrap()
            .unwrap()
            .snapshot()
            == before.snapshot()
    );
    assert!(
        repository
            .account_by_id(&pending.snapshot().id)
            .unwrap()
            .unwrap()
            .snapshot()
            == pending.snapshot()
    );
}

#[test]
fn sqlite_login_session_admission_serializes_counts_and_preserves_legacy_history() {
    let mut store = fixture_store();
    store.migrate().unwrap();
    let before = legacy_snapshot(&store);
    assert_login_admission_contract(&mut store);
    let after = legacy_snapshot(&store);
    for (table, rows) in before {
        assert!(
            rows.iter().all(|row| after[&table].contains(row)),
            "prior {table} changed"
        );
    }
}

#[test]
fn sqlite_lookup_cleanup_is_per_kind_bounded_and_preserves_accounts_and_audit() {
    let mut store = fixture_store();
    store.migrate().unwrap();
    let before = legacy_snapshot(&store);
    assert_bounded_lookup_cleanup_contract(&mut store);
    let after = legacy_snapshot(&store);
    for (table, rows) in before {
        if table == "audit_events" {
            assert_eq!(after[&table].len(), rows.len() + 1);
        }
        assert!(
            rows.iter().all(|row| after[&table].contains(row)),
            "prior {table} changed"
        );
    }
}

struct FixtureEpoch(HumanAuthEpoch);
impl HumanAuthEpochGenerator for FixtureEpoch {
    fn fresh_epoch(&self) -> Result<HumanAuthEpoch, AdminAccessError> {
        Ok(self.0)
    }
}

fn next_restore_epoch(repository: &impl AdminIdentityRead) -> FixtureEpoch {
    let mut bytes = *repository.auth_state().unwrap().epoch.bytes();
    bytes[0] ^= 0xff;
    FixtureEpoch(HumanAuthEpoch::from_bytes(bytes))
}

fn seed_restore_credentials<R: AdminIdentityRepository>(
    repository: &mut R,
) -> (Vec<AdminAccountSnapshot>, Vec<AdminCredentialSnapshot>) {
    let generator = FixtureGenerator::new();
    let owner = initialize_owner(repository, &generator);
    let actor = seed_credential(repository, &owner.id, 0xa1, AdminCredentialKind::WebSession);
    seed_credential(
        repository,
        &owner.id,
        0xa2,
        AdminCredentialKind::PersonalToken,
    );
    let mut pending = Vec::new();
    for username in ["setup_pending", "reset_pending"] {
        pending.push(
            CreateAdminAccount::execute(
                repository,
                &actor,
                &FixtureOperation,
                &FixturePasswords,
                &generator,
                CreateAdminAccountInput {
                    username: AdminUsername::parse(username).unwrap(),
                    display_name: AdminDisplayName::parse(username).unwrap(),
                    role: AdminRole::Operator,
                    current_password: CURRENT_PASSWORD,
                },
            )
            .unwrap(),
        );
    }
    let reset = ResetAdminPassword::execute(
        repository,
        &actor,
        &FixtureOperation,
        &FixturePasswords,
        &generator,
        ResetAdminPasswordInput {
            user_id: pending[1].account.id.clone(),
            current_password: CURRENT_PASSWORD,
        },
    )
    .unwrap();
    assert!(
        repository
            .credential_by_id(&pending[1].setup.id)
            .unwrap()
            .is_none()
    );
    let accounts = [
        owner.id,
        pending[0].account.id.clone(),
        pending[1].account.id.clone(),
    ]
    .iter()
    .map(|id| repository.account_by_id(id).unwrap().unwrap().snapshot())
    .collect();
    let credentials = [
        AdminCredentialId::parse(format!("crd_{:032x}", 0xa1)).unwrap(),
        AdminCredentialId::parse(format!("crd_{:032x}", 0xa2)).unwrap(),
        pending[0].setup.id.clone(),
        reset.id,
    ]
    .iter()
    .map(|id| repository.credential_by_id(id).unwrap().unwrap().snapshot())
    .collect();
    (accounts, credentials)
}

fn assert_restore_contract<R: AdminIdentityRepository>(repository: &mut R) {
    let (accounts, credentials) = seed_restore_credentials(repository);
    let before = repository.auth_state().unwrap();
    let valid: Vec<_> = credentials
        .iter()
        .filter(|value| value.state == AdminCredentialState::Active)
        .collect();
    assert_eq!(valid.len(), 4);
    for credential in &valid {
        let account = repository
            .account_by_id(&credential.binding.user_id)
            .unwrap()
            .unwrap();
        AdminCredential::from_snapshot((*credential).clone())
            .unwrap()
            .validate(credential.kind, before.mode, &account, before.epoch, 1_000)
            .unwrap();
    }
    let epoch = next_restore_epoch(repository);
    assert_eq!(
        InvalidateAdminCredentialsAfterRestore::execute(
            repository,
            &FixtureLocalAuthority,
            &FixtureOperation,
            &epoch
        )
        .unwrap(),
        AdminAuthMode::Personal
    );
    assert_eq!(
        repository.auth_state().unwrap(),
        AdminAuthState {
            mode: AdminAuthMode::Personal,
            epoch: epoch.0
        }
    );
    for account in accounts {
        assert_eq!(
            repository
                .account_by_id(&account.id)
                .unwrap()
                .unwrap()
                .snapshot(),
            account
        );
    }
    for credential in &credentials {
        assert_eq!(
            repository
                .credential_by_id(&credential.id)
                .unwrap()
                .unwrap()
                .snapshot(),
            *credential
        );
    }
    for credential in valid {
        if credential.kind.is_grant() {
            assert_eq!(
                CompleteAdminSetup::execute(
                    repository,
                    &FixtureOperation,
                    &FixturePasswords,
                    CompleteAdminSetupInput {
                        kind: credential.kind,
                        digest: credential.digest.clone(),
                        new_password: CURRENT_PASSWORD
                    }
                )
                .unwrap_err(),
                AdminAccessError::Unauthorized
            );
        } else {
            assert_eq!(
                AuthenticateAdminCredential::execute(
                    repository,
                    &FixtureOperation,
                    credential.kind,
                    &credential.digest
                )
                .unwrap_err(),
                AdminAccessError::Unauthorized
            );
        }
    }
}

#[test]
fn sqlite_restored_human_epoch_invalidates_credentials_and_preserves_nonhuman_history() {
    let mut store = fixture_store();
    store.migrate().unwrap();
    let before = legacy_snapshot(&store);
    assert_restore_contract(&mut store);
    let after = legacy_snapshot(&store);
    for (table, rows) in before {
        if table == "audit_events" {
            assert_eq!(after[&table][..rows.len()], rows);
        } else {
            assert_eq!(after[&table], rows);
        }
    }
}

#[test]
fn sqlite_restore_epoch_audit_fault_keeps_old_credentials_and_all_identity_rows() {
    let mut store = fixture_store();
    store.migrate().unwrap();
    seed_restore_credentials(&mut store);
    let tables = [
        "admin_auth_state",
        "admin_accounts",
        "admin_credentials",
        "audit_events",
        "agents",
        "agent_identities",
        "controller_delivery_identity",
    ];
    let before = table_snapshot(&store, &tables);
    let epoch = next_restore_epoch(&store);
    store.connection.execute_batch("CREATE TRIGGER reject_restore_audit BEFORE INSERT ON audit_events WHEN NEW.action='admin_credentials_invalidated_after_restore' BEGIN SELECT RAISE(ABORT,'synthetic restore audit fault'); END;").unwrap();
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
    assert_eq!(table_snapshot(&store, &tables), before);
    authenticate(&store, 0xa1, AdminCredentialKind::WebSession).unwrap();
    authenticate(&store, 0xa2, AdminCredentialKind::PersonalToken).unwrap();
}

#[test]
fn sqlite_legacy_restore_never_reactivates_shared_token_or_changes_agent_delivery_epoch() {
    let mut store = fixture_store();
    store.migrate().unwrap();
    let hash: String = store
        .connection
        .query_row(
            "SELECT token_hash FROM admin_tokens WHERE id=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(store.verify_admin_token_hash(&hash).unwrap());
    let before = legacy_snapshot(&store);
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
    assert!(!store.verify_admin_token_hash(&hash).unwrap());
    assert!(store.admin_token_exists().unwrap());
    assert!(store.find_admin_token_record(&hash).unwrap().is_none());
    let after = legacy_snapshot(&store);
    for (table, rows) in before {
        if table == "audit_events" {
            assert_eq!(after[&table][..rows.len()], rows);
        } else {
            assert_eq!(after[&table], rows);
        }
    }
}

fn assert_application_contract<R: AdminIdentityRepository>(
    repository: &mut R,
    generator: &FixtureGenerator,
) -> (AdminUserId, AdminUserId) {
    let epoch = repository.auth_state().unwrap().epoch;
    let owner = initialize_owner(repository, generator);
    let owner_actor = seed_credential(repository, &owner.id, 0xa1, AdminCredentialKind::WebSession);
    let created = CreateAdminAccount::execute(
        repository,
        &owner_actor,
        &FixtureOperation,
        &FixturePasswords,
        generator,
        CreateAdminAccountInput {
            username: AdminUsername::parse("fixture_viewer").unwrap(),
            display_name: AdminDisplayName::parse("Fixture viewer").unwrap(),
            role: AdminRole::Viewer,
            current_password: CURRENT_PASSWORD,
        },
    )
    .unwrap();
    assert_eq!(created.account.status, AdminAccountStatus::PendingSetup);
    let grant = repository
        .credential_by_id(&created.setup.id)
        .unwrap()
        .unwrap()
        .snapshot();
    CompleteAdminSetup::execute(
        repository,
        &FixtureOperation,
        &FixturePasswords,
        CompleteAdminSetupInput {
            kind: grant.kind,
            digest: grant.digest.clone(),
            new_password: CURRENT_PASSWORD,
        },
    )
    .unwrap();
    assert!(repository.credential_by_id(&grant.id).unwrap().is_none());
    assert_eq!(
        CompleteAdminSetup::execute(
            repository,
            &FixtureOperation,
            &FixturePasswords,
            CompleteAdminSetupInput {
                kind: grant.kind,
                digest: grant.digest,
                new_password: CURRENT_PASSWORD,
            }
        ),
        Err(AdminAccessError::Unauthorized)
    );
    let user = created.account.id;
    let viewer = seed_credential(repository, &user, 0xa2, AdminCredentialKind::PersonalToken);
    seed_credential(repository, &user, 0xa3, AdminCredentialKind::WebSession);
    assert_eq!(
        CreateAdminAccount::execute(
            repository,
            &viewer,
            &FixtureOperation,
            &FixturePasswords,
            generator,
            CreateAdminAccountInput {
                username: AdminUsername::parse("forbidden_user").unwrap(),
                display_name: AdminDisplayName::parse("Forbidden fixture").unwrap(),
                role: AdminRole::Owner,
                current_password: CURRENT_PASSWORD,
            }
        )
        .unwrap_err(),
        AdminAccessError::Forbidden
    );
    ChangeAdminAccount::execute(
        repository,
        &owner_actor,
        &FixtureOperation,
        &FixturePasswords,
        ChangeAdminAccountInput {
            user_id: user.clone(),
            display_name: Some(AdminDisplayName::parse("운영자 이름 변경").unwrap()),
            role: None,
            disable: false,
            current_password: CURRENT_PASSWORD,
        },
    )
    .unwrap();
    assert!(authenticate(repository, 0xa2, AdminCredentialKind::PersonalToken).is_ok());
    ChangeAdminAccount::execute(
        repository,
        &owner_actor,
        &FixtureOperation,
        &FixturePasswords,
        ChangeAdminAccountInput {
            user_id: user.clone(),
            display_name: None,
            role: Some(AdminRole::Operator),
            disable: false,
            current_password: CURRENT_PASSWORD,
        },
    )
    .unwrap();
    assert_eq!(
        authenticate(repository, 0xa2, AdminCredentialKind::PersonalToken).unwrap_err(),
        AdminAccessError::Unauthorized
    );
    assert_eq!(
        authenticate(repository, 0xa3, AdminCredentialKind::WebSession).unwrap_err(),
        AdminAccessError::Unauthorized
    );
    let operator = seed_credential(repository, &user, 0xa4, AdminCredentialKind::PersonalToken);
    ChangeOwnAdminPassword::execute(
        repository,
        &operator,
        &FixtureOperation,
        &FixturePasswords,
        ChangeOwnAdminPasswordInput {
            current_password: CURRENT_PASSWORD,
            new_password: "new fixture passphrase",
        },
    )
    .unwrap();
    assert_eq!(
        authenticate(repository, 0xa4, AdminCredentialKind::PersonalToken).unwrap_err(),
        AdminAccessError::Unauthorized
    );
    let reset = ResetAdminPassword::execute(
        repository,
        &owner_actor,
        &FixtureOperation,
        &FixturePasswords,
        generator,
        ResetAdminPasswordInput {
            user_id: user.clone(),
            current_password: CURRENT_PASSWORD,
        },
    )
    .unwrap();
    assert_eq!(
        repository
            .account_by_id(&user)
            .unwrap()
            .unwrap()
            .snapshot()
            .status,
        AdminAccountStatus::PendingSetup
    );
    let reset = repository
        .credential_by_id(&reset.id)
        .unwrap()
        .unwrap()
        .snapshot();
    CompleteAdminSetup::execute(
        repository,
        &FixtureOperation,
        &FixturePasswords,
        CompleteAdminSetupInput {
            kind: reset.kind,
            digest: reset.digest,
            new_password: "reset fixture passphrase",
        },
    )
    .unwrap();
    let account = repository.account_by_id(&user).unwrap().unwrap().snapshot();
    assert_eq!(account.status, AdminAccountStatus::Active);
    assert_eq!(account.role, AdminRole::Operator);
    assert_eq!(account.credential_revision.value(), 5);
    assert_eq!(repository.auth_state().unwrap().epoch, epoch);
    assert_eq!(
        authenticate(repository, 0xa1, AdminCredentialKind::WebSession)
            .unwrap()
            .user_id(),
        &owner.id
    );
    (owner.id, user)
}

#[test]
fn sqlite_application_contract_preserves_legacy_rows_and_records_person_actors() {
    let mut store = fixture_store();
    store.migrate().unwrap();
    let before = legacy_snapshot(&store);
    let (owner, user) = assert_application_contract(&mut store, &FixtureGenerator::new());
    let after = legacy_snapshot(&store);
    for (table, rows) in before {
        if table != "audit_events" {
            assert_eq!(after[&table], rows);
        }
    }
    let events = store.list_audit_events(100).unwrap();
    assert_eq!(
        events
            .iter()
            .find(|event| event.action == "admin_password_changed")
            .unwrap()
            .actor
            .as_str(),
        user.as_str()
    );
    assert_eq!(
        events
            .iter()
            .find(|event| event.action == "admin_password_reset_requested")
            .unwrap()
            .actor
            .as_str(),
        owner.as_str()
    );
    assert!(
        events
            .iter()
            .filter(|event| event.action.starts_with("admin_"))
            .all(|event| event.value == AuditValue::Redacted)
    );
}

#[test]
fn sqlite_application_reset_audit_fault_rolls_back_all_identity_rows() {
    let mut store = SqliteStore::in_memory().unwrap();
    let generator = FixtureGenerator::new();
    let (_, user) = assert_application_contract(&mut store, &generator);
    let actor = authenticate(&store, 0xa1, AdminCredentialKind::WebSession).unwrap();
    let before = table_snapshot(
        &store,
        &[
            "admin_auth_state",
            "admin_accounts",
            "admin_credentials",
            "audit_events",
        ],
    );
    store.connection.execute_batch("CREATE TRIGGER reject_reset_audit BEFORE INSERT ON audit_events WHEN NEW.action='admin_password_reset_requested' BEGIN SELECT RAISE(ABORT,'synthetic reset audit fault'); END;").unwrap();
    assert_eq!(
        ResetAdminPassword::execute(
            &mut store,
            &actor,
            &FixtureOperation,
            &FixturePasswords,
            &generator,
            ResetAdminPasswordInput {
                user_id: user,
                current_password: CURRENT_PASSWORD,
            }
        )
        .unwrap_err(),
        AdminAccessError::Unavailable
    );
    assert_eq!(
        table_snapshot(
            &store,
            &[
                "admin_auth_state",
                "admin_accounts",
                "admin_credentials",
                "audit_events"
            ]
        ),
        before
    );
}

#[derive(Clone)]
struct Rendezvous(std::sync::Arc<(std::sync::Mutex<usize>, std::sync::Condvar)>);
impl Rendezvous {
    fn new() -> Self {
        Self(std::sync::Arc::new((
            std::sync::Mutex::new(0),
            std::sync::Condvar::new(),
        )))
    }
    fn arrive(&self) -> Result<(), AdminAccessError> {
        let (lock, condition) = &*self.0;
        let mut count = lock.lock().map_err(|_| AdminAccessError::Unavailable)?;
        *count += 1;
        condition.notify_all();
        let (count, _) = condition
            .wait_timeout_while(count, std::time::Duration::from_secs(3), |count| *count < 2)
            .map_err(|_| AdminAccessError::Unavailable)?;
        if *count < 2 {
            Err(AdminAccessError::Unavailable)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy)]
enum RendezvousAt {
    Hash,
    Verify,
}
struct RacingPasswords {
    gate: Rendezvous,
    at: RendezvousAt,
}
impl AdminPasswordPort for RacingPasswords {
    fn hash_new(
        &self,
        input: &str,
        username: &AdminUsername,
    ) -> Result<AdminPasswordVerifier, AdminAccessError> {
        if matches!(self.at, RendezvousAt::Hash) {
            self.gate.arrive()?;
        }
        FixturePasswords.hash_new(input, username)
    }
    fn verify(
        &self,
        input: &str,
        verifier: Option<&AdminPasswordVerifier>,
    ) -> Result<bool, AdminAccessError> {
        if matches!(self.at, RendezvousAt::Verify) {
            self.gate.arrive()?;
        }
        FixturePasswords.verify(input, verifier)
    }
}

fn second_owner<R: AdminIdentityRepository>(store: &mut R) -> AdminUserId {
    let mut account = AdminAccount::pending(
        AdminUserId::parse("usr_00000000000000000000000000000002").unwrap(),
        AdminUsername::parse("second_owner").unwrap(),
        AdminDisplayName::parse("Second owner").unwrap(),
        AdminRole::Owner,
    );
    account
        .install_password(
            FixturePasswords
                .hash_new(CURRENT_PASSWORD, &account.snapshot().username)
                .unwrap(),
        )
        .unwrap();
    store
        .identity_transaction(|tx| tx.insert_account(&account.snapshot()))
        .unwrap();
    account.snapshot().id
}

#[test]
fn sqlite_concurrent_owners_cannot_both_demote_themselves() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("identity.sqlite3");
    let mut store = SqliteStore::open(&database).unwrap();
    let first = super::commit_owner(&mut store).unwrap().snapshot().id;
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
                let database = database.clone();
                let gate = gate.clone();
                scope.spawn(move || {
                    let mut repository = SqliteStore::open(database).unwrap();
                    let target = actor.user_id().clone();
                    ChangeAdminAccount::execute(
                        &mut repository,
                        &actor,
                        &FixtureOperation,
                        &RacingPasswords {
                            gate,
                            at: RendezvousAt::Verify,
                        },
                        ChangeAdminAccountInput {
                            user_id: target,
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
    assert_eq!(
        store
            .list_audit_events(100)
            .unwrap()
            .iter()
            .filter(|event| event.action == "admin_account_updated")
            .count(),
        1
    );
}

#[test]
fn sqlite_concurrent_setup_claims_commit_one_password_and_one_audit() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("identity.sqlite3");
    let mut store = SqliteStore::open(&database).unwrap();
    let owner = super::commit_owner(&mut store).unwrap().snapshot().id;
    let actor = seed_credential(&mut store, &owner, 0xb1, AdminCredentialKind::WebSession);
    let generator = FixtureGenerator {
        users: Cell::new(1),
        credentials: Cell::new(0),
    };
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
                let database = database.clone();
                let gate = gate.clone();
                let grant = grant.clone();
                scope.spawn(move || {
                    let mut repository = SqliteStore::open(database).unwrap();
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
    let account = store
        .account_by_id(&created.account.id)
        .unwrap()
        .unwrap()
        .snapshot();
    assert_eq!(account.status, AdminAccountStatus::Active);
    assert_eq!(account.record_revision.value(), 1);
    assert_eq!(account.credential_revision.value(), 1);
    assert!(store.credential_by_id(&grant.id).unwrap().is_none());
    assert_eq!(
        store
            .list_audit_events(100)
            .unwrap()
            .iter()
            .filter(|event| event.action == "admin_password_setup_completed")
            .count(),
        1
    );
}

struct HeldPassword {
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
}
impl AdminPasswordPort for HeldPassword {
    fn hash_new(
        &self,
        input: &str,
        username: &AdminUsername,
    ) -> Result<AdminPasswordVerifier, AdminAccessError> {
        FixturePasswords.hash_new(input, username)
    }
    fn verify(
        &self,
        input: &str,
        verifier: Option<&AdminPasswordVerifier>,
    ) -> Result<bool, AdminAccessError> {
        self.entered
            .try_send(())
            .map_err(|_| AdminAccessError::Unavailable)?;
        self.release
            .recv_timeout(std::time::Duration::from_secs(3))
            .map_err(|_| AdminAccessError::Unavailable)?;
        FixturePasswords.verify(input, verifier)
    }
}

#[test]
fn sqlite_role_revocation_while_password_verifies_blocks_the_later_account_creation() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("identity.sqlite3");
    let mut store = SqliteStore::open(&database).unwrap();
    let first = super::commit_owner(&mut store).unwrap().snapshot().id;
    let second = second_owner(&mut store);
    let first_actor = seed_credential(&mut store, &first, 0xb1, AdminCredentialKind::WebSession);
    let second_actor = seed_credential(&mut store, &second, 0xb2, AdminCredentialKind::WebSession);
    let (entered, started) = std::sync::mpsc::sync_channel(1);
    let (release, resume) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let handle = scope.spawn(move || {
            let mut repository = SqliteStore::open(database).unwrap();
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
        store
            .connection
            .query_row("SELECT COUNT(*) FROM admin_credentials", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    authenticate(&store, 0xb1, AdminCredentialKind::WebSession).unwrap();
    assert_eq!(
        authenticate(&store, 0xb2, AdminCredentialKind::WebSession).unwrap_err(),
        AdminAccessError::Unauthorized
    );
    assert!(
        store
            .list_audit_events(100)
            .unwrap()
            .iter()
            .all(|event| event.action != "admin_account_created")
    );
}

#[test]
fn sqlite_concurrent_first_owners_have_one_atomic_cutover() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("identity.sqlite3");
    let store = SqliteStore::open(&database).unwrap();
    let legacy_hash = "b".repeat(64);
    store.insert_admin_token_hash(&legacy_hash).unwrap();
    let epoch = store.auth_state().unwrap().epoch;
    let gate = Rendezvous::new();
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2u128)
            .map(|index| {
                let database = database.clone();
                let gate = gate.clone();
                scope.spawn(move || {
                    let mut repository = SqliteStore::open(database).unwrap();
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
    assert_eq!(store.auth_state().unwrap().mode, AdminAuthMode::Personal);
    assert_eq!(store.auth_state().unwrap().epoch, epoch);
    assert_eq!(store.loginable_owner_count().unwrap(), 1);
    assert_eq!(
        store
            .connection
            .query_row("SELECT COUNT(*) FROM admin_accounts", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(!store.verify_admin_token_hash(&legacy_hash).unwrap());
    assert_eq!(
        store
            .list_audit_events(100)
            .unwrap()
            .iter()
            .filter(|event| event.action == "admin_owner_initialized")
            .count(),
        1
    );
}

#[cfg(all(feature = "postgres", unix))]
#[path = "admin_identity_postgres_tests.rs"]
mod postgres;
