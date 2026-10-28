//! Conditional, atomic persistence for Application-prepared catalog Job creation.

use crate::*;
use fleet_application::catalog_execution::CatalogRunbookJobQueryRepository;
use fleet_application::{
    CatalogJobSelectorSnapshot, CatalogRunbookJobCreation, CatalogRunbookJobCreationOutcome,
    CatalogRunbookJobCreationRepository,
};

fn catalog_job_provenance_from_columns(
    source: String,
    commit: String,
    path: String,
    checksum: String,
) -> Result<fleet_domain::CatalogRunbookProvenance, StoreError> {
    let document = CatalogDocument::new(
        CatalogSourceId::new(source)
            .map_err(|_| StoreError::Domain("invalid stored catalog provenance".into()))?,
        CatalogCommitId::new(commit)
            .map_err(|_| StoreError::Domain("invalid stored catalog provenance".into()))?,
        CatalogDocumentKind::Runbook,
        path,
        checksum,
    )
    .map_err(|_| StoreError::Domain("invalid stored catalog provenance".into()))?;
    fleet_domain::CatalogRunbookProvenance::from_document(&document)
        .map_err(|_| StoreError::Domain("invalid stored catalog provenance".into()))
}

impl CatalogRunbookJobQueryRepository for SqliteStore {
    type Error = StoreError;
    fn find_catalog_runbook_job_provenance(
        &self,
        job_id: &JobId,
    ) -> Result<Option<fleet_domain::CatalogRunbookProvenance>, StoreError> {
        self.connection.query_row(
            "SELECT source_id, commit_id, path, checksum FROM job_catalog_runbook_provenance WHERE job_id=?1",
            [job_id.as_str()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional()?.map(|(s,c,p,h)| catalog_job_provenance_from_columns(s,c,p,h)).transpose()
    }
}

#[cfg(feature = "postgres")]
impl CatalogRunbookJobQueryRepository for PostgresStore {
    type Error = StoreError;
    fn find_catalog_runbook_job_provenance(
        &self,
        job_id: &JobId,
    ) -> Result<Option<fleet_domain::CatalogRunbookProvenance>, StoreError> {
        self.checkout_client()?.query_opt(
            "SELECT source_id,commit_id,path,checksum FROM job_catalog_runbook_provenance WHERE job_id=$1",
            &[&job_id.as_str()],
        ).map_err(|_| postgres_error("postgres catalog provenance lookup failed"))?
            .map(|row| catalog_job_provenance_from_columns(row.get(0),row.get(1),row.get(2),row.get(3))).transpose()
    }
}

fn selector_storage_snapshot(
    snapshot: &CatalogJobSelectorSnapshot,
) -> Result<(&'static str, String), StoreError> {
    let encode = |value: &serde_json::Value| {
        serde_json::to_string(value)
            .map_err(|_| StoreError::Domain("catalog selector snapshot encoding failed".to_owned()))
    };
    match snapshot {
        CatalogJobSelectorSnapshot::ExplicitIds(ids) => Ok((
            "explicit_ids",
            encode(&serde_json::json!(
                ids.iter().map(AgentId::as_str).collect::<Vec<_>>()
            ))?,
        )),
        CatalogJobSelectorSnapshot::Selector(selector) => Ok((
            "selector",
            match selector {
                fleet_domain::Selector::Agent(id) => format!("agent:{id}"),
                fleet_domain::Selector::Labels(labels) => labels
                    .iter()
                    .map(|label| format!("{}={}", label.key(), label.value()))
                    .collect::<Vec<_>>()
                    .join(","),
            },
        )),
        CatalogJobSelectorSnapshot::MatchLabels(labels) => {
            Ok(("matchLabels", encode(&serde_json::json!(labels))?))
        }
        CatalogJobSelectorSnapshot::Runbook(fleet_domain::Selector::Agent(id)) => {
            Ok(("runbook_selector", format!("agent:{id}")))
        }
        CatalogJobSelectorSnapshot::Runbook(fleet_domain::Selector::Labels(labels)) => {
            let labels = labels
                .iter()
                .map(|label| (label.key(), label.value()))
                .collect::<BTreeMap<_, _>>();
            Ok(("runbook_matchLabels", encode(&serde_json::json!(labels))?))
        }
    }
}

struct CatalogStorageSettings {
    selector_kind: &'static str,
    selector_source: String,
    timeout_ms: i64,
}
impl CatalogStorageSettings {
    fn prepare(creation: &CatalogRunbookJobCreation<'_>) -> Result<Self, StoreError> {
        let (selector_kind, selector_source) =
            selector_storage_snapshot(creation.selector_snapshot())?;
        let timeout_ms = i64::try_from(creation.job().timeout().as_millis()).map_err(|_| {
            StoreError::Domain("catalog job timeout exceeds database range".to_owned())
        })?;
        Ok(Self {
            selector_kind,
            selector_source,
            timeout_ms,
        })
    }
}

impl SqliteStore {
    fn persist_catalog_creation(
        &self,
        creation: &CatalogRunbookJobCreation<'_>,
        settings: &CatalogStorageSettings,
    ) -> Result<CatalogRunbookJobCreationOutcome, StoreError> {
        let job = creation.job();
        let provenance = creation.provenance();
        let selector_kind = settings.selector_kind;
        let selector_source = settings.selector_source.as_str();
        let timeout_ms = settings.timeout_ms;
        let exists = self
            .connection
            .query_row(
                "SELECT 1 FROM jobs WHERE id=?1",
                [job.id().as_str()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if exists {
            return Ok(CatalogRunbookJobCreationOutcome::DuplicateJob);
        }
        let current = self
            .connection
            .query_row(
                "SELECT 1 FROM catalog_sources s
                 JOIN catalog_revisions r ON r.source_id=s.id AND r.commit_id=s.active_revision
                 JOIN catalog_documents d ON d.source_id=r.source_id AND d.commit_id=r.commit_id
                 WHERE s.id=?1 AND s.active_revision=?2 AND r.state='ready' AND d.path=?3
                   AND d.kind='runbook' AND d.checksum=?4 AND d.body=?5",
                params![
                    provenance.source_id().as_str(),
                    provenance.commit().as_str(),
                    provenance.path(),
                    provenance.checksum(),
                    creation.task().runbook_document()
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !current {
            return Ok(CatalogRunbookJobCreationOutcome::SelectionChanged);
        }
        self.connection.execute(
            "INSERT INTO jobs (id,status,risk,approval_requirement,timeout_ms,runbook_document,
                    strategy_concurrency,strategy_max_failures,selector_kind,selector_source)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                job.id().as_str(),
                job_status_to_str(job.status()),
                task_risk_to_str(job.risk()),
                approval_requirement_to_str(job.approval_requirement()),
                timeout_ms,
                creation.task().runbook_document(),
                i64::from(creation.strategy().concurrency.get()),
                creation
                    .strategy()
                    .max_failures
                    .map(|value| i64::from(value.get())),
                selector_kind,
                selector_source
            ],
        )?;
        self.insert_catalog_job_provenance_and_assignments(
            job.id().as_str(),
            provenance,
            creation.assignments(),
        )?;
        if let Some(approval) = creation.approval_request() {
            SqliteStore::insert_approval_request(self, approval.clone())?;
        }
        for event in creation.audit_events() {
            self.insert_audit(event)?;
        }
        Ok(CatalogRunbookJobCreationOutcome::Saved)
    }
    /// Rechecks human authority and immutable catalog binding in the same transaction.
    pub fn commit_admin_catalog_job_record(
        &self,
        principal: &fleet_application::admin_identity::AdminMutationPrincipal,
        operation: &dyn fleet_application::admin_identity::AdminOperation,
        creation: CatalogRunbookJobCreation<'_>,
    ) -> Result<CatalogRunbookJobCreationOutcome, fleet_application::AdminJobCommitError<StoreError>>
    {
        use fleet_application::AdminJobCommitError as Error;
        let settings = CatalogStorageSettings::prepare(&creation).map_err(Error::Repository)?;
        let transaction = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .map_err(|error| Error::Repository(error.into()))?;
        creation
            .authorize(self, principal, operation)
            .map_err(Error::Authorization)?;
        let outcome = self
            .persist_catalog_creation(&creation, &settings)
            .map_err(Error::Repository)?;
        if outcome == CatalogRunbookJobCreationOutcome::Saved {
            creation
                .authorize(self, principal, operation)
                .map_err(Error::Authorization)?;
            transaction
                .commit()
                .map_err(|error| Error::Repository(error.into()))?;
        }
        Ok(outcome)
    }
}
impl CatalogRunbookJobCreationRepository for SqliteStore {
    fn commit_catalog_runbook_job(
        &mut self,
        creation: CatalogRunbookJobCreation<'_>,
    ) -> Result<CatalogRunbookJobCreationOutcome, StoreError> {
        let settings = CatalogStorageSettings::prepare(&creation)?;
        self.run_sqlite_transaction(|| self.persist_catalog_creation(&creation, &settings))
    }
}
impl fleet_application::AdminCatalogJobRepository for SqliteStore {
    fn commit_admin_catalog_job(
        &mut self,
        principal: &fleet_application::admin_identity::AdminMutationPrincipal,
        operation: &dyn fleet_application::admin_identity::AdminOperation,
        creation: CatalogRunbookJobCreation<'_>,
    ) -> Result<CatalogRunbookJobCreationOutcome, fleet_application::AdminJobCommitError<StoreError>>
    {
        self.commit_admin_catalog_job_record(principal, operation, creation)
    }
}

#[cfg(feature = "postgres")]
fn postgres_persist_catalog_creation(
    transaction: &mut ::postgres::Transaction<'_>,
    creation: &CatalogRunbookJobCreation<'_>,
    settings: &CatalogStorageSettings,
) -> Result<CatalogRunbookJobCreationOutcome, StoreError> {
    let job = creation.job();
    let provenance = creation.provenance();
    let selector_kind = settings.selector_kind;
    let selector_source = settings.selector_source.as_str();
    let timeout_ms = settings.timeout_ms;
    if transaction
        .query_opt("SELECT 1 FROM jobs WHERE id=$1", &[&job.id().as_str()])
        .map_err(|_| postgres_error("postgres catalog duplicate check failed"))?
        .is_some()
    {
        return Ok(CatalogRunbookJobCreationOutcome::DuplicateJob);
    }
    // Locks keep the checked source pointer and immutable document binding
    // stable until this transaction commits; no selector is resolved here.
    let current = transaction
        .query_opt(
            "SELECT s.id FROM catalog_sources s
             JOIN catalog_revisions r ON r.source_id=s.id AND r.commit_id=s.active_revision
             JOIN catalog_documents d ON d.source_id=r.source_id AND d.commit_id=r.commit_id
             WHERE s.id=$1 AND s.active_revision=$2 AND r.state='ready' AND d.path=$3
               AND d.kind='runbook' AND d.checksum=$4 AND d.body=$5
             FOR SHARE OF s,r,d",
            &[
                &provenance.source_id().as_str(),
                &provenance.commit().as_str(),
                &provenance.path(),
                &provenance.checksum(),
                &creation.task().runbook_document(),
            ],
        )
        .map_err(|_| postgres_error("postgres catalog binding check failed"))?;
    if current.is_none() {
        return Ok(CatalogRunbookJobCreationOutcome::SelectionChanged);
    }
    let inserted = transaction
        .execute(
            "INSERT INTO jobs (id,status,risk,approval_requirement,timeout_ms,runbook_document,
                 strategy_concurrency,strategy_max_failures,selector_kind,selector_source)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(id) DO NOTHING",
            &[
                &job.id().as_str(),
                &job_status_to_str(job.status()),
                &task_risk_to_str(job.risk()),
                &approval_requirement_to_str(job.approval_requirement()),
                &timeout_ms,
                &creation.task().runbook_document(),
                &i64::from(creation.strategy().concurrency.get()),
                &creation
                    .strategy()
                    .max_failures
                    .map(|value| i64::from(value.get())),
                &selector_kind,
                &selector_source,
            ],
        )
        .map_err(|error| {
            postgres_constraint_or_context(error, "postgres catalog job insert failed")
        })?;
    if inserted == 0 {
        return Ok(CatalogRunbookJobCreationOutcome::DuplicateJob);
    }
    transaction.execute(
            "INSERT INTO job_catalog_runbook_provenance(job_id,source_id,commit_id,path,checksum) VALUES($1,$2,$3,$4,$5)",
            &[&job.id().as_str(), &provenance.source_id().as_str(), &provenance.commit().as_str(), &provenance.path(), &provenance.checksum()],
        ).map_err(|error| postgres_constraint_or_context(error, "postgres catalog provenance insert failed"))?;
    for assignment in creation.assignments() {
        postgres_insert_task_assignment_in_transaction(transaction, assignment)?;
    }
    if let Some(approval) = creation.approval_request() {
        transaction.execute(
                "INSERT INTO approval_requests(id,job_id,requester,approver,reason,status,expires_at,created_at,decided_at)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                &[&approval.id, &approval.job_id, &approval.requester, &approval.approver, &approval.reason, &approval.status,
                  &system_time_to_unix_secs(approval.expires_at), &system_time_to_unix_secs(approval.created_at), &approval.decided_at.map(system_time_to_unix_secs)],
            ).map_err(|error| postgres_constraint_or_context(error, "postgres catalog approval insert failed"))?;
    }
    for event in creation.audit_events() {
        postgres_insert_audit_in_transaction(transaction, event)?;
    }

    Ok(CatalogRunbookJobCreationOutcome::Saved)
}
#[cfg(feature = "postgres")]
impl CatalogRunbookJobCreationRepository for PostgresStore {
    fn commit_catalog_runbook_job(
        &mut self,
        creation: CatalogRunbookJobCreation<'_>,
    ) -> Result<CatalogRunbookJobCreationOutcome, StoreError> {
        let settings = CatalogStorageSettings::prepare(&creation)?;
        let mut client = self.checkout_client()?;
        let mut transaction = client
            .transaction()
            .map_err(|_| postgres_error("postgres catalog creation transaction failed"))?;
        let outcome = postgres_persist_catalog_creation(&mut transaction, &creation, &settings)?;
        if outcome == CatalogRunbookJobCreationOutcome::Saved {
            transaction
                .commit()
                .map_err(|_| postgres_error("postgres catalog creation commit failed"))?;
        }
        Ok(outcome)
    }
}
#[cfg(feature = "postgres")]
impl PostgresStore {
    /// Serializes identity and catalog binding without signing or dispatching under the lock.
    pub fn commit_admin_catalog_job_record(
        &mut self,
        principal: &fleet_application::admin_identity::AdminMutationPrincipal,
        operation: &dyn fleet_application::admin_identity::AdminOperation,
        creation: CatalogRunbookJobCreation<'_>,
    ) -> Result<CatalogRunbookJobCreationOutcome, fleet_application::AdminJobCommitError<StoreError>>
    {
        use fleet_application::AdminJobCommitError as Error;
        let settings = CatalogStorageSettings::prepare(&creation).map_err(Error::Repository)?;
        let mut client = self.checkout_client().map_err(Error::Repository)?;
        let transaction = client.transaction().map_err(|_| {
            Error::Repository(postgres_error(
                "postgres catalog authority transaction failed",
            ))
        })?;
        let adapter = crate::admin_identity::PgIdentityTransaction::begin(transaction)
            .map_err(Error::Authorization)?;
        creation
            .authorize(&adapter, principal, operation)
            .map_err(Error::Authorization)?;
        let outcome = postgres_persist_catalog_creation(
            &mut adapter.transaction.borrow_mut(),
            &creation,
            &settings,
        )
        .map_err(Error::Repository)?;
        if outcome == CatalogRunbookJobCreationOutcome::Saved {
            creation
                .authorize(&adapter, principal, operation)
                .map_err(Error::Authorization)?;
            adapter.transaction.into_inner().commit().map_err(|_| {
                Error::Repository(postgres_error("postgres catalog authority commit failed"))
            })?;
        }
        Ok(outcome)
    }
}
#[cfg(feature = "postgres")]
impl fleet_application::AdminCatalogJobRepository for PostgresStore {
    fn commit_admin_catalog_job(
        &mut self,
        principal: &fleet_application::admin_identity::AdminMutationPrincipal,
        operation: &dyn fleet_application::admin_identity::AdminOperation,
        creation: CatalogRunbookJobCreation<'_>,
    ) -> Result<CatalogRunbookJobCreationOutcome, fleet_application::AdminJobCommitError<StoreError>>
    {
        self.commit_admin_catalog_job_record(principal, operation, creation)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::*;
    use fleet_application::catalog_execution::CatalogRunbookJobQueryRepository;
    use fleet_application::{
        CatalogJobCreationStrategy, CatalogJobTargetSelection, CreateCatalogRunbookJob,
        CreateCatalogRunbookJobError, CreateCatalogRunbookJobInput, TaskEnvelopeSigner,
    };
    use std::convert::Infallible;

    const BODY: &str = "apiVersion: fleet.sponzey.dev/v1alpha1\nkind: Runbook\nmetadata:\n  name: catalog-atomic\nspec:\n  targets:\n    selector: role=web\n  tasks:\n    - id: install\n      package:\n        name: nginx\n        state: present\n";

    struct TestRoot(PathBuf);
    impl TestRoot {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "fleet-catalog-creation-unit-{name}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&root).unwrap();
            Self(root)
        }
        fn database(&self) -> PathBuf {
            self.0.join("controller.db")
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    struct Signer;
    impl TaskEnvelopeSigner for Signer {
        type Error = Infallible;
        fn sign(&mut self, _payload: &str) -> Result<String, Self::Error> {
            Ok("unit-signature".to_owned())
        }
    }
    pub(crate) fn input() -> CreateCatalogRunbookJobInput {
        CreateCatalogRunbookJobInput {
            strategy: CatalogJobCreationStrategy {
                concurrency: std::num::NonZeroU32::new(3).unwrap(),
                max_failures: std::num::NonZeroU32::new(2),
            },
            target_selection: CatalogJobTargetSelection::ExplicitIds,
            source_id: "catalog-atomic".to_owned(),
            commit: "a".repeat(40),
            path: "runbooks/atomic.yaml".to_owned(),
            checksum: format!("{:x}", Sha256::digest(BODY.as_bytes())),
            job_id: "catalog-job-atomic".to_owned(),
            target_agent_ids: vec!["agent-1".to_owned(), "agent-2".to_owned()],
            timeout: Duration::from_secs(30),
            confirmed_high_risk: true,
            confirmed_by: "unit-admin".to_owned(),
            issued_at: UNIX_EPOCH,
            expires_at: UNIX_EPOCH + Duration::from_secs(60),
            nonce_prefix: "nonce-catalog-atomic".to_owned(),
            approval_request_id: "approval-catalog-atomic".to_owned(),
            approval_expires_at: UNIX_EPOCH + Duration::from_secs(60),
        }
    }

    #[test]
    fn catalog_creation_cannot_use_a_retained_principal_after_authority_changes() {
        let root = TestRoot::new("authority");
        let mut store = fixture(&root);
        let digest = "cd".repeat(32);
        store
            .insert_admin_token_hash_with_identity(&digest, "catalog-operator", "operator")
            .unwrap();
        let record = store.find_admin_token_record(&digest).unwrap().unwrap();
        let principal =
            fleet_application::admin_identity::AdminMutationPrincipal::legacy(&digest, &record)
                .unwrap();
        struct Clock;
        impl fleet_application::admin_identity::AdminOperation for Clock {
            fn checked_now(
                &self,
            ) -> Result<i64, fleet_application::admin_identity::AdminAccessError> {
                Ok(0)
            }
        }
        fleet_application::CreateAuthorizedCatalogRunbookJob::execute(
            &mut store,
            &principal,
            &Clock,
            &mut Signer,
            input(),
        )
        .unwrap();
        store
            .connection
            .execute("UPDATE admin_tokens SET role='viewer' WHERE id=1", [])
            .unwrap();
        let mut stale = input();
        stale.job_id = "catalog-stale".to_owned();
        stale.nonce_prefix = "nonce-stale".to_owned();
        stale.approval_request_id = "approval-stale".to_owned();
        let denied = fleet_application::CreateAuthorizedCatalogRunbookJob::execute(
            &mut store,
            &principal,
            &Clock,
            &mut Signer,
            stale,
        );
        assert!(matches!(
            denied,
            Err(CreateCatalogRunbookJobError::Repository(
                fleet_application::AdminJobCommitError::Authorization(
                    fleet_application::admin_identity::AdminAccessError::Forbidden
                )
            ))
        ));
        assert!(store.find_job_summary("catalog-stale").unwrap().is_none());
        assert!(
            store
                .find_job_summary("catalog-job-atomic")
                .unwrap()
                .is_some()
        );
    }
    pub(crate) fn seed_catalog<R>(store: &mut R, request: &CreateCatalogRunbookJobInput)
    where
        R: AgentRepository<Error = StoreError> + CatalogRepository<Error = StoreError>,
    {
        for id in &request.target_agent_ids {
            let mut agent = Agent::new(
                AgentId::new(id).unwrap(),
                AgentName::new(id).unwrap(),
                AgentIdentity {
                    public_key: AgentPublicKey::new(format!("public-{id}")).unwrap(),
                    fingerprint: AgentFingerprint::new(format!(
                        "{:x}",
                        Sha256::digest(id.as_bytes())
                    ))
                    .unwrap(),
                },
            );
            agent.set_labels(vec![AgentLabel::new("role", "web").unwrap()]);
            AgentRepository::save(store, agent).unwrap();
        }
        let mut source = CatalogSource::new(
            CatalogSourceId::new(&request.source_id).unwrap(),
            PublicCatalogUrl::new("https://example.com/catalog.git").unwrap(),
            CatalogReference::new("main").unwrap(),
        );
        let mut revision = source.begin_sync(CatalogCommitId::new(&request.commit).unwrap());
        revision.begin_validation().unwrap();
        revision.mark_ready(1).unwrap();
        source.activate(&revision).unwrap();
        store.save_catalog_source(source.clone()).unwrap();
        store.save_catalog_revision(revision).unwrap();
        store
            .save_catalog_document(
                CatalogDocument::new(
                    source.id().clone(),
                    CatalogCommitId::new(&request.commit).unwrap(),
                    CatalogDocumentKind::Runbook,
                    &request.path,
                    &request.checksum,
                )
                .unwrap(),
                BODY.to_owned(),
            )
            .unwrap();
    }
    fn fixture(root: &TestRoot) -> SqliteStore {
        let mut store = SqliteStore::open(root.database()).unwrap();
        seed_catalog(&mut store, &input());
        store
    }
    fn counts(store: &SqliteStore) -> Vec<i64> {
        [
            "jobs",
            "job_catalog_runbook_provenance",
            "task_assignments",
            "job_targets",
            "approval_requests",
            "audit_events",
        ]
        .iter()
        .map(|table| {
            store
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap()
        })
        .collect()
    }

    #[test]
    fn sqlite_catalog_job_provenance_read_is_job_owned_after_activation_and_reopen() {
        let root = TestRoot::new("provenance-read");
        let mut store = fixture(&root);
        let request = input();
        let job = JobId::new(&request.job_id).unwrap();
        assert!(
            store
                .find_catalog_runbook_job_provenance(&job)
                .unwrap()
                .is_none()
        );
        CreateCatalogRunbookJob::execute(&mut store, &mut Signer, request.clone()).unwrap();
        let before = store
            .find_catalog_runbook_job_provenance(&job)
            .unwrap()
            .unwrap();
        assert_eq!(before.source_id().as_str(), request.source_id);
        assert_eq!(before.commit().as_str(), request.commit);
        assert_eq!(before.path(), request.path);
        assert_eq!(before.checksum(), request.checksum);
        let mut source = store
            .find_catalog_source(before.source_id())
            .unwrap()
            .unwrap();
        let mut revision = source.begin_sync(CatalogCommitId::new("b".repeat(40)).unwrap());
        revision.begin_validation().unwrap();
        revision.mark_ready(1).unwrap();
        source.activate(&revision).unwrap();
        store.save_catalog_revision(revision.clone()).unwrap();
        store.activate_catalog_revision(source, &revision).unwrap();
        drop(store);
        let store = SqliteStore::open(root.database()).unwrap();
        assert_eq!(
            store.find_catalog_runbook_job_provenance(&job).unwrap(),
            Some(before)
        );
        assert!(
            store
                .find_catalog_runbook_job_provenance(&JobId::new("raw-or-missing").unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn sqlite_catalog_creation_unknown_agent_rolls_back_preceding_assignments() {
        let root = TestRoot::new("unknown-agent");
        let mut store = fixture(&root);
        let mut request = input();
        request.target_agent_ids.push("missing-agent".to_owned());
        assert!(matches!(
            CreateCatalogRunbookJob::execute(&mut store, &mut Signer, request),
            Err(CreateCatalogRunbookJobError::Repository(_))
        ));
        assert!(store.connection.is_autocommit());
        assert_eq!(counts(&store), vec![0; 6]);
        drop(store);
        let store = SqliteStore::open(root.database()).unwrap();
        assert_eq!(counts(&store), vec![0; 6]);
    }

    #[test]
    fn sqlite_catalog_creation_commits_all_effects_and_snapshots_after_reopen() {
        let root = TestRoot::new("success");
        let mut store = fixture(&root);
        let output = CreateCatalogRunbookJob::execute(&mut store, &mut Signer, input()).unwrap();
        assert_eq!(output.envelopes.len(), 2);
        assert!(output.approval_request.is_some());
        drop(store);
        let store = SqliteStore::open(root.database()).unwrap();
        assert_eq!(counts(&store), vec![1, 1, 2, 2, 1, 2]);
        let snapshot = store.connection.query_row("SELECT strategy_concurrency, strategy_max_failures, selector_kind, selector_source, runbook_document FROM jobs WHERE id='catalog-job-atomic'", [], |row| Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?))).unwrap();
        assert_eq!(
            (
                snapshot.0,
                snapshot.1,
                snapshot.2.as_str(),
                snapshot.4.as_str()
            ),
            (3, 2, "explicit_ids", BODY)
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&snapshot.3).unwrap(),
            serde_json::json!(["agent-1", "agent-2"])
        );
        assert_eq!(
            store
                .find_approval_request("approval-catalog-atomic")
                .unwrap()
                .unwrap()
                .status,
            "pending"
        );
        let provenance = store.connection.query_row("SELECT source_id,commit_id,path,checksum FROM job_catalog_runbook_provenance WHERE job_id='catalog-job-atomic'", [], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?))).unwrap();
        let expected = input();
        assert_eq!(
            provenance,
            (
                expected.source_id,
                expected.commit,
                expected.path,
                expected.checksum
            )
        );
        let persisted = store
            .connection
            .prepare(
                "SELECT id,agent_id,nonce,payload_hash,signature FROM task_assignments ORDER BY id",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let expected = output
            .envelopes
            .iter()
            .map(|envelope| {
                (
                    envelope.task_id.as_str().to_owned(),
                    envelope.target_agent_id.as_str().to_owned(),
                    envelope.nonce.as_str().to_owned(),
                    envelope.payload_hash.clone(),
                    envelope.signature.as_ref().unwrap().as_str().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(persisted, expected);
        let audits = store.list_audit_events(10).unwrap();
        assert!(
            audits
                .iter()
                .any(|event| event.action == "approval_requested")
        );
        assert!(
            audits
                .iter()
                .any(|event| event.action == "catalog_runbook_job_created")
        );
        assert!(
            audits
                .iter()
                .all(|event| !format!("{:?}", event.value).contains("package:"))
        );
    }

    #[test]
    fn sqlite_catalog_creation_rolls_back_every_fault_and_can_retry_after_reopen() {
        for (name, table, condition) in [
            ("job", "jobs", "1=1"),
            ("provenance", "job_catalog_runbook_provenance", "1=1"),
            ("assignment", "task_assignments", "NEW.agent_id='agent-2'"),
            ("target", "job_targets", "NEW.agent_id='agent-2'"),
            ("approval", "approval_requests", "1=1"),
            (
                "audit-first",
                "audit_events",
                "NEW.action='approval_requested'",
            ),
            (
                "audit-last",
                "audit_events",
                "NEW.action='catalog_runbook_job_created'",
            ),
        ] {
            let root = TestRoot::new(name);
            let mut store = fixture(&root);
            store.connection.execute_batch(&format!("CREATE TEMP TRIGGER inject_catalog_creation_fault BEFORE INSERT ON {table} WHEN {condition} BEGIN SELECT RAISE(ABORT,'injected catalog creation fault'); END;")).unwrap();
            let result = CreateCatalogRunbookJob::execute(&mut store, &mut Signer, input());
            assert!(
                matches!(result, Err(CreateCatalogRunbookJobError::Repository(_))),
                "{name} did not fail at the repository boundary"
            );
            assert!(store.connection.is_autocommit());
            assert_eq!(counts(&store), vec![0; 6], "partial effects after {name}");
            drop(store);
            let mut store = SqliteStore::open(root.database()).unwrap();
            assert_eq!(
                counts(&store),
                vec![0; 6],
                "partial effects after reopen/{name}"
            );
            CreateCatalogRunbookJob::execute(&mut store, &mut Signer, input()).unwrap();
            assert_eq!(counts(&store), vec![1, 1, 2, 2, 1, 2]);
        }
    }

    #[test]
    fn sqlite_catalog_creation_rechecks_catalog_binding_after_another_connection_changes_it() {
        struct ChangingSigner {
            store: SqliteStore,
            remove_document: bool,
            changed: bool,
        }
        impl TaskEnvelopeSigner for ChangingSigner {
            type Error = Infallible;
            fn sign(&mut self, _payload: &str) -> Result<String, Self::Error> {
                if !self.changed {
                    self.changed = true;
                    if self.remove_document {
                        self.store.connection.execute("DELETE FROM catalog_documents WHERE source_id='catalog-atomic' AND commit_id=?1", ["a".repeat(40)]).unwrap();
                    } else {
                        let mut source = self
                            .store
                            .find_catalog_source(&CatalogSourceId::new("catalog-atomic").unwrap())
                            .unwrap()
                            .unwrap();
                        let revision = self
                            .store
                            .find_catalog_revision(
                                source.id(),
                                &CatalogCommitId::new("b".repeat(40)).unwrap(),
                            )
                            .unwrap()
                            .unwrap();
                        source.activate(&revision).unwrap();
                        self.store
                            .activate_catalog_revision(source, &revision)
                            .unwrap();
                    }
                }
                Ok("unit-signature".to_owned())
            }
        }
        for remove_document in [false, true] {
            let root = TestRoot::new(if remove_document {
                "document-race"
            } else {
                "active-race"
            });
            let mut store = fixture(&root);
            let source = store
                .find_catalog_source(&CatalogSourceId::new("catalog-atomic").unwrap())
                .unwrap()
                .unwrap();
            let commit = CatalogCommitId::new("b".repeat(40)).unwrap();
            let mut revision = source.begin_sync(commit.clone());
            revision.begin_validation().unwrap();
            revision.mark_ready(1).unwrap();
            store.save_catalog_revision(revision).unwrap();
            store
                .save_catalog_document(
                    CatalogDocument::new(
                        source.id().clone(),
                        commit.clone(),
                        CatalogDocumentKind::Runbook,
                        "runbooks/atomic.yaml",
                        input().checksum,
                    )
                    .unwrap(),
                    BODY.to_owned(),
                )
                .unwrap();
            let mut signer = ChangingSigner {
                store: SqliteStore::open(root.database()).unwrap(),
                remove_document,
                changed: false,
            };
            let result = CreateCatalogRunbookJob::execute(&mut store, &mut signer, input());
            assert!(matches!(
                result,
                Err(CreateCatalogRunbookJobError::SelectionChanged)
            ));
            assert!(signer.changed);
            assert_eq!(counts(&store), vec![0; 6]);
            drop(signer);
            drop(store);
            let store = SqliteStore::open(root.database()).unwrap();
            assert_eq!(counts(&store), vec![0; 6]);
            if !remove_document {
                assert_eq!(
                    store
                        .find_catalog_source(source.id())
                        .unwrap()
                        .unwrap()
                        .active_revision(),
                    Some(&commit)
                );
            }
        }
    }

    #[test]
    fn sqlite_catalog_creation_preserves_selector_origin_and_labels_after_creation() {
        for (index, selection, kind, source) in [
            (
                0,
                CatalogJobTargetSelection::Selector("role=web".to_owned()),
                "selector",
                "role=web",
            ),
            (
                1,
                CatalogJobTargetSelection::MatchLabels(BTreeMap::from([(
                    "role".to_owned(),
                    "web".to_owned(),
                )])),
                "matchLabels",
                "{\"role\":\"web\"}",
            ),
            (
                2,
                CatalogJobTargetSelection::Runbook,
                "runbook_matchLabels",
                "{\"role\":\"web\"}",
            ),
        ] {
            let root = TestRoot::new(&format!("selector-{index}"));
            let mut store = fixture(&root);
            let mut request = input();
            request.target_selection = selection;
            CreateCatalogRunbookJob::execute(&mut store, &mut Signer, request).unwrap();
            let saved = store
                .connection
                .query_row(
                    "SELECT selector_kind,selector_source FROM jobs WHERE id='catalog-job-atomic'",
                    [],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap();
            assert_eq!(saved, (kind.to_owned(), source.to_owned()));
            let before = store.connection.query_row("SELECT agent_display_name,agent_status_snapshot,labels_snapshot FROM job_targets WHERE job_id='catalog-job-atomic' AND agent_id='agent-1'", [], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?))).unwrap();
            assert!(
                store
                    .update_agent_labels("agent-1", &[AgentLabel::new("role", "db").unwrap()])
                    .unwrap()
            );
            assert_eq!(
                AgentRepository::find_by_id(&store, &AgentId::new("agent-1").unwrap())
                    .unwrap()
                    .unwrap()
                    .labels(),
                &[AgentLabel::new("role", "db").unwrap()]
            );
            let after = store.connection.query_row("SELECT agent_display_name,agent_status_snapshot,labels_snapshot FROM job_targets WHERE job_id='catalog-job-atomic' AND agent_id='agent-1'", [], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?))).unwrap();
            assert_eq!(after, before);
            assert_eq!(counts(&store), vec![1, 1, 2, 2, 1, 2]);
        }
    }

    #[test]
    fn sqlite_catalog_creation_does_not_rollback_a_transaction_it_did_not_start() {
        let root = TestRoot::new("nested");
        let mut store = fixture(&root);
        store.connection.execute_batch("BEGIN IMMEDIATE; INSERT INTO jobs(id,status,risk,approval_requirement,timeout_ms) VALUES('caller-job','queued','low','none',1000)").unwrap();
        assert!(matches!(
            CreateCatalogRunbookJob::execute(&mut store, &mut Signer, input()),
            Err(CreateCatalogRunbookJobError::Repository(_))
        ));
        assert!(!store.connection.is_autocommit());
        assert_eq!(counts(&store), vec![1, 0, 0, 0, 0, 0]);
        store.connection.execute_batch("ROLLBACK").unwrap();
        assert_eq!(counts(&store), vec![0; 6]);
    }

    #[test]
    fn sqlite_catalog_creation_commit_failure_rolls_back_and_releases_its_transaction() {
        let root = TestRoot::new("commit-failure");
        let mut store = fixture(&root);
        store
            .connection
            .execute_batch(
                "CREATE TABLE unit_commit_barrier(
                agent_id TEXT REFERENCES agents(id) DEFERRABLE INITIALLY DEFERRED
            );
            CREATE TEMP TRIGGER inject_commit_failure AFTER INSERT ON jobs BEGIN
                INSERT INTO unit_commit_barrier(agent_id) VALUES('missing-agent');
            END;",
            )
            .unwrap();
        let changes_before = store.connection.total_changes();
        let result = CreateCatalogRunbookJob::execute(&mut store, &mut Signer, input());
        assert!(matches!(
            result,
            Err(CreateCatalogRunbookJobError::Repository(_))
        ));
        assert!(
            store.connection.total_changes() - changes_before >= 10,
            "all insertion stages must finish before the commit fault"
        );
        assert!(
            store.connection.is_autocommit(),
            "failed commit must release its transaction"
        );
        assert_eq!(counts(&store), vec![0; 6]);
        store
            .connection
            .execute_batch("DROP TRIGGER inject_commit_failure")
            .unwrap();
        CreateCatalogRunbookJob::execute(&mut store, &mut Signer, input()).unwrap();
        assert_eq!(counts(&store), vec![1, 1, 2, 2, 1, 2]);
    }

    #[test]
    fn sqlite_catalog_creation_duplicate_id_preserves_the_original_job_and_audits() {
        let root = TestRoot::new("duplicate");
        let mut store = fixture(&root);
        CreateCatalogRunbookJob::execute(&mut store, &mut Signer, input()).unwrap();
        let before = counts(&store);
        let mut changed = input();
        changed.target_agent_ids.pop();
        changed.strategy.concurrency = std::num::NonZeroU32::new(7).unwrap();
        assert!(matches!(
            CreateCatalogRunbookJob::execute(&mut store, &mut Signer, changed),
            Err(CreateCatalogRunbookJobError::DuplicateJob)
        ));
        drop(store);
        let store = SqliteStore::open(root.database()).unwrap();
        assert_eq!(counts(&store), before);
        assert_eq!(
            store
                .job_strategy("catalog-job-atomic")
                .unwrap()
                .unwrap()
                .concurrency,
            3
        );
    }

    #[cfg(feature = "postgres")]
    fn postgres_input() -> CreateCatalogRunbookJobInput {
        let mut request = input();
        request.source_id = "catalog-pg-atomic".to_owned();
        request.job_id = "catalog-pg-job-atomic".to_owned();
        request.approval_request_id = "approval-catalog-pg-atomic".to_owned();
        request.nonce_prefix = "nonce-catalog-pg-atomic".to_owned();
        request.target_agent_ids = vec![
            "catalog-pg-agent-1".to_owned(),
            "catalog-pg-agent-2".to_owned(),
        ];
        request
    }
    #[cfg(feature = "postgres")]
    fn postgres_counts(store: &PostgresStore) -> Vec<i64> {
        [
            ("jobs", "id"),
            ("job_catalog_runbook_provenance", "job_id"),
            ("task_assignments", "job_id"),
            ("job_targets", "job_id"),
            ("approval_requests", "job_id"),
            ("audit_events", "target"),
        ]
        .iter()
        .map(|(table, column)| {
            store
                .checkout_client()
                .unwrap()
                .query_one(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {column}=$1"),
                    &[&postgres_input().job_id],
                )
                .unwrap()
                .get(0)
        })
        .collect()
    }
    #[cfg(feature = "postgres")]
    fn clear_postgres_fixture(store: &PostgresStore) -> Result<(), StoreError> {
        let request = postgres_input();
        let mut client = store.checkout_client()?;
        for table in [
            "jobs",
            "job_catalog_runbook_provenance",
            "task_assignments",
            "job_targets",
            "approval_requests",
            "audit_events",
        ] {
            client
                .batch_execute(&format!(
                    "DROP TRIGGER IF EXISTS unit_catalog_creation_fault ON {table}"
                ))
                .map_err(|_| postgres_error("test trigger cleanup failed"))?;
        }
        client
            .batch_execute("DROP FUNCTION IF EXISTS unit_catalog_raise_failure()")
            .map_err(|_| postgres_error("test function cleanup failed"))?;
        for (table, column) in [
            ("approval_requests", "job_id"),
            ("jobs", "id"),
            ("audit_events", "target"),
        ] {
            client
                .execute(
                    &format!("DELETE FROM {table} WHERE {column}=$1"),
                    &[&request.job_id],
                )
                .map_err(|_| postgres_error("test Job cleanup failed"))?;
        }
        client
            .execute(
                "DELETE FROM catalog_sources WHERE id=$1",
                &[&request.source_id],
            )
            .map_err(|_| postgres_error("test catalog cleanup failed"))?;
        client
            .execute(
                "DELETE FROM agents WHERE id=$1 OR id=$2",
                &[&request.target_agent_ids[0], &request.target_agent_ids[1]],
            )
            .map_err(|_| postgres_error("test Agent cleanup failed"))?;
        Ok(())
    }
    #[cfg(feature = "postgres")]
    fn postgres_test_url() -> String {
        std::env::var("FLEET_TEST_POSTGRES_URL").expect("requires a disposable Postgres test URL")
    }
    #[cfg(feature = "postgres")]
    struct PostgresFixture {
        store: PostgresStore,
        url: String,
    }
    #[cfg(feature = "postgres")]
    impl PostgresFixture {
        fn new(url: &str) -> Self {
            let mut store = PostgresStore::connect(url).unwrap();
            store.migrate().unwrap();
            clear_postgres_fixture(&store).unwrap();
            seed_catalog(&mut store, &postgres_input());
            Self {
                store,
                url: url.to_owned(),
            }
        }
        fn cleanup(&self) {
            clear_postgres_fixture(&self.store).unwrap();
            assert_eq!(postgres_counts(&self.store), vec![0; 6]);
        }
    }
    #[cfg(feature = "postgres")]
    impl Drop for PostgresFixture {
        fn drop(&mut self) {
            let _ = clear_postgres_fixture(&self.store);
        }
    }

    #[cfg(feature = "postgres")]
    #[test]
    #[ignore = "requires explicit FLEET_TEST_POSTGRES_URL and a disposable Postgres database"]
    fn postgres_catalog_creation_roundtrip_reopen_duplicate_and_label_snapshot() {
        let url = postgres_test_url();
        let mut fixture = PostgresFixture::new(&url);
        let request = postgres_input();
        let output =
            CreateCatalogRunbookJob::execute(&mut fixture.store, &mut Signer, request.clone())
                .unwrap();
        assert_eq!(output.envelopes.len(), 2);
        assert!(output.approval_request.is_some());
        let mut reopened = PostgresStore::connect(&fixture.url).unwrap();
        assert_eq!(postgres_counts(&reopened), vec![1, 1, 2, 2, 1, 2]);
        let provenance = reopened
            .find_catalog_runbook_job_provenance(&JobId::new(&request.job_id).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(provenance.source_id().as_str(), request.source_id);
        assert_eq!(provenance.commit().as_str(), request.commit);
        assert_eq!(provenance.path(), request.path);
        assert_eq!(provenance.checksum(), request.checksum);
        assert!(
            reopened
                .find_catalog_runbook_job_provenance(&JobId::new("catalog-pg-missing").unwrap())
                .unwrap()
                .is_none()
        );
        let row = reopened.checkout_client().unwrap().query_one("SELECT strategy_concurrency,strategy_max_failures,selector_kind,selector_source,runbook_document FROM jobs WHERE id=$1", &[&request.job_id]).unwrap();
        assert_eq!(
            (
                row.get::<_, i64>(0),
                row.get::<_, i64>(1),
                row.get::<_, String>(2),
                row.get::<_, String>(4)
            ),
            (3, 2, "explicit_ids".to_owned(), BODY.to_owned())
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&row.get::<_, String>(3)).unwrap(),
            serde_json::json!(request.target_agent_ids)
        );
        let row = reopened.checkout_client().unwrap().query_one("SELECT source_id,commit_id,path,checksum FROM job_catalog_runbook_provenance WHERE job_id=$1", &[&request.job_id]).unwrap();
        assert_eq!(
            (
                row.get::<_, String>(0),
                row.get::<_, String>(1),
                row.get::<_, String>(2),
                row.get::<_, String>(3)
            ),
            (
                request.source_id.clone(),
                request.commit.clone(),
                request.path.clone(),
                request.checksum.clone()
            )
        );
        assert_eq!(
            ApprovalRepository::find_approval_request(&reopened, &request.approval_request_id)
                .unwrap()
                .unwrap()
                .status,
            "pending"
        );
        let before = reopened
            .checkout_client()
            .unwrap()
            .query_one(
                "SELECT labels_snapshot FROM job_targets WHERE job_id=$1 AND agent_id=$2",
                &[&request.job_id, &request.target_agent_ids[0]],
            )
            .unwrap()
            .get::<_, String>(0);
        assert!(
            reopened
                .update_agent_labels(
                    &request.target_agent_ids[0],
                    &[AgentLabel::new("role", "db").unwrap()]
                )
                .unwrap()
        );
        let after = reopened
            .checkout_client()
            .unwrap()
            .query_one(
                "SELECT labels_snapshot FROM job_targets WHERE job_id=$1 AND agent_id=$2",
                &[&request.job_id, &request.target_agent_ids[0]],
            )
            .unwrap()
            .get::<_, String>(0);
        assert_eq!(after, before);
        let mut duplicate = request;
        duplicate.target_agent_ids.pop();
        assert!(matches!(
            CreateCatalogRunbookJob::execute(&mut reopened, &mut Signer, duplicate),
            Err(CreateCatalogRunbookJobError::DuplicateJob)
        ));
        assert_eq!(postgres_counts(&reopened), vec![1, 1, 2, 2, 1, 2]);
        drop(reopened);
        fixture.cleanup();
    }

    #[cfg(feature = "postgres")]
    #[test]
    #[ignore = "requires explicit FLEET_TEST_POSTGRES_URL and a disposable Postgres database"]
    fn postgres_catalog_creation_faults_rollback_every_stage_and_deferred_commit() {
        let url = postgres_test_url();
        for (name, table, condition, deferred) in [
            ("job", "jobs", "true", false),
            (
                "provenance",
                "job_catalog_runbook_provenance",
                "true",
                false,
            ),
            (
                "assignment",
                "task_assignments",
                "NEW.agent_id='catalog-pg-agent-2'",
                false,
            ),
            (
                "target",
                "job_targets",
                "NEW.agent_id='catalog-pg-agent-2'",
                false,
            ),
            ("approval", "approval_requests", "true", false),
            (
                "audit-first",
                "audit_events",
                "NEW.action='approval_requested'",
                false,
            ),
            (
                "audit-last",
                "audit_events",
                "NEW.action='catalog_runbook_job_created'",
                false,
            ),
            ("commit", "jobs", "true", true),
        ] {
            let mut fixture = PostgresFixture::new(&url);
            fixture.store.checkout_client().unwrap().batch_execute("CREATE FUNCTION unit_catalog_raise_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected catalog creation fault'; END; $$").unwrap();
            let sql = if deferred {
                format!(
                    "CREATE CONSTRAINT TRIGGER unit_catalog_creation_fault AFTER INSERT ON {table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION unit_catalog_raise_failure()"
                )
            } else {
                format!(
                    "CREATE TRIGGER unit_catalog_creation_fault BEFORE INSERT ON {table} FOR EACH ROW WHEN ({condition}) EXECUTE FUNCTION unit_catalog_raise_failure()"
                )
            };
            fixture
                .store
                .checkout_client()
                .unwrap()
                .batch_execute(&sql)
                .unwrap();
            assert!(
                matches!(
                    CreateCatalogRunbookJob::execute(
                        &mut fixture.store,
                        &mut Signer,
                        postgres_input()
                    ),
                    Err(CreateCatalogRunbookJobError::Repository(_))
                ),
                "{name} did not fail in persistence"
            );
            let mut reopened = PostgresStore::connect(&fixture.url).unwrap();
            assert_eq!(
                postgres_counts(&fixture.store),
                vec![0; 6],
                "partial effects/{name}"
            );
            assert_eq!(
                postgres_counts(&reopened),
                vec![0; 6],
                "partial effects after reopen/{name}"
            );
            fixture.store.checkout_client().unwrap().batch_execute(&format!("DROP TRIGGER unit_catalog_creation_fault ON {table}; DROP FUNCTION unit_catalog_raise_failure()" )).unwrap();
            CreateCatalogRunbookJob::execute(&mut reopened, &mut Signer, postgres_input()).unwrap();
            assert_eq!(postgres_counts(&reopened), vec![1, 1, 2, 2, 1, 2]);
            drop(reopened);
            fixture.cleanup();
        }
    }

    #[cfg(feature = "postgres")]
    #[test]
    #[ignore = "requires explicit FLEET_TEST_POSTGRES_URL and a disposable Postgres database"]
    fn postgres_catalog_creation_rechecks_a_cross_connection_active_change() {
        struct ChangingSigner {
            store: PostgresStore,
            changed: bool,
        }
        impl TaskEnvelopeSigner for ChangingSigner {
            type Error = Infallible;
            fn sign(&mut self, _payload: &str) -> Result<String, Self::Error> {
                if !self.changed {
                    self.changed = true;
                    let mut source = self
                        .store
                        .find_catalog_source(&CatalogSourceId::new("catalog-pg-atomic").unwrap())
                        .unwrap()
                        .unwrap();
                    let revision = self
                        .store
                        .find_catalog_revision(
                            source.id(),
                            &CatalogCommitId::new("b".repeat(40)).unwrap(),
                        )
                        .unwrap()
                        .unwrap();
                    source.activate(&revision).unwrap();
                    self.store
                        .activate_catalog_revision(source, &revision)
                        .unwrap();
                }
                Ok("unit-signature".to_owned())
            }
        }
        let url = postgres_test_url();
        let mut fixture = PostgresFixture::new(&url);
        let request = postgres_input();
        let source = fixture
            .store
            .find_catalog_source(&CatalogSourceId::new(&request.source_id).unwrap())
            .unwrap()
            .unwrap();
        let mut revision = source.begin_sync(CatalogCommitId::new("b".repeat(40)).unwrap());
        revision.begin_validation().unwrap();
        revision.mark_ready(1).unwrap();
        fixture.store.save_catalog_revision(revision).unwrap();
        fixture
            .store
            .save_catalog_document(
                CatalogDocument::new(
                    source.id().clone(),
                    CatalogCommitId::new("b".repeat(40)).unwrap(),
                    CatalogDocumentKind::Runbook,
                    &request.path,
                    &request.checksum,
                )
                .unwrap(),
                BODY.to_owned(),
            )
            .unwrap();
        let mut signer = ChangingSigner {
            store: PostgresStore::connect(&fixture.url).unwrap(),
            changed: false,
        };
        assert!(matches!(
            CreateCatalogRunbookJob::execute(&mut fixture.store, &mut signer, request),
            Err(CreateCatalogRunbookJobError::SelectionChanged)
        ));
        assert!(signer.changed);
        assert_eq!(postgres_counts(&fixture.store), vec![0; 6]);
        drop(signer);
        fixture.cleanup();
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn postgres_catalog_creation_requires_the_same_composite_repository_contract() {
        fn requires<
            R: fleet_application::CatalogRunbookJobCreationRepository<Error = StoreError>,
        >() {
        }
        requires::<PostgresStore>();
    }
}
