//! Atomic human-authorized DriftCheck/Runbook creation from Application-prepared effects.
//! Identity serialization and rollback match other protected human business writes.

use crate::*;
use fleet_application::admin_identity::{AdminMutationPrincipal, AdminOperation};
use fleet_application::{
    AdminJobCommitError, AdminStructuredJobRepository, JobCreationMetadata, PreparedStructuredJob,
    PreparedStructuredTask,
};

type CommitError = AdminJobCommitError<StoreError>;
fn persistence(error: impl Into<StoreError>) -> CommitError {
    AdminJobCommitError::Repository(error.into())
}
fn documents(creation: &PreparedStructuredJob) -> (Option<&str>, Option<&str>) {
    match creation.task() {
        PreparedStructuredTask::DriftCheck(task) => (Some(task.policy_document()), None),
        PreparedStructuredTask::Runbook(task) => (None, Some(task.runbook_document())),
    }
}

impl SqliteStore {
    pub fn commit_admin_structured_job_record(
        &self,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        creation: &PreparedStructuredJob,
        metadata: &JobCreationMetadata,
    ) -> Result<(), CommitError> {
        let timeout = i64::try_from(creation.job().timeout().as_millis()).map_err(|_| {
            persistence(StoreError::Domain(
                "job timeout exceeds database range".to_owned(),
            ))
        })?;
        let (policy, runbook) = documents(creation);
        let provenance = creation.provenance();
        let transaction = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .map_err(persistence)?;
        creation
            .authorize(self, principal, operation)
            .map_err(AdminJobCommitError::Authorization)?;
        if self
            .connection
            .query_row(
                "SELECT 1 FROM jobs WHERE id=?1",
                [creation.job().id().as_str()],
                |_| Ok(()),
            )
            .optional()
            .map_err(persistence)?
            .is_some()
        {
            return Err(AdminJobCommitError::DuplicateJob);
        }
        self.connection.execute("INSERT INTO jobs(id,status,risk,approval_requirement,timeout_ms,drift_policy_document,runbook_document,drift_policy_id,drift_policy_version,drift_purpose,strategy_concurrency,strategy_max_failures,selector_kind,selector_source) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",params![
            creation.job().id().as_str(), job_status_to_str(creation.job().status()), task_risk_to_str(creation.job().risk()), approval_requirement_to_str(creation.job().approval_requirement()), timeout, policy, runbook,
            provenance.map(|p|p.policy_id.as_str()), provenance.map(|p|i64::from(p.policy_version)), provenance.map(|p|p.purpose.as_str()),
            i64::from(metadata.concurrency()), metadata.max_failures().map(i64::from), metadata.selector_kind(), metadata.selector_source(),
        ]).map_err(persistence)?;
        for envelope in creation.assignments() {
            sqlite_insert_task_assignment_in_connection(&self.connection, envelope)
                .map_err(persistence)?;
        }
        if let Some(approval) = creation.approval() {
            self.insert_approval_request(approval.clone())
                .map_err(persistence)?;
        }
        for audit in creation.audits() {
            self.insert_audit(audit).map_err(persistence)?;
        }
        creation
            .authorize(self, principal, operation)
            .map_err(AdminJobCommitError::Authorization)?;
        transaction.commit().map_err(persistence)
    }
}
impl AdminStructuredJobRepository for SqliteStore {
    type Error = StoreError;
    fn commit_admin_structured_job(
        &mut self,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        creation: &PreparedStructuredJob,
        metadata: &JobCreationMetadata,
    ) -> Result<(), CommitError> {
        self.commit_admin_structured_job_record(principal, operation, creation, metadata)
    }
}

#[cfg(feature = "postgres")]
impl PostgresStore {
    pub fn commit_admin_structured_job_record(
        &mut self,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        creation: &PreparedStructuredJob,
        metadata: &JobCreationMetadata,
    ) -> Result<(), CommitError> {
        let timeout = i64::try_from(creation.job().timeout().as_millis()).map_err(|_| {
            persistence(StoreError::Domain(
                "job timeout exceeds database range".to_owned(),
            ))
        })?;
        let (policy, runbook) = documents(creation);
        let provenance = creation.provenance();
        let mut client = self.checkout_client().map_err(persistence)?;
        let transaction = client.transaction().map_err(|_| {
            persistence(postgres_error("postgres structured job transaction failed"))
        })?;
        let adapter = crate::admin_identity::PgIdentityTransaction::begin(transaction)
            .map_err(AdminJobCommitError::Authorization)?;
        creation
            .authorize(&adapter, principal, operation)
            .map_err(AdminJobCommitError::Authorization)?;
        {
            let mut transaction = adapter.transaction.borrow_mut();
            if transaction
                .query_opt(
                    "SELECT 1 FROM jobs WHERE id=$1",
                    &[&creation.job().id().as_str()],
                )
                .map_err(|_| {
                    persistence(postgres_error(
                        "postgres structured duplicate lookup failed",
                    ))
                })?
                .is_some()
            {
                return Err(AdminJobCommitError::DuplicateJob);
            }
            transaction.execute("INSERT INTO jobs(id,status,risk,approval_requirement,timeout_ms,drift_policy_document,runbook_document,drift_policy_id,drift_policy_version,drift_purpose,strategy_concurrency,strategy_max_failures,selector_kind,selector_source) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",&[
                &creation.job().id().as_str(), &job_status_to_str(creation.job().status()), &task_risk_to_str(creation.job().risk()), &approval_requirement_to_str(creation.job().approval_requirement()), &timeout, &policy, &runbook,
                &provenance.map(|p|p.policy_id.as_str()), &provenance.map(|p|i64::from(p.policy_version)), &provenance.map(|p|p.purpose.as_str()),
                &i64::from(metadata.concurrency()), &metadata.max_failures().map(i64::from), &metadata.selector_kind(), &metadata.selector_source(),
            ]).map_err(|_|persistence(postgres_error("postgres structured job insert failed")))?;
            for envelope in creation.assignments() {
                postgres_insert_task_assignment_in_transaction(&mut transaction, envelope)
                    .map_err(persistence)?;
            }
            if let Some(approval) = creation.approval() {
                transaction.execute("INSERT INTO approval_requests(id,job_id,requester,approver,reason,status,expires_at,created_at,decided_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",&[
                    &approval.id,&approval.job_id,&approval.requester,&approval.approver,&approval.reason,&approval.status,&system_time_to_unix_secs(approval.expires_at),&system_time_to_unix_secs(approval.created_at),&approval.decided_at.map(system_time_to_unix_secs),
                ]).map_err(|_|persistence(postgres_error("postgres structured approval insert failed")))?;
            }
            for audit in creation.audits() {
                postgres_insert_audit_in_transaction(&mut transaction, audit)
                    .map_err(persistence)?;
            }
        }
        creation
            .authorize(&adapter, principal, operation)
            .map_err(AdminJobCommitError::Authorization)?;
        adapter
            .transaction
            .into_inner()
            .commit()
            .map_err(|_| persistence(postgres_error("postgres structured job commit failed")))
    }
}
#[cfg(feature = "postgres")]
impl AdminStructuredJobRepository for PostgresStore {
    type Error = StoreError;
    fn commit_admin_structured_job(
        &mut self,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        creation: &PreparedStructuredJob,
        metadata: &JobCreationMetadata,
    ) -> Result<(), CommitError> {
        self.commit_admin_structured_job_record(principal, operation, creation, metadata)
    }
}
