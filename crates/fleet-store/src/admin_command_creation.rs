//! Atomic human-authorized Command creation. Prepared signatures precede this boundary;
//! current identity, Job/assignments, approval, audit and display settings share one commit.

use crate::*;
use fleet_application::admin_identity::{
    AdminAccessError, AdminMutationPrincipal, AdminOperation, AdminWriteRead,
};
use fleet_application::{
    AdminCommandCommitError, AdminCommandJobRepository, CommandCreationMetadata, PreparedCommandJob,
};

type CommitError = AdminCommandCommitError<StoreError>;
fn persistence(error: impl Into<StoreError>) -> CommitError {
    AdminCommandCommitError::Repository(error.into())
}

impl AdminWriteRead for SqliteStore {
    fn legacy_admin_by_hash(
        &self,
        digest: &str,
    ) -> Result<Option<AppAdminTokenRecord>, AdminAccessError> {
        self.find_admin_token_record(digest)
            .map_err(|_| AdminAccessError::Unavailable)
    }
}

impl SqliteStore {
    pub fn commit_admin_command_record(
        &self,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        creation: &PreparedCommandJob,
        metadata: &CommandCreationMetadata,
    ) -> Result<(), CommitError> {
        let transaction = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .map_err(persistence)?;
        creation
            .authorize(self, principal, operation)
            .map_err(AdminCommandCommitError::Authorization)?;
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
            return Err(AdminCommandCommitError::DuplicateJob);
        }
        self.save_command_job_record(creation.job(), creation.task())
            .map_err(persistence)?;
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
        if !self
            .update_job_strategy(
                creation.job().id().as_str(),
                metadata.concurrency(),
                metadata.max_failures(),
            )
            .map_err(persistence)?
            || !self
                .update_job_selector_snapshot(
                    creation.job().id().as_str(),
                    metadata.selector_kind(),
                    metadata.selector_source(),
                )
                .map_err(persistence)?
        {
            return Err(persistence(StoreError::NotFound));
        }
        creation
            .authorize(self, principal, operation)
            .map_err(AdminCommandCommitError::Authorization)?;
        transaction.commit().map_err(persistence)
    }
}

impl AdminCommandJobRepository for SqliteStore {
    type Error = StoreError;
    fn commit_admin_command_job(
        &mut self,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        creation: &PreparedCommandJob,
        metadata: &CommandCreationMetadata,
    ) -> Result<(), CommitError> {
        self.commit_admin_command_record(principal, operation, creation, metadata)
    }
}

#[cfg(feature = "postgres")]
impl PostgresStore {
    pub fn commit_admin_command_record(
        &mut self,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        creation: &PreparedCommandJob,
        metadata: &CommandCreationMetadata,
    ) -> Result<(), CommitError> {
        let args = serde_json::to_string(creation.task().args()).map_err(|_| {
            persistence(StoreError::Domain(
                "command arguments encoding failed".to_owned(),
            ))
        })?;
        let timeout = i64::try_from(creation.job().timeout().as_millis()).map_err(|_| {
            persistence(StoreError::Domain(
                "command timeout exceeds database range".to_owned(),
            ))
        })?;
        let mut client = self.checkout_client().map_err(persistence)?;
        let transaction = client
            .transaction()
            .map_err(|_| persistence(postgres_error("postgres command transaction failed")))?;
        let adapter = crate::admin_identity::PgIdentityTransaction::begin(transaction)
            .map_err(AdminCommandCommitError::Authorization)?;
        creation
            .authorize(&adapter, principal, operation)
            .map_err(AdminCommandCommitError::Authorization)?;
        {
            let mut transaction = adapter.transaction.borrow_mut();
            if transaction
                .query_opt(
                    "SELECT 1 FROM jobs WHERE id=$1",
                    &[&creation.job().id().as_str()],
                )
                .map_err(|_| {
                    persistence(postgres_error("postgres command duplicate check failed"))
                })?
                .is_some()
            {
                return Err(AdminCommandCommitError::DuplicateJob);
            }
            transaction.execute("INSERT INTO jobs (id,status,risk,approval_requirement,timeout_ms,command_program,command_args_json,command_max_output_bytes,strategy_concurrency,strategy_max_failures,selector_kind,selector_source)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)", &[
                &creation.job().id().as_str(),&job_status_to_str(creation.job().status()),&task_risk_to_str(creation.job().risk()),
                &approval_requirement_to_str(creation.job().approval_requirement()),&timeout,&creation.task().program(),&args,
                &(creation.task().max_output_bytes() as i64),&(metadata.concurrency() as i64),&metadata.max_failures().map(i64::from),
                &metadata.selector_kind(),&metadata.selector_source(),
            ]).map_err(|error|persistence(postgres_constraint_or_context(error,"postgres authorized command insert failed")))?;
            for envelope in creation.assignments() {
                postgres_insert_task_assignment_in_transaction(&mut transaction, envelope)
                    .map_err(persistence)?;
            }
            if let Some(approval) = creation.approval() {
                transaction.execute("INSERT INTO approval_requests (id,job_id,requester,approver,reason,status,expires_at,created_at,decided_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",&[
                    &approval.id,&approval.job_id,&approval.requester,&approval.approver,&approval.reason,&approval.status,
                    &system_time_to_unix_secs(approval.expires_at),&system_time_to_unix_secs(approval.created_at),&approval.decided_at.map(system_time_to_unix_secs),
                ]).map_err(|error|persistence(postgres_constraint_or_context(error,"postgres authorized approval insert failed")))?;
            }
            for audit in creation.audits() {
                postgres_insert_audit_in_transaction(&mut transaction, audit)
                    .map_err(persistence)?;
            }
        }
        creation
            .authorize(&adapter, principal, operation)
            .map_err(AdminCommandCommitError::Authorization)?;
        adapter
            .transaction
            .into_inner()
            .commit()
            .map_err(|_| persistence(postgres_error("postgres authorized command commit failed")))
    }
}

#[cfg(feature = "postgres")]
impl AdminCommandJobRepository for PostgresStore {
    type Error = StoreError;
    fn commit_admin_command_job(
        &mut self,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        creation: &PreparedCommandJob,
        metadata: &CommandCreationMetadata,
    ) -> Result<(), CommitError> {
        self.commit_admin_command_record(principal, operation, creation, metadata)
    }
}
