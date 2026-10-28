//! Protected approval transactions serialize human authority with the decision,
//! pending Job transition and append-only audit. No dispatch or credential work.

use crate::*;
use fleet_application::admin_approval::{
    AdminApprovalError, AdminApprovalRepository, AdminApprovalTransaction,
};
use fleet_application::admin_identity::AdminAccessError;

fn unavailable(_: impl std::fmt::Debug) -> AdminApprovalError {
    AdminAccessError::Unavailable.into()
}

impl fleet_application::admin_identity::AdminWriteRead
    for crate::admin_identity::SqliteIdentityTransaction<'_>
{
    fn legacy_admin_by_hash(
        &self,
        digest: &str,
    ) -> Result<Option<AppAdminTokenRecord>, AdminAccessError> {
        fleet_application::admin_identity::AdminWriteRead::legacy_admin_by_hash(self.store, digest)
    }
}

impl AdminApprovalTransaction for crate::admin_identity::SqliteIdentityTransaction<'_> {
    fn save_remediation_action(
        &mut self,
        creation: &fleet_application::admin_remediation::PreparedAdminRemediation<'_>,
    ) -> Result<(), AdminApprovalError> {
        crate::admin_remediation::save_sqlite(self.store, creation).map_err(Into::into)
    }
    fn pending_approvals(
        &self,
        limit: usize,
    ) -> Result<Vec<AppApprovalRequestRecord>, AdminApprovalError> {
        if limit == 0 || limit > fleet_application::admin_approval::ADMIN_EXPIRY_SCAN_LIMIT {
            return Err(AdminAccessError::InvalidRequest.into());
        }
        self.store
            .list_approval_requests(Some("pending"), limit)
            .map_err(unavailable)
    }
    fn save_expiry(
        &mut self,
        before: &AppApprovalRequestRecord,
        after: &AppApprovalRequestRecord,
        audit: &AuditEvent,
    ) -> Result<(), AdminApprovalError> {
        let changed = self.store.connection.execute("UPDATE approval_requests SET status='expired',decided_at=?3 WHERE id=?1 AND job_id=?2 AND status='pending'",params![before.id,before.job_id,after.decided_at.map(system_time_to_unix_secs)]).map_err(unavailable)?;
        if changed != 1 {
            return Err(AdminAccessError::Conflict.into());
        }
        self.store
            .connection
            .execute(
                "UPDATE jobs SET status='expired' WHERE id=?1 AND status='pending_approval'",
                [before.job_id.as_str()],
            )
            .map_err(unavailable)?;
        self.store.insert_audit(audit).map_err(unavailable)
    }
    fn approval(&self, id: &str) -> Result<Option<AppApprovalRequestRecord>, AdminApprovalError> {
        self.store.find_approval_request(id).map_err(unavailable)
    }
    fn save_decision(
        &mut self,
        before: &AppApprovalRequestRecord,
        after: &AppApprovalRequestRecord,
        status: JobStatus,
        audit: &AuditEvent,
    ) -> Result<(), AdminApprovalError> {
        let changed = self.store.connection.execute("UPDATE approval_requests SET approver=?2,reason=?3,status=?4,decided_at=?5 WHERE id=?1 AND job_id=?6 AND status='pending'", params![before.id,after.approver,after.reason,after.status,after.decided_at.map(system_time_to_unix_secs),before.job_id]).map_err(unavailable)?;
        if changed != 1 {
            return Err(AdminAccessError::Conflict.into());
        }
        let changed = self
            .store
            .connection
            .execute(
                "UPDATE jobs SET status=?2 WHERE id=?1 AND status='pending_approval'",
                params![before.job_id, job_status_to_str(status)],
            )
            .map_err(unavailable)?;
        if changed != 1 {
            return Err(AdminAccessError::Conflict.into());
        }
        self.store.insert_audit(audit).map_err(unavailable)
    }
}

impl AdminApprovalRepository for &SqliteStore {
    fn approval_transaction<T>(
        &mut self,
        work: impl FnOnce(&mut dyn AdminApprovalTransaction) -> Result<T, AdminApprovalError>,
    ) -> Result<T, AdminApprovalError> {
        let transaction = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .map_err(unavailable)?;
        let result = work(&mut crate::admin_identity::SqliteIdentityTransaction { store: self })?;
        transaction.commit().map_err(unavailable)?;
        Ok(result)
    }
}

#[cfg(feature = "postgres")]
impl AdminApprovalTransaction for crate::admin_identity::PgIdentityTransaction<'_> {
    fn save_remediation_action(
        &mut self,
        creation: &fleet_application::admin_remediation::PreparedAdminRemediation<'_>,
    ) -> Result<(), AdminApprovalError> {
        crate::admin_remediation::save_postgres(&mut self.transaction.borrow_mut(), creation)
            .map_err(Into::into)
    }
    fn pending_approvals(
        &self,
        limit: usize,
    ) -> Result<Vec<AppApprovalRequestRecord>, AdminApprovalError> {
        if limit == 0 || limit > fleet_application::admin_approval::ADMIN_EXPIRY_SCAN_LIMIT {
            return Err(AdminAccessError::InvalidRequest.into());
        }
        self.transaction.borrow_mut().query("SELECT id,job_id,requester,approver,reason,status,expires_at,created_at,decided_at FROM approval_requests WHERE status='pending' ORDER BY created_at DESC,id DESC LIMIT $1 FOR UPDATE",&[&(limit as i64)]).map_err(unavailable)?
            .into_iter().map(|row|postgres_row_to_app_approval_request_record(&row).map_err(unavailable)).collect()
    }
    fn save_expiry(
        &mut self,
        before: &AppApprovalRequestRecord,
        after: &AppApprovalRequestRecord,
        audit: &AuditEvent,
    ) -> Result<(), AdminApprovalError> {
        let mut transaction = self.transaction.borrow_mut();
        let changed = transaction.execute("UPDATE approval_requests SET status='expired',decided_at=$3 WHERE id=$1 AND job_id=$2 AND status='pending'",&[&before.id,&before.job_id,&after.decided_at.map(system_time_to_unix_secs)]).map_err(unavailable)?;
        if changed != 1 {
            return Err(AdminAccessError::Conflict.into());
        }
        transaction
            .execute(
                "UPDATE jobs SET status='expired' WHERE id=$1 AND status='pending_approval'",
                &[&before.job_id],
            )
            .map_err(unavailable)?;
        postgres_insert_audit_in_transaction(&mut transaction, audit).map_err(unavailable)
    }
    fn approval(&self, id: &str) -> Result<Option<AppApprovalRequestRecord>, AdminApprovalError> {
        self.transaction.borrow_mut().query_opt("SELECT id,job_id,requester,approver,reason,status,expires_at,created_at,decided_at FROM approval_requests WHERE id=$1 FOR UPDATE", &[&id]).map_err(unavailable)?
            .map(|row| postgres_row_to_app_approval_request_record(&row).map_err(unavailable)).transpose()
    }
    fn save_decision(
        &mut self,
        before: &AppApprovalRequestRecord,
        after: &AppApprovalRequestRecord,
        status: JobStatus,
        audit: &AuditEvent,
    ) -> Result<(), AdminApprovalError> {
        let mut transaction = self.transaction.borrow_mut();
        let changed = transaction.execute("UPDATE approval_requests SET approver=$2,reason=$3,status=$4,decided_at=$5 WHERE id=$1 AND job_id=$6 AND status='pending'", &[&before.id,&after.approver,&after.reason,&after.status,&after.decided_at.map(system_time_to_unix_secs),&before.job_id]).map_err(unavailable)?;
        if changed != 1 {
            return Err(AdminAccessError::Conflict.into());
        }
        let changed = transaction
            .execute(
                "UPDATE jobs SET status=$2 WHERE id=$1 AND status='pending_approval'",
                &[&before.job_id, &job_status_to_str(status)],
            )
            .map_err(unavailable)?;
        if changed != 1 {
            return Err(AdminAccessError::Conflict.into());
        }
        postgres_insert_audit_in_transaction(&mut transaction, audit).map_err(unavailable)
    }
}

#[cfg(feature = "postgres")]
impl AdminApprovalRepository for PostgresStore {
    fn approval_transaction<T>(
        &mut self,
        work: impl FnOnce(&mut dyn AdminApprovalTransaction) -> Result<T, AdminApprovalError>,
    ) -> Result<T, AdminApprovalError> {
        let mut client = self.checkout_client().map_err(unavailable)?;
        let transaction = client.transaction().map_err(unavailable)?;
        let mut adapter = crate::admin_identity::PgIdentityTransaction::begin(transaction)?;
        let result = work(&mut adapter)?;
        adapter
            .transaction
            .into_inner()
            .commit()
            .map_err(unavailable)?;
        Ok(result)
    }
}

impl AdminApprovalRepository for SqliteStore {
    fn approval_transaction<T>(
        &mut self,
        work: impl FnOnce(&mut dyn AdminApprovalTransaction) -> Result<T, AdminApprovalError>,
    ) -> Result<T, AdminApprovalError> {
        AdminApprovalRepository::approval_transaction(&mut &*self, work)
    }
}
