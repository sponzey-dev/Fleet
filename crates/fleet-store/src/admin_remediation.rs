//! Remediation snapshots and prepared effects within the protected approval transaction.
//! No signing, independent transaction, dispatch or direct human authorization lives here.

use crate::*;
use fleet_application::admin_identity::AdminAccessError;
use fleet_application::admin_remediation::{AdminRemediationRead, PreparedAdminRemediation};

fn unavailable(_: impl std::fmt::Debug) -> AdminAccessError {
    AdminAccessError::Unavailable
}

impl AdminRemediationRead for SqliteStore {
    fn remediation_for_action(
        &self,
        id: &str,
    ) -> Result<Option<AppRemediationRequestRecord>, AdminAccessError> {
        self.find_remediation_request_record(id)
            .map_err(unavailable)
    }
    fn approval_for_remediation_action(
        &self,
        id: &str,
    ) -> Result<Option<AppApprovalRequestRecord>, AdminAccessError> {
        self.find_approval_request(id).map_err(unavailable)
    }
}
impl AdminRemediationRead for crate::admin_identity::SqliteIdentityTransaction<'_> {
    fn remediation_for_action(
        &self,
        id: &str,
    ) -> Result<Option<AppRemediationRequestRecord>, AdminAccessError> {
        self.store.remediation_for_action(id)
    }
    fn approval_for_remediation_action(
        &self,
        id: &str,
    ) -> Result<Option<AppApprovalRequestRecord>, AdminAccessError> {
        self.store.approval_for_remediation_action(id)
    }
}

pub(crate) fn save_sqlite(
    store: &SqliteStore,
    creation: &PreparedAdminRemediation<'_>,
) -> Result<(), AdminAccessError> {
    if store.connection.is_autocommit() {
        return Err(AdminAccessError::Unavailable);
    }
    if let Some(execution) = creation.execution() {
        i64::try_from(execution.job().timeout().as_millis())
            .map_err(|_| AdminAccessError::InvalidRequest)?;
        if store
            .connection
            .query_row(
                "SELECT 1 FROM jobs WHERE id=?1",
                [execution.job().id().as_str()],
                |_| Ok(()),
            )
            .optional()
            .map_err(unavailable)?
            .is_some()
        {
            return Err(AdminAccessError::Conflict);
        }
        store
            .save_runbook_job_record(execution.job(), execution.task())
            .map_err(unavailable)?;
        for assignment in execution.assignments() {
            sqlite_insert_task_assignment_in_connection(&store.connection, assignment)
                .map_err(unavailable)?;
        }
        let approval = creation.approval();
        let changed=store.connection.execute("UPDATE approval_requests SET approver=?3,reason=?4,status=?5,decided_at=?6 WHERE id=?1 AND job_id=?2 AND status='pending'",params![approval.id,approval.job_id,approval.approver,approval.reason,approval.status,approval.decided_at.map(system_time_to_unix_secs)]).map_err(unavailable)?;
        if changed != 1 {
            return Err(AdminAccessError::Conflict);
        }
    } else {
        store
            .insert_approval_request(creation.approval().clone())
            .map_err(unavailable)?;
    }
    let before = creation.before();
    let after = creation.after();
    let changed=store.connection.execute("UPDATE remediation_requests SET status=?2,job_id=?3,updated_at=?4 WHERE id=?1 AND status=?5 AND job_id IS ?6",params![after.id,after.status,after.job_id,system_time_to_unix_secs(after.updated_at),before.status,before.job_id]).map_err(unavailable)?;
    if changed != 1 {
        return Err(AdminAccessError::Conflict);
    }
    for event in creation.audits() {
        store.insert_audit(event).map_err(unavailable)?;
    }
    Ok(())
}

#[cfg(feature = "postgres")]
impl AdminRemediationRead for PostgresStore {
    fn remediation_for_action(
        &self,
        id: &str,
    ) -> Result<Option<AppRemediationRequestRecord>, AdminAccessError> {
        fleet_application::RemediationRequestRepository::find_remediation_request(self, id)
            .map_err(unavailable)
    }
    fn approval_for_remediation_action(
        &self,
        id: &str,
    ) -> Result<Option<AppApprovalRequestRecord>, AdminAccessError> {
        fleet_application::ApprovalRepository::find_approval_request(self, id).map_err(unavailable)
    }
}
#[cfg(feature = "postgres")]
impl AdminRemediationRead for crate::admin_identity::PgIdentityTransaction<'_> {
    fn remediation_for_action(
        &self,
        id: &str,
    ) -> Result<Option<AppRemediationRequestRecord>, AdminAccessError> {
        self.transaction.borrow_mut().query_opt("SELECT id,policy_id,policy_name,agent_id,runbook_ref,status,approval_required,risk_summary,job_id,origin_drift_report_id,policy_version,created_at,updated_at FROM remediation_requests WHERE id=$1 FOR UPDATE",&[&id]).map_err(unavailable)?.map(|row|postgres_row_to_remediation_request_record(&row).map_err(unavailable)).transpose()
    }
    fn approval_for_remediation_action(
        &self,
        id: &str,
    ) -> Result<Option<AppApprovalRequestRecord>, AdminAccessError> {
        self.transaction.borrow_mut().query_opt("SELECT id,job_id,requester,approver,reason,status,expires_at,created_at,decided_at FROM approval_requests WHERE id=$1 FOR UPDATE",&[&id]).map_err(unavailable)?.map(|row|postgres_row_to_app_approval_request_record(&row).map_err(unavailable)).transpose()
    }
}
#[cfg(feature = "postgres")]
pub(crate) fn save_postgres(
    transaction: &mut ::postgres::Transaction<'_>,
    creation: &PreparedAdminRemediation<'_>,
) -> Result<(), AdminAccessError> {
    if let Some(execution) = creation.execution() {
        let timeout = i64::try_from(execution.job().timeout().as_millis())
            .map_err(|_| AdminAccessError::InvalidRequest)?;
        let changed=transaction.execute("INSERT INTO jobs(id,status,risk,approval_requirement,timeout_ms,runbook_document) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING",&[&execution.job().id().as_str(),&job_status_to_str(execution.job().status()),&task_risk_to_str(execution.job().risk()),&approval_requirement_to_str(execution.job().approval_requirement()),&timeout,&execution.task().runbook_document()]).map_err(unavailable)?;
        if changed != 1 {
            return Err(AdminAccessError::Conflict);
        }
        for assignment in execution.assignments() {
            postgres_insert_task_assignment_in_transaction(transaction, assignment)
                .map_err(unavailable)?;
        }
        let approval = creation.approval();
        let changed=transaction.execute("UPDATE approval_requests SET approver=$3,reason=$4,status=$5,decided_at=$6 WHERE id=$1 AND job_id=$2 AND status='pending'",&[&approval.id,&approval.job_id,&approval.approver,&approval.reason,&approval.status,&approval.decided_at.map(system_time_to_unix_secs)]).map_err(unavailable)?;
        if changed != 1 {
            return Err(AdminAccessError::Conflict);
        }
    } else {
        let approval = creation.approval();
        transaction.execute("INSERT INTO approval_requests(id,job_id,requester,approver,reason,status,expires_at,created_at,decided_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",&[&approval.id,&approval.job_id,&approval.requester,&approval.approver,&approval.reason,&approval.status,&system_time_to_unix_secs(approval.expires_at),&system_time_to_unix_secs(approval.created_at),&approval.decided_at.map(system_time_to_unix_secs)]).map_err(unavailable)?;
    }
    let before = creation.before();
    let after = creation.after();
    let changed=transaction.execute("UPDATE remediation_requests SET status=$2,job_id=$3,updated_at=$4 WHERE id=$1 AND status=$5 AND job_id IS NOT DISTINCT FROM $6",&[&after.id,&after.status,&after.job_id,&system_time_to_unix_secs(after.updated_at),&before.status,&before.job_id]).map_err(unavailable)?;
    if changed != 1 {
        return Err(AdminAccessError::Conflict);
    }
    for event in creation.audits() {
        postgres_insert_audit_in_transaction(transaction, event).map_err(unavailable)?;
    }
    Ok(())
}
