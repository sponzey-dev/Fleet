//! Atomic human cancellation. Canonical transitions/audit come from Application;
//! this adapter has no session handle and cannot send an Agent cancellation.

use crate::*;
use fleet_application::admin_cancel::{
    AdminCancellationRepository, AdminCancellationTransaction, CancellationAssignment,
    CancellationSnapshot, PreparedCancellation,
};
use fleet_application::admin_identity::AdminAccessError;

fn unavailable(_: impl std::fmt::Debug) -> AdminAccessError {
    AdminAccessError::Unavailable
}
fn assignment(
    job: String,
    task: String,
    agent: String,
    status: String,
) -> Result<CancellationAssignment, AdminAccessError> {
    Ok(CancellationAssignment {
        job_id: JobId::new(job).map_err(unavailable)?,
        task_id: TaskId::new(task).map_err(unavailable)?,
        agent_id: AgentId::new(agent).map_err(unavailable)?,
        status: AssignmentStatus::parse(&status).ok_or(AdminAccessError::Unavailable)?,
    })
}
fn snapshot(
    status: String,
    max: Option<i64>,
    assignments: Vec<CancellationAssignment>,
) -> Result<CancellationSnapshot, AdminAccessError> {
    Ok(CancellationSnapshot {
        status: JobStatus::parse(&status).ok_or(AdminAccessError::Unavailable)?,
        max_failures: max.map(u32::try_from).transpose().map_err(unavailable)?,
        assignments,
    })
}

impl AdminCancellationTransaction for crate::admin_identity::SqliteIdentityTransaction<'_> {
    fn cancellation_snapshot(
        &self,
        id: &JobId,
    ) -> Result<Option<CancellationSnapshot>, AdminAccessError> {
        let job = self
            .store
            .connection
            .query_row(
                "SELECT status,strategy_max_failures FROM jobs WHERE id=?1",
                [id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .optional()
            .map_err(unavailable)?;
        let Some((status, max)) = job else {
            return Ok(None);
        };
        let mut query = self.store.connection.prepare("SELECT job_id,id,agent_id,status FROM task_assignments WHERE job_id=?1 ORDER BY created_at,id").map_err(unavailable)?;
        let rows = query
            .query_map([id.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(unavailable)?;
        let assignments = rows
            .map(|row| {
                let (job, task, agent, status) = row.map_err(unavailable)?;
                assignment(job, task, agent, status)
            })
            .collect::<Result<Vec<_>, _>>()?;
        snapshot(status, max, assignments).map(Some)
    }
    fn apply_cancellation(
        &mut self,
        prepared: &PreparedCancellation,
    ) -> Result<(), AdminAccessError> {
        for item in prepared.assignments() {
            let changed = self.store.connection.execute("UPDATE task_assignments SET status='canceled',completed_at=?5,last_error=?6 WHERE id=?1 AND job_id=?2 AND agent_id=?3 AND status=?4",params![item.task_id.as_str(),item.job_id.as_str(),item.agent_id.as_str(),item.status.as_str(),system_time_to_unix_secs(prepared.occurred_at()),prepared.reason()]).map_err(unavailable)?;
            if changed != 1 {
                return Err(AdminAccessError::Conflict);
            }
        }
        if prepared.update_job() {
            let changed = self
                .store
                .connection
                .execute(
                    "UPDATE jobs SET status=?2 WHERE id=?1 AND status=?3",
                    params![
                        prepared.job_id().as_str(),
                        prepared.status().as_str(),
                        prepared.before().as_str()
                    ],
                )
                .map_err(unavailable)?;
            if changed != 1 {
                return Err(AdminAccessError::Conflict);
            }
        }
        if let Some(event) = prepared.audit() {
            self.store.insert_audit(event).map_err(unavailable)?;
        }
        Ok(())
    }
}
impl AdminCancellationRepository for &SqliteStore {
    fn cancellation_transaction<T>(
        &mut self,
        work: impl FnOnce(&mut dyn AdminCancellationTransaction) -> Result<T, AdminAccessError>,
    ) -> Result<T, AdminAccessError> {
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
impl AdminCancellationRepository for SqliteStore {
    fn cancellation_transaction<T>(
        &mut self,
        work: impl FnOnce(&mut dyn AdminCancellationTransaction) -> Result<T, AdminAccessError>,
    ) -> Result<T, AdminAccessError> {
        AdminCancellationRepository::cancellation_transaction(&mut &*self, work)
    }
}

#[cfg(feature = "postgres")]
impl AdminCancellationTransaction for crate::admin_identity::PgIdentityTransaction<'_> {
    fn cancellation_snapshot(
        &self,
        id: &JobId,
    ) -> Result<Option<CancellationSnapshot>, AdminAccessError> {
        let mut transaction = self.transaction.borrow_mut();
        // Assignment-before-Job matches the lifecycle write direction; immutable
        // target snapshots cannot gain assignments while this cancellation runs.
        let rows = transaction.query("SELECT job_id,id,agent_id,status FROM task_assignments WHERE job_id=$1 ORDER BY created_at,id FOR UPDATE",&[&id.as_str()]).map_err(unavailable)?;
        let assignments = rows
            .into_iter()
            .map(|row| {
                assignment(
                    row.try_get(0).map_err(unavailable)?,
                    row.try_get(1).map_err(unavailable)?,
                    row.try_get(2).map_err(unavailable)?,
                    row.try_get(3).map_err(unavailable)?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        transaction
            .query_opt(
                "SELECT status,strategy_max_failures FROM jobs WHERE id=$1 FOR UPDATE",
                &[&id.as_str()],
            )
            .map_err(unavailable)?
            .map(|row| {
                snapshot(
                    row.try_get(0).map_err(unavailable)?,
                    row.try_get(1).map_err(unavailable)?,
                    assignments,
                )
            })
            .transpose()
    }
    fn apply_cancellation(
        &mut self,
        prepared: &PreparedCancellation,
    ) -> Result<(), AdminAccessError> {
        let mut transaction = self.transaction.borrow_mut();
        for item in prepared.assignments() {
            let changed = transaction.execute("UPDATE task_assignments SET status='canceled',completed_at=$5,last_error=$6 WHERE id=$1 AND job_id=$2 AND agent_id=$3 AND status=$4",&[&item.task_id.as_str(),&item.job_id.as_str(),&item.agent_id.as_str(),&item.status.as_str(),&system_time_to_unix_secs(prepared.occurred_at()),&prepared.reason()]).map_err(unavailable)?;
            if changed != 1 {
                return Err(AdminAccessError::Conflict);
            }
        }
        if prepared.update_job() {
            let changed = transaction
                .execute(
                    "UPDATE jobs SET status=$2 WHERE id=$1 AND status=$3",
                    &[
                        &prepared.job_id().as_str(),
                        &prepared.status().as_str(),
                        &prepared.before().as_str(),
                    ],
                )
                .map_err(unavailable)?;
            if changed != 1 {
                return Err(AdminAccessError::Conflict);
            }
        }
        if let Some(event) = prepared.audit() {
            postgres_insert_audit_in_transaction(&mut transaction, event).map_err(unavailable)?;
        }
        Ok(())
    }
}
#[cfg(feature = "postgres")]
impl AdminCancellationRepository for PostgresStore {
    fn cancellation_transaction<T>(
        &mut self,
        work: impl FnOnce(&mut dyn AdminCancellationTransaction) -> Result<T, AdminAccessError>,
    ) -> Result<T, AdminAccessError> {
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
