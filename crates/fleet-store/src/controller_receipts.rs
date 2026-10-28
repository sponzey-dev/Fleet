//! SQLite receipt replay storage. A staged report is never receipt authority;
//! signed bytes are stored only after the inbox effect reaches committed state.
//! A changed signer can replace bytes for the same exact committed report only
//! because the Controller receipt helper verifies the active-key candidate first.

use crate::{SqliteStore, StoreError};
use fleet_application::delivery::{
    ControllerStoredReceiptRepository, StoredReceiptOutcome, StoredReportReceipt,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use std::fmt::Write as _;

fn digest_hex(receipt: &StoredReportReceipt) -> String {
    let mut output = String::with_capacity(64);
    for byte in receipt.digest().0 {
        write!(&mut output, "{byte:02x}").expect("String write is infallible");
    }
    output
}

impl ControllerStoredReceiptRepository for SqliteStore {
    type Error = StoreError;

    fn persist_stored_receipt(
        &mut self,
        receipt: &StoredReportReceipt,
    ) -> Result<StoredReceiptOutcome, Self::Error> {
        let [controller, agent, job, task, report] = receipt.key().parts();
        let digest = digest_hex(receipt);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active: (String, String) = tx.query_row(
            "SELECT namespace, store_epoch FROM controller_delivery_identity WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if active.0 != controller {
            return Err(StoreError::AssignmentOwnershipMismatch);
        }
        if active.1 != receipt.store_epoch() {
            return Ok(StoredReceiptOutcome::StaleEpoch);
        }
        let inbox: Option<(String, String, bool)> = tx
            .query_row(
                "SELECT inbox.status, inbox.digest_hex,
                        EXISTS(SELECT 1 FROM task_assignments AS assignment
                               WHERE assignment.id = inbox.task_id
                                 AND assignment.job_id = inbox.job_id
                                 AND assignment.agent_id = inbox.agent_id)
                 FROM controller_report_inbox AS inbox
                 WHERE inbox.controller_namespace = ?1 AND inbox.agent_id = ?2
                   AND inbox.job_id = ?3 AND inbox.task_id = ?4 AND inbox.report_id = ?5",
                params![controller, agent, job, task, report],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((status, staged_digest, owns_task)) = inbox else {
            return Ok(StoredReceiptOutcome::NotCommitted);
        };
        if !owns_task {
            return Err(StoreError::AssignmentOwnershipMismatch);
        }
        if staged_digest != digest {
            return Ok(StoredReceiptOutcome::ConflictingDigest);
        }
        if status != "committed" {
            return Ok(StoredReceiptOutcome::NotCommitted);
        }
        let existing: Option<(String, String, String, Vec<u8>)> = tx
            .query_row(
                "SELECT digest_hex, store_epoch, signer_fingerprint, receipt_bytes
                 FROM controller_report_receipts
                 WHERE controller_namespace = ?1 AND agent_id = ?2 AND job_id = ?3
                   AND task_id = ?4 AND report_id = ?5",
                params![controller, agent, job, task, report],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if let Some((old_digest, old_epoch, old_signer, bytes)) = existing {
            if old_digest != digest || bytes.is_empty() || bytes.len() > 8192 {
                return Err(StoreError::Domain("stored receipt row corrupt".into()));
            }
            if old_epoch == receipt.store_epoch() && old_signer == receipt.signer_fingerprint() {
                return Ok(StoredReceiptOutcome::AlreadyStored(bytes));
            }
            tx.execute(
                "UPDATE controller_report_receipts
                 SET store_epoch = ?6, signer_fingerprint = ?7, receipt_bytes = ?8
                 WHERE controller_namespace = ?1 AND agent_id = ?2 AND job_id = ?3
                   AND task_id = ?4 AND report_id = ?5",
                params![
                    controller,
                    agent,
                    job,
                    task,
                    report,
                    receipt.store_epoch(),
                    receipt.signer_fingerprint(),
                    receipt.encoded_bytes()
                ],
            )?;
        } else {
            tx.execute(
                "INSERT INTO controller_report_receipts (
                    controller_namespace, agent_id, job_id, task_id, report_id,
                    digest_hex, store_epoch, signer_fingerprint, receipt_bytes
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    controller,
                    agent,
                    job,
                    task,
                    report,
                    digest,
                    receipt.store_epoch(),
                    receipt.signer_fingerprint(),
                    receipt.encoded_bytes()
                ],
            )?;
        }
        tx.commit()?;
        Ok(StoredReceiptOutcome::Stored(
            receipt.encoded_bytes().to_vec(),
        ))
    }
}
