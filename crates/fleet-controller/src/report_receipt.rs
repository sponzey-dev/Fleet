//! Controller-side signed storage-receipt issuance boundary.
//! A caller must obtain its outcome from a committed inbox effect and must authenticate the session before delivery.

use crate::ControllerIdentity;
use fleet_application::delivery::{
    ControllerDeliveryIdentity, ControllerStoredReceiptRepository, InboxEffectOutcome,
    PersistControllerStoredReceipt, StoredReceiptOutcome, StoredReportReceipt,
};
use fleet_domain::delivery::ReportKey;
use fleet_protocol::receipt::{
    ReportDispositionWire, ReportReceiptStatementWire, SignedReportReceiptWire,
};
use std::fmt::{Display, Formatter, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptIssueError {
    NotCommitted,
    IdentityMismatch,
    InvalidSigningMaterial,
    InvalidStatement,
    StoreFailed,
    ReceiptConflict,
    StaleEpoch,
    SigningKeyChanged,
    StoredReceiptCorrupt,
}

impl Display for ReceiptIssueError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::NotCommitted => "report effects are not committed",
            Self::IdentityMismatch => "receipt delivery identity mismatch",
            Self::InvalidSigningMaterial => "invalid receipt signing material",
            Self::InvalidStatement => "invalid receipt statement",
            Self::StoreFailed => "receipt storage failed",
            Self::ReceiptConflict => "stored receipt digest conflict",
            Self::StaleEpoch => "receipt store epoch changed",
            Self::SigningKeyChanged => "stored receipt signer changed",
            Self::StoredReceiptCorrupt => "stored receipt is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ReceiptIssueError {}

/// Signs only a completed inbox effect. `authenticated_agent_id` must come from
/// the verified session; the caller must load namespace/epoch from the active
/// store and still owns authenticated delivery.
pub fn issue_stored_receipt(
    delivery: &ControllerDeliveryIdentity,
    key: &ReportKey,
    authenticated_agent_id: &str,
    outcome: InboxEffectOutcome,
    signing_identity: &ControllerIdentity,
    signed_at_ms: u64,
) -> Result<SignedReportReceiptWire, ReceiptIssueError> {
    let digest = match outcome {
        InboxEffectOutcome::Committed(digest)
        | InboxEffectOutcome::LateDispositionCommitted(digest)
        | InboxEffectOutcome::AlreadyCommitted(digest) => digest,
        InboxEffectOutcome::ConflictingBody | InboxEffectOutcome::NotStaged => {
            return Err(ReceiptIssueError::NotCommitted);
        }
    };
    let [controller, agent, job, task, report] = key.parts();
    if controller != delivery.namespace || agent != authenticated_agent_id {
        return Err(ReceiptIssueError::IdentityMismatch);
    }
    let mut digest_hex = String::with_capacity(64);
    for byte in digest.0 {
        write!(&mut digest_hex, "{byte:02x}").expect("String write is infallible");
    }
    let statement = ReportReceiptStatementWire {
        controller_namespace: controller.to_owned(),
        store_epoch: delivery.store_epoch.clone(),
        agent_id: agent.to_owned(),
        job_id: job.to_owned(),
        task_id: task.to_owned(),
        report_id: report.to_owned(),
        digest_hex,
        signed_at_ms,
        disposition: ReportDispositionWire::Stored,
        signing_key_fingerprint: signing_identity.fingerprint.clone(),
    };
    let preimage = statement
        .signing_preimage()
        .map_err(|_| ReceiptIssueError::InvalidStatement)?;
    let fingerprint = fleet_core::fingerprint_public_key(&signing_identity.public_key)
        .map_err(|_| ReceiptIssueError::InvalidSigningMaterial)?;
    if fingerprint != signing_identity.fingerprint {
        return Err(ReceiptIssueError::InvalidSigningMaterial);
    }
    let signature_hex = fleet_core::sign_challenge(&signing_identity.private_key, &preimage)
        .map_err(|_| ReceiptIssueError::InvalidSigningMaterial)?;
    if !fleet_core::verify_challenge_signature(
        &signing_identity.public_key,
        &preimage,
        &signature_hex,
    )
    .map_err(|_| ReceiptIssueError::InvalidSigningMaterial)?
    {
        return Err(ReceiptIssueError::InvalidSigningMaterial);
    }
    let receipt = SignedReportReceiptWire {
        statement,
        signature_hex,
    };
    receipt
        .validate_shape()
        .map_err(|_| ReceiptIssueError::InvalidStatement)?;
    Ok(receipt)
}

/// Persists the first signed bytes and returns those same bytes on duplicate
/// requests. Repository errors or invalid previously stored bytes never produce
/// a sendable receipt; the caller remains responsible for authenticated delivery.
pub fn issue_and_persist_stored_receipt<R: ControllerStoredReceiptRepository>(
    repository: &mut R,
    delivery: &ControllerDeliveryIdentity,
    key: &ReportKey,
    authenticated_agent_id: &str,
    outcome: InboxEffectOutcome,
    signing_identity: &ControllerIdentity,
    signed_at_ms: u64,
) -> Result<SignedReportReceiptWire, ReceiptIssueError> {
    let issued = issue_stored_receipt(
        delivery,
        key,
        authenticated_agent_id,
        outcome,
        signing_identity,
        signed_at_ms,
    )?;
    let digest = match outcome {
        InboxEffectOutcome::Committed(digest)
        | InboxEffectOutcome::LateDispositionCommitted(digest)
        | InboxEffectOutcome::AlreadyCommitted(digest) => digest,
        _ => return Err(ReceiptIssueError::NotCommitted),
    };
    let candidate = StoredReportReceipt::new(
        key.clone(),
        digest,
        delivery.store_epoch.clone(),
        signing_identity.fingerprint.clone(),
        serde_json::to_vec(&issued).map_err(|_| ReceiptIssueError::InvalidStatement)?,
    )
    .map_err(|_| ReceiptIssueError::InvalidStatement)?;
    let persisted = PersistControllerStoredReceipt::execute(repository, &candidate)
        .map_err(|_| ReceiptIssueError::StoreFailed)?;
    let encoded = match persisted {
        StoredReceiptOutcome::Stored(bytes) | StoredReceiptOutcome::AlreadyStored(bytes) => bytes,
        StoredReceiptOutcome::NotCommitted => return Err(ReceiptIssueError::NotCommitted),
        StoredReceiptOutcome::ConflictingDigest => return Err(ReceiptIssueError::ReceiptConflict),
        StoredReceiptOutcome::StaleEpoch => return Err(ReceiptIssueError::StaleEpoch),
        StoredReceiptOutcome::SigningKeyChanged => {
            return Err(ReceiptIssueError::SigningKeyChanged);
        }
    };
    let stored: SignedReportReceiptWire =
        serde_json::from_slice(&encoded).map_err(|_| ReceiptIssueError::StoredReceiptCorrupt)?;
    let preimage = stored
        .statement
        .signing_preimage()
        .map_err(|_| ReceiptIssueError::StoredReceiptCorrupt)?;
    stored
        .validate_shape()
        .map_err(|_| ReceiptIssueError::StoredReceiptCorrupt)?;
    let statement = &stored.statement;
    let [controller, agent, job, task, report] = key.parts();
    if statement.controller_namespace != controller
        || statement.store_epoch != delivery.store_epoch
        || statement.agent_id != agent
        || statement.job_id != job
        || statement.task_id != task
        || statement.report_id != report
        || statement.digest_hex != issued.statement.digest_hex
        || statement.signing_key_fingerprint != signing_identity.fingerprint
        || statement.disposition != ReportDispositionWire::Stored
    {
        return Err(ReceiptIssueError::StoredReceiptCorrupt);
    }
    if !fleet_core::verify_challenge_signature(
        &signing_identity.public_key,
        &preimage,
        &stored.signature_hex,
    )
    .map_err(|_| ReceiptIssueError::StoredReceiptCorrupt)?
    {
        return Err(ReceiptIssueError::StoredReceiptCorrupt);
    }
    Ok(stored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_application::delivery::{
        ControllerStoredReceiptRepository, StoredReceiptOutcome, StoredReportReceipt,
    };
    use fleet_domain::delivery::ReportDigest;

    #[derive(Default)]
    struct MemoryReceiptRepository(Option<Vec<u8>>);

    impl ControllerStoredReceiptRepository for MemoryReceiptRepository {
        type Error = ();

        fn persist_stored_receipt(
            &mut self,
            receipt: &StoredReportReceipt,
        ) -> Result<StoredReceiptOutcome, Self::Error> {
            if let Some(bytes) = &self.0 {
                Ok(StoredReceiptOutcome::AlreadyStored(bytes.clone()))
            } else {
                self.0 = Some(receipt.encoded_bytes().to_vec());
                Ok(StoredReceiptOutcome::Stored(
                    receipt.encoded_bytes().to_vec(),
                ))
            }
        }
    }

    fn fixture() -> (ControllerIdentity, ControllerDeliveryIdentity, ReportKey) {
        let pair = fleet_core::generate_agent_key_pair().unwrap();
        (
            ControllerIdentity {
                public_key: pair.public_key_hex,
                fingerprint: pair.fingerprint,
                private_key: pair.private_key_hex,
            },
            ControllerDeliveryIdentity {
                namespace: "controller-1".into(),
                store_epoch: "epoch-1".into(),
            },
            ReportKey::new("controller-1", "agent-1", "job-1", "task-1", "report-1").unwrap(),
        )
    }

    #[test]
    fn committed_report_produces_verifiable_stored_receipt() {
        let (signer, delivery, key) = fixture();
        let receipt = issue_stored_receipt(
            &delivery,
            &key,
            "agent-1",
            InboxEffectOutcome::Committed(ReportDigest([0xab; 32])),
            &signer,
            10,
        )
        .unwrap();
        assert!(matches!(
            receipt.statement.disposition,
            fleet_protocol::receipt::ReportDispositionWire::Stored
        ));
        assert_eq!(receipt.statement.digest_hex, "ab".repeat(32));
        assert_eq!(receipt.statement.store_epoch, "epoch-1");
        assert_eq!(
            receipt.statement.signing_key_fingerprint,
            signer.fingerprint
        );
        assert!(
            fleet_core::verify_challenge_signature(
                &signer.public_key,
                &receipt.statement.signing_preimage().unwrap(),
                &receipt.signature_hex
            )
            .unwrap()
        );
        let duplicate = issue_stored_receipt(
            &delivery,
            &key,
            "agent-1",
            InboxEffectOutcome::AlreadyCommitted(ReportDigest([0xab; 32])),
            &signer,
            10,
        )
        .unwrap();
        assert_eq!(receipt, duplicate);
    }

    #[test]
    fn uncommitted_or_wrong_identity_never_issues_receipt() {
        let (signer, mut delivery, key) = fixture();
        for outcome in [
            InboxEffectOutcome::NotStaged,
            InboxEffectOutcome::ConflictingBody,
        ] {
            assert_eq!(
                issue_stored_receipt(&delivery, &key, "agent-1", outcome, &signer, 10),
                Err(ReceiptIssueError::NotCommitted)
            );
        }
        delivery.namespace = "other-controller".into();
        assert_eq!(
            issue_stored_receipt(
                &delivery,
                &key,
                "agent-1",
                InboxEffectOutcome::Committed(ReportDigest([1; 32])),
                &signer,
                10
            ),
            Err(ReceiptIssueError::IdentityMismatch)
        );
        delivery.namespace = "controller-1".into();
        assert_eq!(
            issue_stored_receipt(
                &delivery,
                &key,
                "agent-2",
                InboxEffectOutcome::Committed(ReportDigest([1; 32])),
                &signer,
                10
            ),
            Err(ReceiptIssueError::IdentityMismatch)
        );
        delivery.store_epoch.clear();
        assert_eq!(
            issue_stored_receipt(
                &delivery,
                &key,
                "agent-1",
                InboxEffectOutcome::Committed(ReportDigest([1; 32])),
                &signer,
                10
            ),
            Err(ReceiptIssueError::InvalidStatement)
        );
    }

    #[test]
    fn wrong_fingerprint_or_private_key_never_issues_receipt() {
        let (mut signer, delivery, key) = fixture();
        assert!(!format!("{signer:?}").contains(&signer.private_key));
        let outcome = InboxEffectOutcome::Committed(ReportDigest([1; 32]));
        signer.fingerprint = "a".repeat(64);
        assert_eq!(
            issue_stored_receipt(&delivery, &key, "agent-1", outcome, &signer, 10),
            Err(ReceiptIssueError::InvalidSigningMaterial)
        );
        signer.fingerprint = fleet_core::fingerprint_public_key(&signer.public_key).unwrap();
        signer.private_key = fleet_core::generate_agent_key_pair()
            .unwrap()
            .private_key_hex;
        assert_eq!(
            issue_stored_receipt(&delivery, &key, "agent-1", outcome, &signer, 10),
            Err(ReceiptIssueError::InvalidSigningMaterial)
        );
    }

    #[test]
    fn persisted_receipt_replays_identical_verified_bytes() {
        let (signer, delivery, key) = fixture();
        let mut repository = MemoryReceiptRepository::default();
        let outcome = InboxEffectOutcome::Committed(ReportDigest([0xab; 32]));
        let first = issue_and_persist_stored_receipt(
            &mut repository,
            &delivery,
            &key,
            "agent-1",
            outcome,
            &signer,
            10,
        )
        .unwrap();
        let second = issue_and_persist_stored_receipt(
            &mut repository,
            &delivery,
            &key,
            "agent-1",
            outcome,
            &signer,
            11,
        )
        .unwrap();
        assert_eq!(first, second);
        repository.0 = Some(b"corrupt-stored-receipt".to_vec());
        assert_eq!(
            issue_and_persist_stored_receipt(
                &mut repository,
                &delivery,
                &key,
                "agent-1",
                outcome,
                &signer,
                12
            ),
            Err(ReceiptIssueError::StoredReceiptCorrupt)
        );
    }
}
