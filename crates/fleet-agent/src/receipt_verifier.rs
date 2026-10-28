//! Agent-side future v2 receipt authenticity boundary. It performs no storage
//! mutation; only a verified stored candidate may reach journal cleanup.

use fleet_application::delivery::PendingReport;
use fleet_core::{fingerprint_public_key, verify_challenge_signature};
use fleet_domain::delivery::{ReportDigest, ReportKey};
use fleet_domain::{ControllerSigningTrustBundle, SigningKeyFingerprint};
use fleet_protocol::receipt::{ReportDispositionWire, SignedReportReceiptWire};
use std::fmt::{Display, Formatter};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReceiptCandidate {
    pub key: ReportKey,
    pub digest: ReportDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptVerificationError {
    InvalidShape,
    WrongController,
    WrongStoreEpoch,
    WrongReport,
    UntrustedSigner,
    InvalidSignature,
    Rejected,
    InvalidSigningTime,
}

impl Display for ReceiptVerificationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            Self::InvalidShape => "invalid report receipt encoding",
            Self::WrongController => "report receipt controller mismatch",
            Self::WrongStoreEpoch => "report receipt store epoch mismatch",
            Self::WrongReport => "report receipt owner or digest mismatch",
            Self::UntrustedSigner => "report receipt signer is not trusted",
            Self::InvalidSignature => "invalid report receipt signature",
            Self::Rejected => "report was rejected; local copy retained",
            Self::InvalidSigningTime => "report receipt signing time is invalid",
        };
        formatter.write_str(reason)
    }
}

impl std::error::Error for ReceiptVerificationError {}

fn lowercase_digest(digest: ReportDigest) -> String {
    digest.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Caller must supply immutable local ownership context, never values read from
/// the received receipt. This function never deletes the local report itself.
pub fn verify_stored_receipt(
    receipt: &SignedReportReceiptWire,
    local: &PendingReport,
    expected_namespace: &str,
    expected_store_epoch: &str,
    trust: &ControllerSigningTrustBundle,
    now: SystemTime,
) -> Result<StoredReceiptCandidate, ReceiptVerificationError> {
    receipt
        .validate_shape()
        .map_err(|_| ReceiptVerificationError::InvalidShape)?;
    let statement = &receipt.statement;
    if statement.controller_namespace != expected_namespace
        || local.report.key.parts()[0] != expected_namespace
    {
        return Err(ReceiptVerificationError::WrongController);
    }
    if statement.store_epoch != expected_store_epoch {
        return Err(ReceiptVerificationError::WrongStoreEpoch);
    }
    let [_, agent, job, task, report] = local.report.key.parts();
    if statement.agent_id != agent
        || statement.job_id != job
        || statement.task_id != task
        || statement.report_id != report
        || statement.digest_hex != lowercase_digest(local.digest)
    {
        return Err(ReceiptVerificationError::WrongReport);
    }
    if !matches!(statement.disposition, ReportDispositionWire::Stored) {
        return Err(ReceiptVerificationError::Rejected);
    }
    let signed_at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_millis(statement.signed_at_ms))
        .ok_or(ReceiptVerificationError::InvalidSigningTime)?;
    if signed_at > now {
        return Err(ReceiptVerificationError::InvalidSigningTime);
    }
    let fingerprint = SigningKeyFingerprint::new(&statement.signing_key_fingerprint)
        .map_err(|_| ReceiptVerificationError::UntrustedSigner)?;
    let trusted = trust
        .entry_for_fingerprint(&fingerprint, signed_at, now)
        .map_err(|_| ReceiptVerificationError::UntrustedSigner)?;
    let public_key = trusted.public_key().as_str();
    if fingerprint_public_key(public_key).ok().as_deref()
        != Some(&statement.signing_key_fingerprint)
    {
        return Err(ReceiptVerificationError::UntrustedSigner);
    }
    let preimage = statement
        .signing_preimage()
        .map_err(|_| ReceiptVerificationError::InvalidShape)?;
    let valid = verify_challenge_signature(public_key, &preimage, &receipt.signature_hex)
        .map_err(|_| ReceiptVerificationError::InvalidSignature)?;
    if !valid {
        return Err(ReceiptVerificationError::InvalidSignature);
    }
    Ok(StoredReceiptCandidate {
        key: local.report.key.clone(),
        digest: local.digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_application::delivery::JournalReport;
    use fleet_core::{AgentKeyPair, generate_agent_key_pair, sign_challenge};
    use fleet_domain::delivery::ReportClass;
    use fleet_domain::{
        ControllerSigningPublicKey, ControllerSigningTrustEntry, ControllerSigningTrustRole,
        SigningKeyFingerprint,
    };
    use fleet_protocol::receipt::{ReportDispositionWire, ReportReceiptStatementWire};
    use std::time::Duration;

    fn local() -> PendingReport {
        let key = ReportKey::new("controller-1", "agent-1", "job-1", "task-1", "report-1").unwrap();
        PendingReport {
            report: JournalReport::new(key, ReportClass::Output, b"body".to_vec()).unwrap(),
            digest: ReportDigest([0xaa; 32]),
        }
    }

    fn signed_receipt() -> (
        SignedReportReceiptWire,
        ControllerSigningTrustBundle,
        AgentKeyPair,
    ) {
        let keys = generate_agent_key_pair().unwrap();
        let statement = ReportReceiptStatementWire {
            controller_namespace: "controller-1".into(),
            store_epoch: "epoch-1".into(),
            agent_id: "agent-1".into(),
            job_id: "job-1".into(),
            task_id: "task-1".into(),
            report_id: "report-1".into(),
            digest_hex: "aa".repeat(32),
            signed_at_ms: 1,
            disposition: ReportDispositionWire::Stored,
            signing_key_fingerprint: keys.fingerprint.clone(),
        };
        let signature_hex = sign_challenge(
            &keys.private_key_hex,
            &statement.signing_preimage().unwrap(),
        )
        .unwrap();
        let trust = ControllerSigningTrustBundle::from_legacy_pinned(
            SigningKeyFingerprint::new(keys.fingerprint.clone()).unwrap(),
            ControllerSigningPublicKey::new(keys.public_key_hex.clone()).unwrap(),
        )
        .unwrap();
        (
            SignedReportReceiptWire {
                statement,
                signature_hex,
            },
            trust,
            keys,
        )
    }

    fn verify(
        receipt: &SignedReportReceiptWire,
        trust: &ControllerSigningTrustBundle,
    ) -> Result<StoredReceiptCandidate, ReceiptVerificationError> {
        verify_stored_receipt(
            receipt,
            &local(),
            "controller-1",
            "epoch-1",
            trust,
            SystemTime::UNIX_EPOCH + Duration::from_millis(2),
        )
    }

    #[test]
    fn valid_signed_stored_receipt_returns_exact_local_cleanup_candidate() {
        let (receipt, trust, _) = signed_receipt();
        assert_eq!(
            verify(&receipt, &trust),
            Ok(StoredReceiptCandidate {
                key: local().report.key,
                digest: local().digest
            })
        );
    }

    #[test]
    fn forged_or_wrong_identity_receipts_do_not_authorize_cleanup() {
        let (receipt, trust, keys) = signed_receipt();
        let mut forged = receipt.clone();
        forged.signature_hex = "0".repeat(128);
        assert!(verify(&forged, &trust).is_err());
        assert!(
            verify_stored_receipt(
                &receipt,
                &local(),
                "another-controller",
                "epoch-1",
                &trust,
                SystemTime::UNIX_EPOCH + Duration::from_millis(2)
            )
            .is_err()
        );
        assert_eq!(
            verify_stored_receipt(
                &receipt,
                &local(),
                "controller-1",
                "restored-epoch",
                &trust,
                SystemTime::UNIX_EPOCH + Duration::from_millis(2)
            ),
            Err(ReceiptVerificationError::WrongStoreEpoch),
            "a pre-restore receipt cannot authorize cleanup in the restored epoch"
        );
        assert!(
            verify_stored_receipt(
                &receipt,
                &local(),
                "controller-1",
                "another-epoch",
                &trust,
                SystemTime::UNIX_EPOCH + Duration::from_millis(2)
            )
            .is_err()
        );
        let mut changed = receipt.clone();
        changed.statement.digest_hex = "bb".repeat(32);
        assert!(verify(&changed, &trust).is_err());
        let mut changed = receipt.clone();
        changed.statement.report_id = "other-report".into();
        assert!(verify(&changed, &trust).is_err());
        let mut changed = receipt.clone();
        changed.statement.disposition = ReportDispositionWire::Rejected {
            reason_code: "owner_mismatch".into(),
        };
        changed.signature_hex = sign_challenge(
            &keys.private_key_hex,
            &changed.statement.signing_preimage().unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify(&changed, &trust),
            Err(ReceiptVerificationError::Rejected)
        );
        let mut future = receipt.clone();
        future.statement.signed_at_ms = 3;
        future.signature_hex = sign_challenge(
            &keys.private_key_hex,
            &future.statement.signing_preimage().unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify(&future, &trust),
            Err(ReceiptVerificationError::InvalidSigningTime)
        );
        let other_key = generate_agent_key_pair().unwrap();
        let other_trust = ControllerSigningTrustBundle::from_legacy_pinned(
            SigningKeyFingerprint::new(other_key.fingerprint).unwrap(),
            ControllerSigningPublicKey::new(other_key.public_key_hex).unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify(&receipt, &other_trust),
            Err(ReceiptVerificationError::UntrustedSigner)
        );
    }

    #[test]
    fn previous_signer_is_accepted_only_within_rotation_grace() {
        let (receipt, _, previous_key) = signed_receipt();
        let current_key = generate_agent_key_pair().unwrap();
        let current_fingerprint = current_key.fingerprint.clone();
        let current_public_key = current_key.public_key_hex.clone();
        let trust = ControllerSigningTrustBundle::new(vec![
            ControllerSigningTrustEntry::new(
                ControllerSigningTrustRole::Previous,
                SigningKeyFingerprint::new(previous_key.fingerprint).unwrap(),
                ControllerSigningPublicKey::new(previous_key.public_key_hex).unwrap(),
                SystemTime::UNIX_EPOCH + Duration::from_millis(2),
                Some(SystemTime::UNIX_EPOCH + Duration::from_millis(3)),
            )
            .unwrap(),
            ControllerSigningTrustEntry::new(
                ControllerSigningTrustRole::Current,
                SigningKeyFingerprint::new(current_fingerprint.clone()).unwrap(),
                ControllerSigningPublicKey::new(current_public_key).unwrap(),
                SystemTime::UNIX_EPOCH + Duration::from_millis(2),
                None,
            )
            .unwrap(),
        ])
        .unwrap();
        assert!(verify(&receipt, &trust).is_ok());
        assert_eq!(
            verify_stored_receipt(
                &receipt,
                &local(),
                "controller-1",
                "epoch-1",
                &trust,
                SystemTime::UNIX_EPOCH + Duration::from_millis(4)
            ),
            Err(ReceiptVerificationError::UntrustedSigner)
        );
        let mut current_receipt = receipt;
        current_receipt.statement.signing_key_fingerprint = current_fingerprint;
        current_receipt.statement.signed_at_ms = 2;
        current_receipt.signature_hex = sign_challenge(
            &current_key.private_key_hex,
            &current_receipt.statement.signing_preimage().unwrap(),
        )
        .unwrap();
        assert!(
            verify_stored_receipt(
                &current_receipt,
                &local(),
                "controller-1",
                "epoch-1",
                &trust,
                SystemTime::UNIX_EPOCH + Duration::from_millis(4)
            )
            .is_ok(),
            "current signer remains authorized after previous-key grace expires"
        );
    }
}
