//! Protocol-v2 receipt statement contract. No v1 runtime path uses this module.
//! Validation and canonical bytes are not signature verification or deletion authority.

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReportDispositionWire {
    Stored,
    Rejected { reason_code: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportReceiptStatementWire {
    pub controller_namespace: String,
    pub store_epoch: String,
    pub agent_id: String,
    pub job_id: String,
    pub task_id: String,
    pub report_id: String,
    pub digest_hex: String,
    pub signed_at_ms: u64,
    pub disposition: ReportDispositionWire,
    pub signing_key_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReportReceiptWire {
    pub statement: ReportReceiptStatementWire,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptContractError {
    InvalidIdentity,
    InvalidDigest,
    InvalidReason,
    InvalidSignature,
}

impl Display for ReceiptContractError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            Self::InvalidIdentity => "invalid receipt identity",
            Self::InvalidDigest => "invalid receipt digest or signer fingerprint",
            Self::InvalidReason => "invalid receipt rejection reason",
            Self::InvalidSignature => "invalid receipt signature encoding",
        };
        formatter.write_str(reason)
    }
}

impl std::error::Error for ReceiptContractError {}

fn identity_is_valid(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn lowercase_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn framed(value: &str, output: &mut String) {
    output.push_str(&value.len().to_string());
    output.push(':');
    output.push_str(value);
}

impl ReportReceiptStatementWire {
    /// This merely defines bytes to sign; callers still authenticate the signer
    /// against the Agent's pinned trust bundle and compare a locally stored row.
    pub fn signing_preimage(&self) -> Result<String, ReceiptContractError> {
        for value in [
            &self.controller_namespace,
            &self.store_epoch,
            &self.agent_id,
            &self.job_id,
            &self.task_id,
            &self.report_id,
        ] {
            if !identity_is_valid(value) {
                return Err(ReceiptContractError::InvalidIdentity);
            }
        }
        if !lowercase_hex(&self.digest_hex, 64) || !lowercase_hex(&self.signing_key_fingerprint, 64)
        {
            return Err(ReceiptContractError::InvalidDigest);
        }
        let (disposition, reason) = match &self.disposition {
            ReportDispositionWire::Stored => ("stored", ""),
            ReportDispositionWire::Rejected { reason_code } => {
                if reason_code.is_empty()
                    || reason_code.len() > 64
                    || !reason_code.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    })
                {
                    return Err(ReceiptContractError::InvalidReason);
                }
                ("rejected", reason_code.as_str())
            }
        };
        let mut output = String::from("fleet:report-receipt:v2:");
        let signed_at_ms = self.signed_at_ms.to_string();
        for value in [
            &self.controller_namespace,
            &self.store_epoch,
            &self.agent_id,
            &self.job_id,
            &self.task_id,
            &self.report_id,
            &self.digest_hex,
            &signed_at_ms,
            disposition,
            reason,
            &self.signing_key_fingerprint,
        ] {
            framed(value, &mut output);
        }
        Ok(output)
    }
}

impl SignedReportReceiptWire {
    /// Shape validation only. A caller must verify the Ed25519 signature, trust
    /// chain, namespace/epoch and local report before acting on this receipt.
    pub fn validate_shape(&self) -> Result<(), ReceiptContractError> {
        self.statement.signing_preimage()?;
        if !lowercase_hex(&self.signature_hex, 128) {
            return Err(ReceiptContractError::InvalidSignature);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement() -> ReportReceiptStatementWire {
        ReportReceiptStatementWire {
            controller_namespace: "controller-stable-1".into(),
            store_epoch: "epoch-1".into(),
            agent_id: "agent-1".into(),
            job_id: "job-1".into(),
            task_id: "task-1".into(),
            report_id: "report-1".into(),
            digest_hex: "a".repeat(64),
            signed_at_ms: 1,
            disposition: ReportDispositionWire::Stored,
            signing_key_fingerprint: "b".repeat(64),
        }
    }

    #[test]
    fn every_security_field_changes_the_receipt_preimage() {
        let baseline = statement().signing_preimage().unwrap();
        let mut mutations = Vec::new();
        let mut changed = statement();
        changed.controller_namespace.push('2');
        mutations.push(changed);
        let mut changed = statement();
        changed.store_epoch.push('2');
        mutations.push(changed);
        let mut changed = statement();
        changed.agent_id.push('2');
        mutations.push(changed);
        let mut changed = statement();
        changed.job_id.push('2');
        mutations.push(changed);
        let mut changed = statement();
        changed.task_id.push('2');
        mutations.push(changed);
        let mut changed = statement();
        changed.report_id.push('2');
        mutations.push(changed);
        let mut changed = statement();
        changed.digest_hex.replace_range(..1, "c");
        mutations.push(changed);
        let mut changed = statement();
        changed.signed_at_ms += 1;
        mutations.push(changed);
        let mut changed = statement();
        changed.disposition = ReportDispositionWire::Rejected {
            reason_code: "owner_mismatch".into(),
        };
        mutations.push(changed);
        let mut changed = statement();
        changed.signing_key_fingerprint.replace_range(..1, "c");
        mutations.push(changed);
        for changed in mutations {
            assert_ne!(changed.signing_preimage().unwrap(), baseline);
        }
    }

    #[test]
    fn length_prefixing_prevents_field_boundary_ambiguity() {
        let baseline = statement();
        let mut shifted = baseline.clone();
        shifted.controller_namespace = "controller-stable".into();
        shifted.store_epoch = "-1epoch-1".into();
        assert_ne!(
            baseline.signing_preimage().unwrap(),
            shifted.signing_preimage().unwrap()
        );
    }

    #[test]
    fn malformed_identity_digest_and_reason_are_rejected_before_signing() {
        let mut value = statement();
        value.agent_id.clear();
        assert_eq!(
            value.signing_preimage(),
            Err(ReceiptContractError::InvalidIdentity)
        );
        let mut value = statement();
        value.digest_hex = "A".repeat(64);
        assert_eq!(
            value.signing_preimage(),
            Err(ReceiptContractError::InvalidDigest)
        );
        let mut value = statement();
        value.disposition = ReportDispositionWire::Rejected {
            reason_code: "raw\nbody".into(),
        };
        assert_eq!(
            value.signing_preimage(),
            Err(ReceiptContractError::InvalidReason)
        );
    }

    #[test]
    fn signed_wire_roundtrips_but_invalid_signature_shape_is_rejected() {
        let receipt = SignedReportReceiptWire {
            statement: statement(),
            signature_hex: "c".repeat(128),
        };
        receipt.validate_shape().unwrap();
        let body = serde_json::to_string(&receipt).unwrap();
        assert_eq!(
            serde_json::from_str::<SignedReportReceiptWire>(&body).unwrap(),
            receipt
        );
        let mut malformed = receipt;
        malformed.signature_hex = "NOT_A_SIGNATURE".into();
        assert_eq!(
            malformed.validate_shape(),
            Err(ReceiptContractError::InvalidSignature)
        );
    }
}
