//! Version-2 report and receipt body contract used by active session payloads.
//! Decoding validates shape and content; it does not authenticate a socket or verify a receipt signature.

use crate::receipt::SignedReportReceiptWire;
use crate::{CorrelationId, MessageId, TaskRejectionReasonCode, VersionProbe};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use fleet_domain::delivery::{ReportClass, ReportKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Debug, Display, Formatter};

pub const V2_PROTOCOL_VERSION: u16 = 2;
pub const MAX_REPORT_BODY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_V2_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// Report/receipt-only validation envelope used by the active session adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2WireMessage {
    pub protocol_version: u16,
    pub message_id: MessageId,
    pub correlation_id: CorrelationId,
    pub agent_id: String,
    pub timestamp_ms: u64,
    pub payload: V2WirePayload,
}

impl V2WireMessage {
    pub fn new(
        message_id: impl Into<String>,
        correlation_id: impl Into<String>,
        agent_id: impl Into<String>,
        timestamp_ms: u64,
        payload: V2WirePayload,
    ) -> Self {
        Self {
            protocol_version: V2_PROTOCOL_VERSION,
            message_id: MessageId(message_id.into()),
            correlation_id: CorrelationId(correlation_id.into()),
            agent_id: agent_id.into(),
            timestamp_ms,
            payload,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), V2ProtocolError> {
        if self.protocol_version != V2_PROTOCOL_VERSION {
            return Err(V2ProtocolError::VersionMismatch {
                expected: V2_PROTOCOL_VERSION,
                actual: self.protocol_version,
            });
        }
        if !valid_identity(&self.message_id.0)
            || !valid_identity(&self.correlation_id.0)
            || !valid_identity(&self.agent_id)
        {
            return Err(V2ProtocolError::InvalidIdentity);
        }
        match &self.payload {
            V2WirePayload::TaskReport(report) => {
                report.validate()?;
                if self.agent_id != report.agent_id {
                    return Err(V2ProtocolError::IdentityMismatch);
                }
            }
            V2WirePayload::ReportReceipt(receipt) => {
                receipt
                    .validate_shape()
                    .map_err(|_| V2ProtocolError::InvalidReceipt)?;
                if self.agent_id != receipt.statement.agent_id {
                    return Err(V2ProtocolError::IdentityMismatch);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum V2WirePayload {
    TaskReport(V2TaskReportWire),
    ReportReceipt(SignedReportReceiptWire),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum V2ReportClassWire {
    Lifecycle,
    DriftEvidence,
    Output,
    FinalResult,
}

/// Stable, bounded observation emitted by a persistent DriftCheck task.
/// Controller-owned policy/provenance is deliberately absent from the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2DriftEvidenceReportBody {
    pub status: V2DriftStatusWire,
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum V2DriftStatusWire {
    Compliant,
    Drifted,
    Unknown,
}

/// Strict final-result body used by the active persistent v2 report path.
/// `output` describes the exact per-stream chunk prefix the Agent durably
/// journaled before this final report; it does not promise that every byte
/// produced by the child process was captured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2FinalResultReportBody {
    pub exit_code: i32,
    pub status: crate::TaskResultStatus,
    pub reason: String,
    pub artifacts: Vec<crate::TaskResultArtifactWire>,
    pub output: V2OutputSummary,
}

/// Per-stream output sequence coverage claimed by a final-result report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2OutputSummary {
    pub stdout_chunks: u64,
    pub stderr_chunks: u64,
    pub truncated: bool,
}

/// Lifecycle reports supported by the persistent v2 delivery path.
/// Other lifecycle events remain on their existing control-message path until
/// they receive their own durable effect contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", deny_unknown_fields, rename_all = "snake_case")]
pub enum V2TaskLifecycleReportBody {
    TaskAck {},
    TaskStarted {},
    TaskRejected {
        reason_code: TaskRejectionReasonCode,
        reason: String,
    },
}

impl From<ReportClass> for V2ReportClassWire {
    fn from(value: ReportClass) -> Self {
        match value {
            ReportClass::Lifecycle => Self::Lifecycle,
            ReportClass::DriftEvidence => Self::DriftEvidence,
            ReportClass::Output => Self::Output,
            ReportClass::FinalResult => Self::FinalResult,
        }
    }
}

/// Immutable report payload. `body_base64` and its decoded bytes are sensitive output.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2TaskReportWire {
    pub controller_namespace: String,
    pub agent_id: String,
    pub job_id: String,
    pub task_id: String,
    pub report_id: String,
    pub class: V2ReportClassWire,
    pub digest_hex: String,
    body_base64: String,
}

impl Debug for V2TaskReportWire {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("V2TaskReportWire")
            .field("class", &self.class)
            .field("body_base64", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl V2TaskReportWire {
    pub fn new(key: &ReportKey, class: ReportClass, body: &[u8]) -> Result<Self, V2ProtocolError> {
        if body.is_empty() {
            return Err(V2ProtocolError::EmptyBody);
        }
        if body.len() > MAX_REPORT_BODY_BYTES {
            return Err(V2ProtocolError::BodyTooLarge);
        }
        let [controller, agent, job, task, report] = key.parts();
        Ok(Self {
            controller_namespace: controller.to_owned(),
            agent_id: agent.to_owned(),
            job_id: job.to_owned(),
            task_id: task.to_owned(),
            report_id: report.to_owned(),
            class: class.into(),
            digest_hex: digest_hex(body),
            body_base64: STANDARD.encode(body),
        })
    }

    /// Returns the exact bounded body only after all identity and digest checks.
    pub fn body_bytes(&self) -> Result<Vec<u8>, V2ProtocolError> {
        self.validate()
    }

    fn validate(&self) -> Result<Vec<u8>, V2ProtocolError> {
        ReportKey::new(
            &self.controller_namespace,
            &self.agent_id,
            &self.job_id,
            &self.task_id,
            &self.report_id,
        )
        .map_err(|_| V2ProtocolError::InvalidIdentity)?;
        if self.body_base64.len() > MAX_REPORT_BODY_BYTES.div_ceil(3) * 4 {
            return Err(V2ProtocolError::BodyTooLarge);
        }
        let body = STANDARD
            .decode(&self.body_base64)
            .map_err(|_| V2ProtocolError::InvalidBodyEncoding)?;
        if body.is_empty() {
            return Err(V2ProtocolError::EmptyBody);
        }
        if body.len() > MAX_REPORT_BODY_BYTES {
            return Err(V2ProtocolError::BodyTooLarge);
        }
        if self.digest_hex != digest_hex(&body) {
            return Err(V2ProtocolError::DigestMismatch);
        }
        if self.class == V2ReportClassWire::DriftEvidence
            && serde_json::from_slice::<V2DriftEvidenceReportBody>(&body).is_err()
        {
            return Err(V2ProtocolError::InvalidReportBody);
        }
        Ok(body)
    }
}

fn valid_identity(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn digest_hex(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("String write is infallible");
    }
    encoded
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2ProtocolError {
    Json,
    VersionMismatch { expected: u16, actual: u16 },
    InvalidIdentity,
    IdentityMismatch,
    InvalidBodyEncoding,
    EmptyBody,
    BodyTooLarge,
    DigestMismatch,
    InvalidReportBody,
    InvalidReceipt,
}

impl Display for V2ProtocolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let description = match self {
            Self::Json => "invalid v2 protocol JSON",
            Self::VersionMismatch { .. } => "v2 protocol version mismatch",
            Self::InvalidIdentity => "invalid v2 identity",
            Self::IdentityMismatch => "v2 agent identity mismatch",
            Self::InvalidBodyEncoding => "invalid v2 report body encoding",
            Self::EmptyBody => "empty v2 report body",
            Self::BodyTooLarge => "v2 report body too large",
            Self::DigestMismatch => "v2 report digest mismatch",
            Self::InvalidReportBody => "invalid v2 drift evidence report body",
            Self::InvalidReceipt => "invalid v2 receipt shape",
        };
        formatter.write_str(description)
    }
}

impl std::error::Error for V2ProtocolError {}

pub fn encode_v2_message(message: &V2WireMessage) -> Result<String, V2ProtocolError> {
    message.validate()?;
    let encoded = serde_json::to_string(message).map_err(|_| V2ProtocolError::Json)?;
    if encoded.len() > MAX_V2_MESSAGE_BYTES {
        return Err(V2ProtocolError::BodyTooLarge);
    }
    Ok(encoded)
}

pub fn decode_v2_message(body: &str) -> Result<V2WireMessage, V2ProtocolError> {
    if body.len() > MAX_V2_MESSAGE_BYTES {
        return Err(V2ProtocolError::BodyTooLarge);
    }
    let version: VersionProbe = serde_json::from_str(body).map_err(|_| V2ProtocolError::Json)?;
    if version.protocol_version != V2_PROTOCOL_VERSION {
        return Err(V2ProtocolError::VersionMismatch {
            expected: V2_PROTOCOL_VERSION,
            actual: version.protocol_version,
        });
    }
    let message: V2WireMessage = serde_json::from_str(body).map_err(|_| V2ProtocolError::Json)?;
    message.validate()?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::{
        V2DriftEvidenceReportBody, V2DriftStatusWire, V2FinalResultReportBody, V2OutputSummary,
        V2TaskLifecycleReportBody,
    };
    use crate::TaskResultStatus;

    #[test]
    fn task_ack_lifecycle_body_is_strict_and_stable() {
        let body = serde_json::to_string(&V2TaskLifecycleReportBody::TaskAck {}).unwrap();
        assert_eq!(body, r#"{"event":"task_ack"}"#);
        assert_eq!(
            serde_json::from_str::<V2TaskLifecycleReportBody>(&body).unwrap(),
            V2TaskLifecycleReportBody::TaskAck {}
        );
        assert!(
            serde_json::from_str::<V2TaskLifecycleReportBody>(
                r#"{"event":"task_ack","reason":"unexpected"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn task_started_lifecycle_body_is_strict_and_stable() {
        let body = serde_json::to_string(&V2TaskLifecycleReportBody::TaskStarted {}).unwrap();
        assert_eq!(body, r#"{"event":"task_started"}"#);
        assert_eq!(
            serde_json::from_str::<V2TaskLifecycleReportBody>(&body).unwrap(),
            V2TaskLifecycleReportBody::TaskStarted {}
        );
        assert!(
            serde_json::from_str::<V2TaskLifecycleReportBody>(
                r#"{"event":"task_started","reason":"unexpected"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn task_rejected_lifecycle_body_is_strict_and_stable() {
        let body = r#"{"event":"task_rejected","reason_code":"invalid_signature","reason":"signature check failed"}"#;
        let parsed = serde_json::from_str::<V2TaskLifecycleReportBody>(body);
        assert!(
            parsed.is_ok(),
            "v2 must recognize the TaskRejected report body"
        );
        assert_eq!(serde_json::to_string(&parsed.unwrap()).unwrap(), body);
        assert!(serde_json::from_str::<V2TaskLifecycleReportBody>(
            r#"{"event":"task_rejected","reason_code":"invalid_signature","reason":"signature check failed","extra":true}"#
        ).is_err());
    }

    #[test]
    fn drift_evidence_body_is_strict_and_stable() {
        let body = V2DriftEvidenceReportBody {
            status: V2DriftStatusWire::Drifted,
            expected: "service nginx running".into(),
            actual: "stopped".into(),
        };
        let encoded = serde_json::to_string(&body).unwrap();
        assert_eq!(
            encoded,
            r#"{"status":"drifted","expected":"service nginx running","actual":"stopped"}"#
        );
        assert_eq!(
            serde_json::from_str::<V2DriftEvidenceReportBody>(&encoded).unwrap(),
            body
        );
        assert!(
            serde_json::from_str::<V2DriftEvidenceReportBody>(
                r#"{"status":"drifted","expected":"x","actual":"y","policy_id":"agent-supplied"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<V2DriftEvidenceReportBody>(
                r#"{"status":"unknown-agent-state","expected":"x","actual":"y"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn final_result_body_requires_strict_output_summary() {
        let body = V2FinalResultReportBody {
            exit_code: 0,
            status: TaskResultStatus::Succeeded,
            reason: String::new(),
            artifacts: Vec::new(),
            output: V2OutputSummary {
                stdout_chunks: 2,
                stderr_chunks: 1,
                truncated: false,
            },
        };
        let encoded = serde_json::to_string(&body).unwrap();
        assert_eq!(
            encoded,
            r#"{"exit_code":0,"status":"succeeded","reason":"","artifacts":[],"output":{"stdout_chunks":2,"stderr_chunks":1,"truncated":false}}"#
        );
        assert_eq!(
            serde_json::from_str::<V2FinalResultReportBody>(&encoded).unwrap(),
            body
        );
        assert!(
            serde_json::from_str::<V2FinalResultReportBody>(
                r#"{"exit_code":0,"status":"succeeded","reason":"","artifacts":[]}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<V2FinalResultReportBody>(
            r#"{"exit_code":0,"status":"succeeded","reason":"","artifacts":[],"output":{"stdout_chunks":0,"stderr_chunks":0,"truncated":false,"extra":true}}"#
        )
        .is_err());
    }
}
