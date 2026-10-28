//! Versioned Controller-Agent JSON contracts.
//!
//! The active session envelope is v2 and includes bounded report/receipt
//! payloads. The authenticated SQLite Controller handles output and a limited
//! no-artifact final-result subset. Persistent Command Agents journal those
//! reports before send and clean them only after exact signed stored receipts;
//! lifecycle, artifact/follow-up, one-shot and runbook/drift reports remain
//! outside that durable path.

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

pub mod delivery_v2;
pub mod receipt;

pub const PROTOCOL_VERSION: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMessage {
    pub protocol_version: u16,
    pub message_id: MessageId,
    pub correlation_id: CorrelationId,
    pub agent_id: Option<String>,
    pub timestamp_ms: u64,
    pub payload: WirePayload,
}

impl WireMessage {
    pub fn new(
        message_id: impl Into<String>,
        correlation_id: impl Into<String>,
        agent_id: Option<String>,
        timestamp_ms: u64,
        payload: WirePayload,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            message_id: MessageId(message_id.into()),
            correlation_id: CorrelationId(correlation_id.into()),
            agent_id,
            timestamp_ms,
            payload,
        }
    }

    pub fn validate_version(&self) -> Result<(), ProtocolError> {
        if self.protocol_version == PROTOCOL_VERSION {
            Ok(())
        } else {
            Err(ProtocolError::VersionMismatch {
                expected: PROTOCOL_VERSION,
                actual: self.protocol_version,
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum WirePayload {
    EnrollRequest {
        agent_name: String,
        token: String,
        public_key: String,
        fingerprint: String,
        labels: Vec<WireLabel>,
    },
    EnrollResponse {
        agent_id: String,
        controller_public_key: String,
        controller_fingerprint: String,
    },
    AgentHello {
        agent_id: String,
        fingerprint: String,
    },
    AuthChallenge {
        nonce: String,
    },
    AuthResponse {
        nonce: String,
        signature: String,
    },
    AuthAccepted {
        controller_namespace: String,
        store_epoch: String,
    },
    TaskReport(delivery_v2::V2TaskReportWire),
    ReportReceipt(receipt::SignedReportReceiptWire),
    Heartbeat {
        agent_id: String,
        status: String,
    },
    ControllerSigningTrustBundleUpdate {
        entries: Vec<ControllerSigningTrustEntryWire>,
    },
    ControllerSigningTrustBundleAck {
        agent_id: String,
        accepted: bool,
        current_fingerprint: Option<String>,
        entries_count: usize,
        reason_code: Option<String>,
    },
    AgentCertificateLifecycleUpdate {
        agent_id: String,
        action: AgentCertificateLifecycleActionWire,
        state: AgentCertificateLifecycleStateWire,
        current_certificate: Option<AgentCertificateMetadataWire>,
        next_certificate: Option<AgentCertificateMetadataWire>,
        grace_until_ms: Option<u64>,
        reason_code: Option<String>,
    },
    AgentCertificateLifecycleAck {
        agent_id: String,
        accepted: bool,
        state: AgentCertificateLifecycleStateWire,
        current_fingerprint: Option<String>,
        reason_code: Option<String>,
    },
    TaskAssignment {
        envelope: SignedTaskEnvelopeWire,
        task: TaskWire,
    },
    TaskAck {
        job_id: String,
        task_id: String,
    },
    TaskStarted {
        job_id: String,
        task_id: String,
    },
    TaskRejected {
        job_id: String,
        task_id: String,
        reason_code: TaskRejectionReasonCode,
        reason: String,
    },
    TaskCancel {
        job_id: String,
        task_id: String,
        reason: String,
    },
    OutputChunk {
        job_id: String,
        task_id: String,
        stream: OutputStream,
        sequence: u64,
        data: String,
    },
    TaskResult {
        job_id: String,
        task_id: String,
        exit_code: i32,
        #[serde(default)]
        status: Option<TaskResultStatus>,
        #[serde(default)]
        reason: String,
        #[serde(default)]
        artifacts: Vec<TaskResultArtifactWire>,
    },
    SecurityEvent {
        agent_id: String,
        action: String,
        detail: String,
    },
    FactsSnapshot {
        agent_id: String,
        body: String,
    },
    MetricsSnapshot {
        agent_id: String,
        body: String,
    },
    CapabilitySnapshot {
        agent_id: String,
        privilege_level: CapabilityPrivilegeLevelWire,
        package_manager: Option<PackageManagerWire>,
        service_manager: Option<ServiceManagerWire>,
        capabilities: Vec<String>,
        reported_at_ms: u64,
    },
    LogChunk {
        agent_id: String,
        line: String,
    },
    DriftReport {
        agent_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        job_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        task_id: Option<String>,
        status: String,
        expected: String,
        actual: String,
    },
}

impl WirePayload {
    pub fn channel(&self) -> ProtocolChannel {
        match self {
            Self::EnrollRequest { .. }
            | Self::EnrollResponse { .. }
            | Self::AgentHello { .. }
            | Self::AuthChallenge { .. }
            | Self::AuthResponse { .. }
            | Self::AuthAccepted { .. }
            | Self::Heartbeat { .. } => ProtocolChannel::AuthSession,
            Self::ControllerSigningTrustBundleUpdate { .. }
            | Self::ControllerSigningTrustBundleAck { .. }
            | Self::AgentCertificateLifecycleUpdate { .. }
            | Self::AgentCertificateLifecycleAck { .. }
            | Self::TaskAssignment { .. }
            | Self::TaskAck { .. }
            | Self::TaskStarted { .. }
            | Self::TaskRejected { .. }
            | Self::TaskCancel { .. }
            | Self::TaskReport(_)
            | Self::ReportReceipt(_)
            | Self::OutputChunk { .. }
            | Self::TaskResult { .. }
            | Self::SecurityEvent { .. }
            | Self::FactsSnapshot { .. }
            | Self::MetricsSnapshot { .. }
            | Self::CapabilitySnapshot { .. }
            | Self::LogChunk { .. }
            | Self::DriftReport { .. } => ProtocolChannel::TaskData,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolChannel {
    AuthSession,
    TaskData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireLabel {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityPrivilegeLevelWire {
    Unprivileged,
    SudoAvailable,
    Root,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageManagerWire {
    Apt,
    Dnf,
    Yum,
    Apk,
    Brew,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceManagerWire {
    Systemd,
    Launchd,
    OpenRc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerSigningTrustEntryWire {
    pub fingerprint: String,
    pub public_key: String,
    pub role: ControllerSigningTrustRoleWire,
    pub valid_from_ms: u64,
    pub valid_until_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControllerSigningTrustRoleWire {
    Current,
    Previous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCertificateMetadataWire {
    pub serial: String,
    pub fingerprint: String,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCertificateLifecycleActionWire {
    RequestIssuance,
    Issue,
    RequestRenewal,
    ActivateRenewal,
    CompleteRotation,
    Revoke,
    Expire,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCertificateLifecycleStateWire {
    NotIssued,
    IssuanceRequested,
    Issued,
    RenewalRequested,
    DualCertificateActive,
    Revoked,
    Expired,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTaskEnvelopeWire {
    pub job_id: String,
    pub task_id: String,
    pub target_agent_id: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub nonce: String,
    pub payload_hash: String,
    pub signature: String,
}

impl SignedTaskEnvelopeWire {
    pub fn targets_agent(&self, agent_id: &str) -> bool {
        self.target_agent_id == agent_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum TaskWire {
    Command(CommandTaskWire),
    DriftCheck(DriftCheckTaskWire),
    RunbookExecution(RunbookExecutionTaskWire),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandTaskWire {
    pub program: String,
    pub args: Vec<String>,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftCheckTaskWire {
    pub policy_document: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookExecutionTaskWire {
    pub runbook_document: String,
    pub timeout_ms: u64,
    pub confirmed_high_risk: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskRejectionReasonCode {
    AgentBusy,
    InvalidSignature,
    Expired,
    Replay,
    TargetMismatch,
    InvalidTask,
    CapabilityUnsupported,
    LocalPolicy,
    InternalError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskResultStatus {
    Succeeded,
    Failed,
    Canceled,
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskResultArtifactWire {
    pub artifact_id: String,
    pub step_id: String,
    pub destination: String,
    pub checksum_sha256: String,
    pub size_bytes: u64,
    pub retention_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    Json(String),
    VersionMismatch { expected: u16, actual: u16 },
    InvalidV2Payload(crate::delivery_v2::V2ProtocolError),
    MessageTooLarge,
}

impl Display for ProtocolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "protocol json error: {error}"),
            Self::VersionMismatch { expected, actual } => {
                write!(
                    formatter,
                    "protocol version mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::InvalidV2Payload(error) => {
                write!(formatter, "invalid v2 delivery payload: {error}")
            }
            Self::MessageTooLarge => formatter.write_str("protocol message exceeds size limit"),
        }
    }
}

impl std::error::Error for ProtocolError {}

pub fn encode_message(message: &WireMessage) -> Result<String, ProtocolError> {
    message.validate_version()?;
    validate_v2_delivery_payload(message)?;
    let encoded =
        serde_json::to_string(message).map_err(|error| ProtocolError::Json(error.to_string()))?;
    if encoded.len() > crate::delivery_v2::MAX_V2_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge);
    }
    Ok(encoded)
}

pub fn decode_message(body: &str) -> Result<WireMessage, ProtocolError> {
    if body.len() > crate::delivery_v2::MAX_V2_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge);
    }
    let version: VersionProbe =
        serde_json::from_str(body).map_err(|error| ProtocolError::Json(error.to_string()))?;
    if version.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch {
            expected: PROTOCOL_VERSION,
            actual: version.protocol_version,
        });
    }
    let message: WireMessage =
        serde_json::from_str(body).map_err(|error| ProtocolError::Json(error.to_string()))?;
    message.validate_version()?;
    validate_v2_delivery_payload(&message)?;
    Ok(message)
}

fn validate_v2_delivery_payload(message: &WireMessage) -> Result<(), ProtocolError> {
    let payload = match &message.payload {
        WirePayload::TaskReport(report) => Some(crate::delivery_v2::V2WirePayload::TaskReport(
            report.clone(),
        )),
        WirePayload::ReportReceipt(receipt) => Some(
            crate::delivery_v2::V2WirePayload::ReportReceipt(receipt.clone()),
        ),
        _ => None,
    };
    let Some(payload) = payload else {
        return Ok(());
    };
    let agent_id = message.agent_id.clone().ok_or({
        ProtocolError::InvalidV2Payload(crate::delivery_v2::V2ProtocolError::InvalidIdentity)
    })?;
    crate::delivery_v2::V2WireMessage {
        protocol_version: message.protocol_version,
        message_id: message.message_id.clone(),
        correlation_id: message.correlation_id.clone(),
        agent_id,
        timestamp_ms: message.timestamp_ms,
        payload,
    }
    .validate()
    .map_err(ProtocolError::InvalidV2Payload)
}

#[derive(Deserialize)]
pub(crate) struct VersionProbe {
    pub protocol_version: u16,
}

pub fn protocol_version() -> u16 {
    PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery_v2::{
        V2ProtocolError, V2TaskReportWire, V2WireMessage, V2WirePayload, decode_v2_message,
        encode_v2_message,
    };
    use fleet_domain::delivery::{ReportClass, ReportKey};

    fn heartbeat() -> WireMessage {
        WireMessage::new(
            "msg-1",
            "corr-1",
            Some("agent-1".to_owned()),
            1,
            WirePayload::Heartbeat {
                agent_id: "agent-1".to_owned(),
                status: "online".to_owned(),
            },
        )
    }

    #[test]
    fn exposes_protocol_version() {
        assert_eq!(protocol_version(), 2);
    }

    #[test]
    fn v2_report_roundtrips_without_legacy_fallback() {
        let key = ReportKey::new("controller-1", "agent-1", "job-1", "task-1", "report-1").unwrap();
        let report =
            V2TaskReportWire::new(&key, ReportClass::FinalResult, b"secret-body-marker").unwrap();
        assert_eq!(report.body_bytes().unwrap(), b"secret-body-marker");
        let message = V2WireMessage::new(
            "msg-v2",
            "corr-v2",
            "agent-1",
            10,
            V2WirePayload::TaskReport(report),
        );
        let encoded = encode_v2_message(&message).unwrap();
        assert_eq!(decode_v2_message(&encoded).unwrap(), message);
        assert!(!format!("{message:?}").contains("secret-body-marker"));
        assert!(!format!("{message:?}").contains("c2VjcmV0LWJvZHktbWFya2Vy"));
        let session_message = decode_message(&encoded).unwrap();
        assert_eq!(session_message.agent_id.as_deref(), Some("agent-1"));
        assert!(matches!(
            session_message.payload,
            WirePayload::TaskReport(_)
        ));
        let legacy = encode_message(&heartbeat()).unwrap();
        assert!(matches!(
            decode_v2_message(&legacy),
            Err(V2ProtocolError::Json)
        ));
    }

    #[test]
    fn v2_report_rejects_wrong_owner_digest_and_oversize_body() {
        let key = ReportKey::new("controller-1", "agent-1", "job-1", "task-1", "report-1").unwrap();
        let report = V2TaskReportWire::new(&key, ReportClass::Output, b"output").unwrap();
        let message = V2WireMessage::new(
            "msg-v2",
            "corr-v2",
            "agent-1",
            10,
            V2WirePayload::TaskReport(report),
        );
        let mut value: serde_json::Value =
            serde_json::from_str(&encode_v2_message(&message).unwrap()).unwrap();
        value["agent_id"] = "agent-2".into();
        assert_eq!(
            decode_v2_message(&value.to_string()),
            Err(V2ProtocolError::IdentityMismatch)
        );
        value["agent_id"] = "agent-1".into();
        value["payload"]["payload"]["digest_hex"] = "0".repeat(64).into();
        assert_eq!(
            decode_v2_message(&value.to_string()),
            Err(V2ProtocolError::DigestMismatch)
        );
        assert_eq!(
            V2TaskReportWire::new(&key, ReportClass::Output, &vec![0; 4 * 1024 * 1024 + 1]),
            Err(V2ProtocolError::BodyTooLarge)
        );
        assert_eq!(
            V2TaskReportWire::new(&key, ReportClass::Output, b""),
            Err(V2ProtocolError::EmptyBody)
        );
    }

    #[test]
    fn v2_decoder_rejects_invalid_report_encoding_and_unknown_payload() {
        let key = ReportKey::new("controller-1", "agent-1", "job-1", "task-1", "report-1").unwrap();
        let report = V2TaskReportWire::new(&key, ReportClass::Lifecycle, b"accepted").unwrap();
        let message = V2WireMessage::new(
            "msg-v2",
            "corr-v2",
            "agent-1",
            10,
            V2WirePayload::TaskReport(report),
        );
        let mut value: serde_json::Value =
            serde_json::from_str(&encode_v2_message(&message).unwrap()).unwrap();
        value["payload"]["payload"]["body_base64"] = "not base64".into();
        assert_eq!(
            decode_v2_message(&value.to_string()),
            Err(V2ProtocolError::InvalidBodyEncoding)
        );
        value["payload"]["type"] = "task_result".into();
        assert_eq!(
            decode_v2_message(&value.to_string()),
            Err(V2ProtocolError::Json)
        );
        value["protocol_version"] = 1.into();
        assert_eq!(
            decode_v2_message(&value.to_string()),
            Err(V2ProtocolError::VersionMismatch {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn v2_signed_receipt_roundtrips_but_shape_and_owner_are_checked() {
        use crate::receipt::{
            ReportDispositionWire, ReportReceiptStatementWire, SignedReportReceiptWire,
        };
        let receipt = SignedReportReceiptWire {
            statement: ReportReceiptStatementWire {
                controller_namespace: "controller-1".into(),
                store_epoch: "epoch-1".into(),
                agent_id: "agent-1".into(),
                job_id: "job-1".into(),
                task_id: "task-1".into(),
                report_id: "report-1".into(),
                digest_hex: "a".repeat(64),
                signed_at_ms: 10,
                disposition: ReportDispositionWire::Stored,
                signing_key_fingerprint: "b".repeat(64),
            },
            signature_hex: "c".repeat(128),
        };
        let message = V2WireMessage::new(
            "receipt-v2",
            "corr-v2",
            "agent-1",
            11,
            V2WirePayload::ReportReceipt(receipt),
        );
        let encoded = encode_v2_message(&message).unwrap();
        assert_eq!(decode_v2_message(&encoded).unwrap(), message);
        let session_message = decode_message(&encoded).unwrap();
        assert_eq!(session_message.agent_id.as_deref(), Some("agent-1"));
        assert!(matches!(
            session_message.payload,
            WirePayload::ReportReceipt(_)
        ));
        let mut value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        value["agent_id"] = "agent-2".into();
        assert_eq!(
            decode_v2_message(&value.to_string()),
            Err(V2ProtocolError::IdentityMismatch)
        );
        value["agent_id"] = "agent-1".into();
        value["payload"]["payload"]["signature_hex"] = "bad".into();
        assert_eq!(
            decode_v2_message(&value.to_string()),
            Err(V2ProtocolError::InvalidReceipt)
        );
    }

    #[test]
    fn serializes_and_deserializes_wire_message() {
        let encoded = encode_message(&heartbeat()).unwrap();
        let decoded = decode_message(&encoded).unwrap();

        assert_eq!(decoded, heartbeat());
        assert!(encoded.contains("\"protocol_version\":2"));
        assert!(encoded.contains("\"heartbeat\""));
    }

    #[test]
    fn drift_report_legacy_fixture_decodes_without_task_correlation() {
        let body = r#"{
            "protocol_version": 2,
            "message_id": "msg-drift-legacy",
            "correlation_id": "corr-drift-legacy",
            "agent_id": "agent-1",
            "timestamp_ms": 1,
            "payload": {
                "type": "drift_report",
                "payload": {
                    "agent_id": "agent-1",
                    "status": "drifted",
                    "expected": "package nginx present",
                    "actual": "package nginx missing"
                }
            }
        }"#;

        let decoded = decode_message(body).unwrap();
        assert!(!encode_message(&decoded).unwrap().contains("\"job_id\""));
        let WirePayload::DriftReport {
            job_id, task_id, ..
        } = decoded.payload
        else {
            panic!("expected drift report");
        };

        assert_eq!(job_id, None);
        assert_eq!(task_id, None);
    }

    #[test]
    fn drift_report_with_task_correlation_roundtrips() {
        let message = WireMessage::new(
            "msg-drift-correlated",
            "corr-drift-correlated",
            Some("agent-1".to_owned()),
            1,
            WirePayload::DriftReport {
                agent_id: "agent-1".to_owned(),
                job_id: Some("job-drift".to_owned()),
                task_id: Some("task-drift".to_owned()),
                status: "drifted".to_owned(),
                expected: "package nginx present".to_owned(),
                actual: "package nginx missing".to_owned(),
            },
        );

        assert_eq!(
            decode_message(&encode_message(&message).unwrap()).unwrap(),
            message
        );
    }

    #[test]
    fn rejects_malformed_payload() {
        assert!(matches!(
            decode_message("{not-json"),
            Err(ProtocolError::Json(_))
        ));
    }

    #[test]
    fn rejects_unknown_message_type() {
        let body = r#"{
            "protocol_version": 2,
            "message_id": "msg-1",
            "correlation_id": "corr-1",
            "agent_id": "agent-1",
            "timestamp_ms": 1,
            "payload": {
                "type": "unknown_message",
                "payload": {}
            }
        }"#;

        assert!(matches!(decode_message(body), Err(ProtocolError::Json(_))));
    }

    #[test]
    fn rejects_protocol_version_mismatch() {
        let mut message = heartbeat();
        message.protocol_version = 999;

        assert_eq!(
            encode_message(&message),
            Err(ProtocolError::VersionMismatch {
                expected: 2,
                actual: 999,
            })
        );
    }

    #[test]
    fn rejects_v1_session_message_after_protocol_hard_cut() {
        let body = r#"{
            "protocol_version": 1,
            "message_id": "msg-legacy",
            "correlation_id": "corr-legacy",
            "agent_id": "agent-1",
            "timestamp_ms": 1,
            "payload": {
                "type": "heartbeat",
                "payload": { "agent_id": "agent-1", "status": "online" }
            }
        }"#;

        assert!(matches!(
            decode_message(body),
            Err(ProtocolError::VersionMismatch {
                expected: 2,
                actual: 1
            })
        ));
    }

    #[test]
    fn rejects_v1_controller_auth_acceptance_after_protocol_hard_cut() {
        let body = r#"{
            "protocol_version": 1,
            "message_id": "msg-legacy-accepted",
            "correlation_id": "corr-legacy-accepted",
            "agent_id": "agent-1",
            "timestamp_ms": 1,
            "payload": { "type": "auth_accepted", "payload": {} }
        }"#;

        assert!(matches!(
            decode_message(body),
            Err(ProtocolError::VersionMismatch {
                expected: 2,
                actual: 1
            })
        ));
    }

    #[test]
    fn v2_auth_acceptance_requires_delivery_identity() {
        let body = r#"{
            "protocol_version": 2,
            "message_id": "msg-missing-identity",
            "correlation_id": "corr-missing-identity",
            "agent_id": "agent-1",
            "timestamp_ms": 1,
            "payload": { "type": "auth_accepted", "payload": {} }
        }"#;

        assert!(matches!(decode_message(body), Err(ProtocolError::Json(_))));
    }

    #[test]
    fn legacy_hello_ignores_unknown_delivery_capability_without_negotiating_it() {
        let hello = WireMessage::new(
            "msg-hello",
            "corr-hello",
            Some("agent-1".to_owned()),
            1,
            WirePayload::AgentHello {
                agent_id: "agent-1".to_owned(),
                fingerprint: "public-fingerprint".to_owned(),
            },
        );
        let mut body = serde_json::to_value(&hello).unwrap();
        body["payload"]["payload"]["delivery_capabilities"] =
            serde_json::json!(["test-only-future-receipt"]);

        let decoded = decode_message(&body.to_string()).unwrap();

        assert_eq!(decoded, hello);
        assert!(
            !encode_message(&decoded)
                .unwrap()
                .contains("delivery_capabilities")
        );
    }

    #[test]
    fn auth_challenge_roundtrips() {
        let message = WireMessage::new(
            "msg-auth",
            "corr-auth",
            Some("agent-1".to_owned()),
            1,
            WirePayload::AuthChallenge {
                nonce: "nonce-1".to_owned(),
            },
        );

        assert_eq!(
            decode_message(&encode_message(&message).unwrap()).unwrap(),
            message
        );
    }

    #[test]
    fn auth_accepted_roundtrips_controller_delivery_identity() {
        let message = WireMessage::new(
            "msg-auth-accepted",
            "corr-auth-accepted",
            Some("agent-1".to_owned()),
            2,
            WirePayload::AuthAccepted {
                controller_namespace: "a".repeat(64),
                store_epoch: "b".repeat(64),
            },
        );

        let encoded = encode_message(&message).unwrap();

        assert_eq!(decode_message(&encoded).unwrap(), message);
        assert!(encoded.contains("\"protocol_version\":2"));
    }

    #[test]
    fn active_v2_report_payloads_roundtrip_through_session_envelope() {
        use crate::receipt::{
            ReportDispositionWire, ReportReceiptStatementWire, SignedReportReceiptWire,
        };

        let key = ReportKey::new("controller-1", "agent-1", "job-1", "task-1", "report-1").unwrap();
        let report = V2TaskReportWire::new(&key, ReportClass::Output, b"stdout bytes").unwrap();
        let report_message = WireMessage::new(
            "msg-report",
            "corr-report",
            Some("agent-1".to_owned()),
            10,
            WirePayload::TaskReport(report),
        );

        let receipt = SignedReportReceiptWire {
            statement: ReportReceiptStatementWire {
                controller_namespace: "controller-1".into(),
                store_epoch: "epoch-1".into(),
                agent_id: "agent-1".into(),
                job_id: "job-1".into(),
                task_id: "task-1".into(),
                report_id: "report-1".into(),
                digest_hex: "a".repeat(64),
                signed_at_ms: 11,
                disposition: ReportDispositionWire::Stored,
                signing_key_fingerprint: "b".repeat(64),
            },
            signature_hex: "c".repeat(128),
        };
        let receipt_message = WireMessage::new(
            "msg-receipt",
            "corr-receipt",
            Some("agent-1".to_owned()),
            11,
            WirePayload::ReportReceipt(receipt),
        );

        for message in [report_message, receipt_message] {
            let encoded = encode_message(&message).unwrap();
            assert_eq!(decode_message(&encoded).unwrap(), message);
            assert_eq!(decode_v2_message(&encoded).unwrap().agent_id, "agent-1");
        }
    }

    #[test]
    fn active_v2_report_envelope_validates_body_digest_and_owner() {
        let key = ReportKey::new("controller-1", "agent-1", "job-1", "task-1", "report-1").unwrap();
        let report = V2TaskReportWire::new(&key, ReportClass::Output, b"stdout bytes").unwrap();
        let message = WireMessage::new(
            "msg-report",
            "corr-report",
            Some("agent-1".to_owned()),
            10,
            WirePayload::TaskReport(report),
        );
        let encoded = encode_message(&message).unwrap();

        let mut wrong_digest: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        wrong_digest["payload"]["payload"]["digest_hex"] = "0".repeat(64).into();
        assert_eq!(
            decode_message(&wrong_digest.to_string()),
            Err(ProtocolError::InvalidV2Payload(
                V2ProtocolError::DigestMismatch
            ))
        );

        let mut wrong_owner: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        wrong_owner["agent_id"] = "agent-2".into();
        assert_eq!(
            decode_message(&wrong_owner.to_string()),
            Err(ProtocolError::InvalidV2Payload(
                V2ProtocolError::IdentityMismatch
            ))
        );
    }

    #[test]
    fn active_session_message_size_is_bounded() {
        let body = " ".repeat(crate::delivery_v2::MAX_V2_MESSAGE_BYTES + 1);
        assert_eq!(decode_message(&body), Err(ProtocolError::MessageTooLarge));

        let message = WireMessage::new(
            "msg-large",
            "corr-large",
            Some("agent-1".to_owned()),
            1,
            WirePayload::Heartbeat {
                agent_id: "agent-1".to_owned(),
                status: "x".repeat(crate::delivery_v2::MAX_V2_MESSAGE_BYTES + 1),
            },
        );
        assert_eq!(
            encode_message(&message),
            Err(ProtocolError::MessageTooLarge)
        );
    }

    #[test]
    fn signed_task_envelope_serializes_target_agent() {
        let message = WireMessage::new(
            "msg-task",
            "corr-task",
            Some("agent-1".to_owned()),
            1,
            WirePayload::TaskAssignment {
                envelope: SignedTaskEnvelopeWire {
                    job_id: "job-1".to_owned(),
                    task_id: "task-1".to_owned(),
                    target_agent_id: "agent-1".to_owned(),
                    issued_at_ms: 1,
                    expires_at_ms: 60_000,
                    nonce: "nonce-1".to_owned(),
                    payload_hash: "hash".to_owned(),
                    signature: "sig".to_owned(),
                },
                task: TaskWire::Command(CommandTaskWire {
                    program: "uptime".to_owned(),
                    args: Vec::new(),
                    timeout_ms: 30_000,
                    max_output_bytes: 1024,
                }),
            },
        );

        let decoded = decode_message(&encode_message(&message).unwrap()).unwrap();
        let WirePayload::TaskAssignment { envelope, task } = decoded.payload else {
            panic!("expected task assignment");
        };

        assert!(envelope.targets_agent("agent-1"));
        assert!(!envelope.targets_agent("agent-2"));
        assert!(matches!(task, TaskWire::Command(_)));
    }

    #[test]
    fn drift_check_task_roundtrips() {
        let message = WireMessage::new(
            "msg-drift",
            "corr-drift",
            Some("agent-1".to_owned()),
            1,
            WirePayload::TaskAssignment {
                envelope: SignedTaskEnvelopeWire {
                    job_id: "job-drift".to_owned(),
                    task_id: "task-drift".to_owned(),
                    target_agent_id: "agent-1".to_owned(),
                    issued_at_ms: 1,
                    expires_at_ms: 60_000,
                    nonce: "nonce-drift".to_owned(),
                    payload_hash: "hash".to_owned(),
                    signature: "sig".to_owned(),
                },
                task: TaskWire::DriftCheck(DriftCheckTaskWire {
                    policy_document: "apiVersion: fleet.sponzey.dev/v1alpha1".to_owned(),
                }),
            },
        );

        let decoded = decode_message(&encode_message(&message).unwrap()).unwrap();
        let WirePayload::TaskAssignment { task, .. } = decoded.payload else {
            panic!("expected task assignment");
        };

        assert!(matches!(task, TaskWire::DriftCheck(_)));
    }

    #[test]
    fn runbook_execution_task_roundtrips() {
        let message = WireMessage::new(
            "msg-runbook",
            "corr-runbook",
            Some("agent-1".to_owned()),
            1,
            WirePayload::TaskAssignment {
                envelope: SignedTaskEnvelopeWire {
                    job_id: "job-runbook".to_owned(),
                    task_id: "task-runbook".to_owned(),
                    target_agent_id: "agent-1".to_owned(),
                    issued_at_ms: 1,
                    expires_at_ms: 60_000,
                    nonce: "nonce-runbook".to_owned(),
                    payload_hash: "hash".to_owned(),
                    signature: "sig".to_owned(),
                },
                task: TaskWire::RunbookExecution(RunbookExecutionTaskWire {
                    runbook_document: "apiVersion: fleet.sponzey.dev/v1alpha1".to_owned(),
                    timeout_ms: 30_000,
                    confirmed_high_risk: true,
                }),
            },
        );

        let decoded = decode_message(&encode_message(&message).unwrap()).unwrap();
        let WirePayload::TaskAssignment { task, .. } = decoded.payload else {
            panic!("expected task assignment");
        };

        assert!(matches!(task, TaskWire::RunbookExecution(_)));
    }

    #[test]
    fn task_lifecycle_events_roundtrip() {
        for payload in [
            WirePayload::TaskAck {
                job_id: "job-1".to_owned(),
                task_id: "task-1".to_owned(),
            },
            WirePayload::TaskStarted {
                job_id: "job-1".to_owned(),
                task_id: "task-1".to_owned(),
            },
            WirePayload::TaskRejected {
                job_id: "job-1".to_owned(),
                task_id: "task-1".to_owned(),
                reason_code: TaskRejectionReasonCode::InvalidSignature,
                reason: "signature verification failed".to_owned(),
            },
            WirePayload::TaskCancel {
                job_id: "job-1".to_owned(),
                task_id: "task-1".to_owned(),
                reason: "operator requested cancel".to_owned(),
            },
            WirePayload::TaskResult {
                job_id: "job-1".to_owned(),
                task_id: "task-1".to_owned(),
                exit_code: 0,
                status: Some(TaskResultStatus::Succeeded),
                reason: String::new(),
                artifacts: vec![TaskResultArtifactWire {
                    artifact_id: "artifact-1".to_owned(),
                    step_id: "template:template".to_owned(),
                    destination: "/etc/app.conf".to_owned(),
                    checksum_sha256:
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_owned(),
                    size_bytes: 42,
                    retention_class: "rendered_template".to_owned(),
                    content_bytes: None,
                }],
            },
        ] {
            let message = WireMessage::new(
                "msg-task-event",
                "task-1",
                Some("agent-1".to_owned()),
                1,
                payload.clone(),
            );

            let decoded = decode_message(&encode_message(&message).unwrap()).unwrap();

            assert_eq!(decoded.payload, payload);
            assert_eq!(decoded.payload.channel(), ProtocolChannel::TaskData);
        }
    }

    #[test]
    fn legacy_task_result_without_status_still_decodes() {
        let body = r#"{
            "protocol_version": 2,
            "message_id":"msg-result",
            "correlation_id":"corr-result",
            "agent_id":"agent-1",
            "timestamp_ms":1,
            "payload":{
                "type":"task_result",
                "payload":{
                    "job_id":"job-1",
                    "task_id":"task-1",
                    "exit_code":0
                }
            }
        }"#;

        let decoded = decode_message(body).unwrap();
        let WirePayload::TaskResult {
            status,
            reason,
            artifacts,
            ..
        } = decoded.payload
        else {
            panic!("expected task result");
        };

        assert_eq!(status, None);
        assert_eq!(reason, "");
        assert!(artifacts.is_empty());
    }

    #[test]
    fn legacy_task_result_artifact_without_body_still_decodes() {
        let body = r#"{
            "protocol_version": 2,
            "message_id":"msg-result",
            "correlation_id":"corr-result",
            "agent_id":"agent-1",
            "timestamp_ms":1,
            "payload":{
                "type":"task_result",
                "payload":{
                    "job_id":"job-1",
                    "task_id":"task-1",
                    "exit_code":0,
                    "artifacts":[{
                        "artifact_id":"artifact-1",
                        "step_id":"template:template",
                        "destination":"/etc/app.conf",
                        "checksum_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "size_bytes":42,
                        "retention_class":"rendered_template"
                    }]
                }
            }
        }"#;

        let decoded = decode_message(body).unwrap();
        let WirePayload::TaskResult { artifacts, .. } = decoded.payload else {
            panic!("expected task result");
        };

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].artifact_id, "artifact-1");
        assert_eq!(artifacts[0].content_bytes, None);
    }

    #[test]
    fn task_result_artifact_body_roundtrips() {
        let message = WireMessage::new(
            "msg-result",
            "corr-result",
            Some("agent-1".to_owned()),
            1,
            WirePayload::TaskResult {
                job_id: "job-1".to_owned(),
                task_id: "task-1".to_owned(),
                exit_code: 0,
                status: Some(TaskResultStatus::Succeeded),
                reason: String::new(),
                artifacts: vec![TaskResultArtifactWire {
                    artifact_id: "artifact-1".to_owned(),
                    step_id: "template:template".to_owned(),
                    destination: "/etc/app.conf".to_owned(),
                    checksum_sha256:
                        "3f8a286ab667f1b60da3a12c138461dac343cab1eb3928c433a8062a61d417f8"
                            .to_owned(),
                    size_bytes: 5,
                    retention_class: "rendered_template".to_owned(),
                    content_bytes: Some(b"hello".to_vec()),
                }],
            },
        );

        let encoded = encode_message(&message).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        let WirePayload::TaskResult { artifacts, .. } = decoded.payload else {
            panic!("expected task result");
        };

        assert_eq!(artifacts[0].content_bytes.as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn old_agent_hello_without_capability_snapshot_still_decodes() {
        let body = r#"{
            "protocol_version": 2,
            "message_id":"msg-hello",
            "correlation_id":"corr-hello",
            "agent_id":"agent-1",
            "timestamp_ms":1,
            "payload":{
                "type":"agent_hello",
                "payload":{
                    "agent_id":"agent-1",
                    "fingerprint":"0123456789abcdef"
                }
            }
        }"#;

        let decoded = decode_message(body).unwrap();

        assert!(matches!(
            decoded.payload,
            WirePayload::AgentHello {
                agent_id,
                fingerprint
            } if agent_id == "agent-1" && fingerprint == "0123456789abcdef"
        ));
    }

    #[test]
    fn capability_snapshot_roundtrips() {
        let message = WireMessage::new(
            "msg-capability",
            "corr-capability",
            Some("agent-1".to_owned()),
            1,
            WirePayload::CapabilitySnapshot {
                agent_id: "agent-1".to_owned(),
                privilege_level: CapabilityPrivilegeLevelWire::SudoAvailable,
                package_manager: Some(PackageManagerWire::Apt),
                service_manager: Some(ServiceManagerWire::Systemd),
                capabilities: vec![
                    "persistent_session".to_owned(),
                    "command_execution".to_owned(),
                    "package_install".to_owned(),
                ],
                reported_at_ms: 1_710_000_000_000,
            },
        );

        let encoded = encode_message(&message).unwrap();
        let decoded = decode_message(&encoded).unwrap();

        assert!(encoded.contains("\"capability_snapshot\""));
        assert!(encoded.contains("\"sudo_available\""));
        assert_eq!(decoded.payload, message.payload);
        assert_eq!(decoded.payload.channel(), ProtocolChannel::TaskData);
    }

    #[test]
    fn trust_bundle_update_roundtrips_current_and_previous_entries() {
        let payload = WirePayload::ControllerSigningTrustBundleUpdate {
            entries: vec![
                ControllerSigningTrustEntryWire {
                    fingerprint: "controller-fp-new".to_owned(),
                    public_key: "controller-public-new".to_owned(),
                    role: ControllerSigningTrustRoleWire::Current,
                    valid_from_ms: 1_710_000_000_000,
                    valid_until_ms: None,
                },
                ControllerSigningTrustEntryWire {
                    fingerprint: "controller-fp-old".to_owned(),
                    public_key: "controller-public-old".to_owned(),
                    role: ControllerSigningTrustRoleWire::Previous,
                    valid_from_ms: 1_710_000_000_000,
                    valid_until_ms: Some(1_710_000_300_000),
                },
            ],
        };
        let message = WireMessage::new(
            "msg-trust-update",
            "corr-trust-update",
            Some("agent-1".to_owned()),
            1,
            payload.clone(),
        );

        let encoded = encode_message(&message).unwrap();
        let decoded = decode_message(&encoded).unwrap();

        assert!(encoded.contains("\"controller_signing_trust_bundle_update\""));
        assert!(encoded.contains("\"current\""));
        assert!(encoded.contains("\"previous\""));
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.payload.channel(), ProtocolChannel::TaskData);
    }

    #[test]
    fn trust_bundle_update_ignores_private_material_like_unknown_fields() {
        let body = r#"{
            "protocol_version": 2,
            "message_id": "msg-trust-update",
            "correlation_id": "corr-trust-update",
            "agent_id": "agent-1",
            "timestamp_ms": 1,
            "payload": {
                "type": "controller_signing_trust_bundle_update",
                "payload": {
                    "entries": [{
                        "fingerprint": "controller-fp-new",
                        "public_key": "controller-public-new",
                        "role": "current",
                        "valid_from_ms": 1710000000000,
                        "valid_until_ms": null,
                        "private_key": "must-not-enter-model",
                        "key_path": "/tmp/controller_private.key",
                        "tls_certificate": "must-not-enter-model"
                    }]
                }
            }
        }"#;

        let decoded = decode_message(body).unwrap();
        let WirePayload::ControllerSigningTrustBundleUpdate { entries } = decoded.payload else {
            panic!("expected trust bundle update");
        };
        let reencoded = encode_message(&WireMessage::new(
            "msg-trust-update",
            "corr-trust-update",
            Some("agent-1".to_owned()),
            1,
            WirePayload::ControllerSigningTrustBundleUpdate { entries },
        ))
        .unwrap();

        assert!(reencoded.contains("controller-public-new"));
        assert!(!reencoded.contains("must-not-enter-model"));
        assert!(!reencoded.contains("controller_private.key"));
    }

    #[test]
    fn trust_bundle_ack_roundtrips_public_status_only() {
        let payload = WirePayload::ControllerSigningTrustBundleAck {
            agent_id: "agent-1".to_owned(),
            accepted: true,
            current_fingerprint: Some("controller-fp-new".to_owned()),
            entries_count: 2,
            reason_code: None,
        };
        let message = WireMessage::new(
            "msg-trust-ack",
            "corr-trust-ack",
            Some("agent-1".to_owned()),
            1,
            payload.clone(),
        );

        let encoded = encode_message(&message).unwrap();
        let decoded = decode_message(&encoded).unwrap();

        assert!(encoded.contains("\"controller_signing_trust_bundle_ack\""));
        assert!(encoded.contains("\"accepted\":true"));
        assert!(encoded.contains("\"entries_count\":2"));
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.payload.channel(), ProtocolChannel::TaskData);
        assert!(!encoded.contains("public_key"));
        assert!(!encoded.contains("private_key"));
        assert!(!encoded.contains("key_path"));
        assert!(!encoded.contains("tls_certificate"));
    }

    #[test]
    fn agent_certificate_lifecycle_update_roundtrips_public_metadata_only() {
        let payload = WirePayload::AgentCertificateLifecycleUpdate {
            agent_id: "agent-1".to_owned(),
            action: AgentCertificateLifecycleActionWire::ActivateRenewal,
            state: AgentCertificateLifecycleStateWire::DualCertificateActive,
            current_certificate: Some(AgentCertificateMetadataWire {
                serial: "serial-1".to_owned(),
                fingerprint: "0123456789abcdef".to_owned(),
                not_before_ms: 1_710_000_000_000,
                not_after_ms: 1_710_003_600_000,
            }),
            next_certificate: Some(AgentCertificateMetadataWire {
                serial: "serial-2".to_owned(),
                fingerprint: "fedcba9876543210".to_owned(),
                not_before_ms: 1_710_002_000_000,
                not_after_ms: 1_710_006_000_000,
            }),
            grace_until_ms: Some(1_710_002_300_000),
            reason_code: None,
        };
        let message = WireMessage::new(
            "msg-agent-cert",
            "corr-agent-cert",
            Some("agent-1".to_owned()),
            1,
            payload.clone(),
        );

        let encoded = encode_message(&message).unwrap();
        let decoded = decode_message(&encoded).unwrap();

        assert!(encoded.contains("\"agent_certificate_lifecycle_update\""));
        assert!(encoded.contains("\"activate_renewal\""));
        assert!(encoded.contains("\"dual_certificate_active\""));
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.payload.channel(), ProtocolChannel::TaskData);
        for forbidden in [
            "PRIVATE KEY",
            "private_key",
            "certificate_body",
            "pem_body",
            "ca_path",
            "runtime_env",
            "websocket_handle",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "agent certificate lifecycle update must not expose {forbidden}"
            );
        }
    }

    #[test]
    fn agent_certificate_lifecycle_update_ignores_private_material_like_unknown_fields() {
        let body = r#"{
            "protocol_version": 2,
            "message_id": "msg-agent-cert",
            "correlation_id": "corr-agent-cert",
            "agent_id": "agent-1",
            "timestamp_ms": 1,
            "payload": {
                "type": "agent_certificate_lifecycle_update",
                "payload": {
                    "agent_id": "agent-1",
                    "action": "issue",
                    "state": "issued",
                    "current_certificate": {
                        "serial": "serial-1",
                        "fingerprint": "0123456789abcdef",
                        "not_before_ms": 1710000000000,
                        "not_after_ms": 1710003600000,
                        "private_key": "must-not-enter-model",
                        "certificate_body": "must-not-enter-model",
                        "ca_path": "/etc/fleet/ca.pem"
                    },
                    "next_certificate": null,
                    "grace_until_ms": null,
                    "reason_code": null
                }
            }
        }"#;

        let decoded = decode_message(body).unwrap();
        let WirePayload::AgentCertificateLifecycleUpdate {
            agent_id,
            action,
            state,
            current_certificate,
            next_certificate,
            grace_until_ms,
            reason_code,
        } = decoded.payload
        else {
            panic!("expected agent certificate lifecycle update");
        };
        let reencoded = encode_message(&WireMessage::new(
            "msg-agent-cert",
            "corr-agent-cert",
            Some("agent-1".to_owned()),
            1,
            WirePayload::AgentCertificateLifecycleUpdate {
                agent_id,
                action,
                state,
                current_certificate,
                next_certificate,
                grace_until_ms,
                reason_code,
            },
        ))
        .unwrap();

        assert!(reencoded.contains("\"agent_certificate_lifecycle_update\""));
        assert!(!reencoded.contains("must-not-enter-model"));
        assert!(!reencoded.contains("/etc/fleet/ca.pem"));
    }

    #[test]
    fn agent_certificate_lifecycle_ack_roundtrips_public_status_only() {
        let payload = WirePayload::AgentCertificateLifecycleAck {
            agent_id: "agent-1".to_owned(),
            accepted: true,
            state: AgentCertificateLifecycleStateWire::Issued,
            current_fingerprint: Some("0123456789abcdef".to_owned()),
            reason_code: None,
        };
        let message = WireMessage::new(
            "msg-agent-cert-ack",
            "corr-agent-cert",
            Some("agent-1".to_owned()),
            1,
            payload.clone(),
        );

        let encoded = encode_message(&message).unwrap();
        let decoded = decode_message(&encoded).unwrap();

        assert!(encoded.contains("\"agent_certificate_lifecycle_ack\""));
        assert!(encoded.contains("\"accepted\":true"));
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.payload.channel(), ProtocolChannel::TaskData);
        assert!(!encoded.contains("serial"));
        assert!(!encoded.contains("private_key"));
        assert!(!encoded.contains("certificate_body"));
        assert!(!encoded.contains("ca_path"));
    }

    #[test]
    fn task_ack_ignores_unknown_compatible_fields() {
        let body = r#"{
            "protocol_version": 2,
            "message_id": "msg-ack",
            "correlation_id": "task-1",
            "agent_id": "agent-1",
            "timestamp_ms": 1,
            "payload": {
                "type": "task_ack",
                "payload": {
                    "job_id": "job-1",
                    "task_id": "task-1",
                    "future_field": "ignored"
                }
            }
        }"#;

        let decoded = decode_message(body).unwrap();

        assert!(matches!(
            decoded.payload,
            WirePayload::TaskAck { job_id, task_id }
                if job_id == "job-1" && task_id == "task-1"
        ));
    }

    #[test]
    fn separates_auth_and_task_channels() {
        assert_eq!(
            WirePayload::AuthChallenge { nonce: "n1".into() }.channel(),
            ProtocolChannel::AuthSession
        );
        assert_eq!(
            WirePayload::OutputChunk {
                job_id: "job-1".into(),
                task_id: "task-1".into(),
                stream: OutputStream::Stdout,
                sequence: 0,
                data: "ok".into(),
            }
            .channel(),
            ProtocolChannel::TaskData
        );
        assert_eq!(
            WirePayload::TaskAck {
                job_id: "job-1".into(),
                task_id: "task-1".into(),
            }
            .channel(),
            ProtocolChannel::TaskData
        );
        assert_eq!(
            WirePayload::SecurityEvent {
                agent_id: "agent-1".into(),
                action: "task_verification_failed".into(),
                detail: "invalid signature".into(),
            }
            .channel(),
            ProtocolChannel::TaskData
        );
    }
}
