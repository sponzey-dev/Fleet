//! Pure report acknowledgement and bounded journal admission rules.
//! Transport authentication and durable writes remain the caller's responsibility.

use std::fmt::{Display, Formatter};

/// Stable ownership tuple, independent of the current socket or signing key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReportKey {
    controller: String,
    agent: String,
    job: String,
    task: String,
    report: String,
}

impl ReportKey {
    /// Identifiers must be nonempty, bounded, and contain no control characters.
    /// Errors never echo supplied identifiers.
    pub fn new(
        controller: &str,
        agent: &str,
        job: &str,
        task: &str,
        report: &str,
    ) -> Result<Self, DeliveryError> {
        for value in [controller, agent, job, task, report] {
            if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err(DeliveryError::InvalidIdentity);
            }
        }
        Ok(Self {
            controller: controller.to_owned(),
            agent: agent.to_owned(),
            job: job.to_owned(),
            task: task.to_owned(),
            report: report.to_owned(),
        })
    }

    pub fn parts(&self) -> [&str; 5] {
        [
            &self.controller,
            &self.agent,
            &self.job,
            &self.task,
            &self.report,
        ]
    }
}

/// SHA-256 of the immutable encoded report, calculated at the adapter boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportDigest(pub [u8; 32]);

/// Storage receipt matching does not itself authenticate a peer or delete data.
pub fn validate_report_ack(
    expected_key: &ReportKey,
    expected_digest: ReportDigest,
    received_key: &ReportKey,
    received_digest: ReportDigest,
) -> Result<(), DeliveryError> {
    if expected_key != received_key {
        return Err(DeliveryError::IdentityMismatch);
    }
    if expected_digest != received_digest {
        return Err(DeliveryError::DigestMismatch);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportClass {
    Lifecycle,
    /// Persisted policy observation; a receipt confirms storage, not task success.
    DriftEvidence,
    Output,
    FinalResult,
}

/// Committed report usage; byte accounting includes body and persisted metadata.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JournalUsage {
    pub reports: u64,
    pub bytes: u64,
}

/// Reservation protects one active task. Admission must establish a fresh reserve
/// before starting another task, even when earlier final reports remain unACKed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalCapacity {
    maximum: JournalUsage,
    final_reserve: JournalUsage,
}

impl JournalCapacity {
    pub fn new(maximum: JournalUsage, final_reserve: JournalUsage) -> Result<Self, DeliveryError> {
        if final_reserve.reports == 0
            || final_reserve.bytes == 0
            || final_reserve.reports >= maximum.reports
            || final_reserve.bytes >= maximum.bytes
        {
            return Err(DeliveryError::InvalidCapacity);
        }
        Ok(Self {
            maximum,
            final_reserve,
        })
    }

    /// Admission must fit its metadata without consuming the final-result reserve.
    /// The requested final bound includes encoded body and report metadata, not raw
    /// output bytes. This check grants no authority to execute or reuse a nonce.
    pub fn reserve_execution(
        self,
        usage: JournalUsage,
        metadata_bytes: u64,
        final_bytes: u64,
    ) -> Result<(), DeliveryError> {
        let bytes = usage
            .bytes
            .checked_add(metadata_bytes)
            .ok_or(DeliveryError::CapacityExceeded)?;
        if final_bytes == 0
            || final_bytes > self.final_reserve.bytes
            || usage.reports > self.maximum.reports - self.final_reserve.reports
            || bytes > self.maximum.bytes - self.final_reserve.bytes
        {
            return Err(DeliveryError::CapacityExceeded);
        }
        Ok(())
    }

    /// Returns the prospective usage without mutating state. A repository must
    /// check and append in the same transaction; this is not a concurrency lock.
    pub fn after_append(
        self,
        usage: JournalUsage,
        class: ReportClass,
        encoded_bytes: u64,
    ) -> Result<JournalUsage, DeliveryError> {
        let next = JournalUsage {
            reports: usage
                .reports
                .checked_add(1)
                .ok_or(DeliveryError::CapacityExceeded)?,
            bytes: usage
                .bytes
                .checked_add(encoded_bytes)
                .ok_or(DeliveryError::CapacityExceeded)?,
        };
        let limit = if class == ReportClass::FinalResult {
            self.maximum
        } else {
            JournalUsage {
                reports: self.maximum.reports - self.final_reserve.reports,
                bytes: self.maximum.bytes - self.final_reserve.bytes,
            }
        };
        if next.reports > limit.reports || next.bytes > limit.bytes {
            return Err(DeliveryError::CapacityExceeded);
        }
        Ok(next)
    }
}

/// A start intent is committed BEFORE any host effect. It is not evidence that a
/// child started, finished, or can safely be restarted after a process crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionPhase {
    Admitted,
    StartIntent,
    ResultCommitted,
}

/// Output stream identity used by the durable execution progress contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskOutputStream {
    /// Bytes produced on stdout.
    Stdout,
    /// Bytes produced on stderr.
    Stderr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptedExecution {
    BeforeStart,
    OutcomeUnknown,
}

impl InterruptedExecution {
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::BeforeStart => "agent_interrupted_before_start",
            Self::OutcomeUnknown => "execution_outcome_unknown",
        }
    }
}

/// Persistence data contains hashes and committed output counts, not command text,
/// raw nonces, output bytes, or key material. `final_report_key` allocates one
/// stable result ID before execution or recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionSnapshot {
    pub final_report_key: ReportKey,
    pub nonce_digest: ReportDigest,
    pub envelope_digest: ReportDigest,
    pub phase: ExecutionPhase,
    pub admitted_at_ms: u64,
    pub final_max_bytes: u64,
    pub stdout_chunks: u64,
    pub stderr_chunks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionRecord(ExecutionSnapshot);

impl ExecutionRecord {
    /// Restore validated persistence metadata; this does not authorize execution.
    pub fn restore(snapshot: ExecutionSnapshot) -> Result<Self, DeliveryError> {
        if snapshot.final_max_bytes == 0 {
            return Err(DeliveryError::InvalidCapacity);
        }
        Ok(Self(snapshot))
    }

    pub fn snapshot(&self) -> &ExecutionSnapshot {
        &self.0
    }

    pub fn accounted_bytes(&self) -> u64 {
        self.0
            .final_report_key
            .parts()
            .iter()
            .map(|part| part.len() as u64)
            .sum::<u64>()
            + 112
    }

    /// May be applied once by the live execution owner, after nonce validation.
    /// A duplicate start request must never become another host execution.
    pub fn record_start_intent(&mut self) -> Result<(), DeliveryError> {
        if self.0.phase != ExecutionPhase::Admitted {
            return Err(DeliveryError::InvalidExecutionTransition);
        }
        self.0.phase = ExecutionPhase::StartIntent;
        Ok(())
    }

    /// Retain committed output progress even after an individual report receipt
    /// removes its body from the journal.
    pub fn record_output_chunk(
        &mut self,
        stream: TaskOutputStream,
        sequence: u64,
    ) -> Result<(), DeliveryError> {
        if self.0.phase != ExecutionPhase::StartIntent {
            return Err(DeliveryError::InvalidExecutionTransition);
        }
        let next = match stream {
            TaskOutputStream::Stdout => &mut self.0.stdout_chunks,
            TaskOutputStream::Stderr => &mut self.0.stderr_chunks,
        };
        if sequence != *next {
            return Err(DeliveryError::InvalidOutputSequence);
        }
        *next = next
            .checked_add(1)
            .ok_or(DeliveryError::InvalidOutputSequence)?;
        Ok(())
    }

    /// Persist this state in the same transaction as the immutable final report.
    pub fn record_result(&mut self) -> Result<(), DeliveryError> {
        if self.0.phase == ExecutionPhase::ResultCommitted {
            return Err(DeliveryError::InvalidExecutionTransition);
        }
        self.0.phase = ExecutionPhase::ResultCommitted;
        Ok(())
    }

    /// Called only after the prior execution owner has ended, not merely because
    /// its socket disconnected. Neither outcome permits reexecution.
    pub fn interrupted_after_owner_exit(&self) -> Option<InterruptedExecution> {
        match self.0.phase {
            ExecutionPhase::Admitted => Some(InterruptedExecution::BeforeStart),
            ExecutionPhase::StartIntent => Some(InterruptedExecution::OutcomeUnknown),
            ExecutionPhase::ResultCommitted => None,
        }
    }
}

/// Body-free failures safe to map into operator diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryError {
    InvalidIdentity,
    IdentityMismatch,
    DigestMismatch,
    InvalidCapacity,
    CapacityExceeded,
    InvalidExecutionTransition,
    InvalidOutputSequence,
}

impl Display for DeliveryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidIdentity => "invalid report identity",
            Self::IdentityMismatch => "report acknowledgement identity mismatch",
            Self::DigestMismatch => "report acknowledgement digest mismatch",
            Self::InvalidCapacity => "invalid journal capacity",
            Self::CapacityExceeded => "journal capacity exceeded",
            Self::InvalidExecutionTransition => "invalid journal execution transition",
            Self::InvalidOutputSequence => "invalid task output sequence",
        })
    }
}

impl std::error::Error for DeliveryError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(task: &str) -> ReportKey {
        ReportKey::new("controller", "agent", "job", task, "report").unwrap()
    }

    fn capacity() -> JournalCapacity {
        JournalCapacity::new(
            JournalUsage {
                reports: 10,
                bytes: 100,
            },
            JournalUsage {
                reports: 2,
                bytes: 20,
            },
        )
        .unwrap()
    }

    #[test]
    fn execution_reservation_cannot_use_existing_unacknowledged_result_space() {
        assert_eq!(
            capacity().reserve_execution(
                JournalUsage {
                    reports: 8,
                    bytes: 79
                },
                1,
                20
            ),
            Ok(())
        );
        assert_eq!(
            capacity().reserve_execution(
                JournalUsage {
                    reports: 9,
                    bytes: 0
                },
                1,
                20
            ),
            Err(DeliveryError::CapacityExceeded)
        );
        assert_eq!(
            capacity().reserve_execution(
                JournalUsage {
                    reports: 0,
                    bytes: 80
                },
                1,
                20
            ),
            Err(DeliveryError::CapacityExceeded)
        );
        assert_eq!(
            capacity().reserve_execution(JournalUsage::default(), 1, 21),
            Err(DeliveryError::CapacityExceeded)
        );
        assert_eq!(
            capacity().reserve_execution(
                JournalUsage {
                    reports: 0,
                    bytes: u64::MAX
                },
                1,
                1
            ),
            Err(DeliveryError::CapacityExceeded)
        );
    }

    #[test]
    fn execution_start_is_once_only_and_recovery_never_restarts() {
        let mut record = ExecutionRecord::restore(ExecutionSnapshot {
            final_report_key: key("task"),
            nonce_digest: ReportDigest([1; 32]),
            envelope_digest: ReportDigest([2; 32]),
            phase: ExecutionPhase::Admitted,
            admitted_at_ms: 100,
            final_max_bytes: 20,
            stdout_chunks: 0,
            stderr_chunks: 0,
        })
        .unwrap();
        assert_eq!(
            record.interrupted_after_owner_exit(),
            Some(InterruptedExecution::BeforeStart)
        );
        record.record_start_intent().unwrap();
        assert_eq!(
            record.interrupted_after_owner_exit(),
            Some(InterruptedExecution::OutcomeUnknown)
        );
        assert_eq!(
            record.record_start_intent(),
            Err(DeliveryError::InvalidExecutionTransition)
        );
        record.record_result().unwrap();
        assert_eq!(record.interrupted_after_owner_exit(), None);
        assert_eq!(
            record.record_start_intent(),
            Err(DeliveryError::InvalidExecutionTransition)
        );
        assert_eq!(
            record.record_result(),
            Err(DeliveryError::InvalidExecutionTransition)
        );
    }

    #[test]
    fn execution_output_counts_require_contiguous_per_stream_commits() {
        let mut record = ExecutionRecord::restore(ExecutionSnapshot {
            final_report_key: key("task"),
            nonce_digest: ReportDigest([1; 32]),
            envelope_digest: ReportDigest([2; 32]),
            phase: ExecutionPhase::Admitted,
            admitted_at_ms: 100,
            final_max_bytes: 20,
            stdout_chunks: 0,
            stderr_chunks: 0,
        })
        .unwrap();
        assert_eq!(
            record.record_output_chunk(TaskOutputStream::Stdout, 0),
            Err(DeliveryError::InvalidExecutionTransition)
        );
        record.record_start_intent().unwrap();
        record
            .record_output_chunk(TaskOutputStream::Stdout, 0)
            .unwrap();
        record
            .record_output_chunk(TaskOutputStream::Stderr, 0)
            .unwrap();
        assert_eq!(record.snapshot().stdout_chunks, 1);
        assert_eq!(record.snapshot().stderr_chunks, 1);
        assert_eq!(
            record.record_output_chunk(TaskOutputStream::Stdout, 2),
            Err(DeliveryError::InvalidOutputSequence)
        );
    }

    #[test]
    fn acknowledgement_requires_full_identity_and_digest() {
        let digest = ReportDigest([1; 32]);
        assert_eq!(
            validate_report_ack(&key("task"), digest, &key("other"), digest),
            Err(DeliveryError::IdentityMismatch)
        );
        assert_eq!(
            validate_report_ack(&key("task"), digest, &key("task"), ReportDigest([2; 32])),
            Err(DeliveryError::DigestMismatch)
        );
        assert_eq!(
            validate_report_ack(&key("task"), digest, &key("task"), digest),
            Ok(())
        );
    }

    #[test]
    fn ordinary_reports_cannot_consume_final_reserve() {
        let usage = JournalUsage {
            reports: 8,
            bytes: 80,
        };
        for class in [ReportClass::Output, ReportClass::Lifecycle] {
            assert_eq!(
                capacity().after_append(usage, class, 1),
                Err(DeliveryError::CapacityExceeded)
            );
        }
        assert_eq!(
            capacity().after_append(usage, ReportClass::FinalResult, 20),
            Ok(JournalUsage {
                reports: 9,
                bytes: 100
            })
        );
        assert_eq!(
            capacity().after_append(usage, ReportClass::FinalResult, 21),
            Err(DeliveryError::CapacityExceeded)
        );
    }

    #[test]
    fn capacity_rejects_arithmetic_overflow() {
        assert_eq!(
            capacity().after_append(
                JournalUsage {
                    reports: u64::MAX,
                    bytes: 0
                },
                ReportClass::FinalResult,
                1
            ),
            Err(DeliveryError::CapacityExceeded)
        );
        assert_eq!(
            capacity().after_append(
                JournalUsage {
                    reports: 0,
                    bytes: u64::MAX
                },
                ReportClass::FinalResult,
                1
            ),
            Err(DeliveryError::CapacityExceeded)
        );
    }

    #[test]
    fn count_and_byte_bounds_are_independent_and_inclusive() {
        assert_eq!(
            capacity().after_append(
                JournalUsage {
                    reports: 7,
                    bytes: 79
                },
                ReportClass::Output,
                1
            ),
            Ok(JournalUsage {
                reports: 8,
                bytes: 80
            })
        );
        assert_eq!(
            capacity().after_append(
                JournalUsage {
                    reports: 0,
                    bytes: 80
                },
                ReportClass::Output,
                1
            ),
            Err(DeliveryError::CapacityExceeded)
        );
        assert_eq!(
            capacity().after_append(
                JournalUsage {
                    reports: 8,
                    bytes: 0
                },
                ReportClass::Output,
                1
            ),
            Err(DeliveryError::CapacityExceeded)
        );
        assert_eq!(
            capacity().after_append(
                JournalUsage {
                    reports: 10,
                    bytes: 0
                },
                ReportClass::FinalResult,
                1
            ),
            Err(DeliveryError::CapacityExceeded)
        );
    }

    #[test]
    fn rejects_invalid_reservation_and_identity_without_echoing_input() {
        for reserve in [
            JournalUsage {
                reports: 0,
                bytes: 1,
            },
            JournalUsage {
                reports: 1,
                bytes: 0,
            },
            JournalUsage {
                reports: 10,
                bytes: 1,
            },
            JournalUsage {
                reports: 1,
                bytes: 100,
            },
        ] {
            assert_eq!(
                JournalCapacity::new(
                    JournalUsage {
                        reports: 10,
                        bytes: 100
                    },
                    reserve
                ),
                Err(DeliveryError::InvalidCapacity)
            );
        }
        for value in [" ".to_owned(), "secret\nvalue".to_owned(), "a".repeat(257)] {
            let error = ReportKey::new(&value, "agent", "job", "task", "report").unwrap_err();
            assert_eq!(error, DeliveryError::InvalidIdentity);
            assert_eq!(error.to_string(), "invalid report identity");
        }
    }

    #[test]
    fn ownership_changes_are_not_acknowledgements() {
        let original = key("task");
        for index in 0..5 {
            let mut parts = original.parts();
            parts[index] = "different";
            let changed = ReportKey::new(parts[0], parts[1], parts[2], parts[3], parts[4]).unwrap();
            assert_eq!(
                validate_report_ack(
                    &original,
                    ReportDigest([1; 32]),
                    &changed,
                    ReportDigest([1; 32])
                ),
                Err(DeliveryError::IdentityMismatch)
            );
        }
    }
}
