//! Pure eligibility rules for reconciling a task whose Agent stopped reporting.
//!
//! A Controller timeout is not evidence that host execution stopped or failed;
//! overdue active assignments therefore resolve only as an unknown outcome.

use crate::AssignmentStatus;
use std::time::{Duration, SystemTime};

/// The result of assessing one persisted assignment for recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentRecoveryAssessment {
    /// Queued or terminal work is owned by a different lifecycle transition.
    NotEligible,
    /// A required timestamp or safe deadline calculation is unavailable.
    InvalidTiming,
    /// The execution timeout and grace window have not elapsed.
    NotDue,
    /// Execution may have occurred, but no final result is available.
    ExecutionOutcomeUnknown,
}

/// Assesses whether a nonterminal dispatched assignment has exceeded its execution window.
///
/// The Controller's persisted dispatch time, task execution timeout, and recovery grace determine
/// eligibility. This function does not infer process state from envelope expiry or connection loss.
pub fn assess_assignment_recovery(
    status: AssignmentStatus,
    dispatched_at: Option<SystemTime>,
    execution_timeout: Duration,
    grace: Duration,
    now: SystemTime,
) -> AssignmentRecoveryAssessment {
    if !matches!(
        status,
        AssignmentStatus::Dispatched | AssignmentStatus::Accepted | AssignmentStatus::Started
    ) {
        return AssignmentRecoveryAssessment::NotEligible;
    }
    if execution_timeout.is_zero() {
        return AssignmentRecoveryAssessment::InvalidTiming;
    }
    let Some(dispatched_at) = dispatched_at else {
        return AssignmentRecoveryAssessment::InvalidTiming;
    };
    let Some(deadline) = dispatched_at
        .checked_add(execution_timeout)
        .and_then(|deadline| deadline.checked_add(grace))
    else {
        return AssignmentRecoveryAssessment::InvalidTiming;
    };
    if now < deadline {
        AssignmentRecoveryAssessment::NotDue
    } else {
        AssignmentRecoveryAssessment::ExecutionOutcomeUnknown
    }
}

#[cfg(test)]
mod tests {
    use super::{AssignmentRecoveryAssessment, assess_assignment_recovery};
    use crate::AssignmentStatus;
    use std::time::{Duration, SystemTime};

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn active_assignment_is_outcome_unknown_only_after_execution_window_and_grace() {
        let assessment = |now| {
            assess_assignment_recovery(
                AssignmentStatus::Started,
                Some(at(100)),
                Duration::from_secs(10),
                Duration::from_secs(5),
                now,
            )
        };

        assert_eq!(assessment(at(114)), AssignmentRecoveryAssessment::NotDue);
        assert_eq!(
            assessment(at(115)),
            AssignmentRecoveryAssessment::ExecutionOutcomeUnknown
        );
    }

    #[test]
    fn dispatch_ack_or_start_status_never_proves_execution_did_not_happen() {
        for status in [
            AssignmentStatus::Dispatched,
            AssignmentStatus::Accepted,
            AssignmentStatus::Started,
        ] {
            assert_eq!(
                assess_assignment_recovery(
                    status,
                    Some(at(100)),
                    Duration::from_secs(1),
                    Duration::ZERO,
                    at(101),
                ),
                AssignmentRecoveryAssessment::ExecutionOutcomeUnknown
            );
        }
    }

    #[test]
    fn queued_and_terminal_assignments_are_never_recovery_candidates() {
        for status in [
            AssignmentStatus::Queued,
            AssignmentStatus::Succeeded,
            AssignmentStatus::Failed,
            AssignmentStatus::Rejected,
            AssignmentStatus::Canceled,
            AssignmentStatus::Expired,
        ] {
            assert_eq!(
                assess_assignment_recovery(
                    status,
                    Some(at(1)),
                    Duration::from_secs(1),
                    Duration::ZERO,
                    at(100),
                ),
                AssignmentRecoveryAssessment::NotEligible
            );
        }
    }

    #[test]
    fn missing_dispatch_time_zero_timeout_and_overflow_fail_closed() {
        assert_eq!(
            assess_assignment_recovery(
                AssignmentStatus::Dispatched,
                None,
                Duration::from_secs(1),
                Duration::ZERO,
                at(100),
            ),
            AssignmentRecoveryAssessment::InvalidTiming
        );
        assert_eq!(
            assess_assignment_recovery(
                AssignmentStatus::Accepted,
                Some(at(1)),
                Duration::ZERO,
                Duration::ZERO,
                at(100),
            ),
            AssignmentRecoveryAssessment::InvalidTiming
        );
        assert_eq!(
            assess_assignment_recovery(
                AssignmentStatus::Started,
                Some(at(1)),
                Duration::MAX,
                Duration::ZERO,
                at(100),
            ),
            AssignmentRecoveryAssessment::InvalidTiming
        );
    }
}
