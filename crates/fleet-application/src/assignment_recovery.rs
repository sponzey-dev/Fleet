//! Application boundary for bounded recovery of overdue active task assignments.
//!
//! A recovery commit changes an existing assignment to failed with a typed
//! unknown-outcome reason; it never authorizes task replay or reruns host effects.

use fleet_domain::assignment_recovery::{AssignmentRecoveryAssessment, assess_assignment_recovery};
use fleet_domain::delivery::InterruptedExecution;
use fleet_domain::{AssignmentStatus, JobId, TaskId};
use std::fmt::{Display, Formatter};
use std::time::{Duration, SystemTime};

/// Initial grace period after the persisted task execution timeout.
pub const DEFAULT_ASSIGNMENT_RECOVERY_GRACE: Duration = Duration::from_secs(300);

/// Maximum number of candidates one recovery pass may inspect or commit.
pub const MAX_ASSIGNMENT_RECOVERY_BATCH: usize = 100;

/// A persisted assignment snapshot used to assess Controller-side recovery eligibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentRecoveryCandidate {
    /// The durable parent job identity.
    pub job_id: JobId,
    /// The durable assignment/task identity.
    pub task_id: TaskId,
    /// State observed by the candidate scan; the commit must compare it again.
    pub status: AssignmentStatus,
    /// Controller persistence time when dispatch was committed.
    pub dispatched_at: Option<SystemTime>,
    /// Maximum execution duration assigned to this task.
    pub execution_timeout: Duration,
}

/// Outcome of committing a conditional unknown-execution transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentRecoveryCommitOutcome {
    /// The assignment, job aggregate, and redacted audit were committed together.
    Recovered,
    /// A concurrent result, cancellation, or other transition made the candidate stale.
    NoLongerEligible,
}

/// Durable repository contract for bounded overdue-assignment reconciliation.
pub trait AssignmentRecoveryRepository {
    /// The infrastructure error type.
    type Error;

    /// Lists at most limit overdue nonterminal assignments in due-time order.
    ///
    /// The adapter must filter using Controller dispatch time + task timeout + grace, exclude
    /// queued/terminal or unverifiable rows, and return no more than limit. Due-time ordering
    /// prevents a long-timeout assignment from starving later candidates.
    fn list_overdue_assignment_recovery_candidates(
        &self,
        now: SystemTime,
        grace: Duration,
        limit: usize,
    ) -> Result<Vec<AssignmentRecoveryCandidate>, Self::Error>;

    /// Atomically fails the exact still-active candidate as outcome-unknown.
    ///
    /// The adapter must compare the candidate's observed status and dispatch timestamp, preserve
    /// terminal state on races, recompute the Job aggregate, and write a redacted audit in the same
    /// transaction. It must never enqueue or replay the task.
    fn commit_unknown_execution_outcome(
        &mut self,
        candidate: &AssignmentRecoveryCandidate,
        reason: InterruptedExecution,
        now: SystemTime,
    ) -> Result<AssignmentRecoveryCommitOutcome, Self::Error>;
}

/// Input for one bounded overdue-assignment recovery pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoverUncertainAssignmentsInput {
    /// Controller time used consistently for scan and commit.
    pub now: SystemTime,
    /// Grace added after each task's execution timeout.
    pub grace: Duration,
    /// Maximum candidate count for this pass.
    pub limit: usize,
}

/// Summary of one bounded recovery pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoverUncertainAssignmentsOutput {
    /// Candidate rows returned by the repository.
    pub scanned_count: usize,
    /// Unknown-outcome transitions committed atomically.
    pub recovered_count: usize,
    /// Candidates skipped because they were not due or no longer active.
    pub skipped_count: usize,
}

/// Failure while scanning or committing an assignment recovery pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoverUncertainAssignmentsError<RepositoryError> {
    /// The requested batch is outside the bounded supported range.
    InvalidBatchLimit,
    /// The repository violated its bounded result contract.
    RepositoryExceededBatchLimit,
    /// A repository read or conditional commit failed.
    Repository(RepositoryError),
}

impl<RepositoryError: Display> Display for RecoverUncertainAssignmentsError<RepositoryError> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBatchLimit => write!(formatter, "invalid assignment recovery batch limit"),
            Self::RepositoryExceededBatchLimit => {
                write!(
                    formatter,
                    "assignment recovery repository exceeded its batch limit"
                )
            }
            Self::Repository(error) => write!(formatter, "repository error: {error}"),
        }
    }
}

impl<RepositoryError> std::error::Error for RecoverUncertainAssignmentsError<RepositoryError> where
    RepositoryError: std::error::Error + 'static
{
}

/// Applies the pure G2 policy to one bounded batch of overdue assignments.
pub struct RecoverUncertainAssignments;

impl RecoverUncertainAssignments {
    /// Scans and conditionally commits overdue active assignments without replaying tasks.
    pub fn execute<R: AssignmentRecoveryRepository>(
        repository: &mut R,
        input: RecoverUncertainAssignmentsInput,
    ) -> Result<RecoverUncertainAssignmentsOutput, RecoverUncertainAssignmentsError<R::Error>> {
        if input.limit == 0 || input.limit > MAX_ASSIGNMENT_RECOVERY_BATCH {
            return Err(RecoverUncertainAssignmentsError::InvalidBatchLimit);
        }
        let candidates = repository
            .list_overdue_assignment_recovery_candidates(input.now, input.grace, input.limit)
            .map_err(RecoverUncertainAssignmentsError::Repository)?;
        if candidates.len() > input.limit {
            return Err(RecoverUncertainAssignmentsError::RepositoryExceededBatchLimit);
        }
        let mut output = RecoverUncertainAssignmentsOutput {
            scanned_count: candidates.len(),
            ..RecoverUncertainAssignmentsOutput::default()
        };
        for candidate in candidates {
            match assess_assignment_recovery(
                candidate.status,
                candidate.dispatched_at,
                candidate.execution_timeout,
                input.grace,
                input.now,
            ) {
                AssignmentRecoveryAssessment::ExecutionOutcomeUnknown => {
                    match repository
                        .commit_unknown_execution_outcome(
                            &candidate,
                            InterruptedExecution::OutcomeUnknown,
                            input.now,
                        )
                        .map_err(RecoverUncertainAssignmentsError::Repository)?
                    {
                        AssignmentRecoveryCommitOutcome::Recovered => {
                            output.recovered_count += 1;
                        }
                        AssignmentRecoveryCommitOutcome::NoLongerEligible => {
                            output.skipped_count += 1;
                        }
                    }
                }
                AssignmentRecoveryAssessment::NotEligible
                | AssignmentRecoveryAssessment::InvalidTiming
                | AssignmentRecoveryAssessment::NotDue => output.skipped_count += 1,
            }
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakeError;

    impl Display for FakeError {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "fake repository error")
        }
    }

    impl std::error::Error for FakeError {}

    struct FakeRecoveryRepository {
        candidates: Vec<AssignmentRecoveryCandidate>,
        commit_outcome: AssignmentRecoveryCommitOutcome,
        committed: Vec<(TaskId, InterruptedExecution, SystemTime)>,
        requested_limit: Cell<Option<usize>>,
    }

    impl AssignmentRecoveryRepository for FakeRecoveryRepository {
        type Error = FakeError;

        fn list_overdue_assignment_recovery_candidates(
            &self,
            _now: SystemTime,
            _grace: Duration,
            limit: usize,
        ) -> Result<Vec<AssignmentRecoveryCandidate>, Self::Error> {
            self.requested_limit.set(Some(limit));
            Ok(self.candidates.clone())
        }

        fn commit_unknown_execution_outcome(
            &mut self,
            candidate: &AssignmentRecoveryCandidate,
            reason: InterruptedExecution,
            now: SystemTime,
        ) -> Result<AssignmentRecoveryCommitOutcome, Self::Error> {
            self.committed
                .push((candidate.task_id.clone(), reason, now));
            Ok(self.commit_outcome)
        }
    }

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn candidate(
        status: AssignmentStatus,
        dispatched_at: Option<SystemTime>,
    ) -> AssignmentRecoveryCandidate {
        AssignmentRecoveryCandidate {
            job_id: JobId::new("job-1").unwrap(),
            task_id: TaskId::new("task-1").unwrap(),
            status,
            dispatched_at,
            execution_timeout: Duration::from_secs(10),
        }
    }

    fn input(limit: usize) -> RecoverUncertainAssignmentsInput {
        RecoverUncertainAssignmentsInput {
            now: at(115),
            grace: Duration::from_secs(5),
            limit,
        }
    }

    #[test]
    fn commits_only_due_active_candidates_with_unknown_outcome_reason() {
        let mut repository = FakeRecoveryRepository {
            candidates: vec![candidate(AssignmentStatus::Started, Some(at(100)))],
            commit_outcome: AssignmentRecoveryCommitOutcome::Recovered,
            committed: Vec::new(),
            requested_limit: Cell::new(None),
        };

        let output = RecoverUncertainAssignments::execute(&mut repository, input(10)).unwrap();

        assert_eq!(output.scanned_count, 1);
        assert_eq!(output.recovered_count, 1);
        assert_eq!(output.skipped_count, 0);
        assert_eq!(repository.requested_limit.get(), Some(10));
        assert_eq!(
            repository.committed,
            vec![(
                TaskId::new("task-1").unwrap(),
                InterruptedExecution::OutcomeUnknown,
                at(115)
            )]
        );
    }

    #[test]
    fn stale_racing_candidate_is_noop_and_not_due_or_terminal_candidates_are_skipped() {
        let mut repository = FakeRecoveryRepository {
            candidates: vec![
                candidate(AssignmentStatus::Started, Some(at(100))),
                candidate(AssignmentStatus::Queued, Some(at(1))),
                candidate(AssignmentStatus::Dispatched, Some(at(104))),
            ],
            commit_outcome: AssignmentRecoveryCommitOutcome::NoLongerEligible,
            committed: Vec::new(),
            requested_limit: Cell::new(None),
        };

        let output = RecoverUncertainAssignments::execute(&mut repository, input(10)).unwrap();

        assert_eq!(output.scanned_count, 3);
        assert_eq!(output.recovered_count, 0);
        assert_eq!(output.skipped_count, 3);
        assert_eq!(repository.committed.len(), 1);
    }

    #[test]
    fn rejects_unbounded_batch_before_repository_access() {
        let mut repository = FakeRecoveryRepository {
            candidates: Vec::new(),
            commit_outcome: AssignmentRecoveryCommitOutcome::Recovered,
            committed: Vec::new(),
            requested_limit: Cell::new(None),
        };

        assert_eq!(
            RecoverUncertainAssignments::execute(
                &mut repository,
                input(MAX_ASSIGNMENT_RECOVERY_BATCH + 1),
            ),
            Err(RecoverUncertainAssignmentsError::InvalidBatchLimit)
        );
        assert_eq!(repository.requested_limit.get(), None);
    }

    #[test]
    fn rejects_repository_response_larger_than_requested_batch_before_committing() {
        let mut repository = FakeRecoveryRepository {
            candidates: vec![
                candidate(AssignmentStatus::Started, Some(at(100))),
                candidate(AssignmentStatus::Accepted, Some(at(100))),
            ],
            commit_outcome: AssignmentRecoveryCommitOutcome::Recovered,
            committed: Vec::new(),
            requested_limit: Cell::new(None),
        };

        assert_eq!(
            RecoverUncertainAssignments::execute(&mut repository, input(1)),
            Err(RecoverUncertainAssignmentsError::RepositoryExceededBatchLimit)
        );
        assert_eq!(repository.requested_limit.get(), Some(1));
        assert!(repository.committed.is_empty());
    }
}
