//! Owned blocking journal I/O, isolated from session heartbeat/read/write.
//! Requests and unconsumed replies share a bounded logical-byte/count budget.
//! No socket or concrete store dependency belongs in this module.

use fleet_application::delivery::{
    AdmitAgentExecution, AgentExecutionRepository, AgentReportRepository, AppendReportOutcome,
    ConfirmAgentReport, ExecutionAdmission, JournalError, JournalReport, PendingReport,
    QueueAgentReport, StartAgentExecution,
};
use fleet_domain::delivery::{ExecutionRecord, JournalCapacity, ReportDigest, ReportKey};
use std::fmt::{Debug, Display, Formatter};
use std::sync::{Arc, Mutex, Weak, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Immutable bootstrap limits; this is logical payload accounting, not allocator
/// exactness. A replay read reserves its entire requested maximum response size.
#[derive(Clone, Copy, Debug)]
pub struct JournalWorkerLimits {
    requests: usize,
    total_bytes: u64,
    request_bytes: u64,
}

impl JournalWorkerLimits {
    /// Accepts 1..=4096 outstanding requests and positive logical byte limits,
    /// with the per-request bound no greater than the combined bound.
    pub fn new(
        requests: usize,
        total_bytes: u64,
        request_bytes: u64,
    ) -> Result<Self, JournalWorkerError> {
        if requests == 0 || requests > 4096 || request_bytes == 0 || request_bytes > total_bytes {
            return Err(JournalWorkerError::InvalidLimits);
        }
        Ok(Self {
            requests,
            total_bytes,
            request_bytes,
        })
    }
}

struct Gate {
    sender: Option<mpsc::SyncSender<WorkItem>>,
    limits: JournalWorkerLimits,
    requests: usize,
    bytes: u64,
}

struct Lease {
    gate: Weak<Mutex<Gate>>,
    bytes: u64,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(gate) = self.gate.upgrade() {
            let mut gate = gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            gate.requests -= 1;
            gate.bytes -= self.bytes;
        }
    }
}

type Reply<T> = mpsc::SyncSender<Result<T, JournalError>>;

enum Operation {
    Append(JournalReport, Reply<AppendReportOutcome>),
    Pending(u32, u64, Reply<Vec<PendingReport>>),
    Acknowledge(ReportKey, ReportDigest, Reply<bool>),
    Admit(ExecutionRecord, Reply<ExecutionAdmission>),
    Start(ReportKey, Reply<()>),
    Interrupted(Reply<Option<ExecutionRecord>>),
}

struct WorkItem {
    operation: Operation,
    _lease: Arc<Lease>,
}

/// Closing the owner atomically refuses new submissions (including cloned
/// clients), drains accepted requests, and joins the worker. An OS-blocked disk
/// operation cannot safely be canceled or detached; shutdown waits for it.
pub struct JournalWorker {
    client: JournalClient,
    join: Option<JoinHandle<()>>,
}

impl JournalWorker {
    /// Moves the repository to one owned thread. Shutdown closes every cloned
    /// client's submission gate and joins that thread; no worker is detached.
    pub fn spawn<R>(
        repository: R,
        capacity: JournalCapacity,
        limits: JournalWorkerLimits,
    ) -> Result<Self, JournalWorkerError>
    where
        R: AgentReportRepository + AgentExecutionRepository + Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel(limits.requests);
        let client = JournalClient {
            gate: Arc::new(Mutex::new(Gate {
                sender: Some(sender),
                limits,
                requests: 0,
                bytes: 0,
            })),
        };
        let join = thread::Builder::new()
            .name("fleet-agent-journal".to_owned())
            .spawn(move || run(repository, capacity, receiver))
            .map_err(|_| JournalWorkerError::Stopped)?;
        Ok(Self {
            client,
            join: Some(join),
        })
    }

    pub fn client(&self) -> JournalClient {
        self.client.clone()
    }

    /// Must be called outside the session loop; joins all accepted disk work.
    pub fn shutdown(mut self) -> Result<(), JournalWorkerError> {
        self.stop()
    }

    fn stop(&mut self) -> Result<(), JournalWorkerError> {
        let sender = self
            .client
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sender
            .take();
        drop(sender);
        if let Some(join) = self.join.take() {
            join.join().map_err(|_| JournalWorkerError::Panicked)?;
        }
        Ok(())
    }
}

impl Drop for JournalWorker {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Submission only takes a short in-memory lock and never waits for disk or queue
/// space. Busy means not submitted; caller retains the original report for retry.
#[derive(Clone)]
pub struct JournalClient {
    gate: Arc<Mutex<Gate>>,
}

impl JournalClient {
    pub fn append(
        &self,
        report: &JournalReport,
    ) -> Result<JournalTicket<AppendReportOutcome>, JournalWorkerError> {
        self.submit(report.accounted_bytes(), |reply| {
            Operation::Append(report.clone(), reply)
        })
    }

    pub fn pending(
        &self,
        max_reports: u32,
        max_bytes: u64,
    ) -> Result<JournalTicket<Vec<PendingReport>>, JournalWorkerError> {
        if max_reports == 0 || max_reports > 4096 || max_bytes == 0 {
            return Err(JournalWorkerError::InvalidLimits);
        }
        self.submit(max_bytes, |reply| {
            Operation::Pending(max_reports, max_bytes, reply)
        })
    }

    /// Only an authenticated Controller's durable receipt may reach this method.
    pub fn acknowledge(
        &self,
        key: &ReportKey,
        digest: ReportDigest,
    ) -> Result<JournalTicket<bool>, JournalWorkerError> {
        self.submit(key_bytes(key), |reply| {
            Operation::Acknowledge(key.clone(), digest, reply)
        })
    }

    /// Signature, target, expiry and durable nonce checks precede admission.
    pub fn admit(
        &self,
        record: &ExecutionRecord,
    ) -> Result<JournalTicket<ExecutionAdmission>, JournalWorkerError> {
        self.submit(record.accounted_bytes(), |reply| {
            Operation::Admit(record.clone(), reply)
        })
    }

    /// Wait for successful completion before permitting any host side effect.
    pub fn start(&self, key: &ReportKey) -> Result<JournalTicket<()>, JournalWorkerError> {
        self.submit(key_bytes(key), |reply| Operation::Start(key.clone(), reply))
    }

    /// For process bootstrap only, not reconnection of the still-live task owner.
    pub fn interrupted(
        &self,
    ) -> Result<JournalTicket<Option<ExecutionRecord>>, JournalWorkerError> {
        self.submit(5 * 256 + 96, Operation::Interrupted)
    }

    fn submit<T>(
        &self,
        bytes: u64,
        operation: impl FnOnce(Reply<T>) -> Operation,
    ) -> Result<JournalTicket<T>, JournalWorkerError> {
        let (reply, receiver) = mpsc::sync_channel(1);
        let mut gate = self.gate.lock().map_err(|_| JournalWorkerError::Stopped)?;
        if gate.sender.is_none() {
            return Err(JournalWorkerError::Stopped);
        }
        if bytes > gate.limits.request_bytes {
            return Err(JournalWorkerError::RequestTooLarge);
        }
        let total = gate
            .bytes
            .checked_add(bytes)
            .ok_or(JournalWorkerError::Busy)?;
        if gate.requests >= gate.limits.requests || total > gate.limits.total_bytes {
            return Err(JournalWorkerError::Busy);
        }
        gate.requests += 1;
        gate.bytes = total;
        let lease = Arc::new(Lease {
            gate: Arc::downgrade(&self.gate),
            bytes,
        });
        let work = WorkItem {
            operation: operation(reply),
            _lease: lease.clone(),
        };
        let result = gate
            .sender
            .as_ref()
            .ok_or(JournalWorkerError::Stopped)?
            .try_send(work);
        drop(gate); // Drop rejected work/leases only after releasing the gate lock.
        match result {
            Ok(()) => Ok(JournalTicket {
                receiver,
                lease: Some(lease),
            }),
            Err(mpsc::TrySendError::Full(_)) => Err(JournalWorkerError::Busy),
            Err(mpsc::TrySendError::Disconnected(_)) => Err(JournalWorkerError::Stopped),
        }
    }
}

fn key_bytes(key: &ReportKey) -> u64 {
    key.parts()
        .iter()
        .map(|part| part.len() as u64)
        .sum::<u64>()
        + 64
}

/// A queue submission is not a commit. Only Ok(Some(value)) / successful wait
/// crosses the repository completion barrier. Dropping/timing out does NOT cancel
/// an accepted write: it may still commit, and must be retried with the same ID.
pub struct JournalTicket<T> {
    receiver: mpsc::Receiver<Result<T, JournalError>>,
    lease: Option<Arc<Lease>>,
}

impl<T> JournalTicket<T> {
    pub fn poll(&mut self) -> Result<Option<T>, JournalWorkerError> {
        if self.lease.is_none() {
            return Err(JournalWorkerError::AlreadyCompleted);
        }
        match self.receiver.try_recv() {
            Ok(value) => {
                self.lease.take();
                value.map(Some).map_err(JournalWorkerError::Repository)
            }
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => {
                self.lease.take();
                Err(JournalWorkerError::Stopped)
            }
        }
    }

    /// Blocking alternative for execution workers, never for the socket owner.
    /// TimedOut means the write's outcome is still pending, not that it was undone.
    pub fn wait(self, timeout: Duration) -> Result<T, JournalWorkerError> {
        if self.lease.is_none() {
            return Err(JournalWorkerError::AlreadyCompleted);
        }
        self.receiver
            .recv_timeout(timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => JournalWorkerError::TimedOut,
                mpsc::RecvTimeoutError::Disconnected => JournalWorkerError::Stopped,
            })?
            .map_err(JournalWorkerError::Repository)
    }
}

impl<T> Debug for JournalTicket<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JournalTicket")
            .field("completed", &self.lease.is_none())
            .finish_non_exhaustive()
    }
}

fn run<R: AgentReportRepository + AgentExecutionRepository>(
    mut repository: R,
    capacity: JournalCapacity,
    receiver: mpsc::Receiver<WorkItem>,
) {
    for work in receiver {
        let WorkItem {
            operation,
            _lease: lease,
        } = work;
        match operation {
            Operation::Append(report, reply) => {
                complete(
                    reply,
                    QueueAgentReport::execute(&mut repository, &report, capacity),
                    lease,
                );
            }
            Operation::Pending(count, bytes, reply) => {
                complete(reply, repository.pending(count, bytes), lease);
            }
            Operation::Acknowledge(key, digest, reply) => {
                complete(
                    reply,
                    ConfirmAgentReport::execute(&mut repository, &key, digest),
                    lease,
                );
            }
            Operation::Admit(record, reply) => {
                complete(
                    reply,
                    AdmitAgentExecution::execute(&mut repository, &record, capacity),
                    lease,
                );
            }
            Operation::Start(key, reply) => {
                complete(
                    reply,
                    StartAgentExecution::execute(&mut repository, &key),
                    lease,
                );
            }
            Operation::Interrupted(reply) => {
                complete(reply, repository.interrupted_execution(), lease);
            }
        }
    }
}

fn complete<T>(reply: Reply<T>, value: Result<T, JournalError>, lease: Arc<Lease>) {
    // An unconsumed ticket still owns the permit. Release the worker's share
    // before publishing completion so a consumed ticket immediately frees budget.
    drop(lease);
    let _ = reply.send(value);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalWorkerError {
    InvalidLimits,
    RequestTooLarge,
    Busy,
    Stopped,
    Panicked,
    TimedOut,
    AlreadyCompleted,
    Repository(JournalError),
}

impl Display for JournalWorkerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("invalid journal worker limits"),
            Self::RequestTooLarge => f.write_str("journal worker request exceeds byte limit"),
            Self::Busy => f.write_str("journal worker capacity exhausted"),
            Self::Stopped => f.write_str("journal worker stopped"),
            Self::Panicked => f.write_str("journal worker panicked"),
            Self::TimedOut => f.write_str("journal operation still pending after wait timeout"),
            Self::AlreadyCompleted => f.write_str("journal completion already consumed"),
            Self::Repository(error) => Display::fmt(error, f),
        }
    }
}
impl std::error::Error for JournalWorkerError {}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_domain::delivery::{ExecutionPhase, ExecutionSnapshot, JournalUsage, ReportClass};

    struct FakeRepository {
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
        reports: Vec<JournalReport>,
        execution: Option<ExecutionRecord>,
        caller: thread::ThreadId,
        panic_on_pending: bool,
    }
    impl AgentReportRepository for FakeRepository {
        fn append(
            &mut self,
            report: &JournalReport,
            _: JournalCapacity,
        ) -> Result<AppendReportOutcome, JournalError> {
            assert_ne!(thread::current().id(), self.caller);
            let _ = self.entered.send(());
            self.release
                .recv_timeout(Duration::from_secs(2))
                .map_err(|_| JournalError::Unavailable)?;
            self.reports.push(report.clone());
            Ok(AppendReportOutcome::Inserted)
        }
        fn pending(
            &self,
            max_reports: u32,
            max_bytes: u64,
        ) -> Result<Vec<PendingReport>, JournalError> {
            assert_ne!(thread::current().id(), self.caller);
            assert!(!self.panic_on_pending, "injected repository panic");
            let mut bytes = 0;
            Ok(self
                .reports
                .iter()
                .take(max_reports as usize)
                .take_while(|report| {
                    bytes += report.accounted_bytes();
                    bytes <= max_bytes
                })
                .cloned()
                .map(|report| PendingReport {
                    report,
                    digest: ReportDigest([1; 32]),
                })
                .collect())
        }
        fn acknowledge(
            &mut self,
            key: &ReportKey,
            digest: ReportDigest,
        ) -> Result<bool, JournalError> {
            assert_ne!(thread::current().id(), self.caller);
            if digest != ReportDigest([1; 32]) {
                return Err(JournalError::InvalidReceipt);
            }
            let before = self.reports.len();
            self.reports.retain(|report| &report.key != key);
            Ok(self.reports.len() != before)
        }
    }
    impl AgentExecutionRepository for FakeRepository {
        fn admit_execution(
            &mut self,
            record: &ExecutionRecord,
            _: JournalCapacity,
        ) -> Result<ExecutionAdmission, JournalError> {
            assert_ne!(thread::current().id(), self.caller);
            assert_eq!(record.snapshot().phase, ExecutionPhase::Admitted);
            self.execution = Some(record.clone());
            Ok(ExecutionAdmission::New)
        }
        fn start_execution(&mut self, key: &ReportKey) -> Result<(), JournalError> {
            assert_ne!(thread::current().id(), self.caller);
            let execution = self
                .execution
                .as_mut()
                .ok_or(JournalError::InvalidExecutionTransition)?;
            if &execution.snapshot().final_report_key != key {
                return Err(JournalError::Conflict);
            }
            execution
                .record_start_intent()
                .map_err(|_| JournalError::InvalidExecutionTransition)
        }
        fn interrupted_execution(&self) -> Result<Option<ExecutionRecord>, JournalError> {
            assert_ne!(thread::current().id(), self.caller);
            Ok(self.execution.clone())
        }
    }
    fn capacity() -> JournalCapacity {
        JournalCapacity::new(
            JournalUsage {
                reports: 16,
                bytes: 10_000,
            },
            JournalUsage {
                reports: 2,
                bytes: 1000,
            },
        )
        .unwrap()
    }
    fn report() -> JournalReport {
        JournalReport::new(
            ReportKey::new("controller", "agent", "job", "task", "report").unwrap(),
            ReportClass::Output,
            b"private fixture output".to_vec(),
        )
        .unwrap()
    }
    fn worker(
        limits: JournalWorkerLimits,
    ) -> (JournalWorker, mpsc::Receiver<()>, mpsc::SyncSender<()>) {
        let (entered, entering) = mpsc::sync_channel(8);
        let (release, releasing) = mpsc::sync_channel(8);
        (
            JournalWorker::spawn(
                FakeRepository {
                    entered,
                    release: releasing,
                    reports: vec![],
                    execution: None,
                    caller: thread::current().id(),
                    panic_on_pending: false,
                },
                capacity(),
                limits,
            )
            .unwrap(),
            entering,
            release,
        )
    }

    #[test]
    fn uncommitted_write_never_returns_a_send_permission() {
        let (worker, entered, release) = worker(JournalWorkerLimits::new(4, 10_000, 5000).unwrap());
        let mut ticket = worker.client().append(&report()).unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(ticket.poll(), Ok(None));
        release.send(()).unwrap();
        assert_eq!(
            ticket.wait(Duration::from_secs(1)),
            Ok(AppendReportOutcome::Inserted)
        );
        worker.shutdown().unwrap();
    }

    #[test]
    fn outstanding_request_limit_includes_running_and_unconsumed_work() {
        let (worker, entered, release) = worker(JournalWorkerLimits::new(1, 10_000, 5000).unwrap());
        let client = worker.client();
        let first = client.append(&report()).unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            client.append(&report()),
            Err(JournalWorkerError::Busy)
        ));
        release.send(()).unwrap();
        first.wait(Duration::from_secs(1)).unwrap();
        worker.shutdown().unwrap();
    }

    #[test]
    fn slow_write_does_not_block_session_poll_or_another_submission() {
        let (worker, entered, release) = worker(JournalWorkerLimits::new(4, 10_000, 5000).unwrap());
        let client = worker.client();
        let mut write = client.append(&report()).unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        let mut read = client.pending(4, 4000).unwrap();
        for _ in 0..100 {
            assert_eq!(write.poll(), Ok(None));
            assert_eq!(read.poll(), Ok(None));
        }
        release.send(()).unwrap();
        write.wait(Duration::from_secs(1)).unwrap();
        assert_eq!(
            read.wait(Duration::from_secs(1)).unwrap()[0].report,
            report()
        );
        worker.shutdown().unwrap();
    }

    #[test]
    fn retained_response_still_counts_until_consumed() {
        let (worker, entered, release) = worker(JournalWorkerLimits::new(1, 10_000, 5000).unwrap());
        let client = worker.client();
        let mut ticket = client.append(&report()).unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        release.send(()).unwrap();
        // Receiving directly only in this test leaves the ticket's lease intact.
        assert!(
            ticket
                .receiver
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .is_ok()
        );
        assert!(matches!(
            client.pending(1, 1000),
            Err(JournalWorkerError::Busy)
        ));
        drop(ticket.lease.take());
        assert_eq!(ticket.poll(), Err(JournalWorkerError::AlreadyCompleted));
        let next = client.pending(1, 1000).unwrap();
        assert_eq!(next.wait(Duration::from_secs(1)).unwrap().len(), 1);
        worker.shutdown().unwrap();
    }

    #[test]
    fn dropped_or_timed_out_ticket_does_not_cancel_accepted_write() {
        let (worker, entered, release) = worker(JournalWorkerLimits::new(2, 10_000, 5000).unwrap());
        let client = worker.client();
        let ticket = client.append(&report()).unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            ticket.wait(Duration::ZERO),
            Err(JournalWorkerError::TimedOut)
        );
        let pending = client.pending(2, 4000).unwrap();
        assert!(matches!(
            client.append(&report()),
            Err(JournalWorkerError::Busy)
        ));
        release.send(()).unwrap();
        assert_eq!(
            pending.wait(Duration::from_secs(1)).unwrap()[0].report,
            report()
        );
        worker.shutdown().unwrap();
    }

    #[test]
    fn byte_limits_bound_writes_and_reserved_replay_responses() {
        let bytes = report().accounted_bytes();
        let (worker, entered, release) =
            worker(JournalWorkerLimits::new(8, bytes * 2 - 1, bytes).unwrap());
        let client = worker.client();
        let ticket = client.append(&report()).unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            client.append(&report()),
            Err(JournalWorkerError::Busy)
        ));
        assert!(matches!(
            client.pending(1, bytes),
            Err(JournalWorkerError::Busy)
        ));
        assert!(matches!(
            client.pending(1, bytes + 1),
            Err(JournalWorkerError::RequestTooLarge)
        ));
        release.send(()).unwrap();
        ticket.wait(Duration::from_secs(1)).unwrap();
        worker.shutdown().unwrap();
    }

    #[test]
    fn shutdown_drains_accepted_requests_and_revokes_all_clients() {
        let (worker, entered, release) = worker(JournalWorkerLimits::new(4, 10_000, 5000).unwrap());
        let client = worker.client();
        let first = client.append(&report()).unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        let pending = client.pending(1, 4000).unwrap();
        release.send(()).unwrap();
        worker.shutdown().unwrap();
        assert!(first.wait(Duration::from_secs(1)).is_ok());
        assert_eq!(pending.wait(Duration::from_secs(1)).unwrap().len(), 1);
        assert!(matches!(
            client.append(&report()),
            Err(JournalWorkerError::Stopped)
        ));
    }

    #[test]
    fn repository_failure_has_no_success_fallback() {
        let (worker, entered, release) = worker(JournalWorkerLimits::new(4, 10_000, 5000).unwrap());
        let client = worker.client();
        let ticket = client.append(&report()).unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(release);
        assert_eq!(
            ticket.wait(Duration::from_secs(1)),
            Err(JournalWorkerError::Repository(JournalError::Unavailable))
        );
        assert!(
            client
                .pending(1, 4000)
                .unwrap()
                .wait(Duration::from_secs(1))
                .unwrap()
                .is_empty()
        );
        worker.shutdown().unwrap();
    }

    #[test]
    fn execution_and_receipt_commands_use_the_same_serial_owner() {
        let (worker, _, release) = worker(JournalWorkerLimits::new(4, 10_000, 5000).unwrap());
        let client = worker.client();
        let record = ExecutionRecord::restore(ExecutionSnapshot {
            final_report_key: report().key,
            nonce_digest: ReportDigest([2; 32]),
            envelope_digest: ReportDigest([3; 32]),
            phase: ExecutionPhase::Admitted,
            admitted_at_ms: 1,
            final_max_bytes: 1000,
            stdout_chunks: 0,
            stderr_chunks: 0,
        })
        .unwrap();
        assert_eq!(
            client.admit(&record).unwrap().wait(Duration::from_secs(1)),
            Ok(ExecutionAdmission::New)
        );
        client
            .start(&record.snapshot().final_report_key)
            .unwrap()
            .wait(Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            client
                .interrupted()
                .unwrap()
                .wait(Duration::from_secs(1))
                .unwrap()
                .unwrap()
                .snapshot()
                .phase,
            ExecutionPhase::StartIntent
        );
        release.send(()).unwrap();
        client
            .append(&report())
            .unwrap()
            .wait(Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            client
                .acknowledge(&report().key, ReportDigest([0; 32]))
                .unwrap()
                .wait(Duration::from_secs(1)),
            Err(JournalWorkerError::Repository(JournalError::InvalidReceipt))
        );
        assert!(
            client
                .acknowledge(&report().key, ReportDigest([1; 32]))
                .unwrap()
                .wait(Duration::from_secs(1))
                .unwrap()
        );
        worker.shutdown().unwrap();
    }

    #[test]
    fn invalid_limits_are_rejected_before_allocating_a_channel() {
        for (count, total, request) in [
            (0, 100, 10),
            (4097, 100, 10),
            (1, 0, 1),
            (1, 100, 0),
            (1, 100, 101),
        ] {
            assert!(matches!(
                JournalWorkerLimits::new(count, total, request),
                Err(JournalWorkerError::InvalidLimits)
            ));
        }
    }

    #[test]
    fn worker_panic_is_observed_and_joined_without_fake_completion() {
        let (entered, _) = mpsc::sync_channel(1);
        let (_, release) = mpsc::sync_channel(1);
        let worker = JournalWorker::spawn(
            FakeRepository {
                entered,
                release,
                reports: vec![],
                execution: None,
                caller: thread::current().id(),
                panic_on_pending: true,
            },
            capacity(),
            JournalWorkerLimits::new(2, 10_000, 5000).unwrap(),
        )
        .unwrap();
        let ticket = worker.client().pending(1, 1000).unwrap();
        assert_eq!(
            ticket.wait(Duration::from_secs(1)),
            Err(JournalWorkerError::Stopped)
        );
        assert_eq!(worker.shutdown(), Err(JournalWorkerError::Panicked));
    }
}
