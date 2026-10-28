//! Owned bounded password CPU work; clients have no database or credential-issuance authority.

use crate::admin_crypto::{AdminAuthSettings, AdminPasswordPrimitives};
use fleet_application::admin_identity::{AdminAccessError, AdminOperation, AdminPasswordPort};
use fleet_domain::{AdminPasswordVerifier, AdminUsername};
use std::fmt::{Debug, Formatter};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Request owner: dropping it cancels every handle, including queued/running CPU work.
pub struct AdminAuthRequest {
    operation: AdminAuthOperation,
}

impl AdminAuthRequest {
    pub fn new(settings: AdminAuthSettings) -> Result<Self, AdminAccessError> {
        let deadline = Instant::now()
            .checked_add(settings.auth_timeout())
            .ok_or(AdminAccessError::Unavailable)?;
        Ok(Self {
            operation: AdminAuthOperation {
                deadline,
                cancelled: Arc::new(AtomicBool::new(false)),
            },
        })
    }

    pub fn operation(&self) -> AdminAuthOperation {
        self.operation.clone()
    }
    pub fn cancel(&self) {
        self.operation.cancelled.store(true, Ordering::Release);
    }
}

impl Drop for AdminAuthRequest {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Immutable fixed monotonic deadline plus a shared cancellation signal; never sliding.
#[derive(Clone)]
pub struct AdminAuthOperation {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}

impl AdminAuthOperation {
    fn remaining(&self) -> Result<Duration, AdminAccessError> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if self.cancelled.load(Ordering::Acquire) || remaining.is_zero() {
            return Err(AdminAccessError::OperationExpired);
        }
        Ok(remaining)
    }
}

impl AdminOperation for AdminAuthOperation {
    fn checked_now(&self) -> Result<i64, AdminAccessError> {
        self.remaining()?;
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|value| i64::try_from(value.as_secs()).ok())
            .ok_or(AdminAccessError::Unavailable)
    }
}

enum PasswordTask {
    Hash {
        input: Zeroizing<String>,
        username: AdminUsername,
    },
    Verify {
        input: Zeroizing<String>,
        verifier: Option<AdminPasswordVerifier>,
    },
}

#[derive(Debug)]
enum PasswordValue {
    Verifier(AdminPasswordVerifier),
    Verified(bool),
}

type PasswordExecutor =
    Arc<dyn Fn(PasswordTask) -> Result<PasswordValue, AdminAccessError> + Send + Sync>;

struct Work {
    task: PasswordTask,
    operation: AdminAuthOperation,
    reply: mpsc::SyncSender<Result<PasswordValue, AdminAccessError>>,
    lease: Arc<Admission>,
}

struct Gate {
    sender: Option<mpsc::SyncSender<Work>>,
    admitted: usize,
    maximum: usize,
}

struct Admission {
    gate: Weak<Mutex<Gate>>,
}

impl Drop for Admission {
    fn drop(&mut self) {
        if let Some(gate) = self.gate.upgrade() {
            let mut gate = gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            gate.admitted -= 1;
        }
    }
}

struct PasswordTicket {
    receiver: mpsc::Receiver<Result<PasswordValue, AdminAccessError>>,
    _lease: Arc<Admission>,
}

impl Debug for PasswordTicket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordTicket([REDACTED])")
    }
}

impl PasswordTicket {
    fn wait(self, operation: &AdminAuthOperation) -> Result<PasswordValue, AdminAccessError> {
        loop {
            let interval = operation.remaining()?.min(Duration::from_millis(25));
            match self.receiver.recv_timeout(interval) {
                Ok(result) => {
                    operation.checked_now()?;
                    return result;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(AdminAccessError::Unavailable);
                }
            }
        }
    }
}

/// Lifecycle owner. Shutdown rejects every cloned client, skips queued work and
/// joins all native computations; running Argon2 cannot be forcibly interrupted.
/// Runtime callers must join outside the async executor and outside database locks.
pub struct AdminPasswordWorker {
    client: AdminPasswordClient,
    joins: Vec<JoinHandle<Result<(), AdminAccessError>>>,
}

impl AdminPasswordWorker {
    pub fn spawn(settings: AdminAuthSettings) -> Result<Self, AdminAccessError> {
        Self::spawn_with(settings, Arc::new(execute_password))
    }

    fn spawn_with(
        settings: AdminAuthSettings,
        executor: PasswordExecutor,
    ) -> Result<Self, AdminAccessError> {
        let (sender, receiver) = mpsc::sync_channel(settings.pending_capacity());
        let receiver = Arc::new(Mutex::new(receiver));
        let mut owner = Self {
            client: AdminPasswordClient {
                gate: Arc::new(Mutex::new(Gate {
                    sender: Some(sender),
                    admitted: 0,
                    maximum: settings.worker_count() + settings.pending_capacity(),
                })),
                stopping: Arc::new(AtomicBool::new(false)),
            },
            joins: Vec::with_capacity(settings.worker_count()),
        };
        for index in 0..settings.worker_count() {
            let receiver = receiver.clone();
            let executor = executor.clone();
            let client = owner.client.clone();
            let join = thread::Builder::new()
                .name(format!("fleet-admin-kdf-{index}"))
                .spawn(move || run_password_worker(receiver, executor, client))
                .map_err(|_| AdminAccessError::Unavailable)?;
            owner.joins.push(join);
        }
        Ok(owner)
    }

    pub fn client(&self) -> AdminPasswordClient {
        self.client.clone()
    }

    pub fn shutdown(mut self) -> Result<(), AdminAccessError> {
        self.stop()
    }

    fn close_submission(&mut self) {
        self.client.close_submission();
    }

    fn stop(&mut self) -> Result<(), AdminAccessError> {
        self.close_submission();
        let mut failed = false;
        for join in self.joins.drain(..) {
            if !matches!(join.join(), Ok(Ok(()))) {
                failed = true;
            }
        }
        if failed {
            Err(AdminAccessError::Unavailable)
        } else {
            Ok(())
        }
    }
}

impl Drop for AdminPasswordWorker {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Cloneable submission handle, with no ownership of the worker thread lifecycle.
#[derive(Clone)]
pub struct AdminPasswordClient {
    gate: Arc<Mutex<Gate>>,
    stopping: Arc<AtomicBool>,
}

impl AdminPasswordClient {
    pub fn passwords<'a>(&'a self, operation: &'a AdminAuthOperation) -> ScopedAdminPasswords<'a> {
        ScopedAdminPasswords {
            client: self,
            operation,
        }
    }

    fn close_submission(&self) {
        self.stopping.store(true, Ordering::Release);
        let sender = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sender
            .take();
        drop(sender);
    }

    fn submit(
        &self,
        operation: &AdminAuthOperation,
        task: impl FnOnce() -> PasswordTask,
    ) -> Result<PasswordTicket, AdminAccessError> {
        operation.checked_now()?;
        let mut gate = self
            .gate
            .lock()
            .map_err(|_| AdminAccessError::Unavailable)?;
        if gate.sender.is_none() || self.stopping.load(Ordering::Acquire) {
            return Err(AdminAccessError::Unavailable);
        }
        if gate.admitted >= gate.maximum {
            return Err(AdminAccessError::Busy);
        }
        gate.admitted += 1;
        let lease = Arc::new(Admission {
            gate: Arc::downgrade(&self.gate),
        });
        let (reply, receiver) = mpsc::sync_channel(1);
        let work = Work {
            task: task(),
            operation: operation.clone(),
            reply,
            lease: lease.clone(),
        };
        let sent = if let Some(sender) = &gate.sender {
            sender.try_send(work)
        } else {
            drop(gate);
            drop(work);
            return Err(AdminAccessError::Unavailable);
        };
        // A failed send owns a Work/lease; release the gate before dropping it.
        drop(gate);
        match sent {
            Ok(()) => Ok(PasswordTicket {
                receiver,
                _lease: lease,
            }),
            Err(mpsc::TrySendError::Full(_)) => Err(AdminAccessError::Busy),
            Err(mpsc::TrySendError::Disconnected(_)) => Err(AdminAccessError::Unavailable),
        }
    }
}

/// Blocking Application adapter bound to one request's cancellation/deadline.
/// Use outside the async executor and without a store guard.
pub struct ScopedAdminPasswords<'a> {
    client: &'a AdminPasswordClient,
    operation: &'a AdminAuthOperation,
}

impl AdminPasswordPort for ScopedAdminPasswords<'_> {
    fn hash_new(
        &self,
        input: &str,
        username: &AdminUsername,
    ) -> Result<AdminPasswordVerifier, AdminAccessError> {
        validate_submission_input(input)?;
        let ticket = self.client.submit(self.operation, || PasswordTask::Hash {
            input: Zeroizing::new(input.to_owned()),
            username: username.clone(),
        })?;
        match ticket.wait(self.operation)? {
            PasswordValue::Verifier(verifier) => Ok(verifier),
            PasswordValue::Verified(_) => Err(AdminAccessError::Unavailable),
        }
    }

    fn verify(
        &self,
        input: &str,
        verifier: Option<&AdminPasswordVerifier>,
    ) -> Result<bool, AdminAccessError> {
        validate_submission_input(input)?;
        let ticket = self
            .client
            .submit(self.operation, || PasswordTask::Verify {
                input: Zeroizing::new(input.to_owned()),
                verifier: verifier.cloned(),
            })?;
        match ticket.wait(self.operation)? {
            PasswordValue::Verified(valid) => Ok(valid),
            PasswordValue::Verifier(_) => Err(AdminAccessError::Unavailable),
        }
    }
}

fn validate_submission_input(input: &str) -> Result<(), AdminAccessError> {
    if input.len() > 2_048 || input.chars().any(char::is_control) {
        return Err(AdminAccessError::InvalidRequest);
    }
    Ok(())
}

fn execute_password(task: PasswordTask) -> Result<PasswordValue, AdminAccessError> {
    let crypto = AdminPasswordPrimitives::system();
    match task {
        PasswordTask::Hash { input, username } => crypto
            .hash_new(&input, &username)
            .map(PasswordValue::Verifier),
        PasswordTask::Verify { input, verifier } => crypto
            .verify(&input, verifier.as_ref())
            .map(PasswordValue::Verified),
    }
}

fn run_password_worker(
    receiver: Arc<Mutex<mpsc::Receiver<Work>>>,
    executor: PasswordExecutor,
    client: AdminPasswordClient,
) -> Result<(), AdminAccessError> {
    loop {
        let next = match receiver.lock() {
            Ok(receiver) => receiver.recv(),
            Err(_) => {
                client.close_submission();
                return Err(AdminAccessError::Unavailable);
            }
        };
        let Ok(Work {
            task,
            operation,
            reply,
            lease,
        }) = next
        else {
            return Ok(());
        };
        let result = match execute_checked_password(task, &operation, &executor, &client) {
            Ok(result) => result,
            Err(()) => {
                client.close_submission();
                drop(lease);
                let _ = reply.try_send(Err(AdminAccessError::Unavailable));
                return Err(AdminAccessError::Unavailable);
            }
        };
        let result = if client.stopping.load(Ordering::Acquire) {
            Err(AdminAccessError::Unavailable)
        } else if let Err(error) = operation.checked_now() {
            Err(error)
        } else {
            result
        };
        // The ticket retains the reply reservation; release the worker's copy
        // before publishing, so consuming a reply deterministically releases it.
        drop(lease);
        let _ = reply.try_send(result);
    }
}

// Consumes queued input even when skipped, before releasing its admission lease.
fn execute_checked_password(
    task: PasswordTask,
    operation: &AdminAuthOperation,
    executor: &PasswordExecutor,
    client: &AdminPasswordClient,
) -> Result<Result<PasswordValue, AdminAccessError>, ()> {
    if client.stopping.load(Ordering::Acquire) {
        return Ok(Err(AdminAccessError::Unavailable));
    }
    if let Err(error) = operation.checked_now() {
        return Ok(Err(error));
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| executor(task))).map_err(|_| ())
}

#[cfg(test)]
#[path = "admin_password_worker_tests.rs"]
mod tests;
