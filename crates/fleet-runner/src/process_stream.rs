//! Darwin/Linux streaming process ownership. poll keeps cancellation responsive
//! without detached pipe-reader threads or an unbounded channel. The group leader
//! remains unreaped until cleanup so its PID cannot be reused before group kill.

use super::{CommandOutput, CommandOutputChunk, CommandOutputStream, CommandSpec, RunnerError};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::Instant;

struct ProcessOwner {
    child: Child,
    pid: Pid,
    owns_pid: bool,
}

impl ProcessOwner {
    fn spawn(spec: &CommandSpec) -> Result<Self, RunnerError> {
        let mut child = Command::new(&spec.program)
            .args(&spec.args)
            .envs(&spec.env)
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let Some(pid) = Pid::from_raw(child.id() as i32) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RunnerError::Io("invalid child process identity".to_owned()));
        };
        Ok(Self {
            child,
            pid,
            owns_pid: true,
        })
    }

    fn exit_code_without_reaping(&mut self) -> Result<Option<i32>, RunnerError> {
        match waitid(
            WaitId::Pid(self.pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ) {
            Ok(status) => Ok(status.map(|status| status.exit_status().unwrap_or(-1))),
            Err(rustix::io::Errno::INTR) => Ok(None),
            Err(rustix::io::Errno::CHILD) => {
                self.owns_pid = false;
                Err(RunnerError::Io("child process ownership lost".to_owned()))
            }
            Err(_) => Err(RunnerError::Io(
                "child process observation failed".to_owned(),
            )),
        }
    }
}

impl Drop for ProcessOwner {
    fn drop(&mut self) {
        if self.owns_pid {
            // Only this newly spawned, still-unreaped leader identifies the group.
            // Never signal a PID loaded from a journal or discovered after restart.
            let _ = kill_process_group(self.pid, Signal::KILL);
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub(super) fn run(
    spec: CommandSpec,
    mut should_cancel: impl FnMut() -> bool,
    mut on_chunk: impl FnMut(CommandOutputChunk) -> Result<(), RunnerError>,
) -> Result<CommandOutput, RunnerError> {
    let started_at = Instant::now();
    let mut owner = ProcessOwner::spawn(&spec)?;
    let mut stdout = owner
        .child
        .stdout
        .take()
        .ok_or_else(|| RunnerError::Io("stdout pipe unavailable".to_owned()))?;
    let mut stderr = owner
        .child
        .stderr
        .take()
        .ok_or_else(|| RunnerError::Io("stderr pipe unavailable".to_owned()))?;
    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut stdout_body = Vec::new();
    let mut stderr_body = Vec::new();
    let mut stdout_sequence = 0;
    let mut stderr_sequence = 0;
    let poll_interval = Timespec {
        tv_sec: 0,
        tv_nsec: 10_000_000,
    };
    let mut buffer = [0u8; 16 * 1024];

    loop {
        if should_cancel() {
            return Err(RunnerError::Canceled);
        }
        if started_at.elapsed() >= spec.timeout {
            return Err(RunnerError::Timeout);
        }
        if let Some(exit_code) = owner.exit_code_without_reaping()?
            && !stdout_open
            && !stderr_open
        {
            return Ok(CommandOutput {
                stdout: String::from_utf8_lossy(&stdout_body).into_owned(),
                stderr: String::from_utf8_lossy(&stderr_body).into_owned(),
                exit_code,
                truncated: false,
            });
        }
        let (stdout_ready, stderr_ready) = {
            let mut fds = Vec::with_capacity(2);
            if stdout_open {
                fds.push(PollFd::new(&stdout, PollFlags::IN));
            }
            if stderr_open {
                fds.push(PollFd::new(&stderr, PollFlags::IN));
            }
            match poll(&mut fds, Some(&poll_interval)) {
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(_) => return Err(RunnerError::Io("command output poll failed".to_owned())),
            }
            let ready = PollFlags::IN | PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL;
            let stdout_ready = stdout_open && fds[0].revents().intersects(ready);
            let stderr_ready =
                stderr_open && fds[usize::from(stdout_open)].revents().intersects(ready);
            (stdout_ready, stderr_ready)
        };
        // At most one bounded read per stream before checking timeout/cancel again.
        for (ready, open, stream, reader) in [
            (
                stdout_ready,
                &mut stdout_open,
                CommandOutputStream::Stdout,
                &mut stdout as &mut dyn Read,
            ),
            (
                stderr_ready,
                &mut stderr_open,
                CommandOutputStream::Stderr,
                &mut stderr as &mut dyn Read,
            ),
        ] {
            if !ready {
                continue;
            }
            let count = match reader.read(&mut buffer) {
                Ok(0) => {
                    *open = false;
                    continue;
                }
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            let total = stdout_body
                .len()
                .checked_add(stderr_body.len())
                .and_then(|total| total.checked_add(count))
                .ok_or(RunnerError::OutputLimitExceeded)?;
            if total > spec.max_output_bytes {
                return Err(RunnerError::OutputLimitExceeded);
            }
            match stream {
                CommandOutputStream::Stdout => stdout_body.extend_from_slice(&buffer[..count]),
                CommandOutputStream::Stderr => stderr_body.extend_from_slice(&buffer[..count]),
            }
            let sequence = match stream {
                CommandOutputStream::Stdout => &mut stdout_sequence,
                CommandOutputStream::Stderr => &mut stderr_sequence,
            };
            on_chunk(CommandOutputChunk {
                stream,
                sequence: *sequence,
                data: String::from_utf8_lossy(&buffer[..count]).into_owned(),
            })?;
            *sequence += 1;
        }
    }
}
