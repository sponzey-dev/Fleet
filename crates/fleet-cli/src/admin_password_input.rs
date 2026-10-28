//! Bounded local password input and terminal-mode ownership, without argv or environment input.

use std::fmt::{Debug, Display, Formatter};
use std::io::Read;
use zeroize::{Zeroize, Zeroizing};

const MAX_RAW_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Input failures with static diagnostics, without raw password or I/O details.
pub enum PasswordInputError {
    Invalid,
    TooLong,
    Io,
    NoTerminal,
    Cancelled,
    DoesNotMatch,
}

impl Display for PasswordInputError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "password input must be nonempty UTF-8 without control characters or additional lines",
            Self::TooLong => "password input exceeds the 2048-byte raw input limit",
            Self::Io => "could not read password input or restore terminal settings",
            Self::NoTerminal => "a controlling terminal is required; use --password-stdin explicitly for a single password followed by EOF",
            Self::Cancelled => "password input cancelled",
            Self::DoesNotMatch => "password confirmation does not match",
        })
    }
}

impl std::error::Error for PasswordInputError {}

/// Owned input that is scrubbed on drop and only exposed to the password adapter.
pub(super) struct LocalPassword(Zeroizing<String>);

impl LocalPassword {
    fn from_bytes(bytes: &[u8]) -> Result<Self, PasswordInputError> {
        if bytes.len() > MAX_RAW_BYTES {
            return Err(PasswordInputError::TooLong);
        }
        let value = std::str::from_utf8(bytes).map_err(|_| PasswordInputError::Invalid)?;
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(PasswordInputError::Invalid);
        }
        Ok(Self(Zeroizing::new(value.to_owned())))
    }

    pub(super) fn expose(&self) -> &str {
        &self.0
    }
}

impl Debug for LocalPassword {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LocalPassword([REDACTED])")
    }
}

/// Reads one UTF-8 password through EOF, removing only one optional LF/CRLF.
/// The bound includes at most two transport-ending bytes; whitespace is preserved.
pub(super) fn read_stdin(reader: &mut impl Read) -> Result<LocalPassword, PasswordInputError> {
    // Fixed storage prevents reallocations from leaving an unwiped password copy.
    let mut storage = Zeroizing::new([0_u8; MAX_RAW_BYTES + 3]);
    let mut length = 0;
    loop {
        if length == storage.len() {
            return Err(PasswordInputError::TooLong);
        }
        match reader.read(&mut storage[length..]) {
            Ok(0) => break,
            Ok(count) => length += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(PasswordInputError::Io),
        }
    }
    let mut bytes = &storage[..length];
    if let Some(without_lf) = bytes.strip_suffix(b"\n") {
        bytes = without_lf.strip_suffix(b"\r").unwrap_or(without_lf);
    }
    LocalPassword::from_bytes(bytes)
}

/// Uses the controlling terminal, never implicitly consumes redirected stdin.
pub(super) fn read_new_password(use_stdin: bool) -> Result<LocalPassword, PasswordInputError> {
    if use_stdin {
        return read_stdin(&mut std::io::stdin().lock());
    }
    #[cfg(unix)]
    {
        let mut terminal = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|_| PasswordInputError::NoTerminal)?;
        read_terminal_pair(&mut terminal)
    }
    #[cfg(not(unix))]
    {
        Err(PasswordInputError::NoTerminal)
    }
}

/// Reads an existing token once using the same bounded, scrubbed terminal owner.
/// The caller maps static input failures to token-specific diagnostics.
pub(super) fn read_personal_token(
    use_stdin: bool,
) -> Result<Zeroizing<String>, PasswordInputError> {
    if use_stdin {
        return Ok(read_stdin(&mut std::io::stdin().lock())?.0);
    }
    #[cfg(unix)]
    {
        let mut terminal = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|_| PasswordInputError::NoTerminal)?;
        Ok(read_terminal_token(&mut terminal)?.0)
    }
    #[cfg(not(unix))]
    {
        Err(PasswordInputError::NoTerminal)
    }
}

#[cfg(unix)]
fn read_terminal_token(terminal: &mut std::fs::File) -> Result<LocalPassword, PasswordInputError> {
    let mut mode = TerminalMode::hide(terminal)?;
    let result = read_hidden(terminal, b"Personal token (hidden): ");
    mode.restore()?;
    result
}

#[cfg(unix)]
struct TerminalMode {
    terminal: std::fs::File,
    original: rustix::termios::Termios,
    restored: bool,
}

#[cfg(unix)]
impl TerminalMode {
    fn hide(terminal: &std::fs::File) -> Result<Self, PasswordInputError> {
        use rustix::termios::{
            OptionalActions, QueueSelector, SpecialCodeIndex, tcflush, tcgetattr, tcsetattr,
        };
        let terminal = terminal.try_clone().map_err(|_| PasswordInputError::Io)?;
        let original = tcgetattr(&terminal).map_err(|_| PasswordInputError::NoTerminal)?;
        let mut hidden = original.clone();
        // Raw input avoids canonical-terminal truncation and captures Ctrl-C/D/Z
        // as cancellation bytes so normal cancellation always restores the mode.
        hidden.make_raw();
        hidden.special_codes[SpecialCodeIndex::VMIN] = 1;
        hidden.special_codes[SpecialCodeIndex::VTIME] = 0;
        let mut owner = Self {
            terminal,
            original,
            restored: false,
        };
        if tcflush(&owner.terminal, QueueSelector::IFlush).is_err()
            || tcsetattr(&owner.terminal, OptionalActions::Now, &hidden).is_err()
        {
            let _ = owner.restore();
            return Err(PasswordInputError::Io);
        }
        Ok(owner)
    }

    fn restore(&mut self) -> Result<(), PasswordInputError> {
        if !self.restored {
            // TCSAFLUSH also waits for output drain, which can block restoration
            // behind an unread/stopped PTY. Discard input separately, then restore now.
            let flushed =
                rustix::termios::tcflush(&self.terminal, rustix::termios::QueueSelector::IFlush);
            let restored = rustix::termios::tcsetattr(
                &self.terminal,
                rustix::termios::OptionalActions::Now,
                &self.original,
            );
            // Darwin marks canonical re-entry PENDIN. Flush after restoration
            // too, so buffered input cannot be reprocessed/echoed by the next reader.
            let flushed_after =
                rustix::termios::tcflush(&self.terminal, rustix::termios::QueueSelector::IFlush);
            self.restored = restored.is_ok() && flushed_after.is_ok();
            if flushed.is_err() || restored.is_err() || flushed_after.is_err() {
                return Err(PasswordInputError::Io);
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for TerminalMode {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(unix)]
fn read_terminal_pair(terminal: &mut std::fs::File) -> Result<LocalPassword, PasswordInputError> {
    let mut mode = TerminalMode::hide(terminal)?;
    let result = (|| {
        let first = read_hidden(terminal, b"New password: ")?;
        let second = read_hidden(terminal, b"Confirm password: ")?;
        if first.expose() != second.expose() {
            return Err(PasswordInputError::DoesNotMatch);
        }
        Ok(first)
    })();
    mode.restore()?;
    result
}

#[cfg(unix)]
fn read_hidden(
    terminal: &mut std::fs::File,
    prompt: &[u8],
) -> Result<LocalPassword, PasswordInputError> {
    use std::io::Write;
    terminal
        .write_all(prompt)
        .map_err(|_| PasswordInputError::Io)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_RAW_BYTES));
    let mut failure = None;
    loop {
        let mut byte = Zeroizing::new([0_u8; 1]);
        terminal
            .read_exact(&mut *byte)
            .map_err(|_| PasswordInputError::Io)?;
        match byte[0] {
            b'\r' | b'\n' => {
                terminal
                    .write_all(b"\r\n")
                    .map_err(|_| PasswordInputError::Io)?;
                if let Some(error) = failure {
                    return Err(error);
                }
                return LocalPassword::from_bytes(&bytes);
            }
            3 | 4 | 26 => {
                terminal
                    .write_all(b"\r\n")
                    .map_err(|_| PasswordInputError::Io)?;
                return Err(PasswordInputError::Cancelled);
            }
            8 | 127 => {
                if failure.is_some() {
                    continue;
                }
                while let Some(last) = bytes.pop() {
                    if last & 0xc0 != 0x80 {
                        break;
                    }
                }
            }
            21 => {
                bytes.zeroize();
                failure = None;
            }
            value if value < 32 => {
                failure = Some(PasswordInputError::Invalid);
                bytes.zeroize();
            }
            value => {
                // Keep discarding through the line ending while echo remains off.
                // Returning on overflow/control would expose the tail of a paste.
                if failure.is_some() {
                    continue;
                }
                if bytes.len() == MAX_RAW_BYTES {
                    failure = Some(PasswordInputError::TooLong);
                    bytes.zeroize();
                    continue;
                }
                bytes.push(value);
            }
        }
    }
}

#[cfg(test)]
#[path = "admin_password_input_tests.rs"]
mod tests;
