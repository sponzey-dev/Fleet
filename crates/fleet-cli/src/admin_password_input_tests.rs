use super::*;
use std::io::Cursor;

#[test]
fn stdin_preserves_spaces_and_strips_only_one_transport_line_ending() {
    for input in [
        b"  secret phrase  \n".as_slice(),
        b"  secret phrase  \r\n",
        b"  secret phrase  ",
    ] {
        let password = read_stdin(&mut Cursor::new(input)).unwrap();
        assert_eq!(password.expose(), "  secret phrase  ");
        assert!(!format!("{password:?}").contains("secret phrase"));
    }
}

#[test]
fn stdin_rejects_empty_multiple_lines_controls_and_invalid_utf8() {
    for input in [
        b"".as_slice(),
        b"\n",
        b"secret\nsecond\n",
        b"secret\0",
        b"secret\t",
        &[0xff],
    ] {
        assert_eq!(
            read_stdin(&mut Cursor::new(input)).unwrap_err(),
            PasswordInputError::Invalid
        );
    }
}

#[test]
fn stdin_byte_limit_counts_password_not_optional_crlf() {
    let mut input = vec![b'x'; 2048];
    assert_eq!(
        read_stdin(&mut Cursor::new(&input)).unwrap().expose().len(),
        2048
    );
    input.extend_from_slice(b"\r\n");
    assert_eq!(
        read_stdin(&mut Cursor::new(&input)).unwrap().expose().len(),
        2048
    );
    input.insert(0, b'x');
    assert_eq!(
        read_stdin(&mut Cursor::new(input)).unwrap_err(),
        PasswordInputError::TooLong
    );
}

#[test]
fn stdin_never_reads_an_unbounded_stream() {
    struct Infinite(usize);
    impl std::io::Read for Infinite {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            assert!(self.0 <= 2051);
            bytes.fill(b'x');
            Ok(bytes.len())
        }
    }
    let mut reader = Infinite(0);
    assert_eq!(
        read_stdin(&mut reader).unwrap_err(),
        PasswordInputError::TooLong
    );
    assert_eq!(reader.0, 2051);
}

#[test]
fn input_io_errors_do_not_expose_underlying_details() {
    struct Broken;
    impl std::io::Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("secret-and-private-key-path"))
        }
    }
    let error = read_stdin(&mut Broken).unwrap_err();
    assert_eq!(error, PasswordInputError::Io);
    assert!(!format!("{error:?} {error}").contains("secret-and-private-key-path"));
}

#[cfg(unix)]
mod terminal {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    struct Pty {
        master: Option<File>,
        slave: File,
        worker: Option<std::thread::JoinHandle<Result<LocalPassword, PasswordInputError>>>,
        original: rustix::termios::Termios,
        transcript: Vec<u8>,
    }

    impl Pty {
        fn new() -> Self {
            Self::with_reader(read_terminal_pair)
        }

        fn with_reader(read: fn(&mut File) -> Result<LocalPassword, PasswordInputError>) -> Self {
            use rustix::fs::{Mode, OFlags};
            use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
            let master = File::from(openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap());
            rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC).unwrap();
            grantpt(&master).unwrap();
            unlockpt(&master).unwrap();
            let name = ptsname(&master, Vec::new()).unwrap();
            let slave = File::from(
                rustix::fs::open(
                    name.as_c_str(),
                    OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .unwrap(),
            );
            let original = rustix::termios::tcgetattr(&slave).unwrap();
            let mut reader = slave.try_clone().unwrap();
            rustix::fs::fcntl_setfl(&master, OFlags::RDWR | OFlags::NONBLOCK).unwrap();
            let worker = std::thread::spawn(move || read(&mut reader));
            Self {
                master: Some(master),
                slave,
                worker: Some(worker),
                original,
                transcript: Vec::new(),
            }
        }

        fn prompt(&mut self, expected: &[u8]) {
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                let mut bytes = [0; 256];
                match self.master.as_mut().unwrap().read(&mut bytes) {
                    Ok(count) => {
                        self.transcript.extend_from_slice(&bytes[..count]);
                        assert!(self.transcript.len() <= 4096);
                        if self
                            .transcript
                            .windows(expected.len())
                            .any(|part| part == expected)
                        {
                            return;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => panic!("owned PTY failed before the expected prompt"),
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            panic!("owned PTY prompt deadline exceeded");
        }

        fn send(&mut self, bytes: &[u8]) {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut remaining = bytes;
            while !remaining.is_empty() && Instant::now() < deadline {
                match self.master.as_mut().unwrap().write(remaining) {
                    Ok(0) => panic!("owned PTY stopped accepting input"),
                    Ok(count) => remaining = &remaining[count..],
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => panic!("owned PTY input failed"),
                }
            }
            assert!(remaining.is_empty(), "owned PTY input deadline exceeded");
        }

        fn finish(mut self) -> Result<LocalPassword, PasswordInputError> {
            let deadline = Instant::now() + Duration::from_secs(3);
            while !self.worker.as_ref().unwrap().is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            let finished = self.worker.as_ref().unwrap().is_finished();
            if !finished {
                drop(self.master.take());
            }
            let result = self.worker.take().unwrap().join().unwrap();
            assert!(finished, "owned PTY worker deadline exceeded");
            let restored = rustix::termios::tcgetattr(&self.slave).unwrap();
            assert_eq!(restored.input_modes, self.original.input_modes);
            assert_eq!(restored.output_modes, self.original.output_modes);
            assert_eq!(restored.control_modes, self.original.control_modes);
            assert_eq!(restored.local_modes, self.original.local_modes);
            for code in [
                rustix::termios::SpecialCodeIndex::VMIN,
                rustix::termios::SpecialCodeIndex::VTIME,
            ] {
                assert_eq!(
                    restored.special_codes[code],
                    self.original.special_codes[code]
                );
            }
            result
        }
    }

    impl Drop for Pty {
        fn drop(&mut self) {
            drop(self.master.take());
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    #[test]
    fn existing_token_is_read_once_without_echo_and_terminal_is_restored() {
        let mut tty = Pty::with_reader(read_terminal_token);
        tty.prompt(b"Personal token (hidden): ");
        let hidden = rustix::termios::tcgetattr(&tty.slave).unwrap();
        assert!(
            !hidden
                .local_modes
                .contains(rustix::termios::LocalModes::ECHO)
        );
        tty.send(b"fpat_synthetic-token\r");
        assert!(!String::from_utf8_lossy(&tty.transcript).contains("fpat_synthetic-token"));
        assert_eq!(tty.finish().unwrap().expose(), "fpat_synthetic-token");
        let mut cancelled = Pty::with_reader(read_terminal_token);
        cancelled.prompt(b"Personal token (hidden): ");
        cancelled.send(&[3]);
        assert_eq!(
            cancelled.finish().unwrap_err(),
            PasswordInputError::Cancelled
        );
    }

    #[test]
    fn tty_long_unicode_confirmation_is_hidden_and_restores_mode() {
        let mut tty = Pty::new();
        let password = "산".repeat(100);
        tty.prompt(b"New password: ");
        let hidden = rustix::termios::tcgetattr(&tty.slave).unwrap();
        assert!(
            !hidden.local_modes.intersects(
                rustix::termios::LocalModes::ECHO | rustix::termios::LocalModes::ECHONL
            )
        );
        tty.send(format!("{password}\r").as_bytes());
        tty.prompt(b"Confirm password: ");
        assert!(!String::from_utf8_lossy(&tty.transcript).contains(&password));
        tty.send(format!("{password}\r").as_bytes());
        assert_eq!(tty.finish().unwrap().expose(), password);
    }

    #[test]
    fn tty_cancel_overflow_invalid_and_confirmation_failure_restore_mode() {
        for byte in [3, 4, 26] {
            let mut tty = Pty::new();
            tty.prompt(b"New password: ");
            tty.send(&[byte]);
            assert_eq!(tty.finish().unwrap_err(), PasswordInputError::Cancelled);
        }
        let mut tty = Pty::new();
        tty.prompt(b"New password: ");
        let mut oversized = vec![b'x'; 2049];
        oversized.push(b'\r');
        tty.send(&oversized);
        assert_eq!(tty.finish().unwrap_err(), PasswordInputError::TooLong);
        let mut tty = Pty::new();
        tty.prompt(b"New password: ");
        tty.send(&[0xff, b'\r']);
        assert_eq!(tty.finish().unwrap_err(), PasswordInputError::Invalid);
        let mut tty = Pty::new();
        tty.prompt(b"New password: ");
        tty.send(b"first\r");
        tty.prompt(b"Confirm password: ");
        tty.send(b"second\r");
        assert_eq!(tty.finish().unwrap_err(), PasswordInputError::DoesNotMatch);
    }

    #[test]
    fn tty_backspace_and_clear_edit_without_echoing() {
        let mut tty = Pty::new();
        tty.prompt(b"New password: ");
        tty.send("discard\u{15}a산\u{7f}valid passphrase\r".as_bytes());
        tty.prompt(b"Confirm password: ");
        tty.send(b"avalid passphrase\r");
        assert_eq!(tty.finish().unwrap().expose(), "avalid passphrase");
    }

    #[test]
    fn tty_invalid_or_oversized_input_stays_hidden_until_the_line_ends() {
        for (prefix, expected) in [
            (vec![b'x'; 2049], PasswordInputError::TooLong),
            (b"valid\t".to_vec(), PasswordInputError::Invalid),
        ] {
            let mut tty = Pty::new();
            tty.prompt(b"New password: ");
            tty.send(&prefix);
            std::thread::sleep(Duration::from_millis(20));
            assert!(
                !tty.worker.as_ref().unwrap().is_finished(),
                "remaining password bytes must not reach an echo-enabled terminal"
            );
            assert!(
                !rustix::termios::tcgetattr(&tty.slave)
                    .unwrap()
                    .local_modes
                    .contains(rustix::termios::LocalModes::ECHO)
            );
            tty.send(b"remaining-secret-tail\r");
            assert_eq!(tty.finish().unwrap_err(), expected);
        }
    }
}
