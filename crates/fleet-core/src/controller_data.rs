//! Process-lifetime exclusivity for Controller bootstrap and local identity changes.
//!
//! This is an OS/filesystem guard, not application authorization or a database lock.

use std::fmt::{Debug, Display, Formatter};
use std::path::Path;

#[cfg(unix)]
use std::fs::{DirBuilder, File, Metadata};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt};

#[cfg(unix)]
const LOCK_FILE: &str = ".controller.lock";

/// Safe bootstrap failures; diagnostics deliberately contain no filesystem paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerDataError {
    UnsafeDirectory,
    UnsafeLock,
    Busy,
    Io,
    Unsupported,
}

impl Display for ControllerDataError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsafeDirectory => {
                "Controller data directory must be a real directory owned by the current OS user with mode 0700"
            }
            Self::UnsafeLock => {
                "Controller lock must be a private, singly linked regular file owned by the current OS user with mode 0600"
            }
            Self::Busy => "Controller data directory is already in use; stop the Controller before local identity changes",
            Self::Io => "could not acquire the Controller data directory lease",
            Self::Unsupported => "local Controller data authority requires a supported Unix platform",
        })
    }
}

impl std::error::Error for ControllerDataError {}

/// Exclusive advisory lease shared by supported Controller and local identity commands.
///
/// Retain this value for the entire operation or Controller lifetime. Dropping it
/// releases the lock; the stable lock file is never unlinked or truncated. This
/// guard cannot detect an older binary that does not participate in the lease,
/// or defend against a malicious process with the same OS identity.
pub struct ControllerDataLease {
    #[cfg(unix)]
    _directory: File,
    #[cfg(unix)]
    _lock: File,
}

impl Debug for ControllerDataLease {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ControllerDataLease { .. }")
    }
}

#[cfg(unix)]
impl Drop for ControllerDataLease {
    fn drop(&mut self) {
        // A descriptor inherited between fork and exec must not extend authority.
        // Closing this descriptor alone would retain flock while a duplicate lives.
        let _ = rustix::fs::flock(&self._lock, rustix::fs::FlockOperation::Unlock);
    }
}

impl ControllerDataLease {
    /// Creates missing directories privately and acquires a nonblocking OS lease.
    ///
    /// Existing permissions and contents are never repaired automatically. The
    /// final directory and lock may not be symlinks; the lock is opened relative
    /// to the validated directory descriptor rather than an unchecked pathname.
    ///
    /// # Errors
    /// Rejects a foreign/public directory or lock, special files, hard-linked
    /// locks, a lease held by another handle/process, or inaccessible storage.
    #[cfg(unix)]
    pub fn acquire(data_dir: &Path) -> Result<Self, ControllerDataError> {
        use rustix::fs::{FlockOperation, Mode, OFlags, flock, open, openat};

        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(data_dir)
            .map_err(|_| ControllerDataError::Io)?;
        let uid = rustix::process::geteuid().as_raw();
        let directory = File::from(
            open(
                data_dir,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| ControllerDataError::UnsafeDirectory)?,
        );
        validate_directory(
            &directory.metadata().map_err(|_| ControllerDataError::Io)?,
            uid,
        )?;
        let lock = File::from(
            openat(
                &directory,
                LOCK_FILE,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| ControllerDataError::UnsafeLock)?,
        );
        validate_lock(&lock.metadata().map_err(|_| ControllerDataError::Io)?, uid)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                ControllerDataError::Busy
            } else {
                ControllerDataError::Io
            }
        })?;
        // Detect a pathname replacement during acquisition before granting authority.
        let current = File::from(
            openat(
                &directory,
                LOCK_FILE,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| ControllerDataError::UnsafeLock)?,
        );
        let metadata = lock.metadata().map_err(|_| ControllerDataError::Io)?;
        let current = current.metadata().map_err(|_| ControllerDataError::Io)?;
        validate_lock(&metadata, uid)?;
        validate_lock(&current, uid)?;
        if metadata.dev() != current.dev() || metadata.ino() != current.ino() {
            return Err(ControllerDataError::UnsafeLock);
        }
        Ok(Self {
            _directory: directory,
            _lock: lock,
        })
    }

    #[cfg(not(unix))]
    /// Fails closed on platforms without the supported Unix authority boundary.
    pub fn acquire(_data_dir: &Path) -> Result<Self, ControllerDataError> {
        Err(ControllerDataError::Unsupported)
    }
}

#[cfg(unix)]
fn validate_directory(metadata: &Metadata, uid: u32) -> Result<(), ControllerDataError> {
    if metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o7777 == 0o700 {
        Ok(())
    } else {
        Err(ControllerDataError::UnsafeDirectory)
    }
}

#[cfg(unix)]
fn validate_lock(metadata: &Metadata, uid: u32) -> Result<(), ControllerDataError> {
    if metadata.is_file()
        && metadata.uid() == uid
        && metadata.mode() & 0o7777 == 0o600
        && metadata.nlink() == 1
    {
        Ok(())
    } else {
        Err(ControllerDataError::UnsafeLock)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    fn private_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    #[test]
    fn creates_private_directory_and_holds_lease_until_drop() {
        let root = private_dir();
        let path = root.path().join("new").join("controller-data");
        let lease = ControllerDataLease::acquire(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(path.join(LOCK_FILE)).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(
            ControllerDataLease::acquire(&path).unwrap_err(),
            ControllerDataError::Busy
        );
        drop(lease);
        let _next = ControllerDataLease::acquire(&path).unwrap();
    }

    #[test]
    fn accepts_existing_private_directory_without_changing_files() {
        let root = private_dir();
        let path = root.path();
        fs::write(path.join("identity.fixture"), b"preserved").unwrap();
        fs::write(path.join(LOCK_FILE), b"old lock contents").unwrap();
        fs::set_permissions(path.join(LOCK_FILE), fs::Permissions::from_mode(0o600)).unwrap();
        let _lease = ControllerDataLease::acquire(path).unwrap();
        assert_eq!(
            fs::read(path.join(LOCK_FILE)).unwrap(),
            b"old lock contents"
        );
        assert_eq!(
            fs::read(path.join("identity.fixture")).unwrap(),
            b"preserved"
        );
    }

    #[test]
    fn rejects_public_directory_without_chmod_or_creating_lock() {
        let root = private_dir();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            ControllerDataLease::acquire(root.path()).unwrap_err(),
            ControllerDataError::UnsafeDirectory
        );
        assert_eq!(fs::metadata(root.path()).unwrap().mode() & 0o777, 0o755);
        assert!(!root.path().join(LOCK_FILE).exists());
    }

    #[test]
    fn rejects_directory_symlink_and_non_directory() {
        let root = private_dir();
        let alias = root.path().join("alias");
        symlink(root.path(), &alias).unwrap();
        assert!(ControllerDataLease::acquire(&alias).is_err());
        assert!(!root.path().join(LOCK_FILE).exists());
        let file = root.path().join("file");
        fs::write(&file, b"preserved").unwrap();
        assert!(ControllerDataLease::acquire(&file).is_err());
        assert_eq!(fs::read(file).unwrap(), b"preserved");
    }

    #[test]
    fn rejects_lock_symlink_hardlink_and_directory_without_modifying_them() {
        let root = private_dir();
        let lock = root.path().join(LOCK_FILE);
        let target = root.path().join("target");
        fs::write(&target, b"preserved").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &lock).unwrap();
        assert!(ControllerDataLease::acquire(root.path()).is_err());
        fs::remove_file(&lock).unwrap();
        fs::hard_link(&target, &lock).unwrap();
        assert_eq!(
            ControllerDataLease::acquire(root.path()).unwrap_err(),
            ControllerDataError::UnsafeLock
        );
        fs::remove_file(&lock).unwrap();
        fs::create_dir(&lock).unwrap();
        assert!(ControllerDataLease::acquire(root.path()).is_err());
        assert_eq!(fs::read(target).unwrap(), b"preserved");
    }

    #[test]
    fn rejects_fifo_without_waiting_for_another_process() {
        let root = private_dir();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(root.path().join(LOCK_FILE))
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(
            ControllerDataLease::acquire(root.path()).unwrap_err(),
            ControllerDataError::UnsafeLock
        );
    }

    #[test]
    fn rejects_public_lock_and_foreign_owner_policy() {
        let root = private_dir();
        let lock = root.path().join(LOCK_FILE);
        fs::write(&lock, b"preserved").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            ControllerDataLease::acquire(root.path()).unwrap_err(),
            ControllerDataError::UnsafeLock
        );
        let metadata = fs::metadata(root.path()).unwrap();
        assert_eq!(
            validate_directory(&metadata, metadata.uid().wrapping_add(1)),
            Err(ControllerDataError::UnsafeDirectory)
        );
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
        let metadata = fs::metadata(&lock).unwrap();
        assert_eq!(
            validate_lock(&metadata, metadata.uid().wrapping_add(1)),
            Err(ControllerDataError::UnsafeLock)
        );
    }

    #[test]
    fn diagnostics_do_not_include_data_or_key_paths() {
        let root = private_dir();
        let sensitive_path = root.path().join("private-key-path-marker");
        let lease = ControllerDataLease::acquire(&sensitive_path).unwrap();
        let error = ControllerDataLease::acquire(&sensitive_path).unwrap_err();
        assert!(!format!("{lease:?} {error:?} {error}").contains("private-key-path-marker"));
    }

    #[test]
    fn separate_process_observes_live_lease_and_drop_release() {
        let root = private_dir();
        let lease = ControllerDataLease::acquire(root.path()).unwrap();
        run_probe(root.path(), "busy");
        drop(lease);
        run_probe(root.path(), "available");
    }

    #[test]
    fn duplicate_descriptor_does_not_extend_authority_after_guard_drop() {
        let root = private_dir();
        let lease = ControllerDataLease::acquire(root.path()).unwrap();
        let inherited = lease._lock.try_clone().unwrap();
        drop(lease);
        let _next = ControllerDataLease::acquire(root.path()).unwrap();
        drop(inherited);
    }

    fn run_probe(path: &Path, expectation: &str) {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "controller_data::tests::child_process_lease_probe",
            ])
            .env("FLEET_CORE_LEASE_PROBE_DIR", path)
            .env("FLEET_CORE_LEASE_PROBE_EXPECT", expectation)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "lease probe failed: {status}");
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("lease probe exceeded its deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    #[ignore = "subprocess fixture invoked by separate_process_observes_live_lease_and_drop_release"]
    fn child_process_lease_probe() {
        let path = std::env::var_os("FLEET_CORE_LEASE_PROBE_DIR").unwrap();
        let expectation = std::env::var("FLEET_CORE_LEASE_PROBE_EXPECT").unwrap();
        let result = ControllerDataLease::acquire(Path::new(&path));
        match expectation.as_str() {
            "busy" => assert_eq!(result.unwrap_err(), ControllerDataError::Busy),
            "available" => drop(result.unwrap()),
            _ => panic!("unknown lease probe expectation"),
        }
    }
}
