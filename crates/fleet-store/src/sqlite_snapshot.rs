//! Non-migrating inspection of a stopped Controller database or private restore scratch.
//! The caller owns quiescence; this adapter neither takes the Controller lease nor writes.

use rusqlite::{Connection, OpenFlags};
use std::{fmt, fs, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotInspectionError {
    Unavailable,
    TransientFiles,
    InvalidDatabase,
    NewerSchema,
    Unsupported,
}

impl fmt::Display for SnapshotInspectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "SQLite snapshot is unavailable or not a regular file",
            Self::TransientFiles => "SQLite snapshot has transient files; stop all writers first",
            Self::InvalidDatabase => "SQLite snapshot integrity or Fleet schema is invalid",
            Self::NewerSchema => "SQLite snapshot schema is newer than this binary supports",
            Self::Unsupported => {
                "read-only SQLite snapshot inspection is unsupported on this platform"
            }
        })
    }
}

impl std::error::Error for SnapshotInspectionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqliteSnapshotMetadata {
    pub schema_version: i64,
}

/// Checks integrity and the recorded schema without running migrations or creating sidecars.
///
/// All database writers must remain stopped for this call. `immutable=1` deliberately skips
/// SQLite locking/change detection, so a Controller lease and stopped older binaries are the
/// caller's responsibility. Every journal/sidecar (including dangling links) is rejected before
/// opening. Errors exclude SQLite diagnostics, paths and database contents.
pub fn inspect_quiescent_sqlite_snapshot(
    path: &Path,
) -> Result<SqliteSnapshotMetadata, SnapshotInspectionError> {
    use SnapshotInspectionError as E;
    if !fs::symlink_metadata(path)
        .map_err(|_| E::Unavailable)?
        .is_file()
    {
        return Err(E::Unavailable);
    }
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match fs::symlink_metadata(sidecar) {
            Ok(_) => return Err(E::TransientFiles),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(E::Unavailable),
        }
    }
    let uri = immutable_uri(path)?;
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| E::InvalidDatabase)?;
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| E::InvalidDatabase)?;
    if integrity != "ok" {
        return Err(E::InvalidDatabase);
    }
    let version: i64 = connection
        .query_row(
            "SELECT version FROM schema_migrations WHERE name='fleet_store'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| E::InvalidDatabase)?;
    if version > crate::CURRENT_SCHEMA_VERSION {
        return Err(E::NewerSchema);
    }
    if version < 1 {
        return Err(E::InvalidDatabase);
    }
    // A foreign SQLite database with a copied migration row is not a Fleet backup.
    for table in ["agents", "jobs"] {
        let present: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)",
                [table],
                |row| row.get(0),
            )
            .map_err(|_| E::InvalidDatabase)?;
        if !present {
            return Err(E::InvalidDatabase);
        }
    }
    Ok(SqliteSnapshotMetadata {
        schema_version: version,
    })
}

fn immutable_uri(path: &Path) -> Result<String, SnapshotInspectionError> {
    #[cfg(unix)]
    {
        use std::fmt::Write;
        use std::os::unix::ffi::OsStrExt;
        let absolute = fs::canonicalize(path).map_err(|_| SnapshotInspectionError::Unavailable)?;
        let mut uri = String::from("file:");
        for &byte in absolute.as_os_str().as_bytes() {
            if byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte) {
                uri.push(char::from(byte));
            } else {
                write!(&mut uri, "%{byte:02X}")
                    .map_err(|_| SnapshotInspectionError::Unavailable)?;
            }
        }
        uri.push_str("?mode=ro&immutable=1");
        Ok(uri)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(SnapshotInspectionError::Unsupported)
    }
}
