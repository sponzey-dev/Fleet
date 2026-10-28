use crate::{SqliteStore, sqlite_snapshot::*};
use rusqlite::Connection;
use std::fs;

#[test]
fn snapshot_inspection_preserves_previous_and_current_database_bytes() {
    let root = tempfile::tempdir().unwrap();
    for previous in [true, false] {
        let path = root.path().join(format!("한글 ?#% {previous}.db"));
        if previous {
            Connection::open(&path)
                .unwrap()
                .execute_batch(include_str!(
                    "../fixtures/sqlite/schema_v27_identity_baseline.sql"
                ))
                .unwrap();
        } else {
            drop(SqliteStore::open(&path).unwrap());
        }
        let before = fs::read(&path).unwrap();
        let inspected = inspect_quiescent_sqlite_snapshot(&path).unwrap();
        assert_eq!(
            inspected.schema_version,
            if previous {
                27
            } else {
                crate::CURRENT_SCHEMA_VERSION
            }
        );
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
}

#[test]
fn snapshot_inspection_rejects_missing_corrupt_foreign_and_newer_without_writes() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("snapshot.db");
    assert!(inspect_quiescent_sqlite_snapshot(&path).is_err());
    assert!(!path.exists());
    fs::write(&path, b"synthetic-sensitive-corruption").unwrap();
    let error = inspect_quiescent_sqlite_snapshot(&path).unwrap_err();
    assert!(!format!("{error:?} {error}").contains("synthetic-sensitive-corruption"));
    fs::remove_file(&path).unwrap();
    Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE unrelated(id INTEGER)")
        .unwrap();
    assert!(inspect_quiescent_sqlite_snapshot(&path).is_err());
    fs::remove_file(&path).unwrap();
    drop(SqliteStore::open(&path).unwrap());
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE schema_migrations SET version=? WHERE name='fleet_store'",
            [crate::CURRENT_SCHEMA_VERSION + 1],
        )
        .unwrap();
    let before = fs::read(&path).unwrap();
    assert_eq!(
        inspect_quiescent_sqlite_snapshot(&path),
        Err(SnapshotInspectionError::NewerSchema)
    );
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn snapshot_inspection_rejects_all_journals_and_final_symlinks() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("snapshot.db");
    drop(SqliteStore::open(&path).unwrap());
    let before = fs::read(&path).unwrap();
    for suffix in ["-journal", "-wal", "-shm"] {
        let sidecar = root.path().join(format!("snapshot.db{suffix}"));
        fs::write(&sidecar, []).unwrap();
        assert_eq!(
            inspect_quiescent_sqlite_snapshot(&path),
            Err(SnapshotInspectionError::TransientFiles)
        );
        fs::remove_file(&sidecar).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.path().join("missing"), &sidecar).unwrap();
            assert_eq!(
                inspect_quiescent_sqlite_snapshot(&path),
                Err(SnapshotInspectionError::TransientFiles)
            );
            fs::remove_file(&sidecar).unwrap();
        }
    }
    #[cfg(unix)]
    {
        let link = root.path().join("link.db");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(inspect_quiescent_sqlite_snapshot(&link).is_err());
    }
    assert_eq!(fs::read(&path).unwrap(), before);
}
