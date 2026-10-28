use crate::*;

fn source(root: &Path, previous: bool) -> PathBuf {
    let data = root.join("source");
    fs::create_dir_all(controller_dir(&data)).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
    if previous {
        rusqlite::Connection::open(controller_db_path(&data))
            .unwrap()
            .execute_batch(include_str!(
                "../../fleet-store/fixtures/sqlite/schema_v27_identity_baseline.sql"
            ))
            .unwrap();
    } else {
        drop(fleet_store::SqliteStore::open(controller_db_path(&data)).unwrap());
    }
    ensure_controller_identity(&data).unwrap();
    data
}

fn change_file(archive: &mut ControllerBackupArchive, name: &str, body: &[u8]) {
    let file = archive.files.iter_mut().find(|f| f.path == name).unwrap();
    file.size_bytes = body.len() as u64;
    file.content_hex = hex_encode(body);
    file.sha256 = sha256_hex(body);
}

fn fixture_archive(root: &Path) -> ControllerBackupArchive {
    let data = source(root, false);
    build_controller_backup_archive(&data, fleet_store::CURRENT_SCHEMA_VERSION, "ok".into())
        .unwrap()
}

#[test]
fn snapshot_backup_preserves_previous_and_current_source_schema_and_bytes() {
    for previous in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let data = source(root.path(), previous);
        let db = controller_db_path(&data);
        let before = fs::read(&db).unwrap();
        let output = root.path().join("backup.json");
        execute_controller_backup(&data, &output).unwrap();
        assert_eq!(
            fs::read(&db).unwrap(),
            before,
            "backup must not migrate its source"
        );
        let archive = read_backup_archive(&output).unwrap();
        assert_eq!(
            archive.schema_version,
            if previous {
                27
            } else {
                fleet_store::CURRENT_SCHEMA_VERSION
            }
        );
        assert_eq!(archive.files.len(), 3);
        let target = root.path().join("absent-target");
        execute_controller_restore(&target, &output, true, false).unwrap();
        assert!(!target.exists());
        assert_eq!(fs::read(&db).unwrap(), before);
        if previous {
            use fleet_application::admin_identity::AdminIdentityRead;
            let history = snapshot_rows(&db, "admin_tokens");
            execute_controller_restore(&target, &output, false, false).unwrap();
            let restored = fleet_store::SqliteStore::open(controller_db_path(&target)).unwrap();
            assert_eq!(
                restored.auth_state().unwrap().mode,
                fleet_domain::AdminAuthMode::LocalSetupRequired
            );
            assert_eq!(
                restored.current_schema_version().unwrap(),
                Some(fleet_store::CURRENT_SCHEMA_VERSION)
            );
            assert!(snapshot_rows(&controller_db_path(&target), "admin_tokens") == history);
            assert_eq!(fs::read(&db).unwrap(), before);
        }
    }
}

#[test]
fn snapshot_dry_run_rejects_actual_corruption_schema_lies_and_signing_pair_changes() {
    let root = tempfile::tempdir().unwrap();
    let archive = fixture_archive(root.path());
    let target = root.path().join("target");
    fs::create_dir_all(controller_dir(&target)).unwrap();
    fs::write(
        controller_dir(&target).join("preserved"),
        b"existing-target",
    )
    .unwrap();
    let mut variants = Vec::new();
    let mut corrupt = archive.clone();
    change_file(
        &mut corrupt,
        "controller/fleet.db",
        b"not a SQLite database",
    );
    variants.push(corrupt);
    let mut mismatch = archive.clone();
    mismatch.schema_version -= 1;
    variants.push(mismatch);
    let mut missing_key = archive.clone();
    missing_key
        .files
        .retain(|f| f.path != "controller/controller_private.key");
    variants.push(missing_key);
    let mut invalid_key = archive.clone();
    change_file(
        &mut invalid_key,
        "controller/controller_private.key",
        b"synthetic-secret-invalid-key",
    );
    variants.push(invalid_key);
    let other_root = tempfile::tempdir().unwrap();
    let other = source(other_root.path(), false);
    let mut mismatched_pair = archive.clone();
    change_file(
        &mut mismatched_pair,
        "controller/controller_private.key",
        &fs::read(controller_dir(&other).join("controller_private.key")).unwrap(),
    );
    variants.push(mismatched_pair);
    let mut duplicate = archive.clone();
    duplicate.files.push(duplicate.files[0].clone());
    variants.push(duplicate);
    let mut journal = archive.clone();
    journal.files.push(ControllerBackupFile {
        path: "controller/fleet.db-journal".into(),
        size_bytes: 0,
        sha256: sha256_hex(b""),
        content_hex: String::new(),
    });
    variants.push(journal);
    for (index, archive) in variants.iter().enumerate() {
        let output = root.path().join(format!("bad-{index}.json"));
        write_backup_archive(&output, archive).unwrap();
        assert!(
            execute_controller_restore(&target, &output, true, true).is_err(),
            "dry-run accepted invalid variant {index}"
        );
        assert_eq!(
            fs::read(controller_dir(&target).join("preserved")).unwrap(),
            b"existing-target"
        );
        assert_eq!(fs::read_dir(controller_dir(&target)).unwrap().count(), 1);
    }
}

#[test]
fn snapshot_dry_run_checks_database_schema_instead_of_trusting_manifest() {
    let root = tempfile::tempdir().unwrap();
    let mut archive = fixture_archive(root.path());
    let db = controller_db_path(&root.path().join("source"));
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute(
            "UPDATE schema_migrations SET version=? WHERE name='fleet_store'",
            [fleet_store::CURRENT_SCHEMA_VERSION + 1],
        )
        .unwrap();
    change_file(&mut archive, "controller/fleet.db", &fs::read(&db).unwrap());
    let input = root.path().join("newer.json");
    write_backup_archive(&input, &archive).unwrap();
    let target = root.path().join("target");
    assert!(execute_controller_restore(&target, &input, true, false).is_err());
    assert!(!target.exists());
}

#[test]
fn snapshot_diagnostics_exclude_archive_payload_and_key_paths() {
    let root = tempfile::tempdir().unwrap();
    let mut archive = fixture_archive(root.path());
    let sentinel = "synthetic-sensitive-archive-marker";
    archive.format = sentinel.into();
    archive.source_data_dir = sentinel.into();
    archive.files[0].path = sentinel.into();
    archive.files[0].content_hex = sentinel.into();
    archive.files[0].sha256 = sentinel.into();
    assert!(!format!("{archive:?}").contains(sentinel));
    let error = validate_backup_archive(&archive).unwrap_err();
    assert!(!format!("{error:?} {error}").contains(sentinel));
    archive.format = CONTROLLER_BACKUP_FORMAT.into();
    let error = validate_backup_archive(&archive).unwrap_err();
    assert!(!format!("{error:?} {error}").contains(sentinel));
    assert!(!hex_decode("zz").unwrap_err().to_string().contains("zz"));
    let input = root.path().join("invalid-type.json");
    let mut body = serde_json::to_value(&archive).unwrap();
    body["schema_version"] = serde_json::Value::String(sentinel.into());
    fs::write(&input, serde_json::to_vec(&body).unwrap()).unwrap();
    let error = read_backup_archive(&input).unwrap_err();
    assert!(!format!("{error:?} {error}").contains(sentinel));
}

#[test]
fn snapshot_writer_is_private_and_never_clobbers_existing_backup_or_symlink() {
    let root = tempfile::tempdir().unwrap();
    let archive = fixture_archive(root.path());
    let output = root.path().join("backup.json");
    write_backup_archive(&output, &archive).unwrap();
    let before = fs::read(&output).unwrap();
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(write_backup_archive(&output, &archive).is_err());
    assert_eq!(fs::read(&output).unwrap(), before);
    let unrelated = root.path().join("backup.json.tmp");
    fs::write(&unrelated, b"preserved unrelated temp").unwrap();
    fs::remove_file(&output).unwrap();
    write_backup_archive(&output, &archive).unwrap();
    assert_eq!(fs::read(&unrelated).unwrap(), b"preserved unrelated temp");
    #[cfg(unix)]
    {
        let link = root.path().join("link.json");
        std::os::unix::fs::symlink(&output, &link).unwrap();
        assert!(write_backup_archive(&link, &archive).is_err());
        assert_eq!(fs::read(&output).unwrap(), before);
    }
}

#[test]
fn snapshot_actual_restore_rotates_both_epochs_preserves_history_and_rejects_all_old_human_proofs()
{
    use fleet_application::admin_identity::*;
    use fleet_controller::admin_crypto::AdminAuthSettings;
    use fleet_controller::admin_password_worker::{AdminAuthRequest, AdminPasswordWorker};
    use fleet_domain::*;
    let root = tempfile::tempdir().unwrap();
    let data = source(root.path(), true);
    let owner = admin_local::initialize_owner_with(
        &ControllerOwnerInitArgs {
            data_dir: data.clone(),
            db: None,
            username: "owner.fixture".into(),
            display_name: None,
            password_stdin: true,
        },
        || admin_password_input::read_stdin(&mut std::io::Cursor::new(b"Cedar clouds beyond 47\n")),
    )
    .unwrap();
    let mut store = fleet_store::SqliteStore::open(controller_db_path(&data)).unwrap();
    let pending = AdminAccount::pending(
        AdminUserId::parse(format!("usr_{:032x}", 42)).unwrap(),
        AdminUsername::parse("pending.fixture").unwrap(),
        AdminDisplayName::parse("Pending fixture").unwrap(),
        AdminRole::Viewer,
    );
    store
        .identity_transaction(|tx| tx.insert_account(&pending.snapshot()))
        .unwrap();
    let settings = AdminAuthSettings::new(1).unwrap();
    let request = AdminAuthRequest::new(settings).unwrap();
    let operation = request.operation();
    let state = store.auth_state().unwrap();
    let mut old = Vec::new();
    for (index, kind) in [
        AdminCredentialKind::WebSession,
        AdminCredentialKind::PersonalToken,
        AdminCredentialKind::SetupGrant,
        AdminCredentialKind::ResetGrant,
    ]
    .into_iter()
    .enumerate()
    {
        let user = if kind.is_grant() {
            &pending.snapshot().id
        } else {
            &owner.id
        };
        let account = store.account_by_id(user).unwrap().unwrap();
        let credential = AdminCredential::issue(
            AdminCredentialId::parse(format!("crd_{index:032x}")).unwrap(),
            kind,
            AdminCredentialDigest::from_bytes([index as u8 + 1; 32]),
            AdminCredentialBinding::for_account(&account, state.epoch),
            operation.checked_now().unwrap() - 1,
        )
        .unwrap();
        credential
            .validate(
                kind,
                state.mode,
                &account,
                state.epoch,
                operation.checked_now().unwrap(),
            )
            .unwrap();
        store
            .identity_transaction(|tx| tx.insert_credential(&credential.snapshot()))
            .unwrap();
        if !kind.is_grant() {
            AuthenticateAdminCredential::execute(
                &store,
                &operation,
                kind,
                &credential.snapshot().digest,
            )
            .unwrap();
        }
        old.push(credential.snapshot());
    }
    let delivery =
        fleet_application::ControllerDeliveryIdentityRepository::controller_delivery_identity(
            &store,
        )
        .unwrap();
    drop(store);
    let tables = [
        "admin_accounts",
        "admin_credentials",
        "agents",
        "jobs",
        "approval_requests",
        "audit_events",
    ];
    let before: Vec<_> = tables
        .iter()
        .map(|table| snapshot_rows(&controller_db_path(&data), table))
        .collect();
    let key = fs::read(controller_dir(&data).join("controller_private.key")).unwrap();
    let backup = root.path().join("backup.json");
    execute_controller_backup(&data, &backup).unwrap();
    let target = root.path().join("target");
    execute_controller_restore(&target, &backup, true, false).unwrap();
    assert!(!target.exists());
    execute_controller_restore(&target, &backup, false, false).unwrap();
    let mut restored = fleet_store::SqliteStore::open(controller_db_path(&target)).unwrap();
    let restored_auth = restored.auth_state().unwrap();
    assert_eq!(restored_auth.mode, AdminAuthMode::Personal);
    assert_ne!(restored_auth.epoch, state.epoch);
    let restored_delivery =
        fleet_application::ControllerDeliveryIdentityRepository::controller_delivery_identity(
            &restored,
        )
        .unwrap();
    assert_eq!(restored_delivery.namespace, delivery.namespace);
    assert_ne!(restored_delivery.store_epoch, delivery.store_epoch);
    for (index, table) in tables.iter().enumerate() {
        let actual = snapshot_rows(&controller_db_path(&target), table);
        if *table == "audit_events" {
            assert!(
                before[index].iter().all(|row| actual.contains(row)),
                "old audit rows changed"
            );
            assert_eq!(actual.len(), before[index].len() + 1);
        } else {
            assert!(before[index] == actual, "restored {table} history changed");
        }
    }
    assert_eq!(
        fs::read(controller_dir(&target).join("controller_private.key")).unwrap(),
        key
    );
    let worker = AdminPasswordWorker::spawn(settings).unwrap();
    let client = worker.client();
    for credential in old {
        if credential.kind.is_grant() {
            assert_eq!(
                CompleteAdminSetup::execute(
                    &mut restored,
                    &operation,
                    &client.passwords(&operation),
                    CompleteAdminSetupInput {
                        kind: credential.kind,
                        digest: credential.digest,
                        new_password: "unused replacement password 93"
                    }
                ),
                Err(AdminAccessError::Unauthorized)
            );
        } else {
            assert_eq!(
                AuthenticateAdminCredential::execute(
                    &restored,
                    &operation,
                    credential.kind,
                    &credential.digest
                )
                .unwrap_err(),
                AdminAccessError::Unauthorized
            );
        }
    }
    worker.shutdown().unwrap();
    drop(restored);
    execute_controller_restore(&target, &backup, false, true).unwrap();
    let repeated = fleet_store::SqliteStore::open(controller_db_path(&target)).unwrap();
    assert_ne!(repeated.auth_state().unwrap().epoch, restored_auth.epoch);
    assert_ne!(
        fleet_application::ControllerDeliveryIdentityRepository::controller_delivery_identity(
            &repeated
        )
        .unwrap()
        .store_epoch,
        restored_delivery.store_epoch
    );
    assert_eq!(
        fs::metadata(controller_dir(&target))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(!fs::read_dir(&target).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".fleet-restore-")
    }));
}

fn snapshot_rows(db: &Path, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
    let connection = rusqlite::Connection::open(db).unwrap();
    let mut statement = connection
        .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
        .unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| (0..columns).map(|c| row.get(c)).collect())
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn snapshot_backup_and_actual_restore_cannot_bypass_live_controller_lease() {
    let root = tempfile::tempdir().unwrap();
    let data = source(root.path(), false);
    let archive = root.path().join("backup.json");
    execute_controller_backup(&data, &archive).unwrap();
    let before = fs::read(controller_db_path(&data)).unwrap();
    let lease = fleet_core::controller_data::ControllerDataLease::acquire(&data).unwrap();
    let second = root.path().join("second.json");
    assert_eq!(
        execute_controller_backup(&data, &second)
            .unwrap_err()
            .to_string(),
        fleet_core::controller_data::ControllerDataError::Busy.to_string()
    );
    assert!(!second.exists());
    assert_eq!(
        execute_controller_restore(&data, &archive, false, true)
            .unwrap_err()
            .to_string(),
        fleet_core::controller_data::ControllerDataError::Busy.to_string()
    );
    execute_controller_restore(&data, &archive, true, true).unwrap();
    assert_eq!(fs::read(controller_db_path(&data)).unwrap(), before);
    drop(lease);
}

#[test]
fn snapshot_atomic_install_retains_old_candidate_and_failure_never_removes_target() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    let _lease = fleet_core::controller_data::ControllerDataLease::acquire(&data).unwrap();
    let target = controller_dir(&data);
    fs::create_dir(&target).unwrap();
    fs::write(target.join("marker"), b"old").unwrap();
    let stage = tempfile::tempdir_in(&data).unwrap();
    fs::create_dir(stage.path().join("controller")).unwrap();
    fs::write(stage.path().join("controller/marker"), b"new").unwrap();
    assert!(replace_controller_dir(&data, stage.path(), false).is_err());
    assert_eq!(fs::read(target.join("marker")).unwrap(), b"old");
    let missing = data.join("absent-stage");
    assert!(replace_controller_dir(&data, &missing, true).is_err());
    assert_eq!(fs::read(target.join("marker")).unwrap(), b"old");
    replace_controller_dir(&data, stage.path(), true).unwrap();
    assert_eq!(fs::read(target.join("marker")).unwrap(), b"new");
    assert_eq!(
        fs::read(stage.path().join("controller/marker")).unwrap(),
        b"old"
    );
    let stop = AtomicBool::new(false);
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let reader = scope.spawn(|| {
            let first = fs::read(target.join("marker")).unwrap();
            assert!(first == b"old" || first == b"new");
            ready_tx.send(()).unwrap();
            let until = Instant::now() + Duration::from_secs(5);
            let mut reads = 1;
            while !stop.load(Ordering::Acquire) && Instant::now() < until {
                let value = fs::read(target.join("marker")).unwrap();
                assert!(value == b"old" || value == b"new");
                reads += 1;
            }
            reads
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        for _ in 0..200 {
            replace_controller_dir(&data, stage.path(), true).unwrap();
        }
        stop.store(true, Ordering::Release);
        assert!(reader.join().unwrap() > 0);
    });
    // NOREPLACE handles the absent-target case in one syscall, with no unsafe fallback.
    fs::remove_dir_all(&target).unwrap();
    replace_controller_dir(&data, stage.path(), false).unwrap();
    assert!(target.join("marker").is_file());
    assert!(!stage.path().join("controller").exists());
}

#[test]
fn snapshot_post_commit_sync_or_cleanup_failure_is_distinct_from_install_failure() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    let _lease = fleet_core::controller_data::ControllerDataLease::acquire(&data).unwrap();
    fs::create_dir(controller_dir(&data)).unwrap();
    fs::write(
        controller_dir(&data).join("marker"),
        b"committed new target",
    )
    .unwrap();
    let stage = tempfile::tempdir_in(&data).unwrap();
    let retained = stage.path().to_path_buf();
    fs::write(retained.join("old"), b"rollback candidate").unwrap();
    assert_eq!(
        finalize_controller_restore(&data.join("missing"), stage),
        RestoreFinalization::DurabilityUnconfirmed
    );
    assert_eq!(
        fs::read(retained.join("old")).unwrap(),
        b"rollback candidate"
    );
    let stage = tempfile::tempdir_in(&data).unwrap();
    let pending = stage.path().to_path_buf();
    fs::write(pending.join("old"), b"owned old snapshot").unwrap();
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o000)).unwrap();
    assert_eq!(
        finalize_controller_restore(&data, stage),
        RestoreFinalization::CleanupPending
    );
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        fs::read(pending.join("old")).unwrap(),
        b"owned old snapshot"
    );
    assert_eq!(
        fs::read(controller_dir(&data).join("marker")).unwrap(),
        b"committed new target"
    );
}

#[test]
fn snapshot_restore_audit_or_target_failure_preserves_existing_state_and_unrelated_staging() {
    let root = tempfile::tempdir().unwrap();
    let data = source(root.path(), false);
    let fault = "synthetic-sensitive-audit-fault";
    rusqlite::Connection::open(controller_db_path(&data)).unwrap().execute_batch(&format!(
        "CREATE TRIGGER fail_restore_audit BEFORE INSERT ON audit_events WHEN NEW.action='admin_credentials_invalidated_after_restore' BEGIN SELECT RAISE(ABORT, '{fault}'); END;"
    )).unwrap();
    let input = root.path().join("backup.json");
    execute_controller_backup(&data, &input).unwrap();
    let target = root.path().join("target");
    let _lease = fleet_core::controller_data::ControllerDataLease::acquire(&target).unwrap();
    fs::create_dir(controller_dir(&target)).unwrap();
    fs::write(
        controller_dir(&target).join("preserved"),
        b"untouched existing controller",
    )
    .unwrap();
    let unrelated = target.join(".fleet-restore-preserved");
    fs::create_dir(&unrelated).unwrap();
    fs::write(unrelated.join("marker"), b"not owned by this restore").unwrap();
    drop(_lease);
    let error = execute_controller_restore(&target, &input, false, true).unwrap_err();
    assert!(!format!("{error:?} {error}").contains(fault));
    assert_eq!(
        fs::read(controller_dir(&target).join("preserved")).unwrap(),
        b"untouched existing controller"
    );
    assert_eq!(
        fs::read(unrelated.join("marker")).unwrap(),
        b"not owned by this restore"
    );
    assert_eq!(fs::read_dir(&target).unwrap().count(), 3); // lock, original target, unrelated stage
    let released = fleet_core::controller_data::ControllerDataLease::acquire(&target).unwrap();
    drop(released);
    #[cfg(unix)]
    {
        let linked = root.path().join("linked");
        let lease = fleet_core::controller_data::ControllerDataLease::acquire(&linked).unwrap();
        std::os::unix::fs::symlink(controller_dir(&target), controller_dir(&linked)).unwrap();
        drop(lease);
        assert!(execute_controller_restore(&linked, &input, false, true).is_err());
        assert!(
            fs::symlink_metadata(controller_dir(&linked))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read(controller_dir(&target).join("preserved")).unwrap(),
            b"untouched existing controller"
        );
    }
}

#[test]
fn snapshot_process_kill_before_and_after_exchange_leaves_complete_target_and_releases_lease() {
    for after in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let lease = fleet_core::controller_data::ControllerDataLease::acquire(&data).unwrap();
        fs::create_dir(controller_dir(&data)).unwrap();
        fs::write(controller_dir(&data).join("marker"), b"old").unwrap();
        let stage = data.join("owned-stage");
        fs::create_dir_all(stage.join("controller")).unwrap();
        fs::write(stage.join("controller/marker"), b"new").unwrap();
        drop(lease);
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Child(
            ProcessCommand::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "controller_snapshot_tests::snapshot_install_process_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("FLEET_TEST_RESTORE_ROOT", root.path())
                .env("FLEET_TEST_RESTORE_AFTER", if after { "yes" } else { "no" })
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let until = Instant::now() + Duration::from_secs(5);
        while !root.path().join("ready").exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "restore fixture exited before ready"
            );
            assert!(
                Instant::now() < until,
                "restore fixture readiness timed out"
            );
            thread::sleep(Duration::from_millis(10));
        }
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert_eq!(
            fs::read(controller_dir(&data).join("marker")).unwrap(),
            if after { b"new" } else { b"old" }
        );
        assert_eq!(
            fs::read(stage.join("controller/marker")).unwrap(),
            if after { b"old" } else { b"new" }
        );
        let _released = fleet_core::controller_data::ControllerDataLease::acquire(&data).unwrap();
    }
}

#[test]
#[ignore = "subprocess fixture invoked by snapshot_process_kill_before_and_after_exchange"]
fn snapshot_install_process_child() {
    let root =
        PathBuf::from(std::env::var_os("FLEET_TEST_RESTORE_ROOT").expect("test fixture root"));
    let after = std::env::var("FLEET_TEST_RESTORE_AFTER").unwrap() == "yes";
    let data = root.join("data");
    let _lease = fleet_core::controller_data::ControllerDataLease::acquire(&data).unwrap();
    let stage = data.join("owned-stage");
    sync_restore_tree(&stage).unwrap();
    if after {
        replace_controller_dir(&data, &stage, true).unwrap();
    }
    fs::write(root.join("ready"), b"ready").unwrap();
    // Parent kills this owned fixture. A bounded timeout prevents an orphan if the driver fails.
    thread::sleep(Duration::from_secs(10));
    panic!("restore child fixture was not killed by its driver");
}
