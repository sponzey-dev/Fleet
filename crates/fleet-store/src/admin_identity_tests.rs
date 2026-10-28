use crate::{CURRENT_SCHEMA_VERSION, SqliteStore};
use fleet_application::admin_identity::{
    AdminAccessError, AdminAuthState, AdminIdentityRead, AdminIdentityRepository,
};
use fleet_domain::*;
use rusqlite::{Connection, types::Value};
use std::collections::BTreeMap;

fn fixture_store() -> SqliteStore {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(include_str!(
            "../fixtures/sqlite/schema_v27_identity_baseline.sql"
        ))
        .unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(
        connection
            .prepare("PRAGMA foreign_key_check")
            .unwrap()
            .query([])
            .unwrap()
            .next()
            .unwrap()
            .is_none()
    );
    SqliteStore { connection }
}

fn legacy_snapshot(store: &SqliteStore) -> BTreeMap<String, Vec<Vec<Value>>> {
    table_snapshot(
        store,
        &[
            "admin_tokens",
            "agents",
            "agent_identities",
            "jobs",
            "job_targets",
            "approval_requests",
            "approval_decisions",
            "audit_events",
            "controller_delivery_identity",
            "job_output_read_state",
        ],
    )
}

fn table_snapshot(store: &SqliteStore, tables: &[&str]) -> BTreeMap<String, Vec<Vec<Value>>> {
    let mut snapshot = BTreeMap::new();
    for &table in tables {
        let mut statement = store
            .connection
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|index| row.get::<_, Value>(index))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        snapshot.insert(table.to_owned(), rows);
    }
    snapshot
}

#[test]
fn frozen_schema27_fixture_preserves_all_legacy_rows_through_repeat_migration() {
    let store = fixture_store();
    assert_eq!(store.current_schema_version().unwrap(), Some(27));
    let before = legacy_snapshot(&store);
    for table in [
        "admin_tokens",
        "agents",
        "agent_identities",
        "jobs",
        "job_targets",
        "approval_requests",
        "approval_decisions",
        "audit_events",
    ] {
        assert_eq!(
            before[table].len(),
            1,
            "fixture requires representative {table} row"
        );
    }
    store.migrate().unwrap();
    assert_eq!(
        store.current_schema_version().unwrap(),
        Some(CURRENT_SCHEMA_VERSION)
    );
    assert_eq!(legacy_snapshot(&store), before);
    store.migrate().unwrap();
    assert_eq!(legacy_snapshot(&store), before);
}

#[test]
fn output_projection_migration_records_its_own_version27_only() {
    let store = fixture_store();
    store.record_schema_version(26).unwrap();
    store
        .connection
        .execute_batch(
            "DROP TRIGGER output_read_new_job;
        DROP TRIGGER output_read_append_guard; DROP TRIGGER output_read_append;
        DROP TRIGGER output_read_delete_guard; DROP TRIGGER output_read_delete;
        DROP INDEX job_output_chunks_append_read_idx; DROP TABLE job_output_read_state;",
        )
        .unwrap();
    crate::output_read::migrate_projection(&store).unwrap();
    assert_eq!(store.current_schema_version().unwrap(), Some(27));
    assert_eq!(
        store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM job_output_read_state WHERE job_id='legacy-job'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
}

fn active_owner() -> AdminAccount {
    let mut account = AdminAccount::pending(
        AdminUserId::parse("usr_00000000000000000000000000000001").unwrap(),
        AdminUsername::parse("fixture_owner").unwrap(),
        AdminDisplayName::parse("Fixture owner").unwrap(),
        AdminRole::Owner,
    );
    account
        .install_password(
            AdminPasswordVerifier::from_parts(
                AdminPasswordVerifier::PROFILE_ID,
                &[4; 16],
                &[5; 32],
            )
            .unwrap(),
        )
        .unwrap();
    account
}

fn commit_owner(store: &mut SqliteStore) -> Result<AdminAccount, AdminAccessError> {
    let account = active_owner();
    store.identity_transaction(|tx| {
        let before = tx.auth_state()?;
        tx.insert_account(&account.snapshot())?;
        tx.set_auth_state(
            before,
            AdminAuthState {
                mode: AdminAuthMode::Personal,
                epoch: before.epoch,
            },
        )?;
        let mut event =
            AuditEvent::security("admin_owner_initialized", account.snapshot().id.as_str());
        event.actor = AuditActor::new(account.snapshot().id.as_str());
        tx.append_identity_audit(&event)?;
        Ok(account)
    })
}

#[test]
fn identity_schema28_initializes_once_and_preserves_human_epoch() {
    assert_eq!(CURRENT_SCHEMA_VERSION, 28);
    let store = SqliteStore::in_memory().unwrap();
    let state = store.auth_state().unwrap();
    assert_eq!(state.mode, AdminAuthMode::LegacyBootstrap);
    assert_eq!(store.loginable_owner_count().unwrap(), 0);
    store.migrate().unwrap();
    assert_eq!(store.auth_state().unwrap(), state);
    assert_ne!(
        SqliteStore::in_memory()
            .unwrap()
            .auth_state()
            .unwrap()
            .epoch,
        state.epoch
    );
}

#[test]
fn schema28_version_failure_rolls_back_new_tables_epoch_and_version() {
    let store = fixture_store();
    let before = legacy_snapshot(&store);
    store.connection.execute_batch("CREATE TRIGGER reject_identity_version BEFORE UPDATE ON schema_migrations WHEN NEW.version=28 BEGIN SELECT RAISE(ABORT,'synthetic migration fault'); END;").unwrap();
    assert!(store.migrate().is_err());
    assert_eq!(store.current_schema_version().unwrap(), Some(27));
    assert_eq!(legacy_snapshot(&store), before);
    assert_eq!(store.connection.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('admin_auth_state','admin_accounts','admin_credentials')", [], |row| row.get::<_,i64>(0)).unwrap(), 0);
}

#[test]
fn identity_schema28_missing_table_is_corruption_never_a_fresh_legacy_bootstrap() {
    let store = SqliteStore::in_memory().unwrap();
    let state = store.auth_state().unwrap();
    store
        .connection
        .execute_batch("DROP TABLE admin_credentials")
        .unwrap();
    assert!(store.migrate().is_err());
    assert_eq!(store.auth_state().unwrap(), state);
    assert_eq!(
        store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='admin_credentials'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn owner_cutover_disables_legacy_lookup_and_insertion_but_preserves_legacy_history() {
    let mut store = fixture_store();
    store.migrate().unwrap();
    let hash: String = store
        .connection
        .query_row("SELECT token_hash FROM admin_tokens", [], |row| row.get(0))
        .unwrap();
    assert!(store.verify_admin_token_hash(&hash).unwrap());
    assert_eq!(
        store
            .find_admin_token_record(&hash)
            .unwrap()
            .unwrap()
            .actor_id,
        "bootstrap-admin"
    );
    let before = legacy_snapshot(&store);
    let owner = commit_owner(&mut store).unwrap();
    assert_eq!(store.auth_state().unwrap().mode, AdminAuthMode::Personal);
    assert_eq!(
        store
            .account_by_id(&owner.snapshot().id)
            .unwrap()
            .unwrap()
            .snapshot(),
        owner.snapshot()
    );
    assert_eq!(store.loginable_owner_count().unwrap(), 1);
    assert!(!store.verify_admin_token_hash(&hash).unwrap());
    assert!(store.find_admin_token_record(&hash).unwrap().is_none());
    assert!(
        store
            .insert_admin_token_hash("synthetic-unused-hash")
            .is_err()
    );
    let after = legacy_snapshot(&store);
    for (table, rows) in before {
        if table != "audit_events" {
            assert_eq!(after[&table], rows, "cutover must preserve {table}");
        } else {
            assert_eq!(after[&table].len(), rows.len() + 1);
        }
    }
}

#[test]
fn owner_audit_failure_rolls_back_the_whole_identity_transaction() {
    let mut store = fixture_store();
    store.migrate().unwrap();
    let before = legacy_snapshot(&store);
    let auth = store.auth_state().unwrap();
    store.connection.execute_batch("CREATE TRIGGER reject_identity_audit BEFORE INSERT ON audit_events WHEN NEW.action='admin_owner_initialized' BEGIN SELECT RAISE(ABORT,'synthetic audit fault'); END;").unwrap();
    assert_eq!(
        commit_owner(&mut store).unwrap_err(),
        AdminAccessError::Unavailable
    );
    assert_eq!(store.auth_state().unwrap(), auth);
    assert!(
        store
            .account_by_id(&active_owner().snapshot().id)
            .unwrap()
            .is_none()
    );
    assert_eq!(legacy_snapshot(&store), before);
}

#[test]
fn account_mapping_roundtrips_and_rejects_stale_revision_or_username_mutation() {
    let mut store = SqliteStore::in_memory().unwrap();
    let owner = commit_owner(&mut store).unwrap();
    let before = owner.snapshot();
    let mut changed = owner.clone();
    changed
        .rename(AdminDisplayName::parse("Renamed fixture").unwrap())
        .unwrap();
    store
        .identity_transaction(|tx| tx.replace_account(before.record_revision, &changed.snapshot()))
        .unwrap();
    assert_eq!(
        store
            .account_by_username(&before.username)
            .unwrap()
            .unwrap()
            .snapshot(),
        changed.snapshot()
    );
    assert_eq!(
        store.identity_transaction(
            |tx| tx.replace_account(before.record_revision, &changed.snapshot())
        ),
        Err(AdminAccessError::Conflict)
    );
    let mut invalid = changed.snapshot();
    invalid.username = AdminUsername::parse("renamed_login").unwrap();
    assert_eq!(
        store.identity_transaction(
            |tx| tx.replace_account(changed.snapshot().record_revision, &invalid)
        ),
        Err(AdminAccessError::Conflict)
    );
    assert_eq!(
        store.account_by_id(&before.id).unwrap().unwrap().snapshot(),
        changed.snapshot()
    );
}

#[test]
fn credential_lookup_is_purpose_bound_and_revoke_preserves_consumed_grants() {
    let mut store = SqliteStore::in_memory().unwrap();
    commit_owner(&mut store).unwrap();
    let pending = AdminAccount::pending(
        AdminUserId::parse("usr_00000000000000000000000000000002").unwrap(),
        AdminUsername::parse("fixture_pending").unwrap(),
        AdminDisplayName::parse("Pending fixture").unwrap(),
        AdminRole::Viewer,
    );
    let epoch = store.auth_state().unwrap().epoch;
    let mut grant = AdminCredential::issue(
        AdminCredentialId::parse("crd_00000000000000000000000000000001").unwrap(),
        AdminCredentialKind::SetupGrant,
        AdminCredentialDigest::from_bytes([7; 32]),
        AdminCredentialBinding::for_account(&pending, epoch),
        1_000,
    )
    .unwrap();
    store
        .identity_transaction(|tx| {
            tx.insert_account(&pending.snapshot())?;
            tx.insert_credential(&grant.snapshot())
        })
        .unwrap();
    let original = grant.snapshot();
    assert_eq!(
        store
            .credential_by_id(&original.id)
            .unwrap()
            .unwrap()
            .snapshot(),
        original
    );
    assert_eq!(
        store
            .credential_by_digest(original.kind, &original.digest)
            .unwrap()
            .unwrap()
            .snapshot(),
        original
    );
    assert!(
        store
            .credential_by_digest(AdminCredentialKind::PersonalToken, &original.digest)
            .unwrap()
            .is_none()
    );
    grant
        .consume(
            original.kind,
            AdminAuthMode::Personal,
            &pending,
            epoch,
            1_001,
        )
        .unwrap();
    store
        .identity_transaction(|tx| {
            tx.replace_credential(&original, &grant.snapshot())?;
            tx.revoke_user_credentials(&pending.snapshot().id, 1_002)
        })
        .unwrap();
    assert_eq!(
        store
            .credential_by_id(&original.id)
            .unwrap()
            .unwrap()
            .snapshot(),
        grant.snapshot()
    );
    assert_eq!(
        store.identity_transaction(|tx| tx.replace_credential(&grant.snapshot(), &original)),
        Err(AdminAccessError::Conflict)
    );
}

#[test]
fn corrupted_owner_rows_are_not_normalized_or_counted_as_loginable() {
    for (column, value) in [
        ("username", "'Fixture_Owner'"),
        ("display_name", "char(10)"),
        ("password_profile", "'unknown-profile'"),
        ("password_hash", "X'01'"),
    ] {
        let mut store = SqliteStore::in_memory().unwrap();
        let owner = commit_owner(&mut store).unwrap();
        store
            .connection
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        store
            .connection
            .execute_batch(&format!("UPDATE admin_accounts SET {column}={value}"))
            .unwrap();
        assert!(
            matches!(
                store.account_by_id(&owner.snapshot().id),
                Err(AdminAccessError::Unavailable)
            ),
            "corrupt {column} must not become a valid account"
        );
        assert_eq!(
            store.loginable_owner_count(),
            Err(AdminAccessError::Unavailable),
            "corrupt {column} must fail the owner guard closed"
        );
        assert_eq!(store.auth_state().unwrap().mode, AdminAuthMode::Personal);
    }
}

#[test]
fn canonical_username_uniqueness_and_commit_owner_guard_prevent_partial_changes() {
    let mut store = SqliteStore::in_memory().unwrap();
    let owner = commit_owner(&mut store).unwrap();
    let duplicate = AdminAccount::pending(
        AdminUserId::parse("usr_00000000000000000000000000000002").unwrap(),
        AdminUsername::parse("FIXTURE_OWNER").unwrap(),
        AdminDisplayName::parse("Duplicate fixture").unwrap(),
        AdminRole::Viewer,
    );
    assert_eq!(
        store.identity_transaction(|tx| tx.insert_account(&duplicate.snapshot())),
        Err(AdminAccessError::UserExists)
    );
    assert!(
        store
            .account_by_id(&duplicate.snapshot().id)
            .unwrap()
            .is_none()
    );
    let mut disabled = owner.clone();
    disabled.disable(1).unwrap();
    assert_eq!(
        store.identity_transaction(
            |tx| tx.replace_account(owner.snapshot().record_revision, &disabled.snapshot())
        ),
        Err(AdminAccessError::LastOwner)
    );
    assert_eq!(
        store
            .account_by_id(&owner.snapshot().id)
            .unwrap()
            .unwrap()
            .snapshot(),
        owner.snapshot()
    );
    let state = store.auth_state().unwrap();
    assert_eq!(
        store.identity_transaction(|tx| tx.set_auth_state(
            state,
            AdminAuthState {
                mode: AdminAuthMode::LegacyBootstrap,
                epoch: state.epoch
            }
        )),
        Err(AdminAccessError::Conflict)
    );
    assert_eq!(store.auth_state().unwrap(), state);
}

#[test]
fn corrupt_auth_mode_or_epoch_is_an_error_without_bootstrap_fallback() {
    for change in ["mode='unknown'", "epoch=X'01'"] {
        let store = SqliteStore::in_memory().unwrap();
        store
            .connection
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        store
            .connection
            .execute_batch(&format!("UPDATE admin_auth_state SET {change}"))
            .unwrap();
        assert_eq!(store.auth_state(), Err(AdminAccessError::Unavailable));
        assert!(store.migrate().is_err());
    }
}

#[test]
fn identity_primary_keys_reject_null_even_with_sqlite_text_primary_key_semantics() {
    let store = SqliteStore::in_memory().unwrap();
    assert!(
        store
            .connection
            .execute(
                "INSERT INTO admin_accounts
        (user_id,username,display_name,role,status,record_revision,credential_revision)
        VALUES(NULL,'null_fixture','Null fixture','viewer','pending_setup',0,0)",
                []
            )
            .is_err()
    );
}

#[path = "admin_identity_contract_tests.rs"]
mod contracts;
