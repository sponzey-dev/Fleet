//! Human identity persistence and atomic authentication/account/credential/audit boundaries.

#[cfg(feature = "postgres")]
#[path = "admin_identity_postgres.rs"]
mod postgres;
#[cfg(feature = "postgres")]
pub(super) use postgres::PgIdentityTransaction;
#[cfg(feature = "postgres")]
pub(super) use postgres::{migrate_postgres, require_legacy_postgres};

use crate::{SqliteStore, StoreError};
use fleet_application::admin_identity::{
    ADMIN_LOOKUP_CLEANUP_LIMIT, AdminAccessError, AdminAccountQuery, AdminAuthState,
    AdminCredentialCounts, AdminIdentityRead, AdminIdentityRepository, AdminIdentityTransaction,
    AdminPersonalTokenQuery,
};
use fleet_domain::{
    AdminAccount, AdminAccountSnapshot, AdminAccountStatus, AdminAuthMode, AdminCredential,
    AdminCredentialBinding, AdminCredentialDigest, AdminCredentialId, AdminCredentialKind,
    AdminCredentialSnapshot, AdminCredentialState, AdminDisplayName, AdminPasswordVerifier,
    AdminRevision, AdminRole, AdminTokenLabel, AdminUserId, AdminUsername, AuditCategory,
    AuditEvent, AuditValue, HumanAuthEpoch,
};

// Both adapters execute these projections inside their serialized identity transaction.
// Admission counts all physical rows, including rows that bounded cleanup has not reached.
const CREDENTIAL_COUNTS_SQL: &str = "SELECT
    (SELECT count(*) FROM admin_credentials c
     JOIN admin_accounts a ON a.user_id=c.user_id JOIN admin_auth_state s ON s.id=1
     WHERE c.kind=$1 AND c.user_id=$2 AND s.mode='personal' AND c.state='active'
       AND c.epoch=s.epoch AND c.credential_revision=a.credential_revision
       AND c.created_at<=$3 AND c.expires_at>$3 AND a.status='active'),
    (SELECT count(*) FROM admin_credentials WHERE kind=$1)";

const CLEANUP_RETIRED_LOOKUPS_SQL: &str = "DELETE FROM admin_credentials WHERE credential_id IN (
    SELECT c.credential_id FROM admin_credentials c
    JOIN admin_auth_state s ON s.id=1 LEFT JOIN admin_accounts a ON a.user_id=c.user_id
    WHERE c.kind=$1 AND (s.mode<>'personal' OR c.state<>'active' OR c.expires_at<=$2
      OR c.epoch<>s.epoch OR a.user_id IS NULL OR c.credential_revision<>a.credential_revision
      OR (c.kind IN ('setup_grant','reset_grant') AND a.status<>'pending_setup')
      OR (c.kind NOT IN ('setup_grant','reset_grant') AND a.status<>'active'))
    ORDER BY c.credential_id LIMIT $3)";

const PERSONAL_TOKEN_PAGE_SQL: &str = "SELECT credential_id,kind,user_id,credential_revision,epoch,digest,created_at,expires_at,state,ended_at,label
    FROM admin_credentials WHERE kind='personal_token' AND user_id=$1
      AND (CAST($2 AS TEXT) IS NULL OR credential_id>CAST($2 AS TEXT))
    ORDER BY credential_id LIMIT $3";
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

const IDENTITY_SCHEMA: &str = r#"
CREATE TABLE admin_auth_state (
    id INTEGER PRIMARY KEY CHECK(id=1),
    mode TEXT NOT NULL CHECK(mode IN ('legacy_bootstrap','personal','local_setup_required')),
    epoch BLOB NOT NULL CHECK(typeof(epoch)='blob' AND length(epoch)=16)
);
CREATE TABLE admin_accounts (
    user_id TEXT PRIMARY KEY NOT NULL CHECK(length(user_id)=36 AND substr(user_id,1,4)='usr_'
        AND substr(user_id,5) NOT GLOB '*[^0-9a-f]*'),
    username TEXT NOT NULL UNIQUE CHECK(length(username) BETWEEN 3 AND 64
        AND username=lower(username) AND username NOT GLOB '*[^a-z0-9_.-]*'
        AND substr(username,1,1) GLOB '[a-z0-9]'),
    display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 120
        AND length(CAST(display_name AS BLOB))<=480),
    role TEXT NOT NULL CHECK(role IN ('owner','admin','operator','viewer')),
    status TEXT NOT NULL CHECK(status IN ('pending_setup','active','disabled')),
    record_revision INTEGER NOT NULL CHECK(typeof(record_revision)='integer' AND record_revision>=0),
    credential_revision INTEGER NOT NULL CHECK(typeof(credential_revision)='integer'
        AND credential_revision>=0 AND credential_revision<=record_revision),
    password_profile TEXT,
    password_salt BLOB,
    password_hash BLOB,
    CHECK((password_profile IS NULL AND password_salt IS NULL AND password_hash IS NULL AND status<>'active')
        OR (password_profile IS NOT NULL AND password_profile='argon2id-v19-m19456-t2-p1'
            AND typeof(password_salt)='blob' AND length(password_salt)=16
            AND typeof(password_hash)='blob' AND length(password_hash)=32 AND status<>'pending_setup'))
);
CREATE TABLE admin_credentials (
    credential_id TEXT PRIMARY KEY NOT NULL CHECK(length(credential_id)=36 AND substr(credential_id,1,4)='crd_'
        AND substr(credential_id,5) NOT GLOB '*[^0-9a-f]*'),
    kind TEXT NOT NULL CHECK(kind IN ('web_session','personal_token','setup_grant','reset_grant')),
    user_id TEXT NOT NULL REFERENCES admin_accounts(user_id) ON DELETE RESTRICT,
    credential_revision INTEGER NOT NULL CHECK(typeof(credential_revision)='integer' AND credential_revision>=0),
    epoch BLOB NOT NULL CHECK(typeof(epoch)='blob' AND length(epoch)=16),
    digest BLOB NOT NULL CHECK(typeof(digest)='blob' AND length(digest)=32),
    created_at INTEGER NOT NULL CHECK(typeof(created_at)='integer' AND created_at>=0),
    expires_at INTEGER NOT NULL CHECK(typeof(expires_at)='integer' AND expires_at>created_at
        AND expires_at-created_at=CASE kind WHEN 'web_session' THEN 28800
            WHEN 'personal_token' THEN 2592000 ELSE 900 END),
    state TEXT NOT NULL CHECK(state IN ('active','revoked','consumed')),
    ended_at INTEGER,
    label TEXT CHECK(label IS NULL OR length(CAST(label AS BLOB))<=256),
    UNIQUE(kind,digest),
    CHECK((state='active' AND ended_at IS NULL)
        OR (state='revoked' AND typeof(ended_at)='integer' AND ended_at>=created_at)
        OR (state='consumed' AND kind IN ('setup_grant','reset_grant')
            AND typeof(ended_at)='integer' AND ended_at>=created_at AND ended_at<expires_at))
);
"#;

fn unavailable(_: impl std::fmt::Debug) -> AdminAccessError {
    AdminAccessError::Unavailable
}

fn schema_unavailable(_: impl std::fmt::Debug) -> StoreError {
    StoreError::Domain("administrator identity schema unavailable".into())
}

/// The new identity schema, human epoch and v28 marker commit together.
/// A v28 store missing these objects is corrupt; never recreate legacy access.
pub(super) fn migrate_sqlite(store: &SqliteStore) -> Result<(), StoreError> {
    if store
        .current_schema_version()?
        .is_some_and(|version| version >= 28)
    {
        let count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'
             AND name IN ('admin_auth_state','admin_accounts','admin_credentials')",
                [],
                |row| row.get(0),
            )
            .map_err(schema_unavailable)?;
        if count != 3 {
            return Err(schema_unavailable(()));
        }
        read_auth(&store.connection).map_err(schema_unavailable)?;
        return Ok(());
    }
    let transaction = Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate)
        .map_err(schema_unavailable)?;
    transaction
        .execute_batch(IDENTITY_SCHEMA)
        .map_err(schema_unavailable)?;
    let mut epoch = [0u8; 16];
    getrandom::getrandom(&mut epoch).map_err(schema_unavailable)?;
    transaction
        .execute(
            "INSERT INTO admin_auth_state(id,mode,epoch) VALUES(1,'legacy_bootstrap',?1)",
            [&epoch[..]],
        )
        .map_err(schema_unavailable)?;
    store
        .record_schema_version(28)
        .map_err(schema_unavailable)?;
    transaction.commit().map_err(schema_unavailable)
}

pub(super) fn require_legacy_token_mode(store: &SqliteStore) -> Result<(), StoreError> {
    if read_auth(&store.connection)
        .map_err(schema_unavailable)?
        .mode
        != AdminAuthMode::LegacyBootstrap
    {
        return Err(StoreError::Domain(
            "legacy administrator access is disabled".into(),
        ));
    }
    Ok(())
}

fn mode_text(mode: AdminAuthMode) -> &'static str {
    match mode {
        AdminAuthMode::LegacyBootstrap => "legacy_bootstrap",
        AdminAuthMode::Personal => "personal",
        AdminAuthMode::LocalSetupRequired => "local_setup_required",
    }
}

fn role_text(role: AdminRole) -> &'static str {
    match role {
        AdminRole::Owner => "owner",
        AdminRole::Admin => "admin",
        AdminRole::Operator => "operator",
        AdminRole::Viewer => "viewer",
    }
}

fn status_text(status: AdminAccountStatus) -> &'static str {
    match status {
        AdminAccountStatus::PendingSetup => "pending_setup",
        AdminAccountStatus::Active => "active",
        AdminAccountStatus::Disabled => "disabled",
    }
}

fn kind_text(kind: AdminCredentialKind) -> &'static str {
    match kind {
        AdminCredentialKind::WebSession => "web_session",
        AdminCredentialKind::PersonalToken => "personal_token",
        AdminCredentialKind::SetupGrant => "setup_grant",
        AdminCredentialKind::ResetGrant => "reset_grant",
    }
}

fn credential_state_text(state: AdminCredentialState) -> &'static str {
    match state {
        AdminCredentialState::Active => "active",
        AdminCredentialState::Revoked => "revoked",
        AdminCredentialState::Consumed => "consumed",
    }
}

fn read_auth(connection: &Connection) -> Result<AdminAuthState, AdminAccessError> {
    let (mode, epoch): (String, Vec<u8>) = connection
        .query_row(
            "SELECT mode,epoch FROM admin_auth_state WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(unavailable)?;
    auth_from_parts(&mode, epoch)
}

fn auth_from_parts(mode: &str, epoch: Vec<u8>) -> Result<AdminAuthState, AdminAccessError> {
    let mode = match mode {
        "legacy_bootstrap" => AdminAuthMode::LegacyBootstrap,
        "personal" => AdminAuthMode::Personal,
        "local_setup_required" => AdminAuthMode::LocalSetupRequired,
        _ => return Err(AdminAccessError::Unavailable),
    };
    Ok(AdminAuthState {
        mode,
        epoch: HumanAuthEpoch::from_bytes(epoch.try_into().map_err(unavailable)?),
    })
}

struct AccountRow {
    id: String,
    username: String,
    display_name: String,
    role: String,
    status: String,
    record_revision: i64,
    credential_revision: i64,
    profile: Option<String>,
    salt: Option<Vec<u8>>,
    hash: Option<Vec<u8>>,
}

impl AccountRow {
    fn into_domain(self) -> Result<AdminAccount, AdminAccessError> {
        let username = AdminUsername::parse(&self.username).map_err(unavailable)?;
        if username.as_str() != self.username {
            return Err(AdminAccessError::Unavailable);
        }
        let password_verifier = match (self.profile, self.salt, self.hash) {
            (None, None, None) => None,
            (Some(profile), Some(salt), Some(hash)) => Some(
                AdminPasswordVerifier::from_parts(&profile, &salt, &hash).map_err(unavailable)?,
            ),
            _ => return Err(AdminAccessError::Unavailable),
        };
        let status = match self.status.as_str() {
            "pending_setup" => AdminAccountStatus::PendingSetup,
            "active" => AdminAccountStatus::Active,
            "disabled" => AdminAccountStatus::Disabled,
            _ => return Err(AdminAccessError::Unavailable),
        };
        AdminAccount::from_snapshot(AdminAccountSnapshot {
            id: AdminUserId::parse(self.id).map_err(unavailable)?,
            username,
            display_name: AdminDisplayName::parse(self.display_name).map_err(unavailable)?,
            role: AdminRole::parse(&self.role).ok_or(AdminAccessError::Unavailable)?,
            status,
            record_revision: AdminRevision::new(self.record_revision).map_err(unavailable)?,
            credential_revision: AdminRevision::new(self.credential_revision)
                .map_err(unavailable)?,
            password_verifier,
        })
        .map_err(unavailable)
    }
}

const ACCOUNT_COLUMNS: &str = "user_id,username,display_name,role,status,record_revision,
    credential_revision,password_profile,password_salt,password_hash";

fn account_page_query() -> String {
    format!(
        "SELECT {ACCOUNT_COLUMNS} FROM admin_accounts
        WHERE (CAST($1 AS TEXT) IS NULL OR user_id>CAST($1 AS TEXT))
        ORDER BY user_id LIMIT $2"
    )
}

fn account_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccountRow> {
    Ok(AccountRow {
        id: row.get(0)?,
        username: row.get(1)?,
        display_name: row.get(2)?,
        role: row.get(3)?,
        status: row.get(4)?,
        record_revision: row.get(5)?,
        credential_revision: row.get(6)?,
        profile: row.get(7)?,
        salt: row.get(8)?,
        hash: row.get(9)?,
    })
}

fn read_account(
    connection: &Connection,
    column: &'static str,
    value: &str,
) -> Result<Option<AdminAccount>, AdminAccessError> {
    let sql = format!("SELECT {ACCOUNT_COLUMNS} FROM admin_accounts WHERE {column}=?1");
    let row = connection
        .query_row(&sql, [value], account_row)
        .optional()
        .map_err(unavailable)?;
    row.map(AccountRow::into_domain).transpose()
}

struct CredentialRow {
    id: String,
    kind: String,
    user_id: String,
    revision: i64,
    epoch: Vec<u8>,
    digest: Vec<u8>,
    created_at: i64,
    expires_at: i64,
    state: String,
    ended_at: Option<i64>,
    label: Option<String>,
}

impl CredentialRow {
    fn into_domain(self) -> Result<AdminCredential, AdminAccessError> {
        let kind = match self.kind.as_str() {
            "web_session" => AdminCredentialKind::WebSession,
            "personal_token" => AdminCredentialKind::PersonalToken,
            "setup_grant" => AdminCredentialKind::SetupGrant,
            "reset_grant" => AdminCredentialKind::ResetGrant,
            _ => return Err(AdminAccessError::Unavailable),
        };
        let state = match self.state.as_str() {
            "active" => AdminCredentialState::Active,
            "revoked" => AdminCredentialState::Revoked,
            "consumed" => AdminCredentialState::Consumed,
            _ => return Err(AdminAccessError::Unavailable),
        };
        AdminCredential::from_snapshot(AdminCredentialSnapshot {
            id: AdminCredentialId::parse(self.id).map_err(unavailable)?,
            kind,
            digest: AdminCredentialDigest::from_bytes(self.digest.try_into().map_err(unavailable)?),
            binding: AdminCredentialBinding {
                user_id: AdminUserId::parse(self.user_id).map_err(unavailable)?,
                credential_revision: AdminRevision::new(self.revision).map_err(unavailable)?,
                epoch: HumanAuthEpoch::from_bytes(self.epoch.try_into().map_err(unavailable)?),
            },
            created_at: self.created_at,
            expires_at: self.expires_at,
            state,
            ended_at: self.ended_at,
            label: self
                .label
                .as_deref()
                .map(AdminTokenLabel::parse)
                .transpose()
                .map_err(unavailable)?,
        })
        .map_err(unavailable)
    }
}

fn read_credential(
    connection: &Connection,
    condition: &'static str,
    values: impl rusqlite::Params,
) -> Result<Option<AdminCredential>, AdminAccessError> {
    let sql = format!("SELECT credential_id,kind,user_id,credential_revision,epoch,digest,created_at,expires_at,state,ended_at,label
        FROM admin_credentials WHERE {condition}");
    let row = connection
        .query_row(&sql, values, sqlite_credential_row)
        .optional()
        .map_err(unavailable)?;
    row.map(CredentialRow::into_domain).transpose()
}

fn sqlite_credential_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CredentialRow> {
    Ok(CredentialRow {
        id: row.get(0)?,
        kind: row.get(1)?,
        user_id: row.get(2)?,
        revision: row.get(3)?,
        epoch: row.get(4)?,
        digest: row.get(5)?,
        created_at: row.get(6)?,
        expires_at: row.get(7)?,
        state: row.get(8)?,
        ended_at: row.get(9)?,
        label: row.get(10)?,
    })
}

impl AdminAccountQuery for SqliteStore {
    fn account_page(
        &self,
        after: Option<&AdminUserId>,
        limit: usize,
    ) -> Result<Vec<AdminAccount>, AdminAccessError> {
        if !(1..=101).contains(&limit) {
            return Err(AdminAccessError::InvalidRequest);
        }
        let limit = i64::try_from(limit).map_err(unavailable)?;
        let mut statement = self
            .connection
            .prepare(&account_page_query())
            .map_err(unavailable)?;
        let rows = statement
            .query_map(params![after.map(AdminUserId::as_str), limit], account_row)
            .map_err(unavailable)?;
        rows.map(|row| row.map_err(unavailable)?.into_domain())
            .collect()
    }
}

impl AdminPersonalTokenQuery for SqliteStore {
    fn personal_token_page(
        &self,
        owner: &AdminUserId,
        after: Option<&AdminCredentialId>,
        limit: usize,
    ) -> Result<Vec<AdminCredential>, AdminAccessError> {
        if !(1..=101).contains(&limit) {
            return Err(AdminAccessError::InvalidRequest);
        }
        let limit = i64::try_from(limit).map_err(unavailable)?;
        let mut statement = self
            .connection
            .prepare(PERSONAL_TOKEN_PAGE_SQL)
            .map_err(unavailable)?;
        let rows = statement
            .query_map(
                params![owner.as_str(), after.map(AdminCredentialId::as_str), limit],
                sqlite_credential_row,
            )
            .map_err(unavailable)?;
        rows.map(|row| row.map_err(unavailable)?.into_domain())
            .collect()
    }
}

impl AdminIdentityRead for SqliteStore {
    fn own_personal_token(
        &self,
        owner: &AdminUserId,
        id: &AdminCredentialId,
    ) -> Result<Option<AdminCredential>, AdminAccessError> {
        read_credential(
            &self.connection,
            "credential_id=?1 AND user_id=?2 AND kind='personal_token'",
            params![id.as_str(), owner.as_str()],
        )
    }
    fn auth_state(&self) -> Result<AdminAuthState, AdminAccessError> {
        read_auth(&self.connection)
    }
    fn account_by_id(&self, id: &AdminUserId) -> Result<Option<AdminAccount>, AdminAccessError> {
        read_account(&self.connection, "user_id", id.as_str())
    }
    fn account_by_username(
        &self,
        name: &AdminUsername,
    ) -> Result<Option<AdminAccount>, AdminAccessError> {
        read_account(&self.connection, "username", name.as_str())
    }
    fn loginable_owner_count(&self) -> Result<usize, AdminAccessError> {
        let sql = format!(
            "SELECT {ACCOUNT_COLUMNS} FROM admin_accounts WHERE role='owner' AND status='active'"
        );
        let mut statement = self.connection.prepare(&sql).map_err(unavailable)?;
        let rows = statement.query_map([], account_row).map_err(unavailable)?;
        let mut count = 0usize;
        for row in rows {
            let account = row.map_err(unavailable)?.into_domain()?;
            if !account.is_loginable() {
                return Err(AdminAccessError::Unavailable);
            }
            count = count.checked_add(1).ok_or(AdminAccessError::Unavailable)?;
        }
        Ok(count)
    }
    fn credential_by_id(
        &self,
        id: &AdminCredentialId,
    ) -> Result<Option<AdminCredential>, AdminAccessError> {
        read_credential(&self.connection, "credential_id=?1", [id.as_str()])
    }
    fn credential_by_digest(
        &self,
        kind: AdminCredentialKind,
        digest: &AdminCredentialDigest,
    ) -> Result<Option<AdminCredential>, AdminAccessError> {
        read_credential(
            &self.connection,
            "kind=?1 AND digest=?2",
            params![kind_text(kind), digest.bytes().as_slice()],
        )
    }
}

pub(crate) struct SqliteIdentityTransaction<'a> {
    pub(crate) store: &'a SqliteStore,
}

impl AdminIdentityRead for SqliteIdentityTransaction<'_> {
    fn own_personal_token(
        &self,
        owner: &AdminUserId,
        id: &AdminCredentialId,
    ) -> Result<Option<AdminCredential>, AdminAccessError> {
        self.store.own_personal_token(owner, id)
    }
    fn auth_state(&self) -> Result<AdminAuthState, AdminAccessError> {
        self.store.auth_state()
    }
    fn account_by_id(&self, id: &AdminUserId) -> Result<Option<AdminAccount>, AdminAccessError> {
        self.store.account_by_id(id)
    }
    fn account_by_username(
        &self,
        name: &AdminUsername,
    ) -> Result<Option<AdminAccount>, AdminAccessError> {
        self.store.account_by_username(name)
    }
    fn loginable_owner_count(&self) -> Result<usize, AdminAccessError> {
        self.store.loginable_owner_count()
    }
    fn credential_by_id(
        &self,
        id: &AdminCredentialId,
    ) -> Result<Option<AdminCredential>, AdminAccessError> {
        self.store.credential_by_id(id)
    }
    fn credential_by_digest(
        &self,
        kind: AdminCredentialKind,
        digest: &AdminCredentialDigest,
    ) -> Result<Option<AdminCredential>, AdminAccessError> {
        self.store.credential_by_digest(kind, digest)
    }
}

impl AdminIdentityTransaction for SqliteIdentityTransaction<'_> {
    fn credential_counts(
        &self,
        kind: AdminCredentialKind,
        user: &AdminUserId,
        now: i64,
    ) -> Result<AdminCredentialCounts, AdminAccessError> {
        if kind.is_grant() || now < 0 {
            return Err(AdminAccessError::InvalidRequest);
        }
        let counts: (i64, i64) = self
            .store
            .connection
            .query_row(
                CREDENTIAL_COUNTS_SQL,
                params![kind_text(kind), user.as_str(), now],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(unavailable)?;
        Ok(AdminCredentialCounts {
            valid_for_user: usize::try_from(counts.0).map_err(unavailable)?,
            total_rows: usize::try_from(counts.1).map_err(unavailable)?,
        })
    }

    fn cleanup_retired_credentials(
        &mut self,
        kind: AdminCredentialKind,
        now: i64,
        limit: usize,
    ) -> Result<usize, AdminAccessError> {
        if now < 0 || limit == 0 || limit > ADMIN_LOOKUP_CLEANUP_LIMIT {
            return Err(AdminAccessError::InvalidRequest);
        }
        let limit = i64::try_from(limit).map_err(unavailable)?;
        self.store
            .connection
            .execute(
                CLEANUP_RETIRED_LOOKUPS_SQL,
                params![kind_text(kind), now, limit],
            )
            .map_err(unavailable)
    }

    fn insert_account(&mut self, value: &AdminAccountSnapshot) -> Result<(), AdminAccessError> {
        AdminAccount::from_snapshot(value.clone()).map_err(|_| AdminAccessError::Conflict)?;
        if self.account_by_id(&value.id)?.is_some() {
            return Err(AdminAccessError::Conflict);
        }
        if self.account_by_username(&value.username)?.is_some() {
            return Err(AdminAccessError::UserExists);
        }
        let verifier = value.password_verifier.as_ref();
        self.store.connection.execute("INSERT INTO admin_accounts
            (user_id,username,display_name,role,status,record_revision,credential_revision,password_profile,password_salt,password_hash)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",params![
            value.id.as_str(),value.username.as_str(),value.display_name.as_str(),role_text(value.role),status_text(value.status),
            value.record_revision.value(),value.credential_revision.value(),verifier.map(|_|AdminPasswordVerifier::PROFILE_ID),
            verifier.map(|v|v.salt_bytes().as_slice()),verifier.map(|v|v.hash_bytes().as_slice())
        ]).map_err(unavailable)?;
        Ok(())
    }

    fn replace_account(
        &mut self,
        expected: AdminRevision,
        value: &AdminAccountSnapshot,
    ) -> Result<(), AdminAccessError> {
        AdminAccount::from_snapshot(value.clone()).map_err(|_| AdminAccessError::Conflict)?;
        let old = self
            .account_by_id(&value.id)?
            .ok_or(AdminAccessError::Conflict)?
            .snapshot();
        validate_account_replacement(&old, expected, value)?;
        let verifier = value.password_verifier.as_ref();
        let changed=self.store.connection.execute("UPDATE admin_accounts SET display_name=?2,role=?3,status=?4,
            record_revision=?5,credential_revision=?6,password_profile=?7,password_salt=?8,password_hash=?9
            WHERE user_id=?1 AND record_revision=?10",params![
            value.id.as_str(),value.display_name.as_str(),role_text(value.role),status_text(value.status),
            value.record_revision.value(),value.credential_revision.value(),verifier.map(|_|AdminPasswordVerifier::PROFILE_ID),
            verifier.map(|v|v.salt_bytes().as_slice()),verifier.map(|v|v.hash_bytes().as_slice()),expected.value()
        ]).map_err(unavailable)?;
        if changed != 1 {
            return Err(AdminAccessError::Conflict);
        }
        Ok(())
    }

    fn set_auth_state(
        &mut self,
        expected: AdminAuthState,
        value: AdminAuthState,
    ) -> Result<(), AdminAccessError> {
        if self.auth_state()? != expected
            || (value.mode == AdminAuthMode::LegacyBootstrap && expected.mode != value.mode)
        {
            return Err(AdminAccessError::Conflict);
        }
        let changed = self
            .store
            .connection
            .execute(
                "UPDATE admin_auth_state SET mode=?1,epoch=?2
            WHERE id=1 AND mode=?3 AND epoch=?4",
                params![
                    mode_text(value.mode),
                    value.epoch.bytes().as_slice(),
                    mode_text(expected.mode),
                    expected.epoch.bytes().as_slice()
                ],
            )
            .map_err(unavailable)?;
        if changed != 1 {
            return Err(AdminAccessError::Conflict);
        }
        Ok(())
    }

    fn revoke_user_credentials(
        &mut self,
        user: &AdminUserId,
        now: i64,
    ) -> Result<(), AdminAccessError> {
        if now < 0 {
            return Err(AdminAccessError::InvalidRequest);
        }
        let future: bool = self
            .store
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM admin_credentials
            WHERE user_id=?1 AND state='active' AND created_at>?2)",
                params![user.as_str(), now],
                |row| row.get(0),
            )
            .map_err(unavailable)?;
        if future {
            return Err(AdminAccessError::Conflict);
        }
        self.store
            .connection
            .execute(
                "UPDATE admin_credentials SET state='revoked',ended_at=?2
            WHERE user_id=?1 AND state='active'",
                params![user.as_str(), now],
            )
            .map_err(unavailable)?;
        Ok(())
    }

    fn insert_credential(
        &mut self,
        value: &AdminCredentialSnapshot,
    ) -> Result<(), AdminAccessError> {
        let credential = AdminCredential::from_snapshot(value.clone())
            .map_err(|_| AdminAccessError::Conflict)?;
        if value.state != AdminCredentialState::Active {
            return Err(AdminAccessError::Conflict);
        }
        let account = self
            .account_by_id(&value.binding.user_id)?
            .ok_or(AdminAccessError::Conflict)?;
        let auth = self.auth_state()?;
        credential
            .validate(
                value.kind,
                auth.mode,
                &account,
                auth.epoch,
                value.created_at,
            )
            .map_err(|_| AdminAccessError::Conflict)?;
        if self.credential_by_id(&value.id)?.is_some()
            || self
                .credential_by_digest(value.kind, &value.digest)?
                .is_some()
        {
            return Err(AdminAccessError::Conflict);
        }
        self.store.connection.execute("INSERT INTO admin_credentials
            (credential_id,kind,user_id,credential_revision,epoch,digest,created_at,expires_at,state,ended_at,label)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",params![
            value.id.as_str(),kind_text(value.kind),value.binding.user_id.as_str(),value.binding.credential_revision.value(),
            value.binding.epoch.bytes().as_slice(),value.digest.bytes().as_slice(),value.created_at,value.expires_at,
            credential_state_text(value.state),value.ended_at,value.label.as_ref().map(AdminTokenLabel::as_str)
        ]).map_err(unavailable)?;
        Ok(())
    }

    fn replace_credential(
        &mut self,
        expected: &AdminCredentialSnapshot,
        value: &AdminCredentialSnapshot,
    ) -> Result<(), AdminAccessError> {
        AdminCredential::from_snapshot(value.clone()).map_err(|_| AdminAccessError::Conflict)?;
        let current = self
            .credential_by_id(&expected.id)?
            .ok_or(AdminAccessError::Conflict)?
            .snapshot();
        validate_credential_replacement(&current, expected, value)?;
        self.store
            .connection
            .execute(
                "UPDATE admin_credentials SET state=?2,ended_at=?3
            WHERE credential_id=?1",
                params![
                    value.id.as_str(),
                    credential_state_text(value.state),
                    value.ended_at
                ],
            )
            .map_err(unavailable)?;
        Ok(())
    }

    fn append_identity_audit(&mut self, event: &AuditEvent) -> Result<(), AdminAccessError> {
        if event.category != AuditCategory::Security || event.value != AuditValue::Redacted {
            return Err(AdminAccessError::InvalidRequest);
        }
        self.store.insert_audit(event).map_err(unavailable)
    }
}

impl AdminIdentityRepository for SqliteStore {
    fn identity_transaction<T>(
        &mut self,
        work: impl FnOnce(&mut dyn AdminIdentityTransaction) -> Result<T, AdminAccessError>,
    ) -> Result<T, AdminAccessError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(unavailable)?;
        let mut adapter = SqliteIdentityTransaction { store: self };
        let value = work(&mut adapter)?;
        let auth = adapter.auth_state()?;
        let owners = adapter.loginable_owner_count()?;
        match auth.mode {
            AdminAuthMode::Personal if owners == 0 => return Err(AdminAccessError::LastOwner),
            AdminAuthMode::LegacyBootstrap => {
                let accounts: i64 = adapter
                    .store
                    .connection
                    .query_row("SELECT COUNT(*) FROM admin_accounts", [], |row| row.get(0))
                    .map_err(unavailable)?;
                if accounts != 0 {
                    return Err(AdminAccessError::Conflict);
                }
            }
            AdminAuthMode::LocalSetupRequired if owners != 0 => {
                return Err(AdminAccessError::Conflict);
            }
            _ => {}
        }
        transaction.commit().map_err(unavailable)?;
        Ok(value)
    }
}

fn validate_account_replacement(
    old: &AdminAccountSnapshot,
    expected: AdminRevision,
    value: &AdminAccountSnapshot,
) -> Result<(), AdminAccessError> {
    if old.record_revision != expected
        || old.username != value.username
        || value.record_revision <= expected
        || value.credential_revision < old.credential_revision
    {
        return Err(AdminAccessError::Conflict);
    }
    let security_change = old.role != value.role
        || old.status != value.status
        || old.password_verifier != value.password_verifier;
    if (security_change && value.credential_revision == old.credential_revision)
        || value.record_revision.value() - old.record_revision.value()
            < value.credential_revision.value() - old.credential_revision.value()
    {
        return Err(AdminAccessError::Conflict);
    }
    Ok(())
}

fn validate_credential_replacement(
    current: &AdminCredentialSnapshot,
    expected: &AdminCredentialSnapshot,
    value: &AdminCredentialSnapshot,
) -> Result<(), AdminAccessError> {
    let mut lifecycle = expected.clone();
    lifecycle.state = value.state;
    lifecycle.ended_at = value.ended_at;
    if current != expected
        || lifecycle != *value
        || (current.state != AdminCredentialState::Active && current != value)
    {
        return Err(AdminAccessError::Conflict);
    }
    Ok(())
}

#[cfg(test)]
#[path = "admin_identity_tests.rs"]
mod tests;
