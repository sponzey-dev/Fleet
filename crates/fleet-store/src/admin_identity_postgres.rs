//! Feature-gated PostgreSQL human identity adapter with one canonical authentication-row write lock.

use super::{
    ACCOUNT_COLUMNS, AccountRow, CLEANUP_RETIRED_LOOKUPS_SQL, CREDENTIAL_COUNTS_SQL, CredentialRow,
    PERSONAL_TOKEN_PAGE_SQL, account_page_query, auth_from_parts, credential_state_text, kind_text,
    mode_text, role_text, status_text, unavailable, validate_account_replacement,
    validate_credential_replacement,
};
use crate::{PostgresStore, StoreError, postgres_insert_audit_in_transaction};
use ::postgres::{
    Client, GenericClient, Transaction, fallible_iterator::FallibleIterator, types::ToSql,
};
use fleet_application::admin_identity::{
    ADMIN_LOOKUP_CLEANUP_LIMIT, AdminAccessError, AdminAccountQuery, AdminAuthState,
    AdminCredentialCounts, AdminIdentityRead, AdminIdentityRepository, AdminIdentityTransaction,
    AdminPersonalTokenQuery, AdminWriteRead,
};
use fleet_domain::{
    AdminAccount, AdminAccountSnapshot, AdminAuthMode, AdminCredential, AdminCredentialDigest,
    AdminCredentialId, AdminCredentialKind, AdminCredentialSnapshot, AdminCredentialState,
    AdminPasswordVerifier, AdminRevision, AdminTokenLabel, AdminUserId, AdminUsername,
    AuditCategory, AuditEvent, AuditValue,
};
use std::cell::RefCell;

const IDENTITY_SCHEMA: &str = r#"
CREATE TABLE admin_auth_state (
    id BIGINT PRIMARY KEY CHECK(id=1),
    mode TEXT NOT NULL CHECK(mode IN ('legacy_bootstrap','personal','local_setup_required')),
    epoch BYTEA NOT NULL CHECK(octet_length(epoch)=16)
);
CREATE TABLE admin_accounts (
    user_id TEXT PRIMARY KEY CHECK(user_id ~ '^usr_[0-9a-f]{32}$'),
    username TEXT NOT NULL UNIQUE CHECK(username ~ '^[a-z0-9][a-z0-9_.-]{2,63}$'),
    display_name TEXT NOT NULL CHECK(char_length(display_name) BETWEEN 1 AND 120 AND octet_length(display_name)<=480),
    role TEXT NOT NULL CHECK(role IN ('owner','admin','operator','viewer')),
    status TEXT NOT NULL CHECK(status IN ('pending_setup','active','disabled')),
    record_revision BIGINT NOT NULL CHECK(record_revision>=0),
    credential_revision BIGINT NOT NULL CHECK(credential_revision>=0 AND credential_revision<=record_revision),
    password_profile TEXT,
    password_salt BYTEA,
    password_hash BYTEA,
    CHECK((password_profile IS NULL AND password_salt IS NULL AND password_hash IS NULL AND status<>'active')
        OR (password_profile IS NOT NULL AND password_profile='argon2id-v19-m19456-t2-p1'
            AND password_salt IS NOT NULL AND octet_length(password_salt)=16
            AND password_hash IS NOT NULL AND octet_length(password_hash)=32 AND status<>'pending_setup'))
);
CREATE TABLE admin_credentials (
    credential_id TEXT PRIMARY KEY CHECK(credential_id ~ '^crd_[0-9a-f]{32}$'),
    kind TEXT NOT NULL CHECK(kind IN ('web_session','personal_token','setup_grant','reset_grant')),
    user_id TEXT NOT NULL REFERENCES admin_accounts(user_id) ON DELETE RESTRICT,
    credential_revision BIGINT NOT NULL CHECK(credential_revision>=0),
    epoch BYTEA NOT NULL CHECK(octet_length(epoch)=16),
    digest BYTEA NOT NULL CHECK(octet_length(digest)=32),
    created_at BIGINT NOT NULL CHECK(created_at>=0),
    expires_at BIGINT NOT NULL CHECK(expires_at>created_at AND expires_at-created_at=
        CASE kind WHEN 'web_session' THEN 28800 WHEN 'personal_token' THEN 2592000 ELSE 900 END),
    state TEXT NOT NULL CHECK(state IN ('active','revoked','consumed')),
    ended_at BIGINT,
    label TEXT CHECK(label IS NULL OR octet_length(label)<=256),
    UNIQUE(kind,digest),
    CHECK((state='active' AND ended_at IS NULL)
        OR (state='revoked' AND ended_at IS NOT NULL AND ended_at>=created_at)
        OR (state='consumed' AND kind IN ('setup_grant','reset_grant')
            AND ended_at IS NOT NULL AND ended_at>=created_at AND ended_at<expires_at))
);
"#;

fn schema_unavailable(_: impl std::fmt::Debug) -> StoreError {
    StoreError::Postgres("postgres administrator identity schema unavailable".into())
}

/// Commits the new identity schema, epoch and version marker together, without repairing v28 corruption.
pub(crate) fn migrate_postgres(
    client: &mut Client,
    previous: Option<i64>,
) -> Result<(), StoreError> {
    if previous.is_some_and(|version| version >= 28) {
        let row=client.query_one("SELECT to_regclass('admin_auth_state') IS NOT NULL
            AND to_regclass('admin_accounts') IS NOT NULL AND to_regclass('admin_credentials') IS NOT NULL",&[]).map_err(schema_unavailable)?;
        if !row.try_get::<_, bool>(0).map_err(schema_unavailable)? {
            return Err(schema_unavailable(()));
        }
        pg_auth(client).map_err(schema_unavailable)?;
        return Ok(());
    }
    let mut transaction = client.transaction().map_err(schema_unavailable)?;
    transaction
        .batch_execute(IDENTITY_SCHEMA)
        .map_err(schema_unavailable)?;
    let mut epoch = [0u8; 16];
    getrandom::getrandom(&mut epoch).map_err(schema_unavailable)?;
    transaction
        .execute(
            "INSERT INTO admin_auth_state(id,mode,epoch) VALUES(1,'legacy_bootstrap',$1)",
            &[&epoch.as_slice()],
        )
        .map_err(schema_unavailable)?;
    transaction.execute("INSERT INTO schema_migrations(name,version,applied_at)
        VALUES('fleet_store',28,EXTRACT(EPOCH FROM now())::BIGINT)
        ON CONFLICT(name) DO UPDATE SET version=EXCLUDED.version, applied_at=CASE
            WHEN schema_migrations.version=EXCLUDED.version THEN schema_migrations.applied_at ELSE EXCLUDED.applied_at END",&[]).map_err(schema_unavailable)?;
    transaction.commit().map_err(schema_unavailable)
}

pub(crate) fn require_legacy_postgres(client: &mut Client) -> Result<(), StoreError> {
    if pg_auth(client).map_err(schema_unavailable)?.mode != AdminAuthMode::LegacyBootstrap {
        return Err(StoreError::Postgres(
            "legacy administrator access is disabled".into(),
        ));
    }
    Ok(())
}

fn pg_auth<C: GenericClient>(client: &mut C) -> Result<AdminAuthState, AdminAccessError> {
    let row = client
        .query_opt("SELECT mode,epoch FROM admin_auth_state WHERE id=1", &[])
        .map_err(unavailable)?
        .ok_or(AdminAccessError::Unavailable)?;
    let mode: String = row.try_get(0).map_err(unavailable)?;
    let epoch: Vec<u8> = row.try_get(1).map_err(unavailable)?;
    auth_from_parts(&mode, epoch)
}

fn pg_account_row(row: &::postgres::Row) -> Result<AccountRow, AdminAccessError> {
    Ok(AccountRow {
        id: row.try_get(0).map_err(unavailable)?,
        username: row.try_get(1).map_err(unavailable)?,
        display_name: row.try_get(2).map_err(unavailable)?,
        role: row.try_get(3).map_err(unavailable)?,
        status: row.try_get(4).map_err(unavailable)?,
        record_revision: row.try_get(5).map_err(unavailable)?,
        credential_revision: row.try_get(6).map_err(unavailable)?,
        profile: row.try_get(7).map_err(unavailable)?,
        salt: row.try_get(8).map_err(unavailable)?,
        hash: row.try_get(9).map_err(unavailable)?,
    })
}

fn pg_account<C: GenericClient>(
    client: &mut C,
    column: &'static str,
    value: &str,
) -> Result<Option<AdminAccount>, AdminAccessError> {
    let sql = format!("SELECT {ACCOUNT_COLUMNS} FROM admin_accounts WHERE {column}=$1");
    client
        .query_opt(sql.as_str(), &[&value])
        .map_err(unavailable)?
        .map(|row| pg_account_row(&row)?.into_domain())
        .transpose()
}

fn pg_owner_count<C: GenericClient>(client: &mut C) -> Result<usize, AdminAccessError> {
    let sql = format!(
        "SELECT {ACCOUNT_COLUMNS} FROM admin_accounts WHERE role='owner' AND status='active'"
    );
    let parameters: [&(dyn ToSql + Sync); 0] = [];
    let mut rows = client
        .query_raw(sql.as_str(), parameters)
        .map_err(unavailable)?;
    let mut count = 0usize;
    while let Some(row) = rows.next().map_err(unavailable)? {
        let account = pg_account_row(&row)?.into_domain()?;
        if !account.is_loginable() {
            return Err(AdminAccessError::Unavailable);
        }
        count = count.checked_add(1).ok_or(AdminAccessError::Unavailable)?;
    }
    Ok(count)
}

fn pg_credential<C: GenericClient>(
    client: &mut C,
    condition: &'static str,
    parameters: &[&(dyn ToSql + Sync)],
) -> Result<Option<AdminCredential>, AdminAccessError> {
    let sql=format!("SELECT credential_id,kind,user_id,credential_revision,epoch,digest,created_at,expires_at,state,ended_at,label
        FROM admin_credentials WHERE {condition}");
    client
        .query_opt(sql.as_str(), parameters)
        .map_err(unavailable)?
        .map(|row| pg_credential_row(&row)?.into_domain())
        .transpose()
}

fn pg_credential_row(row: &::postgres::Row) -> Result<CredentialRow, AdminAccessError> {
    Ok(CredentialRow {
        id: row.try_get(0).map_err(unavailable)?,
        kind: row.try_get(1).map_err(unavailable)?,
        user_id: row.try_get(2).map_err(unavailable)?,
        revision: row.try_get(3).map_err(unavailable)?,
        epoch: row.try_get(4).map_err(unavailable)?,
        digest: row.try_get(5).map_err(unavailable)?,
        created_at: row.try_get(6).map_err(unavailable)?,
        expires_at: row.try_get(7).map_err(unavailable)?,
        state: row.try_get(8).map_err(unavailable)?,
        ended_at: row.try_get(9).map_err(unavailable)?,
        label: row.try_get(10).map_err(unavailable)?,
    })
}

impl AdminAccountQuery for PostgresStore {
    fn account_page(
        &self,
        after: Option<&AdminUserId>,
        limit: usize,
    ) -> Result<Vec<AdminAccount>, AdminAccessError> {
        if !(1..=101).contains(&limit) {
            return Err(AdminAccessError::InvalidRequest);
        }
        let limit = i64::try_from(limit).map_err(unavailable)?;
        self.checkout_client()
            .map_err(unavailable)?
            .query(
                account_page_query().as_str(),
                &[&after.map(AdminUserId::as_str), &limit],
            )
            .map_err(unavailable)?
            .iter()
            .map(|row| pg_account_row(row)?.into_domain())
            .collect()
    }
}

impl AdminPersonalTokenQuery for PostgresStore {
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
        self.checkout_client()
            .map_err(unavailable)?
            .query(
                PERSONAL_TOKEN_PAGE_SQL,
                &[
                    &owner.as_str(),
                    &after.map(AdminCredentialId::as_str),
                    &limit,
                ],
            )
            .map_err(unavailable)?
            .iter()
            .map(|row| pg_credential_row(row)?.into_domain())
            .collect()
    }
}

impl AdminIdentityRead for PostgresStore {
    fn own_personal_token(
        &self,
        owner: &AdminUserId,
        id: &AdminCredentialId,
    ) -> Result<Option<AdminCredential>, AdminAccessError> {
        pg_credential(
            &mut *self.checkout_client().map_err(unavailable)?,
            "credential_id=$1 AND user_id=$2 AND kind='personal_token'",
            &[&id.as_str(), &owner.as_str()],
        )
    }
    fn auth_state(&self) -> Result<AdminAuthState, AdminAccessError> {
        pg_auth(&mut *self.checkout_client().map_err(unavailable)?)
    }
    fn account_by_id(&self, id: &AdminUserId) -> Result<Option<AdminAccount>, AdminAccessError> {
        pg_account(
            &mut *self.checkout_client().map_err(unavailable)?,
            "user_id",
            id.as_str(),
        )
    }
    fn account_by_username(
        &self,
        name: &AdminUsername,
    ) -> Result<Option<AdminAccount>, AdminAccessError> {
        pg_account(
            &mut *self.checkout_client().map_err(unavailable)?,
            "username",
            name.as_str(),
        )
    }
    fn loginable_owner_count(&self) -> Result<usize, AdminAccessError> {
        pg_owner_count(&mut *self.checkout_client().map_err(unavailable)?)
    }
    fn credential_by_id(
        &self,
        id: &AdminCredentialId,
    ) -> Result<Option<AdminCredential>, AdminAccessError> {
        pg_credential(
            &mut *self.checkout_client().map_err(unavailable)?,
            "credential_id=$1",
            &[&id.as_str()],
        )
    }
    fn credential_by_digest(
        &self,
        kind: AdminCredentialKind,
        digest: &AdminCredentialDigest,
    ) -> Result<Option<AdminCredential>, AdminAccessError> {
        pg_credential(
            &mut *self.checkout_client().map_err(unavailable)?,
            "kind=$1 AND digest=$2",
            &[&kind_text(kind), &digest.bytes().as_slice()],
        )
    }
}

pub(crate) struct PgIdentityTransaction<'a> {
    pub(crate) transaction: RefCell<Transaction<'a>>,
}

impl<'a> PgIdentityTransaction<'a> {
    pub(crate) fn begin(mut transaction: Transaction<'a>) -> Result<Self, AdminAccessError> {
        if transaction
            .query_opt("SELECT id FROM admin_auth_state WHERE id=1 FOR UPDATE", &[])
            .map_err(unavailable)?
            .is_none()
        {
            return Err(AdminAccessError::Unavailable);
        }
        Ok(Self {
            transaction: RefCell::new(transaction),
        })
    }
}

impl AdminWriteRead for PgIdentityTransaction<'_> {
    fn legacy_admin_by_hash(
        &self,
        digest: &str,
    ) -> Result<Option<fleet_application::AdminTokenRecord>, AdminAccessError> {
        self.transaction
            .borrow_mut()
            .query_opt(
                "SELECT actor_id,role FROM admin_tokens WHERE id=1 AND token_hash=$1
            AND EXISTS(SELECT 1 FROM admin_auth_state WHERE id=1 AND mode='legacy_bootstrap') FOR SHARE",
                &[&digest],
            )
            .map_err(unavailable)?
            .map(|row| {
                Ok(fleet_application::AdminTokenRecord {
                    actor_id: row.try_get(0).map_err(unavailable)?,
                    role: row.try_get(1).map_err(unavailable)?,
                })
            })
            .transpose()
    }
}

impl AdminIdentityRead for PgIdentityTransaction<'_> {
    fn own_personal_token(
        &self,
        owner: &AdminUserId,
        id: &AdminCredentialId,
    ) -> Result<Option<AdminCredential>, AdminAccessError> {
        pg_credential(
            &mut *self.transaction.borrow_mut(),
            "credential_id=$1 AND user_id=$2 AND kind='personal_token'",
            &[&id.as_str(), &owner.as_str()],
        )
    }
    fn auth_state(&self) -> Result<AdminAuthState, AdminAccessError> {
        pg_auth(&mut *self.transaction.borrow_mut())
    }
    fn account_by_id(&self, id: &AdminUserId) -> Result<Option<AdminAccount>, AdminAccessError> {
        pg_account(&mut *self.transaction.borrow_mut(), "user_id", id.as_str())
    }
    fn account_by_username(
        &self,
        name: &AdminUsername,
    ) -> Result<Option<AdminAccount>, AdminAccessError> {
        pg_account(
            &mut *self.transaction.borrow_mut(),
            "username",
            name.as_str(),
        )
    }
    fn loginable_owner_count(&self) -> Result<usize, AdminAccessError> {
        pg_owner_count(&mut *self.transaction.borrow_mut())
    }
    fn credential_by_id(
        &self,
        id: &AdminCredentialId,
    ) -> Result<Option<AdminCredential>, AdminAccessError> {
        pg_credential(
            &mut *self.transaction.borrow_mut(),
            "credential_id=$1",
            &[&id.as_str()],
        )
    }
    fn credential_by_digest(
        &self,
        kind: AdminCredentialKind,
        digest: &AdminCredentialDigest,
    ) -> Result<Option<AdminCredential>, AdminAccessError> {
        pg_credential(
            &mut *self.transaction.borrow_mut(),
            "kind=$1 AND digest=$2",
            &[&kind_text(kind), &digest.bytes().as_slice()],
        )
    }
}

impl AdminIdentityTransaction for PgIdentityTransaction<'_> {
    fn credential_counts(
        &self,
        kind: AdminCredentialKind,
        user: &AdminUserId,
        now: i64,
    ) -> Result<AdminCredentialCounts, AdminAccessError> {
        if kind.is_grant() || now < 0 {
            return Err(AdminAccessError::InvalidRequest);
        }
        let row = self
            .transaction
            .borrow_mut()
            .query_one(
                CREDENTIAL_COUNTS_SQL,
                &[&kind_text(kind), &user.as_str(), &now],
            )
            .map_err(unavailable)?;
        let valid: i64 = row.try_get(0).map_err(unavailable)?;
        let total: i64 = row.try_get(1).map_err(unavailable)?;
        Ok(AdminCredentialCounts {
            valid_for_user: usize::try_from(valid).map_err(unavailable)?,
            total_rows: usize::try_from(total).map_err(unavailable)?,
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
        let deleted = self
            .transaction
            .borrow_mut()
            .execute(
                CLEANUP_RETIRED_LOOKUPS_SQL,
                &[&kind_text(kind), &now, &limit],
            )
            .map_err(unavailable)?;
        usize::try_from(deleted).map_err(unavailable)
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
        self.transaction.borrow_mut().execute("INSERT INTO admin_accounts
            (user_id,username,display_name,role,status,record_revision,credential_revision,password_profile,password_salt,password_hash)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",&[
            &value.id.as_str(),&value.username.as_str(),&value.display_name.as_str(),&role_text(value.role),&status_text(value.status),
            &value.record_revision.value(),&value.credential_revision.value(),&verifier.map(|_|AdminPasswordVerifier::PROFILE_ID),
            &verifier.map(|v|v.salt_bytes().as_slice()),&verifier.map(|v|v.hash_bytes().as_slice()),
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
        let changed=self.transaction.borrow_mut().execute("UPDATE admin_accounts SET display_name=$2,role=$3,status=$4,
            record_revision=$5,credential_revision=$6,password_profile=$7,password_salt=$8,password_hash=$9
            WHERE user_id=$1 AND record_revision=$10",&[
            &value.id.as_str(),&value.display_name.as_str(),&role_text(value.role),&status_text(value.status),
            &value.record_revision.value(),&value.credential_revision.value(),&verifier.map(|_|AdminPasswordVerifier::PROFILE_ID),
            &verifier.map(|v|v.salt_bytes().as_slice()),&verifier.map(|v|v.hash_bytes().as_slice()),&expected.value(),
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
            || (value.mode == AdminAuthMode::LegacyBootstrap && value.mode != expected.mode)
        {
            return Err(AdminAccessError::Conflict);
        }
        let changed = self
            .transaction
            .borrow_mut()
            .execute(
                "UPDATE admin_auth_state SET mode=$1,epoch=$2
            WHERE id=1 AND mode=$3 AND epoch=$4",
                &[
                    &mode_text(value.mode),
                    &value.epoch.bytes().as_slice(),
                    &mode_text(expected.mode),
                    &expected.epoch.bytes().as_slice(),
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
            .transaction
            .borrow_mut()
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM admin_credentials
            WHERE user_id=$1 AND state='active' AND created_at>$2)",
                &[&user.as_str(), &now],
            )
            .map_err(unavailable)?
            .try_get(0)
            .map_err(unavailable)?;
        if future {
            return Err(AdminAccessError::Conflict);
        }
        self.transaction
            .borrow_mut()
            .execute(
                "UPDATE admin_credentials SET state='revoked',ended_at=$2
            WHERE user_id=$1 AND state='active'",
                &[&user.as_str(), &now],
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
        self.transaction.borrow_mut().execute("INSERT INTO admin_credentials
            (credential_id,kind,user_id,credential_revision,epoch,digest,created_at,expires_at,state,ended_at,label)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",&[
            &value.id.as_str(),&kind_text(value.kind),&value.binding.user_id.as_str(),&value.binding.credential_revision.value(),
            &value.binding.epoch.bytes().as_slice(),&value.digest.bytes().as_slice(),&value.created_at,&value.expires_at,
            &credential_state_text(value.state),&value.ended_at,&value.label.as_ref().map(AdminTokenLabel::as_str),
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
        self.transaction
            .borrow_mut()
            .execute(
                "UPDATE admin_credentials SET state=$2,ended_at=$3 WHERE credential_id=$1",
                &[
                    &value.id.as_str(),
                    &credential_state_text(value.state),
                    &value.ended_at,
                ],
            )
            .map_err(unavailable)?;
        Ok(())
    }

    fn append_identity_audit(&mut self, event: &AuditEvent) -> Result<(), AdminAccessError> {
        if event.category != AuditCategory::Security || event.value != AuditValue::Redacted {
            return Err(AdminAccessError::InvalidRequest);
        }
        postgres_insert_audit_in_transaction(&mut self.transaction.borrow_mut(), event)
            .map_err(unavailable)
    }
}

impl AdminIdentityRepository for PostgresStore {
    fn identity_transaction<T>(
        &mut self,
        work: impl FnOnce(&mut dyn AdminIdentityTransaction) -> Result<T, AdminAccessError>,
    ) -> Result<T, AdminAccessError> {
        let mut client = self.checkout_client().map_err(unavailable)?;
        let transaction = client.transaction().map_err(unavailable)?;
        let mut adapter = PgIdentityTransaction::begin(transaction)?;
        let value = work(&mut adapter)?;
        let auth = adapter.auth_state()?;
        let owners = adapter.loginable_owner_count()?;
        match auth.mode {
            AdminAuthMode::Personal if owners == 0 => return Err(AdminAccessError::LastOwner),
            AdminAuthMode::LegacyBootstrap => {
                let accounts: i64 = adapter
                    .transaction
                    .borrow_mut()
                    .query_one("SELECT COUNT(*) FROM admin_accounts", &[])
                    .map_err(unavailable)?
                    .try_get(0)
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
        adapter
            .transaction
            .into_inner()
            .commit()
            .map_err(unavailable)?;
        Ok(value)
    }
}
