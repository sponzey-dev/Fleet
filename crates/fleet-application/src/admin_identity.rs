//! Human identity use cases; persistence, password work and local authority are explicit ports.

use fleet_domain::{
    AdminAccount, AdminAccountError, AdminAccountSnapshot, AdminAccountStatus, AdminAuthMode,
    AdminCredential, AdminCredentialBinding, AdminCredentialDigest, AdminCredentialId,
    AdminCredentialKind, AdminCredentialSnapshot, AdminDisplayName, AdminIdentityError,
    AdminPasswordVerifier, AdminPermission, AdminRevision, AdminRole, AdminUserId, AdminUsername,
    AuditActor, AuditEvent, HumanAuthEpoch,
};
use std::fmt::{Debug, Display, Formatter};
use std::time::{Duration, SystemTime};

#[path = "admin_auth.rs"]
mod auth;
pub use auth::*;
#[path = "admin_account_query.rs"]
mod account_query;
pub use account_query::*;
#[path = "admin_write.rs"]
mod write;
pub(crate) use write::OrderedAdminOperation;
pub use write::{AdminMutationPrincipal, AdminWriteRead, AuthorizeAdminWrite};

/// Publicly classifiable failures; adapter errors and credential material never cross this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAccessError {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    UserExists,
    LastOwner,
    Conflict,
    Limit,
    Busy,
    Unavailable,
    OperationExpired,
}

impl Display for AdminAccessError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "invalid administrator identity request",
            Self::Unauthorized => "administrator authentication required",
            Self::Forbidden => "administrator operation forbidden",
            Self::NotFound => "administrator identity resource not found",
            Self::UserExists => "administrator username already exists",
            Self::LastOwner => "the last active owner must remain available",
            Self::Conflict => "administrator identity state conflict",
            Self::Limit => "administrator credential limit reached",
            Self::Busy => "administrator authentication capacity exceeded",
            Self::Unavailable => "administrator identity service unavailable",
            Self::OperationExpired => "administrator operation expired or cancelled",
        })
    }
}

impl std::error::Error for AdminAccessError {}

impl From<AdminAccountError> for AdminAccessError {
    fn from(error: AdminAccountError) -> Self {
        match error {
            AdminAccountError::LastOwner => Self::LastOwner,
            AdminAccountError::DisabledAccount | AdminAccountError::RevisionExhausted => {
                Self::Conflict
            }
            AdminAccountError::InvalidRevision | AdminAccountError::InvalidSnapshot => {
                Self::Unavailable
            }
        }
    }
}

impl From<AdminIdentityError> for AdminAccessError {
    fn from(_: AdminIdentityError) -> Self {
        Self::InvalidRequest
    }
}

/// Human authentication mode and restore generation, independent of Agent delivery state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminAuthState {
    pub mode: AdminAuthMode,
    pub epoch: HumanAuthEpoch,
}

/// Identity metadata only. Verifiers and credential lookup material have no public projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAccountSummary {
    pub id: AdminUserId,
    pub username: AdminUsername,
    pub display_name: AdminDisplayName,
    pub role: AdminRole,
    pub status: AdminAccountStatus,
    pub record_revision: AdminRevision,
}

impl From<&AdminAccount> for AdminAccountSummary {
    fn from(account: &AdminAccount) -> Self {
        let account = account.snapshot();
        Self {
            id: account.id,
            username: account.username,
            display_name: account.display_name,
            role: account.role,
            status: account.status,
            record_revision: account.record_revision,
        }
    }
}

/// Canonical identity reads. Restored corrupt records must fail rather than become active accounts.
pub trait AdminIdentityRead {
    /// Applies owner and PAT purpose scope before semantic decoding. Foreign/corrupt foreign
    /// rows must remain indistinguishable from missing resources to a self-service caller.
    fn own_personal_token(
        &self,
        owner: &AdminUserId,
        id: &AdminCredentialId,
    ) -> Result<Option<AdminCredential>, AdminAccessError>;
    fn auth_state(&self) -> Result<AdminAuthState, AdminAccessError>;
    fn account_by_id(&self, id: &AdminUserId) -> Result<Option<AdminAccount>, AdminAccessError>;
    fn account_by_username(
        &self,
        username: &AdminUsername,
    ) -> Result<Option<AdminAccount>, AdminAccessError>;
    fn loginable_owner_count(&self) -> Result<usize, AdminAccessError>;
    fn credential_by_id(
        &self,
        id: &AdminCredentialId,
    ) -> Result<Option<AdminCredential>, AdminAccessError>;
    fn credential_by_digest(
        &self,
        kind: AdminCredentialKind,
        digest: &AdminCredentialDigest,
    ) -> Result<Option<AdminCredential>, AdminAccessError>;
}

/// Writes are available only during an exclusive, rollback-capable identity transaction.
///
/// Implementations must serialize owner counts, mode, account and credential changes
/// with other protected canonical writes. Any operation or audit failure rolls back
/// every effect. Replace methods reject stale revisions; audit is append-only.
pub trait AdminIdentityTransaction: AdminIdentityRead {
    /// Counts current-valid user credentials separately from all remaining physical lookup rows.
    /// WebSession/PersonalToken only; the surrounding transaction serializes admission.
    fn credential_counts(
        &self,
        kind: AdminCredentialKind,
        user: &AdminUserId,
        now: i64,
    ) -> Result<AdminCredentialCounts, AdminAccessError>;
    /// Removes at most limit retired lookup rows of this kind (1..=128). Retirement includes
    /// revocation, expiry, stale epoch/revision and unusable account/mode. Future-created but
    /// otherwise current rows are retained. Never deletes accounts or audit history.
    fn cleanup_retired_credentials(
        &mut self,
        kind: AdminCredentialKind,
        now: i64,
        limit: usize,
    ) -> Result<usize, AdminAccessError>;
    fn insert_account(&mut self, account: &AdminAccountSnapshot) -> Result<(), AdminAccessError>;
    fn replace_account(
        &mut self,
        expected_revision: AdminRevision,
        account: &AdminAccountSnapshot,
    ) -> Result<(), AdminAccessError>;
    fn set_auth_state(
        &mut self,
        expected: AdminAuthState,
        state: AdminAuthState,
    ) -> Result<(), AdminAccessError>;
    fn revoke_user_credentials(
        &mut self,
        user_id: &AdminUserId,
        now: i64,
    ) -> Result<(), AdminAccessError>;
    fn insert_credential(
        &mut self,
        credential: &AdminCredentialSnapshot,
    ) -> Result<(), AdminAccessError>;
    /// Only lifecycle fields may change; identity, purpose, binding, digest and lifetime are immutable.
    fn replace_credential(
        &mut self,
        expected: &AdminCredentialSnapshot,
        credential: &AdminCredentialSnapshot,
    ) -> Result<(), AdminAccessError>;
    fn append_identity_audit(&mut self, event: &AuditEvent) -> Result<(), AdminAccessError>;
}

/// Admission projection from the same serialized transaction as credential issuance.
/// Physical rows include retired bindings that bounded cleanup has not reached yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminCredentialCounts {
    pub valid_for_user: usize,
    pub total_rows: usize,
}

/// Maximum ephemeral lookup rows reclaimed per purpose and invocation; account/audit rows remain.
pub const ADMIN_LOOKUP_CLEANUP_LIMIT: usize = 128;

/// Opens one atomic write boundary; no sequential or best-effort fallback is permitted.
pub trait AdminIdentityRepository: AdminIdentityRead {
    fn identity_transaction<T>(
        &mut self,
        work: impl FnOnce(&mut dyn AdminIdentityTransaction) -> Result<T, AdminAccessError>,
    ) -> Result<T, AdminAccessError>;
}

/// Normalizes, rejects weak/bounded input, then derives the selected verifier profile.
/// Calls may be expensive and must run outside repository transactions.
pub trait AdminPasswordPort {
    fn hash_new(
        &self,
        input: &str,
        username: &AdminUsername,
    ) -> Result<AdminPasswordVerifier, AdminAccessError>;
    /// Uses the fixed profile; None performs an equivalent dummy KDF and returns false.
    fn verify(
        &self,
        input: &str,
        verifier: Option<&AdminPasswordVerifier>,
    ) -> Result<bool, AdminAccessError>;
}

/// Generates collision-resistant IDs from trusted adapter entropy, never from request actors.
pub trait AdminIdentityGenerator {
    fn user_id(&self) -> Result<AdminUserId, AdminAccessError>;
    /// Generates a fresh 256-bit secret, purpose-bound digest and unrelated random record ID.
    fn credential(&self, kind: AdminCredentialKind)
    -> Result<AdminNewCredential, AdminAccessError>;
}

/// Generates a human-only restore generation from trusted adapter entropy.
/// This never supplies Agent delivery, signing or TLS identity material.
pub trait HumanAuthEpochGenerator {
    fn fresh_epoch(&self) -> Result<HumanAuthEpoch, AdminAccessError>;
}

/// Trusted local composition proves OS data-directory authority and a held exclusive lifetime lock.
/// No remote request value can provide this capability.
pub trait AdminLocalAuthority {
    fn require_exclusive(&self) -> Result<AuditActor, AdminAccessError>;
}

/// Supplies UTC seconds only while the operation is uncancelled and before its fixed deadline.
/// Adapters recheck cancellation/deadline on every call; late KDF results have no write authority.
pub trait AdminOperation {
    fn checked_now(&self) -> Result<i64, AdminAccessError>;
}

pub struct InitializeOwnerInput<'a> {
    pub username: AdminUsername,
    pub display_name: AdminDisplayName,
    pub new_password: &'a str,
}

impl Debug for InitializeOwnerInput<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitializeOwnerInput")
            .field("username", &self.username)
            .field("display_name", &self.display_name)
            .field("new_password", &"[REDACTED]")
            .finish()
    }
}

pub struct RecoverOwnerInput<'a> {
    pub user_id: AdminUserId,
    pub new_password: &'a str,
}

impl Debug for RecoverOwnerInput<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoverOwnerInput")
            .field("user_id", &self.user_id)
            .field("new_password", &"[REDACTED]")
            .finish()
    }
}

/// Installs the first loginable owner and ends legacy access in the same canonical commit.
pub struct InitializeAdminOwner;

impl InitializeAdminOwner {
    pub fn execute<R: AdminIdentityRepository>(
        repository: &mut R,
        authority: &dyn AdminLocalAuthority,
        operation: &dyn AdminOperation,
        passwords: &dyn AdminPasswordPort,
        generator: &dyn AdminIdentityGenerator,
        input: InitializeOwnerInput<'_>,
    ) -> Result<AdminAccountSummary, AdminAccessError> {
        authority.require_exclusive()?;
        checked_now(operation)?;
        let observed = repository.auth_state()?;
        if observed.mode == AdminAuthMode::Personal {
            return Err(AdminAccessError::Conflict);
        }
        if repository.account_by_username(&input.username)?.is_some() {
            return Err(AdminAccessError::UserExists);
        }
        let verifier = passwords.hash_new(input.new_password, &input.username)?;
        let mut account = AdminAccount::pending(
            generator.user_id()?,
            input.username,
            input.display_name,
            AdminRole::Owner,
        );
        account.install_password(verifier)?;
        repository.identity_transaction(|transaction| {
            let actor = authority.require_exclusive()?;
            let now = checked_now(operation)?;
            if transaction.auth_state()? != observed || transaction.loginable_owner_count()? > 0 {
                return Err(AdminAccessError::Conflict);
            }
            transaction.insert_account(&account.snapshot())?;
            transaction.set_auth_state(
                observed,
                AdminAuthState {
                    mode: AdminAuthMode::Personal,
                    epoch: observed.epoch,
                },
            )?;
            transaction.append_identity_audit(&identity_audit(
                "admin_owner_initialized",
                actor,
                &account.snapshot().id,
                now,
            )?)?;
            checked_now(operation)?;
            Ok(AdminAccountSummary::from(&account))
        })
    }
}

/// Restores one person's owner access without altering Agent identity or another person's account.
pub struct RecoverAdminOwner;

impl RecoverAdminOwner {
    pub fn execute<R: AdminIdentityRepository>(
        repository: &mut R,
        authority: &dyn AdminLocalAuthority,
        operation: &dyn AdminOperation,
        passwords: &dyn AdminPasswordPort,
        input: RecoverOwnerInput<'_>,
    ) -> Result<AdminAccountSummary, AdminAccessError> {
        authority.require_exclusive()?;
        checked_now(operation)?;
        let observed_auth = repository.auth_state()?;
        if observed_auth.mode == AdminAuthMode::LegacyBootstrap {
            return Err(AdminAccessError::Conflict);
        }
        let observed = repository
            .account_by_id(&input.user_id)?
            .ok_or(AdminAccessError::NotFound)?
            .snapshot();
        let verifier = passwords.hash_new(input.new_password, &observed.username)?;
        repository.identity_transaction(|transaction| {
            let actor = authority.require_exclusive()?;
            let now = checked_now(operation)?;
            let mut account = transaction
                .account_by_id(&input.user_id)?
                .ok_or(AdminAccessError::Conflict)?;
            if transaction.auth_state()? != observed_auth
                || account.snapshot().record_revision != observed.record_revision
            {
                return Err(AdminAccessError::Conflict);
            }
            account.recover_owner(verifier)?;
            transaction.replace_account(observed.record_revision, &account.snapshot())?;
            transaction.revoke_user_credentials(&input.user_id, now)?;
            auth::cleanup_lookups(transaction, now)?;
            transaction.set_auth_state(
                observed_auth,
                AdminAuthState {
                    mode: AdminAuthMode::Personal,
                    epoch: observed_auth.epoch,
                },
            )?;
            transaction.append_identity_audit(&identity_audit(
                "admin_owner_recovered",
                actor,
                &input.user_id,
                now,
            )?)?;
            checked_now(operation)?;
            Ok(AdminAccountSummary::from(&account))
        })
    }
}

/// Invalidates every restored human credential without rewriting accounts or credential history.
///
/// The caller owns a verified, offline restore candidate and the local target lease.
/// Rotation plus its audit is atomic; file replacement and the independent Agent
/// delivery-epoch rotation remain the restore adapter's responsibility.
pub struct InvalidateAdminCredentialsAfterRestore;

impl InvalidateAdminCredentialsAfterRestore {
    pub fn execute<R: AdminIdentityRepository>(
        repository: &mut R,
        authority: &dyn AdminLocalAuthority,
        operation: &dyn AdminOperation,
        generator: &dyn HumanAuthEpochGenerator,
    ) -> Result<AdminAuthMode, AdminAccessError> {
        authority.require_exclusive()?;
        checked_now(operation)?;
        let observed = repository.auth_state()?;
        let epoch = generator.fresh_epoch()?;
        if epoch == observed.epoch {
            return Err(AdminAccessError::Unavailable);
        }
        checked_now(operation)?;
        repository.identity_transaction(|transaction| {
            let actor = authority.require_exclusive()?;
            let now = checked_now(operation)?;
            if transaction.auth_state()? != observed {
                return Err(AdminAccessError::Conflict);
            }
            let mode = AdminAuthMode::after_restore(transaction.loginable_owner_count()? > 0);
            transaction.set_auth_state(observed, AdminAuthState { mode, epoch })?;
            let mut event =
                AuditEvent::security("admin_credentials_invalidated_after_restore", "human-auth");
            event.actor = actor;
            event.occurred_at = SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(now as u64))
                .ok_or(AdminAccessError::InvalidRequest)?;
            transaction.append_identity_audit(&event)?;
            checked_now(operation)?;
            Ok(mode)
        })
    }
}

/// Short-lived delivery material. Debug/Display are redacted; persistence accepts digests only.
pub struct AdminSecret(String);

impl AdminSecret {
    /// Trusted generator boundary; syntax bounds do not replace its CSPRNG entropy contract.
    pub fn from_adapter(value: String) -> Result<Self, AdminAccessError> {
        if !(43..=256).contains(&value.len())
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(AdminAccessError::Unavailable);
        }
        Ok(Self(value))
    }

    /// One issuance response/cookie/local output only; never a log, audit or persisted configuration.
    pub fn expose_for_delivery(&self) -> &str {
        &self.0
    }
}

impl Debug for AdminSecret {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AdminSecret([REDACTED])")
    }
}

impl Display for AdminSecret {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("admin_secret")
    }
}

/// Adapter-generated material has no authority until its digest record commits.
#[derive(Debug)]
pub struct AdminNewCredential {
    pub id: AdminCredentialId,
    pub kind: AdminCredentialKind,
    pub digest: AdminCredentialDigest,
    pub secret: AdminSecret,
}

#[derive(Debug)]
pub struct IssuedAdminCredential {
    pub id: AdminCredentialId,
    pub kind: AdminCredentialKind,
    pub expires_at: i64,
    pub secret: AdminSecret,
}

/// Server-created context records the validated credential binding, never a claimed role or actor.
/// Protected writes must resolve it again within their canonical transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedAdmin {
    credential_id: AdminCredentialId,
    kind: AdminCredentialKind,
    binding: AdminCredentialBinding,
}

impl AuthenticatedAdmin {
    pub fn user_id(&self) -> &AdminUserId {
        &self.binding.user_id
    }

    pub fn credential_id(&self) -> &AdminCredentialId {
        &self.credential_id
    }

    pub fn credential_kind(&self) -> AdminCredentialKind {
        self.kind
    }
}

/// Accepts only purpose-specific digest lookup from the credential adapter.
pub struct AuthenticateAdminCredential;

impl AuthenticateAdminCredential {
    pub fn execute<R: AdminIdentityRead + ?Sized>(
        repository: &R,
        operation: &dyn AdminOperation,
        kind: AdminCredentialKind,
        digest: &AdminCredentialDigest,
    ) -> Result<AuthenticatedAdmin, AdminAccessError> {
        if kind.is_grant() {
            return Err(AdminAccessError::Unauthorized);
        }
        let now = checked_now(operation)?;
        let credential = repository
            .credential_by_digest(kind, digest)?
            .ok_or(AdminAccessError::Unauthorized)?;
        let snapshot = credential.snapshot();
        let account = repository
            .account_by_id(&snapshot.binding.user_id)?
            .ok_or(AdminAccessError::Unauthorized)?;
        let state = repository.auth_state()?;
        credential
            .validate(kind, state.mode, &account, state.epoch, now)
            .map_err(|_| AdminAccessError::Unauthorized)?;
        Ok(AuthenticatedAdmin {
            credential_id: snapshot.id,
            kind,
            binding: snapshot.binding,
        })
    }
}

pub struct CreateAdminAccountInput<'a> {
    pub username: AdminUsername,
    pub display_name: AdminDisplayName,
    pub role: AdminRole,
    pub current_password: &'a str,
}

impl Debug for CreateAdminAccountInput<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreateAdminAccountInput")
            .field("username", &self.username)
            .field("display_name", &self.display_name)
            .field("role", &self.role)
            .field("current_password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug)]
pub struct CreatedAdminAccount {
    pub account: AdminAccountSummary,
    pub setup: IssuedAdminCredential,
}

/// Owner-only creation keeps the account pending until a single-use password setup succeeds.
pub struct CreateAdminAccount;

impl CreateAdminAccount {
    pub fn execute<R: AdminIdentityRepository>(
        repository: &mut R,
        actor: &AuthenticatedAdmin,
        operation: &dyn AdminOperation,
        passwords: &dyn AdminPasswordPort,
        generator: &dyn AdminIdentityGenerator,
        input: CreateAdminAccountInput<'_>,
    ) -> Result<CreatedAdminAccount, AdminAccessError> {
        verify_current_password(
            repository,
            actor,
            operation,
            passwords,
            input.current_password,
            AdminPermission::AccountManage,
        )?;
        let account = AdminAccount::pending(
            generator.user_id()?,
            input.username,
            input.display_name,
            input.role,
        );
        let material = generator.credential(AdminCredentialKind::SetupGrant)?;
        if material.kind != AdminCredentialKind::SetupGrant {
            return Err(AdminAccessError::Unavailable);
        }
        repository.identity_transaction(|transaction| {
            let now = checked_now(operation)?;
            authorize_current(transaction, actor, AdminPermission::AccountManage, now)?;
            let state = transaction.auth_state()?;
            let credential = AdminCredential::issue(
                material.id.clone(),
                material.kind,
                material.digest,
                AdminCredentialBinding::for_account(&account, state.epoch),
                now,
            )
            .map_err(|_| AdminAccessError::InvalidRequest)?
            .snapshot();
            transaction.insert_account(&account.snapshot())?;
            transaction.insert_credential(&credential)?;
            auth::cleanup_lookups(transaction, now)?;
            transaction.append_identity_audit(&identity_audit(
                "admin_account_created",
                AuditActor::new(actor.user_id().as_str()),
                &account.snapshot().id,
                now,
            )?)?;
            checked_now(operation)?;
            Ok(CreatedAdminAccount {
                account: AdminAccountSummary::from(&account),
                setup: IssuedAdminCredential {
                    id: material.id,
                    kind: material.kind,
                    expires_at: credential.expires_at,
                    secret: material.secret,
                },
            })
        })
    }
}

pub struct ChangeAdminAccountInput<'a> {
    pub user_id: AdminUserId,
    pub display_name: Option<AdminDisplayName>,
    pub role: Option<AdminRole>,
    pub disable: bool,
    pub current_password: &'a str,
}

impl Debug for ChangeAdminAccountInput<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChangeAdminAccountInput")
            .field("user_id", &self.user_id)
            .field("display_name", &self.display_name)
            .field("role", &self.role)
            .field("disable", &self.disable)
            .field("current_password", &"[REDACTED]")
            .finish()
    }
}

/// Owner-only metadata/role/disable changes with a transactional last-loginable-owner guard.
pub struct ChangeAdminAccount;

impl ChangeAdminAccount {
    pub fn execute<R: AdminIdentityRepository>(
        repository: &mut R,
        actor: &AuthenticatedAdmin,
        operation: &dyn AdminOperation,
        passwords: &dyn AdminPasswordPort,
        input: ChangeAdminAccountInput<'_>,
    ) -> Result<AdminAccountSummary, AdminAccessError> {
        if input.display_name.is_none() && input.role.is_none() && !input.disable {
            return Err(AdminAccessError::InvalidRequest);
        }
        verify_current_password(
            repository,
            actor,
            operation,
            passwords,
            input.current_password,
            AdminPermission::AccountManage,
        )?;
        let observed = repository
            .account_by_id(&input.user_id)?
            .ok_or(AdminAccessError::NotFound)?
            .snapshot();
        repository.identity_transaction(|transaction| {
            let now = checked_now(operation)?;
            authorize_current(transaction, actor, AdminPermission::AccountManage, now)?;
            let mut account = transaction
                .account_by_id(&input.user_id)?
                .ok_or(AdminAccessError::Conflict)?;
            if account.snapshot().record_revision != observed.record_revision {
                return Err(AdminAccessError::Conflict);
            }
            let other_owners = other_owner_count(transaction, &account)?;
            if let Some(name) = input.display_name {
                account.rename(name)?;
            }
            if let Some(role) = input.role {
                account.change_role(role, other_owners)?;
            }
            if input.disable {
                account.disable(other_owners)?;
            }
            let updated = account.snapshot();
            if updated.record_revision == observed.record_revision {
                return Ok(AdminAccountSummary::from(&account));
            }
            transaction.replace_account(observed.record_revision, &updated)?;
            if updated.credential_revision != observed.credential_revision {
                transaction.revoke_user_credentials(&input.user_id, now)?;
                auth::cleanup_lookups(transaction, now)?;
            }
            transaction.append_identity_audit(&identity_audit(
                "admin_account_updated",
                AuditActor::new(actor.user_id().as_str()),
                &input.user_id,
                now,
            )?)?;
            checked_now(operation)?;
            Ok(AdminAccountSummary::from(&account))
        })
    }
}

pub struct ResetAdminPasswordInput<'a> {
    pub user_id: AdminUserId,
    pub current_password: &'a str,
}

impl Debug for ResetAdminPasswordInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResetAdminPasswordInput")
            .field("user_id", &self.user_id)
            .field("current_password", &"[REDACTED]")
            .finish()
    }
}

/// Revokes a target's old password and credentials before issuing its new one-time reset grant.
pub struct ResetAdminPassword;

impl ResetAdminPassword {
    pub fn execute<R: AdminIdentityRepository>(
        repository: &mut R,
        actor: &AuthenticatedAdmin,
        operation: &dyn AdminOperation,
        passwords: &dyn AdminPasswordPort,
        generator: &dyn AdminIdentityGenerator,
        input: ResetAdminPasswordInput<'_>,
    ) -> Result<IssuedAdminCredential, AdminAccessError> {
        verify_current_password(
            repository,
            actor,
            operation,
            passwords,
            input.current_password,
            AdminPermission::AccountManage,
        )?;
        let observed = repository
            .account_by_id(&input.user_id)?
            .ok_or(AdminAccessError::NotFound)?
            .snapshot();
        let material = generator.credential(AdminCredentialKind::ResetGrant)?;
        if material.kind != AdminCredentialKind::ResetGrant {
            return Err(AdminAccessError::Unavailable);
        }
        repository.identity_transaction(|tx| {
            let now = checked_now(operation)?;
            authorize_current(tx, actor, AdminPermission::AccountManage, now)?;
            let mut account = tx
                .account_by_id(&input.user_id)?
                .ok_or(AdminAccessError::Conflict)?;
            if account.snapshot().record_revision != observed.record_revision {
                return Err(AdminAccessError::Conflict);
            }
            account.begin_password_reset(other_owner_count(tx, &account)?)?;
            let state = tx.auth_state()?;
            let credential = AdminCredential::issue(
                material.id.clone(),
                material.kind,
                material.digest,
                AdminCredentialBinding::for_account(&account, state.epoch),
                now,
            )
            .map_err(|_| AdminAccessError::InvalidRequest)?
            .snapshot();
            tx.replace_account(observed.record_revision, &account.snapshot())?;
            tx.revoke_user_credentials(&input.user_id, now)?;
            auth::cleanup_lookups(tx, now)?;
            tx.insert_credential(&credential)?;
            tx.append_identity_audit(&identity_audit(
                "admin_password_reset_requested",
                AuditActor::new(actor.user_id().as_str()),
                &input.user_id,
                now,
            )?)?;
            checked_now(operation)?;
            Ok(IssuedAdminCredential {
                id: material.id,
                kind: material.kind,
                expires_at: credential.expires_at,
                secret: material.secret,
            })
        })
    }
}

pub struct CompleteAdminSetupInput<'a> {
    pub kind: AdminCredentialKind,
    pub digest: AdminCredentialDigest,
    pub new_password: &'a str,
}

impl Debug for CompleteAdminSetupInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompleteAdminSetupInput")
            .field("kind", &self.kind)
            .field("digest", &self.digest)
            .field("new_password", &"[REDACTED]")
            .finish()
    }
}

/// Claims a single-use setup/reset code without creating any login session or personal token.
pub struct CompleteAdminSetup;

impl CompleteAdminSetup {
    pub fn execute<R: AdminIdentityRepository>(
        repository: &mut R,
        operation: &dyn AdminOperation,
        passwords: &dyn AdminPasswordPort,
        input: CompleteAdminSetupInput<'_>,
    ) -> Result<(), AdminAccessError> {
        if !input.kind.is_grant() {
            return Err(AdminAccessError::Unauthorized);
        }
        let now = checked_now(operation)?;
        let grant = repository
            .credential_by_digest(input.kind, &input.digest)?
            .ok_or(AdminAccessError::Unauthorized)?;
        let observed = grant.snapshot();
        let account = repository
            .account_by_id(&observed.binding.user_id)?
            .ok_or(AdminAccessError::Unauthorized)?;
        let state = repository.auth_state()?;
        grant
            .validate(input.kind, state.mode, &account, state.epoch, now)
            .map_err(|_| AdminAccessError::Unauthorized)?;
        let verifier = passwords.hash_new(input.new_password, &account.snapshot().username)?;
        repository.identity_transaction(|tx| {
            let now = checked_now(operation)?;
            let mut current = tx
                .credential_by_id(&observed.id)?
                .ok_or(AdminAccessError::Unauthorized)?;
            if current.snapshot().binding != observed.binding {
                return Err(AdminAccessError::Unauthorized);
            }
            let before = current.snapshot();
            let mut account = tx
                .account_by_id(&observed.binding.user_id)?
                .ok_or(AdminAccessError::Unauthorized)?;
            let state = tx.auth_state()?;
            current
                .consume(input.kind, state.mode, &account, state.epoch, now)
                .map_err(|_| AdminAccessError::Unauthorized)?;
            let previous_revision = account.snapshot().record_revision;
            account.install_password(verifier)?;
            tx.replace_credential(&before, &current.snapshot())?;
            tx.replace_account(previous_revision, &account.snapshot())?;
            tx.revoke_user_credentials(&observed.binding.user_id, now)?;
            auth::cleanup_lookups(tx, now)?;
            let action = match input.kind {
                AdminCredentialKind::SetupGrant => "admin_password_setup_completed",
                AdminCredentialKind::ResetGrant => "admin_password_reset_completed",
                _ => return Err(AdminAccessError::Unauthorized),
            };
            tx.append_identity_audit(&identity_audit(
                action,
                AuditActor::new(observed.binding.user_id.as_str()),
                &observed.binding.user_id,
                now,
            )?)?;
            checked_now(operation)?;
            Ok(())
        })
    }
}

pub struct ChangeOwnAdminPasswordInput<'a> {
    pub current_password: &'a str,
    pub new_password: &'a str,
}

impl Debug for ChangeOwnAdminPasswordInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangeOwnAdminPasswordInput")
            .field("current_password", &"[REDACTED]")
            .field("new_password", &"[REDACTED]")
            .finish()
    }
}

/// Changes only the authenticated person's password, keeping the account active and revoking all credentials.
pub struct ChangeOwnAdminPassword;

impl ChangeOwnAdminPassword {
    pub fn execute<R: AdminIdentityRepository>(
        repository: &mut R,
        actor: &AuthenticatedAdmin,
        operation: &dyn AdminOperation,
        passwords: &dyn AdminPasswordPort,
        input: ChangeOwnAdminPasswordInput<'_>,
    ) -> Result<(), AdminAccessError> {
        let observed = verify_current_password(
            repository,
            actor,
            operation,
            passwords,
            input.current_password,
            AdminPermission::SelfCredentialManage,
        )?;
        let verifier = passwords.hash_new(input.new_password, &observed.snapshot().username)?;
        repository.identity_transaction(|tx| {
            let now = checked_now(operation)?;
            let mut account =
                authorize_current(tx, actor, AdminPermission::SelfCredentialManage, now)?;
            let previous_revision = account.snapshot().record_revision;
            account.install_password(verifier)?;
            tx.replace_account(previous_revision, &account.snapshot())?;
            tx.revoke_user_credentials(actor.user_id(), now)?;
            auth::cleanup_lookups(tx, now)?;
            tx.append_identity_audit(&identity_audit(
                "admin_password_changed",
                AuditActor::new(actor.user_id().as_str()),
                actor.user_id(),
                now,
            )?)?;
            checked_now(operation)?;
            Ok(())
        })
    }
}

fn authorize_current<R: AdminIdentityRead + ?Sized>(
    repository: &R,
    actor: &AuthenticatedAdmin,
    permission: AdminPermission,
    now: i64,
) -> Result<AdminAccount, AdminAccessError> {
    let credential = repository
        .credential_by_id(&actor.credential_id)?
        .ok_or(AdminAccessError::Unauthorized)?;
    if credential.snapshot().binding != actor.binding {
        return Err(AdminAccessError::Unauthorized);
    }
    let account = repository
        .account_by_id(actor.user_id())?
        .ok_or(AdminAccessError::Unauthorized)?;
    let state = repository.auth_state()?;
    credential
        .validate(actor.kind, state.mode, &account, state.epoch, now)
        .map_err(|_| AdminAccessError::Unauthorized)?;
    if !account.snapshot().role.allows(permission) {
        return Err(AdminAccessError::Forbidden);
    }
    Ok(account)
}

fn verify_current_password<R: AdminIdentityRead + ?Sized>(
    repository: &R,
    actor: &AuthenticatedAdmin,
    operation: &dyn AdminOperation,
    passwords: &dyn AdminPasswordPort,
    input: &str,
    permission: AdminPermission,
) -> Result<AdminAccount, AdminAccessError> {
    let account = authorize_current(repository, actor, permission, checked_now(operation)?)?;
    if !passwords.verify(input, account.snapshot().password_verifier.as_ref())? {
        return Err(AdminAccessError::Unauthorized);
    }
    Ok(account)
}

fn other_owner_count<R: AdminIdentityRead + ?Sized>(
    repository: &R,
    account: &AdminAccount,
) -> Result<usize, AdminAccessError> {
    let includes_self = account.is_loginable() && account.snapshot().role == AdminRole::Owner;
    repository
        .loginable_owner_count()?
        .checked_sub(usize::from(includes_self))
        .ok_or(AdminAccessError::Unavailable)
}

fn checked_now(operation: &dyn AdminOperation) -> Result<i64, AdminAccessError> {
    let now = operation.checked_now()?;
    if now < 0 {
        return Err(AdminAccessError::OperationExpired);
    }
    Ok(now)
}

fn identity_audit(
    action: &'static str,
    actor: AuditActor,
    user: &AdminUserId,
    now: i64,
) -> Result<AuditEvent, AdminAccessError> {
    let mut event = AuditEvent::security(action, user.as_str());
    event.actor = actor;
    event.occurred_at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(now as u64))
        .ok_or(AdminAccessError::InvalidRequest)?;
    Ok(event)
}

#[cfg(test)]
#[path = "admin_identity_tests.rs"]
mod tests;
