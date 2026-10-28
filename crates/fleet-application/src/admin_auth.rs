//! Human authentication and credential lifecycles. Password work and entropy are outside
//! the canonical write transaction; their results never replace a current binding check.

use super::*;

pub struct LoginAdminInput<'a> {
    pub username: &'a str,
    pub password: &'a str,
}

impl Debug for LoginAdminInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("LoginAdminInput([REDACTED])")
    }
}

/// Interface adapters deliver the secret only as a session cookie, never in a JSON view.
#[derive(Debug)]
pub struct AdminLogin {
    pub account: AdminAccountSummary,
    pub session: IssuedAdminCredential,
}

pub struct LoginAdmin;

impl LoginAdmin {
    /// Verifies a real or equivalent dummy password and rechecks the current account before
    /// issuing a fixed-lifetime session. Invalid identity/password states share Unauthorized.
    pub fn execute<R: AdminIdentityRepository>(
        repository: &mut R,
        operation: &dyn AdminOperation,
        passwords: &dyn AdminPasswordPort,
        generator: &dyn AdminIdentityGenerator,
        input: LoginAdminInput<'_>,
    ) -> Result<AdminLogin, AdminAccessError> {
        let began = checked_now(operation)?;
        let state = repository.auth_state()?;
        let account = match AdminUsername::parse(input.username) {
            Ok(username) => repository.account_by_username(&username)?,
            Err(_) => None,
        };
        let observed = account
            .filter(|account| state.mode == AdminAuthMode::Personal && account.is_loginable())
            .map(|account| account.snapshot());
        let verified = passwords
            .verify(
                input.password,
                observed
                    .as_ref()
                    .and_then(|account| account.password_verifier.as_ref()),
            )
            .map_err(|error| {
                if error == AdminAccessError::InvalidRequest {
                    AdminAccessError::Unauthorized
                } else {
                    error
                }
            })?;
        let verified_at = checked_auth_now(operation, began)?;
        if !verified {
            return Err(AdminAccessError::Unauthorized);
        }
        let observed = observed.ok_or(AdminAccessError::Unauthorized)?;
        let material = generator.credential(AdminCredentialKind::WebSession)?;
        if material.kind != AdminCredentialKind::WebSession {
            return Err(AdminAccessError::Unavailable);
        }
        let issued = repository.identity_transaction(|transaction| {
            let now = checked_auth_now(operation, verified_at)?;
            let account = transaction
                .account_by_id(&observed.id)?
                .ok_or(AdminAccessError::Unauthorized)?;
            let current = account.snapshot();
            if transaction.auth_state()? != state
                || !account.is_loginable()
                || current.credential_revision != observed.credential_revision
                || current.password_verifier != observed.password_verifier
            {
                return Err(AdminAccessError::Unauthorized);
            }
            cleanup_lookups(transaction, now)?;
            if !has_credential_capacity(
                transaction,
                AdminCredentialKind::WebSession,
                &current.id,
                now,
            )? {
                // Commit bounded garbage collection even when a restored over-budget
                // snapshot still cannot admit a new session. No new credential/audit commits.
                checked_auth_now(operation, now)?;
                return Ok(None);
            }
            let credential = AdminCredential::issue(
                material.id.clone(),
                material.kind,
                material.digest,
                AdminCredentialBinding::for_account(&account, state.epoch),
                now,
            )
            .map_err(|_| AdminAccessError::Unavailable)?
            .snapshot();
            transaction.insert_credential(&credential)?;
            transaction.append_identity_audit(&identity_audit(
                "admin_session_created",
                AuditActor::new(current.id.as_str()),
                &current.id,
                now,
            )?)?;
            checked_auth_now(operation, now)?;
            Ok(Some(AdminLogin {
                account: AdminAccountSummary::from(&account),
                session: IssuedAdminCredential {
                    id: material.id,
                    kind: material.kind,
                    expires_at: credential.expires_at,
                    secret: material.secret,
                },
            }))
        })?;
        issued.ok_or(AdminAccessError::Limit)
    }
}

pub struct CreateAdminPersonalTokenInput<'a> {
    pub current_password: &'a str,
    pub label: Option<fleet_domain::AdminTokenLabel>,
}

impl Debug for CreateAdminPersonalTokenInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateAdminPersonalTokenInput")
            .field("current_password", &"[REDACTED]")
            .field("label", &self.label)
            .finish()
    }
}

pub struct CreateAdminPersonalToken;

impl CreateAdminPersonalToken {
    /// Creates only the caller's PAT after same-request password proof and current binding checks.
    /// Metadata never contains the returned secret; adapters may deliver this one result once.
    pub fn execute<R: AdminIdentityRepository>(
        repository: &mut R,
        actor: &AuthenticatedAdmin,
        operation: &dyn AdminOperation,
        passwords: &dyn AdminPasswordPort,
        generator: &dyn AdminIdentityGenerator,
        input: CreateAdminPersonalTokenInput<'_>,
    ) -> Result<IssuedAdminCredential, AdminAccessError> {
        let began = checked_now(operation)?;
        let observed = verify_current_password(
            repository,
            actor,
            operation,
            passwords,
            input.current_password,
            AdminPermission::SelfCredentialManage,
        )?
        .snapshot();
        let verified_at = checked_auth_now(operation, began)?;
        let material = generator.credential(AdminCredentialKind::PersonalToken)?;
        if material.kind != AdminCredentialKind::PersonalToken {
            return Err(AdminAccessError::Unavailable);
        }
        let issued = repository.identity_transaction(|tx| {
            let now = checked_auth_now(operation, verified_at)?;
            let account = authorize_current(tx, actor, AdminPermission::SelfCredentialManage, now)?;
            let current = account.snapshot();
            if current.credential_revision != observed.credential_revision
                || current.password_verifier != observed.password_verifier
            {
                return Err(AdminAccessError::Unauthorized);
            }
            cleanup_lookups(tx, now)?;
            if !has_credential_capacity(tx, AdminCredentialKind::PersonalToken, &current.id, now)? {
                checked_auth_now(operation, now)?;
                return Ok(None);
            }
            let state = tx.auth_state()?;
            let credential = AdminCredential::issue_personal_token(
                material.id.clone(),
                material.digest,
                AdminCredentialBinding::for_account(&account, state.epoch),
                now,
                input.label,
            )
            .map_err(|_| AdminAccessError::Unavailable)?
            .snapshot();
            tx.insert_credential(&credential)?;
            tx.append_identity_audit(&credential_audit(
                "admin_personal_token_created",
                &current.id,
                &material.id,
                now,
            )?)?;
            let final_now = checked_auth_now(operation, now)?;
            authorize_current(tx, actor, AdminPermission::SelfCredentialManage, final_now)?;
            Ok(Some(IssuedAdminCredential {
                id: material.id,
                kind: material.kind,
                expires_at: credential.expires_at,
                secret: material.secret,
            }))
        })?;
        issued.ok_or(AdminAccessError::Limit)
    }
}

/// Bounded read port; owner comes from authenticated application context, never request claims.
pub trait AdminPersonalTokenQuery: AdminIdentityRead {
    /// Returns PATs in strictly increasing ID order after the exclusive position.
    /// Limit is 1..=101 (one lookahead beyond the maximum public metadata page).
    fn personal_token_page(
        &self,
        owner: &AdminUserId,
        after: Option<&AdminCredentialId>,
        limit: usize,
    ) -> Result<Vec<AdminCredential>, AdminAccessError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminMetadataPageSize(usize);

impl AdminMetadataPageSize {
    pub fn new(value: usize) -> Result<Self, AdminAccessError> {
        if !(1..=100).contains(&value) {
            return Err(AdminAccessError::InvalidRequest);
        }
        Ok(Self(value))
    }
    pub fn get(self) -> usize {
        self.0
    }
}
impl Default for AdminMetadataPageSize {
    fn default() -> Self {
        Self(25)
    }
}

/// Explicit public projection. No digest, credential binding or secret can be delivered by it.
#[derive(Debug)]
pub struct AdminPersonalTokenMetadata {
    pub id: AdminCredentialId,
    pub label: Option<fleet_domain::AdminTokenLabel>,
    pub created_at: i64,
    pub expires_at: i64,
    pub active: bool,
}

#[derive(Debug)]
pub struct AdminPersonalTokenPage {
    pub items: Vec<AdminPersonalTokenMetadata>,
    pub next_after: Option<AdminCredentialId>,
}

pub struct ListOwnAdminPersonalTokensInput<'a> {
    pub after: Option<&'a AdminCredentialId>,
    pub limit: AdminMetadataPageSize,
}

pub struct ListOwnAdminPersonalTokens;

impl ListOwnAdminPersonalTokens {
    /// Reads only this caller's bounded metadata without cleanup, renewal or any write.
    /// Interface adapters encode the internal ID position as their opaque page cursor.
    pub fn execute<R: AdminPersonalTokenQuery + ?Sized>(
        repository: &R,
        actor: &AuthenticatedAdmin,
        operation: &dyn AdminOperation,
        input: ListOwnAdminPersonalTokensInput<'_>,
    ) -> Result<AdminPersonalTokenPage, AdminAccessError> {
        let began = checked_now(operation)?;
        authorize_current(
            repository,
            actor,
            AdminPermission::SelfCredentialManage,
            began,
        )?;
        let mut credentials =
            repository.personal_token_page(actor.user_id(), input.after, input.limit.get() + 1)?;
        if credentials.len() > input.limit.get() + 1
            || credentials
                .windows(2)
                .any(|pair| pair[0].snapshot().id >= pair[1].snapshot().id)
            || credentials.iter().any(|credential| {
                let row = credential.snapshot();
                row.kind != AdminCredentialKind::PersonalToken
                    || &row.binding.user_id != actor.user_id()
                    || input.after.is_some_and(|position| &row.id <= position)
            })
        {
            return Err(AdminAccessError::Unavailable);
        }
        let has_more = credentials.len() > input.limit.get();
        credentials.truncate(input.limit.get());
        let now = checked_auth_now(operation, began)?;
        let account = authorize_current(
            repository,
            actor,
            AdminPermission::SelfCredentialManage,
            now,
        )?;
        let state = repository.auth_state()?;
        let mut items = Vec::with_capacity(credentials.len());
        for credential in credentials {
            let row = credential.snapshot();
            let active = credential
                .validate(
                    AdminCredentialKind::PersonalToken,
                    state.mode,
                    &account,
                    state.epoch,
                    now,
                )
                .is_ok();
            items.push(AdminPersonalTokenMetadata {
                id: row.id,
                label: row.label,
                created_at: row.created_at,
                expires_at: row.expires_at,
                active,
            });
        }
        let next_after = if has_more {
            items.last().map(|row| row.id.clone())
        } else {
            None
        };
        Ok(AdminPersonalTokenPage { items, next_after })
    }
}

pub struct LogoutAdminSession;

impl LogoutAdminSession {
    /// Invalidates only the authenticated web session. PATs cannot impersonate browser logout.
    /// Already missing/expired/revoked callers remain Unauthorized; adapters still clear cookies.
    pub fn execute<R: AdminIdentityRepository>(
        repository: &mut R,
        actor: &AuthenticatedAdmin,
        operation: &dyn AdminOperation,
    ) -> Result<(), AdminAccessError> {
        let began = checked_now(operation)?;
        repository.identity_transaction(|tx| {
            let now = checked_auth_now(operation, began)?;
            authorize_current(tx, actor, AdminPermission::SelfCredentialManage, now)?;
            if actor.credential_kind() != AdminCredentialKind::WebSession {
                return Err(AdminAccessError::Forbidden);
            }
            let mut credential = tx
                .credential_by_id(actor.credential_id())?
                .ok_or(AdminAccessError::Unauthorized)?;
            let before = credential.snapshot();
            let changed = credential
                .revoke(now)
                .map_err(|_| AdminAccessError::OperationExpired)?;
            if changed {
                tx.replace_credential(&before, &credential.snapshot())?;
            }
            cleanup_lookups(tx, now)?;
            if changed {
                tx.append_identity_audit(&credential_audit(
                    "admin_session_logged_out",
                    actor.user_id(),
                    actor.credential_id(),
                    now,
                )?)?;
            }
            checked_auth_now(operation, now)?;
            Ok(())
        })
    }
}

pub struct RevokeOwnAdminPersonalToken;

impl RevokeOwnAdminPersonalToken {
    /// Revokes only a PAT owned by this current principal. Foreign, missing, non-PAT and
    /// already-revoked IDs are indistinguishable NotFound, regardless of pending lookup cleanup.
    /// Removing the caller's own PAT is allowed.
    pub fn execute<R: AdminIdentityRepository>(
        repository: &mut R,
        actor: &AuthenticatedAdmin,
        operation: &dyn AdminOperation,
        id: &AdminCredentialId,
    ) -> Result<(), AdminAccessError> {
        let began = checked_now(operation)?;
        repository.identity_transaction(|tx| {
            let now = checked_auth_now(operation, began)?;
            authorize_current(tx, actor, AdminPermission::SelfCredentialManage, now)?;
            let mut credential = tx
                .own_personal_token(actor.user_id(), id)?
                .ok_or(AdminAccessError::NotFound)?;
            let before = credential.snapshot();
            if before.kind != AdminCredentialKind::PersonalToken
                || before.state != fleet_domain::AdminCredentialState::Active
                || &before.binding.user_id != actor.user_id()
            {
                return Err(AdminAccessError::NotFound);
            }
            let changed = credential
                .revoke(now)
                .map_err(|_| AdminAccessError::OperationExpired)?;
            if changed {
                tx.replace_credential(&before, &credential.snapshot())?;
            }
            cleanup_lookups(tx, now)?;
            if changed {
                tx.append_identity_audit(&credential_audit(
                    "admin_personal_token_revoked",
                    actor.user_id(),
                    id,
                    now,
                )?)?;
            }
            checked_auth_now(operation, now)?;
            Ok(())
        })
    }
}

pub struct CleanupAdminCredentialLookups;

impl CleanupAdminCredentialLookups {
    /// Bootstrap/maintenance-only bounded reclamation. Never creates authority or touches
    /// accounts, audit, Jobs or Agent state; no periodic worker is implied by this use case.
    pub fn execute<R: AdminIdentityRepository>(
        repository: &mut R,
        operation: &dyn AdminOperation,
    ) -> Result<usize, AdminAccessError> {
        let began = checked_now(operation)?;
        repository.identity_transaction(|tx| {
            let now = checked_auth_now(operation, began)?;
            let deleted = cleanup_lookups(tx, now)?;
            checked_auth_now(operation, now)?;
            Ok(deleted)
        })
    }
}

fn has_credential_capacity(
    tx: &dyn AdminIdentityTransaction,
    kind: AdminCredentialKind,
    user: &AdminUserId,
    now: i64,
) -> Result<bool, AdminAccessError> {
    let (per_user, global) = match kind {
        AdminCredentialKind::WebSession => (8, 4_096),
        AdminCredentialKind::PersonalToken => (16, 8_192),
        _ => return Err(AdminAccessError::InvalidRequest),
    };
    let counts = tx.credential_counts(kind, user, now)?;
    Ok(counts.valid_for_user < per_user && counts.total_rows < global)
}

fn credential_audit(
    action: &'static str,
    actor: &AdminUserId,
    credential: &AdminCredentialId,
    now: i64,
) -> Result<AuditEvent, AdminAccessError> {
    let mut event = AuditEvent::security(action, credential.as_str());
    event.actor = AuditActor::new(actor.as_str());
    event.occurred_at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(now as u64))
        .ok_or(AdminAccessError::InvalidRequest)?;
    Ok(event)
}

pub(super) fn cleanup_lookups(
    transaction: &mut dyn AdminIdentityTransaction,
    now: i64,
) -> Result<usize, AdminAccessError> {
    let mut total = 0;
    for kind in [
        AdminCredentialKind::WebSession,
        AdminCredentialKind::PersonalToken,
        AdminCredentialKind::SetupGrant,
        AdminCredentialKind::ResetGrant,
    ] {
        let deleted =
            transaction.cleanup_retired_credentials(kind, now, ADMIN_LOOKUP_CLEANUP_LIMIT)?;
        if deleted > ADMIN_LOOKUP_CLEANUP_LIMIT {
            return Err(AdminAccessError::Unavailable);
        }
        total += deleted;
    }
    Ok(total)
}

pub(super) fn checked_auth_now(
    operation: &dyn AdminOperation,
    began: i64,
) -> Result<i64, AdminAccessError> {
    let now = checked_now(operation)?;
    if now < began {
        Err(AdminAccessError::OperationExpired)
    } else {
        Ok(now)
    }
}
