//! Current human authority for canonical business transactions. A principal records
//! a server-authenticated credential; it is never a reusable permission grant.

use super::*;
use crate::AdminTokenRecord;

/// One synchronous business use case observes a nondecreasing UTC sequence in
/// addition to the caller's fixed monotonic deadline/cancellation contract.
pub(crate) struct OrderedAdminOperation<'a> {
    inner: &'a dyn AdminOperation,
    observed: std::cell::Cell<Option<i64>>,
}

impl<'a> OrderedAdminOperation<'a> {
    pub(crate) fn new(inner: &'a dyn AdminOperation) -> Self {
        Self {
            inner,
            observed: std::cell::Cell::new(None),
        }
    }
}

impl AdminOperation for OrderedAdminOperation<'_> {
    fn checked_now(&self) -> Result<i64, AdminAccessError> {
        let now = self.inner.checked_now()?;
        if now < 0 {
            return Err(AdminAccessError::Unavailable);
        }
        if self.observed.get().is_some_and(|previous| now < previous) {
            return Err(AdminAccessError::OperationExpired);
        }
        self.observed.set(Some(now));
        Ok(now)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AdminMutationPrincipal {
    credential: MutationCredential,
}

#[derive(Clone, PartialEq, Eq)]
enum MutationCredential {
    Personal(AuthenticatedAdmin),
    Legacy { digest: String, actor_id: String },
}

impl Debug for AdminMutationPrincipal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AdminMutationPrincipal([REDACTED])")
    }
}

impl AdminMutationPrincipal {
    pub fn personal(actor: AuthenticatedAdmin) -> Self {
        Self {
            credential: MutationCredential::Personal(actor),
        }
    }

    /// Receives only the hash and record from the existing authentication boundary.
    /// The canonical transaction must resolve that hash again; the record grants no authority.
    pub fn legacy(digest: &str, record: &AdminTokenRecord) -> Result<Self, AdminAccessError> {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || record.actor_id.is_empty()
            || AdminRole::parse(&record.role).is_none()
        {
            return Err(AdminAccessError::InvalidRequest);
        }
        Ok(Self {
            credential: MutationCredential::Legacy {
                digest: digest.to_owned(),
                actor_id: record.actor_id.clone(),
            },
        })
    }

    pub fn actor_id(&self) -> &str {
        match &self.credential {
            MutationCredential::Personal(actor) => actor.user_id().as_str(),
            MutationCredential::Legacy { actor_id, .. } => actor_id,
        }
    }
}

/// Implemented by the read view of the same transaction that commits the business effect.
/// Legacy mode/hash and human account/credential/epoch must share its serialization boundary.
pub trait AdminWriteRead: AdminIdentityRead {
    fn legacy_admin_by_hash(
        &self,
        digest: &str,
    ) -> Result<Option<AdminTokenRecord>, AdminAccessError>;
}

pub struct AuthorizeAdminWrite;

impl AuthorizeAdminWrite {
    /// Resolves authority now, inside the caller's canonical transaction. The returned
    /// audit actor is identity metadata and must never be cached as a later write grant.
    pub fn execute<R: AdminWriteRead + ?Sized>(
        repository: &R,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        permission: AdminPermission,
    ) -> Result<AuditActor, AdminAccessError> {
        let began = checked_now(operation)?;
        let actor = match &principal.credential {
            MutationCredential::Personal(actor) => {
                let account = authorize_current(repository, actor, permission, began)?;
                AuditActor::new(account.snapshot().id.as_str())
            }
            MutationCredential::Legacy { digest, actor_id } => {
                if repository.auth_state()?.mode != AdminAuthMode::LegacyBootstrap {
                    return Err(AdminAccessError::Unauthorized);
                }
                let record = repository
                    .legacy_admin_by_hash(digest)?
                    .ok_or(AdminAccessError::Unauthorized)?;
                if record.actor_id != *actor_id {
                    return Err(AdminAccessError::Unauthorized);
                }
                let role = AdminRole::parse(&record.role).ok_or(AdminAccessError::Unavailable)?;
                if !role.allows(permission) {
                    return Err(AdminAccessError::Forbidden);
                }
                AuditActor::new(record.actor_id)
            }
        };
        let finished = auth::checked_auth_now(operation, began)?;
        if finished > began
            && let MutationCredential::Personal(authenticated) = &principal.credential
        {
            authorize_current(repository, authenticated, permission, finished)?;
        }
        Ok(actor)
    }
}
